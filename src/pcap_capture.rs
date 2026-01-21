#![cfg_attr(not(feature = "pcap"), allow(dead_code))]

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, SystemTime};

#[cfg(feature = "pcap")]
use std::net::{Ipv4Addr, Ipv6Addr};
#[cfg(feature = "pcap")]
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(feature = "pcap")]
use std::sync::mpsc::{self, Receiver, SyncSender, TryRecvError};
#[cfg(feature = "pcap")]
use std::sync::Arc;
#[cfg(feature = "pcap")]
use std::thread::JoinHandle;

const DNS_TTL_SECS: u64 = 300;
const SNI_TTL_SECS: u64 = 600;
const CLEANUP_INTERVAL_SECS: u64 = 60;
const CHANNEL_CAPACITY: usize = 1000;
const CACHE_MAX_ENTRIES: usize = 10_000;
const DNS_PORT: u16 = 53;
const TLS_SNI_PORT: u16 = 443;
const MAX_DNS_PTR_DEPTH: usize = 6;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DomainSource {
    Dns,
    Sni,
}

#[derive(Clone, Debug)]
pub struct DomainMapping {
    pub hostname: String,
    pub source: DomainSource,
    captured_at: SystemTime,
    ttl: Duration,
}

pub struct DomainCache {
    by_ip_port: HashMap<(IpAddr, u16), DomainMapping>,
    by_ip: HashMap<IpAddr, DomainMapping>,
    last_cleanup: SystemTime,
    max_entries: usize,
}

impl DomainCache {
    pub fn new() -> Self {
        Self {
            by_ip_port: HashMap::new(),
            by_ip: HashMap::new(),
            last_cleanup: SystemTime::now(),
            max_entries: CACHE_MAX_ENTRIES,
        }
    }

    pub fn lookup(&mut self, ip: IpAddr, port: u16) -> Option<String> {
        let now = SystemTime::now();
        self.maybe_cleanup(now);

        if let Some(mapping) = self.by_ip_port.get(&(ip, port)) {
            if !is_expired(mapping, now) {
                return Some(mapping.hostname.clone());
            }
        }
        if let Some(mapping) = self.by_ip.get(&ip) {
            if !is_expired(mapping, now) {
                return Some(mapping.hostname.clone());
            }
        }
        None
    }

    pub fn apply_msg(&mut self, msg: PcapMsg) {
        match msg {
            PcapMsg::DnsMapping { ip, hostname } => self.insert_dns(ip, hostname),
            PcapMsg::SniMapping { ip, port, hostname } => self.insert_sni(ip, port, hostname),
        }
    }

    fn insert_dns(&mut self, ip: IpAddr, hostname: String) {
        let mapping = DomainMapping {
            hostname,
            source: DomainSource::Dns,
            captured_at: SystemTime::now(),
            ttl: Duration::from_secs(DNS_TTL_SECS),
        };
        self.by_ip.insert(ip, mapping);
        self.prune_if_needed();
    }

    fn insert_sni(&mut self, ip: IpAddr, port: u16, hostname: String) {
        let mapping = DomainMapping {
            hostname,
            source: DomainSource::Sni,
            captured_at: SystemTime::now(),
            ttl: Duration::from_secs(SNI_TTL_SECS),
        };
        self.by_ip_port.insert((ip, port), mapping);
        self.prune_if_needed();
    }

    fn maybe_cleanup(&mut self, now: SystemTime) {
        if now
            .duration_since(self.last_cleanup)
            .map(|d| d.as_secs() >= CLEANUP_INTERVAL_SECS)
            .unwrap_or(true)
        {
            self.by_ip.retain(|_, v| !is_expired(v, now));
            self.by_ip_port.retain(|_, v| !is_expired(v, now));
            self.last_cleanup = now;
        }
    }

    fn prune_if_needed(&mut self) {
        let total = self.by_ip.len() + self.by_ip_port.len();
        if total <= self.max_entries {
            return;
        }
        self.remove_oldest();
    }

    fn remove_oldest(&mut self) {
        let mut oldest_time: Option<SystemTime> = None;
        enum OldestKey {
            Ip(IpAddr),
            IpPort(IpAddr, u16),
        }
        let mut oldest_key: Option<OldestKey> = None;

        for (key, value) in self.by_ip.iter() {
            if oldest_time.map(|t| value.captured_at < t).unwrap_or(true) {
                oldest_time = Some(value.captured_at);
                oldest_key = Some(OldestKey::Ip(*key));
            }
        }
        for (key, value) in self.by_ip_port.iter() {
            if oldest_time.map(|t| value.captured_at < t).unwrap_or(true) {
                oldest_time = Some(value.captured_at);
                oldest_key = Some(OldestKey::IpPort(key.0, key.1));
            }
        }

        if let Some(key) = oldest_key {
            match key {
                OldestKey::Ip(ip) => {
                    self.by_ip.remove(&ip);
                }
                OldestKey::IpPort(ip, port) => {
                    self.by_ip_port.remove(&(ip, port));
                }
            }
        }
    }
}

fn is_expired(mapping: &DomainMapping, now: SystemTime) -> bool {
    now.duration_since(mapping.captured_at)
        .map(|d| d >= mapping.ttl)
        .unwrap_or(true)
}

#[derive(Debug)]
pub enum PcapMsg {
    DnsMapping { ip: IpAddr, hostname: String },
    SniMapping { ip: IpAddr, port: u16, hostname: String },
}

pub struct PcapHandle {
    #[cfg(feature = "pcap")]
    receiver: Receiver<PcapMsg>,
    #[cfg(feature = "pcap")]
    stop: Arc<AtomicBool>,
    #[cfg(feature = "pcap")]
    handle: Option<JoinHandle<()>>,
}

impl PcapHandle {
    #[cfg(feature = "pcap")]
    pub fn drain_into(&self, cache: &mut DomainCache) -> usize {
        let mut count = 0;
        loop {
            match self.receiver.try_recv() {
                Ok(msg) => {
                    cache.apply_msg(msg);
                    count += 1;
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => break,
            }
        }
        count
    }

    #[cfg(not(feature = "pcap"))]
    pub fn drain_into(&self, _cache: &mut DomainCache) -> usize {
        0
    }

    #[cfg(feature = "pcap")]
    pub fn shutdown(mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }

    #[cfg(not(feature = "pcap"))]
    pub fn shutdown(self) {}
}

pub fn pcap_supported() -> bool {
    cfg!(feature = "pcap")
}

#[cfg(feature = "pcap")]
pub fn start_pcap_capture() -> Result<PcapHandle, String> {
    use pcap::{Capture, Device};

    let device = Device::lookup()
        .map_err(|e| format!("pcap device lookup failed: {e}"))?
        .ok_or_else(|| "no default pcap device found".to_string())?;
    let mut cap = Capture::from_device(device)
        .map_err(|e| format!("pcap device open failed: {e}"))?
        .promisc(true)
        .immediate_mode(true)
        .open()
        .map_err(|e| format!("pcap capture open failed: {e}"))?;

    cap.filter("udp port 53 or tcp port 53 or tcp port 443", true)
        .map_err(|e| format!("pcap filter failed: {e}"))?;

    let cap = cap
        .setnonblock()
        .map_err(|e| format!("pcap nonblock failed: {e}"))?;

    let (sender, receiver) = mpsc::sync_channel(CHANNEL_CAPACITY);
    let stop = Arc::new(AtomicBool::new(false));
    let stop_thread = stop.clone();

    let handle = std::thread::spawn(move || loop {
        if stop_thread.load(Ordering::SeqCst) {
            break;
        }
        match cap.next_packet() {
            Ok(packet) => {
                if let Some(tp) = parse_transport_packet(packet.data) {
                    handle_transport_packet(tp, &sender);
                }
            }
            Err(pcap::Error::TimeoutExpired) => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(_) => {
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    });

    Ok(PcapHandle {
        receiver,
        stop,
        handle: Some(handle),
    })
}

#[cfg(not(feature = "pcap"))]
pub fn start_pcap_capture() -> Result<PcapHandle, String> {
    Err("pcap feature not enabled".to_string())
}

#[cfg(feature = "pcap")]
#[derive(Debug)]
enum TransportProto {
    Tcp,
    Udp,
}

#[cfg(feature = "pcap")]
#[derive(Debug)]
struct TransportPacket<'a> {
    src_ip: IpAddr,
    dst_ip: IpAddr,
    src_port: u16,
    dst_port: u16,
    proto: TransportProto,
    payload: &'a [u8],
}

#[cfg(feature = "pcap")]
fn handle_transport_packet(packet: TransportPacket<'_>, sender: &SyncSender<PcapMsg>) {
    match packet.proto {
        TransportProto::Udp => {
            if packet.src_port == DNS_PORT || packet.dst_port == DNS_PORT {
                if let Some((hostname, ips)) = parse_dns_packet(packet.payload, false) {
                    for ip in ips {
                        let _ = sender.try_send(PcapMsg::DnsMapping {
                            ip,
                            hostname: hostname.clone(),
                        });
                    }
                }
            }
        }
        TransportProto::Tcp => {
            if packet.src_port == DNS_PORT || packet.dst_port == DNS_PORT {
                if let Some((hostname, ips)) = parse_dns_packet(packet.payload, true) {
                    for ip in ips {
                        let _ = sender.try_send(PcapMsg::DnsMapping {
                            ip,
                            hostname: hostname.clone(),
                        });
                    }
                }
            }
            if packet.dst_port == TLS_SNI_PORT {
                if let Some(hostname) = parse_tls_sni(packet.payload) {
                    let _ = sender.try_send(PcapMsg::SniMapping {
                        ip: packet.dst_ip,
                        port: packet.dst_port,
                        hostname,
                    });
                }
            }
        }
    }
}

#[cfg(feature = "pcap")]
fn parse_transport_packet(data: &[u8]) -> Option<TransportPacket<'_>> {
    if data.len() < 14 {
        return None;
    }
    let mut offset = 14;
    let mut ethertype = u16::from_be_bytes([data[12], data[13]]);

    if ethertype == 0x8100 {
        if data.len() < 18 {
            return None;
        }
        ethertype = u16::from_be_bytes([data[16], data[17]]);
        offset = 18;
    }

    match ethertype {
        0x0800 => parse_ipv4_packet(data, offset),
        0x86DD => parse_ipv6_packet(data, offset),
        _ => None,
    }
}

#[cfg(feature = "pcap")]
fn parse_ipv4_packet(data: &[u8], offset: usize) -> Option<TransportPacket<'_>> {
    if data.len() < offset + 20 {
        return None;
    }
    let ihl = (data[offset] & 0x0f) as usize * 4;
    if ihl < 20 || data.len() < offset + ihl {
        return None;
    }
    let proto = data[offset + 9];
    let src_ip = IpAddr::V4(Ipv4Addr::new(
        data[offset + 12],
        data[offset + 13],
        data[offset + 14],
        data[offset + 15],
    ));
    let dst_ip = IpAddr::V4(Ipv4Addr::new(
        data[offset + 16],
        data[offset + 17],
        data[offset + 18],
        data[offset + 19],
    ));
    let l4_offset = offset + ihl;
    match proto {
        6 => parse_tcp_segment(data, l4_offset, src_ip, dst_ip),
        17 => parse_udp_datagram(data, l4_offset, src_ip, dst_ip),
        _ => None,
    }
}

#[cfg(feature = "pcap")]
fn parse_ipv6_packet(data: &[u8], offset: usize) -> Option<TransportPacket<'_>> {
    if data.len() < offset + 40 {
        return None;
    }
    let next_header = data[offset + 6];
    let src_bytes: [u8; 16] = data[offset + 8..offset + 24].try_into().ok()?;
    let src_ip = IpAddr::V6(Ipv6Addr::from(src_bytes));
    let dst_bytes: [u8; 16] = data[offset + 24..offset + 40].try_into().ok()?;
    let dst_ip = IpAddr::V6(Ipv6Addr::from(dst_bytes));
    let l4_offset = offset + 40;
    match next_header {
        6 => parse_tcp_segment(data, l4_offset, src_ip, dst_ip),
        17 => parse_udp_datagram(data, l4_offset, src_ip, dst_ip),
        _ => None,
    }
}

#[cfg(feature = "pcap")]
fn parse_udp_datagram(
    data: &[u8],
    offset: usize,
    src_ip: IpAddr,
    dst_ip: IpAddr,
) -> Option<TransportPacket<'_>> {
    if data.len() < offset + 8 {
        return None;
    }
    let src_port = u16::from_be_bytes([data[offset], data[offset + 1]]);
    let dst_port = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
    let payload = &data[offset + 8..];
    Some(TransportPacket {
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        proto: TransportProto::Udp,
        payload,
    })
}

#[cfg(feature = "pcap")]
fn parse_tcp_segment(
    data: &[u8],
    offset: usize,
    src_ip: IpAddr,
    dst_ip: IpAddr,
) -> Option<TransportPacket<'_>> {
    if data.len() < offset + 20 {
        return None;
    }
    let src_port = u16::from_be_bytes([data[offset], data[offset + 1]]);
    let dst_port = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
    let data_offset = (data[offset + 12] >> 4) as usize * 4;
    if data_offset < 20 || data.len() < offset + data_offset {
        return None;
    }
    let payload = &data[offset + data_offset..];
    Some(TransportPacket {
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        proto: TransportProto::Tcp,
        payload,
    })
}

#[cfg(feature = "pcap")]
fn parse_dns_packet(payload: &[u8], tcp: bool) -> Option<(String, Vec<IpAddr>)> {
    let data = if tcp {
        if payload.len() < 2 {
            return None;
        }
        let len = u16::from_be_bytes([payload[0], payload[1]]) as usize;
        if payload.len() < 2 + len {
            return None;
        }
        &payload[2..2 + len]
    } else {
        payload
    };

    parse_dns_response(data)
}

#[cfg(feature = "pcap")]
fn parse_dns_response(packet: &[u8]) -> Option<(String, Vec<IpAddr>)> {
    if packet.len() < 12 {
        return None;
    }
    let flags = u16::from_be_bytes([packet[2], packet[3]]);
    if (flags & 0x8000) == 0 {
        return None;
    }
    let qdcount = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    let ancount = u16::from_be_bytes([packet[6], packet[7]]) as usize;
    if qdcount == 0 || ancount == 0 {
        return None;
    }

    let mut offset = 12;
    let hostname = parse_dns_name(packet, &mut offset, 0)?;
    if offset + 4 > packet.len() {
        return None;
    }
    offset += 4;

    let mut ips = Vec::new();
    for _ in 0..ancount {
        let _ = parse_dns_name(packet, &mut offset, 0)?;
        if offset + 10 > packet.len() {
            return None;
        }
        let rtype = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
        let rdlen = u16::from_be_bytes([packet[offset + 8], packet[offset + 9]]) as usize;
        offset += 10;
        if offset + rdlen > packet.len() {
            return None;
        }
        match rtype {
            1 if rdlen == 4 => {
                let ip = Ipv4Addr::new(
                    packet[offset],
                    packet[offset + 1],
                    packet[offset + 2],
                    packet[offset + 3],
                );
                ips.push(IpAddr::V4(ip));
            }
            28 if rdlen == 16 => {
                let mut bytes = [0u8; 16];
                bytes.copy_from_slice(&packet[offset..offset + 16]);
                ips.push(IpAddr::V6(Ipv6Addr::from(bytes)));
            }
            _ => {}
        }
        offset += rdlen;
    }

    if ips.is_empty() {
        None
    } else {
        Some((hostname, ips))
    }
}

#[cfg(feature = "pcap")]
fn parse_dns_name(packet: &[u8], offset: &mut usize, depth: usize) -> Option<String> {
    if depth > MAX_DNS_PTR_DEPTH {
        return None;
    }
    let mut labels = Vec::new();
    let mut pos = *offset;
    let mut jumped = false;

    loop {
        if pos >= packet.len() {
            return None;
        }
        let len = packet[pos];
        if len & 0xC0 == 0xC0 {
            if pos + 1 >= packet.len() {
                return None;
            }
            let ptr = (((len & 0x3F) as usize) << 8) | packet[pos + 1] as usize;
            if !jumped {
                *offset = pos + 2;
                jumped = true;
            }
            let mut new_offset = ptr;
            let name = parse_dns_name(packet, &mut new_offset, depth + 1)?;
            if !name.is_empty() {
                labels.push(name);
            }
            break;
        }
        if len == 0 {
            if !jumped {
                *offset = pos + 1;
            }
            break;
        }
        pos += 1;
        let end = pos + len as usize;
        if end > packet.len() {
            return None;
        }
        labels.push(String::from_utf8_lossy(&packet[pos..end]).to_string());
        pos = end;
    }

    Some(labels.join("."))
}

#[cfg(feature = "pcap")]
fn parse_tls_sni(payload: &[u8]) -> Option<String> {
    if payload.len() < 5 {
        return None;
    }
    if payload[0] != 0x16 {
        return None;
    }
    let record_len = u16::from_be_bytes([payload[3], payload[4]]) as usize;
    if payload.len() < 5 + record_len {
        return None;
    }
    if payload.len() < 9 {
        return None;
    }
    if payload[5] != 0x01 {
        return None;
    }
    let hs_len = ((payload[6] as usize) << 16)
        | ((payload[7] as usize) << 8)
        | (payload[8] as usize);
    if record_len < 4 + hs_len {
        return None;
    }
    let mut pos = 9;
    if payload.len() < pos + 2 + 32 {
        return None;
    }
    pos += 2 + 32;

    if payload.len() <= pos {
        return None;
    }
    let session_len = payload[pos] as usize;
    pos += 1;
    if payload.len() < pos + session_len {
        return None;
    }
    pos += session_len;

    if payload.len() < pos + 2 {
        return None;
    }
    let cipher_len = u16::from_be_bytes([payload[pos], payload[pos + 1]]) as usize;
    pos += 2;
    if payload.len() < pos + cipher_len {
        return None;
    }
    pos += cipher_len;

    if payload.len() <= pos {
        return None;
    }
    let comp_len = payload[pos] as usize;
    pos += 1;
    if payload.len() < pos + comp_len {
        return None;
    }
    pos += comp_len;

    if payload.len() < pos + 2 {
        return None;
    }
    let ext_len = u16::from_be_bytes([payload[pos], payload[pos + 1]]) as usize;
    pos += 2;
    if payload.len() < pos + ext_len {
        return None;
    }
    let end = pos + ext_len;
    while pos + 4 <= end {
        let ext_type = u16::from_be_bytes([payload[pos], payload[pos + 1]]);
        let len = u16::from_be_bytes([payload[pos + 2], payload[pos + 3]]) as usize;
        pos += 4;
        if pos + len > end {
            return None;
        }
        if ext_type == 0x0000 {
            if len < 2 {
                return None;
            }
            let list_len = u16::from_be_bytes([payload[pos], payload[pos + 1]]) as usize;
            pos += 2;
            if pos + list_len > end {
                return None;
            }
            let list_end = pos + list_len;
            while pos + 3 <= list_end {
                let name_type = payload[pos];
                pos += 1;
                let name_len = u16::from_be_bytes([payload[pos], payload[pos + 1]]) as usize;
                pos += 2;
                if pos + name_len > list_end {
                    return None;
                }
                if name_type == 0 {
                    let name_bytes = &payload[pos..pos + name_len];
                    if let Ok(hostname) = std::str::from_utf8(name_bytes) {
                        return Some(hostname.to_string());
                    }
                }
                pos += name_len;
            }
            return None;
        }
        pos += len;
    }
    None
}
