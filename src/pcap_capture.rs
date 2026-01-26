#![cfg_attr(not(feature = "pcap"), allow(dead_code))]
#![allow(clippy::collapsible_if)]

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, SystemTime};

#[cfg(feature = "pcap")]
use std::env;
#[cfg(feature = "pcap")]
use std::net::{Ipv4Addr, Ipv6Addr};
#[cfg(feature = "pcap")]
use std::sync::Arc;
#[cfg(feature = "pcap")]
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(feature = "pcap")]
use std::sync::mpsc::{self, Receiver, SyncSender, TryRecvError};
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
    #[allow(dead_code)]
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
    DnsMapping {
        ip: IpAddr,
        hostname: String,
    },
    SniMapping {
        ip: IpAddr,
        port: u16,
        hostname: String,
    },
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

    let offline_path = env::var("RANO_PCAP_FILE")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());

    let (sender, receiver) = mpsc::sync_channel(CHANNEL_CAPACITY);
    let stop = Arc::new(AtomicBool::new(false));

    // Handle offline (file) capture separately from live capture
    // because pcap crate uses different types: Capture<Offline> vs Capture<Active>
    if let Some(path) = offline_path {
        let mut cap =
            Capture::from_file(&path).map_err(|e| format!("pcap file open failed: {e}"))?;
        cap.filter("udp port 53 or tcp port 53 or tcp port 443", true)
            .map_err(|e| format!("pcap filter failed: {e}"))?;

        loop {
            match cap.next_packet() {
                Ok(packet) => {
                    if let Some(tp) = parse_transport_packet(packet.data) {
                        handle_transport_packet(tp, &sender);
                    }
                }
                Err(pcap::Error::NoMorePackets) => {
                    break;
                }
                Err(_) => {
                    break;
                }
            }
        }

        return Ok(PcapHandle {
            receiver,
            stop,
            handle: None,
        });
    }

    // Live capture mode
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

    cap = cap
        .setnonblock()
        .map_err(|e| format!("pcap nonblock failed: {e}"))?;

    let stop_thread = stop.clone();
    let handle = std::thread::spawn(move || {
        loop {
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
                Err(pcap::Error::NoMorePackets) => {
                    break;
                }
                Err(_) => {
                    std::thread::sleep(Duration::from_millis(50));
                }
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
    #[allow(dead_code)]
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
    let mut next_header = data[offset + 6];
    let src_bytes: [u8; 16] = data[offset + 8..offset + 24].try_into().ok()?;
    let src_ip = IpAddr::V6(Ipv6Addr::from(src_bytes));
    let dst_bytes: [u8; 16] = data[offset + 24..offset + 40].try_into().ok()?;
    let dst_ip = IpAddr::V6(Ipv6Addr::from(dst_bytes));

    let mut current_offset = offset + 40;

    // Loop to skip extension headers
    // We limit the number of extensions to avoid infinite loops or DoS
    for _ in 0..10 {
        match next_header {
            6 => return parse_tcp_segment(data, current_offset, src_ip, dst_ip),
            17 => return parse_udp_datagram(data, current_offset, src_ip, dst_ip),
            // Hop-by-Hop (0), Routing (43), Destination Options (60)
            0 | 43 | 60 => {
                if data.len() < current_offset + 2 {
                    return None;
                }
                next_header = data[current_offset];
                // Length is in 8-octet units, not including the first 8 octets
                let hdr_ext_len = data[current_offset + 1];
                let len_bytes = (hdr_ext_len as usize + 1) * 8;
                current_offset += len_bytes;
                if current_offset > data.len() {
                    return None;
                }
            }
            // Fragment Header (44)
            44 => {
                if data.len() < current_offset + 8 {
                    return None;
                }
                next_header = data[current_offset];

                // Check Fragment Offset to ensure this is the first fragment
                // Offset is in the high 13 bits of the 16-bit field at offset + 2
                let field =
                    u16::from_be_bytes([data[current_offset + 2], data[current_offset + 3]]);
                let frag_offset = field >> 3;

                if frag_offset != 0 {
                    // Not the first fragment, so we can't see the L4 header
                    return None;
                }

                // Fragment header is fixed 8 bytes
                current_offset += 8;
            }
            // Authentication Header (51)
            51 => {
                if data.len() < current_offset + 2 {
                    return None;
                }
                next_header = data[current_offset];
                // Payload Len is in 4-byte units, minus 2
                let payload_len = data[current_offset + 1];
                let len_bytes = (payload_len as usize + 2) * 4;
                current_offset += len_bytes;
                if current_offset > data.len() {
                    return None;
                }
            }
            // Unknown or unhandled extension (e.g. ESP=50, NoNext=59)
            _ => return None,
        }
    }

    None
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
                #[allow(unused_assignments)]
                {
                    jumped = true;
                }
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
    let hs_len =
        ((payload[6] as usize) << 16) | ((payload[7] as usize) << 8) | (payload[8] as usize);
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    // ============================================================
    // DomainCache tests (no pcap feature required)
    // ============================================================

    #[test]
    fn domain_cache_new_is_empty() {
        let mut cache = DomainCache::new();
        let ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        assert!(cache.lookup(ip, 443).is_none());
    }

    #[test]
    fn domain_cache_dns_insert_and_lookup() {
        let mut cache = DomainCache::new();
        let ip = IpAddr::V4(Ipv4Addr::new(142, 250, 189, 206));

        cache.apply_msg(PcapMsg::DnsMapping {
            ip,
            hostname: "www.google.com".to_string(),
        });

        // Lookup by IP (any port) should find DNS mapping
        assert_eq!(cache.lookup(ip, 443), Some("www.google.com".to_string()));
        assert_eq!(cache.lookup(ip, 80), Some("www.google.com".to_string()));
    }

    #[test]
    fn domain_cache_sni_insert_and_lookup() {
        let mut cache = DomainCache::new();
        let ip = IpAddr::V4(Ipv4Addr::new(104, 18, 32, 7));

        cache.apply_msg(PcapMsg::SniMapping {
            ip,
            port: 443,
            hostname: "api.anthropic.com".to_string(),
        });

        // Lookup by exact IP+port should find SNI mapping
        assert_eq!(cache.lookup(ip, 443), Some("api.anthropic.com".to_string()));
        // Different port should not find SNI mapping
        assert!(cache.lookup(ip, 80).is_none());
    }

    #[test]
    fn domain_cache_sni_preferred_over_dns() {
        let mut cache = DomainCache::new();
        let ip = IpAddr::V4(Ipv4Addr::new(104, 18, 32, 7));

        // Insert DNS mapping first (broader match)
        cache.apply_msg(PcapMsg::DnsMapping {
            ip,
            hostname: "cloudflare.net".to_string(),
        });

        // Insert SNI mapping (more specific)
        cache.apply_msg(PcapMsg::SniMapping {
            ip,
            port: 443,
            hostname: "api.anthropic.com".to_string(),
        });

        // SNI should be preferred for exact port match
        assert_eq!(cache.lookup(ip, 443), Some("api.anthropic.com".to_string()));
        // DNS should be used for other ports
        assert_eq!(cache.lookup(ip, 80), Some("cloudflare.net".to_string()));
    }

    #[test]
    fn domain_cache_ipv6_support() {
        let mut cache = DomainCache::new();
        let ip = IpAddr::V6(Ipv6Addr::new(
            0x2607, 0xf8b0, 0x4004, 0x800, 0, 0, 0, 0x200e,
        ));

        cache.apply_msg(PcapMsg::DnsMapping {
            ip,
            hostname: "ipv6.google.com".to_string(),
        });

        assert_eq!(cache.lookup(ip, 443), Some("ipv6.google.com".to_string()));
    }

    #[test]
    fn domain_cache_overwrites_existing() {
        let mut cache = DomainCache::new();
        let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));

        cache.apply_msg(PcapMsg::DnsMapping {
            ip,
            hostname: "old.example.com".to_string(),
        });
        cache.apply_msg(PcapMsg::DnsMapping {
            ip,
            hostname: "new.example.com".to_string(),
        });

        assert_eq!(cache.lookup(ip, 443), Some("new.example.com".to_string()));
    }

    #[test]
    fn domain_cache_eviction_when_full() {
        // Create cache with small max_entries for testing
        let mut cache = DomainCache {
            by_ip_port: HashMap::new(),
            by_ip: HashMap::new(),
            last_cleanup: SystemTime::now(),
            max_entries: 3,
        };

        // Insert 4 entries - should trigger eviction
        for i in 0..4u8 {
            let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, i));
            cache.apply_msg(PcapMsg::DnsMapping {
                ip,
                hostname: format!("host{}.example.com", i),
            });
            // Small sleep to ensure different timestamps
            std::thread::sleep(std::time::Duration::from_millis(1));
        }

        // Total entries should be <= max_entries
        let total = cache.by_ip.len() + cache.by_ip_port.len();
        assert!(total <= 3);

        // Latest entry should still exist
        let latest_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
        assert_eq!(
            cache.lookup(latest_ip, 443),
            Some("host3.example.com".to_string())
        );
    }

    #[test]
    fn domain_source_enum_equality() {
        assert_eq!(DomainSource::Dns, DomainSource::Dns);
        assert_eq!(DomainSource::Sni, DomainSource::Sni);
        assert_ne!(DomainSource::Dns, DomainSource::Sni);
    }

    #[test]
    fn pcap_msg_debug_format() {
        let dns_msg = PcapMsg::DnsMapping {
            ip: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            hostname: "dns.google".to_string(),
        };
        let debug_str = format!("{:?}", dns_msg);
        assert!(debug_str.contains("DnsMapping"));
        assert!(debug_str.contains("dns.google"));

        let sni_msg = PcapMsg::SniMapping {
            ip: IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            port: 443,
            hostname: "example.com".to_string(),
        };
        let debug_str = format!("{:?}", sni_msg);
        assert!(debug_str.contains("SniMapping"));
        assert!(debug_str.contains("443"));
    }

    #[test]
    fn pcap_supported_returns_correct_value() {
        // This test verifies the function exists and returns a boolean
        let supported = pcap_supported();
        #[cfg(feature = "pcap")]
        assert!(supported);
        #[cfg(not(feature = "pcap"))]
        assert!(!supported);
    }

    // ============================================================
    // DNS parsing tests (requires pcap feature)
    // ============================================================

    #[cfg(feature = "pcap")]
    #[test]
    fn dns_response_parse_a_record() {
        // Minimal DNS response with A record for "example.com" -> 93.184.216.34
        // Header: ID=0x1234, Flags=0x8180 (response, no error), QD=1, AN=1
        let packet = vec![
            0x12, 0x34, // ID
            0x81, 0x80, // Flags: response, recursion available
            0x00, 0x01, // QDCOUNT = 1
            0x00, 0x01, // ANCOUNT = 1
            0x00, 0x00, // NSCOUNT = 0
            0x00, 0x00, // ARCOUNT = 0
            // Question: example.com
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00,
            0x01, // QTYPE = A
            0x00, 0x01, // QCLASS = IN
            // Answer: example.com -> 93.184.216.34
            0xc0, 0x0c, // Name pointer to offset 12
            0x00, 0x01, // TYPE = A
            0x00, 0x01, // CLASS = IN
            0x00, 0x00, 0x0e, 0x10, // TTL = 3600
            0x00, 0x04, // RDLENGTH = 4
            93, 184, 216, 34, // RDATA = 93.184.216.34
        ];

        let result = parse_dns_response(&packet);
        assert!(result.is_some());
        let (hostname, ips) = result.unwrap();
        assert_eq!(hostname, "example.com");
        assert_eq!(ips.len(), 1);
        assert_eq!(ips[0], IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)));
    }

    #[cfg(feature = "pcap")]
    #[test]
    fn dns_response_parse_aaaa_record() {
        // DNS response with AAAA record for "ipv6.example.com" -> 2001:db8::1
        let packet = vec![
            0x12, 0x34, // ID
            0x81, 0x80, // Flags: response
            0x00, 0x01, // QDCOUNT = 1
            0x00, 0x01, // ANCOUNT = 1
            0x00, 0x00, // NSCOUNT = 0
            0x00, 0x00, // ARCOUNT = 0
            // Question: ipv6.example.com
            0x04, b'i', b'p', b'v', b'6', 0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03,
            b'c', b'o', b'm', 0x00, 0x00, 0x1c, // QTYPE = AAAA
            0x00, 0x01, // QCLASS = IN
            // Answer
            0xc0, 0x0c, // Name pointer
            0x00, 0x1c, // TYPE = AAAA (28)
            0x00, 0x01, // CLASS = IN
            0x00, 0x00, 0x0e, 0x10, // TTL
            0x00, 0x10, // RDLENGTH = 16
            // 2001:0db8:0000:0000:0000:0000:0000:0001
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01,
        ];

        let result = parse_dns_response(&packet);
        assert!(result.is_some());
        let (hostname, ips) = result.unwrap();
        assert_eq!(hostname, "ipv6.example.com");
        assert_eq!(ips.len(), 1);
        assert_eq!(
            ips[0],
            IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1))
        );
    }

    #[cfg(feature = "pcap")]
    #[test]
    fn dns_response_parse_multiple_a_records() {
        // DNS response with multiple A records (round-robin)
        let packet = vec![
            0x12, 0x34, // ID
            0x81, 0x80, // Flags
            0x00, 0x01, // QDCOUNT = 1
            0x00, 0x02, // ANCOUNT = 2
            0x00, 0x00, // NSCOUNT = 0
            0x00, 0x00, // ARCOUNT = 0
            // Question: multi.example.com
            0x05, b'm', b'u', b'l', b't', b'i', 0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
            0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, // QTYPE = A
            0x00, 0x01, // QCLASS = IN
            // Answer 1
            0xc0, 0x0c, // Name pointer
            0x00, 0x01, // TYPE = A
            0x00, 0x01, // CLASS = IN
            0x00, 0x00, 0x0e, 0x10, // TTL
            0x00, 0x04, // RDLENGTH
            10, 0, 0, 1, // 10.0.0.1
            // Answer 2
            0xc0, 0x0c, // Name pointer
            0x00, 0x01, // TYPE = A
            0x00, 0x01, // CLASS = IN
            0x00, 0x00, 0x0e, 0x10, // TTL
            0x00, 0x04, // RDLENGTH
            10, 0, 0, 2, // 10.0.0.2
        ];

        let result = parse_dns_response(&packet);
        assert!(result.is_some());
        let (hostname, ips) = result.unwrap();
        assert_eq!(hostname, "multi.example.com");
        assert_eq!(ips.len(), 2);
        assert!(ips.contains(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert!(ips.contains(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))));
    }

    #[cfg(feature = "pcap")]
    #[test]
    fn dns_response_rejects_query() {
        // DNS query (not response) should be rejected
        let packet = vec![
            0x12, 0x34, // ID
            0x01, 0x00, // Flags: query (QR=0)
            0x00, 0x01, // QDCOUNT = 1
            0x00, 0x00, // ANCOUNT = 0
            0x00, 0x00, 0x00, 0x00, // Question
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00,
            0x01, 0x00, 0x01,
        ];

        let result = parse_dns_response(&packet);
        assert!(result.is_none());
    }

    #[cfg(feature = "pcap")]
    #[test]
    fn dns_response_rejects_no_answers() {
        // DNS response with no answers
        let packet = vec![
            0x12, 0x34, // ID
            0x81, 0x80, // Flags: response
            0x00, 0x01, // QDCOUNT = 1
            0x00, 0x00, // ANCOUNT = 0
            0x00, 0x00, 0x00, 0x00, // Question
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00,
            0x01, 0x00, 0x01,
        ];

        let result = parse_dns_response(&packet);
        assert!(result.is_none());
    }

    #[cfg(feature = "pcap")]
    #[test]
    fn dns_response_rejects_truncated() {
        // Truncated packet (too short)
        let packet = vec![0x12, 0x34, 0x81, 0x80, 0x00, 0x01];
        let result = parse_dns_response(&packet);
        assert!(result.is_none());
    }

    #[cfg(feature = "pcap")]
    #[test]
    fn dns_name_parse_simple() {
        // Simple domain name: "test.com"
        let packet = vec![0x04, b't', b'e', b's', b't', 0x03, b'c', b'o', b'm', 0x00];
        let mut offset = 0;
        let result = parse_dns_name(&packet, &mut offset, 0);
        assert_eq!(result, Some("test.com".to_string()));
        assert_eq!(offset, 10); // Advanced past the name
    }

    #[cfg(feature = "pcap")]
    #[test]
    fn dns_name_parse_with_pointer() {
        // Name with compression pointer
        let packet = vec![
            // Offset 0: "example.com"
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm',
            0x00, // Offset 13: pointer to offset 0
            0xc0, 0x00,
        ];
        let mut offset = 13;
        let result = parse_dns_name(&packet, &mut offset, 0);
        assert_eq!(result, Some("example.com".to_string()));
    }

    #[cfg(feature = "pcap")]
    #[test]
    fn dns_name_rejects_deep_recursion() {
        // Malicious packet with deep pointer recursion
        // This creates a chain of pointers that exceeds MAX_DNS_PTR_DEPTH
        let mut packet = vec![0xc0, 0x02, 0xc0, 0x04, 0xc0, 0x06, 0xc0, 0x08];
        packet.extend_from_slice(&[0xc0, 0x0a, 0xc0, 0x0c, 0xc0, 0x0e, 0xc0, 0x00]);
        let mut offset = 0;
        let result = parse_dns_name(&packet, &mut offset, 0);
        // Should return None due to recursion depth limit
        assert!(result.is_none());
    }

    // ============================================================
    // TLS SNI parsing tests (requires pcap feature)
    // ============================================================

    #[cfg(feature = "pcap")]
    #[test]
    fn tls_sni_parse_client_hello() {
        // Minimal TLS ClientHello with SNI extension for "api.example.com"
        let client_hello = build_tls_client_hello("api.example.com");
        let result = parse_tls_sni(&client_hello);
        assert_eq!(result, Some("api.example.com".to_string()));
    }

    #[cfg(feature = "pcap")]
    #[test]
    fn tls_sni_parse_long_hostname() {
        // Test with longer hostname
        let hostname = "very-long-subdomain.api.services.example.com";
        let client_hello = build_tls_client_hello(hostname);
        let result = parse_tls_sni(&client_hello);
        assert_eq!(result, Some(hostname.to_string()));
    }

    #[cfg(feature = "pcap")]
    #[test]
    fn tls_sni_rejects_non_handshake() {
        // Non-TLS data
        let data = vec![0x17, 0x03, 0x03, 0x00, 0x20]; // Application data record
        let result = parse_tls_sni(&data);
        assert!(result.is_none());
    }

    #[cfg(feature = "pcap")]
    #[test]
    fn tls_sni_rejects_server_hello() {
        // Server Hello (handshake type 0x02, not ClientHello 0x01)
        let data = vec![
            0x16, // Handshake record
            0x03, 0x03, // TLS 1.2
            0x00, 0x10, // Length
            0x02, // ServerHello (not ClientHello)
            0x00, 0x00, 0x0c, // Handshake length
            0x03, 0x03, // Version
                  // ... rest would be server hello data
        ];
        let result = parse_tls_sni(&data);
        assert!(result.is_none());
    }

    #[cfg(feature = "pcap")]
    #[test]
    fn tls_sni_rejects_truncated() {
        // Truncated TLS record
        let data = vec![0x16, 0x03, 0x03];
        let result = parse_tls_sni(&data);
        assert!(result.is_none());
    }

    #[cfg(feature = "pcap")]
    #[test]
    fn tls_sni_handles_no_sni_extension() {
        // ClientHello without SNI extension (e.g., connecting by IP)
        let client_hello = build_tls_client_hello_no_sni();
        let result = parse_tls_sni(&client_hello);
        assert!(result.is_none());
    }

    // ============================================================
    // Transport packet parsing tests (requires pcap feature)
    // ============================================================

    #[cfg(feature = "pcap")]
    #[test]
    fn transport_parse_ipv4_udp() {
        // Ethernet + IPv4 + UDP packet
        let packet = build_test_udp_packet_ipv4();
        let result = parse_transport_packet(&packet);
        assert!(result.is_some());
        let tp = result.unwrap();
        assert!(matches!(tp.proto, TransportProto::Udp));
        assert_eq!(tp.src_port, 12345);
        assert_eq!(tp.dst_port, 53);
    }

    #[cfg(feature = "pcap")]
    #[test]
    fn transport_parse_ipv4_tcp() {
        // Ethernet + IPv4 + TCP packet
        let packet = build_test_tcp_packet_ipv4();
        let result = parse_transport_packet(&packet);
        assert!(result.is_some());
        let tp = result.unwrap();
        assert!(matches!(tp.proto, TransportProto::Tcp));
        assert_eq!(tp.dst_port, 443);
    }

    #[cfg(feature = "pcap")]
    #[test]
    fn transport_parse_vlan_tagged() {
        // VLAN-tagged packet (802.1Q)
        let packet = build_test_vlan_packet();
        let result = parse_transport_packet(&packet);
        assert!(result.is_some());
    }

    #[cfg(feature = "pcap")]
    #[test]
    fn transport_rejects_short_packet() {
        // Too short to be valid Ethernet frame
        let packet = vec![0; 10];
        let result = parse_transport_packet(&packet);
        assert!(result.is_none());
    }

    #[cfg(feature = "pcap")]
    #[test]
    fn transport_rejects_non_ip() {
        // Ethernet frame with non-IP ethertype (ARP = 0x0806)
        let mut packet = vec![0; 14];
        packet[12] = 0x08;
        packet[13] = 0x06;
        let result = parse_transport_packet(&packet);
        assert!(result.is_none());
    }

    // ============================================================
    // Integration tests for the full pipeline
    // ============================================================

    #[cfg(feature = "pcap")]
    #[test]
    fn integration_dns_to_cache() {
        let mut cache = DomainCache::new();

        // Simulate DNS response message
        let msg = PcapMsg::DnsMapping {
            ip: IpAddr::V4(Ipv4Addr::new(140, 82, 114, 4)),
            hostname: "github.com".to_string(),
        };
        cache.apply_msg(msg);

        // Connection to that IP should resolve
        assert_eq!(
            cache.lookup(IpAddr::V4(Ipv4Addr::new(140, 82, 114, 4)), 443),
            Some("github.com".to_string())
        );
    }

    #[cfg(feature = "pcap")]
    #[test]
    fn integration_sni_to_cache() {
        let mut cache = DomainCache::new();

        // Simulate SNI message
        let msg = PcapMsg::SniMapping {
            ip: IpAddr::V4(Ipv4Addr::new(104, 18, 32, 7)),
            port: 443,
            hostname: "api.anthropic.com".to_string(),
        };
        cache.apply_msg(msg);

        // Exact IP+port lookup should resolve
        assert_eq!(
            cache.lookup(IpAddr::V4(Ipv4Addr::new(104, 18, 32, 7)), 443),
            Some("api.anthropic.com".to_string())
        );
    }

    // ============================================================
    // Helper functions for building test packets
    // ============================================================

    #[cfg(feature = "pcap")]
    fn build_tls_client_hello(hostname: &str) -> Vec<u8> {
        let hostname_bytes = hostname.as_bytes();
        let sni_ext_len = 5 + hostname_bytes.len(); // type(1) + length(2) + hostname
        let extensions_len = 4 + sni_ext_len; // ext_type(2) + ext_len(2) + sni_ext

        let mut packet = Vec::new();
        // TLS record header
        packet.push(0x16); // Handshake
        packet.extend_from_slice(&[0x03, 0x01]); // TLS 1.0
        let record_len = 4 + 2 + 32 + 1 + 2 + 1 + 2 + extensions_len;
        packet.extend_from_slice(&(record_len as u16).to_be_bytes());

        // Handshake header
        packet.push(0x01); // ClientHello
        let hs_len = record_len - 4;
        packet.push(0);
        packet.extend_from_slice(&(hs_len as u16).to_be_bytes());

        // Version
        packet.extend_from_slice(&[0x03, 0x03]); // TLS 1.2

        // Random (32 bytes)
        packet.extend_from_slice(&[0; 32]);

        // Session ID (0 length)
        packet.push(0);

        // Cipher suites (2 bytes for length, then empty)
        packet.extend_from_slice(&[0x00, 0x02, 0x00, 0x00]);

        // Compression methods (1 byte for length, then null)
        packet.extend_from_slice(&[0x01, 0x00]);

        // Extensions length
        packet.extend_from_slice(&(extensions_len as u16).to_be_bytes());

        // SNI extension (type 0x0000)
        packet.extend_from_slice(&[0x00, 0x00]);
        packet.extend_from_slice(&(sni_ext_len as u16).to_be_bytes());
        // SNI list length
        packet.extend_from_slice(&((sni_ext_len - 2) as u16).to_be_bytes());
        // SNI entry: type=0 (hostname), length, hostname
        packet.push(0x00);
        packet.extend_from_slice(&(hostname_bytes.len() as u16).to_be_bytes());
        packet.extend_from_slice(hostname_bytes);

        packet
    }

    #[cfg(feature = "pcap")]
    fn build_tls_client_hello_no_sni() -> Vec<u8> {
        // Minimal ClientHello without SNI extension
        let mut packet = Vec::new();
        // TLS record header
        packet.push(0x16); // Handshake
        packet.extend_from_slice(&[0x03, 0x01]); // TLS 1.0
        let record_len = 4 + 2 + 32 + 1 + 2 + 1 + 2;
        packet.extend_from_slice(&(record_len as u16).to_be_bytes());

        // Handshake header
        packet.push(0x01); // ClientHello
        let hs_len = record_len - 4;
        packet.push(0);
        packet.extend_from_slice(&(hs_len as u16).to_be_bytes());

        // Version
        packet.extend_from_slice(&[0x03, 0x03]);

        // Random (32 bytes)
        packet.extend_from_slice(&[0; 32]);

        // Session ID (0 length)
        packet.push(0);

        // Cipher suites
        packet.extend_from_slice(&[0x00, 0x02, 0x00, 0x00]);

        // Compression methods
        packet.extend_from_slice(&[0x01, 0x00]);

        // Extensions length = 0
        packet.extend_from_slice(&[0x00, 0x00]);

        packet
    }

    #[cfg(feature = "pcap")]
    fn build_test_udp_packet_ipv4() -> Vec<u8> {
        let mut packet = Vec::new();
        // Ethernet header (14 bytes)
        packet.extend_from_slice(&[0; 12]); // MAC addresses
        packet.extend_from_slice(&[0x08, 0x00]); // IPv4 ethertype

        // IPv4 header (20 bytes minimum)
        packet.push(0x45); // Version + IHL
        packet.push(0x00); // DSCP/ECN
        packet.extend_from_slice(&[0x00, 0x28]); // Total length
        packet.extend_from_slice(&[0x00, 0x00]); // ID
        packet.extend_from_slice(&[0x00, 0x00]); // Flags/Fragment
        packet.push(64); // TTL
        packet.push(17); // Protocol = UDP
        packet.extend_from_slice(&[0x00, 0x00]); // Checksum
        packet.extend_from_slice(&[192, 168, 1, 100]); // Src IP
        packet.extend_from_slice(&[8, 8, 8, 8]); // Dst IP

        // UDP header (8 bytes)
        packet.extend_from_slice(&(12345u16).to_be_bytes()); // Src port
        packet.extend_from_slice(&(53u16).to_be_bytes()); // Dst port
        packet.extend_from_slice(&[0x00, 0x10]); // Length
        packet.extend_from_slice(&[0x00, 0x00]); // Checksum

        // UDP payload
        packet.extend_from_slice(&[0; 8]);

        packet
    }

    #[cfg(feature = "pcap")]
    fn build_test_tcp_packet_ipv4() -> Vec<u8> {
        let mut packet = Vec::new();
        // Ethernet header
        packet.extend_from_slice(&[0; 12]);
        packet.extend_from_slice(&[0x08, 0x00]); // IPv4

        // IPv4 header
        packet.push(0x45); // Version + IHL (20 bytes)
        packet.push(0x00);
        packet.extend_from_slice(&[0x00, 0x34]); // Total length
        packet.extend_from_slice(&[0x00, 0x00]); // ID
        packet.extend_from_slice(&[0x00, 0x00]); // Flags/Fragment
        packet.push(64); // TTL
        packet.push(6); // Protocol = TCP
        packet.extend_from_slice(&[0x00, 0x00]); // Checksum
        packet.extend_from_slice(&[192, 168, 1, 100]); // Src IP
        packet.extend_from_slice(&[104, 18, 32, 7]); // Dst IP

        // TCP header (20 bytes minimum)
        packet.extend_from_slice(&(54321u16).to_be_bytes()); // Src port
        packet.extend_from_slice(&(443u16).to_be_bytes()); // Dst port
        packet.extend_from_slice(&[0; 4]); // Seq
        packet.extend_from_slice(&[0; 4]); // Ack
        packet.push(0x50); // Data offset (5 * 4 = 20 bytes)
        packet.push(0x02); // Flags (SYN)
        packet.extend_from_slice(&[0xff, 0xff]); // Window
        packet.extend_from_slice(&[0x00, 0x00]); // Checksum
        packet.extend_from_slice(&[0x00, 0x00]); // Urgent pointer

        packet
    }

    #[cfg(feature = "pcap")]
    #[test]
    fn transport_parse_ipv6_with_extension_headers() {
        // Construct IPv6 packet with Hop-by-Hop options -> UDP
        let mut packet = Vec::new();
        // Ethernet header
        packet.extend_from_slice(&[0; 12]);
        packet.extend_from_slice(&[0x86, 0xDD]); // IPv6

        // IPv6 header
        packet.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]); // Version, Class, Flow
        packet.extend_from_slice(&[0x00, 0x10]); // Payload length (16 bytes: 8 ext + 8 UDP)
        packet.push(0); // Next Header: Hop-by-Hop (0)
        packet.push(64); // Hop Limit
        packet.extend_from_slice(&[0; 16]); // Src IP
        packet.extend_from_slice(&[0; 16]); // Dst IP

        // Hop-by-Hop Options Header
        packet.push(17); // Next Header: UDP (17)
        packet.push(0); // Hdr Ext Len: (0 + 1) * 8 = 8 bytes
        packet.extend_from_slice(&[0; 6]); // Padding

        // UDP Header
        packet.extend_from_slice(&(1234u16).to_be_bytes()); // Src Port
        packet.extend_from_slice(&(53u16).to_be_bytes()); // Dst Port
        packet.extend_from_slice(&[0x00, 0x08]); // Length
        packet.extend_from_slice(&[0x00, 0x00]); // Checksum

        let result = parse_transport_packet(&packet);
        assert!(result.is_some(), "Should parse IPv6 with extension header");
        let tp = result.unwrap();
        assert!(matches!(tp.proto, TransportProto::Udp));
        assert_eq!(tp.dst_port, 53);
    }

    #[cfg(feature = "pcap")]
    fn build_test_vlan_packet() -> Vec<u8> {
        let mut packet = Vec::new();
        // Ethernet header with VLAN tag
        packet.extend_from_slice(&[0; 12]); // MAC addresses
        packet.extend_from_slice(&[0x81, 0x00]); // 802.1Q ethertype
        packet.extend_from_slice(&[0x00, 0x64]); // VLAN ID = 100
        packet.extend_from_slice(&[0x08, 0x00]); // IPv4 ethertype

        // IPv4 header
        packet.push(0x45);
        packet.push(0x00);
        packet.extend_from_slice(&[0x00, 0x28]);
        packet.extend_from_slice(&[0x00, 0x00]);
        packet.extend_from_slice(&[0x00, 0x00]);
        packet.push(64);
        packet.push(17); // UDP
        packet.extend_from_slice(&[0x00, 0x00]);
        packet.extend_from_slice(&[10, 0, 0, 1]);
        packet.extend_from_slice(&[10, 0, 0, 2]);

        // UDP header
        packet.extend_from_slice(&(1234u16).to_be_bytes());
        packet.extend_from_slice(&(5678u16).to_be_bytes());
        packet.extend_from_slice(&[0x00, 0x10]);
        packet.extend_from_slice(&[0x00, 0x00]);

        packet
    }
}
