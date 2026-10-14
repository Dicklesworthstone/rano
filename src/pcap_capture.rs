#![cfg_attr(not(feature = "pcap"), allow(dead_code))]
#![allow(clippy::collapsible_if)]

use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;
#[cfg(feature = "pcap")]
use std::time::UNIX_EPOCH;
use std::time::{Duration, SystemTime};

#[cfg(feature = "pcap")]
use std::env;
#[cfg(feature = "pcap")]
use std::net::{Ipv4Addr, Ipv6Addr};
#[cfg(feature = "pcap")]
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
#[cfg(feature = "pcap")]
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TryRecvError, TrySendError};
#[cfg(feature = "pcap")]
use std::sync::{Arc, Mutex};
#[cfg(feature = "pcap")]
use std::thread::JoinHandle;

const DNS_TTL_SECS: u64 = 300;
const SNI_TTL_SECS: u64 = 600;
const CLEANUP_INTERVAL_SECS: u64 = 60;
const CHANNEL_CAPACITY: usize = 1000;
pub const DEFAULT_CACHE_MAX_ENTRIES: usize = 10_000;
const DNS_PORT: u16 = 53;
const TLS_SNI_PORT: u16 = 443;
const MAX_DNS_PTR_DEPTH: usize = 6;
// Each `vlan` changes subsequent BPF decoding offsets. Nest the branches so
// untagged, one-tag and two-tag packets each use the matching transport offsets.
const CAPTURE_FILTER: &str = "(udp port 53 or tcp port 53 or tcp port 443) or (vlan and ((udp port 53 or tcp port 53 or tcp port 443) or (vlan and (udp port 53 or tcp port 53 or tcp port 443))))";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DomainSource {
    Dns,
    Sni,
    Ptr,
}

impl DomainSource {
    /// Stable lowercase label used in events JSON, SQLite `domain_source`,
    /// exports, and reports.
    pub fn label(self) -> &'static str {
        match self {
            DomainSource::Dns => "dns",
            DomainSource::Sni => "sni",
            DomainSource::Ptr => "ptr",
        }
    }
}

#[derive(Clone, Debug)]
pub struct DomainMapping {
    pub hostname: String,
    pub source: DomainSource,
    captured_at: SystemTime,
    ttl: Duration,
    offline: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct FlowKey {
    pub local_ip: IpAddr,
    pub local_port: u16,
    pub remote_ip: IpAddr,
    pub remote_port: u16,
}

#[derive(Clone, Debug)]
pub struct DomainEvidence {
    pub hostname: Option<String>,
    pub source: Option<DomainSource>,
    pub scope: &'static str,
    pub captured_at: Option<SystemTime>,
    pub offline: bool,
    pub dns_candidates: Vec<String>,
    pub dns_candidate_count: usize,
    pub sni_ambiguous: bool,
}

impl Default for DomainEvidence {
    fn default() -> Self {
        Self {
            hostname: None,
            source: None,
            scope: "unresolved",
            captured_at: None,
            offline: false,
            dns_candidates: Vec::new(),
            dns_candidate_count: 0,
            sni_ambiguous: false,
        }
    }
}

struct FlowMapping {
    mapping: Option<DomainMapping>,
    inode: Option<u64>,
    not_before: Option<SystemTime>,
    last_seen: SystemTime,
    ambiguous: bool,
}

pub struct DomainCache {
    by_flow: HashMap<FlowKey, FlowMapping>,
    by_ip: HashMap<IpAddr, BTreeMap<String, DomainMapping>>,
    dns_entries: usize,
    last_cleanup: SystemTime,
    max_entries: usize,
}

impl DomainCache {
    /// Create a cache with a caller-provided entry cap (the `--pcap-cache-max`
    /// knob). Values below the 100-entry floor are rejected by CLI/config
    /// validation before reaching this constructor.
    pub fn with_max_entries(max_entries: usize) -> Self {
        Self {
            by_flow: HashMap::new(),
            by_ip: HashMap::new(),
            dns_entries: 0,
            last_cleanup: SystemTime::now(),
            max_entries,
        }
    }

    /// Correlate SNI with the complete tuple and a currently observed inode.
    /// DNS remains host-IP evidence and is unresolved when names disagree.
    pub fn lookup(&mut self, flow: FlowKey, inode: u64, not_before: SystemTime) -> DomainEvidence {
        let now = SystemTime::now();
        self.maybe_cleanup(now);
        let mut evidence = DomainEvidence::default();
        let dns = self.by_ip.get(&flow.remote_ip);
        if let Some(names) = dns {
            evidence.dns_candidate_count = names
                .values()
                .filter(|mapping| !is_expired(mapping, now))
                .count();
            evidence.dns_candidates = names
                .iter()
                .filter(|(_, mapping)| !is_expired(mapping, now))
                .map(|(name, _)| name.clone())
                .take(8)
                .collect();
        }
        if let Some(record) = self.by_flow.get_mut(&flow) {
            if record.inode.is_some_and(|previous| previous != inode) {
                // A new kernel socket cannot inherit an earlier association.
                // Require a new capture after this reuse was actually observed.
                record.mapping = None;
                record.not_before = Some(now);
                record.ambiguous = false;
            }
            record.inode = Some(inode);
            record.last_seen = now;
            evidence.sni_ambiguous = record.ambiguous;
            if let Some(mapping) = &record.mapping {
                let floor = record
                    .not_before
                    .map_or(not_before, |floor| floor.max(not_before));
                if !record.ambiguous && mapping.captured_at >= floor && !is_expired(mapping, now) {
                    evidence.hostname = Some(mapping.hostname.clone());
                    evidence.source = Some(mapping.source);
                    evidence.scope = "socket-tuple";
                    evidence.captured_at = Some(mapping.captured_at);
                    evidence.offline = mapping.offline;
                    return evidence;
                }
            }
        }
        if !evidence.dns_candidates.is_empty() {
            evidence.scope = "host-ip";
            if let [name] = evidence.dns_candidates.as_slice() {
                if evidence.dns_candidate_count != 1 {
                    return evidence;
                }
                if let Some(mapping) = dns.and_then(|names| names.get(name)) {
                    evidence.hostname = Some(name.clone());
                    evidence.source = Some(mapping.source);
                    evidence.captured_at = Some(mapping.captured_at);
                    evidence.offline = mapping.offline;
                }
            }
        }
        evidence
    }

    pub fn retire_flow(&mut self, flow: FlowKey, inode: u64, observed_at: SystemTime) {
        if let Some(record) = self.by_flow.get_mut(&flow) {
            if record.inode == Some(inode) {
                record.mapping = None;
                record.inode = None;
                record.not_before = Some(observed_at);
                record.last_seen = observed_at;
                record.ambiguous = false;
            }
        }
    }

    pub fn apply_msg(&mut self, msg: PcapMsg) {
        match msg {
            PcapMsg::DnsMapping {
                ip,
                hostname,
                captured_at,
                ttl_seconds,
                offline,
            } => {
                self.insert_dns(ip, hostname, captured_at, ttl_seconds, offline);
            }
            PcapMsg::SniMapping {
                flow,
                hostname,
                captured_at,
                offline,
            } => {
                self.insert_sni(flow, hostname, captured_at, offline);
            }
        }
    }

    fn insert_dns(
        &mut self,
        ip: IpAddr,
        hostname: String,
        captured_at: SystemTime,
        ttl_seconds: u32,
        offline: bool,
    ) {
        let hostname = hostname.to_ascii_lowercase();
        if !valid_hostname(&hostname) {
            return;
        }
        let now = SystemTime::now();
        let Ok(age) = now.duration_since(captured_at) else {
            return;
        };
        let ttl = Duration::from_secs(u64::from(ttl_seconds).min(DNS_TTL_SECS));
        if age >= ttl {
            if let Some(names) = self.by_ip.get_mut(&ip) {
                if names
                    .get(&hostname)
                    .is_some_and(|old| old.captured_at <= captured_at)
                {
                    names.remove(&hostname);
                    self.dns_entries -= 1;
                }
                if names.is_empty() {
                    self.by_ip.remove(&ip);
                }
            }
            return;
        }
        let mapping = DomainMapping {
            hostname: hostname.clone(),
            source: DomainSource::Dns,
            captured_at,
            ttl,
            offline,
        };
        let names = self.by_ip.entry(ip).or_default();
        if names
            .get(&hostname)
            .is_some_and(|old| old.captured_at > captured_at)
        {
            return;
        }
        if names.insert(hostname, mapping).is_none() {
            self.dns_entries += 1;
        }
        self.prune_if_needed();
    }

    fn insert_sni(
        &mut self,
        flow: FlowKey,
        hostname: String,
        captured_at: SystemTime,
        offline: bool,
    ) {
        let hostname = hostname.to_ascii_lowercase();
        if !valid_hostname(&hostname) {
            return;
        }
        let now = SystemTime::now();
        if !now
            .duration_since(captured_at)
            .is_ok_and(|age| age.as_secs() < SNI_TTL_SECS)
        {
            return;
        }
        let record = self.by_flow.entry(flow).or_insert_with(|| FlowMapping {
            mapping: None,
            inode: None,
            not_before: None,
            last_seen: now,
            ambiguous: false,
        });
        if record.not_before.is_some_and(|floor| captured_at < floor) {
            return;
        }
        if let Some(old) = &record.mapping {
            if captured_at < old.captured_at {
                return;
            }
            if captured_at == old.captured_at {
                if old.hostname != hostname {
                    record.ambiguous = true;
                }
                return;
            }
        }
        let mapping = DomainMapping {
            hostname,
            source: DomainSource::Sni,
            captured_at,
            ttl: Duration::from_secs(SNI_TTL_SECS),
            offline,
        };
        record.mapping = Some(mapping);
        record.last_seen = now;
        record.ambiguous = false;
        self.prune_if_needed();
    }

    fn maybe_cleanup(&mut self, now: SystemTime) {
        if now
            .duration_since(self.last_cleanup)
            .map(|d| d.as_secs() >= CLEANUP_INTERVAL_SECS)
            .unwrap_or(true)
        {
            self.by_ip.retain(|_, names| {
                names.retain(|_, mapping| !is_expired(mapping, now));
                !names.is_empty()
            });
            self.dns_entries = self.by_ip.values().map(BTreeMap::len).sum();
            self.by_flow.retain(|_, record| {
                now.duration_since(record.last_seen)
                    .is_ok_and(|elapsed| elapsed.as_secs() < SNI_TTL_SECS)
            });
            self.last_cleanup = now;
        }
    }

    fn prune_if_needed(&mut self) {
        while self.dns_entries + self.by_flow.len() > self.max_entries {
            self.remove_oldest();
        }
    }

    fn remove_oldest(&mut self) {
        let mut oldest_time: Option<SystemTime> = None;
        enum OldestKey {
            Dns(IpAddr),
            Flow(FlowKey),
        }
        let mut oldest_key: Option<OldestKey> = None;

        for (ip, names) in &self.by_ip {
            for value in names.values() {
                if oldest_time.map(|t| value.captured_at < t).unwrap_or(true) {
                    oldest_time = Some(value.captured_at);
                    oldest_key = Some(OldestKey::Dns(*ip));
                }
            }
        }
        for (key, value) in &self.by_flow {
            if oldest_time.map(|t| value.last_seen < t).unwrap_or(true) {
                oldest_time = Some(value.last_seen);
                oldest_key = Some(OldestKey::Flow(*key));
            }
        }

        if let Some(key) = oldest_key {
            match key {
                OldestKey::Dns(ip) => {
                    // Evict the whole candidate group so removing one alias
                    // cannot turn known ambiguity into false single-name proof.
                    if let Some(names) = self.by_ip.remove(&ip) {
                        self.dns_entries -= names.len();
                    }
                }
                OldestKey::Flow(flow) => {
                    self.by_flow.remove(&flow);
                }
            }
        }
    }
}

fn valid_hostname(hostname: &str) -> bool {
    !hostname.is_empty()
        && hostname.len() <= 253
        && hostname.is_ascii()
        && hostname.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        })
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
        captured_at: SystemTime,
        ttl_seconds: u32,
        offline: bool,
    },
    SniMapping {
        flow: FlowKey,
        hostname: String,
        captured_at: SystemTime,
        offline: bool,
    },
}

#[derive(Clone, Debug, Default)]
pub struct CaptureHealth {
    pub state: &'static str,
    pub offline: bool,
    pub packets: u64,
    pub rejected_frames: u64,
    pub mappings: u64,
    pub delivered: u64,
    pub drained: u64,
    pub mapping_lost: u64,
    pub kernel_dropped: u64,
    pub interface_dropped: u64,
    pub idle_polls: u64,
    pub error: Option<String>,
}

impl CaptureHealth {
    pub fn unhealthy(&self) -> bool {
        self.state == "failed"
            || self.mapping_lost > 0
            || self.kernel_dropped > 0
            || self.interface_dropped > 0
    }
}

#[cfg(feature = "pcap")]
#[derive(Default)]
struct CaptureCounters {
    state: AtomicU8,
    offline: bool,
    packets: AtomicU64,
    rejected_frames: AtomicU64,
    mappings: AtomicU64,
    delivered: AtomicU64,
    drained: AtomicU64,
    mapping_lost: AtomicU64,
    kernel_dropped: AtomicU64,
    interface_dropped: AtomicU64,
    idle_polls: AtomicU64,
    error: Mutex<Option<String>>,
}

#[cfg(feature = "pcap")]
impl CaptureCounters {
    fn fail(&self, error: String) {
        if let Ok(mut stored) = self.error.lock() {
            *stored = Some(error);
        }
        self.state.store(4, Ordering::Release);
    }

    fn snapshot(&self) -> CaptureHealth {
        CaptureHealth {
            state: match self.state.load(Ordering::Acquire) {
                0 if self.offline => "replaying",
                0 => "live",
                1 => "complete",
                2 => "stopped",
                _ => "failed",
            },
            offline: self.offline,
            packets: self.packets.load(Ordering::Relaxed),
            rejected_frames: self.rejected_frames.load(Ordering::Relaxed),
            mappings: self.mappings.load(Ordering::Relaxed),
            delivered: self.delivered.load(Ordering::Relaxed),
            drained: self.drained.load(Ordering::Relaxed),
            mapping_lost: self.mapping_lost.load(Ordering::Relaxed),
            kernel_dropped: self.kernel_dropped.load(Ordering::Relaxed),
            interface_dropped: self.interface_dropped.load(Ordering::Relaxed),
            idle_polls: self.idle_polls.load(Ordering::Relaxed),
            error: self.error.lock().ok().and_then(|stored| stored.clone()),
        }
    }
}

pub struct PcapHandle {
    #[cfg(feature = "pcap")]
    receiver: Receiver<PcapMsg>,
    #[cfg(feature = "pcap")]
    stop: Arc<AtomicBool>,
    #[cfg(feature = "pcap")]
    handle: Option<JoinHandle<()>>,
    #[cfg(feature = "pcap")]
    counters: Arc<CaptureCounters>,
}

impl PcapHandle {
    #[cfg(feature = "pcap")]
    pub fn drain_into(&self, cache: &mut DomainCache) -> usize {
        let mut count = 0;
        loop {
            let message = if self.counters.offline {
                // Complete a finite regular-file replay through bounded
                // backpressure, including --once, without losing its tail.
                match self.receiver.recv_timeout(Duration::from_millis(50)) {
                    Ok(message) => Some(message),
                    Err(RecvTimeoutError::Disconnected) => None,
                    Err(RecvTimeoutError::Timeout) => {
                        if self.counters.state.load(Ordering::Acquire) != 0 {
                            break;
                        }
                        continue;
                    }
                }
            } else {
                if count >= CHANNEL_CAPACITY {
                    break;
                }
                match self.receiver.try_recv() {
                    Ok(message) => Some(message),
                    Err(TryRecvError::Empty) => None,
                    Err(TryRecvError::Disconnected) => {
                        if self.counters.state.load(Ordering::Acquire) == 0 {
                            self.counters.fail(
                                "pcap producer disconnected without a terminal state".to_string(),
                            );
                        }
                        None
                    }
                }
            };
            match message {
                Some(msg) => {
                    cache.apply_msg(msg);
                    count += 1;
                    self.counters.drained.fetch_add(1, Ordering::Relaxed);
                }
                None => break,
            }
        }
        count
    }

    #[cfg(not(feature = "pcap"))]
    pub fn drain_into(&self, _cache: &mut DomainCache) -> usize {
        0
    }

    #[cfg(feature = "pcap")]
    pub fn health(&self) -> CaptureHealth {
        self.counters.snapshot()
    }

    #[cfg(not(feature = "pcap"))]
    pub fn health(&self) -> CaptureHealth {
        CaptureHealth::default()
    }

    #[cfg(feature = "pcap")]
    pub fn stop_capture(&self) {
        self.stop.store(true, Ordering::Release);
    }

    #[cfg(not(feature = "pcap"))]
    pub fn stop_capture(&self) {}

    #[cfg(feature = "pcap")]
    pub fn shutdown(mut self, cache: Option<&mut DomainCache>) -> CaptureHealth {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(handle) = self.handle.take() {
            if handle.join().is_err() {
                self.counters
                    .fail("pcap capture worker panicked".to_string());
            }
        }
        if let Some(cache) = cache {
            self.drain_into(cache);
        } else {
            while self.receiver.try_recv().is_ok() {
                self.counters.mapping_lost.fetch_add(1, Ordering::Relaxed);
            }
        }
        self.counters.snapshot()
    }

    #[cfg(not(feature = "pcap"))]
    pub fn shutdown(self, _cache: Option<&mut DomainCache>) -> CaptureHealth {
        CaptureHealth::default()
    }
}

pub fn pcap_supported() -> bool {
    cfg!(feature = "pcap")
}

/// Tuning knobs for the pcap capture subsystem (feature `pcap`). The DNS/SNI
/// cache cap (`--pcap-cache-max`) is applied by the caller at
/// [`DomainCache::with_max_entries`], so only the interface lives here.
#[derive(Clone, Debug, Default)]
pub struct PcapOptions {
    /// Capture interface name; `None` uses libpcap's default device.
    pub interface: Option<String>,
}

#[cfg(feature = "pcap")]
pub fn start_pcap_capture(options: PcapOptions) -> Result<PcapHandle, String> {
    use pcap::{Capture, Device};

    let offline_path = env::var("RANO_PCAP_FILE")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());

    let (sender, receiver) = mpsc::sync_channel(CHANNEL_CAPACITY);
    let stop = Arc::new(AtomicBool::new(false));
    let counters = Arc::new(CaptureCounters {
        offline: offline_path.is_some(),
        ..CaptureCounters::default()
    });

    // Handle offline (file) capture separately from live capture
    // because pcap crate uses different types: Capture<Offline> vs Capture<Active>
    if let Some(path) = offline_path {
        if !std::fs::metadata(&path)
            .map_err(|error| format!("pcap file metadata failed: {error}"))?
            .is_file()
        {
            return Err("RANO_PCAP_FILE must name a finite regular capture file".to_string());
        }
        let mut cap =
            Capture::from_file(&path).map_err(|e| format!("pcap file open failed: {e}"))?;
        validate_datalink(cap.get_datalink())?;
        cap.filter(CAPTURE_FILTER, true)
            .map_err(|e| format!("pcap filter failed: {e}"))?;

        let handle = spawn_capture(cap, sender, stop.clone(), counters.clone());

        return Ok(PcapHandle {
            receiver,
            stop,
            handle: Some(handle),
            counters,
        });
    }

    // Live capture mode: honor an explicit --pcap-interface, else libpcap default.
    let device = match options.interface.as_deref() {
        Some(name) => {
            let devices =
                Device::list().map_err(|e| format!("pcap device enumeration failed: {e}"))?;
            match devices.into_iter().find(|d| d.name == name) {
                Some(device) => device,
                None => {
                    let devices: Vec<Device> = Device::list()
                        .map_err(|e| format!("pcap device enumeration failed: {e}"))?;
                    let available: Vec<&str> = devices.iter().map(|d| d.name.as_str()).collect();
                    return Err(format!(
                        "pcap interface '{}' not found; available interfaces: {}",
                        name,
                        available.join(", ")
                    ));
                }
            }
        }
        None => Device::lookup()
            .map_err(|e| format!("pcap device lookup failed: {e}"))?
            .ok_or_else(|| "no default pcap device found".to_string())?,
    };
    let mut cap = Capture::from_device(device)
        .map_err(|e| format!("pcap device open failed: {e}"))?
        .promisc(true)
        // Preserve the largest supported IPv6 payload plus Ethernet/two VLAN
        // headers with an explicit, bounded snapshot size.
        .snaplen(65_535 + 40 + 14 + 8)
        // A bounded eight-MiB capture buffer absorbs short bursts while the
        // nonblocking worker is idle. Loss still degrades health and exits1.
        .buffer_size(8 * 1024 * 1024)
        .immediate_mode(true)
        .open()
        .map_err(|e| format!("pcap capture open failed: {e}"))?;

    validate_datalink(cap.get_datalink())?;
    cap.filter(CAPTURE_FILTER, true)
        .map_err(|e| format!("pcap filter failed: {e}"))?;

    cap = cap
        .setnonblock()
        .map_err(|e| format!("pcap nonblock failed: {e}"))?;

    let handle = spawn_capture(cap, sender, stop.clone(), counters.clone());

    Ok(PcapHandle {
        receiver,
        stop,
        handle: Some(handle),
        counters,
    })
}

#[cfg(feature = "pcap")]
fn validate_datalink(link: pcap::Linktype) -> Result<(), String> {
    if link == pcap::Linktype::ETHERNET {
        Ok(())
    } else {
        Err(format!(
            "unsupported pcap datalink {} ({}); only Ethernet with up to two VLAN tags is parsed; select an Ethernet interface or capture file",
            link.0,
            link.get_name().unwrap_or_else(|_| "unknown".to_string())
        ))
    }
}

#[cfg(feature = "pcap")]
fn spawn_capture<T: pcap::Activated + Send + 'static>(
    mut cap: pcap::Capture<T>,
    sender: SyncSender<PcapMsg>,
    stop: Arc<AtomicBool>,
    counters: Arc<CaptureCounters>,
) -> JoinHandle<()> {
    std::thread::spawn(move || {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            while !stop.load(Ordering::Acquire) {
                match cap.next_packet() {
                    Ok(packet) => {
                        counters.packets.fetch_add(1, Ordering::Relaxed);
                        if let (Some(tp), Some(captured_at)) = (
                            parse_transport_packet(packet.data),
                            packet_capture_time(packet.header),
                        ) {
                            handle_transport_packet(tp, captured_at, &sender, &stop, &counters);
                        } else {
                            counters.rejected_frames.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    Err(pcap::Error::TimeoutExpired) if !counters.offline => {
                        counters.idle_polls.fetch_add(1, Ordering::Relaxed);
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(pcap::Error::NoMorePackets) if counters.offline => {
                        counters.state.store(1, Ordering::Release);
                        return;
                    }
                    Err(error) => {
                        counters.fail(format!("pcap read failed: {error}"));
                        return;
                    }
                }
                if !counters.offline {
                    match cap.stats() {
                        Ok(stats) => {
                            counters
                                .kernel_dropped
                                .store(u64::from(stats.dropped), Ordering::Relaxed);
                            counters
                                .interface_dropped
                                .store(u64::from(stats.if_dropped), Ordering::Relaxed);
                        }
                        Err(error) => {
                            counters.fail(format!("pcap capture statistics unavailable: {error}"));
                            return;
                        }
                    }
                }
            }
            counters.state.store(2, Ordering::Release);
        }));
        if result.is_err() {
            counters.fail("pcap capture worker panicked".to_string());
        }
    })
}

#[cfg(feature = "pcap")]
fn send_mapping(
    mut message: PcapMsg,
    sender: &SyncSender<PcapMsg>,
    stop: &AtomicBool,
    counters: &CaptureCounters,
) {
    counters.mappings.fetch_add(1, Ordering::Relaxed);
    loop {
        if stop.load(Ordering::Acquire) {
            counters.mapping_lost.fetch_add(1, Ordering::Relaxed);
            return;
        }
        match sender.try_send(message) {
            Ok(()) => {
                counters.delivered.fetch_add(1, Ordering::Relaxed);
                return;
            }
            Err(TrySendError::Full(returned)) if counters.offline => {
                message = returned;
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(error) => {
                counters.mapping_lost.fetch_add(1, Ordering::Relaxed);
                if matches!(error, TrySendError::Disconnected(_)) {
                    counters.fail("pcap mapping receiver disconnected".to_string());
                }
                return;
            }
        }
    }
}

#[cfg(not(feature = "pcap"))]
pub fn start_pcap_capture(_options: PcapOptions) -> Result<PcapHandle, String> {
    Err("pcap feature not enabled".to_string())
}

#[cfg(feature = "pcap")]
fn packet_capture_time(header: &pcap::PacketHeader) -> Option<SystemTime> {
    let seconds = u64::try_from(header.ts.tv_sec).ok()?;
    let micros = u32::try_from(header.ts.tv_usec).ok()?;
    if micros >= 1_000_000 {
        return None;
    }
    UNIX_EPOCH.checked_add(Duration::new(seconds, micros * 1000))
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
fn handle_transport_packet(
    packet: TransportPacket<'_>,
    captured_at: SystemTime,
    sender: &SyncSender<PcapMsg>,
    stop: &AtomicBool,
    counters: &CaptureCounters,
) {
    match packet.proto {
        TransportProto::Udp => {
            if packet.src_port == DNS_PORT || packet.dst_port == DNS_PORT {
                if let Some(response) = parse_dns_packet(packet.payload, false) {
                    for (ip, ttl_seconds) in response.answers {
                        send_mapping(
                            PcapMsg::DnsMapping {
                                ip,
                                hostname: response.hostname.clone(),
                                captured_at,
                                ttl_seconds,
                                offline: counters.offline,
                            },
                            sender,
                            stop,
                            counters,
                        );
                    }
                }
            }
        }
        TransportProto::Tcp => {
            if packet.src_port == DNS_PORT || packet.dst_port == DNS_PORT {
                if let Some(response) = parse_dns_packet(packet.payload, true) {
                    for (ip, ttl_seconds) in response.answers {
                        send_mapping(
                            PcapMsg::DnsMapping {
                                ip,
                                hostname: response.hostname.clone(),
                                captured_at,
                                ttl_seconds,
                                offline: counters.offline,
                            },
                            sender,
                            stop,
                            counters,
                        );
                    }
                }
            }
            if packet.dst_port == TLS_SNI_PORT {
                if let Some(hostname) = parse_tls_sni(packet.payload) {
                    send_mapping(
                        PcapMsg::SniMapping {
                            flow: FlowKey {
                                local_ip: packet.src_ip,
                                local_port: packet.src_port,
                                remote_ip: packet.dst_ip,
                                remote_port: packet.dst_port,
                            },
                            hostname,
                            captured_at,
                            offline: counters.offline,
                        },
                        sender,
                        stop,
                        counters,
                    );
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

    // Skip up to two stacked VLAN tags: 802.1Q (0x8100), 802.1ad QinQ outer
    // (0x88A8), and the common 0x9100 variant. Deeper stacking is rejected.
    for _ in 0..2 {
        match ethertype {
            0x8100 | 0x88A8 | 0x9100 => {
                if data.len() < offset + 4 {
                    return None;
                }
                ethertype = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
                offset += 4;
            }
            _ => break,
        }
    }
    if matches!(ethertype, 0x8100 | 0x88A8 | 0x9100) {
        return None;
    }

    match ethertype {
        0x0800 => parse_ipv4_packet(data, offset),
        0x86DD => parse_ipv6_packet(data, offset),
        _ => None,
    }
}

#[cfg(feature = "pcap")]
fn parse_ipv4_packet(data: &[u8], offset: usize) -> Option<TransportPacket<'_>> {
    if data.len() < offset + 20 || data[offset] >> 4 != 4 {
        return None;
    }
    let ihl = (data[offset] & 0x0f) as usize * 4;
    if ihl < 20 || data.len() < offset + ihl {
        return None;
    }
    let total = usize::from(u16::from_be_bytes([data[offset + 2], data[offset + 3]]));
    if total < ihl || data.len() < offset + total {
        return None;
    }
    let fragment = u16::from_be_bytes([data[offset + 6], data[offset + 7]]);
    if fragment & 0x3fff != 0 {
        // Neither partial first fragments nor non-first fragments can establish
        // a complete DNS/TLS message without reassembly.
        return None;
    }
    let data = &data[..offset + total];
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
    if data.len() < offset + 40 || data[offset] >> 4 != 6 {
        return None;
    }
    let payload_len = usize::from(u16::from_be_bytes([data[offset + 4], data[offset + 5]]));
    if payload_len == 0 || data.len() < offset + 40 + payload_len {
        // IPv6 jumbograms require additional parsing and are unsupported.
        return None;
    }
    let data = &data[..offset + 40 + payload_len];
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

                if frag_offset != 0 || field & 1 != 0 {
                    // Only an atomic fragment (offset=0, M=0) is complete.
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
    let length = usize::from(u16::from_be_bytes([data[offset + 4], data[offset + 5]]));
    if length < 8 || data.len() < offset + length {
        return None;
    }
    let src_port = u16::from_be_bytes([data[offset], data[offset + 1]]);
    let dst_port = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
    let payload = &data[offset + 8..offset + length];
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
fn parse_dns_packet(payload: &[u8], tcp: bool) -> Option<DnsResponse> {
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
struct DnsResponse {
    hostname: String,
    answers: Vec<(IpAddr, u32)>,
}

#[cfg(feature = "pcap")]
fn parse_dns_response(packet: &[u8]) -> Option<DnsResponse> {
    if packet.len() < 12 {
        return None;
    }
    let flags = u16::from_be_bytes([packet[2], packet[3]]);
    if flags & 0x8000 == 0 || flags & 0x020f != 0 {
        return None;
    }
    let qdcount = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    let ancount = u16::from_be_bytes([packet[6], packet[7]]) as usize;
    if qdcount != 1 || ancount == 0 {
        return None;
    }

    let mut offset = 12;
    let hostname = parse_dns_name(packet, &mut offset, 0)?;
    if offset + 4 > packet.len() {
        return None;
    }
    if !valid_hostname(&hostname)
        || u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]) != 1
    {
        return None;
    }
    offset += 4;

    let mut answers = Vec::new();
    for _ in 0..ancount {
        let _ = parse_dns_name(packet, &mut offset, 0)?;
        if offset + 10 > packet.len() {
            return None;
        }
        let rtype = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
        let class = u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]);
        let ttl = u32::from_be_bytes(packet[offset + 4..offset + 8].try_into().ok()?);
        let rdlen = u16::from_be_bytes([packet[offset + 8], packet[offset + 9]]) as usize;
        offset += 10;
        if offset + rdlen > packet.len() {
            return None;
        }
        match rtype {
            1 if class == 1 && rdlen == 4 => {
                let ip = Ipv4Addr::new(
                    packet[offset],
                    packet[offset + 1],
                    packet[offset + 2],
                    packet[offset + 3],
                );
                answers.push((IpAddr::V4(ip), ttl));
            }
            28 if class == 1 && rdlen == 16 => {
                let mut bytes = [0u8; 16];
                bytes.copy_from_slice(&packet[offset..offset + 16]);
                answers.push((IpAddr::V6(Ipv6Addr::from(bytes)), ttl));
            }
            _ => {}
        }
        offset += rdlen;
    }

    if answers.is_empty() {
        None
    } else {
        Some(DnsResponse { hostname, answers })
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
        if len > 63 {
            return None;
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
    if record_len < 4 || payload.len() < 5 + record_len {
        return None;
    }
    if payload.len() < 9 {
        return None;
    }
    let payload = &payload[..5 + record_len];
    if payload[5] != 0x01 {
        return None;
    }
    let hs_len =
        ((payload[6] as usize) << 16) | ((payload[7] as usize) << 8) | (payload[8] as usize);
    if record_len < 4 + hs_len {
        return None;
    }
    let payload = &payload[..9 + hs_len];
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
            if list_len + 2 != len || pos + list_len > end {
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
                        if valid_hostname(hostname) {
                            return Some(hostname.to_string());
                        }
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
    #[cfg(not(feature = "pcap"))]
    use std::time::UNIX_EPOCH;

    fn flow(ip: IpAddr, port: u16, local_port: u16) -> FlowKey {
        FlowKey {
            local_ip: if ip.is_ipv6() {
                "::1".parse().unwrap()
            } else {
                "127.0.0.1".parse().unwrap()
            },
            local_port,
            remote_ip: ip,
            remote_port: port,
        }
    }

    #[test]
    #[cfg(feature = "pcap")]
    fn live_mapping_overflow_and_disconnection_are_counted() {
        let (sender, receiver) = mpsc::sync_channel(1);
        let counters = CaptureCounters::default();
        let stop = AtomicBool::new(false);
        let message = || PcapMsg::DnsMapping {
            ip: "127.0.0.1".parse().unwrap(),
            hostname: "overflow.test".to_string(),
            captured_at: SystemTime::now(),
            ttl_seconds: 300,
            offline: false,
        };
        send_mapping(message(), &sender, &stop, &counters);
        send_mapping(message(), &sender, &stop, &counters);
        let health = counters.snapshot();
        assert_eq!(
            (health.mappings, health.delivered, health.mapping_lost),
            (2, 1, 1)
        );
        assert!(health.unhealthy());
        drop(receiver);
        send_mapping(message(), &sender, &stop, &counters);
        let health = counters.snapshot();
        assert_eq!(health.mapping_lost, 2);
        assert_eq!(health.state, "failed");
        assert!(health.error.unwrap().contains("disconnected"));
    }

    #[test]
    #[cfg(feature = "pcap")]
    fn offline_mapping_backpressure_preserves_every_message() {
        let (sender, receiver) = mpsc::sync_channel(1);
        let counters = Arc::new(CaptureCounters {
            offline: true,
            ..CaptureCounters::default()
        });
        let stop = Arc::new(AtomicBool::new(false));
        let worker_counters = counters.clone();
        let worker_stop = stop.clone();
        let worker = std::thread::spawn(move || {
            for index in 0..3 {
                send_mapping(
                    PcapMsg::DnsMapping {
                        ip: "127.0.0.1".parse().unwrap(),
                        hostname: format!("{index}.test"),
                        captured_at: SystemTime::now(),
                        ttl_seconds: 300,
                        offline: true,
                    },
                    &sender,
                    &worker_stop,
                    &worker_counters,
                );
            }
        });
        let mut names = Vec::new();
        for _ in 0..3 {
            let PcapMsg::DnsMapping { hostname, .. } =
                receiver.recv_timeout(Duration::from_secs(5)).unwrap()
            else {
                panic!("wrong mapping kind")
            };
            names.push(hostname);
        }
        worker.join().unwrap();
        assert_eq!(names, ["0.test", "1.test", "2.test"]);
        let health = counters.snapshot();
        assert_eq!(
            (health.mappings, health.delivered, health.mapping_lost),
            (3, 3, 0)
        );
        assert!(!health.unhealthy());
    }

    #[test]
    #[cfg(feature = "pcap")]
    fn capture_shutdown_exposes_a_panicked_worker() {
        let (_sender, receiver) = mpsc::sync_channel(1);
        let handle = PcapHandle {
            receiver,
            stop: Arc::new(AtomicBool::new(false)),
            counters: Arc::new(CaptureCounters::default()),
            handle: Some(std::thread::spawn(|| panic!("forced capture failure"))),
        };
        let health = handle.shutdown(None);
        assert_eq!(health.state, "failed");
        assert!(health.unhealthy());
        assert!(health.error.unwrap().contains("panicked"));
    }

    #[test]
    #[cfg(feature = "pcap")]
    fn unsupported_link_types_refuse_before_packet_parsing() {
        assert!(validate_datalink(pcap::Linktype::ETHERNET).is_ok());
        for link in [
            pcap::Linktype(0),
            pcap::Linktype(101),
            pcap::Linktype(113),
            pcap::Linktype(276),
        ] {
            assert!(
                validate_datalink(link)
                    .unwrap_err()
                    .contains("only Ethernet")
            );
        }
    }

    #[test]
    #[cfg(feature = "pcap")]
    fn ipv4_lengths_fragments_and_padding_cannot_forge_payload() {
        let valid = build_test_udp_packet_ipv4();
        assert_eq!(parse_transport_packet(&valid).unwrap().payload.len(), 8);
        for (field, value) in [
            (14, 0x65),
            (16, 0xff),
            (17, 0xff),
            (20, 0x20),
            (21, 1),
            (38, 0xff),
            (39, 0xff),
        ] {
            let mut packet = valid.clone();
            packet[field] = value;
            assert!(
                parse_transport_packet(&packet).is_none(),
                "accepted field {field}={value}"
            );
        }
        let mut padded = valid;
        padded.extend_from_slice(&[42; 100]);
        assert_eq!(parse_transport_packet(&padded).unwrap().payload.len(), 8);
    }

    #[test]
    #[cfg(feature = "pcap")]
    fn tls_record_and_handshake_boundaries_reject_trailing_bytes() {
        let valid = build_tls_client_hello("bounded.test");
        assert_eq!(parse_tls_sni(&valid).as_deref(), Some("bounded.test"));
        for length in [
            0u16,
            1,
            3,
            4,
            5,
            12,
            u16::from_be_bytes([valid[3], valid[4]]) - 1,
        ] {
            let mut packet = valid.clone();
            packet[3..5].copy_from_slice(&length.to_be_bytes());
            assert!(
                parse_tls_sni(&packet).is_none(),
                "accepted truncated record length {length}"
            );
        }
        let mut packet = valid;
        packet[6..9].copy_from_slice(&[0, 0, 1]);
        assert!(parse_tls_sni(&packet).is_none());
    }

    // ============================================================
    // DomainCache tests (no pcap feature required)
    // ============================================================

    #[test]
    fn domain_cache_new_is_empty() {
        let mut cache = DomainCache::with_max_entries(DEFAULT_CACHE_MAX_ENTRIES);
        let ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        assert!(
            cache
                .lookup(flow(ip, 443, 12345), 1, UNIX_EPOCH)
                .hostname
                .is_none()
        );
    }

    #[test]
    fn domain_cache_dns_insert_and_lookup() {
        let mut cache = DomainCache::with_max_entries(DEFAULT_CACHE_MAX_ENTRIES);
        let ip = IpAddr::V4(Ipv4Addr::new(142, 250, 189, 206));

        cache.apply_msg(PcapMsg::DnsMapping {
            ip,
            hostname: "www.google.com".to_string(),
            captured_at: SystemTime::now(),
            ttl_seconds: 300,
            offline: false,
        });

        // Lookup by IP (any port) should find DNS mapping
        for port in [443, 80] {
            let evidence = cache.lookup(flow(ip, port, 12345), 1, UNIX_EPOCH);
            assert_eq!(evidence.hostname.as_deref(), Some("www.google.com"));
            assert_eq!(evidence.source, Some(DomainSource::Dns));
            assert_eq!(evidence.scope, "host-ip");
        }
    }

    #[test]
    fn domain_cache_sni_insert_and_lookup() {
        let mut cache = DomainCache::with_max_entries(DEFAULT_CACHE_MAX_ENTRIES);
        let ip = IpAddr::V4(Ipv4Addr::new(104, 18, 32, 7));

        cache.apply_msg(PcapMsg::SniMapping {
            flow: flow(ip, 443, 12345),
            hostname: "api.anthropic.com".to_string(),
            captured_at: SystemTime::now(),
            offline: false,
        });

        let evidence = cache.lookup(flow(ip, 443, 12345), 1, UNIX_EPOCH);
        assert_eq!(evidence.hostname.as_deref(), Some("api.anthropic.com"));
        assert_eq!(evidence.source, Some(DomainSource::Sni));
        assert_eq!(evidence.scope, "socket-tuple");
        // Different port should not find SNI mapping
        assert!(
            cache
                .lookup(flow(ip, 80, 12345), 1, UNIX_EPOCH)
                .hostname
                .is_none()
        );
        assert!(
            cache
                .lookup(flow(ip, 443, 12346), 1, UNIX_EPOCH)
                .hostname
                .is_none()
        );
    }

    #[test]
    fn domain_cache_sni_preferred_over_dns() {
        let mut cache = DomainCache::with_max_entries(DEFAULT_CACHE_MAX_ENTRIES);
        let ip = IpAddr::V4(Ipv4Addr::new(104, 18, 32, 7));

        // Insert DNS mapping first (broader match)
        cache.apply_msg(PcapMsg::DnsMapping {
            ip,
            hostname: "cloudflare.net".to_string(),
            captured_at: SystemTime::now(),
            ttl_seconds: 300,
            offline: false,
        });

        // Insert SNI mapping (more specific)
        cache.apply_msg(PcapMsg::SniMapping {
            flow: flow(ip, 443, 12345),
            hostname: "api.anthropic.com".to_string(),
            captured_at: SystemTime::now(),
            offline: false,
        });

        // SNI should be preferred for exact port match
        let evidence = cache.lookup(flow(ip, 443, 12345), 1, UNIX_EPOCH);
        assert_eq!(evidence.hostname.as_deref(), Some("api.anthropic.com"));
        assert_eq!(evidence.source, Some(DomainSource::Sni));
        // DNS should be used for other ports
        let evidence = cache.lookup(flow(ip, 80, 12345), 1, UNIX_EPOCH);
        assert_eq!(evidence.hostname.as_deref(), Some("cloudflare.net"));
        assert_eq!(evidence.source, Some(DomainSource::Dns));
    }

    #[test]
    fn domain_cache_ipv6_support() {
        let mut cache = DomainCache::with_max_entries(DEFAULT_CACHE_MAX_ENTRIES);
        let ip = IpAddr::V6(Ipv6Addr::new(
            0x2607, 0xf8b0, 0x4004, 0x800, 0, 0, 0, 0x200e,
        ));

        cache.apply_msg(PcapMsg::DnsMapping {
            ip,
            hostname: "ipv6.google.com".to_string(),
            captured_at: SystemTime::now(),
            ttl_seconds: 300,
            offline: false,
        });

        let evidence = cache.lookup(flow(ip, 443, 12345), 1, UNIX_EPOCH);
        assert_eq!(evidence.hostname.as_deref(), Some("ipv6.google.com"));
        assert_eq!(evidence.source, Some(DomainSource::Dns));
    }

    #[test]
    fn domain_cache_preserves_conflicting_dns_candidates() {
        let mut cache = DomainCache::with_max_entries(DEFAULT_CACHE_MAX_ENTRIES);
        let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));

        cache.apply_msg(PcapMsg::DnsMapping {
            ip,
            hostname: "old.example.com".to_string(),
            captured_at: SystemTime::now(),
            ttl_seconds: 300,
            offline: false,
        });
        cache.apply_msg(PcapMsg::DnsMapping {
            ip,
            hostname: "new.example.com".to_string(),
            captured_at: SystemTime::now(),
            ttl_seconds: 300,
            offline: false,
        });

        let evidence = cache.lookup(flow(ip, 443, 12345), 1, UNIX_EPOCH);
        assert!(evidence.hostname.is_none() && evidence.source.is_none());
        assert_eq!(evidence.scope, "host-ip");
        assert_eq!(
            evidence.dns_candidates,
            ["new.example.com", "old.example.com"]
        );
    }

    #[test]
    fn separate_flows_keep_names_and_out_of_order_capture_cannot_overwrite() {
        let mut cache = DomainCache::with_max_entries(100);
        let now = SystemTime::now();
        let ip = "127.0.0.1".parse().unwrap();
        let first = flow(ip, 443, 40001);
        let second = flow(ip, 443, 40002);
        for (flow, hostname, age) in [
            (first, "a.test", 1),
            (second, "b.test", 1),
            (first, "older.test", 2),
        ] {
            cache.apply_msg(PcapMsg::SniMapping {
                flow,
                hostname: hostname.to_string(),
                captured_at: now - Duration::from_secs(age),
                offline: false,
            });
        }
        assert_eq!(
            cache.lookup(first, 11, UNIX_EPOCH).hostname.as_deref(),
            Some("a.test")
        );
        assert_eq!(
            cache.lookup(second, 12, UNIX_EPOCH).hostname.as_deref(),
            Some("b.test")
        );
        assert!(
            cache
                .lookup(flow(ip, 443, 40003), 13, UNIX_EPOCH)
                .hostname
                .is_none()
        );
    }

    #[test]
    fn reused_or_retired_flow_requires_a_new_capture() {
        let mut cache = DomainCache::with_max_entries(100);
        let flow = flow("127.0.0.1".parse().unwrap(), 443, 40001);
        let old = SystemTime::now() - Duration::from_secs(1);
        let message = |name: &str, captured_at| PcapMsg::SniMapping {
            flow,
            hostname: name.to_string(),
            captured_at,
            offline: false,
        };
        cache.apply_msg(message("old.test", old));
        assert_eq!(
            cache.lookup(flow, 11, UNIX_EPOCH).hostname.as_deref(),
            Some("old.test")
        );
        assert!(cache.lookup(flow, 22, UNIX_EPOCH).hostname.is_none());
        cache.apply_msg(message("old.test", old));
        assert!(cache.lookup(flow, 22, UNIX_EPOCH).hostname.is_none());
        cache.apply_msg(message("new.test", SystemTime::now()));
        assert_eq!(
            cache.lookup(flow, 22, UNIX_EPOCH).hostname.as_deref(),
            Some("new.test")
        );
        cache.retire_flow(flow, 22, SystemTime::now());
        cache.apply_msg(message("old.test", old));
        assert!(cache.lookup(flow, 33, UNIX_EPOCH).hostname.is_none());
        cache.apply_msg(message("next.test", SystemTime::now()));
        assert_eq!(
            cache.lookup(flow, 33, UNIX_EPOCH).hostname.as_deref(),
            Some("next.test")
        );
    }

    #[test]
    fn captured_ttl_future_clock_and_observation_floor_are_enforced() {
        let now = SystemTime::now();
        let ip = "127.0.0.1".parse().unwrap();
        let flow = flow(ip, 443, 40001);
        let mut cache = DomainCache::with_max_entries(100);
        cache.apply_msg(PcapMsg::DnsMapping {
            ip,
            hostname: "expired.test".to_string(),
            captured_at: now - Duration::from_secs(2),
            ttl_seconds: 1,
            offline: true,
        });
        cache.apply_msg(PcapMsg::DnsMapping {
            ip,
            hostname: "LIVE.test".to_string(),
            captured_at: now,
            ttl_seconds: 30,
            offline: true,
        });
        let evidence = cache.lookup(flow, 1, UNIX_EPOCH);
        assert_eq!(evidence.hostname.as_deref(), Some("live.test"));
        assert_eq!(evidence.dns_candidates, ["live.test"]);
        assert!(evidence.offline);
        cache.apply_msg(PcapMsg::DnsMapping {
            ip,
            hostname: "live.test".to_string(),
            captured_at: now,
            ttl_seconds: 0,
            offline: true,
        });
        assert!(cache.lookup(flow, 1, UNIX_EPOCH).hostname.is_none());
        for captured_at in [
            now - Duration::from_secs(601),
            now + Duration::from_secs(60),
        ] {
            cache.apply_msg(PcapMsg::SniMapping {
                flow,
                hostname: "invalid-time.test".to_string(),
                captured_at,
                offline: false,
            });
            assert!(cache.lookup(flow, 1, UNIX_EPOCH).hostname.is_none());
        }
        // Independent flow avoids the deliberate newer-capture ordering guard.
        let fresh = FlowKey {
            local_port: 40002,
            ..flow
        };
        cache.apply_msg(PcapMsg::SniMapping {
            flow: fresh,
            hostname: "prior.test".to_string(),
            captured_at: now - Duration::from_secs(2),
            offline: false,
        });
        assert!(
            cache
                .lookup(fresh, 2, now - Duration::from_secs(1))
                .hostname
                .is_none()
        );
    }

    #[test]
    fn equal_time_conflicting_sni_is_unresolved_and_dns_eviction_preserves_ambiguity() {
        let now = SystemTime::now();
        let ip = "127.0.0.1".parse().unwrap();
        let flow = flow(ip, 443, 40001);
        let mut cache = DomainCache::with_max_entries(2);
        for name in ["a.test", "b.test", "a.test"] {
            cache.apply_msg(PcapMsg::SniMapping {
                flow,
                hostname: name.to_string(),
                captured_at: now,
                offline: false,
            });
        }
        let evidence = cache.lookup(flow, 1, UNIX_EPOCH);
        assert!(evidence.hostname.is_none() && evidence.sni_ambiguous);
        for name in ["first.test", "second.test"] {
            cache.apply_msg(PcapMsg::DnsMapping {
                ip,
                hostname: name.to_string(),
                captured_at: now - Duration::from_secs(1),
                ttl_seconds: 30,
                offline: false,
            });
        }
        assert!(
            cache.lookup(flow, 1, UNIX_EPOCH).hostname.is_none(),
            "eviction promoted one retained DNS alias to false uniqueness"
        );
        assert!(cache.dns_entries + cache.by_flow.len() <= 2);
    }

    #[test]
    fn domain_cache_eviction_when_full() {
        // Create cache with small max_entries for testing
        let mut cache = DomainCache {
            by_flow: HashMap::new(),
            by_ip: HashMap::new(),
            dns_entries: 0,
            last_cleanup: SystemTime::now(),
            max_entries: 3,
        };

        // Insert 4 entries - should trigger eviction
        for i in 0..4u8 {
            let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, i));
            cache.apply_msg(PcapMsg::DnsMapping {
                ip,
                hostname: format!("host{}.example.com", i),
                captured_at: SystemTime::now(),
                ttl_seconds: 300,
                offline: false,
            });
            // Small sleep to ensure different timestamps
            std::thread::sleep(std::time::Duration::from_millis(1));
        }

        // Total entries should be <= max_entries
        let latest_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
        let evidence = cache.lookup(flow(latest_ip, 443, 12345), 1, UNIX_EPOCH);
        assert_eq!(evidence.hostname.as_deref(), Some("host3.example.com"));
        assert_eq!(evidence.source, Some(DomainSource::Dns));
        assert_eq!(cache.dns_entries + cache.by_flow.len(), 3);
    }

    #[test]
    fn domain_source_enum_equality() {
        assert_eq!(DomainSource::Dns, DomainSource::Dns);
        assert_eq!(DomainSource::Sni, DomainSource::Sni);
        assert_ne!(DomainSource::Dns, DomainSource::Sni);
        assert_eq!(DomainSource::Ptr, DomainSource::Ptr);
        assert_eq!(DomainSource::Dns.label(), "dns");
        assert_eq!(DomainSource::Sni.label(), "sni");
        assert_eq!(DomainSource::Ptr.label(), "ptr");
    }
    #[test]
    fn pcap_msg_debug_format() {
        let dns_msg = PcapMsg::DnsMapping {
            ip: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            hostname: "dns.google".to_string(),
            captured_at: SystemTime::now(),
            ttl_seconds: 300,
            offline: false,
        };
        let debug_str = format!("{:?}", dns_msg);
        assert!(debug_str.contains("DnsMapping"));
        assert!(debug_str.contains("dns.google"));

        let sni_msg = PcapMsg::SniMapping {
            flow: flow(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 443, 12345),
            hostname: "example.com".to_string(),
            captured_at: SystemTime::now(),
            offline: false,
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
        let response = result.unwrap();
        assert_eq!(response.hostname, "example.com");
        assert_eq!(
            response.answers,
            [(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 3600)]
        );
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
        let response = result.unwrap();
        assert_eq!(response.hostname, "ipv6.example.com");
        assert_eq!(response.answers.len(), 1);
        assert_eq!(
            response.answers[0],
            (
                IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1)),
                3600
            )
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
        let response = result.unwrap();
        assert_eq!(response.hostname, "multi.example.com");
        assert_eq!(response.answers.len(), 2);
        assert!(
            response
                .answers
                .contains(&(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 3600))
        );
        assert!(
            response
                .answers
                .contains(&(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 3600))
        );
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
    fn transport_parse_qinq_double_tagged_dns() {
        // QinQ frame: 802.1ad outer (0x88A8) + 802.1Q inner (0x8100), UDP dst 53
        // carrying a valid DNS response. The DNS payload must parse end to end.
        let packet = build_test_stacked_vlan_packet(&[0x88A8, 0x8100]);
        let result = parse_transport_packet(&packet);
        assert!(result.is_some(), "QinQ double-tagged frame should parse");
        let tp = result.unwrap();
        assert!(matches!(tp.proto, TransportProto::Udp));
        assert_eq!(tp.dst_port, 53);

        let response = parse_dns_response(tp.payload).expect("DNS payload should parse");
        assert_eq!(response.hostname, "example.com");
        assert_eq!(
            response.answers,
            [(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 3600)]
        );
    }

    #[cfg(feature = "pcap")]
    #[test]
    fn transport_rejects_triple_vlan_stack() {
        // Three stacked tags exceed the supported depth: reject instead of looping.
        let packet = build_test_stacked_vlan_packet(&[0x88A8, 0x8100, 0x9100]);
        let result = parse_transport_packet(&packet);
        assert!(
            result.is_none(),
            "triple-stacked VLAN frames must be rejected"
        );
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
        let mut cache = DomainCache::with_max_entries(DEFAULT_CACHE_MAX_ENTRIES);

        // Simulate DNS response message
        let msg = PcapMsg::DnsMapping {
            ip: IpAddr::V4(Ipv4Addr::new(140, 82, 114, 4)),
            hostname: "github.com".to_string(),
            captured_at: SystemTime::now(),
            ttl_seconds: 300,
            offline: false,
        };
        cache.apply_msg(msg);

        // Connection to that IP should resolve
        let evidence = cache.lookup(
            flow(IpAddr::V4(Ipv4Addr::new(140, 82, 114, 4)), 443, 12345),
            1,
            UNIX_EPOCH,
        );
        assert_eq!(evidence.hostname.as_deref(), Some("github.com"));
        assert_eq!(evidence.source, Some(DomainSource::Dns));
    }

    #[cfg(feature = "pcap")]
    #[test]
    fn integration_sni_to_cache() {
        let mut cache = DomainCache::with_max_entries(DEFAULT_CACHE_MAX_ENTRIES);

        // Simulate SNI message
        let msg = PcapMsg::SniMapping {
            flow: flow(IpAddr::V4(Ipv4Addr::new(104, 18, 32, 7)), 443, 12345),
            hostname: "api.anthropic.com".to_string(),
            captured_at: SystemTime::now(),
            offline: false,
        };
        cache.apply_msg(msg);

        // Exact IP+port lookup should resolve
        let evidence = cache.lookup(
            flow(IpAddr::V4(Ipv4Addr::new(104, 18, 32, 7)), 443, 12345),
            1,
            UNIX_EPOCH,
        );
        assert_eq!(evidence.hostname.as_deref(), Some("api.anthropic.com"));
        assert_eq!(evidence.source, Some(DomainSource::Sni));
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
        let record_len = 4 + 2 + 32 + 1 + 4 + 2 + 2 + extensions_len;
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
        let record_len = 4 + 2 + 32 + 1 + 4 + 2 + 2;
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
        packet.extend_from_slice(&[0x00, 0x24]); // Total length: 20 IPv4 + 8 UDP + 8 payload
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
        packet.extend_from_slice(&[0x00, 0x28]); // Total length: 20 IPv4 + 20 TCP
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
    #[test]
    fn ipv6_atomic_fragments_parse_but_partial_fragments_cannot_supply_payload() {
        let mut packet = vec![0; 14 + 40 + 8 + 8];
        packet[12..14].copy_from_slice(&[0x86, 0xdd]);
        packet[14] = 0x60;
        packet[18..20].copy_from_slice(&16u16.to_be_bytes());
        packet[20] = 44; // Fragment extension, followed by a complete UDP header.
        packet[21] = 64;
        packet[54] = 17;
        packet[62..64].copy_from_slice(&1234u16.to_be_bytes());
        packet[64..66].copy_from_slice(&53u16.to_be_bytes());
        packet[66..68].copy_from_slice(&8u16.to_be_bytes());
        let parsed = parse_transport_packet(&packet).expect("complete atomic fragment");
        assert_eq!(parsed.dst_port, 53);
        assert!(parsed.payload.is_empty());
        for fragment_field in [1u16, 8, 9, 0xfff8] {
            let mut partial = packet.clone();
            partial[56..58].copy_from_slice(&fragment_field.to_be_bytes());
            assert!(
                parse_transport_packet(&partial).is_none(),
                "accepted partial IPv6 fragment field {fragment_field}"
            );
        }
        packet.truncate(61);
        assert!(parse_transport_packet(&packet).is_none());
    }

    #[cfg(feature = "pcap")]
    /// Build an Ethernet frame with the given stack of VLAN tag ethertypes
    /// (outermost first), carrying IPv4/UDP dst 53 with a minimal DNS response.
    fn build_test_stacked_vlan_packet(tag_ethertypes: &[u16]) -> Vec<u8> {
        let dns_payload: &[u8] = &[
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
            93, 184, 216, 34, // RDATA
        ];

        let mut packet = Vec::new();
        packet.extend_from_slice(&[0; 12]); // MAC addresses
        for (i, ethertype) in tag_ethertypes.iter().enumerate() {
            packet.extend_from_slice(&ethertype.to_be_bytes());
            // TCI: VLAN ID 100 + i so stacked tags stay distinguishable
            packet.extend_from_slice(&(100u16 + i as u16).to_be_bytes());
        }
        packet.extend_from_slice(&[0x08, 0x00]); // IPv4 ethertype

        // IPv4 header (20 bytes) with correct total length
        let udp_len = 8 + dns_payload.len();
        let ip_total_len = 20 + udp_len;
        packet.push(0x45);
        packet.push(0x00);
        packet.extend_from_slice(&(ip_total_len as u16).to_be_bytes());
        packet.extend_from_slice(&[0x00, 0x00]); // ID
        packet.extend_from_slice(&[0x00, 0x00]); // flags/frag
        packet.push(64);
        packet.push(17); // UDP
        packet.extend_from_slice(&[0x00, 0x00]); // checksum
        packet.extend_from_slice(&[10, 0, 0, 1]);
        packet.extend_from_slice(&[10, 0, 0, 2]);

        // UDP header with dst port 53 (DNS)
        packet.extend_from_slice(&(1234u16).to_be_bytes());
        packet.extend_from_slice(&(53u16).to_be_bytes());
        packet.extend_from_slice(&(udp_len as u16).to_be_bytes());
        packet.extend_from_slice(&[0x00, 0x00]); // checksum

        packet.extend_from_slice(dns_payload);
        packet
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
        packet.extend_from_slice(&[0x00, 0x1c]); // 20 IPv4 + 8 UDP
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
        packet.extend_from_slice(&[0x00, 0x08]); // UDP header only
        packet.extend_from_slice(&[0x00, 0x00]);

        packet
    }
}
