> **As-built note (2026-10-13):** Capture filters UDP/TCP 53 and TCP 443. Ethernet
> with up to two VLAN tags is supported; other datalink types refuse with fallback.
> `--pcap-interface` and `--pcap-cache-max` work. DNS uses observed answer TTL,
> capped at 300 seconds; SNI cache TTL remains 600 seconds. Lazy cleanup and the
> configured cap bound DNS candidates plus flow records. DNS ambiguity is
> explicit host-IP evidence; SNI uses the complete tuple, observed inode and
> original capture time. Late associations correct the original SQLite row and
> emit separate live/file metadata updates. Unused TTL/SNI-port tuning flags,
> unbounded stream reassembly, encrypted DNS and ECH inner names remain outside
> the implemented scope. The implementation graph's independent proofs stay open.

# Pcap Domain Attribution Design

Status: design for bead rust_agent_network_observer-35w.1.1

## Problem Statement

PTR (reverse DNS) lookups are unreliable for domain attribution:
- Many IPs map to CDN hostnames (e.g., `a23-45-67-89.deploy.static.akamaitechnologies.com`)
- Multiple domains can share the same IP (virtual hosting)
- PTR records often don't exist or return generic provider names

Hostname evidence comes from either:
1. DNS query/response packets
2. Visible TLS SNI (Server Name Indication) in ClientHello for a socket tuple

DNS does not establish which monitored process issued a query. Multiple
unexpired names for one IP remain ambiguous. Captured outer SNI does not expose
an ECH inner hostname. Neither source proves connect-versus-accept direction or
events lost between `/proc` polls.

## Dataflow Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Network Interface                             │
└─────────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    libpcap Capture Thread                            │
│  Filter: "udp port 53 or tcp port 53 or tcp port 443"                │
└─────────────────────────────────────────────────────────────────────┘
                                  │
                    ┌─────────────┴─────────────┐
                    ▼                           ▼
         ┌──────────────────┐        ┌──────────────────┐
         │  DNS Parser      │        │  TLS SNI Parser  │
         │  (UDP/TCP:53)    │        │  (TCP:443)       │
         └──────────────────┘        └──────────────────┘
                    │                           │
                    │   Extract:                │   Extract:
                    │   - Query name            │   - SNI hostname
                    │   - Response IP(s)/TTL    │   - Full tuple/time
                    │                           │
                    ▼                           ▼
         ┌─────────────────────────────────────────────────┐
         │              Domain Mapping Cache                │
         │  SNI: full tuple + observed inode binding      │
         │  DNS: IP -> timestamped candidate names/TTLs   │
         └─────────────────────────────────────────────────┘
                                  │
                                  ▼
         ┌─────────────────────────────────────────────────┐
         │              Main Polling Thread                 │
         │  Initial and later observed socket polls:      │
         │  1. Check tuple, inode and capture timestamp    │
         │  2. Use DNS for one unexpired candidate         │
         │  3. Preserve ambiguity with labeled PTR fallback│
         └─────────────────────────────────────────────────┘
                                  │
                                  ▼
         ┌─────────────────────────────────────────────────┐
         │              Event Emission                      │
         │  { domain: "api.anthropic.com", source: "sni" } │
         └─────────────────────────────────────────────────┘
```

## Domain Mapping Cache

### Data Structure

```rust
struct DomainMapping {
    hostname: String,
    source: DomainSource,      // Dns, Sni, Ptr
    captured_at: SystemTime,
    ttl_seconds: u64,
}

enum DomainSource {
    Dns,    // From DNS response
    Sni,    // From TLS ClientHello
    Ptr,    // Fallback reverse lookup
}

// SNI maps complete tuples; DNS remains host-global IP evidence.
struct DomainCache {
    by_flow: HashMap<FlowKey, FlowMapping>,

    // Fallback lookup: ip -> mapping (for DNS-only entries)
    by_ip: HashMap<IpAddr, BTreeMap<String, DomainMapping>>,
}
```

### TTL Strategy

| Source | Default TTL | Rationale |
|--------|-------------|-----------|
| DNS | Observed TTL capped at 5 minutes | Never extends a short TTL; zero TTL is not cached |
| SNI | 10 minutes in cache | Tuple, capture-time and known inode/retirement checks |
| PTR | 10 minutes | Fallback; matches existing behavior |

### Eviction

- Lazy eviction on lookup (check TTL, remove if expired)
- Lazy sweep during lookups every 60 seconds
- Max cache size: 10,000 entries (configurable via `--pcap-cache-max`)
- Evict entire DNS candidate groups so pruning cannot turn ambiguity into false
  uniqueness. Emitted name samples are sorted and capped at eight, with the full
  candidate count retained. The same held inode retains its earlier observed SNI
  after cache expiry; known inode changes/retired tuples require fresh capture.

## DNS Parsing

### Packet Structure

```
DNS Query (UDP/TCP port 53):
  - Transaction ID (2 bytes)
  - Flags (2 bytes)
  - Questions (query names)

DNS Response:
  - Same structure + Answer section with resolved IPs
```

### What to Extract

1. **DNS Responses only** (QR bit = 1)
2. For each A/AAAA record in Answer section:
   - Query name (the original hostname)
   - Resolved IP address
3. Preserve hostname candidates, answer TTLs and original packet capture time.

### Minimal Parsing Approach

- Use a minimal DNS parser (not full RFC-compliant)
- Only parse A (IPv4) and AAAA (IPv6) responses
- Ignore CNAME chains, MX, TXT, etc.
- Skip malformed packets with length check

```rust
fn parse_dns_response(packet: &[u8]) -> Option<Vec<(IpAddr, String)>> {
    // Quick validation
    if packet.len() < 12 { return None; }

    // Check QR bit (response)
    let flags = u16::from_be_bytes([packet[2], packet[3]]);
    if (flags & 0x8000) == 0 { return None; }  // Not a response

    // Parse question name (for hostname)
    // Parse answer records (for IPs)
    // ...
}
```

## TLS SNI Parsing

### Packet Structure

```
TLS ClientHello (first packet of TLS handshake):
  - Content Type: 0x16 (Handshake)
  - Version: 0x0301 (TLS 1.0) or 0x0303 (TLS 1.2)
  - Handshake Type: 0x01 (ClientHello)
  - Extensions:
    - Extension Type 0x0000 = SNI
    - SNI contains hostname
```

### What to Extract

1. Filter: TCP packets to port 443 (or user-specified ports)
2. Match: Content Type = 0x16, Handshake Type = 0x01
3. Parse: Find SNI extension (type 0x0000) in extensions
4. Extract: Hostname from SNI
5. Insert by complete local/remote tuple and capture time. Older reordered
   messages cannot replace newer evidence; equal-time conflicts stay ambiguous.

### Minimal Parsing Approach

```rust
fn parse_tls_sni(packet: &[u8], dest_ip: IpAddr, dest_port: u16) -> Option<(IpAddr, u16, String)> {
    // Check TLS record layer
    if packet.len() < 5 { return None; }
    if packet[0] != 0x16 { return None; }  // Not handshake

    // Check handshake type
    let handshake_start = 5;
    if packet.get(handshake_start)? != &0x01 { return None; }  // Not ClientHello

    // Find SNI extension
    // Return (dest_ip, dest_port, hostname)
}
```

## IPv4 vs IPv6 Handling

| Layer | IPv4 | IPv6 |
|-------|------|------|
| IP Header | 20+ bytes, check IHL | 40 bytes fixed |
| Protocol | Header byte 9 (TCP=6, UDP=17) | Next Header byte 6 |
| DNS | Same parsing | Same parsing |
| SNI | Same parsing | Same parsing |
| Cache Key | `IpAddr::V4(...)` | `IpAddr::V6(...)` |

Both are stored in the same cache; `IpAddr` enum handles distinction.

## UDP vs TCP Handling

### DNS
- **UDP port 53**: Most DNS queries (single packet)
- **TCP port 53**: Large responses, zone transfers (uncommon for lookup)
- Implementation: UDP and complete length-prefixed TCP DNS messages are parsed

### TLS SNI
- **TCP port 443**: Standard HTTPS
- **TCP other ports**: Not selected; `--pcap-sni-ports` is not implemented
- Implementation: Complete visible ClientHello transport payload; no stream reassembly

## Integration with Main Loop

### Startup

```rust
if args.domain_mode == DomainMode::Pcap {
    // Check for elevated privileges
    if !can_capture_packets() {
        eprintln!("Warning: pcap capture requires elevated privileges");
        eprintln!("Falling back to PTR mode");
        args.domain_mode = DomainMode::Ptr;
    } else {
        pcap_thread = Some(start_pcap_capture(args.clone()));
    }
}
```

### Connection Detection

```rust
// Conceptual lookup; production resolve_observed_domain supplies these fields
// from ConnKey and its observation window, preserving DNS ambiguity for PTR.
fn connection_evidence(cache: &mut DomainCache, flow: FlowKey,
                       inode: u64, not_before: SystemTime) -> DomainEvidence {
    cache.lookup(flow, inode, not_before)
}
```

### Thread Communication

```rust
// Pcap thread sends mappings via channel
enum PcapMsg {
    DnsMapping { ip: IpAddr, hostname: String, captured_at: SystemTime,
                 ttl_seconds: u32, offline: bool },
    SniMapping { flow: FlowKey, hostname: String, captured_at: SystemTime,
                 offline: bool },
}

// Main consumes messages with DomainCache::apply_msg. SQLite DomainUpdate
// targets the original run_id/observation_id and adds no connection/event row.
```

## Feature Gating

Pcap support is compile-time optional:

```toml
# Cargo.toml
[features]
default = []
pcap = ["pcap"]  # pcap crate dependency
```

```rust
#[cfg(feature = "pcap")]
mod pcap_capture {
    // All pcap-related code
}

#[cfg(not(feature = "pcap"))]
fn start_pcap_capture(_args: &MonitorArgs) -> Option<PcapHandle> {
    eprintln!("Warning: rano built without pcap support");
    None
}
```

## Configuration Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--domain-mode pcap` | - | Enable pcap capture mode |
| `--pcap-interface <if>` | auto | Network interface to capture |
| `--pcap-dns-ttl <sec>` | 300 | TTL for DNS-derived mappings |
| `--pcap-sni-ttl <sec>` | 600 | TTL for SNI-derived mappings |
| `--pcap-cache-max <n>` | 10000 | Max entries in domain cache |
| `--pcap-sni-ports <ports>` | 443 | Comma-separated ports for SNI capture |

## Fallback Behavior

1. **Build without pcap feature**: `--domain-mode pcap` warns and uses PTR
2. **Insufficient privileges**: Warn and fall back to PTR
3. **Interface not found**: Error with available interfaces list
4. **Runtime capture errors/loss**: Typed health, stderr/file warning, PTR or
   unresolved fallback, preserved valid socket observations and nonzero exit
5. **Offline EOF**: Successful `complete` state; original timestamps retained

Regular-file replay streams through bounded backpressure before the first socket
poll, including `--once`; fixtures larger than the 1000-message queue retain their
tail. Live drains are bounded per poll and idle timeouts continue capture. Final
JSON/pretty/file summaries expose packets, rejected frames, mappings, delivery,
drain, loss, kernel/interface drop snapshots, state and error. These counters
describe parser messages; expired evidence can remain unresolved after draining.
Malformed lengths and unsupported fragments cannot supply DNS/SNI, and TLS
extraction requires a complete visible ClientHello transport payload.

## Performance Considerations

1. **BPF filter**: DNS/TLS transport filters have separate untagged, one-VLAN
   and two-VLAN branches; a port-only filter would hide supported tagged frames.
2. **Minimal parsing**: Extract hostname, full tuple, capture time and DNS TTL
3. **Bounded cache**: Prevent unbounded memory growth
4. **Lazy eviction**: Amortize cleanup cost
5. **Channel buffer**: A bounded 1000-message channel reports live mapping loss;
   finite offline replay retries with backpressure until consumed or stopped.
