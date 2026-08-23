> **As-built note (2026-08-23):** Implemented as designed except: no port 80 in the BPF
> filter; the "background sweep" is lazy cleanup inside cache lookups (idle caches persist);
> TTLs and the 10k cap are compile-time constants — the tuning-flag table below was not
> implemented (`--pcap-interface` / `--pcap-cache-max` are tracked separately). DomainSource
> currently has Dns/Sni variants only; provenance surfacing is tracked separately.

# Pcap Domain Attribution Design

Status: design for bead rust_agent_network_observer-35w.1.1

## Problem Statement

PTR (reverse DNS) lookups are unreliable for domain attribution:
- Many IPs map to CDN hostnames (e.g., `a23-45-67-89.deploy.static.akamaitechnologies.com`)
- Multiple domains can share the same IP (virtual hosting)
- PTR records often don't exist or return generic provider names

True domain attribution requires capturing the **original destination hostname** from either:
1. DNS query/response packets
2. TLS SNI (Server Name Indication) extension in ClientHello

## Dataflow Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Network Interface                             │
└─────────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    libpcap Capture Thread                            │
│  Filter: "port 53 or port 443 or port 80"                           │
│  (Or more specific: "udp port 53 or tcp port 443 or tcp port 80")   │
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
                    │   - Response IP(s)        │   - Dest IP:port
                    │                           │
                    ▼                           ▼
         ┌─────────────────────────────────────────────────┐
         │              Domain Mapping Cache                │
         │  Key: (remote_ip, remote_port) or (remote_ip)   │
         │  Value: { hostname, source: dns|sni, ttl }      │
         └─────────────────────────────────────────────────┘
                                  │
                                  ▼
         ┌─────────────────────────────────────────────────┐
         │              Main Polling Thread                 │
         │  When new connection detected:                   │
         │  1. Lookup (remote_ip, remote_port) in cache    │
         │  2. If miss, lookup (remote_ip) only            │
         │  3. If miss, fall back to PTR                   │
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

// Cache keyed by (IP, Option<Port>)
// - SNI mappings use (IP, Port) for precision
// - DNS mappings use (IP, None) since response applies to all ports
struct DomainCache {
    // Primary lookup: (ip, port) -> mapping
    by_ip_port: HashMap<(IpAddr, u16), DomainMapping>,

    // Fallback lookup: ip -> mapping (for DNS-only entries)
    by_ip: HashMap<IpAddr, DomainMapping>,
}
```

### TTL Strategy

| Source | Default TTL | Rationale |
|--------|-------------|-----------|
| DNS | 5 minutes | DNS TTLs vary; 5m balances freshness vs. memory |
| SNI | 10 minutes | Connection-specific; longer TTL safe |
| PTR | 10 minutes | Fallback; matches existing behavior |

### Eviction

- Lazy eviction on lookup (check TTL, remove if expired)
- Background sweep every 60 seconds to bound memory
- Max cache size: 10,000 entries (configurable via `--pcap-cache-max`)

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
3. Insert into cache: `by_ip[resolved_ip] = hostname`

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
5. Insert: `by_ip_port[(dest_ip, dest_port)] = hostname`

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
- Implementation: Parse UDP only initially; TCP DNS is rare for client queries

### TLS SNI
- **TCP port 443**: Standard HTTPS
- **TCP other ports**: Custom TLS ports (user can specify `--pcap-sni-ports`)
- Implementation: Track TCP stream state minimally; SNI is in first packet

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
fn resolve_domain(ip: IpAddr, port: u16, cache: &DomainCache, dns_cache: &DnsCache) -> (String, DomainSource) {
    // 1. Check pcap cache (IP + port)
    if let Some(mapping) = cache.get(ip, port) {
        if !mapping.is_expired() {
            return (mapping.hostname.clone(), mapping.source);
        }
    }

    // 2. Check pcap cache (IP only, for DNS)
    if let Some(mapping) = cache.get_ip_only(ip) {
        if !mapping.is_expired() {
            return (mapping.hostname.clone(), mapping.source);
        }
    }

    // 3. Fall back to PTR
    match reverse_dns(ip) {
        Some(hostname) => (hostname, DomainSource::Ptr),
        None => ("unknown".to_string(), DomainSource::Ptr),
    }
}
```

### Thread Communication

```rust
// Pcap thread sends mappings via channel
enum PcapMsg {
    DnsMapping { ip: IpAddr, hostname: String },
    SniMapping { ip: IpAddr, port: u16, hostname: String },
}

// Main thread receives and updates cache
fn update_domain_cache(cache: &mut DomainCache, msg: PcapMsg) {
    match msg {
        PcapMsg::DnsMapping { ip, hostname } => {
            cache.insert_dns(ip, hostname);
        }
        PcapMsg::SniMapping { ip, port, hostname } => {
            cache.insert_sni(ip, port, hostname);
        }
    }
}
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
4. **Capture errors**: Log to stderr, continue with PTR fallback

## Performance Considerations

1. **BPF filter**: Use `port 53 or port 443` to minimize packets processed
2. **Minimal parsing**: Only extract what's needed (hostname + IP)
3. **Bounded cache**: Prevent unbounded memory growth
4. **Lazy eviction**: Amortize cleanup cost
5. **Channel buffer**: Use bounded channel (1000 messages) with try_send
