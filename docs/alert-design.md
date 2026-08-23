> **As-built note (2026-08-23):** The `alerts` table, its views, and `--alert-domain-regex`
> below were NOT implemented. Alerts denormalize onto `events.alert=1` (see README) and
> domain matching uses the in-tree glob matcher only. Thresholds fire at `>=` the value.
> JSON alerts go to stdout (interleaved with events); pretty alerts to stderr. The rest of
> this document describes shipped behavior.

# Alert System Design

Status: design for bead bd-1jj (parent: bd-2iu)

## Overview

The alert system transforms rano from a passive observer into an active monitoring tool. Users can set thresholds and pattern matches to be notified when suspicious or notable network activity occurs, without watching output constantly.

## CLI Design

```bash
# Domain pattern alerts (glob or regex)
rano --alert-domain "*.evil.com"
rano --alert-domain "malware*" --alert-domain "*.suspicious.io"
rano --alert-domain-regex "^(api|www)\.attacker\.(com|net)$"

# Connection count thresholds
rano --alert-max-connections 100
rano --alert-max-per-provider 50

# Duration threshold (flag long-lived connections)
rano --alert-duration-ms 30000

# Unknown domain alert (unresolved reverse DNS)
rano --alert-unknown-domain

# Alert output options
rano --alert-bell              # Ring terminal bell on alert
rano --alert-cooldown-ms 5000  # Suppress duplicate alerts within window
```

### Flag Summary

| Flag | Description | Default |
|------|-------------|---------|
| `--alert-domain <pattern>` | Glob pattern for domains to alert on (repeatable) | - |
| `--alert-domain-regex <regex>` | Regex pattern for domains (repeatable) | - |
| `--alert-max-connections <n>` | Alert when total active connections exceed N | - |
| `--alert-max-per-provider <n>` | Alert when any provider exceeds N connections | - |
| `--alert-duration-ms <ms>` | Alert on connections lasting longer than N ms | - |
| `--alert-unknown-domain` | Alert on connections to unresolved domains | false |
| `--alert-bell` | Ring terminal bell on alerts | false |
| `--alert-cooldown-ms <ms>` | Suppress duplicate alerts within window | 10000 |
| `--no-alerts` | Disable all alerting (useful with config file) | false |

### Config File Support

```ini
# ~/.config/rano/config.conf
alert_domain=*.evil.com,malware*
alert_domain_regex=^attacker\.(com|net)$
alert_max_connections=100
alert_max_per_provider=50
alert_duration_ms=30000
alert_unknown_domain=true
alert_bell=false
alert_cooldown_ms=10000
```

## Data Structures

### AlertConfig Struct

```rust
#[derive(Clone, Debug)]
struct AlertConfig {
    /// Glob patterns for domain matching (case-insensitive)
    domain_patterns: Vec<String>,

    /// Compiled regex patterns for domain matching
    domain_regexes: Vec<Regex>,

    /// Alert when total active connections exceed this
    max_connections: Option<u64>,

    /// Alert when any single provider exceeds this
    max_per_provider: Option<u64>,

    /// Alert on connections longer than this (milliseconds)
    duration_threshold_ms: Option<u64>,

    /// Alert on connections with unresolved domain
    alert_unknown_domain: bool,

    /// Ring terminal bell on alert
    bell: bool,

    /// Cooldown between duplicate alerts (milliseconds)
    cooldown_ms: u64,
}

impl Default for AlertConfig {
    fn default() -> Self {
        Self {
            domain_patterns: Vec::new(),
            domain_regexes: Vec::new(),
            max_connections: None,
            max_per_provider: None,
            duration_threshold_ms: None,
            alert_unknown_domain: false,
            bell: false,
            cooldown_ms: 10_000,
        }
    }
}
```

### Alert Event Structure

```rust
#[derive(Clone, Debug)]
enum AlertKind {
    /// Domain matched a pattern
    DomainMatch { pattern: String },

    /// Total connections exceeded threshold
    MaxConnections { current: u64, threshold: u64 },

    /// Provider connections exceeded threshold
    MaxPerProvider { provider: Provider, current: u64, threshold: u64 },

    /// Connection exceeded duration threshold
    LongDuration { duration_ms: u64, threshold_ms: u64 },

    /// Connection to unresolved domain
    UnknownDomain,
}

#[derive(Clone, Debug)]
struct Alert {
    /// When the alert was triggered
    ts: SystemTime,

    /// Type of alert
    kind: AlertKind,

    /// Severity level
    severity: AlertSeverity,

    /// Associated connection (if applicable)
    conn_key: Option<ConnKey>,

    /// Associated connection info
    conn_info: Option<ConnInfo>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AlertSeverity {
    Warning,  // Yellow - approaching threshold, unknown domain
    Critical, // Red - threshold exceeded, domain match
}
```

### Alert State Tracking (Cooldown)

```rust
#[derive(Debug)]
struct AlertState {
    /// Last alert time per alert signature
    last_alert: HashMap<AlertSignature, SystemTime>,

    /// Total alerts triggered this session
    alert_count: u64,

    /// Alerts suppressed due to cooldown
    suppressed_count: u64,
}

/// Unique signature for deduplication
#[derive(Clone, Debug, Hash, Eq, PartialEq)]
enum AlertSignature {
    DomainMatch { domain: String, pattern: String },
    MaxConnections,
    MaxPerProvider { provider: Provider },
    LongDuration { conn_key: ConnKey },
    UnknownDomain { remote_ip: IpAddr },
}
```

## SQLite Schema Extension

### Alerts Table

```sql
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    run_id TEXT,
    kind TEXT NOT NULL,           -- 'domain_match', 'max_connections', 'max_per_provider', 'long_duration', 'unknown_domain'
    severity TEXT NOT NULL,       -- 'warning', 'critical'
    pattern TEXT,                 -- For domain_match: the pattern that matched
    threshold INTEGER,            -- For thresholds: the configured limit
    actual INTEGER,               -- For thresholds: the actual value
    provider TEXT,                -- For max_per_provider
    duration_ms INTEGER,          -- For long_duration
    -- Connection details (nullable, may not apply to all alert types)
    pid INTEGER,
    comm TEXT,
    proto TEXT,
    local_ip TEXT,
    local_port INTEGER,
    remote_ip TEXT,
    remote_port INTEGER,
    domain TEXT
);

CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts);
CREATE INDEX IF NOT EXISTS idx_alerts_run_id ON alerts(run_id);
CREATE INDEX IF NOT EXISTS idx_alerts_kind ON alerts(kind);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
```

### Alert Views

```sql
-- Alert counts by kind
CREATE VIEW IF NOT EXISTS alert_counts AS
    SELECT kind, severity, COUNT(*) as count
    FROM alerts
    GROUP BY kind, severity
    ORDER BY count DESC;

-- Alert timeline (hourly buckets)
CREATE VIEW IF NOT EXISTS alert_timeline AS
    SELECT
        strftime('%Y-%m-%d %H:00', ts) as hour,
        kind,
        COUNT(*) as count
    FROM alerts
    GROUP BY hour, kind
    ORDER BY hour DESC;

-- Alerts by domain pattern
CREATE VIEW IF NOT EXISTS alert_domain_patterns AS
    SELECT pattern, domain, COUNT(*) as hits
    FROM alerts
    WHERE kind = 'domain_match'
    GROUP BY pattern, domain
    ORDER BY hits DESC;
```

## Output Format

### Stderr Output (Pretty Mode)

```
[ALERT] 2026-01-21T10:30:45Z | CRITICAL | domain_match | api.evil.com matched *.evil.com | pid=12345 | claude | tcp | 127.0.0.1:54321 -> 1.2.3.4:443
[ALERT] 2026-01-21T10:30:46Z | WARNING  | max_connections | 101/100 active connections
[ALERT] 2026-01-21T10:30:47Z | WARNING  | max_per_provider | anthropic: 51/50 connections
[ALERT] 2026-01-21T10:30:48Z | WARNING  | long_duration | 35000ms > 30000ms | pid=12345 | claude | tcp | 127.0.0.1:54321 -> 1.2.3.4:443
[ALERT] 2026-01-21T10:30:49Z | WARNING  | unknown_domain | unresolved: 1.2.3.4 | pid=12345 | codex | tcp | 127.0.0.1:54322 -> 1.2.3.4:443
```

### Color Scheme

| Severity | Color | ANSI Code |
|----------|-------|-----------|
| CRITICAL | Red | `\x1b[1;31m` (bold red) |
| WARNING | Yellow | `\x1b[1;33m` (bold yellow) |
| [ALERT] prefix | Red | `\x1b[31m` |

### JSON Output

When `--json` is enabled, alerts are emitted as JSON lines to stdout (interleaved with connection events):

```json
{"ts":"2026-01-21T10:30:45Z","type":"alert","kind":"domain_match","severity":"critical","pattern":"*.evil.com","domain":"api.evil.com","pid":12345,"comm":"claude","proto":"tcp","local":"127.0.0.1:54321","remote":"1.2.3.4:443"}
{"ts":"2026-01-21T10:30:46Z","type":"alert","kind":"max_connections","severity":"warning","threshold":100,"actual":101}
```

## Pattern Matching

### Glob Patterns (--alert-domain)

- Case-insensitive matching
- Supports `*` (matches any characters) and `?` (matches single character)
- Examples:
  - `*.evil.com` matches `www.evil.com`, `api.evil.com`
  - `malware*` matches `malware.io`, `malware-host.net`
  - `*.*.evil.com` matches `www.api.evil.com`

### Regex Patterns (--alert-domain-regex)

- Full regex support via the `regex` crate
- Case-insensitive by default (use `(?-i)` to disable)
- Anchored to full domain (implicitly wrapped in `^...$`)
- Examples:
  - `(api|www)\.evil\.(com|net)` matches `api.evil.com`, `www.evil.net`
  - `.*\.ru$` matches any `.ru` domain

### Implementation Decision: Regex vs Glob

**Recommendation**: Support both glob and regex patterns.

**Rationale**:
1. Glob patterns are simpler and cover most use cases (`*.evil.com`)
2. Regex provides power users with full flexibility
3. Separate flags (`--alert-domain` vs `--alert-domain-regex`) make intent clear
4. The `regex` crate is already indirectly available via optional pcap dependencies

**Implementation**: Use the `glob` crate for glob matching and `regex` crate for regex patterns. Both are compiled once at startup for performance.

## Alert Evaluation Flow

```
┌─────────────────────────────────────────────────────────────┐
│                   Per-Poll Cycle                            │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│ 1. Check max_connections threshold                          │
│    - Compare stats.active vs config.max_connections         │
│    - Emit alert if exceeded (with cooldown check)           │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│ 2. Check max_per_provider threshold                         │
│    - For each provider in stats.per_provider:               │
│      - Compare count vs config.max_per_provider             │
│      - Emit alert if exceeded (with cooldown check)         │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│ 3. For each new connection event:                           │
│    a. Check domain patterns (glob + regex)                  │
│    b. Check alert_unknown_domain if domain is None          │
│    c. Emit alerts with cooldown                             │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│ 4. For each close event:                                    │
│    - If duration_threshold_ms configured:                   │
│      - Check if duration > threshold                        │
│      - Emit alert if exceeded                               │
└─────────────────────────────────────────────────────────────┘
```

## Cooldown Logic

To prevent alert spam, duplicate alerts are suppressed within a cooldown window:

```rust
fn should_emit_alert(state: &mut AlertState, sig: &AlertSignature, config: &AlertConfig) -> bool {
    let now = SystemTime::now();

    if let Some(last) = state.last_alert.get(sig) {
        let elapsed = now.duration_since(*last).unwrap_or_default();
        if elapsed.as_millis() < config.cooldown_ms as u128 {
            state.suppressed_count += 1;
            return false;
        }
    }

    state.last_alert.insert(sig.clone(), now);
    state.alert_count += 1;
    true
}
```

**Design Questions Answered:**

1. **Per-connection or per-threshold-breach?**
   - Domain and duration alerts are per-connection
   - Max connection/provider alerts are per-threshold-breach
   - Cooldown applies to both with appropriate signatures

2. **How to handle cooldown?**
   - In-memory HashMap with `AlertSignature -> SystemTime`
   - Default cooldown: 10 seconds
   - Configurable via `--alert-cooldown-ms`
   - No persistence needed (resets each session)

3. **Track 'alert acknowledged' state?**
   - No. Alerts are informational; users can query SQLite for history.
   - Keep the system simple; acknowledgement is out of scope for v1.

4. **JSON mode interaction?**
   - Alerts emit as JSON lines with `"type": "alert"`
   - Interleaved with connection events in output stream
   - Alerts still logged to SQLite regardless of output format

## Performance Considerations

1. **Pattern compilation**: Compile glob and regex patterns once at startup
2. **Cooldown check**: O(1) HashMap lookup per potential alert
3. **Threshold checks**: Run once per poll cycle, not per-connection
4. **SQLite batching**: Alerts batched with connection events (same queue)

## Testing Requirements

### Unit Tests

1. Glob pattern matching (various patterns and edge cases)
2. Regex pattern matching (valid patterns, invalid patterns)
3. Cooldown logic (suppression, expiry)
4. Threshold checks (boundary conditions)
5. Alert serialization (JSON format)

### E2E Tests

1. Generate traffic that triggers each alert type
2. Verify alert output format (stderr, colors)
3. Verify SQLite alert records
4. Verify cooldown suppression works
5. Verify alerts don't fire for normal traffic
6. Test --no-alerts flag

## Dependencies

New crate dependencies:

```toml
[dependencies]
regex = "1"          # For --alert-domain-regex
glob = "0.3"         # For --alert-domain glob matching (OR use simple custom impl)
```

**Alternative**: Implement simple glob matching inline to avoid new dependency. The glob crate is small but adds to compile time.

## Migration Path

1. Add AlertConfig struct and CLI parsing
2. Add AlertState tracking
3. Implement pattern matching
4. Add alert evaluation to main loop
5. Add stderr output formatting
6. Add SQLite alerts table and insertion
7. Add JSON alert output
8. Add config file support
9. Write tests

## Open Questions

1. **Should we add an `--alert-file` for dedicated alert log?**
   - Could be useful for integration with external tools
   - Defer to future enhancement

2. **Should alerts appear in `rano report`?**
   - Yes, but as a future enhancement
   - Add `--alerts` flag to include alert summary in reports

---

*This design document addresses the deliverables specified in bd-1jj and provides the foundation for bd-291 (CLI flags) and bd-20u (implementation).*
