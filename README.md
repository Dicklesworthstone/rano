# rano

<div align="center">
  <img src="rano_illustration.webp" alt="rano - network observer for AI CLI processes">
</div>

<div align="center">

[![CI](https://github.com/Dicklesworthstone/rano/actions/workflows/ci.yml/badge.svg)](https://github.com/Dicklesworthstone/rano/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/Dicklesworthstone/rano?sort=semver)](https://github.com/Dicklesworthstone/rano/releases)

</div>

rano is a **network observer for AI CLI processes** that tracks outbound connections from Claude Code, Codex CLI, Gemini CLI, and their descendants—live in your terminal and durably in SQLite.

<div align="center">

### Quick Install

```bash
curl -fsSL https://raw.githubusercontent.com/Dicklesworthstone/rano/main/install.sh | bash
```

```powershell
irm https://raw.githubusercontent.com/Dicklesworthstone/rano/main/install.ps1 | iex
```

</div>

---

## TL;DR

**The Problem**: AI CLI tools spawn subprocesses and open sockets you can’t easily attribute back to a provider or process in real time.

**The Solution**: rano polls `/proc`, maps sockets to PIDs, and prints connection events with provider tags while logging a complete history to SQLite.

### Why Use rano?

| Feature | What It Does |
|---------|--------------|
| **Provider-aware** | Tags traffic as `anthropic`, `openai`, `google`, or `unknown`. |
| **Descendant-aware** | Follows child processes automatically. |
| **Live stats** | In-terminal summaries with top IPs/domains and provider totals. |
| **SQLite logging** | Queryable history with built-in aggregate views. |
| **Flexible output** | Pretty or JSON output + optional file logging. |

---

## Quick Example

```bash
# Observe default AI CLIs (claude/codex/gemini)
./rano

# Narrow to Codex + log JSON
rano --pattern codex --json --log-file /tmp/rano.log

# Run with per-run log files
rano --log-dir /tmp/rano-logs --log-format json

# Track a specific PID (no descendants)
rano --pid 1234 --no-descendants

# Emit a single poll and exit
rano --once

# View SQLite aggregates
sqlite3 observer.sqlite "select * from provider_counts;"
```

---

## Design Philosophy

1. **Trustworthy attribution**: tie sockets to PIDs and command lines, not guesses.
2. **Low overhead**: polling `/proc` is fast and avoids ptrace or intrusive hooks.
3. **Human-first output**: readable live output with clear provider tags and colors.
4. **Durable history**: every run can be analyzed later via SQLite views.

---

## How rano Compares

| Feature | rano | lsof + grep | ss/netstat | tcpdump/wireshark |
|---------|------|-------------|------------|-------------------|
| PID → socket mapping | ✅ Built-in | ✅ but manual | ⚠️ limited | ❌ not PID-aware |
| Provider attribution | ✅ tags | ❌ | ❌ | ❌ |
| Live stats | ✅ | ❌ | ⚠️ basic | ⚠️ manual |
| Durable history | ✅ SQLite | ❌ | ❌ | ✅ (pcap) |
| Low privileges | ✅ (PTR mode) | ✅ | ✅ | ❌ (often root) |

**When to use rano:** monitor AI CLI network behavior during dev or audits.

**When it might not fit:** you need full packet capture, payload inspection, or decrypted TLS analysis.

---

## Installation

### Quick Install (Recommended)

```bash
curl -fsSL https://raw.githubusercontent.com/Dicklesworthstone/rano/main/install.sh | bash
```

**With options:**

```bash
# Specific version
curl -fsSL https://raw.githubusercontent.com/Dicklesworthstone/rano/main/install.sh | bash -s -- --version v0.1.0

# System-wide (requires sudo)
curl -fsSL https://raw.githubusercontent.com/Dicklesworthstone/rano/main/install.sh | sudo bash -s -- --system

# Auto-update PATH in shell rc files
curl -fsSL https://raw.githubusercontent.com/Dicklesworthstone/rano/main/install.sh | bash -s -- --easy-mode
```

### Windows (PowerShell)

```powershell
irm https://raw.githubusercontent.com/Dicklesworthstone/rano/main/install.ps1 | iex
```

### From Source

```bash
git clone https://github.com/Dicklesworthstone/rano
cd rano
cargo build --release
cp target/release/rano ~/.local/bin/
```

### Cargo Install

```bash
cargo install --git https://github.com/Dicklesworthstone/rano --locked
```

---

## Quick Start

1. **Run with defaults** (auto-monitors claude/codex/gemini):
   ```bash
   rano
   ```
2. **Target a process name**:
   ```bash
   rano --pattern codex
   ```
3. **Log to SQLite** (default `observer.sqlite`):
   ```bash
   rano --sqlite /tmp/rano.sqlite
   ```
4. **See aggregates**:
   ```bash
   sqlite3 /tmp/rano.sqlite "select * from provider_counts;"
   ```

---

## Commands

### `rano`

Monitor outgoing connections and print events/stats.

```bash
rano --pattern claude --pattern codex
rano --exclude-pattern browser
rano --pid 1234 --no-descendants
rano --stats-interval-ms 2000 --stats-width 60
rano --log-dir /tmp/rano-logs --log-format json
rano --once
```

**Common flags**

```bash
--pattern <str>           # Repeatable process/cmdline substring
--exclude-pattern <str>   # Repeatable exclusion filter
--pid <pid>               # Repeatable PID targeting
--no-descendants          # Only exact PIDs
--interval-ms <ms>        # Polling interval
--json                    # Emit JSON lines to stdout
--summary-only            # Suppress live events
--domain-mode <auto|ptr|pcap>
--pcap                    # Force pcap mode (falls back)
--no-dns                  # Disable PTR lookups
--include-udp             # Include UDP sockets
--no-udp                  # Exclude UDP sockets
--include-listening       # Include TCP listening sockets
--log-file <path>         # Append output to a file
--log-dir <path>          # Per-run log files
--log-format <auto|pretty|json>
--sqlite <path>           # SQLite file for event logging
--no-sqlite               # Disable SQLite
--db-batch-size <n>       # SQLite batch size (events per transaction)
--db-flush-ms <ms>        # SQLite flush interval in ms
--db-queue-max <n>        # SQLite queue capacity (events)
--stats-interval-ms <ms>  # Live stats cadence (0 disables)
--stats-width <n>         # ASCII bar width
--stats-top <n>           # Top-N lists size
--once                    # Single poll and exit
--color <auto|always|never>
--no-color                # Disable ANSI color
--theme <vivid|mono|colorblind>
--no-banner
--config <path>           # Load key=value config
--no-config
```

### Domain Attribution Modes

rano can resolve domains in two modes:

- **PTR (default)**: reverse DNS lookups. No elevated privileges required.
- **pcap**: uses libpcap to capture DNS responses + TLS SNI. Requires root/CAP_NET_RAW.
  If capture fails, rano logs a warning and falls back to PTR automatically.

Examples:

```bash
# Prefer pcap attribution (falls back if unavailable)
rano --domain-mode pcap
rano --pcap --pattern claude

# Force PTR mode (no packet capture)
rano --domain-mode ptr
```

Offline verification (no root) is supported via a pcap file:

```bash
RANO_PCAP_FILE=tests/fixtures/pcap/dns-fixture.pcap \
  rano --pcap --once --json --no-banner
```

### `rano update`

Update the installed binary.

```bash
rano update
rano update --version v0.1.0
rano update --system
rano update --owner your-org --repo rano --branch main
```

### `rano report`

Generate reports from SQLite event history.

```bash
# Show latest session report
rano report --latest

# Show specific session by run_id
rano report --run-id "12345-1705512345000"

# Filter by time range
rano report --since 24h                    # Last 24 hours
rano report --since 7d                     # Last 7 days
rano report --since 2026-01-17             # Since date
rano report --since 2026-01-17T10:00:00Z   # Since timestamp

# Combine filters
rano report --since 2026-01-17 --until 2026-01-18

# Output options
rano report --latest --json                # JSON output
rano report --latest --top 5               # Top 5 domains/IPs
rano report --sqlite /path/to/rano.sqlite  # Custom database

# Color control
rano report --latest --color always
```

**Report sections**

- **Session**: run ID, start/end times, duration, host, patterns
- **Summary**: total events, connects, closes, active connections
- **Providers**: event counts per provider (anthropic, openai, google, unknown)
- **Top Domains**: most active domains with provider attribution
- **Top IPs**: most active remote IPs with reverse DNS

**Time range formats**

- Relative: `1h`, `24h`, `7d`, `30m`, `1w`
- Date: `2026-01-17` (interpreted as midnight UTC)
- RFC3339: `2026-01-17T10:00:00Z`

### `rano status`

One-line status output for shell prompt integration (PS1, starship, etc.).

```bash
# Default one-line format
rano status

# Custom format template
rano status --format '{active}/{total}'

# Custom SQLite database
rano status --sqlite /path/to/rano.sqlite
```

**Template variables**

| Variable | Description |
|----------|-------------|
| `{active}` | Current active connection count |
| `{total}` | Total connections this session |
| `{anthropic}` | Anthropic provider connection count |
| `{openai}` | OpenAI provider connection count |
| `{google}` | Google provider connection count |
| `{session_name}` | Current session name (if available) |

**Default format**: `{active} active | anthropic:{anthropic} openai:{openai}`

**Shell integration examples**

```bash
# Bash PS1
PS1='$(rano status 2>/dev/null) \$ '

# Zsh RPROMPT
RPROMPT='$(rano status 2>/dev/null)'

# Starship custom command
[custom.rano]
command = "rano status 2>/dev/null"
when = "command -v rano"
```

**Performance**: Optimized for prompt use (<50ms typical execution).

---

## Alert Thresholds

rano can proactively alert you when connections match suspicious patterns or exceed thresholds. Alerts appear on stderr with distinct formatting so you can monitor without watching output constantly.

### Quick Examples

```bash
# Watch for connections to suspicious domains
rano --alert-domain "*.evil.com" --alert-domain "*.malware.org"

# Alert when total connections exceed 100
rano --alert-max-connections 100

# Alert when any provider exceeds 50 connections
rano --alert-max-per-provider 50

# Alert on connections lasting longer than 30 seconds
rano --alert-duration-ms 30000

# Alert on unresolved domains (potential DNS tunneling)
rano --alert-unknown-domain

# Combine multiple alerts for security monitoring
rano --alert-domain "*.suspicious.com" \
     --alert-max-connections 200 \
     --alert-unknown-domain \
     --alert-bell
```

### Alert Flags

| Flag | Description |
|------|-------------|
| `--alert-domain <pattern>` | Glob pattern for domains to watch (repeatable) |
| `--alert-max-connections <N>` | Alert when total active connections exceed N |
| `--alert-max-per-provider <N>` | Alert when any provider exceeds N connections |
| `--alert-duration-ms <N>` | Alert on connections lasting longer than N ms |
| `--alert-unknown-domain` | Alert on connections to unresolved IPs |
| `--alert-bell` | Ring terminal bell on alert |
| `--alert-cooldown-ms <N>` | Suppress duplicate alerts within N ms (default: 10000) |
| `--no-alerts` | Disable all alerting |

### Alert Output Format

Alerts print to stderr with timestamps and details:

```
[ALERT] 2026-01-20T10:00:00Z | CRITICAL | domain_match | evil.malicious.com matched *.malicious.com
[ALERT] 2026-01-20T10:00:01Z | WARNING | max_connections | 101/100 active connections
[ALERT] 2026-01-20T10:00:02Z | WARNING | long_duration | 45000ms > 30000ms
```

In JSON mode, alerts are JSON objects on stderr:

```json
{"type":"alert","ts":"2026-01-20T10:00:00Z","kind":"domain_match","severity":"critical","pattern":"*.malicious.com","domain":"evil.malicious.com"}
```

### SQLite Alert Tracking

Events that trigger alerts are stored with `alert=1` in SQLite for later analysis:

```sql
-- Find all alert-triggering events
SELECT * FROM events WHERE alert = 1;

-- Count alerts by domain
SELECT domain, COUNT(*) as alerts FROM events WHERE alert = 1 GROUP BY domain;
```

### Use Cases

**Security audit**: Watch for unexpected outbound connections during a code review session.

```bash
rano --pattern claude \
     --alert-domain "*.unknown-cdn.com" \
     --alert-unknown-domain \
     --alert-max-connections 50
```

**Rate limit detection**: Identify when AI CLI tools are making too many connections.

```bash
rano --alert-max-per-provider 100 \
     --alert-duration-ms 60000
```

**Compliance monitoring**: Log all connections that match suspicious patterns.

```bash
rano --alert-domain "*.cn" \
     --alert-domain "*.ru" \
     --sqlite /var/log/rano-audit.sqlite
```

### Troubleshooting

**Alerts aren't firing**

1. Verify the pattern matches: `rano --alert-domain "*.example.com" --once` should show the flag is accepted
2. Check cooldown: default is 10 seconds. Use `--alert-cooldown-ms 1000` for more frequent alerts
3. Ensure `--no-alerts` is not set
4. For domain alerts, ensure DNS resolution is working (`--no-dns` disables it)

**Too many alerts (spam)**

1. Increase cooldown: `--alert-cooldown-ms 60000` (60 seconds)
2. Narrow patterns: use more specific domain patterns
3. Raise thresholds: increase `--alert-max-connections` value

---

## Presets

rano includes built-in configuration presets for common use cases. Presets bundle multiple settings into a single flag, making it easy to switch between monitoring styles without remembering individual options.

### Built-in Presets

| Preset | Description | Key Settings |
|--------|-------------|--------------|
| `audit` | Security review / minimal noise | `stats_interval_ms=0`, `include_udp=true`, `summary_only=true` |
| `quiet` | Reduce terminal output | `stats_interval_ms=0`, `no_banner=true`, `summary_only=true` |
| `live` | Real-time monitoring focus | `stats_interval_ms=500`, `stats_top=10` |
| `verbose` | Maximum detail | `include_udp=true`, `include_listening=true`, `stats_interval_ms=1000` |

### Quick Examples

```bash
# Security audit mode - captures everything, minimal output noise
rano --preset audit --pattern claude

# Quiet mode - background monitoring
rano --preset quiet --log-file /tmp/rano.log

# Live monitoring - see stats frequently
rano --preset live

# Verbose mode - show all details including UDP and listening sockets
rano --preset verbose

# List available presets
rano --list-presets

# Combine presets - later preset wins for conflicting settings
rano --preset audit --preset verbose

# Override preset values with CLI flags
rano --preset verbose --stats-interval-ms 5000
```

### Preset Flags

| Flag | Description |
|------|-------------|
| `--preset <name>` | Load a preset configuration (repeatable) |
| `--list-presets` | Show all available presets and exit |

### Creating Custom Presets

Create custom presets in `~/.config/rano/presets/`:

```bash
mkdir -p ~/.config/rano/presets

# Create a custom preset
cat > ~/.config/rano/presets/myaudit.conf << 'EOF'
# Description: Custom audit for my workflow
include_udp=true
include_listening=true
stats_interval_ms=2000
stats_top=20
summary_only=false
EOF
```

The first line comment `# Description: ...` becomes the preset description shown in `--list-presets`.

**Preset file format:**
- One `key=value` per line
- Lines starting with `#` are comments
- Uses the same keys as config files (see Configuration section)
- Boolean values: `true` or `false`

### Preset Merging

When multiple presets are specified, they're applied in order. Later presets override earlier ones:

```bash
# audit sets stats_interval_ms=0
# verbose sets stats_interval_ms=1000
# Result: stats_interval_ms=1000 (verbose wins)
rano --preset audit --preset verbose
```

CLI flags always override preset values:

```bash
# verbose sets stats_interval_ms=1000
# CLI sets stats_interval_ms=5000
# Result: stats_interval_ms=5000 (CLI wins)
rano --preset verbose --stats-interval-ms 5000
```

### Troubleshooting

**Preset not found**

```
error: Unknown preset 'mypreset'. Available: audit, live, quiet, verbose
```

1. Check the preset name spelling
2. Ensure the preset file exists: `ls ~/.config/rano/presets/`
3. Verify file extension is `.conf`
4. Run `rano --list-presets` to see available presets

**Preset not loading values**

1. Check file format: must be `key=value` (no spaces around `=`)
2. Verify key names match config options (see Configuration section)
3. For boolean values, use `true` or `false` (not `yes`/`no` or `1`/`0`)

---

## Process Ancestry

rano tracks the full process ancestry chain for each connection, showing exactly how a network-making process was spawned. This is invaluable for understanding which AI CLI session initiated a particular connection, especially when processes spawn deep subprocess trees.

### How It Works

For each tracked process, rano walks the process tree from init (PID 1) down to the process making the connection. The ancestry is stored as a comma-separated path:

```
init:1,systemd:500,sshd:1200,bash:1500,tmux:1600,bash:1700,claude:2000
```

Each entry is `comm:pid` where `comm` is the process name and `pid` is the process ID.

### Display Format

In live output, long ancestry chains are truncated to keep output readable:

```
init(1) → systemd(500) → bash(1700) → claude(2000)
```

Chains longer than 5 levels show ellipsis: `... → bash(1700) → claude(2000)`

### SQLite Storage

The full ancestry path is stored in the `ancestry_path` column:

```sql
-- Find all connections from processes spawned by tmux
SELECT * FROM events WHERE ancestry_path LIKE '%tmux%';

-- Group connections by their spawn path
SELECT ancestry_path, COUNT(*) as connections
FROM events
GROUP BY ancestry_path
ORDER BY connections DESC;

-- Find connections from a specific process tree
SELECT * FROM events WHERE ancestry_path LIKE '%claude:1234%';
```

### Export Support

The ancestry path is included in CSV and JSONL exports:

```bash
# Export with ancestry
rano export --format csv > connections.csv

# Filter and analyze ancestry in JSON
rano export --format jsonl | jq 'select(.ancestry_path | contains("tmux"))'
```

### Use Cases

**Attribution**: Determine which terminal session or tmux pane initiated a connection.

**Security audit**: Verify that AI CLI processes are being launched from expected parent processes.

**Debugging**: Trace why a particular subprocess made an unexpected connection.

**Process tree analysis**: Identify patterns in how AI CLIs spawn their network-making children.

### Performance

Ancestry is cached with a configurable TTL (default 30 seconds) and staleness detection. The cache is invalidated if the process's comm name changes, ensuring accuracy even for long-running sessions.

---

## Exporting Data

rano can export SQLite event history to CSV or JSONL for use with external tools like Excel, Pandas, jq, or data pipelines.

### Quick Examples

```bash
# Export all events to CSV (Excel-compatible)
rano export --format csv > connections.csv

# Export to JSONL for shell pipelines
rano export --format jsonl | jq '.domain' | sort | uniq -c

# Filter by time range
rano export --format csv --since 24h > daily.csv
rano export --format csv --since 2026-01-20 --until 2026-01-21 > jan20.csv

# Filter by provider
rano export --format csv --provider anthropic > anthropic.csv

# Filter by domain pattern
rano export --format csv --domain "*.openai.com" > openai.csv

# Custom SQLite file
rano export --format csv --sqlite /path/to/observer.sqlite > export.csv
```

### Export Flags

| Flag | Description |
|------|-------------|
| `--format csv\|jsonl` | Output format (required) |
| `--sqlite <path>` | SQLite database (default: observer.sqlite) |
| `--since <timestamp>` | Events after timestamp (RFC3339, date, or relative like `24h`) |
| `--until <timestamp>` | Events before timestamp |
| `--run-id <id>` | Filter by session run ID |
| `--provider <name>` | Filter by provider (anthropic, openai, google, unknown) |
| `--domain <pattern>` | Filter by domain glob pattern (repeatable) |
| `--fields <list>` | Override default field list (comma-separated) |
| `--no-header` | Omit CSV header row |

### Output Fields

Both CSV and JSONL include these fields (in order for CSV):

| Field | Type | Description |
|-------|------|-------------|
| `ts` | string | ISO 8601 timestamp |
| `run_id` | string | Session identifier |
| `event` | string | `connect` or `close` |
| `provider` | string | anthropic, openai, google, unknown |
| `pid` | integer | Process ID |
| `comm` | string | Process command name |
| `cmdline` | string | Full command line |
| `proto` | string | `tcp` or `udp` |
| `local_ip` | string | Local IP address |
| `local_port` | integer | Local port |
| `remote_ip` | string | Remote IP address |
| `remote_port` | integer | Remote port |
| `domain` | string | Resolved domain name (if available) |
| `ancestry_path` | string | Process ancestry chain (`comm:pid,comm:pid,...`) |
| `duration_ms` | integer | Connection duration in ms (close events only) |

### Format Notes

**CSV**
- RFC 4180 compliant with CRLF line endings
- Fields with commas, quotes, or newlines are properly escaped
- UTF-8 encoded, compatible with Excel

**JSONL**
- One JSON object per line
- LF line endings
- Null fields are omitted
- UTF-8 encoded, ideal for `jq` pipelines

### Use Cases

**Daily summary to spreadsheet**
```bash
rano export --format csv --since 24h > "$(date +%Y-%m-%d)-connections.csv"
```

**Find unique domains by provider**
```bash
rano export --format jsonl --provider anthropic | jq -r '.domain // empty' | sort -u
```

**Count connections per domain**
```bash
rano export --format jsonl | jq -r '.domain // "unknown"' | sort | uniq -c | sort -rn | head -20
```

**Import to Pandas**
```python
import pandas as pd
df = pd.read_csv("connections.csv")
df.groupby("provider")["event"].count()
```

---

## Configuration Validation

rano provides built-in configuration validation to catch errors and typos before runtime. The `config` subcommand helps you verify, inspect, and troubleshoot your configuration.

### Quick Examples

```bash
# Validate all config files
rano config check

# Show resolved configuration
rano config show

# Show configuration as JSON
rano config show --json

# List config file search paths
rano config paths
```

### Config Subcommands

| Subcommand | Description |
|------------|-------------|
| `config check` | Validate all config files and report errors/warnings |
| `config show` | Display the resolved configuration (all sources merged) |
| `config show --json` | Output resolved configuration as JSON |
| `config paths` | Show where rano looks for config files |

### Validation Output

**Errors** (prevent rano from starting):
```
1 error(s) found:
  ✗ /home/user/.config/rano/config.conf:3: 'interval_ms' must be a non-negative integer, got 'abc'
```

**Warnings** (rano will run but may not behave as expected):
```
1 warning(s) found:
  ⚠ /home/user/.config/rano/config.conf:5: unknown key 'intervall_ms' (possible typo?)
```

### What Gets Validated

| Check | Example Error |
|-------|---------------|
| Unknown keys | `unknown key 'intervall_ms' (possible typo?)` |
| Invalid numbers | `'interval_ms' must be a non-negative integer, got 'abc'` |
| Invalid booleans | `'json' must be a boolean (true/false/yes/no/1/0), got 'maybe'` |
| Invalid enum values | `'domain_mode' must be one of [auto, ptr, pcap], got 'invalid'` |
| Zero where >= 1 required | `'db_batch_size' must be >= 1, got 0` |
| Invalid stats_view | `'stats_view' contains invalid value 'invalid'` |
| TOML syntax errors | `TOML parse error: expected `]`...` |
| Invalid provider mode | `providers.mode must be one of [merge, replace], got 'bad'` |
| Missing parent directory | `log_file parent directory '/nonexistent' does not exist` |

### Workflow

1. **Create or edit config**:
   ```bash
   vim ~/.config/rano/config.conf
   ```

2. **Validate before running**:
   ```bash
   rano config check
   ```

3. **If errors, fix and re-validate**:
   ```
   1 error(s) found:
     ✗ config.conf:3: 'json' must be a boolean...
   ```

4. **Once valid, run rano**:
   ```bash
   rano --pattern claude
   ```

### Common Issues and Fixes

| Issue | Fix |
|-------|-----|
| `unknown key 'intervall_ms'` | Fix typo: `interval_ms` |
| `must be a boolean` | Use `true`, `false`, `1`, `0`, `yes`, or `no` |
| `must be one of [auto, ptr, pcap]` | Use a valid value from the list |
| `TOML parse error` | Check TOML syntax (missing quotes, brackets) |
| `must be >= 1` | Use a positive integer (not 0) |

### E2E Testing

Config validation is tested via the E2E harness:

```bash
scripts/e2e/run.sh config-validation scripts/e2e/config-validation.sh
```

Logs are written to `logs/e2e/config-validation-*.log`.

---

## Configuration

Default path: `~/.config/rano/config.conf`

```ini
# Process matching
pattern=codex,claude
exclude_pattern=browser

# Polling
interval_ms=1000

# Output
json=false
summary_only=false
color=auto
log_dir=/tmp/rano-logs
log_format=pretty

# Domains
no_dns=false
include_udp=true
include_listening=false

# SQLite
sqlite=/tmp/rano.sqlite
no_sqlite=false
db_batch_size=200
db_flush_ms=1000
db_queue_max=10000

# Stats
stats_interval_ms=2000
stats_width=50
stats_top=5

# UI
no_banner=false
theme=vivid
```

### SQLite Batching Performance

SQLite writes use an async batching system for better performance under high event rates.

**Default settings:**

| Flag | Default | Description |
|------|---------|-------------|
| `db_batch_size` | 200 | Events per transaction |
| `db_flush_ms` | 1000 | Maximum time before flush |
| `db_queue_max` | 10000 | Event queue capacity |

**Tuning guidance:**

- **High event rate** (>500 events/sec): Increase `db_batch_size` to 500-1000, increase `db_queue_max` to 50000
- **Low latency queries**: Decrease `db_flush_ms` to 100-500
- **Memory constrained**: Decrease `db_queue_max` to 1000-5000
- **SSD storage**: Defaults work well
- **HDD storage**: Increase `db_batch_size` to 500+

If the queue fills, events are dropped with a warning. Monitor for "sqlite queue full" messages.

### Provider Configuration (`rano.toml`)

Customize provider pattern matching without recompiling. rano searches for config at:

1. `~/.rano.toml`
2. `~/.config/rano/rano.toml`
3. `./rano.toml`
4. `--config-toml <path>` (CLI)
5. `RANO_CONFIG_TOML` (env)

**Example `rano.toml`:**

```toml
[providers]
# "merge" extends defaults; "replace" clears and uses only specified patterns
mode = "merge"

# Patterns are case-insensitive substrings matched against comm+cmdline
anthropic = ["acme-claude", "internal-claude"]
openai = ["company-codex"]
google = ["corp-gemini"]
```

**Merge mode (default):** Adds your patterns to the built-in defaults (`claude`, `codex`, `gemini`, etc.).

**Replace mode:** Clears all defaults and uses only your specified patterns. Useful for strict environments.

**Default patterns:**

| Provider | Default patterns |
|----------|------------------|
| anthropic | `claude`, `anthropic` |
| openai | `codex`, `openai` |
| google | `gemini`, `google` |

**Verification:** Run with `--once` to see provider attribution:

```bash
rano --pattern myprocess --once 2>&1 | grep provider
```

---

## Architecture

```
┌──────────────────────────────┐
│        Target Processes       │
│  claude / codex / gemini PIDs │
└──────────────┬───────────────┘
               │
               ▼
┌──────────────────────────────┐
│          /proc Poller         │
│  sockets ↔ inodes ↔ PIDs      │
└──────────────┬───────────────┘
               │
               ▼
┌──────────────────────────────┐
│     Provider Attribution      │
│  comm/cmdline → provider tag  │
└──────────────┬───────────────┘
               │
     ┌─────────┴─────────┐
     ▼                   ▼
┌──────────────┐  ┌────────────────┐
│ Live Output  │  │ SQLite Logger  │
│ pretty/json  │  │ events + views │
└──────────────┘  └────────────────┘
```

---

## Troubleshooting

### "warning: pcap capture requires elevated privileges"

You requested pcap mode. Run as root or grant `CAP_NET_RAW`, or switch to PTR mode.
rano will log the warning and fall back to PTR automatically.

```bash
rano --domain-mode ptr
```

### "no matching processes"

Your patterns didn’t match any running processes. List processes or add `--pid`.

```bash
ps aux | rg -i codex
rano --pid <pid>
```

### "SQLite file is locked"

Another process is holding a lock on the database. Stop the other writer or use a new file.

```bash
rano --sqlite /tmp/rano-$(date +%s).sqlite
```

### "domains are unknown"

PTR lookups are disabled or reverse DNS doesn’t resolve for that IP.

Edit your config:

```ini
no_dns=false
```

### "stats aren't printing"

Stats are suppressed when JSON output is enabled or when `--stats-interval-ms 0`.

```bash
rano --stats-interval-ms 2000
```

---

## Live Stats Views

rano provides four real-time stats views that display aggregated connection data as colorized bar charts. Views can cycle automatically or be displayed individually.

### Available Views

| View | Description | Use Case |
|------|-------------|----------|
| `provider` | Connections grouped by AI provider (anthropic, openai, google, unknown) | See which AI services are being used |
| `domain` | Top domains by connection count | Identify active endpoints |
| `port` | Top destination ports | Monitor protocol distribution |
| `process` | Top process names (comm) | See which executables are connecting |

### Quick Examples

```bash
# Single view - provider stats only
rano --stats-view provider

# Multiple views - cycle between them
rano --stats-view provider --stats-view domain --stats-cycle-ms 5000

# All views cycling every 3 seconds
rano --stats-view provider --stats-view domain --stats-view port --stats-view process --stats-cycle-ms 3000

# Customize display
rano --stats-view domain --stats-top 10 --stats-width 60 --stats-interval-ms 1000
```

### Stats Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--stats-view <view>` | provider | View to display (repeatable for cycling) |
| `--stats-interval-ms <ms>` | 2000 | How often to refresh stats (0 disables) |
| `--stats-cycle-ms <ms>` | 0 | Cycle between views (0 = no cycling) |
| `--stats-top <n>` | 5 | Number of items to show in domain/port/process views |
| `--stats-width <n>` | 40 | Width of bar charts in characters |

### Output Examples

**Provider View** (`--stats-view provider`):

```
Live Stats [provider]
  anthropic   █████████████████████████████████████░░░ 42 (domains=3, ips=2)
  openai      ████████████████░░░░░░░░░░░░░░░░░░░░░░░░ 18 (domains=2, ips=2)
  google      ██████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░ 6 (domains=1, ips=1)
  unknown     ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░ 0 (domains=0, ips=0)
  active=12 peak=45 avg_dur=250ms
```

**Domain View** (`--stats-view domain --stats-top 5`):

```
Live Stats [domain]
    42 ████████████████████████████████████████ api.anthropic.com
    18 █████████████████░░░░░░░░░░░░░░░░░░░░░░░ api.openai.com
     6 █████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░ generativelanguage.googleapis.com
     3 ██░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░ www.google.com
     1 █░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░ github.com
```

**Port View** (`--stats-view port`):

```
Live Stats [port]
    65 ████████████████████████████████████████ 443
     4 ██░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░ 80
     1 █░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░ 8080
```

**Process View** (`--stats-view process`):

```
Live Stats [process]
    35 ████████████████████████████████████████ claude
    20 ██████████████████████░░░░░░░░░░░░░░░░░░ node
    10 ███████████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░ curl
     5 █████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░ codex
```

### E2E Testing

The stats views are tested via the E2E harness:

```bash
# Run the stats views E2E test
scripts/e2e/run.sh stats-views tests/e2e/stats-views.sh

# View test output
cat logs/e2e/stats-views-*.log
```

The test verifies that all four view types render correctly and cycle in sequence.

### Configuration

Stats settings can be set in `~/.config/rano/config.conf`:

```ini
stats_interval_ms=1000
stats_width=50
stats_top=10
stats_view=provider,domain
stats_cycle_ms=5000
```

Or via presets:

```bash
# The 'live' preset enables frequent stats
rano --preset live  # stats_interval_ms=500, stats_top=10
```

### Verify pcap attribution (E2E)

The offline pcap test uses the shared harness and writes logs to `logs/e2e/`:

```bash
scripts/e2e/run.sh pcap-attribution scripts/e2e/pcap-attribution.sh
```

Logs:
- `logs/e2e/pcap-attribution-<timestamp>.log`
- `logs/e2e/outputs/` for full command output

---

## Limitations

### What rano Doesn’t Do (Yet)

- **Perfect hostname attribution**: pcap relies on observed DNS/SNI; some flows still resolve via PTR or remain `unknown`.
- **Packet-level inspection**: it’s not a packet sniffer; use tcpdump/wireshark for payloads.
- **Windows `/proc` parity**: primary monitoring relies on `/proc`, so non-Linux support is limited.

---

## FAQ

### Why “rano”? 

Short for **rust_agent_network_observer**.

### Does it require root?

No for PTR mode. Pcap mode uses libpcap and typically needs root/CAP_NET_RAW, but it
falls back to PTR automatically if capture is unavailable. Offline pcap replay can
be done without privileges via `RANO_PCAP_FILE`.

### Can I monitor a single PID without descendants?

```bash
rano --pid 1234 --no-descendants
```

### How do I get JSON output for automation?

```bash
rano --json --log-file /tmp/rano.jsonl
```

### Where are logs stored?

`--log-file` writes a single file; `--log-dir` creates per-run files. SQLite logs default to `observer.sqlite`.

---

## About Contributions

> *About Contributions:* Please don't take this the wrong way, but I do not accept outside contributions for any of my projects. I simply don't have the mental bandwidth to review anything, and it's my name on the thing, so I'm responsible for any problems it causes; thus, the risk-reward is highly asymmetric from my perspective. I'd also have to worry about other "stakeholders," which seems unwise for tools I mostly make for myself for free. Feel free to submit issues, and even PRs if you want to illustrate a proposed fix, but know I won't merge them directly. Instead, I'll have Claude or Codex review submissions via `gh` and independently decide whether and how to address them. Bug reports in particular are welcome. Sorry if this offends, but I want to avoid wasted time and hurt feelings. I understand this isn't in sync with the prevailing open-source ethos that seeks community contributions, but it's the only way I can move at this velocity and keep my sanity.

---

## License

License is currently unspecified.
