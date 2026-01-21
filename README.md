# rano

<div align="center">
  <img src="rano_illustration.webp" alt="rano - network observer for AI CLI processes">
</div>

<div align="center">

[![CI](https://github.com/lumera-ai/rano/actions/workflows/ci.yml/badge.svg)](https://github.com/lumera-ai/rano/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/lumera-ai/rano?sort=semver)](https://github.com/lumera-ai/rano/releases)

</div>

rano is a **network observer for AI CLI processes** that tracks outbound connections from Claude Code, Codex CLI, Gemini CLI, and their descendants—live in your terminal and durably in SQLite.

<div align="center">

### Quick Install

```bash
curl -fsSL https://raw.githubusercontent.com/lumera-ai/rano/main/install.sh | bash
```

```powershell
irm https://raw.githubusercontent.com/lumera-ai/rano/main/install.ps1 | iex
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

**When it might not fit:** you need full DNS/SNI capture or packet-level inspection.

---

## Installation

### Quick Install (Recommended)

```bash
curl -fsSL https://raw.githubusercontent.com/lumera-ai/rano/main/install.sh | bash
```

**With options:**

```bash
# Specific version
curl -fsSL https://raw.githubusercontent.com/lumera-ai/rano/main/install.sh | bash -s -- --version v0.1.0

# System-wide (requires sudo)
curl -fsSL https://raw.githubusercontent.com/lumera-ai/rano/main/install.sh | sudo bash -s -- --system

# Auto-update PATH in shell rc files
curl -fsSL https://raw.githubusercontent.com/lumera-ai/rano/main/install.sh | bash -s -- --easy-mode
```

### Windows (PowerShell)

```powershell
irm https://raw.githubusercontent.com/lumera-ai/rano/main/install.ps1 | iex
```

### From Source

```bash
git clone https://github.com/lumera-ai/rano
cd rano
cargo build --release
cp target/release/rano ~/.local/bin/
```

### Cargo Install

```bash
cargo install --git https://github.com/lumera-ai/rano --locked
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
--theme <vivid|mono>
--no-banner
--config <path>           # Load key=value config
--no-config
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

You requested pcap mode. Run as root or use PTR mode instead.

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

### "stats aren’t printing"

Stats are suppressed when JSON output is enabled or when `--stats-interval-ms 0`.

```bash
rano --stats-interval-ms 2000
```

---

## Limitations

### What rano Doesn’t Do (Yet)

- **True DNS/SNI attribution**: PTR lookups are best-effort and may not match original hostnames.
- **Packet-level inspection**: it’s not a packet sniffer; use tcpdump/wireshark for payloads.
- **Windows `/proc` parity**: primary monitoring relies on `/proc`, so non-Linux support is limited.

---

## FAQ

### Why “rano”? 

Short for **rust_agent_network_observer**.

### Does it require root?

No for PTR mode. Pcap mode (planned) typically needs elevated privileges.

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
