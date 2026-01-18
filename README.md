# rano

rano is a robust, user-friendly network observer for monitoring outgoing connections made by AI CLI processes (Claude Code, Codex CLI, Gemini CLI) and their descendants. It polls `/proc` to associate sockets with PIDs, prints connection events (connect/close), and logs to SQLite with rich aggregate stats.

## Highlights

- **Provider-aware**: categorizes Anthropic/OpenAI/Google with color-coded output
- **Descendant-aware**: tracks children and subprocesses (or monitor exact PIDs)
- **Live stats**: ASCII bar charts with per-provider totals, domains, IPs, top-N lists
- **SQLite logging**: durable event history + aggregate views + duration tracking
- **Flexible logging**: per-run log directory, pretty/JSON log formats
- **Config support**: simple `key=value` config file (no extra parser deps)

## What it captures

- PID, process name, command line, provider, protocol, local/remote IP:port
- Best-effort domain via reverse DNS (PTR)
- Connection open/close events
- Run/session metadata (args, host, user, stats summary)

## Domain capture modes

- **PTR (default)**: reverse DNS lookups. This does **not** always match the original target hostname (e.g., HTTPS SNI).
- **PCAP (planned)**: true DNS+SNI capture requires libpcap + elevated privileges. If requested but unavailable, rano logs a warning and falls back to PTR.

## Usage

```bash
cd /data/projects/rust_agent_network_observer
cargo run --release -- --pattern claude --pattern codex --pattern gemini
```

### Common options

```bash
# JSON output with log file
cargo run --release -- --json --log-file /tmp/rano.log

# Per-run log files with JSON format
cargo run --release -- --log-dir /tmp/rano-logs --log-format json

# SQLite logging to custom path
cargo run --release -- --sqlite /tmp/rano.sqlite

# Live stats every 2s with wider bars
cargo run --release -- --stats-interval-ms 2000 --stats-width 60

# Target specific PID(s) and skip descendants
cargo run --release -- --pid 1234 --no-descendants

# Force pcap mode (falls back with warning if unavailable)
cargo run --release -- --pcap

# Single poll
cargo run --release -- --once
```

## Flags

- `--pattern <string>`: process name/cmdline substring to match (repeatable)
- `--exclude-pattern <string>`: exclude processes matching substring (repeatable)
- `--pid <pid>`: monitor specific PID (repeatable)
- `--no-descendants`: do not include descendant processes
- `--interval-ms <ms>`: polling interval (default: 1000)
- `--json`: emit JSON lines instead of colored text
- `--summary-only`: suppress live events, show summary only
- `--domain-mode <auto|ptr|pcap>`: domain capture mode (default: auto)
- `--pcap`: force pcap mode (falls back if unavailable)
- `--no-dns`: disable PTR lookups
- `--include-udp`: include UDP sockets
- `--no-udp`: disable UDP sockets
- `--include-listening`: include listening TCP sockets
- `--log-file <path>`: append output to file
- `--log-dir <path>`: per-run log files in directory
- `--log-format <auto|pretty|json>`: log format for file output
- `--sqlite <path>`: SQLite file for persistent event logging
- `--no-sqlite`: disable SQLite logging
- `--stats-interval-ms <ms>`: live stats interval (0 disables)
- `--stats-width <n>`: ASCII bar width
- `--stats-top <n>`: top-N domains/IPs in stats/summary
- `--once`: emit a single poll and exit
- `--color <auto|always|never>`: output color mode
- `--no-color`: disable ANSI color
- `--theme <vivid|mono>`: output theme
- `--no-banner`: suppress startup banner
- `--config <path>`: load config file (`key=value` format)
- `--no-config`: ignore config file

## Output format (pretty)

```
2026-01-17T19:30:00Z | + connect | openai | pid=1234 | codex-cli | tcp | 127.0.0.1:54012 -> 1.2.3.4:443 | domain=example.com.
2026-01-17T19:31:00Z | - close   | openai | pid=1234 | codex-cli | tcp | 127.0.0.1:54012 -> 1.2.3.4:443 | domain=example.com. dur=1200ms
```

Summary lines at shutdown:
```
Summary
  connects 24
  closes   24
  Providers
    12 openai
    8 anthropic
    4 google
```

## Output format (JSON)

```
{"ts":"2026-01-17T19:31:00Z","run_id":"12345-1705510200000","event":"close","pid":1234,"comm":"codex-cli","cmdline":"codex-cli --some-arg","provider":"openai","proto":"tcp","local":"127.0.0.1:54012","remote":"1.2.3.4:443","domain":"example.com.","duration_ms":1200}
```

## Config file

Default path: `~/.config/rano/config.conf`

Example:
```
pattern=codex
exclude_pattern=browser
interval_ms=1000
stats_top=5
log_dir=/tmp/rano-logs
log_format=pretty
```

### Provider config (TOML)

You can override provider matching patterns with a `rano.toml` file. Configs are applied in order (later entries can override earlier ones):

1. `~/.rano.toml`
2. `~/.config/rano/rano.toml`
3. `./rano.toml` (current working directory)
4. `--config-toml <path>`
5. `RANO_CONFIG_TOML` (explicit path)

Schema:
```
[providers]
mode = "merge" # or "replace"
anthropic = ["claude", "anthropic"]
openai = ["codex", "openai"]
google = ["gemini", "google"]
```

`merge` appends to built-in defaults; `replace` resets patterns at that point.

See `docs/provider-config.md` for schema and merge details.

## SQLite schema

The `events` table stores per-connection events with process and network metadata, and `sessions` stores run metadata. Useful views include:

- `provider_counts`
- `provider_domains`
- `provider_ips`
- `provider_ports`
- `provider_processes`
- `provider_last_hour`
- `provider_hourly`
- `session_summary`

## Install

macOS/Linux:

```bash
curl -fsSL "https://raw.githubusercontent.com/lumera-ai/rano/main/install.sh?$(date +%s)" | bash
```

Windows (PowerShell):

```powershell
irm https://raw.githubusercontent.com/lumera-ai/rano/main/install.ps1 | iex
```

## Self-update

```bash
rano update
# or override repo
rano update --owner your-org --repo rano --branch main
```

You can also set `RANO_OWNER`, `RANO_REPO`, and `RANO_BRANCH` to override defaults.

## Build

```bash
cargo build --release
```
