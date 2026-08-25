# Changelog

All notable changes to [rano](https://github.com/Dicklesworthstone/rano) are documented here.

rano is a **network observer for AI CLI processes** (Claude Code, Codex CLI, Gemini CLI).
It polls `/proc`, maps sockets to PIDs, and prints connection events with provider tags
while logging a complete history to SQLite.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

## [v0.2.0] -- 2026-08-25 (GitHub Release)

115 commits since v0.1.0 (2026-03-19). The headline is the completion of the rano v2 epic —
connection alerting, pcap capture, and a substantially reworked CLI — alongside the removal
of the vestigial Windows build.

**Platform support is now stated plainly: Linux and macOS only.** Windows was already
unsupported in practice (rano reads Linux-only `/proc` and Unix libc APIs) and the dead
`self_update_windows` code and stale install-path references are gone. This release ships
exactly the four targets `install.sh` can request — `x86_64-unknown-linux-gnu`,
`aarch64-unknown-linux-gnu`, `x86_64-apple-darwin`, `aarch64-apple-darwin` — and, unlike
v0.1.0, does **not** ship `install.ps1`, which advertised a Windows artifact that never
existed (see #42).

Both Linux binaries are built with a pinned glibc floor (2.28) rather than inheriting the
build host's, so they run on Debian 12, Ubuntu 22.04, RHEL 9 and Amazon Linux 2023 as well
as current distributions.

### Fixed (release gate)

- Three call sites in `alert_would_trigger_connection_alert` still referenced the
  pre-rename boolean helper; they now call `connection_alert_trigger(..).is_some()` /
  `.is_none()`, which preserves the assertions exactly.
- A `SqliteEvent` test fixture passed a bare integer after `pid` became `Option<u32>`.
- Removed a dead `triggers_alert` binding superseded by `close_alert_emitted`, which is
  the cooldown-aware single decision point for duration alerts.


### Removed

- Dropped dead `self_update_windows` code that lingered after the Windows build removal
  ([961cad8](https://github.com/Dicklesworthstone/rano/commit/961cad89a9fa99e2d2aae0b1587579c2a310aeb8))
- Cleaned up stale Windows install path references from docs and CI scripts
  ([7ebc740](https://github.com/Dicklesworthstone/rano/commit/7ebc74072e58d4f866914d2e27a81505a4d5c62b))

### Fixed

- Style cleanup: removed extra blank lines left behind by Windows code removal
  ([d6175dd](https://github.com/Dicklesworthstone/rano/commit/d6175dd43eac98ac0aca06a99588f92df681614e))
- Pcap-to-PTR fallback no longer silent: domain-mode notes (capture unavailable,
  privilege hint) are emitted on stderr under `--json`/`--no-banner`, and the
  privilege hint now recognizes libpcap's "CAP_NET_RAW may be required" wording
- Legacy SQLite databases (pre `session_name` / missing newer `events` columns)
  are migrated in a dedicated phase before index/view creation, instead of
  failing schema init or disabling SQLite logging entirely
- Alert JSON lines escape `pattern`/`domain`/`comm`, so hostile process names can
  no longer produce malformed JSON on the alert stream
- Retry warnings honor a per-source cooldown (equal to the detection window) and
  prune expired endpoint entries each close, bounding memory over long sessions
### Changed

- JSON retry warnings moved from stderr to stdout to join events/alerts as one
  machine-readable stream; pretty-mode retry warnings remain on stderr
- Every SQLite connection (writer and readers) sets `busy_timeout=5000`;
  concurrent `status`/`report` during monitoring no longer risk SQLITE_BUSY errors
- E2E harness resolves binaries via `CARGO_TARGET_DIR`-aware defaults; CI now runs
  all 14 E2E suites (including pcap-attribution with a feature build) plus a new
  sqlite-concurrency suite, uploading logs on failure
- report-output golden comparison uses stdout only, with the schema-compat
  warnings positively asserted on stderr

---

## [v0.1.0] -- 2026-03-19 (GitHub Release)

> First official release. Published to GitHub Releases with pre-built binaries for
> Linux (x86\_64, aarch64) and macOS (x86\_64, aarch64). Windows is intentionally
> excluded -- rano depends on Unix-only `/proc` and libc APIs.
>
> **Install:** `curl -fsSL https://raw.githubusercontent.com/Dicklesworthstone/rano/main/install.sh | bash`

Tag [`v0.1.0`](https://github.com/Dicklesworthstone/rano/releases/tag/v0.1.0)
covers the full development history from the initial commit on 2026-01-17 through
release prep on 2026-03-19 (105 commits on `main`). Release assets include
compressed binaries with SHA256 checksums for four targets, plus the `install.sh`
and `install.ps1` (WSL stub) scripts.

### Network Monitoring Engine

The foundational poll-based observer that gives rano its reason to exist.

- **`/proc` polling loop** -- reads `/proc/net/tcp` and `/proc/[pid]/fd` to map
  open sockets to PIDs and command lines without ptrace, eBPF, or elevated
  privileges
  ([dcecf6c](https://github.com/Dicklesworthstone/rano/commit/dcecf6ce04482c99d57bb1bc38e7935ddf82722c))
- **Provider attribution** -- classifies each connection as `anthropic`, `openai`,
  `google`, or `unknown` based on reverse DNS and known domain/IP patterns
- **Descendant tracking** -- follows child processes automatically via
  `/proc/[pid]/children`; disable with `--no-descendants`
- **UDP and listening sockets** -- opt-in via `--include-udp` and
  `--include-listening` (off by default to reduce noise)
- **`--once` mode** -- single poll and exit, useful for scripting and cron jobs
- **Process pattern matching** -- `--pattern` (repeatable) and `--exclude-pattern`
  to filter by process name or command-line substring; `--pid` for explicit PID targeting
  ([252ffa7](https://github.com/Dicklesworthstone/rano/commit/252ffa75b5a8d0aeb15bdb39cdcdd57d0f3697ce))

### Domain Attribution Modes

Two strategies for resolving IP addresses to domain names, selectable at runtime.

- **PTR mode** (default) -- reverse DNS lookups via `getnameinfo`; no root or
  capabilities required
- **pcap mode** (feature-gated, `cargo build --features pcap`) -- libpcap-based
  capture of DNS responses and TLS SNI for high-fidelity domain attribution;
  requires root or CAP\_NET\_RAW
  ([759b7c5](https://github.com/Dicklesworthstone/rano/commit/759b7c5d30ebfc5bc6cd392cc8e2169713d01bd8))
- Automatic pcap-to-PTR fallback when capture initialisation fails
- Offline verification via `RANO_PCAP_FILE` environment variable (no root needed)
- Improved pcap capture reliability
  ([9bedb85](https://github.com/Dicklesworthstone/rano/commit/9bedb859012c6ec107a74f63ae93415160b5f36e))
- `--domain-mode <auto|ptr|pcap>`, `--pcap`, `--no-dns` CLI flags

### SQLite Event Logging

Durable, queryable event history with built-in aggregate views.

- Events written to SQLite (default `observer.sqlite`); customise path with
  `--sqlite <path>` or disable with `--no-sqlite`
- Built-in SQL views: `provider_counts`, session summaries
- Configurable write batching for high-throughput scenarios:
  `--db-batch-size`, `--db-flush-ms`, `--db-queue-max`
  ([2761765](https://github.com/Dicklesworthstone/rano/commit/2761765e6867e2b891dd8c3aac99782e54b6ddc4))

### Live Stats Panel

In-terminal summaries refreshed on a configurable cadence.

- Top IPs and domains with provider tags and ASCII bar charts
- `--stats-interval-ms` (0 disables), `--stats-width`, `--stats-top`
- Unit tests for stats panel rendering
  ([fdbcebe](https://github.com/Dicklesworthstone/rano/commit/fdbcebe100831beb0d1b5c931ad5ded27388debd))

### Output and Logging

Flexible output pipelines for both humans and machines.

- Pretty-printed terminal output with ANSI colour by default
- `--json` for JSON-lines to stdout
- `--summary-only` to suppress per-event output
- `--log-file <path>` for append-mode file logging
- `--log-dir <path>` for per-run log files with automatic naming
- `--log-format <auto|pretty|json>` to control file output format
  ([dcecf6c](https://github.com/Dicklesworthstone/rano/commit/dcecf6ce04482c99d57bb1bc38e7935ddf82722c),
   [a377be0](https://github.com/Dicklesworthstone/rano/commit/a377be032030cd57d711dc6d747749772485a2c7))

### Provider Config via TOML

User-extensible provider definitions beyond the built-in `anthropic`/`openai`/`google`.

- `rano.toml` or `~/.config/rano/rano.toml` for custom provider definitions and
  domain-to-provider mappings
  ([e2d167f](https://github.com/Dicklesworthstone/rano/commit/e2d167f52eb36ed0e0578a66ae66dcfc31a309f9))
- Provider config unit tests and documentation
  ([a8cdfef](https://github.com/Dicklesworthstone/rano/commit/a8cdfef06a38119fd9e0bee990729bdca307debb),
   [e10667f](https://github.com/Dicklesworthstone/rano/commit/e10667f8aa472731318648c84ad7cad006c73004))

### `rano report` Command

Generate session reports from SQLite event history.

- `--latest`, `--run-id`, `--since` / `--until` (relative durations, dates, or
  RFC 3339 timestamps), `--json`, `--top`
  ([8278547](https://github.com/Dicklesworthstone/rano/commit/8278547b2401cd28d830b4958b5e72cf53002693))
- Report sections: session metadata (run ID, start/end, duration, host, patterns),
  summary (total events, connects, closes, active connections), provider breakdown,
  top domains, top IPs
- Null-safe report summary query
  ([4de07d3](https://github.com/Dicklesworthstone/rano/commit/4de07d39c36847381667cf6757aa7efe9dc5947c))
- E2E tests for report and batching features
  ([9e9d091](https://github.com/Dicklesworthstone/rano/commit/9e9d0919fbf641690baa23ca58ff84ca88dfdd48))

### `rano diff` Command

Compare two monitoring sessions and surface behavioural changes.

- `rano diff --old <run-id> --new <run-id>` with `--threshold` and `--json`
  ([5834863](https://github.com/Dicklesworthstone/rano/commit/58348636fb9b3c489c156f996f71105a5c3474cd))
- Diff sections: new/removed/changed domains, new processes, provider count shifts
- E2E test coverage
  ([ade5805](https://github.com/Dicklesworthstone/rano/commit/ade5805b7a174b993d87fae1435228d40185ff3c))

### `rano status` Command

One-line status output for shell prompt integration.

- Customisable format template: `rano status --format '{active}/{total}'`
- Template variables: `{active}`, `{total}`, `{anthropic}`, `{openai}`,
  `{google}`, `{session_name}`
- Optimised for prompt use (<50 ms typical)
  ([5e7c445](https://github.com/Dicklesworthstone/rano/commit/5e7c445385ca3a12b10ca44e912d9dac84331b9e))
- E2E test and CI pipeline integration
  ([daee398](https://github.com/Dicklesworthstone/rano/commit/daee3980ac0e8e6aaf46c4ded39ec0fbb7e0ac21))

### `rano update` (Self-Updater)

In-place binary update from GitHub Releases.

- `rano update` downloads the latest release binary
- Supports `--version`, `--system`, `--owner`, `--repo`, `--branch` flags

### `rano export` Command

Export SQLite event history to CSV or JSONL for external tools.

- `--format csv|jsonl`, `--since`, `--until`, `--run-id`, `--provider`,
  `--domain`, `--fields`, `--no-header`
- Ancestry path included in exports
- RFC 4180 compliant CSV; LF-delimited JSONL with null-field omission
  ([4d0ae2f](https://github.com/Dicklesworthstone/rano/commit/4d0ae2f158dae693769fdadd421c47dcb0588e23),
   [130122e](https://github.com/Dicklesworthstone/rano/commit/130122e64bac6bba45ee9f2e8f10a470e9f9703f))

### `rano config` Command

Configuration validation and introspection.

- `rano config check` -- validate all config files
- `rano config show` / `rano config show --json` -- display resolved config
- `rano config paths` -- list search paths
- Separate `config_validation.rs` module
  ([35f71ea](https://github.com/Dicklesworthstone/rano/commit/35f71eaef91eb1d6ad69107ec4c30403c93440fc))
- Unit tests for validation edge cases
  ([539deff](https://github.com/Dicklesworthstone/rano/commit/539deff45704ed958a4d6e944b477a5138eacd8a))
- Clippy-clean match guards in config validation
  ([cad677a](https://github.com/Dicklesworthstone/rano/commit/cad677af6e434e500aa62515a6f5e97ea493459f))

### Alert System

Proactive notifications for suspicious patterns and threshold breaches.

- `--alert-domain <glob>` (repeatable), `--alert-max-connections`,
  `--alert-max-per-provider`, `--alert-duration-ms`, `--alert-unknown-domain`,
  `--alert-bell`, `--alert-cooldown-ms`, `--no-alerts`
  ([b799083](https://github.com/Dicklesworthstone/rano/commit/b799083f1589f023906ebee70d7ae2b6e08d139d))
- Alerts written to stderr with timestamps and severity levels; JSON mode
  emits structured JSON alert objects
- SQLite alert tracking (`alert=1` column) for post-hoc analysis
  ([8c5bc42](https://github.com/Dicklesworthstone/rano/commit/8c5bc42c3f767c642f68ac2f81273f056c84f9ea))
- Retry/reconnection pattern detection for connection-churn alerting
  ([5e24270](https://github.com/Dicklesworthstone/rano/commit/5e24270f11926bfc59d2ae5d1cf74979e171cdf0))

### Preset System

Bundled configuration profiles for common use cases.

- Built-in presets: `audit`, `quiet`, `live`, `verbose` via `--preset <name>`
  ([2a49a35](https://github.com/Dicklesworthstone/rano/commit/2a49a35bc22ce8c2860aa123b66590e2010e57eb))
- Custom presets in `~/.config/rano/presets/*.conf` with `key=value` format
- `--list-presets` to enumerate available presets
- Multiple presets composable (later wins); CLI flags always override presets

### Process Ancestry Tracking

Full process-tree lineage for every connection.

- Walks `/proc` from PID 1 to the socket-owning process; stores
  `comm:pid,comm:pid,...` chains in SQLite `ancestry_path` column
- Ancestry cache with configurable TTL and staleness detection
  ([4d0ae2f](https://github.com/Dicklesworthstone/rano/commit/4d0ae2f158dae693769fdadd421c47dcb0588e23))

### Themes and Accessibility

- `--theme <vivid|mono|colorblind>` for colour accessibility
- `--color <auto|always|never>` / `--no-color` for ANSI control
- `--no-banner` to suppress the startup banner
  ([1de487a](https://github.com/Dicklesworthstone/rano/commit/1de487a534ab1e468e1ed6461874480c97268209))

### Cross-Platform Fixes

- BSD/macOS support for `reverse_dns` socket structures (4.4BSD `sin_len`
  field differences)
  ([876f5f4](https://github.com/Dicklesworthstone/rano/commit/876f5f45d03f7afaea19c90300fcfaffe81b7f6a))
- Reverse DNS byte order: use `from_ne_bytes` instead of `from_be_bytes`
  ([6bede31](https://github.com/Dicklesworthstone/rano/commit/6bede31ca157b714ccd93a211ac163d773382f32))
- ARM64 compatibility: use `libc::c_char` instead of hardcoded `i8`
  ([10ab758](https://github.com/Dicklesworthstone/rano/commit/10ab758bc598d06593429b8539fad8f64641441f))
- Prevent potential panic from bare division with `checked_div`
  ([18d3762](https://github.com/Dicklesworthstone/rano/commit/18d3762d4eaad210e8751039cafcca9431a773e0))

### Installer

- `install.sh`: curl-pipe-bash installer with `--version`, `--system`,
  `--easy-mode` options; architecture auto-detection; SHA256 verification
- `install.ps1`: PowerShell stub that directs Windows users to WSL 2

### CI / Release Infrastructure

- **ci.yml** -- build + test matrix, `cargo clippy -D warnings`,
  `cargo fmt --check`, E2E test suite
- **dist.yml** -- cross-compile for four targets (x86\_64-linux,
  aarch64-linux, x86\_64-darwin, aarch64-darwin)
- **release-automation.yml** -- push-triggered (main) version-drift tagging that
  publishes GitHub Releases when Cargo.toml version moves past the latest `v*` tag
- pcap feature CI matrix
  ([bf77dbc](https://github.com/Dicklesworthstone/rano/commit/bf77dbcd38526e1355d7aa1e35914d1cb37e7bef))
- Workflow lint job with actionlint
  ([3c699f9](https://github.com/Dicklesworthstone/rano/commit/3c699f909f50032f0c6c75b5b6d0a9f4951f3acd))
- E2E tests: help-command discoverability, diff-command, status-command,
  report-output, batching-under-load, provider-config-override, stats-views
  ([7f58080](https://github.com/Dicklesworthstone/rano/commit/7f580804550d09eeb43b7089ce330229a7502416),
   [ade5805](https://github.com/Dicklesworthstone/rano/commit/ade5805b7a174b993d87fae1435228d40185ff3c),
   [daee398](https://github.com/Dicklesworthstone/rano/commit/daee3980ac0e8e6aaf46c4ded39ec0fbb7e0ac21))
- ACFS notification workflows for installer changes
  ([1c2bf9f](https://github.com/Dicklesworthstone/rano/commit/1c2bf9fe42d9e09aa5e7853900f847334b8cca16),
   [dd96c14](https://github.com/Dicklesworthstone/rano/commit/dd96c14bc2c6371b38c29e26f46d3bb3715c8282))
- Windows target dropped from dist.yml (Unix-only libc APIs)
  ([2875f46](https://github.com/Dicklesworthstone/rano/commit/2875f46d17eadea5da2211150d3169a237564721))
- Bumped GitHub Actions to latest major versions
  ([31481c1](https://github.com/Dicklesworthstone/rano/commit/31481c10cd3d96eb870831076db9155cd7e327f3))
- Fixed upload/download-artifact action versions
  ([0d90b25](https://github.com/Dicklesworthstone/rano/commit/0d90b2508a345deb9800622da64444b6267f640c))

### Build and Toolchain

- Switched from stable to nightly Rust toolchain (edition 2024)
  ([a2c0056](https://github.com/Dicklesworthstone/rano/commit/a2c00564a7d212a17be06a1bf052d38fc7c9c28f))
- Dependency upgrades: toml 0.9 to 1.0, libc, tempfile, rusqlite, and others
  ([6c98869](https://github.com/Dicklesworthstone/rano/commit/6c988690dea3eeb8c817ffe9baf636ee4c595e4b),
   [ca3b4ba](https://github.com/Dicklesworthstone/rano/commit/ca3b4baa3bad69e7156415c8ae4e6f4aff23c6c0))
- Clippy and rustfmt clean
  ([fe112bc](https://github.com/Dicklesworthstone/rano/commit/fe112bc1f675db7fcc67a97acb7b3f84c9617e80),
   [494f259](https://github.com/Dicklesworthstone/rano/commit/494f259ac11f8a1fec23bf34db9ab571684fea68))

### Other

- MIT License with OpenAI/Anthropic Rider
  ([b725a13](https://github.com/Dicklesworthstone/rano/commit/b725a136077ebd3bb129338b4b1283bd3620d252),
   [79a3ed4](https://github.com/Dicklesworthstone/rano/commit/79a3ed4dd66ec992807a65a71b3ff56236acd75c))
- Replaced `lumera-ai` references with `Dicklesworthstone`
  ([f1941a0](https://github.com/Dicklesworthstone/rano/commit/f1941a09f5ee6c4068b96ff965a1d2017a984078))
- GitHub social preview image (1280x640)
  ([64fcdf9](https://github.com/Dicklesworthstone/rano/commit/64fcdf9a6accdf273e4245fd4345361293f52bca))
- Removed stale macOS resource fork file
  ([cbb39d5](https://github.com/Dicklesworthstone/rano/commit/cbb39d588963401cc4b4b6acc2d9745843f9e18f))

---

<!-- link definitions -->
[Unreleased]: https://github.com/Dicklesworthstone/rano/compare/v0.1.0...HEAD
[v0.1.0]: https://github.com/Dicklesworthstone/rano/releases/tag/v0.1.0
