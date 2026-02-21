# AGENTS.md — rano

> Guidelines for AI coding agents working in this Rust codebase.

---

## RULE 0 - THE FUNDAMENTAL OVERRIDE PREROGATIVE

If I tell you to do something, even if it goes against what follows below, YOU MUST LISTEN TO ME. I AM IN CHARGE, NOT YOU.

---

## RULE NUMBER 1: NO FILE DELETION

**YOU ARE NEVER ALLOWED TO DELETE A FILE WITHOUT EXPRESS PERMISSION.** Even a new file that you yourself created, such as a test code file. You have a horrible track record of deleting critically important files or otherwise throwing away tons of expensive work. As a result, you have permanently lost any and all rights to determine that a file or folder should be deleted.

**YOU MUST ALWAYS ASK AND RECEIVE CLEAR, WRITTEN PERMISSION BEFORE EVER DELETING A FILE OR FOLDER OF ANY KIND.**

---

## Irreversible Git & Filesystem Actions — DO NOT EVER BREAK GLASS

1. **Absolutely forbidden commands:** `git reset --hard`, `git clean -fd`, `rm -rf`, or any command that can delete or overwrite code/data must never be run unless the user explicitly provides the exact command and states, in the same message, that they understand and want the irreversible consequences.
2. **No guessing:** If there is any uncertainty about what a command might delete or overwrite, stop immediately and ask the user for specific approval. "I think it's safe" is never acceptable.
3. **Safer alternatives first:** When cleanup or rollbacks are needed, request permission to use non-destructive options (`git status`, `git diff`, `git stash`, copying to backups) before ever considering a destructive command.
4. **Mandatory explicit plan:** Even after explicit user authorization, restate the command verbatim, list exactly what will be affected, and wait for a confirmation that your understanding is correct. Only then may you execute it—if anything remains ambiguous, refuse and escalate.
5. **Document the confirmation:** When running any approved destructive command, record (in the session notes / final response) the exact user text that authorized it, the command actually run, and the execution time. If that record is absent, the operation did not happen.

---

## Git Branch: ONLY Use `main`, NEVER `master`

**The default branch is `main`. The `master` branch exists only for legacy URL compatibility.**

- **All work happens on `main`** — commits, PRs, feature branches all merge to `main`
- **Never reference `master` in code or docs** — if you see `master` anywhere, it's a bug that needs fixing
- **The `master` branch must stay synchronized with `main`** — after pushing to `main`, also push to `master`:
  ```bash
  git push origin main:master
  ```

**If you see `master` referenced anywhere:**
1. Update it to `main`
2. Ensure `master` is synchronized: `git push origin main:master`

---

## Toolchain: Rust & Cargo

We only use **Cargo** in this project, NEVER any other package manager.

- **Edition:** Rust 2024 (stable toolchain — see `rust-toolchain.toml`)
- **Dependency versions:** Explicit versions for stability
- **Configuration:** Single-crate project (no workspace)
- **Unsafe code:** Not explicitly forbidden, but avoided where possible

### Key Dependencies

| Crate | Purpose |
|-------|---------|
| `rusqlite` | SQLite database for durable event logging (bundled) |
| `serde` | Serialization/deserialization (derive feature) |
| `toml` | TOML config file parsing (provider configuration) |
| `libc` | Low-level C interop (signal handling, TTY detection) |
| `pcap` | Optional libpcap packet capture for DNS/SNI domain attribution |

### Dev Dependencies

| Crate | Purpose |
|-------|---------|
| `tempfile` | Temporary file creation for config validation tests |

### Feature Flags

```toml
[features]
default = []
pcap = ["dep:pcap"]   # libpcap-based DNS/TLS SNI domain attribution (requires root/CAP_NET_RAW)
```

### Release Profile

The release build optimizes for performance (this is a CLI binary):

```toml
[profile.release]
# Uses default Cargo release settings (opt-level 3)
```

---

## Code Editing Discipline

### No Script-Based Changes

**NEVER** run a script that processes/changes code files in this repo. Brittle regex-based transformations create far more problems than they solve.

- **Always make code changes manually**, even when there are many instances
- For many simple changes: use parallel subagents
- For subtle/complex changes: do them methodically yourself

### No File Proliferation

If you want to change something or add a feature, **revise existing code files in place**.

**NEVER** create variations like:
- `mainV2.rs`
- `main_improved.rs`
- `main_enhanced.rs`

New files are reserved for **genuinely new functionality** that makes zero sense to include in any existing file. The bar for creating new files is **incredibly high**.

---

## Backwards Compatibility

We do not care about backwards compatibility—we're in early development with no users. We want to do things the **RIGHT** way with **NO TECH DEBT**.

- Never create "compatibility shims"
- Never create wrapper functions for deprecated APIs
- Just fix the code directly

---

## Compiler Checks (CRITICAL)

**After any substantive code changes, you MUST verify no errors were introduced:**

```bash
# Check for compiler errors and warnings (all targets)
cargo check --all-targets

# Check for clippy lints
cargo clippy --all-targets -- -D warnings

# Verify formatting
cargo fmt --check
```

If you see errors, **carefully understand and resolve each issue**. Read sufficient context to fix them the RIGHT way.

---

## Testing

### Testing Policy

Source files include inline `#[cfg(test)]` unit tests alongside the implementation. Tests must cover:
- Happy path
- Edge cases (empty input, max values, boundary conditions)
- Error conditions

E2E tests live in `tests/e2e/` and `scripts/e2e/`.

### Unit Tests

```bash
# Run all tests
cargo test

# Run with output
cargo test -- --nocapture

# Run tests with pcap feature enabled
cargo test --features pcap

# Run all tests with all features
cargo test --all-features
```

### Test Categories

| Location | Focus Areas |
|----------|-------------|
| `src/main.rs` (inline) | CLI arg parsing, provider matching, JSON/pretty formatting, SQLite schema, ancestry chains, glob matching, alert logic, export formatting, diff computation, status templates, report queries |
| `src/config_validation.rs` (inline) | Config file parsing, TOML validation, boolean/enum/integer value checks, unknown keys, path validation |
| `src/pcap_capture.rs` (inline) | Domain cache lookup/eviction, DNS response parsing, TLS SNI extraction, IPv4/IPv6 packet parsing, VLAN tagged frames |
| `tests/e2e/` | Report output, provider config overrides, SQLite batching under load, stats views, diff command, help command, status command |
| `scripts/e2e/` | Alert thresholds, config validation, export formats, pcap attribution, presets, process ancestry |

### Test Fixtures

Test fixtures are stored in `tests/fixtures/`:
- `report_latest.json` / `report_latest.txt` — expected report output
- `pcap/` — pcap capture files for offline DNS/SNI testing

---

## Third-Party Library Usage

If you aren't 100% sure how to use a third-party library, **SEARCH ONLINE** to find the latest documentation and current best practices.

---

## rano — This Project

**This is the project you're working on.** rano (rust_agent_network_observer) is a network observer CLI for AI coding processes that tracks outbound connections from Claude Code, Codex CLI, Gemini CLI, and their descendants — live in the terminal and durably in SQLite.

### What It Does

Polls `/proc` to map sockets to PIDs, tags connections by AI provider (anthropic, openai, google), and prints live events + stats while logging a complete queryable history to SQLite. Optional libpcap mode adds DNS response and TLS SNI hostname attribution.

### Architecture

```
Target Processes (claude / codex / gemini PIDs)
                │
                ▼
        /proc Poller
  sockets ↔ inodes ↔ PIDs
                │
                ▼
    Provider Attribution
  comm/cmdline → provider tag
                │
      ┌─────────┴─────────┐
      ▼                   ▼
 Live Output         SQLite Logger
 pretty/json         events + views
                          │
      ┌───────┬───────────┼───────────┐
      ▼       ▼           ▼           ▼
   Report   Export      Diff       Status
   command  CSV/JSONL   command    shell prompt
```

### Project Structure

```
rano/
├── Cargo.toml                  # Package manifest (single crate, no workspace)
├── rust-toolchain.toml         # Stable Rust toolchain
├── src/
│   ├── main.rs                 # Core binary: monitoring, CLI, reporting, export, diff, status (~10K lines)
│   ├── config_validation.rs    # Config file validation (KV + TOML)
│   └── pcap_capture.rs         # DNS/SNI packet capture and domain cache
├── tests/
│   ├── e2e/                    # E2E shell test scripts
│   └── fixtures/               # Test fixtures (report snapshots, pcap files)
├── scripts/
│   └── e2e/                    # E2E test harness (lib.sh, run.sh, feature scripts)
├── docs/                       # Design documents (alerts, exports, pcap, presets, providers, reports)
├── install.sh                  # Cross-platform installer (Linux/macOS)
├── install.ps1                 # Windows PowerShell installer
└── .github/workflows/          # CI configuration
```

### Key Source Modules

| File | Key Types & Functions | Purpose |
|------|----------------------|---------|
| `src/main.rs` | `MonitorArgs`, `Cli`, `Command` | CLI argument parsing with manual arg parser (no clap) |
| `src/main.rs` | `Provider`, `ProviderMatcher` | Provider attribution (anthropic/openai/google/unknown) |
| `src/main.rs` | `ConnKey`, `ConnInfo`, `NetEntry` | Connection tracking state |
| `src/main.rs` | `SqliteWriter`, `SqliteEvent`, `SqliteMsg` | Async batched SQLite event logging |
| `src/main.rs` | `Stats`, `RunContext` | Live statistics and session context |
| `src/main.rs` | `AlertConfig`, `AlertState`, `AlertKind` | Alerting subsystem (domain patterns, thresholds, cooldowns) |
| `src/main.rs` | `RetryTracker`, `RetryWarning` | Connection retry storm detection |
| `src/main.rs` | `AncestryCache` | Process ancestry chain resolution with TTL-based caching |
| `src/main.rs` | `PresetLoader`, `PresetInfo` | Built-in and user-defined configuration presets |
| `src/main.rs` | `ExportArgs`, `ExportFilter` | CSV/JSONL export with time/provider/domain filters |
| `src/main.rs` | `DiffArgs`, `DiffResult` | Session comparison (new/removed/changed domains, processes, providers) |
| `src/main.rs` | `StatusArgs`, `StatusData` | Shell prompt integration with template expansion |
| `src/main.rs` | `ReportArgs`, `ReportFilter` | Session report generation (JSON + pretty) |
| `src/main.rs` | `OutputStyle`, `AnsiColor`, `LogWriter` | Color themes (vivid/mono/colorblind) and file logging |
| `src/config_validation.rs` | `ConfigValidator`, `ValidationResult` | KV config + TOML provider config validation |
| `src/pcap_capture.rs` | `DomainCache`, `PcapHandle`, `PcapMsg` | DNS response + TLS SNI capture and IP-to-hostname cache |

### Commands

| Command | Description |
|---------|-------------|
| `rano` (default) | Monitor outbound connections with live events and stats |
| `rano report` | Generate reports from SQLite event history |
| `rano export` | Export events to CSV or JSONL with filters |
| `rano diff` | Compare two monitoring sessions for behavioral changes |
| `rano status` | One-line status output for shell prompt integration |
| `rano config check` | Validate configuration files |
| `rano config show` | Display resolved configuration |
| `rano config paths` | Show config file search paths |
| `rano update` | Self-update the installed binary |

### Configuration Files

| Path | Format | Purpose |
|------|--------|---------|
| `~/.config/rano/config.conf` | `key=value` | Default monitor settings |
| `~/.rano.toml` / `~/.config/rano/rano.toml` | TOML | Provider pattern customization |
| `~/.config/rano/presets/*.conf` | `key=value` | User-defined presets |

### Built-in Presets

| Preset | Description |
|--------|-------------|
| `audit` | Security review / minimal noise |
| `quiet` | Reduce terminal output |
| `live` | Real-time monitoring focus |
| `verbose` | Maximum detail |

### Key Design Decisions

- **No clap or structopt** — manual argument parser keeps binary small and dependency-free
- **`/proc` polling** — avoids ptrace or intrusive hooks, works without elevated privileges
- **Provider attribution by substring matching** — comm + cmdline checked against configurable pattern lists
- **Async SQLite batching** — dedicated writer thread with bounded channel, configurable batch size and flush interval
- **Process ancestry caching** — 30-second TTL with staleness detection (comm name change invalidation)
- **Dual domain resolution modes** — PTR (unprivileged) or pcap (DNS + TLS SNI, requires root/CAP_NET_RAW)
- **Session-based reporting** — each run generates a unique `run_id` for later querying/diffing
- **Alert cooldown deduplication** — prevents alert spam with configurable cooldown per alert signature
- **Glob matching** — hand-rolled `glob_match_impl()` for domain pattern alerts (no regex dep)
- **RFC 4180 CSV export** — proper field escaping for Excel compatibility
- **Template-based status** — `{active}`, `{anthropic}`, etc. for shell prompt integration

---

## MCP Agent Mail — Multi-Agent Coordination

A mail-like layer that lets coding agents coordinate asynchronously via MCP tools and resources. Provides identities, inbox/outbox, searchable threads, and advisory file reservations with human-auditable artifacts in Git.

### Why It's Useful

- **Prevents conflicts:** Explicit file reservations (leases) for files/globs
- **Token-efficient:** Messages stored in per-project archive, not in context
- **Quick reads:** `resource://inbox/...`, `resource://thread/...`

### Same Repository Workflow

1. **Register identity:**
   ```
   ensure_project(project_key=<abs-path>)
   register_agent(project_key, program, model)
   ```

2. **Reserve files before editing:**
   ```
   file_reservation_paths(project_key, agent_name, ["src/**"], ttl_seconds=3600, exclusive=true)
   ```

3. **Communicate with threads:**
   ```
   send_message(..., thread_id="FEAT-123")
   fetch_inbox(project_key, agent_name)
   acknowledge_message(project_key, agent_name, message_id)
   ```

4. **Quick reads:**
   ```
   resource://inbox/{Agent}?project=<abs-path>&limit=20
   resource://thread/{id}?project=<abs-path>&include_bodies=true
   ```

### Macros vs Granular Tools

- **Prefer macros for speed:** `macro_start_session`, `macro_prepare_thread`, `macro_file_reservation_cycle`, `macro_contact_handshake`
- **Use granular tools for control:** `register_agent`, `file_reservation_paths`, `send_message`, `fetch_inbox`, `acknowledge_message`

### Common Pitfalls

- `"from_agent not registered"`: Always `register_agent` in the correct `project_key` first
- `"FILE_RESERVATION_CONFLICT"`: Adjust patterns, wait for expiry, or use non-exclusive reservation
- **Auth errors:** If JWT+JWKS enabled, include bearer token with matching `kid`

---

## Beads (br) — Dependency-Aware Issue Tracking

Beads provides a lightweight, dependency-aware issue database and CLI (`br` - beads_rust) for selecting "ready work," setting priorities, and tracking status. It complements MCP Agent Mail's messaging and file reservations.

### Conventions

- **Single source of truth:** Beads for task status/priority/dependencies; Agent Mail for conversation and audit
- **Shared identifiers:** Use Beads issue ID (e.g., `br-123`) as Mail `thread_id` and prefix subjects with `[br-123]`
- **Reservations:** When starting a task, call `file_reservation_paths()` with the issue ID in `reason`

### Typical Agent Flow

1. **Pick ready work (Beads):**
   ```bash
   bd ready --json  # Choose highest priority, no blockers
   ```

2. **Reserve edit surface (Mail):**
   ```
   file_reservation_paths(project_key, agent_name, ["src/**"], ttl_seconds=3600, exclusive=true, reason="br-123")
   ```

3. **Announce start (Mail):**
   ```
   send_message(..., thread_id="br-123", subject="[br-123] Start: <title>", ack_required=true)
   ```

4. **Work and update:** Reply in-thread with progress

5. **Complete and release:**
   ```bash
   bd close 123 --reason "Completed"
   bd sync  # Export to JSONL (no git operations)
   ```
   ```
   release_file_reservations(project_key, agent_name, paths=["src/**"])
   ```
   Final Mail reply: `[br-123] Completed` with summary

### Mapping Cheat Sheet

| Concept | Value |
|---------|-------|
| Mail `thread_id` | `br-###` |
| Mail subject | `[br-###] ...` |
| File reservation `reason` | `br-###` |
| Commit messages | Include `br-###` for traceability |

---

## bv — Graph-Aware Triage Engine

bv is a graph-aware triage engine for Beads projects (`.beads/beads.jsonl`). It computes PageRank, betweenness, critical path, cycles, HITS, eigenvector, and k-core metrics deterministically.

**Scope boundary:** bv handles *what to work on* (triage, priority, planning). For agent-to-agent coordination (messaging, work claiming, file reservations), use MCP Agent Mail.

**CRITICAL: Use ONLY `--robot-*` flags. Bare `bv` launches an interactive TUI that blocks your session.**

### The Workflow: Start With Triage

**`bv --robot-triage` is your single entry point.** It returns:
- `quick_ref`: at-a-glance counts + top 3 picks
- `recommendations`: ranked actionable items with scores, reasons, unblock info
- `quick_wins`: low-effort high-impact items
- `blockers_to_clear`: items that unblock the most downstream work
- `project_health`: status/type/priority distributions, graph metrics
- `commands`: copy-paste shell commands for next steps

```bash
bv --robot-triage        # THE MEGA-COMMAND: start here
bv --robot-next          # Minimal: just the single top pick + claim command
```

### Command Reference

**Planning:**
| Command | Returns |
|---------|---------|
| `--robot-plan` | Parallel execution tracks with `unblocks` lists |
| `--robot-priority` | Priority misalignment detection with confidence |

**Graph Analysis:**
| Command | Returns |
|---------|---------|
| `--robot-insights` | Full metrics: PageRank, betweenness, HITS, eigenvector, critical path, cycles, k-core, articulation points, slack |
| `--robot-label-health` | Per-label health: `health_level`, `velocity_score`, `staleness`, `blocked_count` |
| `--robot-label-flow` | Cross-label dependency: `flow_matrix`, `dependencies`, `bottleneck_labels` |
| `--robot-label-attention [--attention-limit=N]` | Attention-ranked labels |

**History & Change Tracking:**
| Command | Returns |
|---------|---------|
| `--robot-history` | Bead-to-commit correlations |
| `--robot-diff --diff-since <ref>` | Changes since ref: new/closed/modified issues, cycles |

**Other:**
| Command | Returns |
|---------|---------|
| `--robot-burndown <sprint>` | Sprint burndown, scope changes, at-risk items |
| `--robot-forecast <id\|all>` | ETA predictions with dependency-aware scheduling |
| `--robot-alerts` | Stale issues, blocking cascades, priority mismatches |
| `--robot-suggest` | Hygiene: duplicates, missing deps, label suggestions |
| `--robot-graph [--graph-format=json\|dot\|mermaid]` | Dependency graph export |
| `--export-graph <file.html>` | Interactive HTML visualization |

### Scoping & Filtering

```bash
bv --robot-plan --label backend              # Scope to label's subgraph
bv --robot-insights --as-of HEAD~30          # Historical point-in-time
bv --recipe actionable --robot-plan          # Pre-filter: ready to work
bv --recipe high-impact --robot-triage       # Pre-filter: top PageRank
bv --robot-triage --robot-triage-by-track    # Group by parallel work streams
bv --robot-triage --robot-triage-by-label    # Group by domain
```

### Understanding Robot Output

**All robot JSON includes:**
- `data_hash` — Fingerprint of source beads.jsonl
- `status` — Per-metric state: `computed|approx|timeout|skipped` + elapsed ms
- `as_of` / `as_of_commit` — Present when using `--as-of`

**Two-phase analysis:**
- **Phase 1 (instant):** degree, topo sort, density
- **Phase 2 (async, 500ms timeout):** PageRank, betweenness, HITS, eigenvector, cycles

### jq Quick Reference

```bash
bv --robot-triage | jq '.quick_ref'                        # At-a-glance summary
bv --robot-triage | jq '.recommendations[0]'               # Top recommendation
bv --robot-plan | jq '.plan.summary.highest_impact'        # Best unblock target
bv --robot-insights | jq '.status'                         # Check metric readiness
bv --robot-insights | jq '.Cycles'                         # Circular deps (must fix!)
```

---

## UBS — Ultimate Bug Scanner

**Golden Rule:** `ubs <changed-files>` before every commit. Exit 0 = safe. Exit >0 = fix & re-run.

### Commands

```bash
ubs file.rs file2.rs                    # Specific files (< 1s) — USE THIS
ubs $(git diff --name-only --cached)    # Staged files — before commit
ubs --only=rust,toml src/               # Language filter (3-5x faster)
ubs --ci --fail-on-warning .            # CI mode — before PR
ubs .                                   # Whole project (ignores target/, Cargo.lock)
```

### Output Format

```
Warning  Category (N errors)
    file.rs:42:5 – Issue description
    Suggested fix
Exit code: 1
```

Parse: `file:line:col` -> location | Suggested fix -> how to fix | Exit 0/1 -> pass/fail

### Fix Workflow

1. Read finding -> category + fix suggestion
2. Navigate `file:line:col` -> view context
3. Verify real issue (not false positive)
4. Fix root cause (not symptom)
5. Re-run `ubs <file>` -> exit 0
6. Commit

### Bug Severity

- **Critical (always fix):** Memory safety, use-after-free, data races, SQL injection
- **Important (production):** Unwrap panics, resource leaks, overflow checks
- **Contextual (judgment):** TODO/FIXME, println! debugging

---

## RCH — Remote Compilation Helper

RCH offloads `cargo build`, `cargo test`, `cargo clippy`, and other compilation commands to a fleet of 8 remote Contabo VPS workers instead of building locally. This prevents compilation storms from overwhelming csd when many agents run simultaneously.

**RCH is installed at `~/.local/bin/rch` and is hooked into Claude Code's PreToolUse automatically.** Most of the time you don't need to do anything if you are Claude Code — builds are intercepted and offloaded transparently.

To manually offload a build:
```bash
rch exec -- cargo build --release
rch exec -- cargo test
rch exec -- cargo clippy
```

Quick commands:
```bash
rch doctor                    # Health check
rch workers probe --all       # Test connectivity to all 8 workers
rch status                    # Overview of current state
rch queue                     # See active/waiting builds
```

If rch or its workers are unavailable, it fails open — builds run locally as normal.

**Note for Codex/GPT-5.2:** Codex does not have the automatic PreToolUse hook, but you can (and should) still manually offload compute-intensive compilation commands using `rch exec -- <command>`. This avoids local resource contention when multiple agents are building simultaneously.

---

## ast-grep vs ripgrep

**Use `ast-grep` when structure matters.** It parses code and matches AST nodes, ignoring comments/strings, and can **safely rewrite** code.

- Refactors/codemods: rename APIs, change import forms
- Policy checks: enforce patterns across a repo
- Editor/automation: LSP mode, `--json` output

**Use `ripgrep` when text is enough.** Fastest way to grep literals/regex.

- Recon: find strings, TODOs, log lines, config values
- Pre-filter: narrow candidate files before ast-grep

### Rule of Thumb

- Need correctness or **applying changes** -> `ast-grep`
- Need raw speed or **hunting text** -> `rg`
- Often combine: `rg` to shortlist files, then `ast-grep` to match/modify

### Rust Examples

```bash
# Find structured code (ignores comments)
ast-grep run -l Rust -p 'fn $NAME($$$ARGS) -> $RET { $$$BODY }'

# Find all unwrap() calls
ast-grep run -l Rust -p '$EXPR.unwrap()'

# Quick textual hunt
rg -n 'println!' -t rust

# Combine speed + precision
rg -l -t rust 'unwrap\(' | xargs ast-grep run -l Rust -p '$X.unwrap()' --json
```

---

## Morph Warp Grep — AI-Powered Code Search

**Use `mcp__morph-mcp__warp_grep` for exploratory "how does X work?" questions.** An AI agent expands your query, greps the codebase, reads relevant files, and returns precise line ranges with full context.

**Use `ripgrep` for targeted searches.** When you know exactly what you're looking for.

**Use `ast-grep` for structural patterns.** When you need AST precision for matching/rewriting.

### When to Use What

| Scenario | Tool | Why |
|----------|------|-----|
| "How does the alert system work?" | `warp_grep` | Exploratory; don't know where to start |
| "Where is the SQLite schema defined?" | `warp_grep` | Need to understand architecture |
| "Find all uses of `Provider::Anthropic`" | `ripgrep` | Targeted literal search |
| "Find files with `println!`" | `ripgrep` | Simple pattern |
| "Replace all `unwrap()` with `expect()`" | `ast-grep` | Structural refactor |

### warp_grep Usage

```
mcp__morph-mcp__warp_grep(
  repoPath: "/dp/rano",
  query: "How does the provider attribution work?"
)
```

Returns structured results with file paths, line ranges, and extracted code snippets.

### Anti-Patterns

- **Don't** use `warp_grep` to find a specific function name -> use `ripgrep`
- **Don't** use `ripgrep` to understand "how does X work" -> wastes time with manual reads
- **Don't** use `ripgrep` for codemods -> risks collateral edits
## Landing the Plane (Session Completion)

**When ending a work session**, you MUST complete ALL steps below.

**MANDATORY WORKFLOW:**

1. **File issues for remaining work** - Create issues for anything that needs follow-up
2. **Run quality gates** (if code changed) - Tests, linters, builds
3. **Update issue status** - Close finished work, update in-progress items
4. **Sync beads** - `bd sync` to export to JSONL
5. **Hand off** - Provide context for next session

---

## Note for Codex/GPT-5.2

You constantly bother me and stop working with concerned questions that look similar to this:

```
Unexpected changes (need guidance)

- Working tree still shows edits I did not make in Cargo.toml, Cargo.lock, src/main.rs, src/patterns.rs. Please advise whether to keep/commit/revert these before any further work. I did not touch them.

Next steps (pick one)

1. Decide how to handle the unrelated modified files above so we can resume cleanly.
```

NEVER EVER DO THAT AGAIN. The answer is literally ALWAYS the same: those are changes created by the potentially dozen of other agents working on the project at the same time. This is not only a common occurrence, it happens multiple times PER MINUTE. The way to deal with it is simple: you NEVER, under ANY CIRCUMSTANCE, stash, revert, overwrite, or otherwise disturb in ANY way the work of other agents. Just treat those changes identically to changes that you yourself made. Just fool yourself into thinking YOU made the changes and simply don't recall it for some reason.

---

## Note on Built-in TODO Functionality

Also, if I ask you to explicitly use your built-in TODO functionality, don't complain about this and say you need to use beads. You can use built-in TODOs if I tell you specifically to do so. Always comply with such orders.

<!-- beads-agent-instructions-v2 -->

---

## Beads Workflow Integration

This project uses [beads](https://github.com/steveyegge/beads) for issue tracking. Issues live in `.beads/` and are tracked in git.

Two CLIs: **bd** (issue CRUD) and **bv** (graph-aware triage, read-only).

### bd: Issue Management

```bash
bd ready              # Unblocked issues ready to work
bd list --status=open # All open issues
bd show <id>          # Full details with dependencies
bd create --title="..." --type=task --priority=2
bd update <id> --status=in_progress
bd close <id>         # Mark complete
bd close <id1> <id2>  # Close multiple
bd dep add <a> <b>    # a depends on b
bd sync               # Sync with git
```

### bv: Graph Analysis (read-only)

**NEVER run bare `bv`** — it launches interactive TUI. Always use `--robot-*` flags:

```bash
bv --robot-triage     # Ranked picks, quick wins, blockers, health
bv --robot-next       # Single top pick + claim command
bv --robot-plan       # Parallel execution tracks
bv --robot-alerts     # Stale issues, cascades, mismatches
bv --robot-insights   # Full graph metrics: PageRank, betweenness, cycles
```

### Workflow

1. **Start**: `bd ready` (or `bv --robot-triage` for graph analysis)
2. **Claim**: `bd update <id> --status=in_progress`
3. **Work**: Implement the task
4. **Complete**: `bd close <id>`
5. **Sync**: `bd sync` at session end

### Session Close Protocol

```bash
git status            # Check what changed
git add <files>       # Stage code changes
bd sync               # Commit beads changes
git commit -m "..."   # Commit code
bd sync               # Commit any new beads changes
git push              # Push to remote
```

### Key Concepts

- **Priority**: P0=critical, P1=high, P2=medium, P3=low, P4=backlog (numbers only)
- **Types**: task, bug, feature, epic, question, docs
- **Dependencies**: `bd ready` shows only unblocked work

<!-- end-beads-agent-instructions -->
