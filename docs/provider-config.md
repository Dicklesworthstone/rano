# Provider config schema (rano.toml)

Status: implemented configuration contract; original design for bead rust_agent_network_observer-35w.4.1. Resolution repairs are tracked by reality-check task .12; its independent verification remains open.

Goals
- Allow users to add or override provider matching patterns without recompiling.
- Define a deterministic merge order across multiple config locations.
- Fail invalid selected sources explicitly; retain unknown-key warnings without substituting defaults for an invalid configuration.

## File discovery and precedence

Provider config is a TOML file named `rano.toml`.

Search order (lowest precedence first):
1. `~/.rano.toml`
2. `$XDG_CONFIG_HOME/rano/rano.toml` (or `~/.config/rano/rano.toml`)
3. `./rano.toml` (current working directory)
4. `--config-toml <path>` (CLI override)
5. `RANO_CONFIG_TOML` (environment override)

Files are applied in order; later files override or extend earlier ones.
Missing default files are ignored. Missing `--config-toml` or
`RANO_CONFIG_TOML` paths, an empty environment override, unreadable selected
files, invalid TOML and invalid provider values fail check/show/monitor.
A later override cannot conceal an invalid earlier selected source. Unknown
keys remain visible warnings. The same resolution drives `config check`,
`config show` and monitoring; inspection opens no output sinks or capture.

`--no-config` disables all config file loading.

`config show --json` includes the effective provider lists, their origins,
selected sources and warnings. It masks recognized credential values in
inspection output while original values still drive matching.

## Schema

```toml
[providers]
# Optional: merge (default) or replace
mode = "merge"

anthropic = ["claude", "anthropic"]
openai = ["codex", "openai"]
google = ["gemini", "google"]
```

### Fields
- `providers.mode`: `merge` (default) or `replace`.
- `providers.anthropic|openai|google`: list of case-insensitive substring
  patterns matched against `comm` and `cmdline`.

## Merge rules

- Start with built-in defaults.
- For each config file in precedence order:
  - If `providers.mode = "replace"`, clear all provider patterns first.
  - For each provider list present, apply patterns:
    - `merge`: append new patterns (deduped).
    - `replace`: use exactly the listed patterns for that provider.
- Patterns are normalized by trimming whitespace, lowercasing, and de-duping.

Provider classification uses the original process comm and argv. A unique
direct match wins; otherwise an unmarked or ambiguous process may inherit
the nearest uniquely matched ancestor inside its monitored tree. Socket
ownership records preserve the provider-origin PID/start time and distinguish
direct matching from ancestor inheritance. Patterns identify providers;
they do not identify which holder initiated a shared socket.

## Examples

Minimal merge override:
```toml
[providers]
openai = ["corp-wrapper"]
```

Replace all patterns:
```toml
[providers]
mode = "replace"
openai = ["internal-cli"]
```
