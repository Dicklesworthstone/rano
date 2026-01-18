# Provider config schema (rano.toml)

Status: design for bead rust_agent_network_observer-35w.4.1

Goals
- Allow users to add or override provider matching patterns without recompiling.
- Define a deterministic merge order across multiple config locations.
- Keep failure modes safe (warn and fall back to defaults).

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
`RANO_CONFIG_TOML` paths produce warnings.

`--no-config` disables all config file loading.

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
