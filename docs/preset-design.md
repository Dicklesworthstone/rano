# Preset System Design

Status: design for bead bd-db8 (parent: bd-26d)

## Overview

Presets provide named bundles of configuration values to quickly switch monitoring modes.
Presets are applied like config files, with deterministic precedence and merge rules.

## File Format and Location

- **Format**: same `key=value` style as `config.conf` (one setting per line, `#` comments)
- **Location**: `~/.config/rano/presets/<name>.conf`
- **Encoding**: UTF-8

Example preset file:

```ini
# ~/.config/rano/presets/audit.conf
summary_only=true
stats_interval_ms=0
include_udp=false
no_dns=false
```

## Precedence Rules

Settings apply in this order (later wins):

1. Defaults (hard-coded in binary)
2. `config.conf`
3. Preset(s) in the order specified on the CLI
4. CLI flags

If multiple `--preset` flags are used, they are merged in order:

```bash
rano --preset quiet --preset audit
# audit overrides quiet when they set the same key
```

## Built-in Presets (Embedded)

Built-in presets are compiled into the binary and are always available.
User presets override built-in presets of the same name.

| Preset | Purpose | Key settings (example) |
|--------|---------|------------------------|
| `audit` | Security review / minimal noise | `summary_only=true`, `stats_interval_ms=0`, `include_udp=false`, `no_dns=false`, `log_format=json` |
| `quiet` | Reduce terminal output | `summary_only=true`, `stats_interval_ms=0`, `no_banner=true` |
| `live` | Real-time monitoring | `stats_interval_ms=2000`, `stats_view=provider,domain`, `stats_cycle_ms=5000` |
| `verbose` | Maximum detail | `include_udp=true`, `include_listening=true`, `stats_interval_ms=1000`, `stats_top=10` |

Notes:
- These are defaults; users can override any value via CLI or user presets.
- Presets should not set values that require elevated privileges (e.g., forcing pcap).

## CLI Design

### Flags

- `--preset <name>`: Load a named preset (repeatable)
- `--list-presets`: Print available presets with short descriptions and exit

### Example Usage

```bash
# Use built-in audit preset
rano --preset audit

# Merge multiple presets
rano --preset quiet --preset audit

# Use user-defined preset
rano --preset team-default

# List all presets
rano --list-presets
```

## Error Handling

- **Unknown preset**: print available presets (built-in + user) and exit with error.
- **Invalid preset file**: warn, skip invalid lines, continue processing remaining lines.
- **Unreadable preset file**: warn and ignore the preset.

## Output Format for --list-presets

Example output:

```
Available presets:
  audit    - Security review / minimal noise
  quiet    - Reduce terminal output
  live     - Real-time monitoring focus
  verbose  - Maximum detail
  team-default (user) - ~/.config/rano/presets/team-default.conf
```

## Implementation Notes

- Reuse the existing config parser for preset files to avoid divergent behavior.
- Merge order: config.conf -> preset(s) -> CLI flags.
- Built-in presets can be stored as static strings keyed by name.
- User presets are loaded from `~/.config/rano/presets/` and override built-ins of the same name.

