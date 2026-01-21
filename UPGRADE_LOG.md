# Rano Dependency Upgrade Log

## Upgrade Summary

| Dependency | From | To | Status | Notes |
|------------|------|-----|--------|-------|
| rusqlite | 0.32 | 0.38 | Pending | Major upgrade, requires API review |
| toml | 0.8 | 0.9 | Pending | Breaking changes in parsing/serialization APIs |
| pcap | 1.1 | 2.4 | Pending | `Device::lookup()` return type changed |
| serde | 1.0 | 1.0.228 | Pending | Minor update, backwards compatible |
| libc | 0.2 | 0.2 | Pending | Keep at 0.2.x (1.0 is alpha) |

## GitHub Actions Updates

| Action | From | To | Status |
|--------|------|-----|--------|
| actions/checkout | v4 | v6 | Pending |
| actions/cache | v4 | v4 | Already current |
| actions/upload-artifact | v4 | v4 | Already current |
| actions/download-artifact | v4 | v4 | Already current |

---

## Detailed Upgrade Notes

### rusqlite 0.32 -> 0.38

**Breaking Changes Identified:**
- v0.34.0: Error type changes for `ValueRef` methods
- v0.35.0: `Connection::execute` now checks for trailing statements
- v0.35.0: `prepare` now checks for multiple statements
- Various MSRV bumps

**Code Impact Assessment:**
- Project uses `rusqlite::{params, Connection}`
- Uses `query_row`, `execute_batch`, `prepare`, `query_map`
- Should be mostly compatible, may need minor adjustments

### toml 0.8 -> 0.9

**Breaking Changes Identified:**
- `from_str`, `Deserializer` no longer preserve insertion order by default
- Serde support moved to default `serde` feature
- `impl FromStr for Value` now parses TOML values, not documents
- `Deserializer::new` and `ValueDeserializer::new` now return errors

**Code Impact Assessment:**
- Project uses `toml::from_str` for config parsing
- Uses `#[derive(Deserialize)]` for TomlConfig struct
- Should be compatible with simple `from_str` usage

### pcap 1.1 -> 2.4

**Breaking Changes Identified:**
- `Device::lookup()` signature changed to `Result<Option<Device>, Error>` (was `Result<Device, Error>`)
- `Capture::next()` renamed to `next_packet()` - ALREADY USING next_packet()
- `Capture` and `Savefile` removed `Sync` trait
- MSRV is now 1.63.0+

**Code Impact Assessment:**
- Uses `Device::lookup()` - NEEDS FIX: requires unwrapping Option
- Uses `Capture::from_device()` - compatible
- Uses `next_packet()` - compatible
- Uses `pcap::Error::NoPacket` - need to verify

---

## Upgrade Process Log

### Step 1: Update Cargo.toml

