# Report Subcommand Design

Status: implemented report contract; the initial design belongs to bead rust_agent_network_observer-35w.2.1. Report insight repairs are tracked in reality-check task .8; their independent companion remains a separate qualification gate.

## CLI Design

```bash
# Show latest session report
rano report --latest

# Show specific session by run_id
rano report --run-id "1234-1705512345000"

# Show report for time range (UTC timestamps)
rano report --since "2026-01-17T00:00:00Z" --until "2026-01-18T00:00:00Z"

# Show report for relative time range
rano report --since "1h"    # last hour
rano report --since "24h"   # last 24 hours
rano report --since "7d"    # last 7 days

# Output format
rano report --latest --json

# Limit top-N entries in lists
rano report --latest --top 10

# Specify SQLite file (if not default)
rano report --sqlite /path/to/rano.sqlite --latest
```

### Flag Summary

| Flag | Description | Default |
|------|-------------|---------|
| `--latest` | Report on most recent session | - |
| `--run-id <id>` | Report on specific session | - |
| `--since <ts>` | Start of time range (UTC or relative) | - |
| `--until <ts>` | End of time range (UTC, exclusive) | no upper bound |
| `--json` | Output as JSON | false |
| `--top <n>` | Limit top-N entries | 10 |
| `--sqlite <path>` | SQLite database path | observer.sqlite |

### Mutual Exclusivity

- `--latest` and `--run-id` are mutually exclusive
- `--since`/`--until` can combine with neither (aggregate mode), `--run-id`, or
  `--latest` (filter within the selected session)

## Time Range Semantics

### Timestamp Format

- The monitor stores RFC3339 UTC. Imported history may use known offsets; queries normalize to UTC rather than comparing raw text.
- CLI accepts:
  - RFC3339 format: `2026-01-17T12:34:56Z`
  - ISO-8601 date only: `2026-01-17` (interpreted as `2026-01-17T00:00:00Z`)
  - Relative duration: `1h`, `24h`, `7d`, `30m` (from now, going backwards)

### Range Semantics

- `--since`: **inclusive** (includes events at exact timestamp)
- `--until`: **exclusive** (excludes events at exact timestamp)
- This matches standard interval notation `[since, until)`

### Relative Time Parsing

```
1h   -> 1 hour ago
24h  -> 24 hours ago
7d   -> 7 days ago
30m  -> 30 minutes ago
```

## Report Sections

### Session Info (when --run-id or --latest)

```
Session: 1234-1705512345000
Started: 2026-01-17T12:34:56Z
Ended:   2026-01-17T14:00:00Z
Host:    myhost
User:    ubuntu
Patterns: claude, codex, gemini
Duration: 1h 25m 4s
```

Source: `sessions` table

### Summary Statistics

```
Total events: 2414
Connects: 1234  Closes: 1180
Observed connect-close balance: 54
Observed event peak: 89 (max per-session stored episode balance)
Close durations: avg=45200.000ms max=332000ms samples=1180
```

Source: selected `events` rows. Duration aggregates include only nonnegative integer close durations; missing samples are unavailable, distinct from measured zero. Full-session metadata counters do not replace filtered event totals.

The event peak orders endpoint connect/close rows by normalized UTC and then event ID (or SQLite rowid for tables without an ID). Earlier history establishes a window's opening balance. Aggregate reports take the maximum per session, never the sum of independent observers. This is an episode-ledger peak, not the monitor's reconciled poll-boundary peak or a reconstruction of unobserved network activity. Same-timestamp opens before closes can create a transient event-order peak. Unmatched closes, invalid timestamps, missing run identity/order or no selected endpoint events return a null peak and an explicit reason.

### Provider Breakdown

```
Provider    Connects  Closes  Domains  IPs
----------  --------  ------  -------  ---
anthropic      789     750       12     8
openai         345     330        8     4
google         100      95        5     3
unknown          0       5        2     2
```

Source: filtered event aggregates plus distinct known domains and peer IPs. Empty/unknown domains and absent-peer sentinels are excluded. The displayed table also includes total events.

### Top Domains

```
Top Domains:
  1. api.anthropic.com        456 events  anthropic [sni]
  2. api.openai.com           234 events  openai [dns]
  ...
```

The actual output is one ranked list of domain/provider pairs, with observed attribution provenance and its event count. It orders by count descending, then domain and provider names, and applies one global `--top` limit.

Unresolved endpoint rows remain visible as the `unknown` domain group. They do
not increase the provider breakdown's distinct-known-domain count. Groups
with several provenance kinds are labeled `mixed`; an SNI observation does
not promote the other rows in the group to SNI evidence.

### Top IPs

```
Top IPs:
  1. 34.149.66.137            567 events
  2. 34.36.57.103             123 events
  ...
```

The actual output is one ranked list of peer IPs across selected providers, ordered by count descending and IP text ascending with a global `--top` limit. For multiple known domains on one IP, the alphabetically first is a deterministic display representative; it is not a claim that all events belong to that domain.

### Hourly Activity

```
Hourly Activity:
  2026-01-17T12:00:00Z  anthropic: 45, openai: 23
  2026-01-17T13:00:00Z  anthropic: 89, openai: 56
  ...
```

Source: filtered event timestamps normalized to UTC, then grouped into hour/provider bins. Single-hour activity is included. Unfiltered reports keep malformed-time rows in totals and expose their count in `unbucketed_events`; filtered queries refuse unorderable timestamps rather than assigning them to a window.

## Queries by Section

| Section | Query/View | Filters |
|---------|-----------|---------|
| Session Info | `sessions WHERE run_id = ?` | run_id |
| Summary | `SELECT COUNT(*) ... FROM events` | run_id or ts range |
| Provider Breakdown | filtered event aggregates and distinct endpoint domain/IP counts | run_id or ts range |
| Top Domains | filtered domain/provider aggregates with provenance | run_id or ts range |
| Top IPs | filtered peer-IP aggregates and deterministic domain representative | run_id or ts range |
| Hourly Activity | normalized UTC hour/provider event aggregates | run_id or ts range |

Report queries use inline aggregates within one read transaction, so every section shares a consistent snapshot. Session metadata remains full-session; JSON labels `metric_scope` (`selected_window` or `selected_sessions`) and `session_metadata_scope` (`full_session`). Time filters use strict normalized comparisons:

```sql
-- Provider counts for time range
SELECT provider,
       COUNT(*) AS events,
       SUM(CASE WHEN event='connect' THEN 1 ELSE 0 END) AS connects,
       SUM(CASE WHEN event='close' THEN 1 ELSE 0 END) AS closes
FROM events
WHERE rano_utc(ts) >= rano_utc(?) AND rano_utc(ts) < rano_utc(?)
GROUP BY provider;
```

## Compatibility Behavior

### Missing Tables/Views

1. Check schema on connect:
   ```sql
   SELECT name FROM sqlite_master WHERE type='table' AND name='events';
   SELECT name FROM sqlite_master WHERE type='view' AND name='provider_counts';
   ```

2. If `events` table missing: error with clear message
   ```
   Error: SQLite file does not contain rano event data
   ```

3. If views missing but `events` exists: warn; report sections use inline queries
   ```
   Warning: SQLite views not found, using fallback queries
   ```

### Schema Version

Future: add `schema_version` to sessions or separate metadata table. For now, assume compatible if `events` table has expected columns.

## JSON Output Format

### Stable Keys (schema version 2.0)

Shape outline; ellipses stand for data objects, not literal JSON values.

```json
{
  "hourly_activity": [...],
  "unbucketed_events": 0,
  "meta": {...},
  "providers": [...],
  "session": {...},
  "summary": {...},
  "top_domains": [...],
  "top_ips": [...],
  "ancestry_roots": [...]
}
```

### Session Object

```json
{
  "session": {
    "connects": 1234,
    "closes": 1180,
    "end_ts": "2026-01-17T14:00:00Z",
    "host": "myhost",
    "patterns": "claude, codex, gemini",
    "run_id": "1234-1705512345000",
    "start_ts": "2026-01-17T12:34:56Z",
    "user": "ubuntu"
  }
}
```

### Summary Object

```json
{
  "summary": {
    "active": 54,
    "avg_duration_ms": 45200,
    "closes": 1180,
    "connects": 1234,
    "max_duration_ms": 332000,
    "peak_active": 89,
    "duration_samples": 1180,
    "total_events": 2414,
    "peak_basis": "max_per_session_stored_episode_balance",
    "peak_order": "utc_then_event_id_or_rowid",
    "peak_unavailable_reason": null
  }
}
```

### Provider Breakdown Array

```json
{
  "providers": [
    {
      "closes": 750,
      "connects": 789,
      "events": 1539,
      "domains": 12,
      "ips": 8,
      "provider": "anthropic"
    }
  ]
}
```

### Top Domains/IPs Arrays

```json
{
  "top_domains": [
    {"domain": "api.anthropic.com", "events": 456, "provider": "anthropic", "source": "sni"}
  ],
  "top_ips": [
    {"events": 567, "ip": "34.149.66.137", "domain": "api.anthropic.com"}
  ]
}
```

### Hourly Activity Array

```json
{
  "hourly_activity": [
    {
      "hour": "2026-01-17T12:00:00Z",
      "providers": {"anthropic": 45, "google": 10, "openai": 23}
    }
  ]
}
```

## Deterministic Ordering

- Provider breakdown: event count descending, then provider name ascending
- Top domains/IPs: by event count DESC, then alphabetically
- Hourly activity: chronological (ASC by hour)
- JSON section keys: fixed schema order; hourly provider keys: alphabetical

## Disposition of the Initial Insight Promises

Close-duration average/maximum and sample counts, provider domain/IP diversity,
UTC hourly activity and stored-event peaks are implemented in the current
source. Their filtered/snapshot semantics and unavailable cases are described
above. Reality-check task .8's author evidence is separate from its open
independent companion .25; implementation presence is not qualification.

Report `summary.active` is the selected connect-minus-close ledger balance,
which may be negative in a close-only window. A held socket can remain in that
history after the observer exits; `status` uses separately validated freshness
and returns zero current activity for an ended session. No report infers
network episodes missing from polling or supplies packet/TLS payload analysis.
The initial alert design's proposed `report --alerts` remains a future
enhancement, not an accepted report option.

## Error Cases

| Condition | Behavior |
|-----------|----------|
| SQLite file not found | Error: "SQLite file not found: {path}" |
| No events table | Error: "Database does not contain rano data" |
| No matching sessions | Error: "No sessions found matching criteria" |
| Invalid time format | Error: "Invalid timestamp format: {value}" |
| Both --latest and --run-id | Error: "--latest and --run-id are mutually exclusive" |
