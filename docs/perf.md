# Performance

Evidence for the low-overhead design pillar. Historical measurements below are retained with their limits; they do not qualify the current source. The repaired soak requires actual accepted progress, durable row growth and a complete final summary. Scan/throughput benchmark repair and whole-mode cache/resolver qualification remain in progress.

**Hardware note**: benchmarks below were captured on an AMD EPYC (Genoa) VM, Linux 6.x, rustc nightly (`rust-toolchain.toml`), release profile, 2026-08-24. Absolute numbers shift with hardware; the ratios and boundedness claims are what matter.

## Scan-pass latency (`scripts/bench.sh`)

Historical wall time of a complete `rano --pid <holder> --once` run includes startup, `/proc` scanning, attribution, default DNS/SQLite and pretty output. The old harness neither asserted fixture readiness nor validated observation counts, and suppressed command failures. Its means were:

| Tracked connections | Mean pass time |
|--------------------:|---------------:|
| 500                 | ~30 ms         |
| 2000                | ~30 ms         |

These means do not establish flat scaling or a universal duty cycle. A later CI invocation at `7f342a3` measured 38.100 ms for 500 and 103.266 ms for 2000 on different hardware (2026-10-08, run 37765403655); that comparison is not a speedup claim. A new optimization result requires candidate and incumbent in the same invocation with validated socket counts and identical flags. Pure no-DNS/no-SQLite scans must be reported separately from default end-to-end costs.

## Durable SQLite throughput

Connection-churn generator driving events through the batched writer at `--interval-ms 20`, counting rows that actually landed in SQLite over the run window:

| `--db-batch-size` | Rows durably written | Observed durable rate | Drops |
|------------------:|---------------------:|----------------------:|------:|
| 200               | 2400                 | ~217 events/s         | 0     |
| 1000              | 2400                 | ~217 events/s         | 0     |

The historical rate is workload-specific and does not establish a throughput ceiling. `--db-queue-max` defaults to 10,000; `sqlite_dropped` reconciles queue and write losses. Current summaries also report observed/persisted counts and sink failure. A successful durable measurement requires all those counters to reconcile with actual SQLite rows.

## Memory soak (`scripts/e2e/soak-memory.sh`)

Accelerated long-session check: churned short-lived connections at `--interval-ms 100`, RSS sampled every 5 s.

The revised script uses a dynamic port, accepts every generated TCP connection, holds both endpoints across polls, and checks generated/accepted progress plus durable row growth at every interval. stdout, stderr, file log, SQLite, invocation metadata and RSS/progress samples are retained. Cleanup targets only its own processes.

Assertions enforced by the revised script:

1. **Bounded RSS**: final RSS < 2× the post-minute baseline.
2. **Continued progress**: generation, acceptance and durable rows increase throughout the requested duration.
3. **Zero event drops**: a mandatory complete final summary reports zero queue/write losses, successful enabled SQLite and healthy observation/file output.
4. **Count conservation**: observed/persisted counters, connect/close totals, actual SQLite rows and finalized session totals agree.
5. **Negative controls**: `SOAK_STALL_AFTER=6` stops the real generator; `SOAK_OMIT_SUMMARY=1` validates a retained stream with its summary omitted. Both runs must fail. The normal run also checks that its validator rejects an absent summary.

Historical full-duration run (600 s, EPYC Genoa VM, 2026-08-24):
RSS plateaued within the first minute (~10.5 MB) and never grew — final
10,668 KB vs post-minute baseline 10,524 KB (**+1.4%**, peak 10,744 KB) —
with **2,031 events durably written and zero `sqlite_dropped`**.
Full sample series: `logs/e2e/soak-memory-20260824T081800Z.log`.

That producer never accepted its listener's backlog and stopped progressing. The RSS result applies to a finite stalled workload, not sustained churn. The repaired >=600-second run and broader endpoint/PID, PTR, ancestry and pcap/cache axes remain unqualified. Runs shorter than 600 s are explicitly smoke tests. `SOAK_SOURCE_REVISION` must identify the binary's exact build receipt for a long run; workspace HEAD and the binary hash are recorded separately and are not substitutes for that binding.

The stats-view regression now waits for all four requested views against held real sockets, then checks durable observations and a healthy graceful summary. Its 20 s watchdog bounds failure; it makes no 1 s rendering or poll-latency claim. Missing-view, missing-summary and nonzero-exit controls must fail.

## Reproducing

```bash
cargo build --release
scripts/bench.sh target/release/rano
SOAK_SECS=600 SOAK_SOURCE_REVISION="$(git rev-parse HEAD)" \
  scripts/e2e/run.sh soak-memory scripts/e2e/soak-memory.sh
```
