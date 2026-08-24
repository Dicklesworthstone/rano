# Performance

Evidence for the "low overhead" design pillar (README: *polling `/proc` is fast*). Numbers below are measured, reproducible via `scripts/bench.sh` and `scripts/e2e/soak-memory.sh`; replace them whenever hardware or the hot path changes.

**Hardware note**: benchmarks below were captured on an AMD EPYC (Genoa) VM, Linux 6.x, rustc nightly (`rust-toolchain.toml`), release profile, 2026-08-24. Absolute numbers shift with hardware; the ratios and boundedness claims are what matter.

## Scan-pass latency (`scripts/bench.sh`)

Wall time of a complete `rano --pid <holder> --once` run — process startup, one full `/proc/net/{tcp,udp}` scan, socket→inode→PID mapping, provider attribution, and JSON emission — with N established connections held open by the tracked process. Mean of 30 passes:

| Tracked connections | Mean pass time |
|--------------------:|---------------:|
| 500                 | ~30 ms         |
| 2000                | ~30 ms         |

Flat scaling from 500 → 2000 connections confirms per-connection work is negligible next to fixed startup cost (~30 ms of exec/init). At the default `--interval-ms 1000` cadence this is a ~3% duty cycle even against 2000 live connections.

## Durable SQLite throughput

Connection-churn generator driving events through the batched writer at `--interval-ms 20`, counting rows that actually landed in SQLite over the run window:

| `--db-batch-size` | Rows durably written | Observed durable rate | Drops |
|------------------:|---------------------:|----------------------:|------:|
| 200               | 2400                 | ~217 events/s         | 0     |
| 1000              | 2400                 | ~217 events/s         | 0     |

The observed rate matches the generator's event arrival rate — i.e., the writer kept up end-to-end and batch size showed no measurable effect at audit-scale load. The bounded channel (`--db-queue-max`, default 1024) plus batch flush design means saturation would first appear as `sqlite_dropped > 0` in the summary; the soak below asserts it stays zero.

## Memory soak (`scripts/e2e/soak-memory.sh`)

Accelerated long-session check: churned short-lived connections at `--interval-ms 100`, RSS sampled every 5 s.

Assertions enforced by the script:

1. **Bounded RSS**: final RSS < 2× the post-minute baseline.
2. **Zero event drops**: final summary reports `sqlite_dropped = 0`.

Latest full-duration run (600 s accelerated, EPYC Genoa VM, 2026-08-24):
RSS plateaued within the first minute (~10.5 MB) and never grew — final
10,668 KB vs post-minute baseline 10,524 KB (**+1.4%**, peak 10,744 KB) —
with **2,031 events durably written and zero `sqlite_dropped`**.
Full sample series: `logs/e2e/soak-memory-20260824T081800Z.log`.


## Reproducing

```bash
cargo build --release
scripts/bench.sh target/release/rano
SOAK_SECS=600 scripts/e2e/run.sh soak-memory scripts/e2e/soak-memory.sh
```
