# Performance

Evidence for the low-overhead design pillar. Historical measurements below are retained with their limits; they do not qualify the current source. The repaired soak and benchmark require actual accepted progress, exact observed/durable counts and complete final summaries. Whole-mode cache/resolver qualification remains in progress.

**Hardware note**: benchmarks below were captured on an AMD EPYC (Genoa) VM, Linux 6.x, rustc nightly (`rust-toolchain.toml`), release profile, 2026-08-24. Absolute numbers shift with hardware; the ratios and boundedness claims are what matter.

## Scan-pass latency (`scripts/bench.sh`)

Historical wall time of a complete `rano --pid <holder> --once` run includes startup, `/proc` scanning, attribution, default DNS/SQLite and pretty output. The old harness neither asserted fixture readiness nor validated observation counts, and suppressed command failures. Its means were:

| Tracked connections | Mean pass time |
|--------------------:|---------------:|
| 500                 | ~30 ms         |
| 2000                | ~30 ms         |

These means do not establish flat scaling or a universal duty cycle. A later CI invocation at `7f342a3` measured 38.100 ms for 500 and 103.266 ms for 2000 on different hardware (2026-10-08, run 37765403655); that comparison is not a speedup claim. A new optimization result requires candidate and incumbent in the same invocation with validated socket counts and identical flags. Pure no-DNS/no-SQLite scans must be reported separately from default end-to-end costs.

The revised harness synchronously connects and accepts every dynamic-port fixture pair before measuring. It targets its own socket-owning PID, holds both endpoints until all measured commands complete, and requires exactly twice the pair count in emitted opens and the final summary. It separates no-DNS/no-SQLite invocation costs from default PTR/SQLite invocation costs; both include startup, output and finalization, rather than claiming individual poll latency. It reports mean, median, p95 and maximum, retains stdout/stderr and records actual flags, host, toolchain, binary hashes and separately supplied build revisions. Every command must succeed; an absent summary fails.

An optional second binary is the incumbent. Both run in the same invocation against the same held sockets, with order alternating between iterations. Timings remain observations rather than automatic win/loss qualification. Build revisions must come from each binary's build receipt, not inferred workspace HEAD. A smoke run with the same exact `1cbd545` binary in both arms exercises this pairing mechanism but proves no optimization.

## Durable SQLite throughput

Connection-churn generator driving events through the batched writer at `--interval-ms 20`, counting rows that actually landed in SQLite over the run window:

| `--db-batch-size` | Rows durably written | Observed durable rate | Drops |
|------------------:|---------------------:|----------------------:|------:|
| 200               | 2400                 | ~217 events/s         | 0     |
| 1000              | 2400                 | ~217 events/s         | 0     |

The historical rate is workload-specific and does not establish a throughput ceiling. `--db-queue-max` defaults to 10,000; `sqlite_dropped` reconciles queue and write losses. Current summaries also report observed/persisted counts and sink failure. A successful durable measurement requires all those counters to reconcile with actual SQLite rows.

The revised benchmark's two batch arms use a counted, accepted workload paced by durable readiness: each pair remains held until its two opens persist, then must produce two persisted closes before the next pair. Generation therefore keeps progressing, and final opens/closes, observed/persisted rows, actual SQLite rows and all loss counters must agree. Retained samples include each open/close operation's completion time. This measures a paced end-to-end workload, not maximum writer capacity or queue-saturation behavior.

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

That producer never accepted its listener's backlog and stopped progressing. The RSS result applies to a finite stalled workload, not sustained churn. A repaired exact-`bc72781241cef39bcc4a2472ed93550b1ce0540a` default/no-DNS run requested 600 seconds and completed 626 seconds including startup/finalization: 46,290 exact durable rows, generation=acceptance progressing every 5 seconds, zero event loss, RSS 20,888 KB reference to 21,072 KB final/peak. That is scoped author evidence for that revision and workload; later revisions and broader endpoint/PID, PTR, ancestry and pcap/cache axes remain unqualified. Runs shorter than 600 seconds are smoke tests. `SOAK_SOURCE_REVISION` must identify the binary's exact build receipt for a long run; workspace HEAD and the binary hash are recorded separately and are not substitutes for that binding.

The stats-view regression now waits for all four requested views against held real sockets, then checks durable observations and a healthy graceful summary. Its 20 s watchdog bounds failure; it makes no 1 s rendering or poll-latency claim. Missing-view, missing-summary and nonzero-exit controls must fail.

PTR now uses two background workers, a 64-request queue, at most 66 pending IPs,
and a 1,024-result positive/negative cache with a 600-second TTL. Expired results
are pruned per poll; full caches evict their oldest result. A stalled resolver
can consume worker capacity and leave hostnames unknown, but cannot block the
poll or grow its scratch queue/cache indefinitely. Summary `ptr` counters expose
pending age, completions, unresolved/deferred work and cache occupancy. Held
unknown endpoints receive later corrections using their existing observation
IDs; `--once` can finish with unresolved/pending PTR work. Accurate lifetime
IP/PID/domain statistics remain proportional to distinct observed values.
Eviction or expiry of resolver scratch state does not erase a PTR hostname
already observed on the same held socket while a refresh remains unresolved.

Live capture explicitly requests a 65,597-byte snapshot (the supported maximum
IPv6 payload plus IPv6, Ethernet and two VLAN headers) and an 8 MiB capture
buffer. This adds bounded capture storage; it does not impose a universal RSS
cap or guarantee lossless capture at arbitrary packet rates. Kernel/channel
loss still degrades capture health and makes qualification fail. The PCAP soak
runs in a private network namespace, sends and receives 60 real DNS responses
per progress interval across 300 hostname/IP candidates, limits the domain
cache to 100 entries, and requires every mapping to be delivered and drained.
Its packet counts and zero-loss check supplement the unchanged TCP and durable
row conservation requirements.

The real delayed-resolver probe mounts a private resolver file inside a private
Linux mount/network namespace and holds back an actual DNS reply. The current
author-tested candidate publishes advancing fresh polls while the exact
`3406ad2` incumbent blocks its first poll, then corrects live/file/SQLite/export/
report/statistics after the reply. A real NXDOMAIN case retains unknown
hostname evidence and completes without inventing attribution. Injected inline
worker stalls separately test queue bounds, deduplication and cache expiry;
they are unit tests, not live-service proof. Current whole-session resource
qualification and independent verification remain open.

## Reproducing

```bash
cargo build --release
scripts/bench.sh target/release/rano
# Replace these quoted SHA placeholders with values from the build receipts.
# Optional same-invocation incumbent:
BENCH_SOURCE_REVISION="candidate-build-sha" BENCH_INCUMBENT_REVISION="incumbent-build-sha" \
  scripts/bench.sh target/release/rano /path/to/incumbent/rano
# Fast harness smoke (no scaling or capacity qualification):
BENCH_PASSES=2 BENCH_CONNECTIONS=5,15 BENCH_CHURN_SECS=1 \
  scripts/bench.sh target/release/rano
BENCH_PASSES=2 BENCH_CONNECTIONS=5,15 BENCH_CHURN_SECS=1 \
  BENCH_IP_COUNTS=8,128,1025 BENCH_PID_COUNTS=2,16 \
  scripts/bench.sh target/release/rano /path/to/incumbent/rano
SOAK_PTR_PROBE=1 RANO_PTR_BASELINE=/path/to/incumbent/rano \
  scripts/e2e/run.sh ptr-system scripts/e2e/soak-memory.sh
SOAK_PTR_PROBE=1 SOAK_PTR_REPLY=failure \
  scripts/e2e/run.sh ptr-nxdomain scripts/e2e/soak-memory.sh
SOAK_SECS=600 SOAK_SOURCE_REVISION="built-source-sha" \
  scripts/e2e/run.sh soak-memory scripts/e2e/soak-memory.sh
# SOAK_DOMAIN_MODE=ptr exercises actual PTR. The pcap arm requires a
# pcap-enabled binary, noninteractive sudo, unshare and ip for its private
# network namespace. Both require exact row/loss accounting; the pcap arm
# also reconciles generated/received DNS responses with captured mappings.
```

The CI source now makes default tests, strict checks, installer/real-PTR suites,
progressing 600-second PTR and pcap/no-DNS workloads, and stalled/missing-summary
controls blocking. It pins the same nightly date as `rust-toolchain.toml`.
The manually disabled workflow state remains unchanged; source wiring is not
an executed GitHub qualification.
