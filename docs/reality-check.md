# rano reality check — 2026-10-13

rano delivers a useful Linux socket-observation workflow. Its advertised commands are real implementations, and ordinary monitoring, SQLite history, reports, exports, comparisons, configuration loading and status output have substantial working code. Several trust and reliability promises fail real inputs, however. The project is not qualified as a complete, reliable security-audit tool merely because its original 104 beads are closed or its unit tests pass.

This assessment used `reality-check-for-project` through documentation review, code investigation, compiled/runtime verification, gap analysis, a bridge plan, ambition/refinement passes, granular implementation and companion verification beads, and graph validation. It creates a reviewable plan; it does not claim that the identified repairs have been implemented.

## Scope and evidence boundary

The audited source is `main` at `7f342a3d195dea97f083602274fd2758ff46c88e` (tree `9099002663ca3120b56676fae7fb6e45ca4bf70d`). Both `/data/projects/AGENTS.md` and the complete local `AGENTS.md` were read, followed by all 1,315 lines of README, all seven `docs/*.md` design/performance documents, CHANGELOG, UPGRADE_LOG, the E2E harness documentation, relevant source/tests and workflow files. Historical/deferred design branches were distinguished from active promises.

At the start, Beads and bv independently showed **104 closed, zero open, zero in progress**. The current br automatically rebuilt its schema-0 cache from authoritative JSONL, retaining recovery copies. The original closed issue records and criteria were preserved.

GitHub's latest published release is **v0.2.0**, dated 2026-08-25; Cargo/main says **0.2.1**, and CHANGELOG correctly marks it prepared/unreleased. `git diff v0.2.0..7f342a3 -- src/` is empty: program source is identical, while dependencies, package metadata, installer and other files differ. This was checked against live GitHub release/compare data, not inferred from a changelog alone. [Published release](https://github.com/Dicklesworthstone/rano/releases/tag/v0.2.0).

The released x86_64 Linux archive was downloaded and checksum-verified (`2157680d7c2810d5d01398295299b33dcd8b00d173828764ab5d27c8d5ca998f`). A fresh pcap-enabled release binary was built through exact-SHA RCH clean-baseline/no-overlay execution, checksum `0c717264707546c5e5170c92d266b74e477cb6b17f8341315666c5ae53c3433f`. Runtime counterexamples were checked against both binaries where applicable. The fresh binary's normal TCP, report/export and DNS-fixture positive probes passed.

Raw commands, stdout/stderr, fixture helpers, SQLite files, hashes and build logs are retained under `/tmp/rano-reality-20261013.ScUpVf/`; the fresh binary is `/tmp/rano-reality-20261013-target/release/rano`. These local paths are evidence artifacts, not published release assets. Only fake credentials and controlled local socket traffic were used. E2E scripts were unchanged; their temporary cleanup operations were redirected to moves into retained evidence directories so fixtures were preserved. An initial retention-wrapper path error was corrected before the reported reruns; its failures are not counted as product failures.

## What is working

The dispatch handlers for monitor, report, export, diff, status, config and update all do real work. No `todo!()`/`unimplemented!()` command stubs were found. This is an implemented project with correctness, contract and qualification gaps.

Verified positives include:

- A controlled Linux TCP process produced actual PID-attributed events, an anthropic tag from original argv, and ancestry when requested.
- Normal event batches reached SQLite; the batching E2E observed 50 connects/50 closes and matched 100 durable rows with zero queue drops.
- Normal JSON/pretty reports and CSV/JSONL exports work. Seeded report, export, diff and status regression suites passed; legacy-schema migrations and read/write contention have real implementation and test coverage.
- Config loading, validation of many common errors, TOML provider overrides, preset loading and CLI-over-preset scalar precedence work in ordinary cases.
- Retry detection, domain/provenance extraction, alert/cooldown machinery and stats rendering exist. The optional pcap build attributed a held local socket to `fixture.test` with source `dns` from the real offline fixture.
- Compiler checks, configured strict Clippy and formatting passed at the audited source revision. The originally reported unit-suite passes were incomplete; see the correction below.

These positives establish scoped behavior. They do not erase the counterexamples below.

## Vision checklist and coverage

`WORKING` below refers to the demonstrated ordinary path. `PARTIAL` means a retained promise has a concrete gap; `UNPROVEN` means the available evidence cannot qualify the full claim. The numbered tasks are children of `rust_agent_network_observer-reality-check-20261013-p6t`.

| Goal and measuring stick | Reality | Bridge tasks |
|---|---|---|
| Linux PID/socket mapping and automatic descendants — README introduction/design philosophy | PARTIAL: ordinary TCP works; valid spaced comm names break topology, exclusions do not apply throughout the tree, and shared inode ownership is arbitrary | .1, .2; proofs .18, .19 |
| Provider tags for AI roots and their network-making children — README provider/descendant promises | PARTIAL: directly marked leaves work; an unmarked child of a Claude root is `unknown` | .2; proof .19 |
| Requested TCP listeners and UDP coverage — README monitor flags/verbose preset | PARTIAL: listeners and sendto UDP sockets are skipped before the flag can help; unconnected UDP has no destination in `/proc` | .3; proof .20 |
| Live events, stats, themes and configurable view rotation — README output/live-stats sections | PARTIAL: rendering exists; the required one-second rotation E2E fails on this host | .17; proof .34 |
| Durable history, batching, bounded queue and visible drops — README SQLite philosophy/performance | PARTIAL: normal batches work; failed transactions lose rows without corresponding loss counters, and requested file sinks can disappear silently | .5; proof .22 |
| PTR and optional DNS/SNI provenance — README domain modes, pcap design | PARTIAL: fixture extraction works; SNI is keyed by remote IP/port rather than individual flow, capture loss/health are silent | .9, .10; proofs .26, .27 |
| Reliable independent stdout/file JSON or pretty formats — README output/logging/export promises | PARTIAL: hostile report strings and retry log lines break JSON; file format selection is inconsistent | .6; proof .23 |
| Session/time-filtered reports with designed insights — README report, report-design | PARTIAL: ordinary smaller reports work; time/session errors and designed hourly/duration/peak/distinct insights remain incomplete | .7, .8; proofs .24, .25 |
| Streaming CSV/JSONL exports with fields/provider/domain filters — README export, export-design | WORKING for demonstrated ordinary seeded data; filter correctness still depends on time parsing, and stored redaction may already be incomplete | .4, .7; proofs .21, .24 |
| Session diff by IDs/names and meaningful errors — README diff/design error contracts | PARTIAL: ID-based seeded comparison works; valid empty sessions and named/ambiguous session resolution need repair | .7; proof .24 |
| Current prompt status with session name and low latency — README status | PARTIAL: seeded status works; a newer empty session is ignored and historic open-at-exit sockets can be presented as active | .7, .13; proofs .24, .30 |
| Actual alert emission, concurrent thresholds, cooldown-aware durable flags — README alerts, alert-design | PARTIAL: machinery is real; per-provider threshold uses lifetime connects and the E2E does not drive real breaches | .11; proof .28 |
| Retry storms, cooldowns and durable retry_count — README retry detection | WORKING for observed close/reconnect sequences; JSON file records are broken | .6; proof .23 |
| Secrets/all redaction in SQLite, logs and exports with original attribution — README privacy | PARTIAL: ordinary one-token masking works; a multiword argv value leaks its tail, and existing E2E can pass with zero events | .4; proof .21 |
| Config check/show/path discovery and exact runtime agreement — README config/provider sections | PARTIAL: show dumps source files rather than effective config, zero flush validation disagrees with runtime, advertised overrides are inconsistent | .12; proof .29 |
| Builtin/custom presets and documented precedence — README presets, preset-design | PARTIAL: basic loading works; builtins beat same-name user files and public preset defaults disagree | .12; proof .29 |
| Low overhead and sustained bounded-RSS/zero-loss operation — README performance, perf doc | UNPROVEN beyond measured limited workloads: benchmark checks are weak and the soak stalls after its backlog fills | .13; proof .30 |
| Installation/update, supported platforms and shipped qualification — README install, CHANGELOG/release workflow | PARTIAL: Linux release exists; prepared fallback/ref/toolchain problems and unsupported native Darwin monitoring remain | .14–.17; proofs .31–.34 |

Before this assessment, **every newly identified gap lacked an active bead**, since no open/in-progress issues existed. Some fall within historically closed feature areas, but those historical beads did not carry these counterexamples. Completing the original open backlog would therefore close none of them. The new graph covers the identified retained promises; it does not claim future unknown bugs are impossible.

## Confirmed counterexamples and their implications

**Topology and attribution.** `read_ppid` (`src/main.rs:5871`) splits the entire stat record on whitespace. A real child named `odd name)` owned two TCP sockets. Monitoring its parent found zero child events; targeting the child directly found two, but ancestry contained only the leaf. `collect_descendants` also reintroduces excluded processes, and `map_inodes` lets HashSet iteration decide who owns a shared socket. Separately, `build_pid_meta_map` classifies only the leaf's own text. A Claude-marked parent with an unmarked TCP child yielded two child events tagged `unknown`. The central descendant-aware attribution promise is therefore incomplete.

**Socket inclusion.** The monitor skips every row with `remote_port == 0` before its listening-state check (`src/main.rs:1733`). A real listener with a verified socket fd produced zero events under `--include-listening`; sendto UDP also produced zero. The source observes connected socket endpoints without establishing connect-vs-accept direction. `/proc` polling cannot observe sockets that open/close entirely between polls or infer a sendto destination absent from the table. These limits must be explicit; “complete outbound history” overstates the current evidence.

**Privacy.** `read_cmdline` joins NUL-separated argv, and `redact_cmdline_str` later splits whitespace. For a real `--password` whose single argument was `FAKE WORDS CREDENTIAL`, SQLite persisted `<redacted> WORDS CREDENTIAL` in two rows. The same boundary loss affects durable file masking. The existing redaction E2E creates a sleeper, embeds a literal shell placeholder in Python source, opens no socket, and skips database assertions when no events exist. Its pass does not prove secret protection or attribution. It is also absent from CI.

**Durability.** An independent SQLite trigger forced `INSERT` to fail. The monitor observed two connects, stored zero event rows, emitted a batch-write warning, exited 0, and reported `sqlite_dropped:0`. `sqlite_writer_loop` clears failed batches while only queue failures reach that counter. A requested file under an unavailable parent directory likewise returned success with no log warning because `open_log_writer` silently returns `None`. Error accounting must distinguish observed traffic from durable rows and expose failed sinks.

**Machine output.** A normal run with a quote/backslash in `--pattern` stored that pattern in session metadata; `report --latest --json` then exited 0 but emitted invalid JSON. Many strings in `output_report_json` are interpolated without escaping. Real reconnects produced eight plain-text retry lines in the fresh binary's requested JSONL file. Alerts are printed without file-log routing, and summary/event format paths do not consistently honor an independent `--log-format`. These defects break normal machine consumers even though ordinary golden reports pass.

**Alerts.** A real sequential reconnect workload held at most two simultaneous tracked sockets, yet `--alert-max-per-provider 3` fired and advertised lifetime actual counts 3 through 10 in the fresh run. Global thresholds use active connections, whereas provider thresholds use cumulative `stats.per_provider`. The current alert E2E exercises flags/schema with nonexistent target processes, not the promised breach/cooldown behavior. Cooldown-aware `events.alert=1` and synthesized threshold rows are valuable existing work and should be preserved.

**Per-flow hostname attribution.** The fresh binary was copied to a Linux worker and its checksum rechecked before a controlled port-443 probe. Two real sockets used local ports 57000/57014; standard-library TLS ClientHello bytes carried `a.audit.test` and `b.audit.test` respectively. Both outbound records were labeled `b.audit.test`, source `sni`. `PcapMsg` discards the local endpoint and `DomainCache` keys only the remote endpoint, so the later observation overwrites the earlier flow's identity. This is a reproduced incorrect high-confidence association, not merely an unresolved hostname. The worker probe and fixture are retained in `remote-pcap-collision/` under the evidence directory.

**Session/time semantics.** A deliberately newer empty session was added to a real history database. `status` still returned the previous session name with `2|2`; it chooses the latest event rather than the latest session. A missing requested report session returns an empty success. `2026-99-99` is accepted, and very large relative durations use unchecked multiplication (release wrapping was observed; a debug panic is a source-derived risk). The designed report also lacks hourly activity, summary duration/peak metrics and per-provider distinct domain/IP counts. These are tracked separately from the already useful ordinary report.

**Configuration/presets.** Using the same explicit file, `config check` accepted `db_flush_ms=0` and monitor startup rejected it. `config show --json` returns `sources`, not resolved defaults/merged settings. `RANO_CONFIG` is advertised by `config paths` but is not read, and config/preset path resolution differs from provider TOML XDG handling. The builtin-first loader contradicts user-overrides-builtin design. README audit/live preset tables also disagree with code: audit disables UDP; live uses 2000ms with cycling rather than 500ms/top 10.

**Performance proof.** The unchanged 90-second soak reported a pass, final RSS 9,808KB versus baseline 9,804KB and zero queue drops, with 1,989 durable events. Its first event was 11:08:37Z and last event 11:09:00Z. The workload stopped producing observed events after roughly 23 seconds because its listener never accepts and the backlog fills. These are real limited-workload measurements; they do not establish sustained churn. The harness also substitutes zero when the final drop summary is absent. Default PTR calls block the polling thread, and several lifetime caches/maps lack a full-session resource-bound contract.

Current exact-head nightly CI measured 38.100ms versus 103.266ms for 500/2000 sockets and roughly 1,781/1,800 durable events/s for batches 200/1000. This differs from the older perf-doc hardware/flags/numbers. It is fresh observational data, not a head-to-head performance win. The benchmark suppresses failed monitor exits and does not assert expected captured socket counts. [2026-10-08 performance run](https://github.com/Dicklesworthstone/rano/actions/runs/37765403655).

**Distribution/platform contract.** The checksum-verified v0.2.0 Linux binary lacks pcap support, so the README offline replay requires a separately enabled build. Native Darwin monitoring has no implementation: all process/socket readers use Linux `/proc`; BSD socket structs only help compilation. Darwin runtime was not exercised here, so the platform finding is source-derived. Installer fallback selects unpublished v0.2.1; versioned source fallback ignores the requested ref; Cargo output overrides are not honored; Darwin checksum tooling and custom updater pipeline environment propagation need repair. No installed operator binary was updated during this assessment.

**Verification infrastructure.** Live GitHub state shows `ci`, `dist`, `release-automation` and installer notification workflows **disabled manually**; only perf and Dependabot are active. A successful nonblocking nightly soak cannot substitute for a current blocking product gate. The latest general CI run is an older failing aggregate with successful check/check-pcap jobs and a setup failure in workflow-lint; that is historical evidence, not a current runtime failure. Restoring a deliberate qualification path needs to respect the owner's workflow choices.

## Verification ledger

| Check at the audited revision | Outcome and precise scope |
|---|---|
| `cargo fmt --check` | PASS locally; source was unchanged |
| Exact-SHA RCH `cargo check --all-targets --all-features --locked` | PASS, vmi1149989 |
| Exact-SHA RCH `cargo clippy --all-targets --all-features --locked -j1 -- -D warnings` | PASS under the repository's configured lint allowances |
| Exact-SHA RCH default `cargo test --locked -j1` | INCOMPLETE: 197 tests announced, process exited before completion; initial PASS claim withdrawn |
| Exact-SHA RCH `cargo test --all-features --locked -j1` | INCOMPLETE: 223 tests announced, process exited before completion; initial PASS claim withdrawn |
| Exact-SHA RCH release pcap build | PASS; fresh retrieved binary and source receipt recorded |
| 15 ordinary/privacy E2E suites on shipped v0.2.0 | 14 PASS, stats-views FAIL |
| Same 15 E2E suites on fresh pcap-enabled main binary | 14 PASS, stats-views FAIL |
| Existing pcap-attribution E2E on fresh binary | FAIL with zero captured events; diagnostic rerun also failed with client `ConnectionRefusedError`. The fixture uses fixed sleeps/port and a three-second lifetime; separate held-target DNS proof passes, so this does not establish an engine-wide attribution failure |
| Controlled TCP and ordinary report/export on both binaries | PASS |
| Controlled fresh held-socket offline DNS attribution | PASS: `fixture.test`, source `dns` |
| Controlled fresh two-flow TLS SNI attribution | FAIL: both sockets attributed to the second flow's hostname with source `sni` |
| Controlled negative probes | Reproduced defects above; these are observed failures, not passing product qualification |
| Existing 90-second soak on shipped binary | Script PASS, but workload progress stopped after ~23s; sustained qualification remains UNPROVEN |
| Native Darwin/ARM runtime, long diversity/slow-PTR soak, real external AI sessions | UNPROVEN in this run |
| UBS on the two staged assessment files | NOT EVALUATED: exit 3, `no-supported-languages`; Markdown/JSONL contain no eligible code. JSONL parsing, exact historical-record preservation, dependency pairing and diff whitespace checks passed separately |

Initial RCH attempts encountered admission/queue/pressure problems and missing `-lpcap` linkage. The worker already had the libpcap runtime but lacked the development linker name. A private directory symlink to the installed runtime and a forwarded `LIBRARY_PATH` supplied that name without system package changes; successful commands retained the exact source baseline. These environmental failures were not counted as unit-test failures. One ovh-a attempt failed before source-lock acquisition with a worker filesystem I/O error; `rch jobs recover rchw-e083ef57-f873-4014-b675-83bad95a60e9` also failed to persist cancellation. That ownership-recovery limitation remains recorded; no peer process/cache was cleared.

Implementation follow-up on 2026-10-13 found that `test_parse_update_args_flags` calls `parse_update_args` with `--version <tag>`, whose pre-parser prints the program version and calls `exit(0)` instead of selecting the requested installer release. This prematurely terminates the test process. A later run announced 234 tests but recorded only 178 successful completions and no terminal test summary. The same faulty parser exists at the audit baseline, so announced counts and Cargo's zero exit are insufficient evidence of full-suite completion. This correction preserves the original acceptance criteria and requires completed-test counts plus a terminal summary on the repaired revision.

The red E2E gates remain red even where a controlled focused probe passes. Stats rendering exists, and DNS fixture attribution works with a held target; this does not convert the required aggregate tests into a green qualification result.

## Bridge plan and completion boundary

The new epic is **`rust_agent_network_observer-reality-check-20261013-p6t`**. It contains 17 implementation tasks (.1–.17), 17 companion verification tasks (.18–.34), and final integration qualification (.35). Every implementation task contains its own context, counterexample, source surface, acceptance criteria and unit/E2E requirements. Every companion carries the full implementation contract plus exact-revision/baseline discrimination and negative-control requirements. All 36 new records remain open; no repair or qualification closure was manufactured.

| Order / operator value | Implementation tasks | Required proof |
|---|---|---|
| Trust the observed process/root and protect durable artifacts | .1 topology, .2 root provider, .4 argv privacy, .5 durability | .18, .19, .21, .22 |
| Make records consumable and supported socket modes honest | .3 sockets, .6 all-sink formatting | .20, .23 |
| Correct correlation, insights and control behavior | .7 time/session/status, .8 report insights, .9 per-flow SNI, .10 capture health, .11 active alerts, .12 config/presets | .24–.29 |
| Establish honest resource and shipped-support evidence | .13 progressing performance, .14 installer/update, .15 platform capabilities, .16 prepared release, .17 docs/CI | .30–.34 |
| Qualify the complete workflow at one final source revision | .35 depends on every companion verification | Full default/pcap gates, negative regressions, progressing >=600s soak and actual supported artifact/runtime matrix |

The graph has no dependency cycles. Most runtime tasks share `src/main.rs`, so exact file reservations remain essential even where graph dependencies permit simultaneous work. bv is a scheduling aid: its leading recommendations favor JSON, topology and session semantics, but root attribution, privacy and durability determine whether an operator can trust the records and should drive prioritization.

Three ambition passes expanded the plan from isolated fixes into process/flow identity, durable-sink/session contracts and operator-visible failure/proof quality. Five refinement passes checked vision coverage, bounded implementation scope, positive/negative test discrimination, graph/shared-file ordering and final platform/release evidence. Concrete refinements are recorded on .2/.4/.13/.16/.17 and the epic. The last pass found no additional retained vision goal without a task.

Completing this new graph with its actual acceptance evidence would close the identified gap. Completing tasks without discriminating proofs would not. Explicitly deferred alert regex/separate alert tables, unused pcap TTL/SNI-port flags, packet payload inspection, perfect ECH/encrypted-DNS attribution and a new native Darwin monitoring backend are not smuggled into the plan. Unsupported behavior must be stated accurately; an unresolved criterion stays open.

No production source, golden fixture, release tag or artifact publication was changed by the assessment. The only intended repository changes are this report and the new Beads graph. Four tracked history backups automatically rotated by br were restored byte-for-byte, and further history rotation was throttled for the remaining session. Recovery and newly generated local snapshots are preserved as local artifacts rather than added to the review surface.
