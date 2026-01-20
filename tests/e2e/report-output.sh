#!/usr/bin/env bash
set -euo pipefail

TMP_DIR=$(mktemp -d)
cleanup() {
  rm -rf "${TMP_DIR}"
}
trap cleanup EXIT

RANO_BIN="${RANO_BIN:-./target/release/rano}"
if [ ! -x "${RANO_BIN}" ]; then
  e2e_section "Building rano"
  cargo build --release --quiet
fi

DB_PATH="${TMP_DIR}/report.sqlite"

sqlite3 "${DB_PATH}" <<'SQL'
CREATE TABLE events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    run_id TEXT,
    event TEXT NOT NULL,
    provider TEXT NOT NULL,
    pid INTEGER,
    comm TEXT,
    cmdline TEXT,
    proto TEXT,
    local_ip TEXT,
    local_port INTEGER,
    remote_ip TEXT,
    remote_port INTEGER,
    domain TEXT,
    remote_is_private INTEGER,
    ip_version INTEGER,
    duration_ms INTEGER
);
CREATE TABLE sessions (
    run_id TEXT PRIMARY KEY,
    start_ts TEXT NOT NULL,
    end_ts TEXT,
    host TEXT,
    user TEXT,
    patterns TEXT,
    domain_mode TEXT,
    args TEXT,
    interval_ms INTEGER,
    stats_interval_ms INTEGER,
    connects INTEGER,
    closes INTEGER
);
SQL

sqlite3 "${DB_PATH}" <<'SQL'
INSERT INTO sessions (run_id, start_ts, end_ts, host, user, patterns, domain_mode, args, interval_ms, stats_interval_ms, connects, closes)
VALUES
  ('run-1', '2026-01-17T10:00:00Z', '2026-01-17T10:10:00Z', 'test-host', 'tester', 'codex', 'ptr', 'rano --pattern codex', 1000, 5000, 2, 1),
  ('run-2', '2026-01-18T11:00:00Z', '2026-01-18T11:10:00Z', 'test-host', 'tester', 'codex, claude', 'ptr', 'rano --pattern codex --pattern claude', 1000, 5000, 3, 2);

INSERT INTO events (ts, run_id, event, provider, pid, comm, cmdline, proto, local_ip, local_port, remote_ip, remote_port, domain, remote_is_private, ip_version, duration_ms)
VALUES
  ('2026-01-17T10:05:00Z', 'run-1', 'connect', 'openai', 111, 'codex', 'codex', 'tcp', '127.0.0.1', 50001, '1.1.1.1', 443, 'api.openai.com', 0, 4, 1200),
  ('2026-01-17T10:06:00Z', 'run-1', 'close',   'openai', 111, 'codex', 'codex', 'tcp', '127.0.0.1', 50001, '1.1.1.1', 443, 'api.openai.com', 0, 4, 1200),
  ('2026-01-17T10:07:00Z', 'run-1', 'connect', 'google', 112, 'gemini', 'gemini', 'tcp', '127.0.0.1', 50002, '8.8.8.8', 443, 'api.google.com', 0, 4, 900),
  ('2026-01-18T11:05:00Z', 'run-2', 'connect', 'openai', 211, 'codex', 'codex', 'tcp', '127.0.0.1', 50003, '1.1.1.1', 443, 'api.openai.com', 0, 4, 800),
  ('2026-01-18T11:06:00Z', 'run-2', 'connect', 'openai', 211, 'codex', 'codex', 'tcp', '127.0.0.1', 50003, '1.1.1.1', 443, 'api.openai.com', 0, 4, 700),
  ('2026-01-18T11:07:00Z', 'run-2', 'close',   'openai', 211, 'codex', 'codex', 'tcp', '127.0.0.1', 50003, '1.1.1.1', 443, 'api.openai.com', 0, 4, 600),
  ('2026-01-18T11:08:00Z', 'run-2', 'connect', 'anthropic', 212, 'claude', 'claude', 'tcp', '127.0.0.1', 50004, '2.2.2.2', 443, 'api.anthropic.com', 0, 4, 1100),
  ('2026-01-18T11:09:00Z', 'run-2', 'close',   'anthropic', 212, 'claude', 'claude', 'tcp', '127.0.0.1', 50004, '2.2.2.2', 443, 'api.anthropic.com', 0, 4, 1100);
SQL

E2E_FIXTURES="fixture sqlite at ${DB_PATH}"
export E2E_FIXTURES

e2e_section "Fixture summary"
e2e_info "db_path=${DB_PATH}"
e2e_info "run_latest=run-2"
e2e_info "range_since=2026-01-18"
e2e_info "range_until=2026-01-19"

events_run2=$(sqlite3 "${DB_PATH}" "SELECT COUNT(*) FROM events WHERE run_id='run-2';")
connects_run2=$(sqlite3 "${DB_PATH}" "SELECT COUNT(*) FROM events WHERE run_id='run-2' AND event='connect';")
closes_run2=$(sqlite3 "${DB_PATH}" "SELECT COUNT(*) FROM events WHERE run_id='run-2' AND event='close';")

e2e_info "events_run2=${events_run2}"
e2e_info "connects_run2=${connects_run2}"
e2e_info "closes_run2=${closes_run2}"

# Pretty output (golden)
e2e_run "report latest pretty" "${RANO_BIN}" report --sqlite "${DB_PATH}" --latest --no-color
e2e_assert_last_status 0

e2e_section "Output snippet (pretty)"
head -n 12 "${E2E_LAST_OUTPUT_FILE}" | while IFS= read -r line; do
  e2e_info "${line}"
done

expected_pretty="$(cat tests/fixtures/report_latest.txt)"
e2e_assert_last_eq "${expected_pretty}"$'\n\n'

# JSON output + schema validation + golden

e2e_run "report latest json" "${RANO_BIN}" report --sqlite "${DB_PATH}" --latest --json
e2e_assert_last_status 0

e2e_section "Output snippet (json)"
head -n 6 "${E2E_LAST_OUTPUT_FILE}" | while IFS= read -r line; do
  e2e_info "${line}"
done

python3 - "${E2E_LAST_OUTPUT_FILE}" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
data = json.loads(path.read_text())

for key in ["meta", "summary", "providers", "top_domains", "top_ips"]:
    if key not in data:
        raise SystemExit(f"missing key: {key}")

summary = data["summary"]
if summary.get("total_events") != 5:
    raise SystemExit(f"unexpected total_events: {summary.get('total_events')}")
if summary.get("connects") != 3:
    raise SystemExit(f"unexpected connects: {summary.get('connects')}")
if summary.get("closes") != 2:
    raise SystemExit(f"unexpected closes: {summary.get('closes')}")

providers = {p["provider"]: p for p in data["providers"]}
if providers.get("openai", {}).get("events") != 3:
    raise SystemExit("openai event count mismatch")
if providers.get("anthropic", {}).get("events") != 2:
    raise SystemExit("anthropic event count mismatch")
PY

NORMALIZED_JSON="${TMP_DIR}/report_latest.normalized.json"
python3 - "${E2E_LAST_OUTPUT_FILE}" "${NORMALIZED_JSON}" <<'PY'
import json
import sys
from pathlib import Path

src = Path(sys.argv[1])
dst = Path(sys.argv[2])

data = json.loads(src.read_text())
meta = data.get("meta", {})
meta["generated_at"] = "PLACEHOLDER"
data["meta"] = meta

dst.write_text(json.dumps(data, sort_keys=True, indent=2) + "\n")
PY

E2E_LAST_OUTPUT_FILE="${NORMALIZED_JSON}"
expected_json="$(cat tests/fixtures/report_latest.json)"
e2e_assert_last_eq "${expected_json}"$'\n'

# Time range filter sanity check

e2e_run "report range json" "${RANO_BIN}" report --sqlite "${DB_PATH}" --since 2026-01-18 --until 2026-01-19 --json
e2e_assert_last_status 0

python3 - "${E2E_LAST_OUTPUT_FILE}" <<'PY'
import json
import sys
from pathlib import Path

data = json.loads(Path(sys.argv[1]).read_text())
summary = data.get("summary", {})
if summary.get("total_events") != 5:
    raise SystemExit(f"range total_events mismatch: {summary.get('total_events')}")
PY
