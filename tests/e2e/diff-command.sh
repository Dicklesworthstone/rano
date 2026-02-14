#!/usr/bin/env bash
set -euo pipefail

# This test verifies that `rano diff` compares two sessions correctly.
# It seeds a temporary SQLite database with deterministic old/new run_ids and validates:
# 1. Pretty output sections for provider/domain/process changes
# 2. JSON output fields and changed entities
# 3. Threshold filtering behavior
# 4. Error handling for unknown session ids

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

SQLITE_PATH="${TMP_DIR}/test-diff.sqlite"

export E2E_FIXTURES="Seeded SQLite at ${SQLITE_PATH}"

e2e_section "Seed fixture database"
e2e_info "path=${SQLITE_PATH}"

sqlite3 "${SQLITE_PATH}" <<'SQL'
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;

CREATE TABLE IF NOT EXISTS events (
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

CREATE TABLE IF NOT EXISTS sessions (
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

INSERT INTO sessions (run_id, start_ts, end_ts, host, user, patterns, domain_mode, interval_ms, stats_interval_ms, connects, closes)
VALUES
  ('diff-old-001', '2026-01-20T10:00:00Z', '2026-01-20T10:10:00Z', 'testhost', 'testuser', 'claude,codex', 'ptr', 1000, 2000, 5, 0),
  ('diff-new-001', '2026-01-20T11:00:00Z', '2026-01-20T11:10:00Z', 'testhost', 'testuser', 'claude,gemini', 'ptr', 1000, 2000, 6, 0);

-- old session: 2x shared, 1x old-only, providers anthropic/openai, process claude
INSERT INTO events (ts, run_id, event, provider, pid, comm, cmdline, proto, local_ip, local_port, remote_ip, remote_port, domain, remote_is_private, ip_version)
VALUES
  ('2026-01-20T10:01:00Z', 'diff-old-001', 'connect', 'anthropic', 1111, 'claude', '/usr/bin/claude', 'tcp', '127.0.0.1', 54001, '104.18.12.34', 443, 'shared.example.com', 0, 4),
  ('2026-01-20T10:02:00Z', 'diff-old-001', 'connect', 'anthropic', 1111, 'claude', '/usr/bin/claude', 'tcp', '127.0.0.1', 54002, '104.18.12.35', 443, 'shared.example.com', 0, 4),
  ('2026-01-20T10:03:00Z', 'diff-old-001', 'connect', 'openai', 1111, 'claude', '/usr/bin/claude', 'tcp', '127.0.0.1', 54003, '13.107.42.14', 443, 'legacy.example.com', 0, 4);

-- new session: 3x shared, 2x new-only, providers anthropic/google, process gemini
INSERT INTO events (ts, run_id, event, provider, pid, comm, cmdline, proto, local_ip, local_port, remote_ip, remote_port, domain, remote_is_private, ip_version)
VALUES
  ('2026-01-20T11:01:00Z', 'diff-new-001', 'connect', 'anthropic', 2222, 'gemini', '/usr/bin/gemini', 'tcp', '127.0.0.1', 55001, '104.18.12.34', 443, 'shared.example.com', 0, 4),
  ('2026-01-20T11:02:00Z', 'diff-new-001', 'connect', 'google', 2222, 'gemini', '/usr/bin/gemini', 'tcp', '127.0.0.1', 55002, '142.250.80.46', 443, 'shared.example.com', 0, 4),
  ('2026-01-20T11:03:00Z', 'diff-new-001', 'connect', 'google', 2222, 'gemini', '/usr/bin/gemini', 'tcp', '127.0.0.1', 55003, '142.250.80.47', 443, 'shared.example.com', 0, 4),
  ('2026-01-20T11:04:00Z', 'diff-new-001', 'connect', 'google', 2222, 'gemini', '/usr/bin/gemini', 'tcp', '127.0.0.1', 55004, '142.250.80.48', 443, 'new.example.com', 0, 4),
  ('2026-01-20T11:05:00Z', 'diff-new-001', 'connect', 'google', 2222, 'gemini', '/usr/bin/gemini', 'tcp', '127.0.0.1', 55005, '142.250.80.49', 443, 'new.example.com', 0, 4);
SQL

event_count=$(sqlite3 "${SQLITE_PATH}" "SELECT COUNT(*) FROM events")
session_count=$(sqlite3 "${SQLITE_PATH}" "SELECT COUNT(*) FROM sessions")
e2e_info "Verified: ${event_count} events, ${session_count} sessions"

e2e_section "Test 1: Pretty output"
e2e_run "rano diff pretty" \
  "${RANO_BIN}" diff --sqlite "${SQLITE_PATH}" --old diff-old-001 --new diff-new-001 --threshold 20 --color never

e2e_assert_last_status 0
e2e_assert_last_contains "Session Diff"
e2e_assert_last_contains "old: diff-old-001"
e2e_assert_last_contains "new: diff-new-001"
e2e_assert_last_contains "Provider Changes:"
e2e_assert_last_contains "New Domains:"
e2e_assert_last_contains "new.example.com"
e2e_assert_last_contains "Removed Domains:"
e2e_assert_last_contains "legacy.example.com"
e2e_assert_last_contains "Changed Domains:"
e2e_assert_last_contains "shared.example.com"
e2e_assert_last_contains "New Processes:"
e2e_assert_last_contains "gemini"
e2e_assert_last_contains "Removed Processes:"
e2e_assert_last_contains "claude"

e2e_section "Test 2: JSON output"
e2e_run "rano diff json" \
  "${RANO_BIN}" diff --sqlite "${SQLITE_PATH}" --old diff-old-001 --new diff-new-001 --threshold 20 --json

e2e_assert_last_status 0
e2e_assert_last_contains '"old_run_id": "diff-old-001"'
e2e_assert_last_contains '"new_run_id": "diff-new-001"'
e2e_assert_last_contains '"new_domains"'
e2e_assert_last_contains '"new.example.com"'
e2e_assert_last_contains '"removed_domains"'
e2e_assert_last_contains '"legacy.example.com"'
e2e_assert_last_contains '"changed_domains"'
e2e_assert_last_contains '"domain": "shared.example.com"'
e2e_assert_last_contains '"provider_changes"'
e2e_assert_last_contains '"openai": {"old_count": 1, "new_count": 0}'
e2e_assert_last_contains '"google": {"old_count": 0, "new_count": 4}'

e2e_section "Test 3: Threshold filtering"
e2e_run "rano diff json (high threshold)" \
  "${RANO_BIN}" diff --sqlite "${SQLITE_PATH}" --old diff-old-001 --new diff-new-001 --threshold 80 --json

e2e_assert_last_status 0
if grep -Fq '"domain": "shared.example.com"' "${E2E_LAST_OUTPUT_FILE}"; then
  e2e_fail "shared.example.com should not appear in changed_domains at threshold=80"
fi
e2e_info "Confirmed: changed_domains filtered by threshold"

e2e_section "Test 4: Unknown session error"
set +e
e2e_run "rano diff missing session" \
  "${RANO_BIN}" diff --sqlite "${SQLITE_PATH}" --old missing-session --new diff-new-001 --json
set -e

e2e_assert_last_status 1
e2e_assert_last_contains "No events found for session 'missing-session'"
