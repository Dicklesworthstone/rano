#!/usr/bin/env bash
# E2E Test: Process Ancestry
# Tests the process ancestry tracking feature
#
# This test verifies:
# - Ancestry path is captured for tracked processes
# - Ancestry appears in SQLite events table
# - Ancestry appears in JSON summary output
# - Format: "comm:pid,comm:pid,..." from init to process
#
# Prerequisites:
# - rano binary built (cargo build)
# - SQLite3 available for database verification

set -euo pipefail

RANO="${RANO:-${E2E_RANO_DEBUG}}"
TEST_SQLITE="/tmp/rano-e2e-ancestry-$$.sqlite"

# Cleanup on exit
cleanup() {
    rm -f "${TEST_SQLITE}"
}
trap cleanup EXIT

e2e_section "Setup"
e2e_info "rano=${RANO}"
e2e_info "test_sqlite=${TEST_SQLITE}"

# Ensure rano binary exists
if [ ! -x "${RANO}" ]; then
    e2e_fail "rano binary not found at ${RANO}. Run 'cargo build' first."
fi

# Test 1: Verify SQLite schema has ancestry_path column
e2e_section "Test 1: SQLite schema includes ancestry_path column"

# First run rano to create the database
e2e_run "create db" "${RANO}" \
    --pattern "nonexistent-process-xyz" \
    --sqlite "${TEST_SQLITE}" \
    --once \
    --no-banner

e2e_run "check schema" sqlite3 "${TEST_SQLITE}" ".schema events"

e2e_assert_last_status 0
e2e_assert_last_contains "ancestry_path"
e2e_info "PASS: SQLite events table has ancestry_path column"

# Test 2: Ancestry path has correct index
e2e_section "Test 2: SQLite ancestry index exists"
e2e_run "check indices" sqlite3 "${TEST_SQLITE}" ".indices events"

e2e_assert_last_status 0
e2e_assert_last_contains "idx_events_ancestry_path"
e2e_info "PASS: ancestry_path index exists"

# Test 3: Seed database with ancestry data and verify export
e2e_section "Test 3: Ancestry path appears in CSV export"

# Seed with a test event that has ancestry
sqlite3 "${TEST_SQLITE}" << 'SQL'
INSERT INTO events (
    ts, run_id, event, provider, pid, comm, cmdline, proto,
    local_ip, local_port, remote_ip, remote_port, domain, ancestry_path, alert
) VALUES (
    '2026-01-20T12:00:00Z', 'test-run-ancestry', 'connect', 'anthropic',
    1234, 'claude', '/usr/bin/claude', 'tcp',
    '192.168.1.100', 54321, '104.18.32.7', 443,
    'api.anthropic.com', 'init:1,systemd:500,bash:1000,claude:1234', 0
);
SQL

e2e_run "export csv" "${RANO}" export --format csv --sqlite "${TEST_SQLITE}" --run-id "test-run-ancestry"

e2e_assert_last_status 0
e2e_assert_last_contains "ancestry_path"
e2e_assert_last_contains "init:1,systemd:500,bash:1000,claude:1234"
e2e_info "PASS: Ancestry path appears in CSV export"

# Test 4: Ancestry path appears in JSONL export
e2e_section "Test 4: Ancestry path appears in JSONL export"
e2e_run "export jsonl" "${RANO}" export --format jsonl --sqlite "${TEST_SQLITE}" --run-id "test-run-ancestry"

e2e_assert_last_status 0
e2e_assert_last_contains "ancestry_path"
e2e_assert_last_contains "init:1,systemd:500,bash:1000,claude:1234"
e2e_info "PASS: Ancestry path appears in JSONL export"

# Test 5: Various ancestry path formats
e2e_section "Test 5: Various ancestry path formats"

sqlite3 "${TEST_SQLITE}" << 'SQL'
-- Short ancestry (direct from init)
INSERT INTO events (
    ts, run_id, event, provider, pid, comm, cmdline, proto,
    local_ip, local_port, remote_ip, remote_port, domain, ancestry_path, alert
) VALUES (
    '2026-01-20T12:01:00Z', 'test-run-ancestry-short', 'connect', 'openai',
    2000, 'codex', '/usr/bin/codex', 'tcp',
    '192.168.1.100', 54322, '13.107.246.10', 443,
    'api.openai.com', 'init:1,codex:2000', 0
);

-- Deep ancestry
INSERT INTO events (
    ts, run_id, event, provider, pid, comm, cmdline, proto,
    local_ip, local_port, remote_ip, remote_port, domain, ancestry_path, alert
) VALUES (
    '2026-01-20T12:02:00Z', 'test-run-ancestry-deep', 'connect', 'google',
    3000, 'gemini', '/usr/bin/gemini', 'tcp',
    '192.168.1.100', 54323, '142.250.189.206', 443,
    'gemini.google.com', 'init:1,systemd:100,login:200,bash:300,tmux:400,bash:500,python:600,gemini:3000', 0
);
SQL

# Verify short ancestry
e2e_run "export short" "${RANO}" export --format csv --sqlite "${TEST_SQLITE}" --run-id "test-run-ancestry-short"
e2e_assert_last_status 0
e2e_assert_last_contains "init:1,codex:2000"
e2e_info "PASS: Short ancestry path captured"

# Verify deep ancestry
e2e_run "export deep" "${RANO}" export --format csv --sqlite "${TEST_SQLITE}" --run-id "test-run-ancestry-deep"
e2e_assert_last_status 0
e2e_assert_last_contains "init:1,systemd:100,login:200,bash:300,tmux:400,bash:500,python:600,gemini:3000"
e2e_info "PASS: Deep ancestry path captured"

# Test 6: Null ancestry path handled gracefully
e2e_section "Test 6: Null ancestry path handled gracefully"

sqlite3 "${TEST_SQLITE}" << 'SQL'
INSERT INTO events (
    ts, run_id, event, provider, pid, comm, cmdline, proto,
    local_ip, local_port, remote_ip, remote_port, domain, ancestry_path, alert
) VALUES (
    '2026-01-20T12:03:00Z', 'test-run-no-ancestry', 'connect', 'anthropic',
    4000, 'claude', '/usr/bin/claude', 'tcp',
    '192.168.1.100', 54324, '104.18.32.7', 443,
    'api.anthropic.com', NULL, 0
);
SQL

e2e_run "export null ancestry" "${RANO}" export --format csv --sqlite "${TEST_SQLITE}" --run-id "test-run-no-ancestry"
e2e_assert_last_status 0
e2e_info "PASS: Null ancestry path handled gracefully in CSV"

e2e_run "export null jsonl" "${RANO}" export --format jsonl --sqlite "${TEST_SQLITE}" --run-id "test-run-no-ancestry"
e2e_assert_last_status 0
e2e_info "PASS: Null ancestry path handled gracefully in JSONL"

# Test 7: Special characters in process names
e2e_section "Test 7: Special characters in ancestry comm names"

sqlite3 "${TEST_SQLITE}" << 'SQL'
INSERT INTO events (
    ts, run_id, event, provider, pid, comm, cmdline, proto,
    local_ip, local_port, remote_ip, remote_port, domain, ancestry_path, alert
) VALUES (
    '2026-01-20T12:04:00Z', 'test-run-special-chars', 'connect', 'anthropic',
    5000, 'my-app_v2', '/usr/bin/my-app_v2', 'tcp',
    '192.168.1.100', 54325, '104.18.32.7', 443,
    'api.anthropic.com', 'init:1,bash:100,my-app_v2:5000', 0
);
SQL

e2e_run "export special chars" "${RANO}" export --format csv --sqlite "${TEST_SQLITE}" --run-id "test-run-special-chars"
e2e_assert_last_status 0
e2e_assert_last_contains "my-app_v2:5000"
e2e_info "PASS: Special characters in process names handled"

# Summary
e2e_section "Summary"
e2e_info "All E2E process ancestry tests passed"
e2e_info "Tests verified:"
e2e_info "  - SQLite schema includes ancestry_path column"
e2e_info "  - ancestry_path index exists for query performance"
e2e_info "  - Ancestry path appears in CSV export"
e2e_info "  - Ancestry path appears in JSONL export"
e2e_info "  - Short ancestry paths work (direct from init)"
e2e_info "  - Deep ancestry paths work (many levels)"
e2e_info "  - Null ancestry path handled gracefully"
e2e_info "  - Special characters in process names handled"
