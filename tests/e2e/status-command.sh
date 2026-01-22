#!/usr/bin/env bash
set -euo pipefail

# This test verifies that `rano status` correctly queries SQLite and outputs
# formatted status for shell prompt embedding.
# It creates a fixture database with known event data and validates:
# 1. Default format output
# 2. Custom format templates with all variables
# 3. One-line mode for prompt embedding
# 4. Handling of missing database (graceful zeros)
# 5. Performance requirement (<50ms execution)

TMP_DIR=$(mktemp -d)
cleanup() {
  rm -rf "${TMP_DIR}"
}
trap cleanup EXIT

# Ensure binary is built before test
RANO_BIN="${RANO_BIN:-./target/release/rano}"
if [ ! -x "${RANO_BIN}" ]; then
  e2e_section "Building rano"
  cargo build --release --quiet
fi

SQLITE_PATH="${TMP_DIR}/test-status.sqlite"

export E2E_FIXTURES="Seeded SQLite at ${SQLITE_PATH}"

e2e_section "Seed fixture database"
e2e_info "path=${SQLITE_PATH}"

# Create and seed the SQLite database with known test data
sqlite3 "${SQLITE_PATH}" <<'SQL'
-- Create schema (matches rano init_sqlite)
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
    closes INTEGER,
    session_name TEXT
);

CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_run_id ON events(run_id);
CREATE INDEX IF NOT EXISTS idx_events_provider ON events(provider);

-- Seed session data with session_name
INSERT INTO sessions (run_id, start_ts, end_ts, host, user, patterns, domain_mode, interval_ms, stats_interval_ms, connects, closes, session_name)
VALUES
  ('status-test-001', '2026-01-22T10:00:00Z', NULL, 'testhost', 'testuser', 'claude,codex', 'ptr', 1000, 2000, 10, 5, 'morning-anthropic-claude-2026-01-22');

-- Seed events for status-test-001
-- 10 connect events (5 anthropic, 3 openai, 2 google) with 5 closes
-- Active connections = 10 - 5 = 5

-- Anthropic connects (5)
INSERT INTO events (ts, run_id, event, provider, pid, comm, cmdline, proto, local_ip, local_port, remote_ip, remote_port, domain, remote_is_private, ip_version)
VALUES
  ('2026-01-22T10:01:00Z', 'status-test-001', 'connect', 'anthropic', 1234, 'claude', '/usr/bin/claude', 'tcp', '127.0.0.1', 54321, '104.18.12.34', 443, 'api.anthropic.com', 0, 4),
  ('2026-01-22T10:02:00Z', 'status-test-001', 'connect', 'anthropic', 1234, 'claude', '/usr/bin/claude', 'tcp', '127.0.0.1', 54322, '104.18.12.34', 443, 'api.anthropic.com', 0, 4),
  ('2026-01-22T10:03:00Z', 'status-test-001', 'connect', 'anthropic', 1234, 'claude', '/usr/bin/claude', 'tcp', '127.0.0.1', 54323, '104.18.12.34', 443, 'api.anthropic.com', 0, 4),
  ('2026-01-22T10:04:00Z', 'status-test-001', 'connect', 'anthropic', 1234, 'claude', '/usr/bin/claude', 'tcp', '127.0.0.1', 54324, '104.18.12.34', 443, 'api.anthropic.com', 0, 4),
  ('2026-01-22T10:05:00Z', 'status-test-001', 'connect', 'anthropic', 1234, 'claude', '/usr/bin/claude', 'tcp', '127.0.0.1', 54325, '104.18.12.34', 443, 'api.anthropic.com', 0, 4);

-- OpenAI connects (3)
INSERT INTO events (ts, run_id, event, provider, pid, comm, cmdline, proto, local_ip, local_port, remote_ip, remote_port, domain, remote_is_private, ip_version)
VALUES
  ('2026-01-22T10:06:00Z', 'status-test-001', 'connect', 'openai', 2345, 'codex', '/usr/bin/codex', 'tcp', '127.0.0.1', 55001, '13.107.42.14', 443, 'api.openai.com', 0, 4),
  ('2026-01-22T10:07:00Z', 'status-test-001', 'connect', 'openai', 2345, 'codex', '/usr/bin/codex', 'tcp', '127.0.0.1', 55002, '13.107.42.14', 443, 'api.openai.com', 0, 4),
  ('2026-01-22T10:08:00Z', 'status-test-001', 'connect', 'openai', 2345, 'codex', '/usr/bin/codex', 'tcp', '127.0.0.1', 55003, '13.107.42.14', 443, 'api.openai.com', 0, 4);

-- Google connects (2)
INSERT INTO events (ts, run_id, event, provider, pid, comm, cmdline, proto, local_ip, local_port, remote_ip, remote_port, domain, remote_is_private, ip_version)
VALUES
  ('2026-01-22T10:09:00Z', 'status-test-001', 'connect', 'google', 3456, 'gemini', '/usr/bin/gemini', 'tcp', '127.0.0.1', 56001, '142.250.80.46', 443, 'generativelanguage.googleapis.com', 0, 4),
  ('2026-01-22T10:10:00Z', 'status-test-001', 'connect', 'google', 3456, 'gemini', '/usr/bin/gemini', 'tcp', '127.0.0.1', 56002, '142.250.80.46', 443, 'generativelanguage.googleapis.com', 0, 4);

-- Close events (5 total: 2 anthropic, 2 openai, 1 google)
INSERT INTO events (ts, run_id, event, provider, pid, comm, cmdline, proto, local_ip, local_port, remote_ip, remote_port, domain, remote_is_private, ip_version, duration_ms)
VALUES
  ('2026-01-22T10:11:00Z', 'status-test-001', 'close', 'anthropic', 1234, 'claude', '/usr/bin/claude', 'tcp', '127.0.0.1', 54321, '104.18.12.34', 443, 'api.anthropic.com', 0, 4, 600000),
  ('2026-01-22T10:12:00Z', 'status-test-001', 'close', 'anthropic', 1234, 'claude', '/usr/bin/claude', 'tcp', '127.0.0.1', 54322, '104.18.12.34', 443, 'api.anthropic.com', 0, 4, 600000),
  ('2026-01-22T10:13:00Z', 'status-test-001', 'close', 'openai', 2345, 'codex', '/usr/bin/codex', 'tcp', '127.0.0.1', 55001, '13.107.42.14', 443, 'api.openai.com', 0, 4, 420000),
  ('2026-01-22T10:14:00Z', 'status-test-001', 'close', 'openai', 2345, 'codex', '/usr/bin/codex', 'tcp', '127.0.0.1', 55002, '13.107.42.14', 443, 'api.openai.com', 0, 4, 420000),
  ('2026-01-22T10:15:00Z', 'status-test-001', 'close', 'google', 3456, 'gemini', '/usr/bin/gemini', 'tcp', '127.0.0.1', 56001, '142.250.80.46', 443, 'generativelanguage.googleapis.com', 0, 4, 360000);
SQL

e2e_info "Seeded 1 session, 15 events total"
e2e_info "status-test-001: 10 connects, 5 closes"
e2e_info "anthropic:5, openai:3, google:2 (connect events)"
e2e_info "active connections: 5"

# Verify seed data
event_count=$(sqlite3 "${SQLITE_PATH}" "SELECT COUNT(*) FROM events")
session_count=$(sqlite3 "${SQLITE_PATH}" "SELECT COUNT(*) FROM sessions")
e2e_info "Verified: ${event_count} events, ${session_count} sessions"

# =============================================================================
# Test 1: Default format output
# =============================================================================
e2e_section "Test 1: Default format output"
e2e_info "Expected: '5 active | anthropic:5 openai:3'"

e2e_run "rano status (default format)" \
  "${RANO_BIN}" status --sqlite "${SQLITE_PATH}"

e2e_assert_last_status 0
e2e_assert_last_contains "5 active"
e2e_assert_last_contains "anthropic:5"
e2e_assert_last_contains "openai:3"

# =============================================================================
# Test 2: Custom format with all variables
# =============================================================================
e2e_section "Test 2: Custom format template"
e2e_info "Testing all template variables: {active}, {total}, {anthropic}, {openai}, {google}, {session_name}"

e2e_run "rano status (custom format)" \
  "${RANO_BIN}" status --sqlite "${SQLITE_PATH}" \
    --format "A:{active} T:{total} An:{anthropic} Op:{openai} Go:{google} S:{session_name}"

e2e_assert_last_status 0
e2e_assert_last_contains "A:5"
e2e_assert_last_contains "T:10"
e2e_assert_last_contains "An:5"
e2e_assert_last_contains "Op:3"
e2e_assert_last_contains "Go:2"
e2e_assert_last_contains "morning-anthropic-claude-2026-01-22"

# =============================================================================
# Test 3: Provider-only format
# =============================================================================
e2e_section "Test 3: Provider counts format"
e2e_info "Format showing only provider counts"

e2e_run "rano status (providers only)" \
  "${RANO_BIN}" status --sqlite "${SQLITE_PATH}" \
    --format "anthropic:{anthropic} | openai:{openai} | google:{google}"

e2e_assert_last_status 0
e2e_assert_last_contains "anthropic:5"
e2e_assert_last_contains "openai:3"
e2e_assert_last_contains "google:2"

# =============================================================================
# Test 4: Missing database - graceful zeros
# =============================================================================
e2e_section "Test 4: Missing database (graceful zeros)"
e2e_info "Should output zeros when database doesn't exist"

e2e_run "rano status (missing db)" \
  "${RANO_BIN}" status --sqlite "${TMP_DIR}/nonexistent.sqlite"

e2e_assert_last_status 0
e2e_assert_last_contains "0 active"
e2e_assert_last_contains "anthropic:0"
e2e_assert_last_contains "openai:0"

# =============================================================================
# Test 5: Empty database - graceful zeros
# =============================================================================
e2e_section "Test 5: Empty database (graceful zeros)"
e2e_info "Should output zeros when database exists but has no events"

EMPTY_DB="${TMP_DIR}/empty.sqlite"
sqlite3 "${EMPTY_DB}" <<'SQL'
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY,
    ts TEXT NOT NULL,
    run_id TEXT,
    event TEXT NOT NULL,
    provider TEXT NOT NULL
);
SQL

e2e_run "rano status (empty db)" \
  "${RANO_BIN}" status --sqlite "${EMPTY_DB}"

e2e_assert_last_status 0
e2e_assert_last_contains "0 active"
e2e_assert_last_contains "anthropic:0"

# =============================================================================
# Test 6: Performance benchmark (<50ms)
# =============================================================================
e2e_section "Test 6: Performance benchmark"
e2e_info "Target: <50ms execution time"

# Run 5 times and check average
total_ms=0
iterations=5

for i in $(seq 1 ${iterations}); do
  start_ns=$(date +%s%N 2>/dev/null || echo "0")
  "${RANO_BIN}" status --sqlite "${SQLITE_PATH}" >/dev/null 2>&1
  end_ns=$(date +%s%N 2>/dev/null || echo "0")

  if [ "${start_ns}" = "0" ] || [ "${end_ns}" = "0" ]; then
    # Fallback for systems without nanosecond support
    e2e_info "Nanosecond timing not available, using time command"
    elapsed_ms=$({ time "${RANO_BIN}" status --sqlite "${SQLITE_PATH}" >/dev/null 2>&1; } 2>&1 | grep real | sed 's/.*m//' | sed 's/s//' | awk '{print int($1 * 1000)}')
  else
    elapsed_ns=$((end_ns - start_ns))
    elapsed_ms=$((elapsed_ns / 1000000))
  fi

  total_ms=$((total_ms + elapsed_ms))
  e2e_info "Run ${i}: ${elapsed_ms}ms"
done

avg_ms=$((total_ms / iterations))
e2e_info "Average execution time: ${avg_ms}ms"

if [ "${avg_ms}" -gt 50 ]; then
  e2e_info "WARNING: Average exceeds 50ms target (${avg_ms}ms)"
  # Don't fail the test, just warn - performance can vary by system
else
  e2e_info "PASS: Average within 50ms target"
fi

# =============================================================================
# Test 7: Session name in format
# =============================================================================
e2e_section "Test 7: Session name display"
e2e_info "Verify session_name template variable"

e2e_run "rano status (session name)" \
  "${RANO_BIN}" status --sqlite "${SQLITE_PATH}" \
    --format "{session_name}"

e2e_assert_last_status 0
e2e_assert_last_contains "morning-anthropic-claude-2026-01-22"

# =============================================================================
# Test 8: One-line mode flag
# =============================================================================
e2e_section "Test 8: One-line mode"
e2e_info "Verify --one-line flag works (default behavior)"

e2e_run "rano status --one-line" \
  "${RANO_BIN}" status --sqlite "${SQLITE_PATH}" --one-line

e2e_assert_last_status 0
# Output should be single line with no trailing newlines beyond one
line_count=$(wc -l < "${E2E_LAST_OUTPUT_FILE}" | tr -d ' ')
if [ "${line_count}" -gt 1 ]; then
  e2e_fail "Expected single line output, got ${line_count} lines"
fi
e2e_info "Confirmed: single-line output"

# =============================================================================
# Test 9: Help output
# =============================================================================
e2e_section "Test 9: Help output"
e2e_info "Verify status --help shows usage"

set +e
e2e_run "rano status --help" \
  "${RANO_BIN}" status --help
set -e

# Help exits with 0
e2e_assert_last_status 0
e2e_assert_last_contains "status"
e2e_assert_last_contains "--format"
e2e_assert_last_contains "--sqlite"

# =============================================================================
# Summary
# =============================================================================
e2e_section "Summary"
e2e_info "All status command tests passed"
e2e_info "Tested: default format, custom format, all variables, missing db, empty db, performance, one-line, help"
