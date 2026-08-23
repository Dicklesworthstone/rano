#!/usr/bin/env bash
set -euo pipefail

# This test verifies that `rano report` correctly queries and reports on seeded SQLite data.
# It creates a fixture database with known event data and validates:
# 1. Pretty output format with session info, summary, providers, domains, IPs
# 2. JSON output format with all expected fields
# 3. Filtering by --latest, --run-id, --since, --until, --top

TMP_DIR=$(mktemp -d)
cleanup() {
  rm -rf "${TMP_DIR}"
}
trap cleanup EXIT

# Ensure binary is built before test
RANO_BIN="${RANO_BIN:-${E2E_RANO_RELEASE}}"
if [ ! -x "${RANO_BIN}" ]; then
  e2e_section "Building rano"
  cargo build --release --quiet
fi

SQLITE_PATH="${TMP_DIR}/test-report.sqlite"

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
    closes INTEGER
);

CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_run_id ON events(run_id);
CREATE INDEX IF NOT EXISTS idx_events_provider ON events(provider);
CREATE INDEX IF NOT EXISTS idx_events_remote_ip ON events(remote_ip);
CREATE INDEX IF NOT EXISTS idx_events_domain ON events(domain);

-- Seed session data
INSERT INTO sessions (run_id, start_ts, end_ts, host, user, patterns, domain_mode, interval_ms, stats_interval_ms, connects, closes)
VALUES
  ('test-run-001', '2026-01-15T10:00:00Z', '2026-01-15T11:00:00Z', 'testhost', 'testuser', 'claude,codex', 'ptr', 1000, 2000, 6, 3),
  ('test-run-002', '2026-01-17T14:00:00Z', '2026-01-17T15:30:00Z', 'testhost', 'testuser', 'claude', 'ptr', 1000, 2000, 4, 3);

-- Seed events for test-run-001 (older session)
-- Anthropic connections
INSERT INTO events (ts, run_id, event, provider, pid, comm, cmdline, proto, local_ip, local_port, remote_ip, remote_port, domain, remote_is_private, ip_version)
VALUES
  ('2026-01-15T10:05:00Z', 'test-run-001', 'connect', 'anthropic', 1234, 'claude', '/usr/bin/claude', 'tcp', '127.0.0.1', 54321, '104.18.12.34', 443, 'api.anthropic.com', 0, 4),
  ('2026-01-15T10:10:00Z', 'test-run-001', 'connect', 'anthropic', 1234, 'claude', '/usr/bin/claude', 'tcp', '127.0.0.1', 54322, '104.18.12.35', 443, 'api.anthropic.com', 0, 4);

INSERT INTO events (ts, run_id, event, provider, pid, comm, cmdline, proto, local_ip, local_port, remote_ip, remote_port, domain, remote_is_private, ip_version, duration_ms)
VALUES
  ('2026-01-15T10:15:00Z', 'test-run-001', 'close', 'anthropic', 1234, 'claude', '/usr/bin/claude', 'tcp', '127.0.0.1', 54321, '104.18.12.34', 443, 'api.anthropic.com', 0, 4, 600000);

-- OpenAI connections
INSERT INTO events (ts, run_id, event, provider, pid, comm, cmdline, proto, local_ip, local_port, remote_ip, remote_port, domain, remote_is_private, ip_version)
VALUES
  ('2026-01-15T10:20:00Z', 'test-run-001', 'connect', 'openai', 2345, 'codex', '/usr/bin/codex', 'tcp', '127.0.0.1', 55001, '13.107.42.14', 443, 'api.openai.com', 0, 4),
  ('2026-01-15T10:25:00Z', 'test-run-001', 'connect', 'openai', 2345, 'codex', '/usr/bin/codex', 'tcp', '127.0.0.1', 55002, '13.107.42.14', 443, 'api.openai.com', 0, 4),
  ('2026-01-15T10:30:00Z', 'test-run-001', 'connect', 'openai', 2345, 'codex', '/usr/bin/codex', 'tcp', '127.0.0.1', 55003, '20.42.73.28', 443, 'cdn.openai.com', 0, 4);

INSERT INTO events (ts, run_id, event, provider, pid, comm, cmdline, proto, local_ip, local_port, remote_ip, remote_port, domain, remote_is_private, ip_version, duration_ms)
VALUES
  ('2026-01-15T10:35:00Z', 'test-run-001', 'close', 'openai', 2345, 'codex', '/usr/bin/codex', 'tcp', '127.0.0.1', 55001, '13.107.42.14', 443, 'api.openai.com', 0, 4, 900000),
  ('2026-01-15T10:40:00Z', 'test-run-001', 'close', 'openai', 2345, 'codex', '/usr/bin/codex', 'tcp', '127.0.0.1', 55002, '13.107.42.14', 443, 'api.openai.com', 0, 4, 900000);

-- Unknown provider connection
INSERT INTO events (ts, run_id, event, provider, pid, comm, cmdline, proto, local_ip, local_port, remote_ip, remote_port, domain, remote_is_private, ip_version)
VALUES
  ('2026-01-15T10:45:00Z', 'test-run-001', 'connect', 'unknown', 9999, 'curl', '/usr/bin/curl', 'tcp', '127.0.0.1', 60000, '8.8.8.8', 443, 'dns.google', 0, 4);

-- Seed events for test-run-002 (more recent session)
INSERT INTO events (ts, run_id, event, provider, pid, comm, cmdline, proto, local_ip, local_port, remote_ip, remote_port, domain, remote_is_private, ip_version)
VALUES
  ('2026-01-17T14:05:00Z', 'test-run-002', 'connect', 'anthropic', 5678, 'claude', '/usr/bin/claude --help', 'tcp', '127.0.0.1', 56001, '104.18.12.34', 443, 'api.anthropic.com', 0, 4),
  ('2026-01-17T14:10:00Z', 'test-run-002', 'connect', 'anthropic', 5678, 'claude', '/usr/bin/claude --help', 'tcp', '127.0.0.1', 56002, '104.18.12.36', 443, 'cdn.anthropic.com', 0, 4),
  ('2026-01-17T14:15:00Z', 'test-run-002', 'connect', 'google', 6789, 'gemini', '/usr/bin/gemini', 'tcp', '127.0.0.1', 57001, '142.250.80.46', 443, 'generativelanguage.googleapis.com', 0, 4),
  ('2026-01-17T14:20:00Z', 'test-run-002', 'connect', 'google', 6789, 'gemini', '/usr/bin/gemini', 'tcp', '127.0.0.1', 57002, '142.250.80.46', 443, 'generativelanguage.googleapis.com', 0, 4);

INSERT INTO events (ts, run_id, event, provider, pid, comm, cmdline, proto, local_ip, local_port, remote_ip, remote_port, domain, remote_is_private, ip_version, duration_ms)
VALUES
  ('2026-01-17T14:25:00Z', 'test-run-002', 'close', 'anthropic', 5678, 'claude', '/usr/bin/claude --help', 'tcp', '127.0.0.1', 56001, '104.18.12.34', 443, 'api.anthropic.com', 0, 4, 1200000),
  ('2026-01-17T14:30:00Z', 'test-run-002', 'close', 'google', 6789, 'gemini', '/usr/bin/gemini', 'tcp', '127.0.0.1', 57001, '142.250.80.46', 443, 'generativelanguage.googleapis.com', 0, 4, 900000),
  ('2026-01-17T14:35:00Z', 'test-run-002', 'close', 'google', 6789, 'gemini', '/usr/bin/gemini', 'tcp', '127.0.0.1', 57002, '142.250.80.46', 443, 'generativelanguage.googleapis.com', 0, 4, 900000);
SQL

e2e_info "Seeded 2 sessions, 16 events total"
e2e_info "test-run-001: 9 events (anthropic:3, openai:5, unknown:1)"
e2e_info "test-run-002: 7 events (anthropic:3, google:4)"

# Verify seed data
event_count=$(sqlite3 "${SQLITE_PATH}" "SELECT COUNT(*) FROM events")
session_count=$(sqlite3 "${SQLITE_PATH}" "SELECT COUNT(*) FROM sessions")
e2e_info "Verified: ${event_count} events, ${session_count} sessions"

# =============================================================================
# Test 1: Report without filters (all data)
# =============================================================================
e2e_section "Expectations (all data)"
e2e_info "total_events=16"
e2e_info "providers=[anthropic, openai, google, unknown]"
e2e_info "top_domains should include api.anthropic.com, api.openai.com, generativelanguage.googleapis.com"

e2e_run "rano report (all data, pretty)" \
  "${RANO_BIN}" report --sqlite "${SQLITE_PATH}" --no-color

e2e_assert_last_status 0
e2e_assert_last_contains "rano report"
e2e_assert_last_contains "anthropic"
e2e_assert_last_contains "openai"
e2e_assert_last_contains "google"
e2e_assert_last_contains "api.anthropic.com"

# =============================================================================
# Test 2: JSON output format
# =============================================================================
e2e_section "Expectations (JSON output)"
e2e_info "JSON should have: meta, summary, providers, top_domains, top_ips"

e2e_run "rano report (all data, JSON)" \
  "${RANO_BIN}" report --sqlite "${SQLITE_PATH}" --json

e2e_assert_last_status 0
e2e_assert_last_contains '"summary"'
e2e_assert_last_contains '"providers"'
e2e_assert_last_contains '"top_domains"'
e2e_assert_last_contains '"top_ips"'
e2e_assert_last_contains '"total_events": 16'

# =============================================================================
# Test 3: --latest flag (most recent session)
# =============================================================================
e2e_section "Expectations (--latest)"
e2e_info "Should report on test-run-002 only"
e2e_info "events=7, providers=[anthropic, google]"

e2e_run "rano report --latest (JSON)" \
  "${RANO_BIN}" report --sqlite "${SQLITE_PATH}" --latest --json

e2e_assert_last_status 0
e2e_assert_last_contains '"run_id": "test-run-002"'
e2e_assert_last_contains '"total_events": 7'

# Verify openai is NOT in the latest session
if grep -q '"provider": "openai"' "${E2E_LAST_OUTPUT_FILE}"; then
  e2e_fail "Latest session should not contain openai provider"
fi
e2e_info "Confirmed: openai not in latest session"

# =============================================================================
# Test 4: --run-id filter
# =============================================================================
e2e_section "Expectations (--run-id test-run-001)"
e2e_info "Should report on test-run-001 only"
e2e_info "events=9, providers=[anthropic, openai, unknown]"

e2e_run "rano report --run-id test-run-001 (JSON)" \
  "${RANO_BIN}" report --sqlite "${SQLITE_PATH}" --run-id test-run-001 --json

e2e_assert_last_status 0
e2e_assert_last_contains '"run_id": "test-run-001"'
e2e_assert_last_contains '"total_events": 9'
e2e_assert_last_contains '"provider": "openai"'

# Verify google is NOT in run-001
if grep -q '"provider": "google"' "${E2E_LAST_OUTPUT_FILE}"; then
  e2e_fail "run-001 should not contain google provider"
fi
e2e_info "Confirmed: google not in run-001"

# =============================================================================
# Test 5: --top flag
# =============================================================================
e2e_section "Expectations (--top 2)"
e2e_info "top_domains and top_ips should have max 2 entries each"

e2e_run "rano report --top 2 (JSON)" \
  "${RANO_BIN}" report --sqlite "${SQLITE_PATH}" --top 2 --json

e2e_assert_last_status 0

# Count top_domains entries (count lines with "domain": followed by "events":)
# The top_domains array entries have format: {"domain": ..., "events": ..., "provider": ...}
# top_ips entries have: {"ip": ..., "events": ..., "domain": ...}
# So we look for entries starting with "domain": (use [[:space:]] for portability)
domain_count=$(grep -E '^[[:space:]]*\{"domain":' "${E2E_LAST_OUTPUT_FILE}" | wc -l)
if [ "${domain_count}" -gt 2 ]; then
  e2e_fail "Expected max 2 top domains, got ${domain_count}"
fi
e2e_info "top_domains count: ${domain_count} (expected <= 2)"

# =============================================================================
# Test 6: --since time filter
# =============================================================================
e2e_section "Expectations (--since 2026-01-17)"
e2e_info "Should only include events from test-run-002"

e2e_run "rano report --since 2026-01-17 (JSON)" \
  "${RANO_BIN}" report --sqlite "${SQLITE_PATH}" --since 2026-01-17 --json

e2e_assert_last_status 0
e2e_assert_last_contains '"total_events": 7'

# =============================================================================
# Test 7: --until time filter
# =============================================================================
e2e_section "Expectations (--until 2026-01-16)"
e2e_info "Should only include events from test-run-001"

e2e_run "rano report --until 2026-01-16 (JSON)" \
  "${RANO_BIN}" report --sqlite "${SQLITE_PATH}" --until 2026-01-16 --json

e2e_assert_last_status 0
e2e_assert_last_contains '"total_events": 9'

# =============================================================================
# Test 8: Combined filters (--since + --until)
# =============================================================================
e2e_section "Expectations (--since 2026-01-15T10:20:00Z --until 2026-01-15T10:40:00Z)"
e2e_info "Should only include openai events from run-001 in that window"

e2e_run "rano report time window (JSON)" \
  "${RANO_BIN}" report --sqlite "${SQLITE_PATH}" \
    --since "2026-01-15T10:20:00Z" --until "2026-01-15T10:40:00Z" --json

e2e_assert_last_status 0
# Should have 4 events (3 openai connects + 1 openai close in that window)
e2e_assert_last_contains '"connects":'
e2e_assert_last_contains '"closes":'

# =============================================================================
# Test 9: Pretty output verification
# =============================================================================
e2e_section "Expectations (pretty output format)"
e2e_info "Should have structured sections with headers"

e2e_run "rano report --latest (pretty)" \
  "${RANO_BIN}" report --sqlite "${SQLITE_PATH}" --latest --no-color

e2e_assert_last_status 0
e2e_assert_last_contains "rano report"
e2e_assert_last_contains "Session"
e2e_assert_last_contains "Run ID:"
e2e_assert_last_contains "Summary"
e2e_assert_last_contains "Events:"
e2e_assert_last_contains "Providers"
e2e_assert_last_contains "Top Domains"
e2e_assert_last_contains "Top IPs"

# =============================================================================
# Test 10: Error handling - missing database
# =============================================================================
e2e_section "Expectations (missing database)"
e2e_info "Should fail gracefully with clear error message"

set +e
e2e_run "rano report (missing db)" \
  "${RANO_BIN}" report --sqlite "/nonexistent/path/db.sqlite"
set -e

if [ "${E2E_LAST_STATUS}" -eq 0 ]; then
  e2e_fail "Expected non-zero exit for missing database"
fi
e2e_assert_last_contains "not found"
e2e_info "Confirmed: graceful error for missing database"

# =============================================================================
# Test 11: Session metadata in pretty output
# =============================================================================
e2e_section "Expectations (session metadata)"
e2e_info "Pretty output should show host, patterns, start/end times"

e2e_run "rano report --run-id test-run-001 (session info)" \
  "${RANO_BIN}" report --sqlite "${SQLITE_PATH}" --run-id test-run-001 --no-color

e2e_assert_last_status 0
e2e_assert_last_contains "test-run-001"
e2e_assert_last_contains "testhost"
e2e_assert_last_contains "claude,codex"

e2e_section "Summary"
e2e_info "All report tests passed"
e2e_info "Tested: all data, JSON, --latest, --run-id, --top, --since, --until, pretty format, error handling"
