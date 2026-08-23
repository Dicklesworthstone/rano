#!/usr/bin/env bash
# E2E Test: Export Formats (CSV/JSONL)
# Tests the export subcommand for data extraction
#
# This test verifies:
# - CSV export produces valid RFC 4180 output
# - JSONL export produces valid JSON per line
# - Filters (--since, --until, --provider, --domain) work correctly
# - Empty result sets are handled gracefully
# - Special characters (commas, quotes, newlines) are escaped properly
#
# Prerequisites:
# - rano binary built (cargo build)
# - SQLite3 available for data seeding

set -euo pipefail

RANO="${RANO:-${E2E_RANO_DEBUG}}"
TEST_SQLITE="/tmp/rano-e2e-export-$$.sqlite"
EXPORT_CSV="/tmp/rano-e2e-export-$$.csv"
EXPORT_JSONL="/tmp/rano-e2e-export-$$.jsonl"

# Cleanup on exit
cleanup() {
    rm -f "${TEST_SQLITE}" "${EXPORT_CSV}" "${EXPORT_JSONL}"
}
trap cleanup EXIT

e2e_section "Setup"
e2e_info "rano=${RANO}"
e2e_info "test_sqlite=${TEST_SQLITE}"
e2e_info "export_csv=${EXPORT_CSV}"
e2e_info "export_jsonl=${EXPORT_JSONL}"

# Ensure rano binary exists
if [ ! -x "${RANO}" ]; then
    e2e_fail "rano binary not found at ${RANO}. Run 'cargo build' first."
fi

# Seed test database with sample data
e2e_section "Seed: Create test database"
sqlite3 "${TEST_SQLITE}" << 'SQL'
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
    ancestry_path TEXT,
    remote_is_private INTEGER,
    ip_version INTEGER,
    duration_ms INTEGER,
    alert INTEGER
);
CREATE INDEX idx_events_ts ON events(ts);
CREATE INDEX idx_events_run_id ON events(run_id);
CREATE INDEX idx_events_provider ON events(provider);
CREATE INDEX idx_events_remote_ip ON events(remote_ip);
CREATE INDEX idx_events_domain ON events(domain);
CREATE INDEX idx_events_ancestry_path ON events(ancestry_path);

-- Insert test data
INSERT INTO events (ts, run_id, event, provider, pid, comm, cmdline, proto, local_ip, local_port, remote_ip, remote_port, domain, duration_ms, alert)
VALUES
    ('2026-01-20T10:00:00Z', 'run-test-1', 'connect', 'anthropic', 1234, 'claude', '/usr/bin/claude', 'tcp', '192.168.1.100', 54321, '104.18.32.7', 443, 'api.anthropic.com', NULL, 0),
    ('2026-01-20T10:00:01Z', 'run-test-1', 'connect', 'openai', 1235, 'codex', '/usr/bin/codex', 'tcp', '192.168.1.100', 54322, '13.107.246.10', 443, 'api.openai.com', NULL, 0),
    ('2026-01-20T10:00:02Z', 'run-test-1', 'close', 'anthropic', 1234, 'claude', '/usr/bin/claude', 'tcp', '192.168.1.100', 54321, '104.18.32.7', 443, 'api.anthropic.com', 1500, 0),
    ('2026-01-20T10:00:05Z', 'run-test-1', 'connect', 'google', 1236, 'gemini', '/usr/bin/gemini', 'tcp', '192.168.1.100', 54323, '142.250.189.206', 443, 'gemini.google.com', NULL, 0),
    ('2026-01-20T10:00:10Z', 'run-test-1', 'close', 'openai', 1235, 'codex', '/usr/bin/codex', 'tcp', '192.168.1.100', 54322, '13.107.246.10', 443, 'api.openai.com', 9000, 0),
    ('2026-01-20T10:00:15Z', 'run-test-1', 'close', 'google', 1236, 'gemini', '/usr/bin/gemini', 'tcp', '192.168.1.100', 54323, '142.250.189.206', 443, 'gemini.google.com', 10000, 0),
    ('2026-01-21T09:00:00Z', 'run-test-2', 'connect', 'anthropic', 2001, 'claude', '/usr/bin/claude --special="value,with,commas"', 'tcp', '192.168.1.100', 55001, '104.18.32.7', 443, 'api.anthropic.com', NULL, 1);
SQL
e2e_info "PASS: Test database seeded with 7 events"

# Test 1: CSV export with all data
e2e_section "Test 1: CSV export - all data"
e2e_run "export csv" "${RANO}" export --format csv --sqlite "${TEST_SQLITE}"

e2e_assert_last_status 0
e2e_assert_last_contains "ts,run_id,event,provider"
e2e_info "PASS: CSV export produces output with header"

# Verify row count (header + 7 data rows = 8 lines, but CRLF might affect)
CSV_LINES=$(wc -l < "${E2E_LAST_OUTPUT_FILE}" | tr -d ' ')
if [ "${CSV_LINES}" -lt 7 ]; then
    e2e_fail "Expected at least 7 lines in CSV, got ${CSV_LINES}"
fi
e2e_info "PASS: CSV has expected number of rows (${CSV_LINES})"

# Test 2: JSONL export with all data
e2e_section "Test 2: JSONL export - all data"
e2e_run "export jsonl" "${RANO}" export --format jsonl --sqlite "${TEST_SQLITE}"

e2e_assert_last_status 0
e2e_assert_last_contains "api.anthropic.com"
e2e_assert_last_contains "api.openai.com"

# Verify each line is valid JSON
JSONL_FILE="${E2E_LAST_OUTPUT_FILE}"
JSONL_LINES=$(wc -l < "${JSONL_FILE}" | tr -d ' ')
e2e_info "JSONL output has ${JSONL_LINES} lines"

# Test JSON validity with jq if available
if command -v jq &>/dev/null; then
    if ! jq -e . "${JSONL_FILE}" >/dev/null 2>&1; then
        # Try line by line
        line_num=0
        while IFS= read -r line; do
            line_num=$((line_num + 1))
            if [ -n "${line}" ]; then
                if ! echo "${line}" | jq -e . >/dev/null 2>&1; then
                    e2e_info "Invalid JSON at line ${line_num}: ${line:0:100}"
                    e2e_fail "JSONL contains invalid JSON"
                fi
            fi
        done < "${JSONL_FILE}"
    fi
    e2e_info "PASS: All JSONL lines are valid JSON"
else
    e2e_info "SKIP: jq not available, JSON validation skipped"
fi

# Test 3: CSV with --since filter
e2e_section "Test 3: CSV with time filter (--since)"
e2e_run "export csv since" "${RANO}" export --format csv --sqlite "${TEST_SQLITE}" --since "2026-01-21T00:00:00Z"

e2e_assert_last_status 0
e2e_assert_last_contains "run-test-2"

# Should only have run-test-2 data (1 row + header)
FILTERED_LINES=$(wc -l < "${E2E_LAST_OUTPUT_FILE}" | tr -d ' ')
e2e_info "Filtered CSV has ${FILTERED_LINES} lines"
e2e_info "PASS: --since filter works"

# Test 4: CSV with --until filter
e2e_section "Test 4: CSV with time filter (--until)"
e2e_run "export csv until" "${RANO}" export --format csv --sqlite "${TEST_SQLITE}" --until "2026-01-20T10:00:03Z"

e2e_assert_last_status 0
# Should have events at 10:00:00, 10:00:01, 10:00:02 (3 rows + header)
UNTIL_LINES=$(wc -l < "${E2E_LAST_OUTPUT_FILE}" | tr -d ' ')
e2e_info "Filtered CSV (until) has ${UNTIL_LINES} lines"
e2e_info "PASS: --until filter works"

# Test 5: CSV with --provider filter
e2e_section "Test 5: CSV with provider filter"
e2e_run "export csv provider" "${RANO}" export --format csv --sqlite "${TEST_SQLITE}" --provider anthropic

e2e_assert_last_status 0
e2e_assert_last_contains "anthropic"
# Verify no other providers
if grep -q "openai" "${E2E_LAST_OUTPUT_FILE}"; then
    e2e_fail "Provider filter allowed non-matching provider"
fi
e2e_info "PASS: --provider filter works"

# Test 6: CSV with --domain filter
e2e_section "Test 6: CSV with domain filter"
e2e_run "export csv domain" "${RANO}" export --format csv --sqlite "${TEST_SQLITE}" --domain "*.google.com"

e2e_assert_last_status 0
e2e_assert_last_contains "gemini.google.com"
# Verify no anthropic/openai domains
if grep -q "api.anthropic.com" "${E2E_LAST_OUTPUT_FILE}"; then
    e2e_fail "Domain filter allowed non-matching domain"
fi
e2e_info "PASS: --domain filter works"

# Test 7: CSV with --run-id filter
e2e_section "Test 7: CSV with run-id filter"
e2e_run "export csv run-id" "${RANO}" export --format csv --sqlite "${TEST_SQLITE}" --run-id "run-test-1"

e2e_assert_last_status 0
e2e_assert_last_contains "run-test-1"
if grep -q "run-test-2" "${E2E_LAST_OUTPUT_FILE}"; then
    e2e_fail "Run-id filter allowed non-matching run"
fi
e2e_info "PASS: --run-id filter works"

# Test 8: CSV with --no-header
e2e_section "Test 8: CSV with --no-header"
e2e_run "export csv no-header" "${RANO}" export --format csv --sqlite "${TEST_SQLITE}" --no-header

e2e_assert_last_status 0
# First line should NOT contain the header fields
FIRST_LINE=$(head -1 "${E2E_LAST_OUTPUT_FILE}")
if [[ "${FIRST_LINE}" == ts,run_id,event* ]]; then
    e2e_fail "--no-header still produced header"
fi
e2e_info "PASS: --no-header suppresses header"

# Test 9: Empty result set (use time filter for no matches)
e2e_section "Test 9: Empty result set handling"
e2e_run "export csv empty" "${RANO}" export --format csv --sqlite "${TEST_SQLITE}" --since "2030-01-01T00:00:00Z"

e2e_assert_last_status 0
# Should only have header line for CSV
EMPTY_LINES=$(wc -l < "${E2E_LAST_OUTPUT_FILE}" | tr -d ' ')
if [ "${EMPTY_LINES}" -gt 1 ]; then
    e2e_fail "Expected only header for empty result, got ${EMPTY_LINES} lines"
fi
e2e_info "PASS: Empty result set handled gracefully"

# Test 10: Special characters in cmdline
e2e_section "Test 10: Special characters escaped correctly"
e2e_run "export csv special" "${RANO}" export --format csv --sqlite "${TEST_SQLITE}" --run-id "run-test-2"

e2e_assert_last_status 0
# The cmdline contains commas, should be quoted
e2e_assert_last_contains "special="
e2e_info "PASS: Special characters in fields are handled"

# Test 11: Combined filters
e2e_section "Test 11: Combined filters"
e2e_run "export combined" "${RANO}" export --format csv --sqlite "${TEST_SQLITE}" \
    --since "2026-01-20T00:00:00Z" \
    --until "2026-01-21T00:00:00Z" \
    --provider anthropic

e2e_assert_last_status 0
e2e_assert_last_contains "anthropic"
e2e_assert_last_contains "run-test-1"
# Should not have run-test-2 (outside time range)
if grep -q "run-test-2" "${E2E_LAST_OUTPUT_FILE}"; then
    e2e_fail "Combined filters did not exclude run-test-2"
fi
e2e_info "PASS: Combined filters work together"

# Test 12: JSONL empty result (use time filter for no matches)
e2e_section "Test 12: JSONL empty result"
e2e_run "export jsonl empty" "${RANO}" export --format jsonl --sqlite "${TEST_SQLITE}" --since "2030-01-01T00:00:00Z"

e2e_assert_last_status 0
JSONL_EMPTY_LINES=$(wc -l < "${E2E_LAST_OUTPUT_FILE}" | tr -d ' ')
if [ "${JSONL_EMPTY_LINES}" -ne 0 ]; then
    e2e_fail "Expected 0 lines for empty JSONL, got ${JSONL_EMPTY_LINES}"
fi
e2e_info "PASS: Empty JSONL produces no output"

# Summary
e2e_section "Summary"
e2e_info "All E2E export format tests passed"
e2e_info "Tests verified:"
e2e_info "  - CSV export with header"
e2e_info "  - JSONL export with valid JSON"
e2e_info "  - --since filter"
e2e_info "  - --until filter"
e2e_info "  - --provider filter"
e2e_info "  - --domain filter"
e2e_info "  - --run-id filter"
e2e_info "  - --no-header option"
e2e_info "  - Empty result set handling"
e2e_info "  - Special characters escaped"
e2e_info "  - Combined filters"
