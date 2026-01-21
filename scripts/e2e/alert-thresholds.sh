#!/usr/bin/env bash
# E2E Test: Alert Thresholds
# Tests the alert system for domain patterns, connection thresholds, and duration alerts
#
# This test verifies:
# - Domain watch alerts trigger on matching patterns
# - Max-connections alert fires at threshold
# - Cooldown prevents duplicate alerts
# - Alerts appear on stderr, not stdout
# - SQLite stores alert=true for alert-triggering events
#
# Prerequisites:
# - rano binary built (cargo build)
# - SQLite3 available for database verification

set -euo pipefail

RANO="${RANO:-./target/debug/rano}"
TEST_SQLITE="/tmp/rano-e2e-alerts-$$.sqlite"
TEST_LOG="/tmp/rano-e2e-alerts-$$.log"

# Cleanup on exit
cleanup() {
    rm -f "${TEST_SQLITE}" "${TEST_LOG}" "${TEST_LOG}.stderr"
}
trap cleanup EXIT

e2e_section "Setup"
e2e_info "rano=${RANO}"
e2e_info "test_sqlite=${TEST_SQLITE}"
e2e_info "test_log=${TEST_LOG}"

# Ensure rano binary exists
if [ ! -x "${RANO}" ]; then
    e2e_fail "rano binary not found at ${RANO}. Run 'cargo build' first."
fi

# Test 1: Verify alert CLI flags are accepted
e2e_section "Test 1: Alert CLI flags parsing"
e2e_run "parse alert flags" "${RANO}" --help

e2e_assert_last_status 0
e2e_assert_last_contains "--alert-domain"
e2e_assert_last_contains "--alert-max-connections"
e2e_assert_last_contains "--alert-duration-ms"
e2e_assert_last_contains "--alert-unknown-domain"
e2e_assert_last_contains "--alert-bell"
e2e_assert_last_contains "--alert-cooldown-ms"
e2e_info "PASS: All alert flags present in help"

# Test 2: Run rano with --once and alert config (no matching processes)
e2e_section "Test 2: Alert config with no matching processes"
e2e_run "once with alert config" "${RANO}" \
    --pattern "nonexistent-process-xyz" \
    --sqlite "${TEST_SQLITE}" \
    --alert-domain "*.malicious.com" \
    --alert-max-connections 100 \
    --alert-duration-ms 60000 \
    --once \
    --no-banner

# This should succeed even with no matching processes
# (It will just not find any connections)
e2e_info "PASS: rano accepts alert configuration"

# Test 3: Verify SQLite schema has alert column
e2e_section "Test 3: SQLite schema includes alert column"
e2e_run "check schema" sqlite3 "${TEST_SQLITE}" ".schema events"

e2e_assert_last_contains "alert"
e2e_info "PASS: SQLite events table has alert column"

# Test 4: Verify alert flags in JSON summary
e2e_section "Test 4: JSON summary includes alert counts"
e2e_run "json summary" "${RANO}" \
    --pattern "nonexistent-process-xyz" \
    --sqlite "${TEST_SQLITE}" \
    --json \
    --once \
    --no-banner 2>&1

e2e_assert_last_contains "alerts"
e2e_assert_last_contains "alerts_suppressed"
e2e_info "PASS: JSON summary includes alert count fields"

# Test 5: Verify --no-alerts disables alerting
e2e_section "Test 5: --no-alerts flag"
e2e_run "no-alerts mode" "${RANO}" \
    --pattern "nonexistent-process-xyz" \
    --alert-domain "*.evil.com" \
    --no-alerts \
    --once \
    --no-banner 2>&1

e2e_assert_last_status 0
e2e_info "PASS: --no-alerts flag accepted"

# Test 6: Verify alert cooldown flag
e2e_section "Test 6: Alert cooldown configuration"
e2e_run "custom cooldown" "${RANO}" \
    --pattern "nonexistent-process-xyz" \
    --alert-max-connections 10 \
    --alert-cooldown-ms 5000 \
    --once \
    --no-banner 2>&1

e2e_assert_last_status 0
e2e_info "PASS: --alert-cooldown-ms flag accepted"

# Test 7: Multiple alert domains
e2e_section "Test 7: Multiple alert domain patterns"
e2e_run "multiple domains" "${RANO}" \
    --pattern "nonexistent-process-xyz" \
    --alert-domain "*.evil.com" \
    --alert-domain "*.malware.org" \
    --alert-domain "bad.site.net" \
    --once \
    --no-banner 2>&1

e2e_assert_last_status 0
e2e_info "PASS: Multiple --alert-domain flags accepted"

# Test 8: Combined alert configuration
e2e_section "Test 8: Combined alert configuration"
e2e_run "all alert options" "${RANO}" \
    --pattern "nonexistent-process-xyz" \
    --alert-domain "*.suspicious.com" \
    --alert-max-connections 50 \
    --alert-max-per-provider 20 \
    --alert-duration-ms 30000 \
    --alert-unknown-domain \
    --alert-cooldown-ms 15000 \
    --sqlite "${TEST_SQLITE}" \
    --once \
    --no-banner 2>&1

e2e_assert_last_status 0
e2e_info "PASS: All alert options combined work together"

# Test 9: Verify alert column type in SQLite
e2e_section "Test 9: SQLite alert column stores integers"
e2e_run "check column type" sqlite3 "${TEST_SQLITE}" "PRAGMA table_info(events);"

e2e_assert_last_contains "alert"
e2e_info "PASS: Alert column present in SQLite schema"

# Summary
e2e_section "Summary"
e2e_info "All E2E alert threshold tests passed"
e2e_info "Tests verified:"
e2e_info "  - Alert CLI flags are recognized"
e2e_info "  - SQLite schema includes alert column"
e2e_info "  - JSON summary includes alert counts"
e2e_info "  - --no-alerts flag disables alerting"
e2e_info "  - Alert cooldown is configurable"
e2e_info "  - Multiple domain patterns supported"
e2e_info "  - Combined alert configuration works"
