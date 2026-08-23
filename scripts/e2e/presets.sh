#!/usr/bin/env bash
# E2E Test: Presets
# Tests the preset system for configuration bundles
#
# This test verifies:
# - Built-in presets (audit, quiet, live, verbose) load without error
# - --list-presets shows all available presets
# - Preset values are applied correctly
# - CLI flags override preset values
# - Multiple presets merge in order
# - Custom user presets can be loaded
#
# Prerequisites:
# - rano binary built (cargo build)

set -euo pipefail

RANO="${RANO:-${E2E_RANO_DEBUG}}"
TEMP_PRESET_DIR=""

# Cleanup on exit
cleanup() {
    if [ -n "${TEMP_PRESET_DIR}" ] && [ -d "${TEMP_PRESET_DIR}" ]; then
        rm -rf "${TEMP_PRESET_DIR}"
    fi
}
trap cleanup EXIT

e2e_section "Setup"
e2e_info "rano=${RANO}"

# Ensure rano binary exists
if [ ! -x "${RANO}" ]; then
    e2e_fail "rano binary not found at ${RANO}. Run 'cargo build' first."
fi

# Test 1: --list-presets shows available presets
e2e_section "Test 1: --list-presets shows built-in presets"
e2e_run "list presets" "${RANO}" --list-presets

e2e_assert_last_status 0
e2e_assert_last_contains "audit"
e2e_assert_last_contains "quiet"
e2e_assert_last_contains "live"
e2e_assert_last_contains "verbose"
e2e_assert_last_contains "Available presets:"
e2e_info "PASS: --list-presets shows all built-in presets"

# Test 2: audit preset runs without error
e2e_section "Test 2: audit preset loads successfully"
e2e_run "preset audit" "${RANO}" --preset audit --pattern nonexistent --once --no-banner

e2e_assert_last_status 0
e2e_assert_last_contains "Summary"
e2e_info "PASS: audit preset loads and runs"

# Test 3: quiet preset runs without error
e2e_section "Test 3: quiet preset loads successfully"
e2e_run "preset quiet" "${RANO}" --preset quiet --pattern nonexistent --once

e2e_assert_last_status 0
# quiet preset sets no_banner=true, so check Summary only
e2e_assert_last_contains "Summary"
e2e_info "PASS: quiet preset loads and runs"

# Test 4: live preset runs without error
e2e_section "Test 4: live preset loads successfully"
e2e_run "preset live" "${RANO}" --preset live --pattern nonexistent --once --no-banner

e2e_assert_last_status 0
e2e_assert_last_contains "Summary"
e2e_info "PASS: live preset loads and runs"

# Test 5: verbose preset runs without error
e2e_section "Test 5: verbose preset loads successfully"
e2e_run "preset verbose" "${RANO}" --preset verbose --pattern nonexistent --once

e2e_assert_last_status 0
# verbose sets include_udp=true, check banner line
e2e_assert_last_contains "udp=true"
e2e_info "PASS: verbose preset loads and runs"

# Test 6: Unknown preset returns error
e2e_section "Test 6: Unknown preset returns error"
e2e_run "preset unknown" "${RANO}" --preset nonexistent --pattern test --once 2>&1 || true

# Should have failed
if [ "${E2E_LAST_STATUS}" -eq 0 ]; then
    e2e_fail "Expected error for unknown preset, but got success"
fi
e2e_assert_last_contains "Unknown preset 'nonexistent'"
e2e_assert_last_contains "audit"
e2e_info "PASS: Unknown preset returns helpful error"

# Test 7: Preset descriptions are shown in list
e2e_section "Test 7: Preset descriptions in --list-presets"
e2e_run "list with descriptions" "${RANO}" --list-presets

e2e_assert_last_status 0
e2e_assert_last_contains "Security review"
e2e_assert_last_contains "Reduce terminal output"
e2e_assert_last_contains "Real-time monitoring"
e2e_assert_last_contains "Maximum detail"
e2e_info "PASS: Preset descriptions are shown"

# Test 8: CLI flags override preset values
e2e_section "Test 8: CLI flags override preset values"
# verbose preset sets stats_interval_ms=1000, override with --stats-interval-ms 5000
# Use verbose instead of quiet since quiet has no_banner=true
e2e_run "cli override" "${RANO}" --preset verbose --pattern nonexistent --once --stats-interval-ms 5000

e2e_assert_last_status 0
# Should show stats=5000ms (overriding verbose's stats_interval_ms=1000)
e2e_assert_last_contains "stats=5000ms"
e2e_info "PASS: CLI flags override preset values"

# Test 9: Multiple presets merge in order
e2e_section "Test 9: Multiple presets merge in order"
# audit sets stats_interval_ms=0, verbose sets it to 1000
# Order: audit then verbose -> verbose wins
e2e_run "merge presets" "${RANO}" --preset audit --preset verbose --pattern nonexistent --once

e2e_assert_last_status 0
# verbose's stats_interval_ms=1000 should win (audit has 0)
e2e_assert_last_contains "stats=1000ms"
e2e_info "PASS: Multiple presets merge in order (later wins)"

# Test 10: Create and load custom user preset
e2e_section "Test 10: Custom user preset"

# Create temporary preset directory
TEMP_PRESET_DIR="$(mktemp -d)"
PRESET_FILE="${TEMP_PRESET_DIR}/custom.conf"
cat > "${PRESET_FILE}" << 'EOF'
# Description: Custom test preset
include_udp=true
stats_interval_ms=3333
EOF
e2e_info "Created custom preset at ${PRESET_FILE}"

# Set HOME to use our custom preset dir
export HOME="${TEMP_PRESET_DIR}"
mkdir -p "${TEMP_PRESET_DIR}/.config/rano/presets"
cp "${PRESET_FILE}" "${TEMP_PRESET_DIR}/.config/rano/presets/custom.conf"

e2e_run "custom preset" "${RANO}" --preset custom --pattern nonexistent --once

e2e_assert_last_status 0
e2e_assert_last_contains "stats=3333ms"
e2e_assert_last_contains "udp=true"
e2e_info "PASS: Custom user preset loads correctly"

# Test 11: Custom preset appears in list
e2e_section "Test 11: Custom preset appears in --list-presets"
e2e_run "list with custom" "${RANO}" --list-presets

e2e_assert_last_status 0
e2e_assert_last_contains "custom"
e2e_assert_last_contains "Custom test preset"
e2e_info "PASS: Custom preset appears in list"

# Summary
e2e_section "Summary"
e2e_info "All E2E preset tests passed"
e2e_info "Tests verified:"
e2e_info "  - --list-presets shows all built-in presets"
e2e_info "  - audit preset loads and runs"
e2e_info "  - quiet preset loads and runs"
e2e_info "  - live preset loads and runs"
e2e_info "  - verbose preset loads and runs"
e2e_info "  - Unknown preset returns helpful error"
e2e_info "  - Preset descriptions are shown"
e2e_info "  - CLI flags override preset values"
e2e_info "  - Multiple presets merge in order"
e2e_info "  - Custom user presets work"
