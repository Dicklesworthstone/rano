#!/usr/bin/env bash
# E2E Test: Config Validation
# Tests the configuration validation system
#
# This test verifies:
# - 'rano config check' validates config files
# - Valid config files pass validation
# - Unknown keys produce warnings
# - Invalid values produce errors
# - Invalid TOML produces errors
# - 'rano config show' displays resolved config
# - 'rano config paths' lists correct paths
#
# Prerequisites:
# - rano binary built (cargo build)

set -euo pipefail

RANO="${RANO:-${E2E_RANO_DEBUG}}"
TEMP_CONFIG_DIR=""
ORIGINAL_HOME="${HOME}"

# Cleanup on exit
cleanup() {
    if [ -n "${TEMP_CONFIG_DIR}" ] && [ -d "${TEMP_CONFIG_DIR}" ]; then
        rm -rf "${TEMP_CONFIG_DIR}"
    fi
    export HOME="${ORIGINAL_HOME}"
}
trap cleanup EXIT

e2e_section "Setup"
e2e_info "rano=${RANO}"

# Ensure rano binary exists
if [ ! -x "${RANO}" ]; then
    e2e_fail "rano binary not found at ${RANO}. Run 'cargo build' first."
fi

# Create temporary config directory
TEMP_CONFIG_DIR="$(mktemp -d)"
export HOME="${TEMP_CONFIG_DIR}"
mkdir -p "${TEMP_CONFIG_DIR}/.config/rano/presets"
e2e_info "temp_config_dir=${TEMP_CONFIG_DIR}"

# Test 1: Valid config file passes validation
e2e_section "Test 1: Valid config file passes validation"

cat > "${TEMP_CONFIG_DIR}/.config/rano/config.conf" << 'EOF'
# Valid configuration
pattern=claude,codex
interval_ms=1000
json=false
no_banner=true
stats_interval_ms=2000
stats_view=provider,domain
EOF
e2e_info "Created valid config at ${TEMP_CONFIG_DIR}/.config/rano/config.conf"

e2e_run "check valid config" "${RANO}" config check

e2e_assert_last_status 0
e2e_assert_last_contains "Configuration is valid"
e2e_info "PASS: Valid config passes validation"

# Test 2: Unknown key produces warning
e2e_section "Test 2: Unknown key produces warning"

cat > "${TEMP_CONFIG_DIR}/.config/rano/config.conf" << 'EOF'
pattern=claude
unknwon_typo=value
interval_ms=1000
EOF

e2e_run "check unknown key" "${RANO}" config check

# Should succeed but with warnings
e2e_assert_last_status 0
e2e_assert_last_contains "warning"
e2e_assert_last_contains "unknown key"
e2e_assert_last_contains "unknwon_typo"
e2e_info "PASS: Unknown key produces warning"

# Test 3: Invalid number produces error
e2e_section "Test 3: Invalid number produces error"

cat > "${TEMP_CONFIG_DIR}/.config/rano/config.conf" << 'EOF'
interval_ms=not_a_number
EOF

e2e_run "check invalid number" "${RANO}" config check || true

# Should fail with error
if [ "${E2E_LAST_STATUS}" -eq 0 ]; then
    e2e_fail "Expected error for invalid number, but got success"
fi
e2e_assert_last_contains "error"
e2e_assert_last_contains "integer"
e2e_info "PASS: Invalid number produces error"

# Test 4: Invalid boolean produces error
e2e_section "Test 4: Invalid boolean produces error"

cat > "${TEMP_CONFIG_DIR}/.config/rano/config.conf" << 'EOF'
json=maybe
EOF

e2e_run "check invalid boolean" "${RANO}" config check || true

# Should fail with error
if [ "${E2E_LAST_STATUS}" -eq 0 ]; then
    e2e_fail "Expected error for invalid boolean, but got success"
fi
e2e_assert_last_contains "error"
e2e_assert_last_contains "boolean"
e2e_info "PASS: Invalid boolean produces error"

# Test 5: Invalid enum value produces error
e2e_section "Test 5: Invalid enum value produces error"

cat > "${TEMP_CONFIG_DIR}/.config/rano/config.conf" << 'EOF'
domain_mode=invalid_mode
EOF

e2e_run "check invalid enum" "${RANO}" config check || true

# Should fail with error
if [ "${E2E_LAST_STATUS}" -eq 0 ]; then
    e2e_fail "Expected error for invalid enum, but got success"
fi
e2e_assert_last_contains "error"
e2e_assert_last_contains "auto, ptr, pcap"
e2e_info "PASS: Invalid enum value produces error"

# Test 6: Invalid TOML produces error
e2e_section "Test 6: Invalid TOML produces error"

# Remove the conf file first
rm -f "${TEMP_CONFIG_DIR}/.config/rano/config.conf"

# Create invalid TOML
cat > "${TEMP_CONFIG_DIR}/.config/rano/rano.toml" << 'EOF'
[providers
mode = "merge"
invalid toml syntax {{{{
EOF

e2e_run "check invalid toml" "${RANO}" config check || true

# Should fail with error
if [ "${E2E_LAST_STATUS}" -eq 0 ]; then
    e2e_fail "Expected error for invalid TOML, but got success"
fi
e2e_assert_last_contains "error"
e2e_assert_last_contains "TOML"
e2e_info "PASS: Invalid TOML produces error"

# Test 7: Valid TOML passes validation
e2e_section "Test 7: Valid TOML passes validation"

cat > "${TEMP_CONFIG_DIR}/.config/rano/rano.toml" << 'EOF'
[providers]
mode = "merge"
anthropic = ["claude", "acme-claude"]
openai = ["codex"]
EOF

e2e_run "check valid toml" "${RANO}" config check

e2e_assert_last_status 0
e2e_assert_last_contains "valid"
e2e_info "PASS: Valid TOML passes validation"

# Test 8: 'config show' displays resolved config
e2e_section "Test 8: config show displays resolved config"

cat > "${TEMP_CONFIG_DIR}/.config/rano/config.conf" << 'EOF'
pattern=test-pattern
interval_ms=500
EOF

e2e_run "config show" "${RANO}" config show

e2e_assert_last_status 0
e2e_assert_last_contains "pattern"
e2e_assert_last_contains "test-pattern"
e2e_assert_last_contains "interval_ms"
e2e_assert_last_contains "500"
e2e_info "PASS: config show displays resolved config"

# Test 9: 'config show --json' outputs JSON
e2e_section "Test 9: config show --json outputs JSON"

e2e_run "config show json" "${RANO}" config show --json

e2e_assert_last_status 0
e2e_assert_last_contains "{"
e2e_assert_last_contains "}"
e2e_assert_last_contains "pattern"
e2e_info "PASS: config show --json outputs JSON"

# Test 10: 'config paths' lists search locations
e2e_section "Test 10: config paths lists search locations"

e2e_run "config paths" "${RANO}" config paths

e2e_assert_last_status 0
e2e_assert_last_contains "config.conf"
e2e_assert_last_contains "rano.toml"
e2e_assert_last_contains ".config/rano"
e2e_info "PASS: config paths lists search locations"

# Test 11: Invalid stats_view value produces error
e2e_section "Test 11: Invalid stats_view value produces error"

cat > "${TEMP_CONFIG_DIR}/.config/rano/config.conf" << 'EOF'
stats_view=provider,invalid_view
EOF

e2e_run "check invalid stats_view" "${RANO}" config check || true

# Should fail with error
if [ "${E2E_LAST_STATUS}" -eq 0 ]; then
    e2e_fail "Expected error for invalid stats_view, but got success"
fi
e2e_assert_last_contains "error"
e2e_assert_last_contains "invalid value"
e2e_info "PASS: Invalid stats_view value produces error"

# Test 12: Zero value for db_batch_size produces error
e2e_section "Test 12: Zero value for required positive integer produces error"

cat > "${TEMP_CONFIG_DIR}/.config/rano/config.conf" << 'EOF'
db_batch_size=0
EOF

e2e_run "check zero db_batch_size" "${RANO}" config check || true

# Should fail with error
if [ "${E2E_LAST_STATUS}" -eq 0 ]; then
    e2e_fail "Expected error for zero db_batch_size, but got success"
fi
e2e_assert_last_contains "error"
e2e_assert_last_contains ">= 1"
e2e_info "PASS: Zero value for required positive integer produces error"

# Test 13: Invalid TOML provider mode produces error
e2e_section "Test 13: Invalid TOML provider mode produces error"

rm -f "${TEMP_CONFIG_DIR}/.config/rano/config.conf"
cat > "${TEMP_CONFIG_DIR}/.config/rano/rano.toml" << 'EOF'
[providers]
mode = "invalid_mode"
EOF

e2e_run "check invalid provider mode" "${RANO}" config check || true

# Should fail with error
if [ "${E2E_LAST_STATUS}" -eq 0 ]; then
    e2e_fail "Expected error for invalid provider mode, but got success"
fi
e2e_assert_last_contains "error"
e2e_assert_last_contains "merge, replace"
e2e_info "PASS: Invalid TOML provider mode produces error"

# Summary
e2e_section "Summary"
e2e_info "All E2E config validation tests passed"
e2e_info "Tests verified:"
e2e_info "  - Valid config passes validation"
e2e_info "  - Unknown key produces warning"
e2e_info "  - Invalid number produces error"
e2e_info "  - Invalid boolean produces error"
e2e_info "  - Invalid enum value produces error"
e2e_info "  - Invalid TOML produces error"
e2e_info "  - Valid TOML passes validation"
e2e_info "  - config show displays resolved config"
e2e_info "  - config show --json outputs JSON"
e2e_info "  - config paths lists search locations"
e2e_info "  - Invalid stats_view value produces error"
e2e_info "  - Zero value for required positive integer produces error"
e2e_info "  - Invalid TOML provider mode produces error"
