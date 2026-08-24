#!/usr/bin/env bash
# E2E Test: pcap attribution + fallback logging
#
# Verifies:
# - Offline pcap fixtures can drive domain attribution in --pcap mode
# - Privilege failure in pcap mode logs warnings and falls back to PTR
# - Logs include fixture path, expected domains, actual domains, and warnings

set -euo pipefail

RANO="${RANO:-${E2E_RANO_DEBUG}}"
FIXTURE_DIR="tests/fixtures/pcap"
PCAP_FIXTURE="${FIXTURE_DIR}/dns-fixture.pcap"
SERVER_PORT=18080

SERVER_PID=""
CLIENT_PID=""

cleanup() {
  if [ -n "${CLIENT_PID}" ] && kill -0 "${CLIENT_PID}" 2>/dev/null; then
    kill "${CLIENT_PID}" 2>/dev/null || true
  fi
  if [ -n "${SERVER_PID}" ] && kill -0 "${SERVER_PID}" 2>/dev/null; then
    kill "${SERVER_PID}" 2>/dev/null || true
  fi
}
trap cleanup EXIT

export E2E_FIXTURES="${PCAP_FIXTURE}"

e2e_section "Setup"
e2e_info "rano=${RANO}"
e2e_info "pcap_fixture=${PCAP_FIXTURE}"
e2e_info "server_port=${SERVER_PORT}"

if [ ! -x "${RANO}" ]; then
  e2e_fail "rano binary not found at ${RANO}. Build with: cargo build --features pcap"
fi

if [ ! -f "${PCAP_FIXTURE}" ]; then
  e2e_fail "pcap fixture missing at ${PCAP_FIXTURE}"
fi

# Start local HTTP server
python3 -m http.server "${SERVER_PORT}" --bind 127.0.0.1 >/dev/null 2>&1 &
SERVER_PID=$!
sleep 0.2

# Start client that keeps a connection open
python3 - <<'PY' "${SERVER_PORT}" &
import socket
import sys
import time

port = int(sys.argv[1])
sock = socket.socket()
sock.connect(("127.0.0.1", port))
time.sleep(3)
PY
CLIENT_PID=$!

sleep 0.2

# Test 1: Offline pcap attribution
EXPECTED_DOMAIN="fixture.test"

e2e_run "pcap attribution" env RANO_PCAP_FILE="${PCAP_FIXTURE}" \
  "${RANO}" --pid "${CLIENT_PID}" --no-descendants --once --json --no-banner --stats-interval-ms 0 --pcap

e2e_assert_last_status 0
e2e_assert_last_contains "\"domain\":\"${EXPECTED_DOMAIN}\""
e2e_assert_last_contains "\"domain_source\":\"dns\""
e2e_assert_last_contains "\"domain_mode\":\"pcap\""

ATTR_OUTPUT="${E2E_LAST_OUTPUT_FILE}"
ACTUAL_DOMAINS=$(python3 - <<'PY' "${ATTR_OUTPUT}"
import json
import sys

path = sys.argv[1]
domains = set()
with open(path, "r", encoding="utf-8") as handle:
    for line in handle:
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        obj = json.loads(line)
        if "event" in obj:
            value = obj.get("domain")
            if value:
                domains.add(value)
print(",".join(sorted(domains)))
PY
)

e2e_info "expected_domains=${EXPECTED_DOMAIN}"
e2e_info "actual_domains=${ACTUAL_DOMAINS}"

# Test 2: Privilege failure -> warning + PTR fallback

e2e_run "pcap privilege fallback" \
  "${RANO}" --pattern "nonexistent-process-xyz" --once --json --no-banner --stats-interval-ms 0 --pcap

e2e_assert_last_status 0
if grep -Fq "pcap feature not enabled" "${E2E_LAST_OUTPUT_FILE}"; then
  e2e_fail "pcap feature not enabled. Build with: cargo build --features pcap"
fi

e2e_assert_last_contains "\"domain_mode\":\"ptr\""
e2e_assert_last_contains "warning: pcap capture unavailable"
e2e_assert_last_contains "pcap capture requires elevated privileges"

FALLBACK_WARNINGS=$(grep -F "warning: pcap" "${E2E_LAST_OUTPUT_FILE}" | tr '\n' ';')
e2e_info "fallback_warnings=${FALLBACK_WARNINGS}"

# Summary

e2e_section "Summary"
e2e_info "pcap attribution verified via offline fixture"
e2e_info "pcap fallback warnings verified"
