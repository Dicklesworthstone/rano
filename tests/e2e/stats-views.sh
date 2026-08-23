#!/usr/bin/env bash
set -euo pipefail

RANO_BIN="${RANO_BIN:-${E2E_RANO_RELEASE}}"
if [ ! -x "${RANO_BIN}" ] || [ "src/main.rs" -nt "${RANO_BIN}" ]; then
  e2e_section "Building rano"
  cargo build --release --quiet
fi

run_with_timeout() {
  local duration="$1"
  shift
  if command -v timeout >/dev/null 2>&1; then
    timeout "${duration}" "$@"
    return $?
  fi
  E2E_TIMEOUT="${duration}" python3 - "$@" <<'PY'
import os
import subprocess
import sys
import time

cmd = sys.argv[1:]
if not cmd:
    sys.exit(1)

duration = float(os.environ.get("E2E_TIMEOUT", "0.5"))
proc = subprocess.Popen(cmd)
try:
    time.sleep(duration)
finally:
    proc.terminate()
    try:
        proc.wait(timeout=1)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=1)

sys.exit(0)
PY
}

EXPECTED_STATUS=124
if ! command -v timeout >/dev/null 2>&1; then
  EXPECTED_STATUS=0
fi

VIEW_ARGS=(
  --stats-view provider
  --stats-view domain
  --stats-view port
  --stats-view process
)

e2e_section "Run stats view cycle"
e2e_run "stats views cycle" run_with_timeout 1.0 \
  "${RANO_BIN}" \
  --pattern "no-such-process" \
  --interval-ms 50 \
  --stats-interval-ms 50 \
  --stats-cycle-ms 50 \
  --stats-top 3 \
  --no-color \
  --no-banner \
  "${VIEW_ARGS[@]}"

e2e_assert_last_status "${EXPECTED_STATUS}"

# Ensure all views appeared in output
e2e_assert_last_contains "Live Stats [provider]"
e2e_assert_last_contains "Live Stats [domain]"
e2e_assert_last_contains "Live Stats [port]"
e2e_assert_last_contains "Live Stats [process]"

e2e_section "View sequence sample"
grep -E "^Live Stats \[(provider|domain|port|process)\]" "${E2E_LAST_OUTPUT_FILE}" | head -n 10 | while IFS= read -r line; do
  e2e_info "${line}"
done
