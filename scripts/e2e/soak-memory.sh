#!/usr/bin/env bash
# E2E Test: Long-session memory soak (bounded RSS, zero event drops)
#
# Runs an accelerated rano session (default 10 minutes at --interval-ms 100)
# while a helper churns short-lived connections. RSS is sampled every 5 s.
#
# Assertions:
# - final RSS < 2x the RSS after the first minute (bounded growth)
# - summary reports sqlite_dropped == 0 at default queue sizes
#
# Env knobs: SOAK_SECS (default 600), SOAK_RANO (binary path)

set -euo pipefail

SOAK_SECS="${SOAK_SECS:-600}"
SAMPLE_EVERY=5          # seconds between RSS samples
MARK_AT=60              # "peak-after-minute" reference point

RANO="${RANO:-${E2E_RANO_DEBUG}}"
TEST_SQLITE="/tmp/rano-e2e-soak-$$.sqlite"
TEST_LOG="/tmp/rano-e2e-soak-$$.log"
PORT="${SOAK_PORT:-18234}"

cleanup() {
    pkill -f "rano_soak_churn ${TMP_SOAK}" 2>/dev/null || true
    rm -f "${TEST_SQLITE}" "${TEST_LOG}"
}

e2e_section "Setup"
e2e_info "rano=${RANO}"
e2e_info "soak_secs=${SOAK_SECS}"

if [ ! -x "${RANO}" ]; then
    e2e_fail "rano binary not found at ${RANO}. Run 'cargo build' first."
fi

TMP_SOAK=$(mktemp -d /tmp/rano-soak.XXXXXX)
trap cleanup EXIT

cat > "${TMP_SOAK}/churn.py" <<'PY'
import socket, sys, time
port = int(sys.argv[1])
duration = float(sys.argv[2])
srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", port))
srv.listen(1024)
deadline = time.time() + duration
socks = []
while time.time() < deadline:
    c = socket.socket()
    try:
        c.connect(("127.0.0.1", port))
    except OSError:
        pass
    socks.append(c)
    if len(socks) > 32:
        socks.pop(0).close()
    time.sleep(0.02)
for s in socks:
    try: s.close()
    except OSError: pass
srv.close()
PY

python3 "${TMP_SOAK}/churn.py" "${PORT}" "$((SOAK_SECS + 10))" &
CHURN_PID=$!

env RANO_SOAK_CHURN="${TMP_SOAK}" "${RANO}" \
    --pid "${CHURN_PID}" --no-descendants --interval-ms 100 \
    --sqlite "${TEST_SQLITE}" --log-format json --log-file "${TEST_LOG}" \
    --json --stats-interval-ms 10000 > "${TEST_LOG}.stdout" 2>&1 &
RANO_PID=$!

RSS_SAMPLES=()
ELAPSED=0
sleep 2
while kill -0 "${RANO_PID}" 2>/dev/null && [ "${ELAPSED}" -lt "${SOAK_SECS}" ]; do
    sleep "${SAMPLE_EVERY}"
    ELAPSED=$((ELAPSED + SAMPLE_EVERY))
    RSS_KB=$(ps -o rss= -p "${RANO_PID}" 2>/dev/null | tr -d ' ' || echo 0)
    RSS_SAMPLES+=("${ELAPSED}:${RSS_KB:-0}")
done

kill "${RANO_PID}" 2>/dev/null || true
wait "${RANO_PID}" 2>/dev/null || true
pkill -f "rano_soak_churn ${TMP_SOAK}" 2>/dev/null || true

e2e_info "rss_samples_kb=${RSS_SAMPLES[*]}"

# Reference: first sample at/after MARK_AT seconds.
BASELINE=""
for sample in "${RSS_SAMPLES[@]}"; do
    t=${sample%%:*}
    if [ "${t}" -ge "${MARK_AT}" ]; then BASELINE=${sample##*:}; break; fi
done
if [ -z "${BASELINE}" ] || [ "${BASELINE}" = "0" ]; then
    # Short runs (smoke): fall back to earliest sample.
    BASELINE=${RSS_SAMPLES[0]##*:}
fi

FINAL=${RSS_SAMPLES[-1]##*:}
PEAK=0
for sample in "${RSS_SAMPLES[@]}"; do
    kb=${sample##*:}
    if [ "${kb}" -gt "${PEAK}" ]; then PEAK=${kb}; fi
done

e2e_info "baseline_rss_kb=${BASELINE} final_rss_kb=${FINAL} peak_rss_kb=${PEAK}"
LIMIT=$(( BASELINE * 2 ))
if [ "${FINAL}" -gt "${LIMIT}" ]; then
    e2e_fail "final RSS ${FINAL}KB exceeds 2x baseline ${BASELINE}KB (limit ${LIMIT}KB)"
fi

# Zero durable drops at default queue sizes.
DROPPED=$(grep -o '"sqlite_dropped":[0-9]*' "${TEST_LOG}.stdout" | tail -1 | cut -d: -f2 || echo 0)
DROPPED=${DROPPED:-0}
e2e_info "sqlite_dropped=${DROPPED}"
if [ "${DROPPED}" != "0" ]; then
    e2e_fail "event drops observed: sqlite_dropped=${DROPPED}"
fi

ROWS=$(sqlite3 "${TEST_SQLITE}" "SELECT COUNT(*) FROM events;" 2>/dev/null || echo 0)
e2e_info "total_events=${ROWS}"

e2e_section "Summary"
e2e_info "bounded RSS verified: final=${FINAL}KB <= 2x baseline(${BASELINE}KB)"
e2e_info "zero event drops over ${ELAPSED}s accelerated session (${ROWS} events)"
