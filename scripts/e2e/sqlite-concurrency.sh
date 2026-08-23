#!/usr/bin/env bash
# E2E Test: SQLite concurrent reader/writer access
#
# Verifies that read-side commands (status, report) succeed while the monitor
# is actively writing events. busy_timeout (PRAGMA on every connection) must
# turn transient SQLITE_BUSY into bounded waits instead of errors.
#
# Regression guard for: "SQLite file is locked" documented as unavoidable in
# README Troubleshooting; shell-prompt status usage dying under load.

set -euo pipefail

RANO="${RANO:-${E2E_RANO_DEBUG:-./target/debug/rano}}"
TEST_SQLITE="/tmp/rano-e2e-conc-$$.sqlite"
STATUS_RUNS=25

cleanup() {
    [ -n "${WRITER_PID:-}" ] && kill "${WRITER_PID}" 2>/dev/null || true
    [ -n "${TRAFFIC_PID:-}" ] && kill "${TRAFFIC_PID}" 2>/dev/null || true
    rm -f "${TEST_SQLITE}"
}
trap cleanup EXIT

if [ ! -x "${RANO}" ]; then
    e2e_fail "rano binary not found at ${RANO}. Run 'cargo build' first."
fi

e2e_section "Setup"
e2e_info "rano=${RANO}"

# Local listener + client holding connections so the writer has real events.
python3 - <<'PY' &
import socket, threading, time
servers = []
for p in (18401, 18402):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", p))
    s.listen(16)
    servers.append(s)
def hold(c):
    try:
        time.sleep(0.4); c.close()
    except OSError:
        pass
def acc(s):
    while True:
        try:
            c, _ = s.accept()
        except OSError:
            return
        threading.Thread(target=hold, args=(c,), daemon=True).start()
for s in servers:
    threading.Thread(target=acc, args=(s,), daemon=True).start()
time.sleep(8)
PY
TRAFFIC_BASE=$!

sleep 0.3

# Churn connections so the writer thread stays busy.
python3 - <<'PY' &
import socket, time
end = time.time() + 7
while time.time() < end:
    conns = []
    for p in (18401, 18402):
        try:
            conns.append(socket.create_connection(("127.0.0.1", p)))
        except OSError:
            pass
    time.sleep(0.15)
    for c in conns:
        try: c.close()
        except OSError: pass
PY
TRAFFIC_PID=$!

"${RANO}" --pattern python3 --interval-ms 100 \
    --sqlite "${TEST_SQLITE}" --no-banner --stats-interval-ms 0 \
    > /dev/null 2>"${TEST_SQLITE}.writer.err" &
WRITER_PID=$!

sleep 1.5

e2e_section "Concurrent readers"
lock_errors=0
for i in $(seq 1 ${STATUS_RUNS}); do
    if ! out=$("${RANO}" status --sqlite "${TEST_SQLITE}" 2>&1); then
        lock_errors=$((lock_errors+1))
        e2e_info "status run ${i} FAILED: ${out}"
    fi
    case "${out}" in
        *locked*|*busy*) lock_errors=$((lock_errors+1)); e2e_info "run ${i} lock text: ${out}" ;;
    esac
done
if [ "${lock_errors}" -ne 0 ]; then
    e2e_fail "${lock_errors}/${STATUS_RUNS} concurrent status reads failed"
fi
e2e_info "PASS: ${STATUS_RUNS}/${STATUS_RUNS} concurrent status reads succeeded"

for i in 1 2 3; do
    e2e_run "report during writes (${i})" "${RANO}" report --latest --sqlite "${TEST_SQLITE}"
    e2e_assert_last_status 0
done

kill -INT "${WRITER_PID}" 2>/dev/null || true
wait "${WRITER_PID}" 2>/dev/null || true
unset WRITER_PID

if grep -qiE "locked|busy|disabled" "${TEST_SQLITE}.writer.err" 2>/dev/null; then
    e2e_fail "writer reported lock/disabled errors: $(cat "${TEST_SQLITE}.writer.err")"
fi

events=$(sqlite3 "${TEST_SQLITE}" "SELECT COUNT(*) FROM events;" 2>/dev/null || echo 0)
e2e_info "events_written=${events}"
if [ "${events}" -eq 0 ]; then
    e2e_fail "expected writer to persist events during concurrent reads"
fi

e2e_section "Summary"
e2e_info "All SQLite concurrency tests passed"
