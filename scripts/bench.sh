#!/usr/bin/env bash
# Performance baseline harness for rano
#
# Measures two pillars of the "low overhead" design claim:
#   A. Full /proc scan + attribution pass latency with 500 / 2000 live
#      connections held open by the tracked process.
#   B. Durable SQLite event throughput (rows/sec observed end-to-end) at
#      --db-batch-size 200 vs 1000 under connection churn.
#
# Usage: scripts/bench.sh [path-to-rano]
# Results are printed as a markdown table fragment (meant for docs/perf.md).

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
RANO="${1:-${RANO_BIN:-}}"
if [ -z "${RANO}" ]; then
  if [ -x "${SCRIPT_DIR}/../target/release/rano" ]; then
    RANO="${SCRIPT_DIR}/../target/release/rano"
  else
    RANO="${SCRIPT_DIR}/../target/debug/rano"
  fi
fi

PASSES="${BENCH_PASSES:-30}"
CHURN_SECS="${BENCH_CHURN_SECS:-8}"
PORT_BASE="${BENCH_PORT_BASE:-18110}"

if [ ! -x "${RANO}" ]; then
  echo "rano binary not found at ${RANO}; build first (cargo build --release)" >&2
  exit 1
fi

TMPDIR_BENCH=$(mktemp -d /tmp/rano-bench.XXXXXX)
cleanup() {
  pkill -f "rano_bench_holder ${TMPDIR_BENCH}" 2>/dev/null || true
  rm -rf "${TMPDIR_BENCH}"
}
trap cleanup EXIT

cat > "${TMPDIR_BENCH}/holder.py" <<'PY'
import socket, sys, threading, time
mode = sys.argv[1]          # hold | churn
count = int(sys.argv[2])    # connection count
port = int(sys.argv[3])
duration = float(sys.argv[4])
socks = []
srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", port))
srv.listen(4096)

def accepter():
    srv.settimeout(0.5)
    while True:
        try:
            conn, _ = srv.accept()
            socks.append(conn)
        except socket.timeout:
            pass
        except OSError:
            return

threading.Thread(target=accepter, daemon=True).start()

if mode == "hold":
    for _ in range(count):
        c = socket.socket()
        c.connect(("127.0.0.1", port))
        socks.append(c)
    time.sleep(duration)
else:
    deadline = time.time() + duration
    while time.time() < deadline:
        c = socket.socket()
        c.connect(("127.0.0.1", port))
        if len(socks) > 64:
            old = socks.pop(0)
            try:
                old.close()
            except OSError:
                pass
        time.sleep(0.002)
for s in socks:
    s.close()
srv.close()
PY

start_holder() {
  local mode=$1 count=$2 port=$3 duration=$4
  python3 "${TMPDIR_BENCH}/holder.py" "${mode}" "${count}" "${port}" "${duration}" &
  echo $!
}

echo "| Metric | Value |"
echo "|--------|-------|"

for CONNS in 500 2000; do
  PORT=$((PORT_BASE + CONNS % 97))
  HOLDER=$(start_holder hold "${CONNS}" "${PORT}" 120)
  sleep 1.5   # let all connections establish

  # Warm-up
  "${RANO}" --pid "${HOLDER}" --no-descendants --once --no-banner >/dev/null 2>&1 || true

  TOTAL_MS=0
  for _ in $(seq 1 "${PASSES}"); do
    START=$(date +%s%N)
    "${RANO}" --pid "${HOLDER}" --no-descendants --once --no-banner >/dev/null 2>&1 || true
    END=$(date +%s%N)
    TOTAL_MS=$(( TOTAL_MS + (END - START) / 1000000 ))
  done
  MEAN_US=$(( (TOTAL_MS * 1000) / PASSES ))
  echo "| /proc scan+attribution pass (${CONNS} conns, n=${PASSES}) | ${MEAN_US} us/pass (mean) |"
  kill "${HOLDER}" 2>/dev/null || true
  wait "${HOLDER}" 2>/dev/null || true
done

for BATCH in 200 1000; do
  PORT=$((PORT_BASE + BATCH % 89 + 7))
  DB="${TMPDIR_BENCH}/bench-${BATCH}.sqlite"
  HOLDER=$(start_holder churn 32 "${PORT}" "${CHURN_SECS}")
  sleep 0.3
  START_NS=$(date +%s%N)
  "${RANO}" --pid "${HOLDER}" --no-descendants --interval-ms 20 \
    --db-batch-size "${BATCH}" --sqlite "${DB}" --no-banner --json \
    --stats-interval-ms 0 > "${TMPDIR_BENCH}/out-${BATCH}.jsonl" 2>&1 || true
  wait "${HOLDER}" 2>/dev/null || true
  END_NS=$(date +%s%N)

  ELAPSED_MS=$(( (END_NS - START_NS) / 1000000 ))
  ROWS=$(sqlite3 "${DB}" "SELECT COUNT(*) FROM events;" 2>/dev/null || echo 0)
  if [ "${ELAPSED_MS}" -gt 0 ] && [ "${ROWS}" != "0" ]; then
    RATE=$(( ROWS * 1000 / ELAPSED_MS ))
    echo "| Durable insert throughput (batch=${BATCH}, ${ELAPSED_MS}ms window) | ${RATE} events/s (${ROWS} rows) |"
  else
    echo "| Durable insert throughput (batch=${BATCH}) | no rows captured |"
  fi
  rm -f "${DB}"
done
