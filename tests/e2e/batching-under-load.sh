#!/usr/bin/env bash
set -euo pipefail

# This test verifies that rano's SQLite batching correctly handles high-rate events.
# It creates many connections rapidly and validates:
# 1. SQLite contains all events (no data loss under normal load)
# 2. Batch configuration flags work (--db-batch-size, --db-flush-ms, --db-queue-max)
# 3. Event counts match between emitted events and SQLite records

TMP_DIR=$(mktemp -d)
cleanup() {
  # Kill any background processes
  if [ -n "${RANO_PID:-}" ] && kill -0 "${RANO_PID}" 2>/dev/null; then
    kill "${RANO_PID}" 2>/dev/null || true
    wait "${RANO_PID}" 2>/dev/null || true
  fi
  if [ -n "${SERVER_PID:-}" ] && kill -0 "${SERVER_PID}" 2>/dev/null; then
    kill "${SERVER_PID}" 2>/dev/null || true
  fi
  if [ -n "${CLIENT_PID:-}" ] && kill -0 "${CLIENT_PID}" 2>/dev/null; then
    kill "${CLIENT_PID}" 2>/dev/null || true
    wait "${CLIENT_PID}" 2>/dev/null || true
  fi
  e2e_info "Retained batching fixtures: ${TMP_DIR}"
}
trap cleanup EXIT

# Ensure binary is built before test
RANO_BIN="${RANO_BIN:-${E2E_RANO_RELEASE}}"
if [ ! -x "${RANO_BIN}" ]; then
  e2e_section "Building rano"
  cargo build --release --quiet
fi

SQLITE_PATH="${TMP_DIR}/batch-test.sqlite"
LOG_FILE="${TMP_DIR}/rano-output.log"

export E2E_FIXTURES="SQLite at ${SQLITE_PATH}, log at ${LOG_FILE}"

# =============================================================================
# Test configuration
# =============================================================================
CONNECTION_COUNT=50
BATCH_SIZE=10
FLUSH_MS=100
QUEUE_MAX=1000

e2e_section "Test Configuration"
e2e_info "connection_count=${CONNECTION_COUNT}"
e2e_info "db_batch_size=${BATCH_SIZE}"
e2e_info "db_flush_ms=${FLUSH_MS}"
e2e_info "db_queue_max=${QUEUE_MAX}"

# =============================================================================
# Start a test server that accepts connections
# =============================================================================
e2e_section "Starting test server"

SERVER_PORT_FILE="${TMP_DIR}/server_port"
python3 - "${CONNECTION_COUNT}" "${SERVER_PORT_FILE}" "${TMP_DIR}/close-clients" <<'PY' &
import socket
import sys
import time
from pathlib import Path

max_conns = int(sys.argv[1])
port_file = sys.argv[2]

# Create server
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(("127.0.0.1", 0))
server.listen(max_conns + 10)

port = server.getsockname()[1]
with open(port_file, 'w') as f:
    f.write(str(port))

# Accept connections
connections = []
server.settimeout(30)  # Total timeout
try:
    while len(connections) < max_conns:
        try:
            conn, addr = server.accept()
            connections.append(conn)
        except socket.timeout:
            break
except Exception:
    pass

# Keep the actual accepted sockets until the observer confirms the complete batch.
release = Path(sys.argv[3])
deadline = time.monotonic() + 30
while not release.exists():
    if time.monotonic() >= deadline:
        raise RuntimeError('observer did not confirm the held batch before watchdog')
    time.sleep(.02)

# Clean up
for conn in connections:
    try:
        conn.close()
    except:
        pass
server.close()
PY
SERVER_PID=$!

# Wait for server to start and report port
for _ in $(seq 1 50); do
  if [ -s "${SERVER_PORT_FILE}" ]; then
    break
  fi
  sleep 0.1
done

SERVER_PORT=$(cat "${SERVER_PORT_FILE}" 2>/dev/null || echo "")
if [ -z "${SERVER_PORT}" ]; then
  e2e_fail "Failed to get server port"
fi

e2e_info "server_pid=${SERVER_PID}"
e2e_info "server_port=${SERVER_PORT}"

# =============================================================================
# Start rano with batching configuration
# =============================================================================
e2e_section "Starting rano observer"

# Use small batch size and fast flush to exercise batching
HOME="${TMP_DIR}/home" XDG_CONFIG_HOME="${TMP_DIR}/xdg" \
"${RANO_BIN}" \
  --pattern batchtest \
  --no-descendants \
  --interval-ms 50 \
  --sqlite "${SQLITE_PATH}" \
  --db-batch-size "${BATCH_SIZE}" \
  --db-flush-ms "${FLUSH_MS}" \
  --db-queue-max "${QUEUE_MAX}" \
  --json \
  --no-dns \
  --no-banner \
  --stats-interval-ms 0 \
  > "${LOG_FILE}" 2>&1 &
RANO_PID=$!

e2e_info "rano_pid=${RANO_PID}"

# Give rano time to start
sleep 0.5

# =============================================================================
# Create rapid connections (client with "batchtest" in command line)
# =============================================================================
e2e_section "Creating ${CONNECTION_COUNT} connections"

CLIENT_LOG="${TMP_DIR}/client.log"
python3 - "${SERVER_PORT}" "${CONNECTION_COUNT}" batchtest "${TMP_DIR}/close-clients" > "${CLIENT_LOG}" 2>&1 <<'PY' &
import socket
import sys
import time
from pathlib import Path

port = int(sys.argv[1])
count = int(sys.argv[2])
# argv[3] is "batchtest" which helps rano pattern match this process

connections = []
errors = 0

# Create connections as fast as possible
for i in range(count):
    try:
        sock = socket.create_connection(("127.0.0.1", port), timeout=5)
        connections.append(sock)
    except Exception as e:
        errors += 1
        print(f"Connection {i} failed: {e}", file=sys.stderr)

print(f"Created {len(connections)} connections, {errors} errors", flush=True)
if errors or len(connections) != count:
    raise RuntimeError('fixture did not establish the declared batch')

release = Path(sys.argv[4])
deadline = time.monotonic() + 30
while not release.exists():
    if time.monotonic() >= deadline:
        raise RuntimeError('observer did not confirm the held batch before watchdog')
    time.sleep(.02)

# Close all connections
for sock in connections:
    try:
        sock.close()
    except:
        pass

print(f"Closed {len(connections)} connections")
PY
CLIENT_PID=$!

e2e_info "client_pid=${CLIENT_PID}"

# Release only after every held client socket has actually been observed.
observed_connects=0
for _ in $(seq 1 300); do
  observed_connects=$(grep -c '"event":"connect"' "${LOG_FILE}" || true)
  if [ "${observed_connects:-0}" -ge "${CONNECTION_COUNT}" ]; then break; fi
  kill -0 "${CLIENT_PID}" 2>/dev/null || e2e_fail "client exited before full batch observation"
  kill -0 "${RANO_PID}" 2>/dev/null || e2e_fail "monitor exited before full batch observation"
  sleep .1
done
[ "${observed_connects:-0}" -eq "${CONNECTION_COUNT}" ] || e2e_fail "observer did not capture exactly ${CONNECTION_COUNT} held sockets"
touch "${TMP_DIR}/close-clients"
wait "${CLIENT_PID}" || e2e_fail "client failed to release its batch"
unset CLIENT_PID

e2e_section "Client results"
cat "${CLIENT_LOG}"

observed_closes=0
for _ in $(seq 1 300); do
  observed_closes=$(grep -c '"event":"close"' "${LOG_FILE}" || true)
  if [ "${observed_closes:-0}" -ge "${CONNECTION_COUNT}" ]; then break; fi
  kill -0 "${RANO_PID}" 2>/dev/null || e2e_fail "monitor exited before close observation"
  sleep .1
done
[ "${observed_closes:-0}" -eq "${CONNECTION_COUNT}" ] || e2e_fail "observer did not capture exactly ${CONNECTION_COUNT} closes"

# =============================================================================
# Stop rano gracefully
# =============================================================================
e2e_section "Stopping rano"

kill -INT "${RANO_PID}" 2>/dev/null || true
wait "${RANO_PID}" || e2e_fail "monitor reported unsuccessful persistence or observation"
unset RANO_PID

e2e_info "rano stopped"

# =============================================================================
# Analyze rano output
# =============================================================================
e2e_section "Analyzing rano output"

# Count connect/close events from JSON output
json_connects=$(grep -c '"event":"connect"' "${LOG_FILE}" || true)
json_closes=$(grep -c '"event":"close"' "${LOG_FILE}" || true)

e2e_info "json_connects=${json_connects}"
e2e_info "json_closes=${json_closes}"

# Check for summary line (if emitted)
if grep -q '"connects":' "${LOG_FILE}"; then
  summary_line=$(grep '"connects":' "${LOG_FILE}" | tail -1)
  e2e_info "summary=${summary_line}"
fi

# =============================================================================
# Validate SQLite data
# =============================================================================
e2e_section "Validating SQLite data"

if [ ! -f "${SQLITE_PATH}" ]; then
  e2e_fail "SQLite file not created: ${SQLITE_PATH}"
fi

sqlite_total=$(sqlite3 "${SQLITE_PATH}" "SELECT COUNT(*) FROM events" 2>/dev/null || echo "0")
sqlite_connects=$(sqlite3 "${SQLITE_PATH}" "SELECT COUNT(*) FROM events WHERE event='connect'" 2>/dev/null || echo "0")
sqlite_closes=$(sqlite3 "${SQLITE_PATH}" "SELECT COUNT(*) FROM events WHERE event='close'" 2>/dev/null || echo "0")
sqlite_sessions=$(sqlite3 "${SQLITE_PATH}" "SELECT COUNT(*) FROM sessions" 2>/dev/null || echo "0")

e2e_info "sqlite_total=${sqlite_total}"
e2e_info "sqlite_connects=${sqlite_connects}"
e2e_info "sqlite_closes=${sqlite_closes}"
e2e_info "sqlite_sessions=${sqlite_sessions}"

# Check for dropped events in output
dropped=$(grep -o '"sqlite_dropped":[0-9]*' "${LOG_FILE}" | tail -1 | cut -d: -f2 || echo "0")
e2e_info "sqlite_dropped=${dropped:-0}"

# =============================================================================
# Assertions
# =============================================================================
e2e_section "Assertions"

# Session should be recorded
if [ "${sqlite_sessions}" -lt 1 ]; then
  e2e_fail "No session recorded in SQLite"
fi
e2e_info "PASS: Session recorded"

# SQLite should have events
if [ "${sqlite_total}" -lt 1 ]; then
  e2e_fail "No events recorded in SQLite"
fi
e2e_info "PASS: Events recorded (${sqlite_total} total)"

# Durable publication must conserve the exact observed batch; poll timing cannot
# explain disagreement between two sinks for the same already observed event.
[ "${json_connects}" -eq "${CONNECTION_COUNT}" ] && [ "${sqlite_connects}" -eq "${CONNECTION_COUNT}" ] || e2e_fail "connect count mismatch"
[ "${json_closes}" -eq "${CONNECTION_COUNT}" ] && [ "${sqlite_closes}" -eq "${CONNECTION_COUNT}" ] || e2e_fail "close count mismatch"
[ "${sqlite_total}" -eq "$((CONNECTION_COUNT * 2))" ] || e2e_fail "extra or missing durable rows"
e2e_info "PASS: Exact connect/close counts conserved across JSON and SQLite"

# If we have connects, we should also have closes (connections were closed)
if [ "${sqlite_connects}" -gt 0 ] && [ "${sqlite_closes}" -eq 0 ]; then
  e2e_info "WARNING: No close events recorded (connects=${sqlite_connects})"
else
  e2e_info "PASS: Both connect and close events recorded"
fi

# Check batching behavior: run_id should be consistent across events
unique_run_ids=$(sqlite3 "${SQLITE_PATH}" "SELECT COUNT(DISTINCT run_id) FROM events" 2>/dev/null || echo "0")
if [ "${unique_run_ids}" -ne 1 ]; then
  e2e_info "WARNING: Multiple run_ids found (${unique_run_ids}), expected 1"
else
  e2e_info "PASS: All events have consistent run_id"
fi

# =============================================================================
# Test 2: Verify batch size configuration is respected
# =============================================================================
e2e_section "Test 2: Batch size configuration"

# Run rano with --help to verify config flags are recognized
e2e_run "rano batch config help" "${RANO_BIN}" --help

e2e_assert_last_status 0
e2e_assert_last_contains "--db-batch-size"
e2e_assert_last_contains "--db-flush-ms"
e2e_assert_last_contains "--db-queue-max"

# =============================================================================
# Test 3: Verify queue overflow handling (with tiny queue)
# =============================================================================
e2e_section "Test 3: Queue overflow handling"
e2e_info "Testing with very small queue to trigger potential overflow warnings"

TINY_QUEUE_SQLITE="${TMP_DIR}/tiny-queue.sqlite"

# Start a quick rano run with tiny queue settings
HOME="${TMP_DIR}/home" XDG_CONFIG_HOME="${TMP_DIR}/xdg" \
  e2e_run "rano with tiny queue (once mode)" \
  "${RANO_BIN}" \
    --pattern nonexistent_process_pattern \
    --once \
    --sqlite "${TINY_QUEUE_SQLITE}" \
    --db-batch-size 1 \
    --db-flush-ms 50 \
    --db-queue-max 5 \
    --no-dns \
    --no-banner

e2e_assert_last_status 0
e2e_info "PASS: Tiny queue config accepted"

e2e_section "Real persistence accounting and sink-failure matrix"
python3 - "${RANO_BIN}" "${TMP_DIR}" <<'PY' || e2e_fail "persistence matrix failed; inspect retained captures"
import json
import os
import signal
import socket
import sqlite3
import subprocess
import sys
import threading
import time
from pathlib import Path

binary = str(Path(sys.argv[1]).resolve())
root = Path(sys.argv[2]) / 'fault-matrix'
root.mkdir()
holder_code = '''import json,socket,sys
sys.stdin.read(1)
clients=[socket.create_connection(('127.0.0.1',int(sys.argv[1]))) for _ in range(int(sys.argv[2]))]
print(json.dumps({'ready':len(clients)}),flush=True)
sys.stdin.read(1)
for client in clients: client.close()
sys.stdin.read(1)
'''

def records(path):
    return [json.loads(line) for line in path.read_text().splitlines(keepends=True) if line.endswith('\n')]

def until(predicate, monitor, description):
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        if predicate(): return
        assert monitor.poll() is None, f'monitor exited before {description}'
        time.sleep(0.02)
    raise AssertionError(f'no {description}; fixtures retained')

for name in ['normal50', 'abort', 'finalize', 'unavailable_db', 'unavailable_file', 'full_file', 'queue_saturation']:
    case = root / name
    case.mkdir()
    count = 50 if name in ['normal50', 'queue_saturation'] else 1
    database = case / 'events.sqlite'
    seed = subprocess.run([binary, '--no-config', '--pid', str(os.getpid()), '--no-descendants',
        '--once', '--no-banner', '--no-dns', '--json', '--sqlite', str(database)], capture_output=True, text=True)
    (case / 'seed.stdout').write_text(seed.stdout)
    (case / 'seed.stderr').write_text(seed.stderr)
    assert seed.returncode == 0, 'database initialization failed'
    conn = sqlite3.connect(database, timeout=1)
    if name == 'abort':
        conn.execute("CREATE TRIGGER force_abort BEFORE INSERT ON events BEGIN SELECT RAISE(ABORT, 'forced E2E batch failure'); END")
    if name == 'finalize':
        conn.execute("CREATE TRIGGER force_finalize BEFORE UPDATE ON sessions BEGIN SELECT RAISE(ABORT, 'forced E2E finalize failure'); END")
    conn.commit()
    server = socket.socket()
    server.bind(('127.0.0.1', 0)); server.listen(128)
    accepted = []
    def accept_clients():
        for _ in range(count):
            accepted.append(server.accept()[0])
    accept_thread = threading.Thread(target=accept_clients, daemon=True)
    accept_thread.start()
    holder = subprocess.Popen([sys.executable, '-u', '-c', holder_code,
        str(server.getsockname()[1]), str(count)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    monitor = None
    try:
        sqlite_path = '/dev/null/unavailable.sqlite' if name == 'unavailable_db' else str(database)
        file_path = '/dev/full' if name == 'full_file' else str(case / ('missing_parent/file.jsonl' if name == 'unavailable_file' else 'file.jsonl'))
        command = [binary, '--no-config', '--pid', str(holder.pid), '--no-descendants', '--interval-ms', '20',
            '--json', '--no-banner', '--no-dns', '--stats-interval-ms', '0', '--sqlite', sqlite_path,
            '--log-file', file_path, '--log-format', 'json', '--db-batch-size', '1' if name == 'queue_saturation' else '10',
            '--db-flush-ms', '50', '--db-queue-max', '1' if name == 'queue_saturation' else '1000']
        with (case / 'stdout.jsonl').open('w') as stdout, (case / 'stderr').open('w') as stderr:
            monitor = subprocess.Popen(command, stdout=stdout, stderr=stderr)
            if name == 'unavailable_file':
                assert monitor.wait(timeout=20) != 0, 'requested file disappeared silently'
                assert any(row.get('type') == 'error' for row in records(case / 'stdout.jsonl')), 'missing structured file error'
                print(f'  PASS {name}: actionable nonzero startup failure')
                continue
            if name == 'queue_saturation':
                until(lambda: conn.execute('SELECT count(*) FROM sessions').fetchone()[0] >= 2, monitor, 'writer readiness')
                conn.execute('BEGIN IMMEDIATE')
            holder.stdin.write('o'); holder.stdin.flush()
            assert json.loads(holder.stdout.readline())['ready'] == count, 'workload did not progress'
            until(lambda: sum(row.get('event') == 'connect' for row in records(case / 'stdout.jsonl')) == count, monitor, 'all connects')
            holder.stdin.write('c'); holder.stdin.flush()
            until(lambda: sum(row.get('event') == 'close' for row in records(case / 'stdout.jsonl')) == count, monitor, 'all closes')
            monitor.send_signal(signal.SIGINT)
            code = monitor.wait(timeout=20)
        output = records(case / 'stdout.jsonl')
        summary = next(row['summary'] for row in reversed(output) if 'summary' in row)
        accounting = summary['sqlite']
        persisted = conn.execute('SELECT count(*) FROM events').fetchone()[0]
        assert accounting['observed'] == 2 * count, 'incorrect observed denominator'
        assert accounting['persisted'] == persisted, 'invented durable rows'
        assert accounting['observed'] == persisted + accounting['queue_lost'] + accounting['write_lost'], 'unaccounted loss'
        assert summary['sqlite_dropped'] == accounting['queue_lost'] + accounting['write_lost'], 'misreported drop total'
        if name == 'normal50':
            assert code == 0 and persisted == 100 and summary['sqlite_dropped'] == 0, 'normal batching lost events'
            assert not accounting['failed'] and not summary['log_failed'], 'normal sink reported failure'
        else:
            assert code != 0, 'failed sink reported success'
        if name in ['abort', 'unavailable_db']:
            assert persisted == 0 and accounting['write_lost'] == 2 and accounting['failed'], 'failed writes disappeared'
        if name == 'finalize':
            assert persisted == 2 and accounting['failed'] and 'forced E2E finalize failure' in accounting['error'], 'finalization error disappeared'
        if name == 'queue_saturation':
            assert accounting['queue_lost'] > 0 and accounting['failed'], 'queue loss not exercised'
        if name == 'full_file':
            assert persisted == 2 and summary['log_failed'], 'file write error disappeared'
        if name != 'full_file':
            file_output = records(case / 'file.jsonl')
            assert any('summary' in row for row in file_output), 'file summary missing'
        assert (case / 'stderr').read_text(), 'expected domain/sink diagnostics missing'
        print(f'  PASS {name}: observed={2 * count} persisted={persisted} queue_lost={accounting["queue_lost"]} write_lost={accounting["write_lost"]} exit={code}')
    finally:
        if monitor is not None and monitor.poll() is None:
            monitor.send_signal(signal.SIGINT); monitor.wait(timeout=20)
        holder.terminate(); holder.wait(timeout=5)
        conn.rollback(); conn.close()
        server.close()
        for connection in accepted: connection.close()
PY

# =============================================================================
# Summary
# =============================================================================
e2e_section "Summary"
e2e_info "Load test: ${CONNECTION_COUNT} connections"
e2e_info "JSON events: connects=${json_connects}, closes=${json_closes}"
e2e_info "SQLite events: total=${sqlite_total}, connects=${sqlite_connects}, closes=${sqlite_closes}"
e2e_info "Batch config: size=${BATCH_SIZE}, flush_ms=${FLUSH_MS}, queue_max=${QUEUE_MAX}"
e2e_info "Dropped: ${dropped:-0}"

# Final validation: we should have recorded a meaningful number of events
# At minimum 20% of expected connections should be captured
min_expected=$((CONNECTION_COUNT / 5))
if [ "${sqlite_connects}" -lt "${min_expected}" ]; then
  e2e_info "WARNING: Low event capture rate (${sqlite_connects} < ${min_expected} expected minimum)"
  e2e_info "This may indicate timing issues in the test environment"
else
  e2e_info "PASS: Reasonable event capture rate"
fi

e2e_info "All batching tests completed"
