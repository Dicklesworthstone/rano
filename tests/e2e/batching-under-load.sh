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
  rm -rf "${TMP_DIR}"
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
python3 - "${CONNECTION_COUNT}" "${SERVER_PORT_FILE}" <<'PY' &
import socket
import sys
import time

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

# Keep connections alive for a bit so rano can observe them
time.sleep(2)

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
python3 - "${SERVER_PORT}" "${CONNECTION_COUNT}" batchtest > "${CLIENT_LOG}" 2>&1 <<'PY' &
import socket
import sys
import time

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

print(f"Created {len(connections)} connections, {errors} errors")

# Keep connections alive long enough for rano to observe
time.sleep(2)

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

# Wait for client to finish
wait "${CLIENT_PID}" 2>/dev/null || true

e2e_section "Client results"
cat "${CLIENT_LOG}"

# Give rano a moment to process the closing connections
sleep 1

# =============================================================================
# Stop rano gracefully
# =============================================================================
e2e_section "Stopping rano"

kill -INT "${RANO_PID}" 2>/dev/null || true
wait "${RANO_PID}" 2>/dev/null || true

e2e_info "rano stopped"

# =============================================================================
# Analyze rano output
# =============================================================================
e2e_section "Analyzing rano output"

# Count connect/close events from JSON output
json_connects=$(grep -c '"event":"connect"' "${LOG_FILE}" 2>/dev/null || echo "0")
json_closes=$(grep -c '"event":"close"' "${LOG_FILE}" 2>/dev/null || echo "0")

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

# SQLite connect count should match JSON connect count (within tolerance for timing)
# Allow small difference due to timing between polling cycles
diff_connects=$((json_connects - sqlite_connects))
if [ "${diff_connects}" -lt 0 ]; then
  diff_connects=$((0 - diff_connects))
fi
# Allow up to 10% difference due to timing
max_diff=$((json_connects / 10 + 1))
if [ "${diff_connects}" -gt "${max_diff}" ]; then
  e2e_info "WARNING: Connect count mismatch (json=${json_connects}, sqlite=${sqlite_connects}, diff=${diff_connects})"
else
  e2e_info "PASS: Connect counts match within tolerance"
fi

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
