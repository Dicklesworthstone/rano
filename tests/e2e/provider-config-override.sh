#!/usr/bin/env bash
set -euo pipefail

TMP_DIR=$(mktemp -d)
cleanup() {
  if [ -n "${CLIENT_PID:-}" ] && kill -0 "${CLIENT_PID}" 2>/dev/null; then
    kill "${CLIENT_PID}" 2>/dev/null || true
  fi
  if [ -n "${SERVER_PID:-}" ] && kill -0 "${SERVER_PID}" 2>/dev/null; then
    kill "${SERVER_PID}" 2>/dev/null || true
  fi
  rm -rf "${TMP_DIR}"
}
trap cleanup EXIT

CONFIG_PATH="${TMP_DIR}/rano.toml"
cat <<'TOML' > "${CONFIG_PATH}"
[providers]
mode = "replace"
openai = ["probecli"]
TOML

export E2E_FIXTURES="rano.toml override at ${CONFIG_PATH}"

server_port_file="${TMP_DIR}/server_port"
python3 - <<'PY' >"${server_port_file}" 2>"${TMP_DIR}/server.err" &
import socket
import time

s = socket.socket()
s.bind(("127.0.0.1", 0))
s.listen(1)
port = s.getsockname()[1]
print(port, flush=True)
conn, _ = s.accept()
time.sleep(2)
conn.close()
s.close()
PY
SERVER_PID=$!

for _ in $(seq 1 50); do
  if [ -s "${server_port_file}" ]; then
    break
  fi
  sleep 0.1
done

PORT=$(cat "${server_port_file}")
if [ -z "${PORT}" ]; then
  e2e_fail "failed to read server port"
fi

python3 - "${PORT}" probecli <<'PY' &
import socket
import sys
import time

port = int(sys.argv[1])
s = socket.create_connection(("127.0.0.1", port))
time.sleep(2)
s.close()
PY
CLIENT_PID=$!

sleep 0.2

e2e_section "Config"
e2e_info "config_path=${CONFIG_PATH}"
while IFS= read -r line; do
  e2e_info "${line}"
done < "${CONFIG_PATH}"

e2e_section "Expectations"
e2e_info "pattern=probecli"
e2e_info "expected_provider=openai"

HOME="${TMP_DIR}/home" XDG_CONFIG_HOME="${TMP_DIR}/xdg" \
  e2e_run "rano once with provider override" \
  cargo run --quiet -- \
    --pattern probecli \
    --no-descendants \
    --once \
    --json \
    --no-dns \
    --no-sqlite \
    --no-banner \
    --interval-ms 100 \
    --config-toml "${CONFIG_PATH}"

e2e_assert_last_status 0
e2e_assert_last_contains "\"provider\":\"openai\""

e2e_section "Actual provider lines"
if ! grep -n "\"provider\"" "${E2E_LAST_OUTPUT_FILE}"; then
  e2e_info "no provider lines found"
fi
