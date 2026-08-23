#!/usr/bin/env bash
set -euo pipefail

E2E_STEP=0
E2E_LAST_OUTPUT_FILE=""
E2E_LAST_STATUS=0
E2E_START_TS=""
E2E_START_EPOCH=0

_e2e_now() {
  date -u +%Y-%m-%dT%H:%M:%SZ
}

_e2e_rano_version() {
  awk -F'"' '/^version/ {print $2; exit}' Cargo.toml 2>/dev/null || echo "unknown"
}

e2e_init() {
  : "${E2E_LOG:?E2E_LOG must be set by runner}"
  : "${E2E_LOG_DIR:?E2E_LOG_DIR must be set by runner}"
  : "${E2E_TEST_NAME:?E2E_TEST_NAME must be set by runner}"
  E2E_START_TS="$(_e2e_now)"
  E2E_START_EPOCH="$(date +%s)"
  export E2E_OUTPUT_DIR="${E2E_LOG_DIR}/outputs"
  mkdir -p "${E2E_OUTPUT_DIR}"

  # Resolve rano binary paths honoring CARGO_TARGET_DIR so hosts with redirected
  # target directories (shared build caches, multi-agent machines) still work.
  if [ -n "${CARGO_TARGET_DIR:-}" ]; then
    E2E_RANO_DEBUG="${CARGO_TARGET_DIR%/}/debug/rano"
    E2E_RANO_RELEASE="${CARGO_TARGET_DIR%/}/release/rano"
  else
    E2E_RANO_DEBUG="./target/debug/rano"
    E2E_RANO_RELEASE="./target/release/rano"
  fi
  export E2E_RANO_DEBUG E2E_RANO_RELEASE
}

e2e_section() {
  echo "== $* =="
}

e2e_info() {
  echo "  $*"
}

e2e_header() {
  e2e_section "E2E Header"
  e2e_info "timestamp=${E2E_START_TS}"
  e2e_info "host=$(hostname)"
  e2e_info "os=$(uname -a)"
  e2e_info "rano_version=$(_e2e_rano_version)"
  e2e_info "test_name=${E2E_TEST_NAME}"
  e2e_info "args=${E2E_ARGS:-}" 
  if [ -n "${E2E_FIXTURES:-}" ]; then
    e2e_info "fixtures=${E2E_FIXTURES}"
  fi
}

_e2e_print_output() {
  local file="$1"
  local max_lines=200
  local head_lines=140
  local tail_lines=40
  local lines
  lines=$(wc -l < "${file}" | tr -d ' ')
  if [ "${lines}" -le "${max_lines}" ]; then
    cat "${file}"
    return
  fi
  head -n "${head_lines}" "${file}"
  echo "... truncated ... (full output: ${file}, lines=${lines})"
  tail -n "${tail_lines}" "${file}"
}

e2e_run() {
  local label="$1"
  shift
  E2E_STEP=$((E2E_STEP + 1))
  local out_file="${E2E_OUTPUT_DIR}/${E2E_TEST_NAME}-step${E2E_STEP}.out"

  e2e_section "RUN ${E2E_STEP}: ${label}"
  e2e_info "cmd=$*"

  set +e
  "$@" >"${out_file}" 2>&1
  local status=$?
  set -e

  E2E_LAST_OUTPUT_FILE="${out_file}"
  E2E_LAST_STATUS=${status}

  e2e_info "status=${status}"
  e2e_info "output (truncated):"
  _e2e_print_output "${out_file}"

  return "${status}"
}

e2e_assert_last_status() {
  local expected="$1"
  e2e_section "ASSERT status"
  e2e_info "expected=${expected}"
  e2e_info "actual=${E2E_LAST_STATUS}"
  if [ "${E2E_LAST_STATUS}" -ne "${expected}" ]; then
    e2e_fail "expected status ${expected}, got ${E2E_LAST_STATUS}"
  fi
}

e2e_assert_last_contains() {
  local needle="$1"
  e2e_section "ASSERT contains"
  e2e_info "expected substring=${needle}"
  if ! grep -Fq -- "${needle}" "${E2E_LAST_OUTPUT_FILE}"; then
    e2e_info "actual output (truncated):"
    _e2e_print_output "${E2E_LAST_OUTPUT_FILE}"
    e2e_fail "output missing expected substring"
  fi
}

e2e_assert_last_regex() {
  local pattern="$1"
  e2e_section "ASSERT regex"
  e2e_info "expected pattern=${pattern}"
  if ! grep -Eq -- "${pattern}" "${E2E_LAST_OUTPUT_FILE}"; then
    e2e_info "actual output (truncated):"
    _e2e_print_output "${E2E_LAST_OUTPUT_FILE}"
    e2e_fail "output missing expected regex"
  fi
}

e2e_assert_last_eq() {
  local expected="$1"
  local expected_file
  expected_file=$(mktemp)
  printf '%s' "${expected}" >"${expected_file}"

  e2e_section "ASSERT equals"
  if ! diff -u "${expected_file}" "${E2E_LAST_OUTPUT_FILE}"; then
    e2e_info "actual output (truncated):"
    _e2e_print_output "${E2E_LAST_OUTPUT_FILE}"
    rm -f "${expected_file}"
    e2e_fail "output did not match expected"
  fi
  rm -f "${expected_file}"
}

e2e_pass() {
  e2e_section "E2E PASS"
  e2e_info "log=${E2E_LOG}"
  e2e_info "duration_seconds=$(( $(date +%s) - ${E2E_START_EPOCH} ))"
}

e2e_fail() {
  local reason="$1"
  e2e_section "E2E FAIL"
  e2e_info "reason=${reason}"
  e2e_info "log=${E2E_LOG}"
  exit 1
}
