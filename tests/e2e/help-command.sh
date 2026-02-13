#!/usr/bin/env bash
set -euo pipefail

RANO_BIN="${RANO_BIN:-./target/debug/rano}"
if [ ! -x "${RANO_BIN}" ]; then
  e2e_section "Building rano"
  cargo build --quiet
fi

e2e_section "Test 1: top-level help lists implemented commands"
e2e_run "rano --help" "${RANO_BIN}" --help
e2e_assert_last_status 0

for usage in \
  "rano report [options]" \
  "rano export [options]" \
  "rano diff --old <id> --new <id> [options]" \
  "rano status [options]" \
  "rano config <subcommand>" \
  "rano update [options]"
do
  e2e_assert_last_contains "${usage}"
done

for command in "  report" "  export" "  diff" "  status" "  config" "  update"
do
  e2e_assert_last_contains "${command}"
done

e2e_section "Test 2: subcommand help entrypoints"

e2e_run "rano report --help" "${RANO_BIN}" report --help
e2e_assert_last_status 0
e2e_assert_last_contains "rano report - query SQLite event history"
e2e_assert_last_contains "USAGE:"

e2e_run "rano export --help" "${RANO_BIN}" export --help
e2e_assert_last_status 0
e2e_assert_last_contains "rano export - export SQLite event history"
e2e_assert_last_contains "USAGE:"

e2e_run "rano diff --help" "${RANO_BIN}" diff --help
e2e_assert_last_status 0
e2e_assert_last_contains "rano diff - compare two monitoring sessions"
e2e_assert_last_contains "--old <id>"
e2e_assert_last_contains "--new <id>"

e2e_run "rano status --help" "${RANO_BIN}" status --help
e2e_assert_last_status 0
e2e_assert_last_contains "rano status - one-line status for shell prompt integration"
e2e_assert_last_contains "USAGE:"

e2e_run "rano config --help" "${RANO_BIN}" config --help
e2e_assert_last_status 0
e2e_assert_last_contains "rano config - validate and inspect configuration"
e2e_assert_last_contains "SUBCOMMANDS:"

e2e_run "rano update --help" "${RANO_BIN}" update --help
e2e_assert_last_status 0
e2e_assert_last_contains "rano update - update the binary"
e2e_assert_last_contains "USAGE:"
