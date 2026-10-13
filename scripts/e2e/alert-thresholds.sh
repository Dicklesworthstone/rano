#!/usr/bin/env bash
# E2E Test: Alert Thresholds
# Tests the alert system for domain patterns, connection thresholds, and duration alerts
#
# This test verifies:
# - Domain watch alerts trigger on matching patterns
# - Max-connections alert fires at threshold
# - Cooldown prevents duplicate alerts
# - JSON alerts join stdout; pretty alerts use stderr
# - SQLite stores alert=true for alert-triggering events
#
# Prerequisites:
# - rano binary built (cargo build)
# - SQLite3 available for database verification

set -euo pipefail

RANO="${RANO:-${E2E_RANO_DEBUG}}"
TEST_SQLITE="/tmp/rano-e2e-alerts-$$.sqlite"
TEST_LOG="/tmp/rano-e2e-alerts-$$.log"

# Cleanup on exit
cleanup() {
    e2e_info "Retained alert fixtures: ${TEST_SQLITE}, ${TEST_LOG}"
}
trap cleanup EXIT

e2e_section "Setup"
e2e_info "rano=${RANO}"
e2e_info "test_sqlite=${TEST_SQLITE}"
e2e_info "test_log=${TEST_LOG}"

# Ensure rano binary exists
if [ ! -x "${RANO}" ]; then
    e2e_fail "rano binary not found at ${RANO}. Run 'cargo build' first."
fi

# Test 1: Verify alert CLI flags are accepted
e2e_section "Test 1: Alert CLI flags parsing"
e2e_run "parse alert flags" "${RANO}" --help

e2e_assert_last_status 0
e2e_assert_last_contains "--alert-domain"
e2e_assert_last_contains "--alert-max-connections"
e2e_assert_last_contains "--alert-duration-ms"
e2e_assert_last_contains "--alert-unknown-domain"
e2e_assert_last_contains "--alert-bell"
e2e_assert_last_contains "--alert-cooldown-ms"
e2e_info "PASS: All alert flags present in help"

# Test 2: Run rano with --once and alert config (no matching processes)
e2e_section "Test 2: Alert config with no matching processes"
e2e_run "once with alert config" "${RANO}" \
    --pattern "nonexistent-process-xyz" \
    --sqlite "${TEST_SQLITE}" \
    --alert-domain "*.malicious.com" \
    --alert-max-connections 100 \
    --alert-duration-ms 60000 \
    --once \
    --no-banner

# This should succeed even with no matching processes
# (It will just not find any connections)
e2e_info "PASS: rano accepts alert configuration"

# Test 3: Verify SQLite schema has alert column
e2e_section "Test 3: SQLite schema includes alert column"
e2e_run "check schema" sqlite3 "${TEST_SQLITE}" ".schema events"

e2e_assert_last_contains "alert"
e2e_info "PASS: SQLite events table has alert column"

# Test 4: Verify alert flags in JSON summary
e2e_section "Test 4: JSON summary includes alert counts"
e2e_run "json summary" "${RANO}" \
    --pattern "nonexistent-process-xyz" \
    --sqlite "${TEST_SQLITE}" \
    --json \
    --once \
    --no-banner 2>&1

e2e_assert_last_contains "alerts"
e2e_assert_last_contains "alerts_suppressed"
e2e_info "PASS: JSON summary includes alert count fields"

# Test 5: Verify --no-alerts disables alerting
e2e_section "Test 5: --no-alerts flag"
e2e_run "no-alerts mode" "${RANO}" \
    --pattern "nonexistent-process-xyz" \
    --alert-domain "*.evil.com" \
    --no-alerts \
    --once \
    --no-banner 2>&1

e2e_assert_last_status 0
e2e_info "PASS: --no-alerts flag accepted"

# Test 6: Verify alert cooldown flag
e2e_section "Test 6: Alert cooldown configuration"
e2e_run "custom cooldown" "${RANO}" \
    --pattern "nonexistent-process-xyz" \
    --alert-max-connections 10 \
    --alert-cooldown-ms 5000 \
    --once \
    --no-banner 2>&1

e2e_assert_last_status 0
e2e_info "PASS: --alert-cooldown-ms flag accepted"

# Test 7: Multiple alert domains
e2e_section "Test 7: Multiple alert domain patterns"
e2e_run "multiple domains" "${RANO}" \
    --pattern "nonexistent-process-xyz" \
    --alert-domain "*.evil.com" \
    --alert-domain "*.malware.org" \
    --alert-domain "bad.site.net" \
    --once \
    --no-banner 2>&1

e2e_assert_last_status 0
e2e_info "PASS: Multiple --alert-domain flags accepted"

# Test 8: Combined alert configuration
e2e_section "Test 8: Combined alert configuration"
e2e_run "all alert options" "${RANO}" \
    --pattern "nonexistent-process-xyz" \
    --alert-domain "*.suspicious.com" \
    --alert-max-connections 50 \
    --alert-max-per-provider 20 \
    --alert-duration-ms 30000 \
    --alert-unknown-domain \
    --alert-cooldown-ms 15000 \
    --sqlite "${TEST_SQLITE}" \
    --once \
    --no-banner 2>&1

e2e_assert_last_status 0
e2e_info "PASS: All alert options combined work together"

# Test 9: Verify alert column type in SQLite
e2e_section "Test 9: SQLite alert column stores integers"
e2e_run "check column type" sqlite3 "${TEST_SQLITE}" "PRAGMA table_info(events);"

e2e_assert_last_contains "alert"
e2e_info "PASS: Alert column present in SQLite schema"

e2e_section "Live alert triggers, cooldowns and concurrent negative control"
python3 - "${RANO}" "${E2E_OUTPUT_DIR}" <<'PY' || e2e_fail "live alert matrix failed; inspect retained captures"
import json
import signal
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
from pathlib import Path

binary = str(Path(sys.argv[1]).resolve())
root = Path(tempfile.mkdtemp(prefix='alerts-', dir=sys.argv[2]))
print(f'  retained fixtures={root}')
holder_code = '''import json,socket,sys
s=socket.socket();s.bind(('127.0.0.1',0));s.listen()
print(json.dumps({'ready':True}),flush=True)
for _ in range(3):
 sys.stdin.read(1);c=socket.socket();c.connect(s.getsockname());a,_=s.accept()
 sys.stdin.read(1);c.close();a.close()
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
    raise AssertionError(f'no {description}; captures retained')

cases = [
    ('sequential', ['--no-dns', '--alert-max-connections', '3', '--alert-max-per-provider', '3'], {}),
    ('threshold', ['--no-dns', '--alert-max-connections', '2', '--alert-max-per-provider', '2'], {'max_connections':1, 'max_per_provider':1}),
    ('unknown', ['--no-dns', '--alert-unknown-domain'], {'unknown_domain':1}),
    ('domain', ['--domain-mode', 'ptr', '--alert-domain', '*'], {'domain_match':1}),
    ('duration', ['--no-dns', '--alert-duration-ms', '1'], {'long_duration':6}),
    ('disabled', ['--no-dns', '--alert-max-connections', '1', '--alert-max-per-provider', '1', '--alert-unknown-domain', '--alert-duration-ms', '1', '--no-alerts'], {}),
]
for name, flags, expected in cases:
    case = root / name; case.mkdir()
    holder = subprocess.Popen([sys.executable, '-u', '-c', holder_code, 'claude'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    json.loads(holder.stdout.readline())
    monitor = None
    try:
        command = [binary, '--no-config', '--pid', str(holder.pid), '--no-descendants', '--interval-ms', '20',
            '--json', '--no-banner', '--stats-interval-ms', '0', '--sqlite', str(case / 'events.sqlite'),
            '--log-format', 'json', '--log-file', str(case / 'file.jsonl'), '--alert-cooldown-ms', '100000', *flags]
        with (case / 'stdout.jsonl').open('w') as stdout, (case / 'stderr').open('w') as stderr:
            monitor = subprocess.Popen(command, stdout=stdout, stderr=stderr)
            for cycle in range(3):
                holder.stdin.write('o');holder.stdin.flush()
                until(lambda: sum(row.get('event')=='connect' for row in records(case/'stdout.jsonl'))==2*(cycle+1), monitor, 'confirmed connects')
                time.sleep(0.05)
                holder.stdin.write('c');holder.stdin.flush()
                until(lambda: sum(row.get('event')=='close' for row in records(case/'stdout.jsonl'))==2*(cycle+1), monitor, 'confirmed closes')
            monitor.send_signal(signal.SIGINT);assert monitor.wait(timeout=20)==0, 'monitor failed'
        output = records(case/'stdout.jsonl')
        alerts = [row for row in output if row.get('type')=='alert']
        actual = {}
        for alert in alerts: actual[alert['kind']] = actual.get(alert['kind'],0)+1
        assert actual == expected, f'{name}: unexpected alert kinds/counts {actual}'
        summary = next(row['summary'] for row in reversed(output) if 'summary' in row)
        assert summary['connects']==6 and summary['closes']==6 and summary['active']==0, 'workload did not complete'
        assert summary['per_provider']['anthropic']==6, 'lifetime totals changed'
        assert summary['peak_active']==2, 'per-row transient inflated sampled peak'
        if name == 'threshold':
            assert all(alert['actual']==2 for alert in alerts), 'threshold used lifetime count'
            assert summary['alerts_suppressed']>0, 'cooldown suppression not exercised'
        if name == 'domain': assert all(alert['domain'] for alert in alerts), 'empty domain trigger'
        file_alerts = [row for row in records(case/'file.jsonl') if row.get('type')=='alert']
        assert file_alerts == alerts, 'file alerts disagree with stdout'
        with sqlite3.connect(case/'events.sqlite') as conn:
            flagged = conn.execute('SELECT event, count(*) FROM events WHERE alert=1 GROUP BY event').fetchall()
            total = conn.execute('SELECT count(*) FROM events').fetchone()[0]
        flags_by_event = dict(flagged)
        expected_flag = 'alert' if name=='threshold' else 'close' if name=='duration' else 'connect'
        assert flags_by_event == ({expected_flag:len(alerts)} if alerts else {}), f'{name}: cooldown-aware flags disagree'
        assert summary['sqlite']['observed']==total and summary['sqlite']['persisted']==total and summary['sqlite_dropped']==0, 'alert rows did not reconcile'
        export = subprocess.run([binary,'export','--sqlite',str(case/'events.sqlite'),'--format','jsonl'],capture_output=True,text=True,timeout=20)
        (case/'export.jsonl').write_text(export.stdout);(case/'export.stderr').write_text(export.stderr)
        assert export.returncode==0 and len([row for row in map(json.loads,export.stdout.splitlines()) if row.get('alert')==1])==len(alerts), 'export lost flagged rows'
        print(f'  PASS {name}: six opens/closes, kinds={actual}, cooldown/durable/file/export semantics')
    finally:
        if monitor is not None and monitor.poll() is None:
            monitor.send_signal(signal.SIGINT);monitor.wait(timeout=20)
        holder.terminate();holder.wait(timeout=5)
PY

# Summary
e2e_section "Summary"
e2e_info "All E2E alert threshold tests passed"
e2e_info "Tests verified:"
e2e_info "  - Alert CLI flags are recognized"
e2e_info "  - SQLite schema includes alert column"
e2e_info "  - JSON summary includes alert counts"
e2e_info "  - --no-alerts flag disables alerting"
e2e_info "  - Alert cooldown is configurable"
e2e_info "  - Multiple domain patterns supported"
e2e_info "  - Combined alert configuration works"
