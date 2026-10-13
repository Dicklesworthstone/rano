#!/usr/bin/env bash
# E2E Test: Process Ancestry
# Tests the process ancestry tracking feature
#
# This test verifies:
# - Ancestry path is captured for tracked processes
# - Ancestry appears in SQLite events table
# - Ancestry appears in JSON summary output
# - Format: "comm:pid,comm:pid,..." from init to process
#
# Prerequisites:
# - rano binary built (cargo build)
# - SQLite3 available for database verification

set -euo pipefail

RANO="${RANO:-${E2E_RANO_DEBUG}}"
TEST_SQLITE="/tmp/rano-e2e-ancestry-$$.sqlite"

# Cleanup on exit
cleanup() {
    e2e_info "Retained ancestry database: ${TEST_SQLITE}"
}
trap cleanup EXIT

e2e_section "Setup"
e2e_info "rano=${RANO}"
e2e_info "test_sqlite=${TEST_SQLITE}"

# Ensure rano binary exists
if [ ! -x "${RANO}" ]; then
    e2e_fail "rano binary not found at ${RANO}. Run 'cargo build' first."
fi

# Test 1: Verify SQLite schema has ancestry_path column
e2e_section "Test 1: SQLite schema includes ancestry_path column"

# First run rano to create the database
e2e_run "create db" "${RANO}" \
    --pattern "nonexistent-process-xyz" \
    --sqlite "${TEST_SQLITE}" \
    --once \
    --no-banner

e2e_run "check schema" sqlite3 "${TEST_SQLITE}" ".schema events"

e2e_assert_last_status 0
e2e_assert_last_contains "ancestry_path"
e2e_info "PASS: SQLite events table has ancestry_path column"

# Test 2: Ancestry path has correct index
e2e_section "Test 2: SQLite ancestry index exists"
e2e_run "check indices" sqlite3 "${TEST_SQLITE}" ".indices events"

e2e_assert_last_status 0
e2e_assert_last_contains "idx_events_ancestry_path"
e2e_info "PASS: ancestry_path index exists"

# Test 3: Seed database with ancestry data and verify export
e2e_section "Test 3: Ancestry path appears in CSV export"

# Seed with a test event that has ancestry
sqlite3 "${TEST_SQLITE}" << 'SQL'
INSERT INTO events (
    ts, run_id, event, provider, pid, comm, cmdline, proto,
    local_ip, local_port, remote_ip, remote_port, domain, ancestry_path, alert
) VALUES (
    '2026-01-20T12:00:00Z', 'test-run-ancestry', 'connect', 'anthropic',
    1234, 'claude', '/usr/bin/claude', 'tcp',
    '192.168.1.100', 54321, '104.18.32.7', 443,
    'api.anthropic.com', 'init:1,systemd:500,bash:1000,claude:1234', 0
);
SQL

e2e_run "export csv" "${RANO}" export --format csv --sqlite "${TEST_SQLITE}" --run-id "test-run-ancestry"

e2e_assert_last_status 0
e2e_assert_last_contains "ancestry_path"
e2e_assert_last_contains "init:1,systemd:500,bash:1000,claude:1234"
e2e_info "PASS: Ancestry path appears in CSV export"

# Test 4: Ancestry path appears in JSONL export
e2e_section "Test 4: Ancestry path appears in JSONL export"
e2e_run "export jsonl" "${RANO}" export --format jsonl --sqlite "${TEST_SQLITE}" --run-id "test-run-ancestry"

e2e_assert_last_status 0
e2e_assert_last_contains "ancestry_path"
e2e_assert_last_contains "init:1,systemd:500,bash:1000,claude:1234"
e2e_info "PASS: Ancestry path appears in JSONL export"

# Test 5: Various ancestry path formats
e2e_section "Test 5: Various ancestry path formats"

sqlite3 "${TEST_SQLITE}" << 'SQL'
-- Short ancestry (direct from init)
INSERT INTO events (
    ts, run_id, event, provider, pid, comm, cmdline, proto,
    local_ip, local_port, remote_ip, remote_port, domain, ancestry_path, alert
) VALUES (
    '2026-01-20T12:01:00Z', 'test-run-ancestry-short', 'connect', 'openai',
    2000, 'codex', '/usr/bin/codex', 'tcp',
    '192.168.1.100', 54322, '13.107.246.10', 443,
    'api.openai.com', 'init:1,codex:2000', 0
);

-- Deep ancestry
INSERT INTO events (
    ts, run_id, event, provider, pid, comm, cmdline, proto,
    local_ip, local_port, remote_ip, remote_port, domain, ancestry_path, alert
) VALUES (
    '2026-01-20T12:02:00Z', 'test-run-ancestry-deep', 'connect', 'google',
    3000, 'gemini', '/usr/bin/gemini', 'tcp',
    '192.168.1.100', 54323, '142.250.189.206', 443,
    'gemini.google.com', 'init:1,systemd:100,login:200,bash:300,tmux:400,bash:500,python:600,gemini:3000', 0
);
SQL

# Verify short ancestry
e2e_run "export short" "${RANO}" export --format csv --sqlite "${TEST_SQLITE}" --run-id "test-run-ancestry-short"
e2e_assert_last_status 0
e2e_assert_last_contains "init:1,codex:2000"
e2e_info "PASS: Short ancestry path captured"

# Verify deep ancestry
e2e_run "export deep" "${RANO}" export --format csv --sqlite "${TEST_SQLITE}" --run-id "test-run-ancestry-deep"
e2e_assert_last_status 0
e2e_assert_last_contains "init:1,systemd:100,login:200,bash:300,tmux:400,bash:500,python:600,gemini:3000"
e2e_info "PASS: Deep ancestry path captured"

# Test 6: Null ancestry path handled gracefully
e2e_section "Test 6: Null ancestry path handled gracefully"

sqlite3 "${TEST_SQLITE}" << 'SQL'
INSERT INTO events (
    ts, run_id, event, provider, pid, comm, cmdline, proto,
    local_ip, local_port, remote_ip, remote_port, domain, ancestry_path, alert
) VALUES (
    '2026-01-20T12:03:00Z', 'test-run-no-ancestry', 'connect', 'anthropic',
    4000, 'claude', '/usr/bin/claude', 'tcp',
    '192.168.1.100', 54324, '104.18.32.7', 443,
    'api.anthropic.com', NULL, 0
);
SQL

e2e_run "export null ancestry" "${RANO}" export --format csv --sqlite "${TEST_SQLITE}" --run-id "test-run-no-ancestry"
e2e_assert_last_status 0
e2e_info "PASS: Null ancestry path handled gracefully in CSV"

e2e_run "export null jsonl" "${RANO}" export --format jsonl --sqlite "${TEST_SQLITE}" --run-id "test-run-no-ancestry"
e2e_assert_last_status 0
e2e_info "PASS: Null ancestry path handled gracefully in JSONL"

# Test 7: Special characters in process names
e2e_section "Test 7: Special characters in ancestry comm names"

sqlite3 "${TEST_SQLITE}" << 'SQL'
INSERT INTO events (
    ts, run_id, event, provider, pid, comm, cmdline, proto,
    local_ip, local_port, remote_ip, remote_port, domain, ancestry_path, alert
) VALUES (
    '2026-01-20T12:04:00Z', 'test-run-special-chars', 'connect', 'anthropic',
    5000, 'my-app_v2', '/usr/bin/my-app_v2', 'tcp',
    '192.168.1.100', 54325, '104.18.32.7', 443,
    'api.anthropic.com', 'init:1,bash:100,my-app_v2:5000', 0
);
SQL

e2e_run "export special chars" "${RANO}" export --format csv --sqlite "${TEST_SQLITE}" --run-id "test-run-special-chars"
e2e_assert_last_status 0
e2e_assert_last_contains "my-app_v2:5000"
e2e_info "PASS: Special characters in process names handled"

e2e_section "Live process topology, exclusions and shared descriptors"
python3 - "${RANO}" "${E2E_OUTPUT_DIR}" <<'PY' || e2e_fail "live topology matrix failed; inspect retained captures"
import base64
import csv
import io
import json
import os
import signal
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path

binary = str(Path(sys.argv[1]).resolve())
root = Path(tempfile.mkdtemp(prefix='topology-', dir=sys.argv[2]))
print(f'  retained fixtures={root}')
leaf_code = '''import base64,ctypes,json,os,socket,sys
ctypes.CDLL(None).prctl(15,base64.b64decode(sys.argv[1]),0,0,0)
s=socket.socket();s.bind(('127.0.0.1',0));s.listen()
c=socket.socket();c.connect(s.getsockname());a,_=s.accept()
print(json.dumps({'leaf':os.getpid()}),flush=True)
sys.stdin.read(1)
'''
middle_code = '''import base64,ctypes,json,os,subprocess,sys
ctypes.CDLL(None).prctl(15,base64.b64decode(sys.argv[1]),0,0,0)
p=subprocess.Popen([sys.executable,'-u','-c',base64.b64decode(sys.argv[2]).decode(),sys.argv[3]],stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True)
ready=json.loads(p.stdout.readline());ready['middle']=os.getpid()
print(json.dumps(ready),flush=True)
try: sys.stdin.read(1)
finally: p.terminate();p.wait()
'''
parent_code = '''import base64,ctypes,json,os,signal,socket,subprocess,sys
ctypes.CDLL(None).prctl(15,b'root-holder',0,0,0)
mode=sys.argv[1]
if mode=='shared':
 s=socket.socket();s.bind(('127.0.0.1',0));s.listen()
 c=socket.socket();c.connect(s.getsockname());a,_=s.accept()
 r,w=os.pipe();child=os.fork()
 if child==0:
  os.close(r);ctypes.CDLL(None).prctl(15,b'shared-child',0,0,0)
  os.write(w,b'x');os.close(w);signal.pause();sys.exit(0)
 os.close(w);os.read(r,1);os.close(r)
 ready={'root':os.getpid(),'child':child}
 print(json.dumps(ready),flush=True)
 try: sys.stdin.read(1)
 finally: os.kill(child,signal.SIGTERM);os.waitpid(child,0)
else:
 code=base64.b64decode(sys.argv[2]).decode()
 args=[sys.executable,'-u','-c',code]+sys.argv[3:-1]
 p=subprocess.Popen(args,stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True)
 ready=json.loads(p.stdout.readline());ready['root']=os.getpid()
 print(json.dumps(ready),flush=True)
 try: sys.stdin.read(1)
 finally:
  p.stdin.write('x');p.stdin.flush();p.wait(timeout=5)
'''

def encoded(value): return base64.b64encode(value.encode()).decode()
def launch(mode, comm):
    if mode == 'excluded':
        arguments = [encoded(middle_code), encoded('skip-subtree'), encoded(leaf_code), encoded(comm)]
    else:
        arguments = [encoded(leaf_code), encoded(comm)]
    # The marker is a real final argv argument. Helper source contains no provider names.
    holder = subprocess.Popen([sys.executable, '-u', '-c', parent_code, mode, *arguments, 'claude'],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    return holder, json.loads(holder.stdout.readline())

def proc_identity(pid):
    raw = Path(f'/proc/{pid}/stat').read_text()
    fields = raw.rsplit(') ', 1)[1].split()
    return {'pid': pid, 'start_time': fields[19]}, int(fields[1])

def inspect(holder, ready, label, flags, expected, owner_ids):
    case = root / label; case.mkdir()
    command = [binary, '--no-config', '--pid', str(holder.pid), '--once', '--json', '--no-banner',
        '--no-dns', '--show-ancestry', '--sqlite', str(case / 'events.sqlite'), *flags]
    result = subprocess.run(command, capture_output=True, text=True, timeout=20)
    (case / 'stdout.jsonl').write_text(result.stdout); (case / 'stderr').write_text(result.stderr)
    assert result.returncode == 0, f'{label}: monitor failed'
    events = [r for r in map(json.loads, result.stdout.splitlines()) if r.get('event') == 'connect']
    assert len(events) == expected, f'{label}: expected {expected} connects, got {len(events)}'
    with sqlite3.connect(case / 'events.sqlite') as conn:
        durable = conn.execute('SELECT pid, ancestry_path, ownership_json FROM events').fetchall()
    assert len(durable) == expected, f'{label}: missing durable rows'
    for event in events:
        ownership = json.loads(event['ownership_json'])
        primary = min(owner_ids)
        identity, ppid = proc_identity(primary)
        root_identity, _ = proc_identity(holder.pid)
        assert event['pid'] == primary and ownership['pid'] == primary, f'{label}: nondeterministic owner'
        assert ownership['start_time'] == identity['start_time'], f'{label}: stale owner identity'
        assert ownership['root_pid'] == holder.pid and ownership['root_start_time'] == root_identity['start_time'], f'{label}: wrong monitored root'
        expected_owners = [proc_identity(pid)[0] for pid in sorted(owner_ids)]
        assert ownership['owners'] == expected_owners, f'{label}: shared holders lost'
        assert f'root-holder({holder.pid})' in event['ancestry'], f'{label}: missing root ancestry'
        assert any(f'({ppid})' in name for name in event['ancestry']), f'{label}: missing immediate parent'
        assert any(json.loads(stored) == ownership for _, _, stored in durable), f'{label}: ownership not persisted'
    export = subprocess.run([binary, 'export', '--sqlite', str(case / 'events.sqlite'), '--format', 'csv'], capture_output=True, text=True, timeout=20)
    (case / 'export.csv').write_text(export.stdout); (case / 'export.stderr').write_text(export.stderr)
    assert export.returncode == 0, f'{label}: export failed'
    rows = list(csv.DictReader(io.StringIO(export.stdout)))
    assert len(rows) == expected, f'{label}: export dropped rows'
    for row in rows:
        assert row['ancestry_path'] and json.loads(row['ownership_json'])['root_pid'] == holder.pid, f'{label}: export lost provenance'
    return [event['pid'] for event in events]

for mode, comm in [('leaf', 'odd name)'), ('excluded', 'socket-child'), ('shared', 'unused')]:
    holder, ready = launch(mode, comm)
    try:
        owners = [holder.pid, ready['child']] if mode == 'shared' else [ready['leaf']]
        inspect(holder, ready, f'{mode}-positive', [], 2, owners)
        if mode == 'leaf':
            inspect(holder, ready, 'no-descendants', ['--no-descendants'], 0, [])
        if mode == 'excluded':
            inspect(holder, ready, 'excluded-subtree', ['--exclude-pattern', 'skip-subtree'], 0, [])
            inspect(holder, ready, 'explicit-excluded', ['--pid', str(ready['leaf']), '--exclude-pattern', 'skip-subtree'], 0, [])
        if mode == 'shared':
            for poll in range(3): inspect(holder, ready, f'shared-repeat-{poll}', [], 2, owners)
        print(f'  PASS {mode}: real sockets, ancestry, ownership, identities, SQLite and export')
    finally:
        holder.stdin.write('x'); holder.stdin.flush(); holder.wait(timeout=5)
PY

# Summary
e2e_section "Summary"
e2e_info "All E2E process ancestry tests passed"
e2e_info "Tests verified:"
e2e_info "  - SQLite schema includes ancestry_path column"
e2e_info "  - ancestry_path index exists for query performance"
e2e_info "  - Ancestry path appears in CSV export"
e2e_info "  - Ancestry path appears in JSONL export"
e2e_info "  - Short ancestry paths work (direct from init)"
e2e_info "  - Deep ancestry paths work (many levels)"
e2e_info "  - Null ancestry path handled gracefully"
e2e_info "  - Special characters in process names handled"
