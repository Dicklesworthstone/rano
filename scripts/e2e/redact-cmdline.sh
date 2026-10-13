#!/usr/bin/env bash
# Real TCP connects/closes, all redaction modes, every durable command-line sink.
# Fixtures and captures are retained for diagnosis; only fake credentials are used.

set -euo pipefail

RANO="${RANO:-${E2E_RANO_DEBUG}}"
e2e_section "Existing help and preset command coverage"
e2e_run "help mentions redact" "${RANO}" --help
e2e_assert_last_status 0
e2e_assert_last_contains "--redact-cmdline"
e2e_run "list presets" "${RANO}" --list-presets
e2e_assert_last_status 0
e2e_section "Live privacy matrix (off, secrets, all, audit preset)"
python3 - "${RANO}" "${E2E_OUTPUT_DIR}" <<'PY' || e2e_fail "live privacy matrix failed; inspect retained captures"
import csv
import io
import json
import signal
import sqlite3
import subprocess
import sys
import tempfile
import time
from pathlib import Path

binary = str(Path(sys.argv[1]).resolve())
root = Path(tempfile.mkdtemp(prefix='redact-', dir=sys.argv[2]))
print(f'  retained fixtures={root}')
holder_code = '''import json,socket,sys
s=socket.socket();s.bind(('127.0.0.1',0));s.listen()
c=socket.socket();c.connect(s.getsockname());a,_=s.accept()
print(json.dumps({'port':s.getsockname()[1]}),flush=True)
sys.stdin.read(1);c.close();a.close();s.close();sys.stdin.read(1)
'''
fake = ['FAKE MULTIWORD\n雪 CREDENTIAL', 'FAKE ASSIGNMENT VALUE',
        'ghp_FAKE0123456789abcdefghijklmnop',
        'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.FAKE0123456789abcd',
        'sk-ant-api03-FAKE0123456789abcdef']
holder_argv = [sys.executable, '-u', '-c', holder_code, 'claude', '--password', fake[0],
               f'API_KEY={fake[1]}', f'--token={fake[2]}', fake[3], '', '--model', 'two words']

def read_records(path):
    # The last record may still be being written by the monitor.
    text = path.read_text()
    return [json.loads(line) for line in text.splitlines(keepends=True) if line.endswith('\n')]

def await_event(path, event, monitor, database=False):
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        if database:
            try:
                with sqlite3.connect(path) as conn:
                    observed = conn.execute('SELECT count(*) FROM events WHERE event=?', [event]).fetchone()[0] > 0
            except sqlite3.Error:
                observed = False
        else:
            observed = any(row.get('event') == event for row in read_records(path))
        if observed:
            return
        assert monitor.poll() is None, f'monitor exited before {event}'
        time.sleep(0.02)
    raise AssertionError(f'no confirmed {event}; captures retained')

for mode in ['secrets', 'off', 'all', 'audit']:
    case = root / mode
    case.mkdir()
    holder = subprocess.Popen(holder_argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    json.loads(holder.stdout.readline())
    monitor = None
    try:
        command = [binary, '--no-config', '--pid', str(holder.pid), '--no-descendants',
                   '--pattern', fake[4], '--interval-ms', '20', '--no-dns', '--no-banner',
                   '--json', '--stats-interval-ms', '0', '--sqlite', str(case / 'events.sqlite'),
                   '--log-file', str(case / 'file.jsonl'), '--log-format', 'json']
        command += ['--preset', 'audit'] if mode == 'audit' else ['--redact-cmdline', mode]
        with (case / 'stdout.jsonl').open('w') as stdout, (case / 'stderr').open('w') as stderr:
            monitor = subprocess.Popen(command, stdout=stdout, stderr=stderr)
            observed_path = case / ('events.sqlite' if mode == 'audit' else 'stdout.jsonl')
            await_event(observed_path, 'connect', monitor, mode == 'audit')
            holder.stdin.write('c'); holder.stdin.flush()
            await_event(observed_path, 'close', monitor, mode == 'audit')
            monitor.send_signal(signal.SIGINT)
            assert monitor.wait(timeout=20) == 0, 'monitor failed'
        with sqlite3.connect(case / 'events.sqlite') as conn:
            events = conn.execute('SELECT event, provider, cmdline FROM events').fetchall()
            sessions = conn.execute('SELECT args, patterns, session_name FROM sessions').fetchall()
        assert sum(event == 'connect' for event, _, _ in events) > 0, 'no durable connects'
        assert sum(event == 'close' for event, _, _ in events) > 0, 'no durable closes'
        assert all(provider == 'anthropic' for _, provider, _ in events), 'attribution changed'
        file_records = read_records(case / 'file.jsonl')
        live = read_records(case / 'stdout.jsonl')
        durable = [cmdline for _, _, cmdline in events]
        durable += [r['cmdline'] for r in file_records if r.get('event') in ['connect', 'close']]
        expected_file_count = 0 if mode == 'audit' else len(events)
        assert len(durable) == len(events) + expected_file_count, 'missing durable file records'
        assert any('summary' in row for row in file_records), 'missing file summary'
        for export_format in ['csv', 'jsonl']:
            export = subprocess.run([binary, 'export', '--sqlite', str(case / 'events.sqlite'),
                                     '--format', export_format], capture_output=True, text=True)
            (case / f'export.{export_format}').write_text(export.stdout)
            (case / f'export.{export_format}.stderr').write_text(export.stderr)
            assert export.returncode == 0, 'export failed'
            rows = list(csv.DictReader(io.StringIO(export.stdout))) if export_format == 'csv' else [json.loads(line) for line in export.stdout.splitlines()]
            assert len(rows) == len(events), 'export omitted events'
            durable += [row['cmdline'] for row in rows]
        if mode == 'off':
            assert all(value == ' '.join(holder_argv) for value in durable), 'off changed argv'
            assert all(fake[4] in value for value in sessions[0][:2]), 'off changed session metadata'
        elif mode == 'all':
            assert all(value == f'<redacted:{len(holder_argv)} args>' for value in durable), 'all leaked argv or counted wrong'
            assert sessions[0][0].startswith('<redacted:') and sessions[0][1] == '<redacted:1 patterns>'
            assert sessions[0][2] == '<redacted>', 'all leaked session name'
        else:
            for value in durable + list(sessions[0]):
                assert not any(secret in value for secret in fake), 'credential leaked (value withheld)'
                assert 'MULTIWORD' not in value and 'CREDENTIAL' not in value, 'partial-value leak'
            assert all('--model two words' in value for value in durable), 'benign argument changed'
            assert all('<redacted>' in value for value in durable), 'mask missing'
        if mode != 'audit':
            assert any(fake[0] in row.get('cmdline', '') for row in live), 'live display policy changed'
        else:
            assert not any(row.get('event') for row in live), 'audit summary-only policy changed'
        print(f'  PASS {mode}: connects/closes, attribution, SQLite, file, CSV, JSONL, session metadata')
    finally:
        if monitor is not None and monitor.poll() is None:
            monitor.send_signal(signal.SIGINT); monitor.wait(timeout=20)
        holder.terminate(); holder.wait(timeout=5)
PY

e2e_section "Summary"
e2e_info "redact-cmdline e2e verified: secrets masked durably, attribution unaffected"
