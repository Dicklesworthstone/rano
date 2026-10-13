#!/usr/bin/env bash
set -euo pipefail

RANO_BIN="${RANO_BIN:-${E2E_RANO_RELEASE}}"
if [ ! -x "${RANO_BIN}" ]; then
  e2e_fail "rano binary missing at ${RANO_BIN}; build the intended revision first"
fi

e2e_section "Run stats view cycle"
e2e_run "stats views cycle with ready held sockets" python3 - "${RANO_BIN}" "${E2E_OUTPUT_DIR}" <<'PY' || e2e_fail "stats view readiness/health assertions failed"
import json, os, pathlib, re, selectors, signal, sqlite3, subprocess, sys, tempfile, time
binary=sys.argv[1];root=pathlib.Path(tempfile.mkdtemp(prefix='stats-views-',dir=sys.argv[2]))
print(f'retained fixtures={root}',flush=True)
holder_code=r'''
import json,os,socket,sys
listener=socket.socket();listener.bind(('127.0.0.1',0));listener.listen()
client=socket.create_connection(listener.getsockname());accepted,_=listener.accept()
print(json.dumps({'pid':os.getpid(),'port':listener.getsockname()[1]}),flush=True)
sys.stdin.read(1)
'''
holder=subprocess.Popen([sys.executable,'-u','-c',holder_code,'claude'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True)
ready=json.loads(holder.stdout.readline())
expected={'provider','domain','port','process'}
def completed_views(text): return set(re.findall(r'^Live Stats \[(provider|domain|port|process)\]',text,re.M))
def validate(text,stderr,status):
    assert status==0, f'monitor exit {status}: {stderr}'
    assert completed_views(text)==expected, 'not all requested views appeared'
    match=re.search(r'^\s+connects\s+(\d+)\s*$',text,re.M)
    assert match and int(match[1])>=2, 'no positive real socket observations'
    assert 'Summary' in text and 'observation_errors=0' in text, 'missing/failed final summary'
    assert 'failed=true' not in text and 'file log failed' not in text, 'unhealthy sinks'
try:
    command=[binary,'--no-config','--pid',str(ready['pid']),'--no-descendants','--no-dns',
        '--interval-ms','50','--stats-interval-ms','50','--stats-cycle-ms','50','--stats-top','3',
        '--no-color','--no-banner','--sqlite',str(root/'events.sqlite')]
    for view in ['provider','domain','port','process']:command+=['--stats-view',view]
    monitor=subprocess.Popen(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    chunks=[];selector=selectors.DefaultSelector();selector.register(monitor.stdout,selectors.EVENT_READ)
    deadline=time.monotonic()+20
    try:
        while completed_views(b''.join(chunks).decode())!=expected and time.monotonic()<deadline:
            assert holder.poll() is None, 'fixture stopped before observation'
            if selector.select(timeout=.1):
                chunk=os.read(monitor.stdout.fileno(),65536)
                if chunk:chunks.append(chunk)
                elif monitor.poll() is not None:break
        monitor.send_signal(signal.SIGTERM)
        remaining,stderr=monitor.communicate(timeout=10);text=(b''.join(chunks)+remaining).decode();stderr=stderr.decode()
    finally:
        selector.close()
        if monitor.poll() is None:monitor.kill();monitor.wait(timeout=5)
    (root/'stdout.txt').write_text(text);(root/'stderr.txt').write_text(stderr)
    validate(text,stderr,monitor.returncode)
    with sqlite3.connect(root/'events.sqlite') as conn:
        assert conn.execute("SELECT COUNT(*) FROM events WHERE event='connect' AND pid=?",[ready['pid']]).fetchone()[0]>=2, 'durable positive observations absent'
    # Negative controls prove the replacement still rejects incomplete rendering,
    # a missing final summary and failed process status rather than accepting exit alone.
    for invalid,status in [(re.sub(r'^Live Stats \[domain\].*$', '',text,flags=re.M),0),
        (text.split('Summary')[0],0),(text,1)]:
        try:validate(invalid,stderr,status)
        except AssertionError:pass
        else:raise AssertionError('stats verifier accepted an invalid control')
    print(text,end='');print('PASS all views, real durable observations, graceful healthy summary and negative controls')
finally:
    holder.stdin.write('x');holder.stdin.flush();holder.wait(timeout=5)
PY

e2e_assert_last_status 0

# Ensure all views appeared in output
e2e_assert_last_contains "Live Stats [provider]"
e2e_assert_last_contains "Live Stats [domain]"
e2e_assert_last_contains "Live Stats [port]"
e2e_assert_last_contains "Live Stats [process]"

e2e_section "View sequence sample"
grep -E "^Live Stats \[(provider|domain|port|process)\]" "${E2E_LAST_OUTPUT_FILE}" | head -n 10 | while IFS= read -r line; do
  e2e_info "${line}"
done
