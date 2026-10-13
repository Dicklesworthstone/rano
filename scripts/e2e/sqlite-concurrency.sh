#!/usr/bin/env bash
# E2E Test: SQLite concurrent reader/writer access
#
# Verifies that read-side commands (status, report) succeed while the monitor
# is actively writing events. busy_timeout (PRAGMA on every connection) must
# turn transient SQLITE_BUSY into bounded waits instead of errors.
#
# Regression guard for: "SQLite file is locked" documented as unavoidable in
# README Troubleshooting; shell-prompt status usage dying under load.

set -euo pipefail

RANO="${RANO:-${E2E_RANO_DEBUG:-./target/debug/rano}}"
STATUS_RUNS=25

if [ ! -x "${RANO}" ]; then
    e2e_fail "rano binary not found at ${RANO}. Run 'cargo build' first."
fi

e2e_section "Setup"
e2e_info "rano=${RANO}"

e2e_section "Concurrent readers against a ready, progressing writer"
python3 - "${RANO}" "${E2E_OUTPUT_DIR}" "${STATUS_RUNS}" <<'PY' || e2e_fail "concurrent writer/reader proof failed"
import json,pathlib,select,signal,sqlite3,subprocess,sys,tempfile,time
binary=sys.argv[1];root=pathlib.Path(tempfile.mkdtemp(prefix='sqlite-concurrency-',dir=sys.argv[2]));database=root/'events.sqlite'
print(f'retained fixtures={root}',flush=True)
code=r'''
import json,os,select,socket,sys,time
listener=socket.socket();listener.bind(('127.0.0.1',0));listener.listen();held=[];generated=0
print(json.dumps({'pid':os.getpid(),'port':listener.getsockname()[1]}),flush=True)
while True:
    now=time.monotonic()
    for _ in range(5):
        client=socket.create_connection(listener.getsockname());server,_=listener.accept();held.append((now,client,server));generated+=1
    while held and now-held[0][0]>3:
        _,client,server=held.pop(0);client.close();server.close()
    if select.select([sys.stdin],[],[],.25)[0]:
        if sys.stdin.readline().strip()=='stop':break
        print(json.dumps({'generated':generated}),flush=True)
'''
holder=subprocess.Popen([sys.executable,'-u','-c',code,'claude'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True)
monitor=None;stdout=open(root/'writer.stdout.jsonl','w');stderr=open(root/'writer.stderr','w')
def count():
    with sqlite3.connect(f'file:{database}?mode=ro',uri=True,timeout=5) as conn:return conn.execute('SELECT COUNT(*) FROM events').fetchone()[0]
def alive():assert monitor.poll() is None and holder.poll() is None,'writer or fixture stopped during reader proof'
try:
    assert select.select([holder.stdout],[],[],5)[0],'fixture never became ready'
    ready=json.loads(holder.stdout.readline())
    monitor=subprocess.Popen([binary,'--no-config','--pid',str(ready['pid']),'--no-descendants','--no-dns','--no-banner',
        '--interval-ms','50','--db-flush-ms','50','--db-batch-size','20','--sqlite',str(database),'--json','--stats-interval-ms','0'],stdout=stdout,stderr=stderr)
    deadline=time.monotonic()+20;before=0
    while time.monotonic()<deadline:
        alive()
        try:before=count()
        except sqlite3.OperationalError:before=0
        if before>0:break
        time.sleep(.05)
    assert before>0,'writer never persisted positive observations'
    for index in range(int(sys.argv[3])):
        alive();result=subprocess.run([binary,'status','--sqlite',str(database)],capture_output=True,text=True,timeout=10)
        (root/f'status-{index}.stdout').write_text(result.stdout);(root/f'status-{index}.stderr').write_text(result.stderr)
        assert result.returncode==0,f'status read failed: {result.stderr}'
        time.sleep(.1)
    after=count();assert after>before,'status reads ran against a stopped writer'
    for index in range(3):
        alive();before_report=count()
        result=subprocess.run([binary,'report','--latest','--json','--sqlite',str(database)],capture_output=True,text=True,timeout=10)
        (root/f'report-{index}.json').write_text(result.stdout);(root/f'report-{index}.stderr').write_text(result.stderr)
        assert result.returncode==0 and json.loads(result.stdout)['summary']['total_events']>0,f'report read failed: {result.stderr}'
        deadline=time.monotonic()+5
        while count()<=before_report and time.monotonic()<deadline:alive();time.sleep(.05)
        assert count()>before_report,'report reads ran against a stopped writer'
    holder.stdin.write('progress\n');holder.stdin.flush();assert select.select([holder.stdout],[],[],3)[0],'generator did not respond'
    generated=json.loads(holder.stdout.readline())['generated'];assert generated>0,'no actual generated/accepted sockets'
    monitor.send_signal(signal.SIGTERM);assert monitor.wait(timeout=15)==0,'writer exited unsuccessfully'
    stdout.close();stderr.close()
    records=list(map(json.loads,(root/'writer.stdout.jsonl').read_text().splitlines()))
    summary=next(row['summary'] for row in records if 'summary' in row);durable=summary['sqlite']
    assert summary['observation_errors']==0 and not durable['failed'] and durable['queue_lost']==durable['write_lost']==0,'unhealthy writer'
    assert durable['persisted']==durable['observed']==count()>after,'final count does not reconcile or writer stopped early'
    print(f"PASS {sys.argv[3]} status reads and3 parsed reports during actual writes; durable rows {before}->{after}->{count()}; generated/accepted pairs {generated}",flush=True)
finally:
    if monitor is not None and monitor.poll() is None:
        monitor.send_signal(signal.SIGTERM)
        try:monitor.wait(timeout=15)
        except subprocess.TimeoutExpired:monitor.kill();monitor.wait(timeout=5)
    if holder.poll() is None:
        holder.stdin.write('stop\n');holder.stdin.flush();holder.wait(timeout=5)
    stdout.close();stderr.close()
PY

e2e_section "Summary"
e2e_info "All SQLite concurrency tests passed"
