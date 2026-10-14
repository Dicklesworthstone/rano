#!/usr/bin/env bash
# Counted scan/startup and durable-workload measurements. Optional second
# binary is the incumbent, exercised in this same invocation on the same sockets.
# These timings include startup and output; they are not individual poll timings.

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
RANO="${1:-${RANO_BIN:-}}"
if [ -z "${RANO}" ]; then
  if [ -x "${SCRIPT_DIR}/../target/release/rano" ]; then
    RANO="${SCRIPT_DIR}/../target/release/rano"
  else
    RANO="${SCRIPT_DIR}/../target/debug/rano"
  fi
fi

if [ ! -x "${RANO}" ]; then
  echo "rano binary not found at ${RANO}; build first (cargo build --release)" >&2
  exit 1
fi

python3 - "${RANO}" "${2:-${BENCH_INCUMBENT:-}}" "${SCRIPT_DIR}/.." <<'PY'
import hashlib,json,math,os,pathlib,platform,select,signal,socket,sqlite3,statistics,subprocess,sys,tempfile,time
root=pathlib.Path(tempfile.mkdtemp(prefix='rano-bench.'));print(f'Retained benchmark artifacts: {root}',flush=True)
passes=int(os.environ.get('BENCH_PASSES','30'));duration=float(os.environ.get('BENCH_CHURN_SECS','8'))
counts=[int(value) for value in os.environ.get('BENCH_CONNECTIONS','500,2000').split(',')]
assert passes>0 and math.isfinite(duration) and duration>0 and counts and all(count>0 for count in counts),'positive finite workload sizes required'
binaries=[('candidate',pathlib.Path(sys.argv[1]).resolve(),os.environ.get('BENCH_SOURCE_REVISION'))]
if sys.argv[2]:binaries.append(('incumbent',pathlib.Path(sys.argv[2]).resolve(),os.environ.get('BENCH_INCUMBENT_REVISION')))
metadata={'host':platform.node(),'platform':platform.platform(),'workspace_revision':subprocess.check_output(['git','-C',sys.argv[3],'rev-parse','HEAD'],text=True).strip(),
          'rustc':subprocess.check_output(['rustc','--version'],text=True).strip(),'passes':passes,'connections':counts,'churn_seconds':duration,'binaries':[]}
for label,binary,revision in binaries:
    assert binary.is_file() and os.access(binary,os.X_OK),f'{label} binary missing: {binary}'
    version=subprocess.run([str(binary),'--version'],capture_output=True,text=True,timeout=10)
    assert version.returncode==0,version.stderr
    metadata['binaries'].append({'label':label,'path':str(binary),'sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),'build_revision':revision,'version':version.stdout.strip()})
(root/'invocation.json').write_text(json.dumps(metadata,indent=2))
listener=socket.socket();listener.bind(('127.0.0.1',0));listener.listen();listener.settimeout(5)
pairs=[];monitor=None
def open_pair():
    client=socket.create_connection(listener.getsockname(),timeout=5);server,_=listener.accept();pairs.append((client,server))
def close_pairs():
    while pairs:
        for sock in pairs.pop():sock.close()
def summary(path):
    rows=[json.loads(line) for line in path.read_text().splitlines()]
    summaries=[row['summary'] for row in rows if isinstance(row.get('summary'),dict)]
    assert len(summaries)==1,'one complete final summary required'
    value=summaries[0]
    assert value['observation_errors']==0 and not value['log_failed'] and value['sqlite_dropped']==0,'unhealthy observation/sink summary'
    return value,rows
def observe(label,binary,mode,count,index):
    database=root/f'{label}-{mode}-{count}-{index}.sqlite'
    flags=['--no-config','--pid',str(os.getpid()),'--no-descendants','--once','--json','--no-banner','--stats-interval-ms','0']
    flags+=['--no-dns','--no-sqlite'] if mode=='no-dns-no-sqlite' else ['--sqlite',str(database)]
    started=time.monotonic_ns()
    result=subprocess.run([str(binary),*flags],capture_output=True,text=True,timeout=60)
    elapsed=(time.monotonic_ns()-started)/1e6
    output=root/f'{label}-{mode}-{count}-{index}.stdout';output.write_text(result.stdout)
    output.with_suffix('.stderr').write_text(result.stderr)
    assert result.returncode==0,f'{label}/{mode} exited {result.returncode}: {result.stderr}'
    final,rows=summary(output)
    opens=[row for row in rows if row.get('event')=='connect']
    assert len(opens)==final['connects']==final['active']==2*count and final['closes']==0,'held sockets not fully observed'
    if mode=='default-dns-sqlite':
        with sqlite3.connect(database) as conn:actual=conn.execute('SELECT COUNT(*) FROM events').fetchone()[0]
        sql=final['sqlite'];assert sql['observed']==sql['persisted']==actual==2*count and not sql['failed'] and sql['metadata_lost']==0,'durable held count/loss mismatch'
    return elapsed,flags
def wait_rows(database,expected):
    deadline=time.monotonic()+20
    while time.monotonic()<deadline:
        assert monitor.poll() is None,'observer exited during churn'
        try:
            with sqlite3.connect(database,timeout=1) as conn:actual=conn.execute('SELECT COUNT(*) FROM events').fetchone()[0]
        except sqlite3.OperationalError:actual=0
        if actual==expected:return
        assert actual<=expected,f'unexpected durable count {actual}>{expected}'
        time.sleep(.02)
    raise AssertionError(f'churn stopped progressing: {actual}!={expected}')
print('| Binary | Workload | n | mean ms | median ms | p95 ms | max ms |',flush=True)
print('|---|---|---:|---:|---:|---:|---:|',flush=True)
measurements=[]
try:
    for count in counts:
        for _ in range(count):open_pair()
        assert len(pairs)==count,'fixture readiness failed'
        for mode in ['no-dns-no-sqlite','default-dns-sqlite']:
            samples={label:[] for label,_,_ in binaries}
            for label,binary,_ in binaries:observe(label,binary,mode,count,'warmup')
            for index in range(passes):
                # Alternate order to expose rather than hide host drift.
                for label,binary,_ in (binaries if index%2==0 else list(reversed(binaries))):
                    elapsed,flags=observe(label,binary,mode,count,index);samples[label].append(elapsed)
                    measurements.append({'label':label,'mode':mode,'connections':count,'endpoint_count':2*count,'iteration':index,'elapsed_ms':elapsed,'flags':flags})
            for label,values in samples.items():
                print(f'| {label} | {mode}; {count} accepted TCP pairs | {passes} | {statistics.mean(values):.3f} | {statistics.median(values):.3f} | {sorted(values)[math.ceil(.95*len(values))-1]:.3f} | {max(values):.3f} |',flush=True)
        close_pairs()
    diversity=[int(value) for value in os.environ.get('BENCH_IP_COUNTS','').split(',') if value]
    pid_counts=[int(value) for value in os.environ.get('BENCH_PID_COUNTS','').split(',') if value]
    assert all(0<count<2**24 for count in diversity) and all(count>0 for count in pid_counts),'invalid diversity axis'
    for count in diversity:
        try:
            for index in range(1,count+1):
                address=socket.inet_ntoa((0x7f000001+index).to_bytes(4,'big'))
                endpoint=socket.socket();endpoint.bind((address,0));endpoint.listen()
                try:
                    client=socket.create_connection(endpoint.getsockname(),timeout=5);server,_=endpoint.accept();pairs.append((client,server))
                finally:endpoint.close()
            for label,binary,_ in binaries:
                elapsed,flags=observe(label,binary,'no-dns-no-sqlite',count,'ip-diversity')
                final,_=summary(root/f'{label}-no-dns-no-sqlite-{count}-ip-diversity.stdout')
                assert len(final['per_ip'])==count+1 and sum(final['per_ip'].values())==2*count,'lifetime IP statistics lost distinct actual peers'
                measurements.append({'label':label,'mode':'ip-diversity','peer_ips':count+1,'endpoint_count':2*count,'elapsed_ms':elapsed,'flags':flags})
                print(f'{label} IP diversity={count+1}: {2*count} exact held endpoints, all lifetime peer counts retained, {elapsed:.3f}ms invocation',flush=True)
        finally:close_pairs()
    holder_code="import json,os,socket,sys;listener=socket.socket();listener.bind(('127.0.0.1',0));listener.listen();client=socket.create_connection(listener.getsockname());server,_=listener.accept();print(json.dumps({'pid':os.getpid()}),flush=True);sys.stdin.read(1)"
    for count in pid_counts:
        holders=[]
        try:
            pids=[]
            for _ in range(count):
                holder=subprocess.Popen([sys.executable,'-u','-c',holder_code],stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True);holders.append(holder)
                assert select.select([holder.stdout],[],[],10)[0],'PID fixture did not become ready'
                pids.append(json.loads(holder.stdout.readline())['pid'])
            for ancestry in [False,True]:
                for label,binary,_ in binaries:
                    flags=['--no-config','--no-descendants','--no-dns','--no-sqlite','--once','--json','--no-banner','--stats-interval-ms','0']
                    for pid in pids:flags+=['--pid',str(pid)]
                    if ancestry:flags.append('--show-ancestry')
                    started=time.monotonic_ns();result=subprocess.run([str(binary),*flags],capture_output=True,text=True,timeout=60);elapsed=(time.monotonic_ns()-started)/1e6
                    output=root/f'{label}-pids-{count}-ancestry-{ancestry}.stdout';output.write_text(result.stdout);output.with_suffix('.stderr').write_text(result.stderr)
                    assert result.returncode==0,result.stderr
                    final,rows=summary(output);opens=[row for row in rows if row.get('event')=='connect']
                    assert final['connects']==final['active']==len(opens)==2*count and final['closes']==0 and set(final['per_pid'])==set(map(str,pids)) and all(value==2 for value in final['per_pid'].values()),'physical PID endpoints/lifetime identities lost'
                    if ancestry:assert all(any(item.endswith('('+str(os.getpid())+')') for item in row['ancestry']) for row in opens),'actual parent missing from ancestry'
                    else:assert all('ancestry' not in row for row in opens),'ancestry disabled path still emitted it'
                    measurements.append({'label':label,'mode':'pid-diversity','pids':count,'ancestry':ancestry,'endpoint_count':2*count,'elapsed_ms':elapsed,'flags':flags})
                    print(f'{label} PID diversity={count}, ancestry={ancestry}: {2*count} exact endpoints/identities, {elapsed:.3f}ms invocation',flush=True)
        finally:
            for holder in holders:
                if holder.poll() is None:holder.stdin.write('x');holder.stdin.flush();holder.wait(timeout=5)
    for label,binary,_ in binaries:
        for batch in [200,1000]:
            database=root/f'{label}-churn-{batch}.sqlite';output=root/f'{label}-churn-{batch}.stdout';operations=[]
            flags=['--no-config','--pid',str(os.getpid()),'--no-descendants','--no-dns','--interval-ms','20','--db-flush-ms','50','--db-batch-size',str(batch),'--sqlite',str(database),'--no-banner','--json','--stats-interval-ms','0']
            with output.open('w') as stdout,output.with_suffix('.stderr').open('w') as stderr:
                open_pair();started=time.monotonic()
                monitor=subprocess.Popen([str(binary),*flags],stdout=stdout,stderr=stderr)
                wait_rows(database,2);close_pairs();wait_rows(database,4);generated=1
                deadline=time.monotonic()+duration
                while time.monotonic()<deadline:
                    tick=time.monotonic();open_pair();wait_rows(database,generated*4+2)
                    close_pairs();generated+=1;wait_rows(database,generated*4)
                    operations.append((time.monotonic()-tick)*1000)
                monitor.send_signal(signal.SIGINT);assert monitor.wait(timeout=20)==0,'churn observer finalized unhealthy'
                elapsed=time.monotonic()-started;monitor=None
            final,_=summary(output);sql=final['sqlite']
            assert final['connects']==final['closes']==generated*2 and sql['observed']==sql['persisted']==generated*4 and not sql['failed'] and sql['metadata_lost']==0,'churn counters/loss do not reconcile'
            with sqlite3.connect(database) as conn:
                assert conn.execute('SELECT COUNT(*) FROM events').fetchone()[0]==generated*4,'churn durable count mismatch'
            assert operations,'no progressing churn interval measured'
            measurements.append({'label':label,'mode':'durable-churn','batch':batch,'generated':generated,'accepted':generated,'rows':generated*4,'elapsed_seconds':elapsed,'rows_per_second':generated*4/elapsed,'operation_ms':operations,'flags':flags})
            print(f'{label} batch={batch}: {generated} generated=accepted pairs, {generated*4} exact durable rows, {elapsed:.3f}s, {generated*4/elapsed:.3f} rows/s; paced workload, not writer capacity',flush=True)
finally:
    close_pairs();listener.close()
    if monitor is not None and monitor.poll() is None:
        monitor.send_signal(signal.SIGINT);monitor.wait(timeout=20)
    (root/'measurements.json').write_text(json.dumps(measurements,indent=2))
print('PASS all commands, expected nonzero sockets, accepted progress and exact durable accounting; timing is observational, no speedup qualification',flush=True)
PY
