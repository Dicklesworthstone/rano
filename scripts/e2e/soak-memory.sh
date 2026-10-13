#!/usr/bin/env bash
# Real accepted TCP churn, interval progress, RSS and durable count conservation.
# SOAK_SECS<600 is a smoke test, never long-session qualification.

set -euo pipefail

SOAK_SECS="${SOAK_SECS:-600}"
RANO="${SOAK_RANO:-${RANO:-${E2E_RANO_DEBUG}}}"

e2e_section "Setup"
e2e_info "rano=${RANO}"
e2e_info "soak_secs=${SOAK_SECS}"

if [ ! -x "${RANO}" ]; then
    e2e_fail "rano binary not found at ${RANO}. Run 'cargo build' first."
fi

python3 - "${RANO}" "${SOAK_SECS}" "${E2E_OUTPUT_DIR}" <<'PY' || e2e_fail "soak progress, summary or conservation failed"
import hashlib,json,os,pathlib,platform,select,signal,sqlite3,subprocess,sys,tempfile,time
binary=sys.argv[1];duration=float(sys.argv[2]);assert duration>=15,'smoke duration must allow at least three progress intervals'
root=pathlib.Path(tempfile.mkdtemp(prefix='soak-',dir=sys.argv[3]));print(f'retained fixtures={root}',flush=True)
code=r'''
import json,os,select,socket,sys,time
listener=socket.socket();listener.bind(('127.0.0.1',int(sys.argv[1])));listener.listen()
listener.settimeout(2);started=time.monotonic();produced=accepted=0;held=[]
stall_after=float(sys.argv[2]);print(json.dumps({'pid':os.getpid(),'port':listener.getsockname()[1]}),flush=True)
while True:
    now=time.monotonic()
    if stall_after<0 or now-started<stall_after:
        for _ in range(5):
            client=socket.create_connection(listener.getsockname(),timeout=2);produced+=1
            server,_=listener.accept();accepted+=1;held.append((now,client,server))
    while held and now-held[0][0]>=3:
        _,client,server=held.pop(0);client.close();server.close()
    if select.select([sys.stdin],[],[],.25)[0]:
        command=sys.stdin.readline().strip()
        if command=='stop':break
        print(json.dumps({'generated':produced,'accepted':accepted,'elapsed':time.monotonic()-started}),flush=True)
'''
holder_log=open(root/'holder.stderr','w')
holder=subprocess.Popen([sys.executable,'-u','-c',code,os.environ.get('SOAK_PORT','0'),os.environ.get('SOAK_STALL_AFTER','-1'),'claude'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=holder_log,text=True)
monitor=None;out=None;err=None
def progress():
    assert holder.poll() is None,'generator exited'
    holder.stdin.write('progress\n');holder.stdin.flush()
    assert select.select([holder.stdout],[],[],3)[0],'generator stalled without progress response'
    return json.loads(holder.stdout.readline())
def validate_summary(records):
    summaries=[row['summary'] for row in records if 'summary' in row]
    assert len(summaries)==1,'missing or duplicated final summary'
    summary=summaries[0];durable=summary['sqlite']
    assert summary['connects']>0 and summary['closes']>0,'no observed churn'
    assert summary['observation_errors']==0 and not summary['log_failed'],'unhealthy observation/log sink'
    assert durable['enabled'] and not durable['failed'],'SQLite disabled or failed'
    assert summary['sqlite_dropped']==durable['queue_lost']+durable['write_lost']==0,'durable losses'
    assert durable['observed']==durable['persisted']==summary['connects']+summary['closes'],'durable count mismatch'
    return summary
try:
    assert select.select([holder.stdout],[],[],5)[0],'fixture never became ready'
    ready=json.loads(holder.stdout.readline());initial=progress()
    assert initial['generated']==initial['accepted']>0,'fixture does not accept actual connections'
    command=[binary,'--no-config','--pid',str(ready['pid']),'--no-descendants','--interval-ms','100',
        '--no-dns','--no-banner','--sqlite',str(root/'events.sqlite'),'--log-format','json','--log-file',str(root/'events.jsonl'),'--json','--stats-interval-ms','10000']
    source=os.environ.get('SOAK_SOURCE_REVISION')
    if duration>=600:assert source,'long run requires SOAK_SOURCE_REVISION bound to the binary build receipt'
    metadata={'host':platform.node(),'platform':platform.platform(),'binary_sha256':hashlib.sha256(pathlib.Path(binary).read_bytes()).hexdigest(),
        'binary_source':source,'workspace_revision':subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip(),
        'configured_toolchain':pathlib.Path('rust-toolchain.toml').read_text(),'command':command,'duration_secs':duration,'long_duration':duration>=600}
    (root/'invocation.json').write_text(json.dumps(metadata,indent=2));print(json.dumps(metadata),flush=True)
    out=open(root/'stdout.jsonl','w');err=open(root/'stderr','w');monitor=subprocess.Popen(command,stdout=out,stderr=err)
    started=time.monotonic();samples=[];previous=initial;previous_rows=None
    while time.monotonic()-started<duration:
        time.sleep(min(5,max(0,duration-(time.monotonic()-started))))
        assert monitor.poll() is None,'monitor exited before duration'
        current=progress();assert current['generated']==current['accepted']>previous['generated'],'generator stopped making accepted progress'
        rss_fields=pathlib.Path(f'/proc/{monitor.pid}/status').read_text().splitlines()
        rss=int(next(line.split()[1] for line in rss_fields if line.startswith('VmRSS:')))
        assert rss>0,'missing RSS observation'
        with sqlite3.connect(root/'events.sqlite',timeout=10) as conn:rows=conn.execute('SELECT COUNT(*) FROM events').fetchone()[0]
        if previous_rows is not None:assert rows>previous_rows,'durable observations stopped progressing'
        sample={'elapsed':time.monotonic()-started,'rss_kb':rss,'durable_rows':rows,**current};samples.append(sample)
        with open(root/'progress.jsonl','a') as stream:stream.write(json.dumps(sample)+'\n')
        print(json.dumps(sample),flush=True);previous=current;previous_rows=rows
    monitor.send_signal(signal.SIGTERM);status=monitor.wait(timeout=20);out.close();err.close();out=err=None
    assert status==0,f'monitor exited {status}; inspect retained stderr'
    final_progress=progress()
    records=[json.loads(line) for line in (root/'stdout.jsonl').read_text().splitlines() if line.strip()]
    if os.environ.get('SOAK_OMIT_SUMMARY')=='1':
        records=[row for row in records if 'summary' not in row]
        (root/'validation-without-summary.jsonl').write_text(''.join(json.dumps(row)+'\n' for row in records))
    summary=validate_summary(records)
    try:validate_summary([row for row in records if 'summary' not in row])
    except AssertionError:pass
    else:raise AssertionError('missing-summary negative control was accepted')
    with sqlite3.connect(root/'events.sqlite') as conn:
        counts=dict(conn.execute('SELECT event,COUNT(*) FROM events GROUP BY event'))
        assert counts.get('connect',0)==summary['connects'] and counts.get('close',0)==summary['closes'],'SQLite event counts disagree with summary'
        assert sum(counts.values())==summary['sqlite']['persisted'],'persisted counter differs from actual rows'
        session=conn.execute('SELECT connects,closes,end_ts FROM sessions').fetchall()
        assert len(session)==1 and session[0][:2]==(summary['connects'],summary['closes']) and session[0][2],'session was not finalized accurately'
    assert summary['connects']<=2*final_progress['generated'],'observer invented endpoint episodes'
    reference=next((sample for sample in samples if sample['elapsed']>=60),samples[0]);final=samples[-1]
    assert final['rss_kb']<=2*reference['rss_kb'],'final RSS exceeds unchanged 2x baseline gate'
    print(f"PASS {'long-session workload' if duration>=600 else 'smoke only'}: accepted progress throughout {duration}s; {summary['sqlite']['persisted']} exact durable rows; RSS {reference['rss_kb']}->{final['rss_kb']}KB; peak {max(sample['rss_kb'] for sample in samples)}KB",flush=True)
finally:
    if monitor is not None and monitor.poll() is None:
        monitor.send_signal(signal.SIGTERM)
        try:monitor.wait(timeout=20)
        except subprocess.TimeoutExpired:monitor.kill();monitor.wait(timeout=5)
    if holder.poll() is None:
        holder.stdin.write('stop\n');holder.stdin.flush()
        try:holder.wait(timeout=5)
        except subprocess.TimeoutExpired:holder.kill();holder.wait(timeout=5)
    if out is not None:out.close()
    if err is not None:err.close()
    holder_log.close()
PY
