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

if [[ "${SOAK_PTR_PROBE:-0}" == 1 ]]; then
    e2e_section "Actual system PTR resolver stalled behind a private DNS server"
    python3 - "$RANO" "$E2E_OUTPUT_DIR" <<'PY' || e2e_fail "Real slow/failing PTR responsiveness and late-sink proof failed"
import os,pathlib,subprocess,sys,tempfile
root=pathlib.Path(tempfile.mkdtemp(prefix='ptr-system-',dir=sys.argv[2])).resolve()
(root/'resolv.conf').write_text('nameserver 127.0.0.1\noptions timeout:2 attempts:1\n')
code=r'''
import hashlib,json,os,pathlib,signal,socket,sqlite3,struct,subprocess,sys,threading,time
binary,root,baseline=sys.argv[1],pathlib.Path(sys.argv[2]),sys.argv[3]=='baseline'
failure=sys.argv[4]=='failure'
dns=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);dns.bind(('127.0.0.1',53));dns.settimeout(.1)
requested=threading.Event();release=threading.Event();stop=threading.Event();queries=[]
def server():
    while not stop.is_set():
        try:query,peer=dns.recvfrom(4096)
        except socket.timeout:continue
        queries.append(query.hex());requested.set()
        if not release.wait(10):return
        end=12
        while query[end]:end+=query[end]+1
        end+=5
        name=b''.join(bytes([len(label)])+label for label in [b'late',b'ptr',b'fixture',b'test'])+b'\0'
        if failure:response=query[:2]+struct.pack('!HHHHH',0x8183,1,0,0,0)+query[12:end]
        else:response=query[:2]+struct.pack('!HHHHH',0x8180,1,1,0,0)+query[12:end]+b'\xc0\x0c'+struct.pack('!HHIH',12,1,30,len(name))+name
        dns.sendto(response,peer)
thread=threading.Thread(target=server,daemon=True);thread.start()
listener=socket.socket();listener.bind(('127.0.0.2',0));listener.listen();client=socket.create_connection(listener.getsockname());accepted,_=listener.accept()
database=root/'events.sqlite';file_log=root/'events.jsonl'
out=open(root/'stdout.jsonl','w');err=open(root/'stderr','w')
command=[binary,'--no-config','--pid',str(os.getpid()),'--no-descendants','--no-udp','--interval-ms','50','--stats-interval-ms','0','--no-banner','--json','--sqlite',str(database),'--log-file',str(file_log),'--log-format','json']
process=subprocess.Popen(command,stdout=out,stderr=err)
try:
    assert requested.wait(8),'system resolver never queried the private DNS server'
    samples=[];deadline=time.monotonic()+1
    while time.monotonic()<deadline:
        with sqlite3.connect(database) as conn:
            samples.append(conn.execute('SELECT last_poll_ts,active_at_poll,poll_valid FROM sessions').fetchone())
        time.sleep(.05)
    rows=[json.loads(line) for line in (root/'stdout.jsonl').read_text().splitlines()]
    opens=[row for row in rows if row.get('event')=='connect']
    if baseline:
        assert not opens and not any(row[0] for row in samples),'baseline no longer blocks its first poll on actual PTR'
    else:
        assert len(opens)==2,'blocking PTR hid actual socket observations'
        assert len({row[0] for row in samples if row[0]})>=2 and all(row[1:]==(2,1) for row in samples if row[0]),'poll publication stopped behind PTR'
        status=subprocess.run([binary,'status','--sqlite',str(database),'--format','{active}|{state}'],capture_output=True,text=True,timeout=5)
        assert status.returncode==0 and status.stdout.strip()=='2|fresh','actual held activity became stale during PTR'
    release.set();deadline=time.monotonic()+8
    while not failure and time.monotonic()<deadline:
        rows=[json.loads(line) for line in (root/'stdout.jsonl').read_text().splitlines()]
        attributed=[row for row in rows if row.get('domain')=='late.ptr.fixture.test' and row.get('event') in ['connect','domain_update']]
        if attributed:break
        assert process.poll() is None,'observer exited before successful PTR result'
        time.sleep(.05)
    else:
        if not failure:raise AssertionError('released actual PTR response was not associated')
        time.sleep(1)
    process.send_signal(signal.SIGTERM);assert process.wait(timeout=10)==0
    out.close();err.close()
    rows=[json.loads(line) for line in (root/'stdout.jsonl').read_text().splitlines()];summary=next(row['summary'] for row in rows if 'summary' in row)
    assert summary['connects']==2 and summary['closes']==0 and summary['sqlite']['observed']==summary['sqlite']['persisted']==2 and summary['sqlite_dropped']==0,'PTR invented events or lost durable sockets'
    if failure:
        assert not baseline and summary['ptr']['unresolved']==1 and summary['ptr']['pending']==0 and not summary['ptr']['failed'],'actual NXDOMAIN did not complete as explicit unresolved result'
        with sqlite3.connect(database) as conn:assert conn.execute("SELECT COUNT(*) FROM events WHERE event='connect' AND remote_ip='127.0.0.2' AND domain='unknown' AND domain_source IS NULL").fetchone()[0]==1,'failed PTR invented hostname evidence'
        assert 'late.ptr.fixture.test' not in summary['per_domain'],'failed PTR polluted lifetime names'
    elif not baseline:
        assert len(attributed)==1 and attributed[0]['event']=='domain_update' and attributed[0]['domain_source']=='ptr','late PTR did not use correction provenance'
        assert json.loads(attributed[0]['ownership_json'])['domain_evidence']['scope']=='reverse-ip','PTR claimed captured hostname evidence'
        with sqlite3.connect(database) as conn:assert conn.execute("SELECT COUNT(*) FROM events WHERE event='connect' AND domain='late.ptr.fixture.test' AND domain_source='ptr'").fetchone()[0]==1,'durable original connect was not corrected'
        logged=list(map(json.loads,file_log.read_text().splitlines()));assert len([row for row in logged if row.get('event')=='domain_update' and row.get('domain')=='late.ptr.fixture.test'])==1,'file log lost late PTR'
        exported=subprocess.run([binary,'export','--sqlite',str(database),'--format','jsonl'],capture_output=True,text=True,timeout=5)
        assert exported.returncode==0 and len([row for row in map(json.loads,exported.stdout.splitlines()) if row['domain']=='late.ptr.fixture.test' and row['domain_source']=='ptr'])==1,'export lost corrected PTR'
        report=json.loads(subprocess.check_output([binary,'report','--sqlite',str(database),'--json'],text=True));assert any(row['domain']=='late.ptr.fixture.test' and row['events']==1 for row in report['top_domains']),'report lost corrected PTR'
        assert summary['per_domain']['late.ptr.fixture.test']==1 and not summary['ptr']['failed'] and summary['ptr']['pending']==0,'lifetime stats or resolver completion disagree'
    (root/'receipt.json').write_text(json.dumps({'binary_sha256':hashlib.sha256(pathlib.Path(binary).read_bytes()).hexdigest(),'baseline':baseline,'queries':queries,'poll_samples':samples,'connects':summary['connects']},indent=2))
    print('PASS '+('real NXDOMAIN remains unresolved with healthy advancing polls and exact durable counts' if failure else 'baseline blocks first poll on actual delayed PTR' if baseline else 'real delayed system PTR preserves advancing fresh polls and corrects live/file/SQLite/export/report/lifetime statistics'),flush=True)
finally:
    release.set();stop.set()
    if process.poll() is None:process.send_signal(signal.SIGTERM);process.wait(timeout=10)
    thread.join(timeout=1)
    client.close();accepted.close();listener.close();dns.close()
    if not out.closed:out.close()
    if not err.closed:err.close()
'''
isolate='set -euo pipefail\nmount --make-rprivate /\nmount --bind "$1" /etc/resolv.conf\nip link set lo up\nshift\nexec "$@"'
for label,binary in [('candidate',sys.argv[1]),('baseline',os.environ.get('RANO_PTR_BASELINE'))]:
    if binary is None:continue
    destination=root/label;destination.mkdir()
    reply=os.environ.get('SOAK_PTR_REPLY','success');assert reply in ['success','failure'],'invalid SOAK_PTR_REPLY'
    result=subprocess.run(['sudo','-n','unshare','--mount','--net','--fork','bash','-c',isolate,'ptr-system-test',str(root/'resolv.conf'),sys.executable,'-u','-c',code,str(pathlib.Path(binary).resolve()),str(destination),label,reply],capture_output=True,text=True,timeout=35)
    (destination/'probe.stdout').write_text(result.stdout);(destination/'probe.stderr').write_text(result.stderr)
    assert result.returncode==0,f'{label} failed: {result.stdout}\n{result.stderr}'
    print(result.stdout,flush=True)
print('Retained real resolver evidence: '+str(root),flush=True)
PY
    return 0
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
    mode=os.environ.get('SOAK_DOMAIN_MODE','disabled');assert mode in ['disabled','ptr','pcap'],'invalid SOAK_DOMAIN_MODE'
    command=[binary,'--no-config','--pid',str(ready['pid']),'--no-descendants','--interval-ms','100',
        '--no-banner','--sqlite',str(root/'events.sqlite'),'--log-format','json','--log-file',str(root/'events.jsonl'),'--json','--stats-interval-ms','10000']
    if mode=='disabled':command.append('--no-dns')
    if mode=='pcap':command+=['--pcap','--pcap-interface','lo']
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
    assert summary['domain_mode']==mode,'requested domain mode did not actually run'
    if mode in ['ptr','pcap']:
        ptr=summary['ptr'];assert not ptr['failed'] and ptr['requested']>0 and ptr['completed']>0,'resolver never completed real requests'
        assert ptr['pending']<=ptr['queue_capacity']+ptr['workers'] and ptr['cached']<=ptr['cache_max'],'PTR scratch limits exceeded'
    if mode=='pcap':
        health=summary['pcap'];assert not health['offline'] and health['packets']>0 and not health['unhealthy'],'live pcap unavailable, inactive or unhealthy'
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
