#!/usr/bin/env bash
# E2E Test: pcap attribution + fallback logging
#
# Verifies:
# - Offline pcap fixtures can drive domain attribution in --pcap mode
# - Privilege failure in pcap mode logs warnings and falls back to PTR
# - Logs include fixture path, expected domains, actual domains, and warnings

set -euo pipefail

RANO="${RANO:-${E2E_RANO_DEBUG}}"
if [ ! -x "${RANO}" ]; then
  e2e_fail "Compiled pcap-enabled rano not found: ${RANO}"
fi

e2e_section "Actual libpcap replay, loss, frame and fallback checks"
python3 - "${RANO}" "${E2E_OUTPUT_DIR}" <<'PY' || e2e_fail "pcap attribution/health proof failed"
import json,os,pathlib,select,signal,socket,sqlite3,struct,subprocess,sys,tempfile,time
binary=str(pathlib.Path(sys.argv[1]).resolve());root=pathlib.Path(tempfile.mkdtemp(prefix='pcap-attribution-',dir=sys.argv[2]))
print(f'retained fixtures={root}',flush=True)
holder_code=r'''
import json,os,socket,sys
listener=socket.socket();listener.bind(('127.0.0.1',0));listener.listen()
client=socket.create_connection(listener.getsockname());accepted,_=listener.accept()
print(json.dumps({'pid':os.getpid(),'port':listener.getsockname()[1]}),flush=True)
sys.stdin.read(1)
'''
holder=subprocess.Popen([sys.executable,'-u','-c',holder_code,'claude'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True)
assert select.select([holder.stdout],[],[],5)[0],'socket fixture never became ready'
ready=json.loads(holder.stdout.readline())
def dns_packet(name='fixture.test',answer='127.0.0.1',ttl=30):
    encoded=b''.join(bytes([len(label)])+label.encode('ascii') for label in name.split('.'))+b'\0'
    dns=struct.pack('!HHHHHH',1,0x8180,1,1,0,0)+encoded+struct.pack('!HH',1,1)+b'\xc0\x0c'+struct.pack('!HHIH',1,1,ttl,4)+socket.inet_aton(answer)
    udp=struct.pack('!HHHH',53,53000,8+len(dns),0)+dns
    ip=struct.pack('!BBHHHBBH4s4s',0x45,0,20+len(udp),1,0x4000,64,17,0,socket.inet_aton('8.8.8.8'),socket.inet_aton('127.0.0.1'))
    return bytes.fromhex('00112233445566778899aabb0800')+ip+udp
def capture(name,packets,link=1,tail=b'',age=0):
    path=root/name
    with path.open('wb') as output:
        output.write(struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,65535,link))
        for packet in packets:
            now=time.time()-age;seconds=int(now);micros=int((now-seconds)*1000000)
            output.write(struct.pack('<IIII',seconds,micros,len(packet),len(packet)));output.write(packet)
        output.write(tail)
    return path
def run(label,arguments,fixture=None,success=True,live_target=True,ptr=False):
    env=dict(os.environ);env.pop('RANO_PCAP_FILE',None)
    if fixture is not None:env['RANO_PCAP_FILE']=str(fixture)
    args=[binary,'--no-config','--no-descendants','--json','--no-banner','--stats-interval-ms','0','--pcap',*arguments]
    if ptr:args+=['--interval-ms','50']
    else:args.append('--once')
    if not ptr:args.append('--no-dns')
    args+=['--pid',str(ready['pid'])] if live_target else ['--pattern','nonexistent-pcap-fixture-root']
    if ptr:
        with open(root/f'{label}.live.jsonl','w') as output,open(root/f'{label}.live.stderr','w') as errors:
            process=subprocess.Popen(args,stdout=output,stderr=errors,env=env)
            try:
                deadline=time.monotonic()+10
                while time.monotonic()<deadline:
                    rows=[json.loads(line) for line in (root/f'{label}.live.jsonl').read_text().splitlines()]
                    if len([row for row in rows if row.get('event')=='domain_update' and row.get('domain_source')=='ptr'])==2:break
                    assert process.poll() is None,'PTR monitor exited before late attribution'
                    time.sleep(.05)
                else:raise AssertionError('both held endpoints never received late PTR attribution')
            finally:
                if process.poll() is None:process.send_signal(signal.SIGTERM)
                process.wait(timeout=20)
        result=subprocess.CompletedProcess(args,process.returncode,(root/f'{label}.live.jsonl').read_text(),(root/f'{label}.live.stderr').read_text())
    else:result=subprocess.run(args,capture_output=True,text=True,env=env,timeout=30)
    (root/f'{label}.stdout.jsonl').write_text(result.stdout);(root/f'{label}.stderr').write_text(result.stderr)
    assert (result.returncode==0)==success,f'{label}: status={result.returncode}; stderr={result.stderr}'
    records=list(map(json.loads,result.stdout.splitlines()));summary=next(row['summary'] for row in records if 'summary' in row)
    return result,records,summary
try:
    database=root/'dns.sqlite';file_log=root/'dns.file.jsonl'
    result,records,summary=run('dns',['--sqlite',str(database),'--log-file',str(file_log),'--log-format','json'],capture('dns.pcap',[dns_packet()]))
    assert summary['domain_mode']=='pcap' and 'pcap' in summary,'this proof requires a pcap-enabled binary'
    connects=[row for row in records if row.get('event')=='connect']
    assert len(connects)==2 and all(row['domain']=='fixture.test' and row['domain_source']=='dns' for row in connects),'actual held endpoints did not receive DNS provenance'
    health=summary['pcap'];assert health['state']=='complete' and health['offline'] and health['mappings']==health['delivered']==health['drained']==1 and health['mapping_lost']==0 and not health['unhealthy'],'offline completion accounting incorrect'
    file_records=list(map(json.loads,file_log.read_text().splitlines()));assert next(row['summary'] for row in file_records if 'summary' in row)['pcap']==health,'file summary lost capture health'
    with sqlite3.connect(database) as conn:
        assert conn.execute("SELECT COUNT(*) FROM events WHERE event='connect' AND domain='fixture.test' AND domain_source='dns'").fetchone()[0]==2,'SQLite lost actual attributed endpoints'
    export=subprocess.run([binary,'export','--sqlite',str(database),'--format','jsonl'],capture_output=True,text=True,timeout=10)
    (root/'dns.export.jsonl').write_text(export.stdout);(root/'dns.export.stderr').write_text(export.stderr)
    assert export.returncode==0 and len(list(map(json.loads,export.stdout.splitlines())))==2,'attributed export failed'
    print('PASS ready dynamic held sockets: live JSON/file/SQLite/export retain fixture.test/dns and healthy offline EOF',flush=True)

    for index,tags in enumerate([(0x8100,),(0x88a8,),(0x9100,),(0x88a8,0x8100),(0x8100,0x9100)]):
        packet=dns_packet();tagged=packet[:12]+b''.join(struct.pack('!HH',tag,100+position) for position,tag in enumerate(tags))+packet[12:]
        _,records,summary=run(f'vlan-{index}',['--no-sqlite'],capture(f'vlan-{index}.pcap',[tagged]))
        connects=[row for row in records if row.get('event')=='connect']
        assert summary['pcap']['mappings']==summary['pcap']['drained']==1 and len(connects)==2 and all(row['domain']=='fixture.test' and row['domain_source']=='dns' for row in connects),f'supported VLAN tags {tags} were filtered out before parsing'
    print('PASS actual libpcap filter admits supported single/stacked802.1Q/802.1ad/9100 VLAN DNS frames',flush=True)

    ambiguous=capture('ambiguous-dns.pcap',[dns_packet('a.fixture.test'),dns_packet('b.fixture.test')])
    _,records,_=run('ambiguous-dns',['--no-sqlite'],ambiguous)
    connects=[row for row in records if row.get('event')=='connect']
    assert len(connects)==2 and all(row['domain']=='unknown' and 'domain_source' not in row for row in connects),'host-global ambiguity became a process-specific hostname'
    assert all(json.loads(row['ownership_json'])['domain_evidence']['dns_ambiguous'] and json.loads(row['ownership_json'])['domain_evidence']['dns_candidates']==['a.fixture.test','b.fixture.test'] for row in connects),'DNS candidates or scope lost'
    expected_ptr=socket.getnameinfo(('127.0.0.1',443),socket.NI_NAMEREQD)[0]
    _,records,ptr_summary=run('ambiguous-dns-ptr',['--no-sqlite'],ambiguous,ptr=True)
    connects=[row for row in records if row.get('event')=='connect']
    updates=[row for row in records if row.get('event')=='domain_update']
    assert len(connects)==2 and all(row['domain']=='unknown' and 'domain_source' not in row for row in connects),'initial poll waited on PTR'
    assert len(updates)==2 and all(row['domain']==expected_ptr and row['domain_source']=='ptr' and json.loads(row['ownership_json'])['domain_evidence']['scope']=='reverse-ip' and json.loads(row['ownership_json'])['domain_evidence']['dns_ambiguous'] for row in updates),'late PTR fallback erased ambiguity or claimed DNS provenance'
    assert ptr_summary['connects']==2 and ptr_summary['closes']==0 and ptr_summary['ptr']['requested']==ptr_summary['ptr']['completed']==1,'late resolution duplicated socket events or PTR requests'
    for label,fixture in [('expired-dns',capture('expired-dns.pcap',[dns_packet(ttl=1)],age=2)),('zero-ttl-dns',capture('zero-ttl-dns.pcap',[dns_packet(ttl=0)])),('future-dns',capture('future-dns.pcap',[dns_packet()],age=-60))]:
        _,records,_=run(label,['--no-sqlite'],fixture)
        connects=[row for row in records if row.get('event')=='connect']
        assert len(connects)==2 and all(row['domain']=='unknown' and 'domain_source' not in row for row in connects),f'{label} supplied untrustworthy cached evidence'
    print('PASS actual captured DNS multi-name ambiguity, independently resolved PTR fallback, observed short/zero TTL and future-time refusal',flush=True)

    large=capture('large-3001.pcap',[dns_packet(answer=f'10.0.{index//256}.{index%256}') for index in range(3000)]+[dns_packet()])
    _,records,summary=run('large-replay',['--no-sqlite'],large)
    health=summary['pcap'];assert health['mappings']==health['delivered']==health['drained']==3001 and health['mapping_lost']==0 and health['state']=='complete' and not health['unhealthy'],'large replay silently discarded mappings'
    assert len([row for row in records if row.get('event')=='connect' and row['domain']=='fixture.test'])==2,'large replay broke positive attribution'
    print('PASS actual libpcap3001-mapping --once replay exceeds1000 queue capacity with zero loss',flush=True)
    baseline=os.environ.get('RANO_PCAP_BASELINE')
    if baseline:
        env=dict(os.environ,RANO_PCAP_FILE=str(large))
        old=subprocess.run([baseline,'--no-config','--pid',str(ready['pid']),'--no-descendants','--once','--json','--no-banner','--no-dns','--no-sqlite','--pcap'],capture_output=True,text=True,env=env,timeout=30)
        (root/'baseline-large.stdout.jsonl').write_text(old.stdout);(root/'baseline-large.stderr').write_text(old.stderr)
        old_connects=[row for row in map(json.loads,old.stdout.splitlines()) if row.get('event')=='connect']
        assert old.returncode==0 and len(old_connects)==2 and all(row['domain']!='fixture.test' for row in old_connects),'baseline failed to reproduce the dropped tail mapping'
        print('PASS declared baseline executes same3001-packet replay and misses the last relevant mapping; candidate retains it',flush=True)

    for label,fixture,expected in [
        ('unsupported-link',capture('raw-ip.pcap',[dns_packet()[14:]],101),'unsupported pcap datalink'),
        ('missing-file',root/'missing.pcap','pcap file metadata failed')]:
        result,_,summary=run(label,['--no-sqlite'],fixture)
        assert expected in result.stderr and summary['domain_mode']=='disabled','startup refusal did not report honest fallback'
    result,_,summary=run('missing-interface',['--no-sqlite','--pcap-interface','rano-nonexistent-interface'])
    assert 'not found' in result.stderr and summary['domain_mode']=='disabled','missing interface was silent'
    broken=capture('truncated.pcap',[dns_packet()],tail=b'\x01\x02\x03')
    result,records,summary=run('runtime-read-error',['--no-sqlite'],broken,False)
    assert summary['pcap']['state']=='failed' and summary['pcap']['error'] and summary['domain_mode']=='disabled','fatal libpcap read error did not degrade visibly'
    assert 'pcap capture degraded' in result.stderr and len([row for row in records if row.get('event')=='connect'])==2,'fatal capture error hid valid socket observations'
    print('PASS unsupported raw link, absent file/interface, real truncated-dump read failure and continuing valid socket observations',flush=True)

    # The ordinary unprivileged process must retain the original permission
    # warning and PTR fallback behavior; select no targets to isolate capture.
    env=dict(os.environ);env.pop('RANO_PCAP_FILE',None)
    prefix=[]
    if os.geteuid()==0:prefix=['sudo','-n','-u','nobody']
    result=subprocess.run([*prefix,binary,'--no-config','--pattern','nonexistent-pcap-fixture-root','--once','--json','--no-banner','--no-sqlite','--pcap'],capture_output=True,text=True,env=env,timeout=20)
    (root/'permission.stdout.jsonl').write_text(result.stdout);(root/'permission.stderr').write_text(result.stderr)
    summary=next(row['summary'] for row in map(json.loads,result.stdout.splitlines()) if 'summary' in row)
    assert result.returncode==0 and summary['domain_mode']=='ptr' and 'pcap capture unavailable' in result.stderr and 'elevated privileges' in result.stderr,'permission warning/PTR fallback regression'
    print('PASS actual unprivileged permission warning and PTR fallback',flush=True)

    # A private network namespace keeps the live DNS fixture isolated from host
    # services. The actual libpcap worker must survive an idle interval first.
    live_helper=root/'live-idle.py'
    live_helper.write_text(r'''
import datetime,json,os,pathlib,signal,socket,sqlite3,struct,subprocess,sys,time
binary=sys.argv[1];root=pathlib.Path(sys.argv[2]);subprocess.run(['ip','link','set','lo','up'],check=True)
listener=socket.socket();listener.bind(('127.0.0.1',443));listener.listen()
client=socket.create_connection(listener.getsockname());accepted,_=listener.accept()
dns=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);dns.bind(('127.0.0.1',53))
request=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);request.bind(('127.0.0.1',0))
database=root/'live-idle.sqlite';stdout=open(root/'live-idle.stdout.jsonl','w');stderr=open(root/'live-idle.stderr','w')
monitor=subprocess.Popen([binary,'--no-config','--pid',str(os.getpid()),'--no-descendants','--no-udp','--no-dns','--no-banner','--json','--pcap','--pcap-interface','lo','--interval-ms','25','--sqlite',str(database)],stdout=stdout,stderr=stderr)
try:
    deadline=time.monotonic()+20
    while time.monotonic()<deadline:
        assert monitor.poll() is None,'monitor exited before idle capture proof'
        try:
            with sqlite3.connect(database,timeout=1) as conn:count=conn.execute("SELECT COUNT(*) FROM events WHERE event='connect'").fetchone()[0]
        except sqlite3.OperationalError:count=0
        if count==2:break
        time.sleep(.05)
    assert count==2,'held TCP endpoints were not persisted'
    time.sleep(.35)
    name=b'\x04idle\x07fixture\x04test\0'
    payload=struct.pack('!HHHHHH',1,0x8180,1,1,0,0)+name+struct.pack('!HH',1,1)+b'\xc0\x0c'+struct.pack('!HHIH',1,1,30,4)+socket.inet_aton('127.0.0.1')
    sent=datetime.datetime.now(datetime.timezone.utc).isoformat().replace('+00:00','Z')
    for _ in range(5):dns.sendto(payload,request.getsockname());time.sleep(.1)
    deadline=time.monotonic()+10
    while time.monotonic()<deadline:
        assert monitor.poll() is None,'monitor died during actual DNS capture'
        with sqlite3.connect(database,timeout=1) as conn:poll=conn.execute('SELECT last_poll_ts FROM sessions').fetchone()[0]
        if poll and datetime.datetime.fromisoformat(poll.replace('Z','+00:00'))>datetime.datetime.fromisoformat(sent.replace('Z','+00:00'))+datetime.timedelta(seconds=1):break
        time.sleep(.05)
    else:raise AssertionError('monitor did not keep polling after actual DNS response')
    monitor.send_signal(signal.SIGTERM);assert monitor.wait(timeout=15)==0,'live capture did not finalize healthy'
    stdout.close();stderr.close()
    summary=next(row['summary'] for row in map(json.loads,(root/'live-idle.stdout.jsonl').read_text().splitlines()) if 'summary' in row)
    health=summary['pcap']
    assert summary['domain_mode']=='pcap' and health['state']=='stopped' and not health['offline'] and health['idle_polls']>0,'worker did not survive idle timeouts'
    assert health['mappings']==health['delivered']==health['drained']>=5 and health['mapping_lost']==0 and not health['unhealthy'],'actual delayed DNS mappings were lost or never captured'
    assert summary['connects']==2 and summary['sqlite']['persisted']==summary['sqlite']['observed']==2,'capture metadata invented socket connections'
    print('PASS actual isolated libpcap live idle -> five delayed DNS responses -> healthy shutdown, two real endpoint rows',flush=True)
finally:
    if monitor.poll() is None:
        monitor.send_signal(signal.SIGTERM)
        try:monitor.wait(timeout=15)
        except subprocess.TimeoutExpired:monitor.kill();monitor.wait(timeout=5)
    stdout.close();stderr.close();request.close();dns.close();accepted.close();client.close();listener.close()
''')
    env=dict(os.environ);env.pop('RANO_PCAP_FILE',None)
    live=subprocess.run(['sudo','-n','unshare','-n','--',sys.executable,str(live_helper),binary,str(root),'claude'],capture_output=True,text=True,env=env,timeout=50)
    (root/'live-helper.stdout').write_text(live.stdout);(root/'live-helper.stderr').write_text(live.stderr)
    assert live.returncode==0,f'isolated real live capture failed: {live.stdout} {live.stderr}'
    print(live.stdout,flush=True)

    flow_helper=root/'flow-attribution.py'
    flow_helper.write_text(r'''
import json,os,pathlib,signal,socket,sqlite3,ssl,struct,subprocess,sys,time
binary=sys.argv[1];root=pathlib.Path(sys.argv[2]);baseline=sys.argv[3]
subprocess.run(['ip','link','set','lo','up'],check=True)
listener=socket.socket();listener.bind(('127.0.0.1',443));listener.listen()
clients=[];servers=[]
for _ in range(2):
    client=socket.socket();client.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);client.connect(listener.getsockname());server,_=listener.accept()
    clients.append(client);servers.append(server)
ports=[client.getsockname()[1] for client in clients];names=['a.audit.test','b.audit.test']
env=dict(os.environ);env.pop('RANO_PCAP_FILE',None)
def hello(name):
    output=ssl.MemoryBIO();session=ssl.create_default_context().wrap_bio(ssl.MemoryBIO(),output,server_hostname=name)
    try:session.do_handshake()
    except ssl.SSLWantReadError:pass
    return output.read()
def frame(port,name):
    payload=hello(name);tcp=struct.pack('!HHIIBBHHH',port,443,1,0,0x50,0x18,65535,0,0)+payload
    ip=struct.pack('!BBHHHBBH4s4s',0x45,0,20+len(tcp),1,0x4000,64,6,0,socket.inet_aton('127.0.0.1'),socket.inet_aton('127.0.0.1'))
    return bytes.fromhex('00112233445566778899aabb0800')+ip+tcp
def capture(label,entries,age=0):
    path=root/f'{label}.pcap'
    with path.open('wb') as output:
        output.write(struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,65535,1))
        for port,name in entries:
            packet=frame(port,name);now=time.time()-age;seconds=int(now);micros=int((now-seconds)*1000000)
            output.write(struct.pack('<IIII',seconds,micros,len(packet),len(packet)));output.write(packet)
    return path
def replay(label,fixture,executable=binary):
    result=subprocess.run([executable,'--no-config','--pid',str(os.getpid()),'--no-descendants','--once','--json','--no-banner','--no-dns','--no-sqlite','--pcap'],env=dict(env,RANO_PCAP_FILE=str(fixture)),capture_output=True,text=True,timeout=30)
    (root/f'{label}.stdout.jsonl').write_text(result.stdout);(root/f'{label}.stderr').write_text(result.stderr)
    assert result.returncode==0,f'{label}: {result.stderr}'
    records=list(map(json.loads,result.stdout.splitlines()));outbound=[row for row in records if row.get('event')=='connect' and row['remote']=='127.0.0.1:443']
    assert len(outbound)==2,'two actual held outbound endpoint tuples missing'
    return outbound
fixture=capture('two-flows',list(zip(ports,names)))
outbound=replay('two-flows',fixture)
expected=dict(zip(ports,names))
assert {int(row['local'].rsplit(':',1)[1]):row['domain'] for row in outbound}==expected,'remote-only cache conflated local ports'
assert all(row['domain_source']=='sni' and json.loads(row['ownership_json'])['domain_evidence']['scope']=='socket-tuple' and json.loads(row['ownership_json'])['domain_evidence']['capture_kind']=='offline' and json.loads(row['ownership_json'])['domain_evidence']['captured_at'] for row in outbound),'flow/capture provenance missing'
if baseline:
    old=replay('baseline-two-flows',fixture,baseline)
    assert all(row['domain']=='b.audit.test' for row in old),'baseline did not reproduce the declared same-server collision'
reversed_capture=capture('reversed-flow-order',list(zip(ports,names))[::-1])
assert {int(row['local'].rsplit(':',1)[1]):row['domain'] for row in replay('reversed-flow-order',reversed_capture)}==expected,'different-flow capture order changed attribution'
assert all(row['domain']=='unknown' for row in replay('expired-flow',capture('expired-flow',list(zip(ports,names)),601))),'expired replay resurrected SNI'
alien=next(port for port in range(1,65536) if port not in ports and port!=443)
assert all(row['domain']=='unknown' for row in replay('wrong-local-tuple',capture('wrong-local-tuple',[(alien,'wrong.audit.test')]))),'unrelated local port supplied a hostname'
print('PASS two actual held local ports/stdTLS ClientHello fixtures, reversed order, expired and wrong-tuple controls; offline scope explicit',flush=True)

database=root/'late-flow.sqlite';file_log=root/'late-flow.file.jsonl';stdout=open(root/'late-flow.stdout.jsonl','w');stderr=open(root/'late-flow.stderr','w')
monitor=subprocess.Popen([binary,'--no-config','--pid',str(os.getpid()),'--no-descendants','--no-udp','--no-dns','--no-banner','--json','--pcap','--pcap-interface','lo','--interval-ms','25','--sqlite',str(database),'--log-file',str(file_log),'--log-format','json'],env=env,stdout=stdout,stderr=stderr)
def rows():
    with sqlite3.connect(database,timeout=5) as conn:
        return conn.execute("SELECT local_port,domain,domain_source,ownership_json,observation_id FROM events WHERE event='connect' AND remote_port=443 ORDER BY id").fetchall()
def await_rows(predicate,label):
    deadline=time.monotonic()+20;last=[]
    while time.monotonic()<deadline:
        assert monitor.poll() is None,f'monitor exited before {label}'
        try:last=rows()
        except sqlite3.OperationalError:last=[]
        if predicate(last):return last
        time.sleep(.05)
    raise AssertionError(f'no {label}: {last}')
try:
    initial=await_rows(lambda rows:len(rows)==2 and all(row[1]=='unknown' for row in rows),'initial unresolved observations')
    original_ids={row[0]:row[4] for row in initial};assert len(set(original_ids.values()))==2 and all(original_ids.values()),'socket observation IDs absent or duplicate'
    time.sleep(.3)
    for client,name in zip(clients,names):client.sendall(hello(name))
    corrected=await_rows(lambda rows:len(rows)==2 and {row[0]:row[1] for row in rows}==expected and all(row[2]=='sni' for row in rows),'late exact-flow SNI')
    assert {row[0]:row[4] for row in corrected}==original_ids,'late association replaced the original observations'
    assert all(json.loads(row[3])['domain_evidence']['capture_kind']=='live' for row in corrected),'real wire observations mislabeled as replay'
    old_port=ports[0]
    clients[0].setsockopt(socket.SOL_SOCKET,socket.SO_LINGER,struct.pack('ii',1,0));servers[0].setsockopt(socket.SOL_SOCKET,socket.SO_LINGER,struct.pack('ii',1,0))
    clients[0].close();servers[0].close()
    deadline=time.monotonic()+20
    while time.monotonic()<deadline:
        with sqlite3.connect(database,timeout=5) as conn:closed=conn.execute("SELECT COUNT(*) FROM events WHERE event='close'").fetchone()[0]
        if closed==2:break
        assert monitor.poll() is None;time.sleep(.05)
    assert closed==2,'old physical endpoints were not observed closing before tuple reuse'
    new_client=socket.socket();new_client.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);new_client.bind(('127.0.0.1',old_port));new_client.connect(listener.getsockname());new_server,_=listener.accept();clients[0]=new_client;servers[0]=new_server
    reused=await_rows(lambda rows:len(rows)==3 and rows[-1][0]==old_port and rows[-1][1]=='unknown','unresolved reused tuple')
    assert reused[-1][4]!=original_ids[old_port],'reused tuple inherited an old observation ID'
    new_client.sendall(hello('next.audit.test'))
    reused=await_rows(lambda rows:len(rows)==3 and rows[-1][1]=='next.audit.test' and rows[-1][2]=='sni','new capture on reused tuple')
    assert next(row for row in reused if row[4]==original_ids[old_port])[1]=='a.audit.test','new capture rewrote the closed original observation'
    monitor.send_signal(signal.SIGTERM);assert monitor.wait(timeout=15)==0,'late flow monitor failed to finalize'
    stdout.close();stderr.close()
    records=list(map(json.loads,(root/'late-flow.stdout.jsonl').read_text().splitlines()));summary=next(row['summary'] for row in records if 'summary' in row)
    assert summary['connects']==6 and summary['closes']==2 and summary['per_provider']=={'anthropic':6},'hostname corrections inflated endpoint/provider counters'
    assert summary['sqlite']['observed']==summary['sqlite']['persisted']==8 and summary['sqlite']['metadata_lost']==0 and not summary['sqlite']['failed'],'durable event denominator changed or correction lost'
    with sqlite3.connect(database) as conn:assert conn.execute('SELECT COUNT(*) FROM events').fetchone()[0]==8,'hostname metadata became extra network rows'
    updates=[row for row in records if row.get('event')=='domain_update'];assert len(updates)==3 and all(row['domain_source']=='sni' for row in updates),'late corrections were not observable separately'
    file_records=list(map(json.loads,file_log.read_text().splitlines()));assert len([row for row in file_records if row.get('event')=='domain_update'])==3,'file log lost corrections'
    for command,args in [('export',['--format','jsonl']),('report',['--latest','--json']),('status',['--format','{total}|{anthropic}|{active}|{state}'])]:
        result=subprocess.run([binary,command,'--sqlite',str(database),*args],capture_output=True,text=True,timeout=15)
        (root/f'late-flow.{command}.stdout').write_text(result.stdout);(root/f'late-flow.{command}.stderr').write_text(result.stderr)
        assert result.returncode==0,f'{command} failed after live correction: {result.stderr}'
        if command=='export':assert len(list(map(json.loads,result.stdout.splitlines())))==8 and 'next.audit.test' in result.stdout,'export lost corrected history'
        elif command=='report':
            report=json.loads(result.stdout);assert report['summary']['connects']==6 and report['summary']['closes']==2 and 'next.audit.test' in result.stdout,'report inflated counts or lost corrected provenance'
        else:assert result.stdout.strip()=='6|6|0|ended','status inflated history or claimed finalized activity'
    print('PASS real delayed stdTLS ClientHello per flow, separate live/file corrections, actual closed/reused tuple, preserved old history, exact6 connects/2 closes/8 durable rows and report/export/status',flush=True)

    # A fresh monitor has no earlier capture cache. Force the real SQLite
    # correction to fail while its original endpoint rows still persist.
    fault_db=root/'hostname-fault.sqlite';stdout=open(root/'hostname-fault.stdout.jsonl','w');stderr=open(root/'hostname-fault.stderr','w')
    monitor=subprocess.Popen([binary,'--no-config','--pid',str(os.getpid()),'--no-descendants','--no-udp','--no-dns','--no-banner','--json','--pcap','--pcap-interface','lo','--interval-ms','25','--sqlite',str(fault_db)],env=env,stdout=stdout,stderr=stderr)
    deadline=time.monotonic()+20;count=0
    while time.monotonic()<deadline:
        assert monitor.poll() is None,'fault monitor exited before positive observations'
        try:
            with sqlite3.connect(fault_db,timeout=5) as conn:count=conn.execute("SELECT COUNT(*) FROM events WHERE event='connect'").fetchone()[0]
        except sqlite3.OperationalError:count=0
        if count==4:break
        time.sleep(.05)
    assert count==4,'fault fixture never persisted four real held endpoints'
    with sqlite3.connect(fault_db) as conn:
        conn.execute("CREATE TRIGGER reject_hostname BEFORE UPDATE OF domain ON events WHEN NEW.domain_source='sni' BEGIN SELECT RAISE(ABORT,'forced live hostname correction failure'); END;")
    clients[0].sendall(hello('failed.audit.test'))
    deadline=time.monotonic()+20
    while time.monotonic()<deadline:
        assert monitor.poll() is None,'fault monitor exited before graceful accounting'
        if 'forced live hostname correction failure' in (root/'hostname-fault.stderr').read_text():break
        time.sleep(.05)
    else:raise AssertionError('real hostname write failure was not observable')
    monitor.send_signal(signal.SIGTERM);assert monitor.wait(timeout=15)==1,'metadata failure returned success'
    stdout.close();stderr.close()
    records=list(map(json.loads,(root/'hostname-fault.stdout.jsonl').read_text().splitlines()));summary=next(row['summary'] for row in records if 'summary' in row)
    outcome=summary['sqlite'];assert outcome['observed']==outcome['persisted']==4 and outcome['queue_lost']==outcome['write_lost']==0 and outcome['metadata_lost']==1 and outcome['failed'],'correction loss hid behind a healthy event denominator'
    assert summary['connects']==4 and summary['closes']==0,'failed metadata invented network events'
    with sqlite3.connect(fault_db) as conn:
        assert conn.execute('SELECT COUNT(*) FROM events').fetchone()[0]==4 and conn.execute("SELECT COUNT(*) FROM events WHERE domain='unknown'").fetchone()[0]==4,'rejected correction corrupted original observations'
    print('PASS real late ClientHello + SQLite UPDATE abort: nonzero exit, metadata_lost1, preserved4 actual durable endpoint rows',flush=True)
finally:
    if monitor.poll() is None:
        monitor.send_signal(signal.SIGTERM)
        try:monitor.wait(timeout=15)
        except subprocess.TimeoutExpired:monitor.kill();monitor.wait(timeout=5)
    stdout.close();stderr.close()
    for client in clients:client.close()
    for server in servers:server.close()
    listener.close()
''')
    flow_result=subprocess.run(['sudo','-n','unshare','-n','--',sys.executable,str(flow_helper),binary,str(root),os.environ.get('RANO_PCAP_BASELINE',''),'claude'],capture_output=True,text=True,env=env,timeout=100)
    (root/'flow-helper.stdout').write_text(flow_result.stdout);(root/'flow-helper.stderr').write_text(flow_result.stderr)
    assert flow_result.returncode==0,f'flow attribution proof failed: {flow_result.stdout} {flow_result.stderr}'
    print(flow_result.stdout,flush=True)
finally:
    if holder.poll() is None:holder.stdin.write('x');holder.stdin.flush();holder.wait(timeout=5)
PY

e2e_section "Summary"
e2e_info "Actual pcap attribution, bounded replay, health and fallback checks passed; fixtures retained"
