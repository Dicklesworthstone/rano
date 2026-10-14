#!/usr/bin/env bash
set -euo pipefail

RANO_BIN="${RANO_BIN:-${E2E_RANO_RELEASE}}"
[[ -x "$RANO_BIN" ]] || e2e_fail "Build the intended revision before provider override tests"
e2e_section "Real held endpoints and exact provider override across durable sinks"
python3 - "$RANO_BIN" "$E2E_OUTPUT_DIR" <<'PY' || e2e_fail "provider override observations or durable reconciliation failed"
import json,os,pathlib,select,sqlite3,subprocess,sys,tempfile
binary=str(pathlib.Path(sys.argv[1]).resolve())
root=pathlib.Path(tempfile.mkdtemp(prefix='provider-override-',dir=sys.argv[2])).resolve()
marker='probecli-'+root.name
configuration=root/'rano.toml'
configuration.write_text('[providers]\nmode = "replace"\nopenai = ["'+marker+'"]\n')
empty_kv=root/'empty.conf';empty_kv.write_text('# isolated defaults\n')
code=r'''
import json,os,socket,sys
listener=socket.socket();listener.bind(('127.0.0.1',0));listener.listen()
client=socket.create_connection(listener.getsockname());server,_=listener.accept()
print(json.dumps({'pid':os.getpid(),'port':listener.getsockname()[1]}),flush=True)
sys.stdin.read(1)
client.close();server.close();listener.close()
'''
env=os.environ.copy();env['XDG_CONFIG_HOME']=str(root/'xdg')
env.pop('RANO_CONFIG_TOML',None)
holder_error=open(root/'holder.stderr','w')
holder=subprocess.Popen([sys.executable,'-u','-c',code,marker],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=holder_error,text=True)
try:
    assert select.select([holder.stdout],[],[],5)[0],'socket fixture never became ready'
    ready=json.loads(holder.stdout.readline());assert ready['pid']==holder.pid and ready['port']>0,'invalid real fixture identity'
    def validate(records,expected):
        opens=[row for row in records if row.get('event')=='connect']
        summaries=[row['summary'] for row in records if isinstance(row.get('summary'),dict)]
        assert len(opens)==2 and len(summaries)==1,'empty or incomplete observations cannot prove an override'
        assert all(row['provider']==expected and row['pid']==holder.pid for row in opens),'configured provider/owner differs from real endpoints'
        summary=summaries[0]
        assert summary['connects']==summary['active']==2 and summary['closes']==0 and summary['observation_errors']==0,'socket totals or observation health differ'
        assert summary['sqlite_dropped']==0 and not summary['log_failed'],'sink failure'
        return summary
    for label,expected,extra in [('default','unknown',['--no-config']),('override','openai',['--config',str(empty_kv),'--config-toml',str(configuration)])]:
        assert holder.poll() is None,'fixture exited before monitoring'
        database=root/(label+'.sqlite');log=root/(label+'.jsonl')
        args=[binary,'--pid',str(holder.pid),'--no-descendants','--once','--json','--no-banner','--no-dns',
            '--sqlite',str(database),'--log-file',str(log),'--log-format','json',*extra]
        result=subprocess.run(args,capture_output=True,text=True,env=env,timeout=20)
        (root/(label+'.stdout')).write_text(result.stdout);(root/(label+'.stderr')).write_text(result.stderr)
        assert result.returncode==0,result.stderr
        records=list(map(json.loads,result.stdout.splitlines()));summary=validate(records,expected)
        assert summary['sqlite']['observed']==summary['sqlite']['persisted']==2 and not summary['sqlite']['failed'],'enabled durable sink did not conserve two events'
        validate(list(map(json.loads,log.read_text().splitlines())),expected)
        with sqlite3.connect(database) as conn:
            assert conn.execute('SELECT provider,pid,event FROM events ORDER BY id').fetchall()==[(expected,holder.pid,'connect')]*2,'SQLite override differs'
        exported=subprocess.run([binary,'export','--sqlite',str(database),'--format','jsonl'],capture_output=True,text=True,env=env,timeout=10)
        (root/(label+'-export.stdout')).write_text(exported.stdout);(root/(label+'-export.stderr')).write_text(exported.stderr)
        exported_rows=list(map(json.loads,exported.stdout.splitlines()))
        assert exported.returncode==0 and len(exported_rows)==2 and all(row['provider']==expected and row['pid']==holder.pid for row in exported_rows),'export override differs'
    try:validate([{'summary':{'connects':0}}],'openai')
    except AssertionError:pass
    else:raise AssertionError('zero-observation negative control was accepted')
    print('PASS same actual held endpoints unknown by default and openai through explicit TOML; live/file/SQLite/export exact two rows; zero-observation control rejects. Retained '+str(root),flush=True)
finally:
    if holder.poll() is None:holder.stdin.write('x');holder.stdin.flush();holder.wait(timeout=5)
    holder_error.close()
PY
