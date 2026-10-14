#!/usr/bin/env bash
set -euo pipefail

INSTALLER_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/install.sh"
if [[ "${RANO_REAL_SOURCE_INSTALL:-0}" == 1 ]]; then
  SOURCE_BUILD_JOBS=1
  if [[ "$#" -gt 0 ]]; then
    [[ "$#" -eq 2 && "$1" == -j && "$2" =~ ^[1-9][0-9]*$ ]] || e2e_fail "Source-install mode accepts -j POSITIVE_JOBS"
    SOURCE_BUILD_JOBS="$2"
  fi
  e2e_section "Real pinned-source installation with redirected Cargo output"
  python3 - "$INSTALLER_PATH" "$E2E_OUTPUT_DIR" "$SOURCE_BUILD_JOBS" <<'PY' || e2e_fail "Real source installation failed"
import hashlib,json,os,pathlib,socket,subprocess,sys
installer=pathlib.Path(sys.argv[1]);root=pathlib.Path(sys.argv[2])/'source-install';root.mkdir()
temporary=root/'retained-tmp';temporary.mkdir();target=root/'redirected-cargo-output';destination=root/'bin'
env=os.environ.copy();env.update({'TMPDIR':str(temporary.resolve()),'CARGO_TARGET_DIR':str(target.resolve()),'CARGO_BUILD_JOBS':sys.argv[3],'RUSTUP_INIT_SKIP':'1','OWNER':'Dicklesworthstone','REPO':'rano','VERSION':'','SOURCE_REF':'','ARTIFACT_URL':'','CHECKSUM':'','CHECKSUM_URL':''})
result=subprocess.run(['bash',str(installer),'--from-source','--version','v0.2.0','--dest',str(destination.resolve()),'--verify','--no-gum'],capture_output=True,text=True,env=env,timeout=900)
(root/'install.stdout').write_text(result.stdout);(root/'install.stderr').write_text(result.stderr)
assert result.returncode==0,f'real source install failed: {result.stderr}'
checkouts=list(temporary.glob('*/src/.git'));assert len(checkouts)==1,'expected one retained source checkout'
checkout=checkouts[0].parent
revision=subprocess.check_output(['git','-C',str(checkout),'rev-parse','HEAD'],text=True).strip()
assert revision=='35041a2ea4304a63b012b32ab16e11e2a7b6b7b7','selected release was replaced by another ref'
artifact_rows=list(map(json.loads,(checkout.parent/'build.jsonl').read_text().splitlines()))
executables=[row['executable'] for row in artifact_rows if row.get('reason')=='compiler-artifact' and row.get('target',{}).get('name')=='rano' and row.get('executable')]
assert len(executables)==1 and pathlib.Path(executables[0]).is_relative_to(target.resolve()),'actual Cargo artifact ignored the redirected output directory'
installed=destination/'rano'
assert hashlib.sha256(installed.read_bytes()).hexdigest()==hashlib.sha256(pathlib.Path(executables[0]).read_bytes()).hexdigest(),'installed bytes differ from the actual compiled executable'
assert subprocess.check_output([str(installed),'--version'],text=True).strip()=='rano 0.2.0','installed source version mismatch'
listener=socket.socket();listener.bind(('127.0.0.1',0));listener.listen();client=socket.create_connection(listener.getsockname());server,_=listener.accept()
try:
    observed=subprocess.run([str(installed),'--no-config','--once','--no-dns','--no-sqlite','--json','--no-banner','--pid',str(os.getpid()),'--no-descendants'],capture_output=True,text=True,timeout=30)
    (root/'socket.stdout').write_text(observed.stdout);(root/'socket.stderr').write_text(observed.stderr)
    assert observed.returncode==0,observed.stderr
    rows=list(map(json.loads,observed.stdout.splitlines()));opens=[row for row in rows if row.get('event')=='connect'];summaries=[row['summary'] for row in rows if isinstance(row.get('summary'),dict)]
    assert len(opens)==2 and len(summaries)==1 and summaries[0]['connects']==2,'source-installed binary did not observe both actual held endpoints'
finally:client.close();server.close();listener.close()
(root/'receipt.json').write_text(json.dumps({'requested_tag':'v0.2.0','source_revision':revision,'executable':executables[0],'installed_sha256':hashlib.sha256(installed.read_bytes()).hexdigest(),'observed_endpoints':2},indent=2))
print('PASS real Git tag/immutable source, actual Cargo release executable in redirected directory, installed bytes/version and two held TCP endpoints; retained '+str(root),flush=True)
PY
  return 0
fi

RANO_BIN="${RANO_BIN:-${E2E_RANO_RELEASE}}"
[[ -x "$RANO_BIN" ]] || e2e_fail "Build the intended rano revision before installer tests"
e2e_section "Isolated real-binary archive installation and failure preservation"
python3 - "$RANO_BIN" "$INSTALLER_PATH" <<'PY' || e2e_fail "Installer archive/ref/tool/failure matrix failed"
import hashlib,json,os,pathlib,shutil,subprocess,sys,tarfile,tempfile
binary=pathlib.Path(sys.argv[1]).resolve();installer=pathlib.Path(sys.argv[2]).resolve()
root=pathlib.Path(tempfile.mkdtemp(prefix='rano-installer-'));print(f'Retained installer fixtures: {root}',flush=True)
version=subprocess.check_output([str(binary),'--version'],text=True).strip().removeprefix('rano ')
archive=root/'rano.tar'
with tarfile.open(archive,'w') as tar:tar.add(binary,arcname='rano')
digest=hashlib.sha256(archive.read_bytes()).hexdigest();sidecar=root/'rano.sha256';sidecar.write_text(f'{digest}  rano.tar\n')
def run(label,args,success,extra=None,path=None):
    destination=root/label;destination.mkdir();existing=destination/'rano';existing.write_text('preserved previous operator fixture\n')
    env=os.environ.copy();env.update({'OWNER':'Dicklesworthstone','REPO':'rano','VERSION':'','SOURCE_REF':'','ARTIFACT_URL':'','CHECKSUM':'','CHECKSUM_URL':'','RUSTUP_INIT_SKIP':'1'})
    if extra:env.update(extra)
    if path:env['PATH']=str(path)
    result=subprocess.run(['bash',str(installer),'--dest',str(destination),*args],capture_output=True,text=True,env=env,timeout=45)
    (root/f'{label}.stdout').write_text(result.stdout);(root/f'{label}.stderr').write_text(result.stderr)
    assert (result.returncode==0)==success,f'{label}: exit {result.returncode}, stderr={result.stderr}, stdout={result.stdout}'
    if success:
        assert hashlib.sha256(existing.read_bytes()).hexdigest()==hashlib.sha256(binary.read_bytes()).hexdigest(),'installed bytes differ from the actual compiled artifact'
        assert subprocess.check_output([str(existing),'--version'],text=True).strip()==f'rano {version}','installed executable version differs'
    else:assert existing.read_text()=='preserved previous operator fixture\n',f'{label}: failed verification overwrote the prior fixture'
    assert not (destination/'.rano-install.lock').exists(),f'{label}: own lock was not retained/released'
    return result
base=['--version','v'+version,'--artifact-url',archive.as_uri(),'--checksum',digest,'--no-gum']
run('real-artifact',base+['--verify'],True)
quiet=run('real-artifact-quiet',base+['--verify','--quiet'],True);assert not quiet.stdout,'quiet install emitted ordinary output'
run('sidecar',['--version','v'+version,'--artifact-url',archive.as_uri(),'--checksum-url',sidecar.as_uri(),'--verify','--quiet'],True)
run('wrong-checksum',[*base[:-3],'--checksum','0'*64],False)
run('missing-archive',['--version','v'+version,'--artifact-url',(root/'absent.tar').as_uri(),'--checksum',digest],False)
truncated=root/'truncated.tar';truncated.write_bytes(archive.read_bytes()[:1024]);bad_digest=hashlib.sha256(truncated.read_bytes()).hexdigest()
run('truncated-archive',['--version','v'+version,'--artifact-url',truncated.as_uri(),'--checksum',bad_digest],False)
run('wrong-version',['--version','v99.0.0','--artifact-url',archive.as_uri(),'--checksum',digest],False)
collateral=root/'operator-data.txt';collateral.write_text('preserved operator data\n')
unsafe_archive=root/'unsafe.tar'
with tarfile.open(unsafe_archive,'w') as tar:
    info=tarfile.TarInfo('../operator-data.txt');payload=b'overwritten\n';info.size=len(payload)
    tar.addfile(info,__import__('io').BytesIO(payload));tar.add(binary,arcname='rano')
run('unsafe-archive-path',['--version','v'+version,'--artifact-url',unsafe_archive.as_uri(),'--checksum',hashlib.sha256(unsafe_archive.read_bytes()).hexdigest()],False)
assert collateral.read_text()=='preserved operator data\n','archive traversal changed unrelated fixture data'
link_archive=root/'linked.tar'
with tarfile.open(link_archive,'w') as tar:
    info=tarfile.TarInfo('rano');info.type=tarfile.SYMTYPE;info.linkname=str(binary);tar.addfile(info)
run('archive-symlink',['--version','v'+version,'--artifact-url',link_archive.as_uri(),'--checksum',hashlib.sha256(link_archive.read_bytes()).hexdigest()],False)
for index,args in enumerate([['--version'],['--dest'],['--ref'],['--unknown'],['--version','not-a-version'],['--ref','main'],['--from-source','--ref','main','--version','v'+version]]):
    run(f'invalid-argument-{index}',args,False)
def tools_dir(label,checksum_tool=None):
    directory=root/label;directory.mkdir()
    for name in ['bash','curl','uname','tr','awk','tar','find','head','install','mkdir','mktemp','mv','cat','cp','sed','grep','sh']:
        target=shutil.which(name);assert target,f'test prerequisite missing: {name}'
        (directory/name).symlink_to(target)
    if checksum_tool:
        target=shutil.which(checksum_tool);assert target,f'test prerequisite missing: {checksum_tool}'
        (directory/checksum_tool).symlink_to(target)
    return directory
run('stock-shasum',base+['--verify','--quiet'],True,path=tools_dir('shasum-tools','shasum'))
run('absent-sha-tool',base,False,path=tools_dir('no-sha-tools'))
broken=root/'broken-rano';broken.write_text('#!/usr/bin/env bash\nexit 7\n');broken.chmod(0o755)
bad_archive=root/'broken.tar'
with tarfile.open(bad_archive,'w') as tar:tar.add(broken,arcname='rano')
run('broken-verify',['--version','v'+version,'--artifact-url',bad_archive.as_uri(),'--checksum',hashlib.sha256(bad_archive.read_bytes()).hexdigest(),'--verify'],False)

# This controlled transport seam proves release-resolution refusal, not a live
# GitHub outage. The actual binary/archive/installed executions above are real.
transport=root/'transport-tools';transport.mkdir();curl=transport/'curl'
curl.write_text('#!/usr/bin/env python3\nimport json,os,sys\nopen(os.environ["CURL_CAPTURE"],"a").write(json.dumps(sys.argv[1:])+"\\n")\nprint("controlled unavailable transport",file=sys.stderr)\nsys.exit(22)\n');curl.chmod(0o755)
capture=root/'resolution-curl.jsonl'
run('resolution-failure',[],False,extra={'CURL_CAPTURE':str(capture)},path=str(transport)+os.pathsep+os.environ['PATH'])
calls=list(map(json.loads,capture.read_text().splitlines()))
assert len(calls)==2 and all('OpenAI File Downloader, XaiImageApiFetch/1.0' in call for call in calls),'resolution transport/user-agent policy wrong'

# Controlled Git/Cargo protocol seams test ref selection and artifact-path
# routing. They do not claim to compile Rust or qualify a source-built release.
source_tools=root/'source-tools';source_tools.mkdir();git_capture=root/'git-calls.jsonl';cargo_capture=root/'cargo-calls.jsonl'
fake_git=source_tools/'git'
fake_git.write_text('''#!/usr/bin/env python3
import json,os,pathlib,sys
args=sys.argv[1:];open(os.environ['GIT_CAPTURE'],'a').write(json.dumps(args)+'\\n')
if 'init' in args or 'clone' in args:pathlib.Path(args[-1]).mkdir(parents=True,exist_ok=True)
if 'fetch' in args and os.environ.get('MISSING_SOURCE_REF')=='1':
    print('controlled nonexistent requested ref',file=sys.stderr);sys.exit(128)
if 'rev-parse' in args:print('0123456789abcdef0123456789abcdef01234567')
''');fake_git.chmod(0o755)
fake_cargo=source_tools/'cargo'
fake_cargo.write_text('''#!/usr/bin/env python3
import json,os,pathlib,shutil,sys
open(os.environ['CARGO_CAPTURE'],'a').write(json.dumps({'args':sys.argv[1:],'cwd':os.getcwd(),'target_dir':os.environ.get('CARGO_TARGET_DIR')})+'\\n')
target=pathlib.Path(os.environ['CARGO_TARGET_DIR'])/'custom-triple'/'release'/'rano';target.parent.mkdir(parents=True,exist_ok=True)
shutil.copy2(os.environ['REAL_RANO_FIXTURE'],target)
print(json.dumps({'reason':'compiler-artifact','target':{'name':'rano','kind':['bin']},'executable':str(target)}))
''');fake_cargo.chmod(0o755)
source_env={'GIT_CAPTURE':str(git_capture),'CARGO_CAPTURE':str(cargo_capture),'REAL_RANO_FIXTURE':str(binary),'CARGO_TARGET_DIR':str(root/'redirected target')}
source_path=str(source_tools)+os.pathsep+os.environ['PATH']
run('source-ref-seam',['--from-source','--ref','reviewed-branch','--quiet','--verify'],True,extra=source_env,path=source_path)
git_calls=list(map(json.loads,git_capture.read_text().splitlines()))
assert any('fetch' in call and call[-1]=='refs/heads/reviewed-branch' for call in git_calls),'selected source branch was ignored'
assert any('checkout' in call and call[-1]=='0123456789abcdef0123456789abcdef01234567' for call in git_calls),'resolved immutable source commit was not checked out'
assert any('http.userAgent=OpenAI File Downloader, XaiImageApiFetch/1.0' in call for call in git_calls),'Git transport user agent missing'
cargo_calls=list(map(json.loads,cargo_capture.read_text().splitlines()))
assert cargo_calls[-1]['args']==['build','--locked','--release','--message-format=json-render-diagnostics'],'source build flags changed'
assert cargo_calls[-1]['target_dir']==str(root/'redirected target'),'Cargo target override lost'
run('source-tag-seam',['--from-source','--version','v'+version,'--quiet'],True,extra=source_env,path=source_path)
git_calls=list(map(json.loads,git_capture.read_text().splitlines()))
assert any('fetch' in call and call[-1]=='refs/tags/v'+version for call in git_calls),'source install ignored the selected release tag'
run('nonexistent-tag-seam',['--from-source','--version','v99.0.0','--quiet'],False,extra={**source_env,'MISSING_SOURCE_REF':'1'},path=source_path)
run('source-version-mismatch-seam',['--from-source','--version','v99.0.0','--quiet'],False,extra=source_env,path=source_path)
print('PASS actual archive/checksum/install/version/quiet/shasum; missing/truncated/mismatched/broken/argument failures preserve prior fixture; controlled release-resolution refusal',flush=True)
print('PASS controlled Git/Cargo seams: exact branch/tag/commit routing and actual Cargo executable path; absent refs/version mismatches refuse. No Rust source-build qualification claimed.',flush=True)
PY

e2e_section "Updater transport failure and installer environment/argv routing"
python3 - "$RANO_BIN" <<'PY' || e2e_fail "Updater transport/environment/argv matrix failed"
import json,os,pathlib,subprocess,sys,tempfile
binary=sys.argv[1];root=pathlib.Path(tempfile.mkdtemp(prefix='rano-updater-'));tools=root/'tools';tools.mkdir()
curl=tools/'curl'
script='''#!/usr/bin/env bash
python3 - "$@" <<'CAPTURE'
import json,os,pathlib,sys
pathlib.Path(os.environ['INSTALLER_CAPTURE']).write_text(json.dumps({'args':sys.argv[1:],'owner':os.environ.get('OWNER'),'repo':os.environ.get('REPO')}))
CAPTURE
exit "${INSTALLER_EXIT:-0}"
'''
curl.write_text('''#!/usr/bin/env python3
import json,os,pathlib,sys
pathlib.Path(os.environ['CURL_CAPTURE']).write_text(json.dumps({'args':sys.argv[1:],'owner':os.environ.get('OWNER'),'repo':os.environ.get('REPO')}))
mode=os.environ.get('CURL_MODE','success')
if mode!='empty':sys.stdout.write(os.environ['CONTROLLED_INSTALLER'])
if mode=='failure':print('controlled transport failure',file=sys.stderr);sys.exit(22)
''');curl.chmod(0o755)
destination=str(root/"literal '$PATH;\ninstaller destination")
args=['update','--owner','audited-owner','--repo','audited-repo','--branch','feature/routing','--version','v0.2.1','--dest',destination,'--from-source','--verify','--quiet','--no-gum','--easy-mode']
for label,mode,installer_exit,success in [('success','success','0',True),('curl-failure','failure','0',False),('empty-download','empty','0',False),('installer-failure','success','17',False)]:
    capture=root/f'{label}-installer.json';curl_capture=root/f'{label}-curl.json'
    env=os.environ.copy();env.update({'PATH':str(tools)+os.pathsep+env['PATH'],'OWNER':'parent-owner','REPO':'parent-repo','INSTALLER_CAPTURE':str(capture),'CURL_CAPTURE':str(curl_capture),'CONTROLLED_INSTALLER':script,'CURL_MODE':mode,'INSTALLER_EXIT':installer_exit})
    result=subprocess.run([binary,*args],capture_output=True,text=True,env=env,timeout=20)
    (root/f'{label}.stdout').write_text(result.stdout);(root/f'{label}.stderr').write_text(result.stderr)
    assert (result.returncode==0)==success,f'{label}: exit {result.returncode}: {result.stderr}'
    downloaded=json.loads(curl_capture.read_text())
    assert 'https://raw.githubusercontent.com/audited-owner/audited-repo/feature/routing/install.sh' in downloaded['args'],'custom installer URL routing incorrect'
    assert 'OpenAI File Downloader, XaiImageApiFetch/1.0' in downloaded['args'],'updater transport user agent missing'
    if mode in ('failure','empty'):assert not capture.exists(),'installer started despite failed/empty download'
    else:
        installed=json.loads(capture.read_text())
        assert (installed['owner'],installed['repo'])==('audited-owner','audited-repo'),'OWNER/REPO applied to transport rather than installer'
        assert installed['args']==['--version','v0.2.1','--easy-mode','--dest',destination,'--from-source','--verify','--quiet','--no-gum'],'literal arguments were changed or evaluated'
print(f'PASS controlled updater transport/environment/literal argv and failure propagation; fixtures retained: {root}. No remote service or operator binary modified.',flush=True)
PY
