#!/usr/bin/env bash
# E2E Test: Config Validation
# Tests the configuration validation system
#
# This test verifies:
# - 'rano config check' validates config files
# - Valid config files pass validation
# - Unknown keys produce warnings
# - Invalid values produce errors
# - Invalid TOML produces errors
# - 'rano config show' displays resolved config
# - 'rano config paths' lists correct paths
#
# Prerequisites:
# - rano binary built (cargo build)

set -euo pipefail

RANO="${RANO:-${E2E_RANO_DEBUG}}"
TEMP_CONFIG_DIR=""

# Cleanup on exit
cleanup() {
    e2e_info "Retained config fixtures: ${TEMP_CONFIG_DIR}"
}
trap cleanup EXIT

e2e_section "Setup"
e2e_info "rano=${RANO}"

# Ensure rano binary exists
if [ ! -x "${RANO}" ]; then
    e2e_fail "rano binary not found at ${RANO}. Run 'cargo build' first."
fi

# Create temporary config directory
TEMP_CONFIG_DIR="$(mktemp -d)"
export XDG_CONFIG_HOME="${TEMP_CONFIG_DIR}/.config"
unset RANO_CONFIG RANO_CONFIG_TOML
mkdir -p "${TEMP_CONFIG_DIR}/.config/rano/presets"
e2e_info "temp_config_dir=${TEMP_CONFIG_DIR}"

# Test 1: Valid config file passes validation
e2e_section "Test 1: Valid config file passes validation"

cat > "${TEMP_CONFIG_DIR}/.config/rano/config.conf" << 'EOF'
# Valid configuration
pattern=claude,codex
interval_ms=1000
json=false
no_banner=true
stats_interval_ms=2000
stats_view=provider,domain
EOF
e2e_info "Created valid config at ${TEMP_CONFIG_DIR}/.config/rano/config.conf"

e2e_run "check valid config" "${RANO}" config check

e2e_assert_last_status 0
e2e_assert_last_contains "Configuration is valid"
e2e_info "PASS: Valid config passes validation"

# Test 2: Unknown key produces warning
e2e_section "Test 2: Unknown key produces warning"

cat > "${TEMP_CONFIG_DIR}/.config/rano/config.conf" << 'EOF'
pattern=claude
unknwon_typo=value
interval_ms=1000
EOF

e2e_run "check unknown key" "${RANO}" config check

# Should succeed but with warnings
e2e_assert_last_status 0
e2e_assert_last_contains "warning"
e2e_assert_last_contains "unknown key"
e2e_assert_last_contains "unknwon_typo"
e2e_info "PASS: Unknown key produces warning"

# Test 3: Invalid number produces error
e2e_section "Test 3: Invalid number produces error"

cat > "${TEMP_CONFIG_DIR}/.config/rano/config.conf" << 'EOF'
interval_ms=not_a_number
EOF

e2e_run "check invalid number" "${RANO}" config check || true

# Should fail with error
if [ "${E2E_LAST_STATUS}" -eq 0 ]; then
    e2e_fail "Expected error for invalid number, but got success"
fi
e2e_assert_last_contains "error"
e2e_assert_last_contains "integer"
e2e_info "PASS: Invalid number produces error"

# Test 4: Invalid boolean produces error
e2e_section "Test 4: Invalid boolean produces error"

cat > "${TEMP_CONFIG_DIR}/.config/rano/config.conf" << 'EOF'
json=maybe
EOF

e2e_run "check invalid boolean" "${RANO}" config check || true

# Should fail with error
if [ "${E2E_LAST_STATUS}" -eq 0 ]; then
    e2e_fail "Expected error for invalid boolean, but got success"
fi
e2e_assert_last_contains "error"
e2e_assert_last_contains "boolean"
e2e_info "PASS: Invalid boolean produces error"

# Test 5: Invalid enum value produces error
e2e_section "Test 5: Invalid enum value produces error"

cat > "${TEMP_CONFIG_DIR}/.config/rano/config.conf" << 'EOF'
domain_mode=invalid_mode
EOF

e2e_run "check invalid enum" "${RANO}" config check || true

# Should fail with error
if [ "${E2E_LAST_STATUS}" -eq 0 ]; then
    e2e_fail "Expected error for invalid enum, but got success"
fi
e2e_assert_last_contains "error"
e2e_assert_last_contains "auto, ptr, pcap"
e2e_info "PASS: Invalid enum value produces error"

# Test 6: Invalid TOML produces error
e2e_section "Test 6: Invalid TOML produces error"

# Remove the conf file first
mv "${TEMP_CONFIG_DIR}/.config/rano/config.conf" "${TEMP_CONFIG_DIR}/case5-config.conf"

# Create invalid TOML
cat > "${TEMP_CONFIG_DIR}/.config/rano/rano.toml" << 'EOF'
[providers
mode = "merge"
invalid toml syntax {{{{
EOF

e2e_run "check invalid toml" "${RANO}" config check || true

# Should fail with error
if [ "${E2E_LAST_STATUS}" -eq 0 ]; then
    e2e_fail "Expected error for invalid TOML, but got success"
fi
e2e_assert_last_contains "error"
e2e_assert_last_contains "TOML"
e2e_info "PASS: Invalid TOML produces error"

# Test 7: Valid TOML passes validation
e2e_section "Test 7: Valid TOML passes validation"

cat > "${TEMP_CONFIG_DIR}/.config/rano/rano.toml" << 'EOF'
[providers]
mode = "merge"
anthropic = ["claude", "acme-claude"]
openai = ["codex"]
EOF

e2e_run "check valid toml" "${RANO}" config check

e2e_assert_last_status 0
e2e_assert_last_contains "valid"
e2e_info "PASS: Valid TOML passes validation"

# Test 8: 'config show' displays resolved config
e2e_section "Test 8: config show displays resolved config"

cat > "${TEMP_CONFIG_DIR}/.config/rano/config.conf" << 'EOF'
pattern=test-pattern
interval_ms=500
EOF

e2e_run "config show" "${RANO}" config show

e2e_assert_last_status 0
e2e_assert_last_contains "pattern"
e2e_assert_last_contains "test-pattern"
e2e_assert_last_contains "interval_ms"
e2e_assert_last_contains "500"
e2e_info "PASS: config show displays resolved config"

# Test 9: 'config show --json' outputs JSON
e2e_section "Test 9: config show --json outputs JSON"

e2e_run "config show json" "${RANO}" config show --json

e2e_assert_last_status 0
e2e_assert_last_contains "{"
e2e_assert_last_contains "}"
e2e_assert_last_contains "pattern"
e2e_info "PASS: config show --json outputs JSON"

# Test 10: 'config paths' lists search locations
e2e_section "Test 10: config paths lists search locations"

e2e_run "config paths" "${RANO}" config paths

e2e_assert_last_status 0
e2e_assert_last_contains "config.conf"
e2e_assert_last_contains "rano.toml"
e2e_assert_last_contains ".config/rano"
e2e_info "PASS: config paths lists search locations"

# Test 11: Invalid stats_view value produces error
e2e_section "Test 11: Invalid stats_view value produces error"

cat > "${TEMP_CONFIG_DIR}/.config/rano/config.conf" << 'EOF'
stats_view=provider,invalid_view
EOF

e2e_run "check invalid stats_view" "${RANO}" config check || true

# Should fail with error
if [ "${E2E_LAST_STATUS}" -eq 0 ]; then
    e2e_fail "Expected error for invalid stats_view, but got success"
fi
e2e_assert_last_contains "error"
e2e_assert_last_contains "invalid value"
e2e_info "PASS: Invalid stats_view value produces error"

# Test 12: Zero value for db_batch_size produces error
e2e_section "Test 12: Zero value for required positive integer produces error"

cat > "${TEMP_CONFIG_DIR}/.config/rano/config.conf" << 'EOF'
db_batch_size=0
EOF

e2e_run "check zero db_batch_size" "${RANO}" config check || true

# Should fail with error
if [ "${E2E_LAST_STATUS}" -eq 0 ]; then
    e2e_fail "Expected error for zero db_batch_size, but got success"
fi
e2e_assert_last_contains "error"
e2e_assert_last_contains ">= 1"
e2e_info "PASS: Zero value for required positive integer produces error"

# Test 13: Invalid TOML provider mode produces error
e2e_section "Test 13: Invalid TOML provider mode produces error"

mv "${TEMP_CONFIG_DIR}/.config/rano/config.conf" "${TEMP_CONFIG_DIR}/case12-config.conf"
cat > "${TEMP_CONFIG_DIR}/.config/rano/rano.toml" << 'EOF'
[providers]
mode = "invalid_mode"
EOF

e2e_run "check invalid provider mode" "${RANO}" config check || true

# Should fail with error
if [ "${E2E_LAST_STATUS}" -eq 0 ]; then
    e2e_fail "Expected error for invalid provider mode, but got success"
fi
e2e_assert_last_contains "error"
e2e_assert_last_contains "merge, replace"
e2e_info "PASS: Invalid TOML provider mode produces error"

e2e_section "Effective settings, actual sources and real monitored sockets"
python3 - "${RANO}" "${TEMP_CONFIG_DIR}" <<'PY' || e2e_fail "effective configuration CLI matrix failed"
import json,os,pathlib,socket,sqlite3,subprocess,sys,time
binary=sys.argv[1];root=pathlib.Path(sys.argv[2])/'effective';root.mkdir()
xdg=root/'xdg';settings=xdg/'rano';presets=settings/'presets';presets.mkdir(parents=True)
env=os.environ.copy()
for key in ['HOME','RANO_CONFIG','RANO_CONFIG_TOML']:env.pop(key,None)
env['XDG_CONFIG_HOME']=str(xdg)
sequence=0
def call(args,label,environment=None,executable=None):
    global sequence
    sequence+=1
    result=subprocess.run([executable or binary,*args],cwd=root,env=environment or env,capture_output=True,text=True,timeout=30)
    (root/f'{sequence:03d}-{label}.stdout').write_text(result.stdout)
    (root/f'{sequence:03d}-{label}.stderr').write_text(result.stderr)
    return result
def show(options=(),environment=None):
    result=call(['config','show','--json','--',*options],'show',environment)
    assert result.returncode==0,f'show failed: {result.stderr}'
    parsed=json.loads(result.stdout)
    assert isinstance(parsed['effective'],dict) and isinstance(parsed['origins'],dict) and isinstance(parsed['sources'],list),'not effective configuration'
    return parsed,result
defaults,_=show(['--no-config'])
for key,value in {'interval_ms':1000,'db_flush_ms':1000,'db_batch_size':200,'db_queue_max':10000,'include_udp':True,'include_listening':False,'stats_interval_ms':5000,'stats_width':40,'stats_top':5,'stats_view':['provider'],'pcap_cache_max':10000,'retry_threshold':3,'retry_window_ms':60000,'redact_cmdline':'off'}.items():
    assert defaults['effective'][key]==value,f'wrong typed default {key}'
    assert defaults['origins'][key]=='defaults',f'wrong default origin {key}'
assert defaults['effective']['pattern']==['claude','codex','gemini'],'wrong default process roster'
assert defaults['introspection_redacted'] is True,'masking policy omitted'
schema={
 'pattern':['first','second'],'exclude_pattern':['ignore-a','ignore-b'],'pid':[4294967295],
 'no_descendants':True,'interval_ms':17,'json':True,'summary_only':False,'pcap':False,'domain_mode':'ptr',
 'no_dns':True,'include_udp':True,'include_listening':True,'show_ancestry':True,
 'log_file':str(root/'schema.jsonl'),'log_dir':str(root/'schema-logs'),'log_format':'json','once':True,
 'color':'never','sqlite':str(root/'schema.sqlite'),'no_sqlite':True,'db_batch_size':3,'db_flush_ms':7,
 'db_queue_max':11,'pcap_interface':'lo','pcap_cache_max':100,'stats_interval_ms':0,'stats_width':19,
 'stats_top':2,'stats_view':['provider','process'],'stats_cycle_ms':0,'no_banner':True,'theme':'mono',
 'session_name':'schema','alert_domain':['one.test','two.test'],'alert_max_connections':2,
 'alert_max_per_provider':1,'alert_duration_ms':3,'alert_unknown_domain':True,'alert_bell':False,
 'alert_cooldown_ms':0,'no_alerts':True,'redact_cmdline':'all','retry_threshold':2,'retry_window_ms':3,
}
schema_path=root/'all-keys.conf'
def encoded(value):
    if isinstance(value,bool):return str(value).lower()
    if isinstance(value,list):return ','.join(map(str,value))
    return str(value)
schema_path.write_text('# Every public KV setting, with independently declared typed expectations.\n'+''.join(f' {key} = {encoded(value)} # setting\n' for key,value in schema.items()))
all_keys,_=show(['--config',str(schema_path)])
assert all_keys['effective']==schema,'a supported setting was omitted, mistyped or wired to the wrong field'
assert all(all_keys['origins'][key]==str(schema_path) for key in schema),'source origin omitted for a supported key'
assert call(['config','check','--config',str(schema_path)],'check-all-keys').returncode==0,'checker rejected valid all-key schema'
marker='rano-config-'+root.parent.name.lower()
secret='sk-ant-api03-fixture-credential-never-real'
kv=settings/'config.conf';kv.write_text(f'interval_ms=333\ninclude_udp=false\npattern=from-kv\nstats_view=domain\nunknown_api_key={secret}\n')
(presets/'audit.conf').write_text('summary_only=false\ninclude_udp=true\ninterval_ms=222\npattern=from-audit\nstats_view=port\nredact_cmdline=secrets\n')
(presets/'team.conf').write_text('interval_ms=111\ninclude_udp=false\npattern=from-team\nstats_view=process\nstats_top=7\n')
provider=settings/'rano.toml';provider.write_text(f'[providers]\nmode="replace"\nanthropic=["xdg-provider"]\ndummy_api_key="{secret}"\n')
(root/'rano.toml').write_text('[providers]\nmode="merge"\nopenai=["cwd-provider"]\n')
explicit_provider=root/'explicit.toml';explicit_provider.write_text(f'[providers]\nmode="replace"\nanthropic=["{marker}"]\n')
env_provider=root/'env.toml';env_provider.write_text('[providers]\nmode="merge"\ngoogle=["env-provider"]\n')
env['RANO_CONFIG_TOML']=str(env_provider)
merged,result=show(['--preset','audit','--preset','team','--interval-ms','55','--include-udp','--pattern',marker,'--stats-view','provider','--config-toml',str(explicit_provider)])
for key,value in {'interval_ms':55,'include_udp':True,'pattern':[marker],'stats_view':['provider'],'stats_top':7,'summary_only':False,'redact_cmdline':'secrets'}.items():
    assert merged['effective'][key]==value,f'wrong merged value {key}'
assert merged['origins']['interval_ms']=='cli' and merged['origins']['stats_top']==str(presets/'team.conf'),'source origin incorrect'
assert merged['providers']=={'anthropic':[marker],'openai':[],'google':['env-provider']},'TOML discovery/replace/merge/explicit/env order incorrect'
assert merged['origins']['providers.anthropic']==[str(explicit_provider)],'replaced provider origins retained discarded defaults'
assert merged['origins']['providers.google']==[str(explicit_provider),str(env_provider)],'provider merge origins missing'
provider_sources=[entry for entry in merged['sources'] if entry['kind']=='providers']
assert [entry['origin'] for entry in provider_sources]==[str(provider),str(root/'rano.toml'),str(explicit_provider),str(env_provider)],'actual provider source inventory incorrect'
assert [entry['provider_mode'] for entry in provider_sources]==['replace','merge','replace','merge'],'provider source modes absent'
assert secret not in result.stdout and 'contents' not in result.stdout,'introspection leaked raw sources/credentials'
assert any('unknown_api_key' in warning for warning in merged['warnings']),'unknown KV warning lost'
assert any('dummy_api_key' in warning for warning in merged['warnings']),'unknown TOML warning lost'
assert call(['config','check','--preset','audit','--preset','team','--interval-ms','55','--include-udp','--config-toml',str(explicit_provider)],'check-merged').returncode==0,'checker rejected actual merged sources'
override=root/'env.conf';override.write_text('interval_ms=456\n')
env_kv=env.copy();env_kv['RANO_CONFIG']=str(override)
assert show(environment=env_kv)[0]['effective']['interval_ms']==456,'RANO_CONFIG did not override XDG default'
explicit=root/'cli.conf';explicit.write_text('interval_ms=789\n')
assert show(['--config',str(explicit)],env_kv)[0]['effective']['interval_ms']==789,'CLI KV path did not override RANO_CONFIG'
assert show(['--preset','team','--preset','audit'])[0]['effective']['interval_ms']==222,'later preset lost precedence'
isolated=env.copy();isolated['XDG_CONFIG_HOME']=str(root/'empty-xdg')
assert show(['--no-config','--preset','audit'],isolated)[0]['effective']['include_udp'] is True,'builtin audit omitted UDP'
live=show(['--no-config','--preset','live'],isolated)[0]['effective']
assert live['stats_interval_ms']==500 and live['stats_top']==10,'builtin live differs from public contract'
literal=show(['--no-config','--pattern','--help'])[0]
assert literal['effective']['pattern']==['--help'],'flag value turned into help/control action'
masked,masked_result=show(['--no-config','--pattern','tool --password multi word credential','--session-name',f'API_KEY={secret}'])
assert masked['effective']['pattern']==['<redacted>'] and 'multi word credential' not in masked_result.stdout and secret not in masked_result.stdout,'known credentials leaked via effective values'
def refuse_all(options,environment,label):
    commands=[['config','check',*options],['config','show','--json','--',*options],[*options,'--once','--no-dns','--no-sqlite','--no-banner']]
    for index,args in enumerate(commands):
        result=call(args,f'{label}-{index}',environment)
        assert result.returncode!=0 and 'error' in result.stderr.lower(),f'{label}: check/show/runtime accepted invalid source/options'
bad_cases=[('db_flush_ms','0'),('db_batch_size','0'),('db_queue_max','0'),('stats_top','0'),('pid','0'),('pid','4294967296'),('interval_ms','18446744073709551616'),('interval_ms','-1'),('json','maybe'),('domain_mode','other'),('stats_view','port,invalid'),('stats_view',',,,'),('pcap_cache_max','99'),('retry_threshold','0'),('retry_window_ms','0'),('alert_max_connections','0'),('alert_max_per_provider','0'),('alert_duration_ms','0'),('redact_cmdline','invalid'),('log_format','xml'),('theme','other'),('color','other'),('pattern',',,,'),('pcap_interface','')]
for index,(key,value) in enumerate(bad_cases):
    path=root/f'invalid-{index}.conf';path.write_text(f'{key}={value}\n')
    refuse_all(['--config',str(path)],env,f'invalid-{key}')
missing=root/'missing.conf';refuse_all(['--config',str(missing)],env,'missing-kv')
refuse_all(['--config-toml',str(missing)],env,'missing-toml')
invalid_toml=root/'invalid.toml';invalid_toml.write_text('[providers]\nanthropic="not-an-array"\n')
refuse_all(['--config-toml',str(invalid_toml)],env,'invalid-toml-type')
invalid_toml.write_text('[providers]\nmode="invalid"\n')
refuse_all(['--config-toml',str(invalid_toml)],env,'invalid-toml-mode')
invalid_toml.write_text(f'[providers\nsecret="{secret}"\n')
refuse_all(['--config-toml',str(invalid_toml)],env,'invalid-toml-syntax')
for variable in ['RANO_CONFIG','RANO_CONFIG_TOML']:
    for value in ['',str(missing)]:
        bad_env=env.copy();bad_env[variable]=value
        refuse_all([],bad_env,f'invalid-env-{variable}')
        assert show(['--no-config'],bad_env)[0]['effective']['interval_ms']==1000,'no-config did not suppress file/env discovery'
bad_preset=presets/'bad.conf';bad_preset.write_text('db_flush_ms=0\n')
refuse_all(['--preset','bad'],env,'invalid-preset')
print(f'PASS parsed defaults/ordered presets/XDG/env/CLI/provider origins/masking; {len(bad_cases)} invalid KV cases and explicit/env/preset/TOML negatives agree across check/show/runtime',flush=True)
baseline=os.environ.get('RANO_CONFIG_BASELINE')
if baseline:
    baseline_zero=call(['config','check','--config',str(root/'invalid-0.conf')],'baseline-check-zero',executable=baseline)
    baseline_runtime=call(['--config',str(root/'invalid-0.conf'),'--once','--no-dns','--no-sqlite','--no-banner'],'baseline-runtime-zero',executable=baseline)
    baseline_show=call(['config','show','--json'],'baseline-show',executable=baseline)
    assert baseline_zero.returncode==0 and baseline_runtime.returncode!=0,'baseline no longer discriminates flush-zero validity'
    assert baseline_show.returncode==0 and 'effective' not in json.loads(baseline_show.stdout) and secret in baseline_show.stdout,'baseline source dump no longer reproduces missing resolution/secret disclosure'
    print('PASS declared baseline executes same files: false flush-zero acceptance and raw-source credential disclosure reproduced',flush=True)
code=r'''
import json,os,socket,sys
listener=socket.socket();listener.bind(('127.0.0.1',0));listener.listen()
client=socket.create_connection(listener.getsockname());accepted,_=listener.accept()
udp_a=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);udp_a.bind(('127.0.0.1',0))
udp_b=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);udp_b.bind(('127.0.0.1',0))
udp_a.connect(udp_b.getsockname());udp_b.connect(udp_a.getsockname())
print(json.dumps({'pid':os.getpid()}),flush=True);sys.stdin.read(1)
'''
holder=subprocess.Popen([sys.executable,'-u','-c',code,marker,f'API_KEY={secret}'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True)
try:
    ready=json.loads(holder.stdout.readline());database=root/'observed.sqlite';log=root/'observed.jsonl'
    options=['--pid',str(ready['pid']),'--no-descendants','--preset','audit','--preset','team','--interval-ms','55','--include-udp','--pattern',marker,'--stats-view','provider','--config-toml',str(explicit_provider),'--sqlite',str(database),'--log-file',str(log),'--log-format','json','--no-dns','--no-banner','--json','--once']
    actual,_=show(options)
    assert actual['effective']['pid']==[ready['pid']] and actual['effective']['json'] is True and actual['effective']['include_udp'] is True and actual['effective']['interval_ms']==55,'show did not expose actual monitor request'
    assert call(['config','check',*options],'check-real').returncode==0,'real monitor request failed check'
    run=call(options,'real-monitor')
    assert run.returncode==0,f'real monitor failed: {run.stderr}'
    records=list(map(json.loads,run.stdout.splitlines()));events=[row for row in records if row.get('event')=='connect'];summary=next(row['summary'] for row in records if 'summary' in row)
    assert len(events)==4 and all(row['pid']==ready['pid'] and row['provider']=='anthropic' for row in events),'resolved process/provider/UDP configuration not used by monitoring'
    assert sorted(row['proto'] for row in events)==['tcp','tcp','udp','udp'],'UDP override did not affect real sockets'
    outcome=summary['sqlite'];assert summary['connects']==4 and outcome['observed']==outcome['persisted']==4 and not outcome['failed'] and outcome['metadata_lost']==outcome['queue_lost']==outcome['write_lost']==0,'real configuration run unhealthy or counts incorrect'
    with sqlite3.connect(database) as conn:
        assert conn.execute('SELECT interval_ms FROM sessions').fetchone()[0]==55,'effective poll interval not persisted'
        rows=conn.execute('SELECT provider,cmdline FROM events').fetchall();assert len(rows)==4 and all(provider=='anthropic' and secret not in cmdline for provider,cmdline in rows),'effective matcher/privacy not used by SQLite'
    logged=list(map(json.loads,log.read_text().splitlines()))
    assert sum(row.get('event')=='connect' for row in logged)==4 and secret not in log.read_text(),'effective log format/privacy not used by requested file sink'
    print('PASS same resolved/check/show request monitors four actual held TCP/UDP endpoints, exact provider/interval, four durable rows and masked JSON file records',flush=True)
finally:
    if holder.poll() is None:holder.stdin.write('x');holder.stdin.flush();holder.wait(timeout=5)
print(f'Retained effective configuration matrix: {root}',flush=True)
PY

# Summary
e2e_section "Summary"
e2e_info "All E2E config validation tests passed"
e2e_info "Tests verified:"
e2e_info "  - Valid config passes validation"
e2e_info "  - Unknown key produces warning"
e2e_info "  - Invalid number produces error"
e2e_info "  - Invalid boolean produces error"
e2e_info "  - Invalid enum value produces error"
e2e_info "  - Invalid TOML produces error"
e2e_info "  - Valid TOML passes validation"
e2e_info "  - config show displays resolved config"
e2e_info "  - config show --json outputs JSON"
e2e_info "  - config paths lists search locations"
e2e_info "  - Invalid stats_view value produces error"
e2e_info "  - Zero value for required positive integer produces error"
e2e_info "  - Invalid TOML provider mode produces error"
