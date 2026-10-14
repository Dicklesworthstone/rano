#!/usr/bin/env bash
set -euo pipefail

# This test verifies that `rano report` correctly queries and reports on seeded SQLite data.
# It creates a fixture database with known event data and validates:
# 1. Pretty output format with session info, summary, providers, domains, IPs
# 2. JSON output format with all expected fields
# 3. Filtering by --latest, --run-id, --since, --until, --top

TMP_DIR=$(mktemp -d)
cleanup() {
  e2e_info "Retained report fixtures: ${TMP_DIR}"
}
trap cleanup EXIT

# Ensure binary is built before test
RANO_BIN="${RANO_BIN:-${E2E_RANO_RELEASE}}"
if [ ! -x "${RANO_BIN}" ]; then
  e2e_fail "rano binary missing at ${RANO_BIN}; build the intended revision first"
fi

SQLITE_PATH="${TMP_DIR}/test-report.sqlite"

export E2E_FIXTURES="Seeded SQLite at ${SQLITE_PATH}"

e2e_section "Seed fixture database"
e2e_info "path=${SQLITE_PATH}"

# Create and seed the SQLite database with known test data
sqlite3 "${SQLITE_PATH}" <<'SQL'
-- Create schema (matches rano init_sqlite)
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;

CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    run_id TEXT,
    event TEXT NOT NULL,
    provider TEXT NOT NULL,
    pid INTEGER,
    comm TEXT,
    cmdline TEXT,
    proto TEXT,
    local_ip TEXT,
    local_port INTEGER,
    remote_ip TEXT,
    remote_port INTEGER,
    domain TEXT,
    remote_is_private INTEGER,
    ip_version INTEGER,
    duration_ms INTEGER
);

CREATE TABLE IF NOT EXISTS sessions (
    run_id TEXT PRIMARY KEY,
    start_ts TEXT NOT NULL,
    end_ts TEXT,
    host TEXT,
    user TEXT,
    patterns TEXT,
    domain_mode TEXT,
    args TEXT,
    interval_ms INTEGER,
    stats_interval_ms INTEGER,
    connects INTEGER,
    closes INTEGER
);

CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_run_id ON events(run_id);
CREATE INDEX IF NOT EXISTS idx_events_provider ON events(provider);
CREATE INDEX IF NOT EXISTS idx_events_remote_ip ON events(remote_ip);
CREATE INDEX IF NOT EXISTS idx_events_domain ON events(domain);

-- Seed session data
INSERT INTO sessions (run_id, start_ts, end_ts, host, user, patterns, domain_mode, interval_ms, stats_interval_ms, connects, closes)
VALUES
  ('test-run-001', '2026-01-15T10:00:00Z', '2026-01-15T11:00:00Z', 'testhost', 'testuser', 'claude,codex', 'ptr', 1000, 2000, 6, 3),
  ('test-run-002', '2026-01-17T14:00:00Z', '2026-01-17T15:30:00Z', 'testhost', 'testuser', 'claude', 'ptr', 1000, 2000, 4, 3);

-- Seed events for test-run-001 (older session)
-- Anthropic connections
INSERT INTO events (ts, run_id, event, provider, pid, comm, cmdline, proto, local_ip, local_port, remote_ip, remote_port, domain, remote_is_private, ip_version)
VALUES
  ('2026-01-15T10:05:00Z', 'test-run-001', 'connect', 'anthropic', 1234, 'claude', '/usr/bin/claude', 'tcp', '127.0.0.1', 54321, '104.18.12.34', 443, 'api.anthropic.com', 0, 4),
  ('2026-01-15T10:10:00Z', 'test-run-001', 'connect', 'anthropic', 1234, 'claude', '/usr/bin/claude', 'tcp', '127.0.0.1', 54322, '104.18.12.35', 443, 'api.anthropic.com', 0, 4);

INSERT INTO events (ts, run_id, event, provider, pid, comm, cmdline, proto, local_ip, local_port, remote_ip, remote_port, domain, remote_is_private, ip_version, duration_ms)
VALUES
  ('2026-01-15T10:15:00Z', 'test-run-001', 'close', 'anthropic', 1234, 'claude', '/usr/bin/claude', 'tcp', '127.0.0.1', 54321, '104.18.12.34', 443, 'api.anthropic.com', 0, 4, 600000);

-- OpenAI connections
INSERT INTO events (ts, run_id, event, provider, pid, comm, cmdline, proto, local_ip, local_port, remote_ip, remote_port, domain, remote_is_private, ip_version)
VALUES
  ('2026-01-15T10:20:00Z', 'test-run-001', 'connect', 'openai', 2345, 'codex', '/usr/bin/codex', 'tcp', '127.0.0.1', 55001, '13.107.42.14', 443, 'api.openai.com', 0, 4),
  ('2026-01-15T10:25:00Z', 'test-run-001', 'connect', 'openai', 2345, 'codex', '/usr/bin/codex', 'tcp', '127.0.0.1', 55002, '13.107.42.14', 443, 'api.openai.com', 0, 4),
  ('2026-01-15T10:30:00Z', 'test-run-001', 'connect', 'openai', 2345, 'codex', '/usr/bin/codex', 'tcp', '127.0.0.1', 55003, '20.42.73.28', 443, 'cdn.openai.com', 0, 4);

INSERT INTO events (ts, run_id, event, provider, pid, comm, cmdline, proto, local_ip, local_port, remote_ip, remote_port, domain, remote_is_private, ip_version, duration_ms)
VALUES
  ('2026-01-15T10:35:00Z', 'test-run-001', 'close', 'openai', 2345, 'codex', '/usr/bin/codex', 'tcp', '127.0.0.1', 55001, '13.107.42.14', 443, 'api.openai.com', 0, 4, 900000),
  ('2026-01-15T10:40:00Z', 'test-run-001', 'close', 'openai', 2345, 'codex', '/usr/bin/codex', 'tcp', '127.0.0.1', 55002, '13.107.42.14', 443, 'api.openai.com', 0, 4, 900000);

-- Unknown provider connection
INSERT INTO events (ts, run_id, event, provider, pid, comm, cmdline, proto, local_ip, local_port, remote_ip, remote_port, domain, remote_is_private, ip_version)
VALUES
  ('2026-01-15T10:45:00Z', 'test-run-001', 'connect', 'unknown', 9999, 'curl', '/usr/bin/curl', 'tcp', '127.0.0.1', 60000, '8.8.8.8', 443, 'dns.google', 0, 4);

-- Seed events for test-run-002 (more recent session)
INSERT INTO events (ts, run_id, event, provider, pid, comm, cmdline, proto, local_ip, local_port, remote_ip, remote_port, domain, remote_is_private, ip_version)
VALUES
  ('2026-01-17T14:05:00Z', 'test-run-002', 'connect', 'anthropic', 5678, 'claude', '/usr/bin/claude --help', 'tcp', '127.0.0.1', 56001, '104.18.12.34', 443, 'api.anthropic.com', 0, 4),
  ('2026-01-17T14:10:00Z', 'test-run-002', 'connect', 'anthropic', 5678, 'claude', '/usr/bin/claude --help', 'tcp', '127.0.0.1', 56002, '104.18.12.36', 443, 'cdn.anthropic.com', 0, 4),
  ('2026-01-17T14:15:00Z', 'test-run-002', 'connect', 'google', 6789, 'gemini', '/usr/bin/gemini', 'tcp', '127.0.0.1', 57001, '142.250.80.46', 443, 'generativelanguage.googleapis.com', 0, 4),
  ('2026-01-17T14:20:00Z', 'test-run-002', 'connect', 'google', 6789, 'gemini', '/usr/bin/gemini', 'tcp', '127.0.0.1', 57002, '142.250.80.46', 443, 'generativelanguage.googleapis.com', 0, 4);

INSERT INTO events (ts, run_id, event, provider, pid, comm, cmdline, proto, local_ip, local_port, remote_ip, remote_port, domain, remote_is_private, ip_version, duration_ms)
VALUES
  ('2026-01-17T14:25:00Z', 'test-run-002', 'close', 'anthropic', 5678, 'claude', '/usr/bin/claude --help', 'tcp', '127.0.0.1', 56001, '104.18.12.34', 443, 'api.anthropic.com', 0, 4, 1200000),
  ('2026-01-17T14:30:00Z', 'test-run-002', 'close', 'google', 6789, 'gemini', '/usr/bin/gemini', 'tcp', '127.0.0.1', 57001, '142.250.80.46', 443, 'generativelanguage.googleapis.com', 0, 4, 900000),
  ('2026-01-17T14:35:00Z', 'test-run-002', 'close', 'google', 6789, 'gemini', '/usr/bin/gemini', 'tcp', '127.0.0.1', 57002, '142.250.80.46', 443, 'generativelanguage.googleapis.com', 0, 4, 900000);
SQL

e2e_info "Seeded 2 sessions, 16 events total"
e2e_info "test-run-001: 9 events (anthropic:3, openai:5, unknown:1)"
e2e_info "test-run-002: 7 events (anthropic:3, google:4)"

# Verify seed data
event_count=$(sqlite3 "${SQLITE_PATH}" "SELECT COUNT(*) FROM events")
session_count=$(sqlite3 "${SQLITE_PATH}" "SELECT COUNT(*) FROM sessions")
e2e_info "Verified: ${event_count} events, ${session_count} sessions"

# =============================================================================
# Test 1: Report without filters (all data)
# =============================================================================
e2e_section "Expectations (all data)"
e2e_info "total_events=16"
e2e_info "providers=[anthropic, openai, google, unknown]"
e2e_info "top_domains should include api.anthropic.com, api.openai.com, generativelanguage.googleapis.com"

e2e_run "rano report (all data, pretty)" \
  "${RANO_BIN}" report --sqlite "${SQLITE_PATH}" --no-color

e2e_assert_last_status 0
e2e_assert_last_contains "rano report"
e2e_assert_last_contains "anthropic"
e2e_assert_last_contains "openai"
e2e_assert_last_contains "google"
e2e_assert_last_contains "api.anthropic.com"

# =============================================================================
# Test 2: JSON output format
# =============================================================================
e2e_section "Expectations (JSON output)"
e2e_info "JSON should have: meta, summary, providers, top_domains, top_ips"

e2e_run "rano report (all data, JSON)" \
  "${RANO_BIN}" report --sqlite "${SQLITE_PATH}" --json

e2e_assert_last_status 0
e2e_assert_last_contains '"summary"'
e2e_assert_last_contains '"providers"'
e2e_assert_last_contains '"top_domains"'
e2e_assert_last_contains '"top_ips"'
e2e_assert_last_contains '"total_events": 16'

# =============================================================================
# Test 3: --latest flag (most recent session)
# =============================================================================
e2e_section "Expectations (--latest)"
e2e_info "Should report on test-run-002 only"
e2e_info "events=7, providers=[anthropic, google]"

e2e_run "rano report --latest (JSON)" \
  "${RANO_BIN}" report --sqlite "${SQLITE_PATH}" --latest --json

e2e_assert_last_status 0
e2e_assert_last_contains '"run_id": "test-run-002"'
e2e_assert_last_contains '"total_events": 7'

# Verify openai is NOT in the latest session
if grep -q '"provider": "openai"' "${E2E_LAST_OUTPUT_FILE}"; then
  e2e_fail "Latest session should not contain openai provider"
fi
e2e_info "Confirmed: openai not in latest session"

# =============================================================================
# Test 4: --run-id filter
# =============================================================================
e2e_section "Expectations (--run-id test-run-001)"
e2e_info "Should report on test-run-001 only"
e2e_info "events=9, providers=[anthropic, openai, unknown]"

e2e_run "rano report --run-id test-run-001 (JSON)" \
  "${RANO_BIN}" report --sqlite "${SQLITE_PATH}" --run-id test-run-001 --json

e2e_assert_last_status 0
e2e_assert_last_contains '"run_id": "test-run-001"'
e2e_assert_last_contains '"total_events": 9'
e2e_assert_last_contains '"provider": "openai"'

# Verify google is NOT in run-001
if grep -q '"provider": "google"' "${E2E_LAST_OUTPUT_FILE}"; then
  e2e_fail "run-001 should not contain google provider"
fi
e2e_info "Confirmed: google not in run-001"

# =============================================================================
# Test 5: --top flag
# =============================================================================
e2e_section "Expectations (--top 2)"
e2e_info "top_domains and top_ips should have max 2 entries each"

e2e_run "rano report --top 2 (JSON)" \
  "${RANO_BIN}" report --sqlite "${SQLITE_PATH}" --top 2 --json

e2e_assert_last_status 0

# Count top_domains entries (count lines with "domain": followed by "events":)
# The top_domains array entries have format: {"domain": ..., "events": ..., "provider": ...}
# top_ips entries have: {"ip": ..., "events": ..., "domain": ...}
# So we look for entries starting with "domain": (use [[:space:]] for portability)
domain_count=$(grep -Ec '^[[:space:]]*\{"domain":' "${E2E_LAST_OUTPUT_FILE}" || true)
if [ "${domain_count}" -gt 2 ]; then
  e2e_fail "Expected max 2 top domains, got ${domain_count}"
fi
e2e_info "top_domains count: ${domain_count} (expected <= 2)"

# =============================================================================
# Test 6: --since time filter
# =============================================================================
e2e_section "Expectations (--since 2026-01-17)"
e2e_info "Should only include events from test-run-002"

e2e_run "rano report --since 2026-01-17 (JSON)" \
  "${RANO_BIN}" report --sqlite "${SQLITE_PATH}" --since 2026-01-17 --json

e2e_assert_last_status 0
e2e_assert_last_contains '"total_events": 7'

# =============================================================================
# Test 7: --until time filter
# =============================================================================
e2e_section "Expectations (--until 2026-01-16)"
e2e_info "Should only include events from test-run-001"

e2e_run "rano report --until 2026-01-16 (JSON)" \
  "${RANO_BIN}" report --sqlite "${SQLITE_PATH}" --until 2026-01-16 --json

e2e_assert_last_status 0
e2e_assert_last_contains '"total_events": 9'

# =============================================================================
# Test 8: Combined filters (--since + --until)
# =============================================================================
e2e_section "Expectations (--since 2026-01-15T10:20:00Z --until 2026-01-15T10:40:00Z)"
e2e_info "Should only include openai events from run-001 in that window"

e2e_run "rano report time window (JSON)" \
  "${RANO_BIN}" report --sqlite "${SQLITE_PATH}" \
    --since "2026-01-15T10:20:00Z" --until "2026-01-15T10:40:00Z" --json

e2e_assert_last_status 0
# Should have 4 events (3 openai connects + 1 openai close in that window)
e2e_assert_last_contains '"connects":'
e2e_assert_last_contains '"closes":'

# =============================================================================
# Test 9: Pretty output verification
# =============================================================================
e2e_section "Expectations (pretty output format)"
e2e_info "Should have structured sections with headers"

e2e_run "rano report --latest (pretty)" \
  "${RANO_BIN}" report --sqlite "${SQLITE_PATH}" --latest --no-color

e2e_assert_last_status 0
e2e_assert_last_contains "rano report"
e2e_assert_last_contains "Session"
e2e_assert_last_contains "Run ID:"
e2e_assert_last_contains "Summary"
e2e_assert_last_contains "Events:"
e2e_assert_last_contains "Providers"
e2e_assert_last_contains "Top Domains"
e2e_assert_last_contains "Top IPs"

# =============================================================================
# Test 10: Error handling - missing database
# =============================================================================
e2e_section "Expectations (missing database)"
e2e_info "Should fail gracefully with clear error message"

set +e
e2e_run "rano report (missing db)" \
  "${RANO_BIN}" report --sqlite "/nonexistent/path/db.sqlite"
set -e

if [ "${E2E_LAST_STATUS}" -eq 0 ]; then
  e2e_fail "Expected non-zero exit for missing database"
fi
e2e_assert_last_contains "not found"
e2e_info "Confirmed: graceful error for missing database"

# =============================================================================
# Test 11: Session metadata in pretty output
# =============================================================================
e2e_section "Expectations (session metadata)"
e2e_info "Pretty output should show host, patterns, start/end times"

e2e_run "rano report --run-id test-run-001 (session info)" \
  "${RANO_BIN}" report --sqlite "${SQLITE_PATH}" --run-id test-run-001 --no-color

e2e_assert_last_status 0
e2e_assert_last_contains "test-run-001"
e2e_assert_last_contains "testhost"
e2e_assert_last_contains "claude,codex"

e2e_section "Independent UTC/session/error query matrix"
python3 - "${RANO_BIN}" "${TMP_DIR}" <<'PY' || e2e_fail "UTC/session query matrix failed"
import csv,io,json,pathlib,sqlite3,subprocess,sys
binary=sys.argv[1];root=pathlib.Path(sys.argv[2])/'query-matrix';root.mkdir();database=root/'events.sqlite'
schema='''CREATE TABLE events(id INTEGER PRIMARY KEY,ts TEXT NOT NULL,run_id TEXT,event TEXT,provider TEXT,pid INTEGER,comm TEXT,cmdline TEXT,proto TEXT,local_ip TEXT,local_port INTEGER,remote_ip TEXT,remote_port INTEGER,domain TEXT,domain_source TEXT,ancestry_path TEXT,duration_ms INTEGER,alert INTEGER,retry_count INTEGER,ownership_json TEXT);
CREATE TABLE sessions(run_id TEXT PRIMARY KEY,start_ts TEXT,end_ts TEXT,host TEXT,user TEXT,patterns TEXT,domain_mode TEXT,args TEXT,interval_ms INTEGER,stats_interval_ms INTEGER,connects INTEGER,closes INTEGER,session_name TEXT);
CREATE INDEX events_run ON events(run_id);CREATE INDEX events_time ON events(ts);'''
with sqlite3.connect(database) as conn:
    conn.executescript(schema)
    conn.executemany('INSERT INTO sessions(run_id,start_ts,session_name) VALUES(?,?,?)',[
        ('a-old','2026-04-02T00:00:00Z','alpha'),('b-empty','2026-04-02T12:00:00+01:00','beta-empty'),('time','2026-04-01T00:00:00Z','time-cases')])
    conn.execute("INSERT INTO events(ts,run_id,event,provider,comm,remote_ip,remote_port,domain) VALUES('2026-04-03T00:00:00Z','a-old','connect','anthropic','old','127.0.0.1',443,'old.test')")
    times=['2026-04-02T01:00:00.000000001+01:00','2026-04-02T00:00:00.000000002Z','2026-04-01T19:00:00.000000003-05:00']
    conn.executemany("INSERT INTO events(ts,run_id,event,provider,comm,remote_ip,remote_port,domain) VALUES(?,'time','connect','openai',?,'127.0.0.1',443,?)",[(stamp,'長'*30,'雪'*30) for stamp in times])
def run(label,args,success=True,db=database):
    result=subprocess.run([binary,*args,'--sqlite',str(db)],capture_output=True,text=True,timeout=20)
    (root/f'{label}.stdout').write_text(result.stdout);(root/f'{label}.stderr').write_text(result.stderr)
    assert (result.returncode==0)==success,f'{label}: unexpected exit {result.returncode}: {result.stderr}'
    return result
latest=json.loads(run('latest-empty',['report','--latest','--json']).stdout)
assert latest['meta']['run_id']=='b-empty' and latest['summary']['total_events']==0,'latest ignored empty metadata or used newer old event'
status=run('latest-empty-status',['status','--format','{active}|{total}|{session_name}|{state}']).stdout.strip()
assert status=='0|0|beta-empty|unverified','status ignored newer empty metadata'
diff=json.loads(run('named-empty-diff',['diff','--old','alpha','--new','beta-empty','--json']).stdout)
assert (diff['old_run_id'],diff['new_run_id'])==('a-old','b-empty') and diff['removed_domains']==['old.test'],'named/empty diff semantics wrong'
bounds=['--run-id','time','--since','2026-04-02T00:00:00.000000001Z','--until','2026-04-02T00:00:00.000000003Z']
report=json.loads(run('offset-fraction-report',['report','--json',*bounds]).stdout)
assert report['summary']['total_events']==report['summary']['connects']==2,'UTC/fraction boundaries wrong'
export=run('offset-fraction-export',['export','--format','jsonl',*bounds]).stdout
assert [row['ts'] for row in map(json.loads,export.splitlines())]==times[:2],'export filter/order differs from specified UTC timeline'
csv_output=run('all-time-order',['export','--format','csv','--run-id','time']).stdout
assert [row['ts'] for row in csv.DictReader(io.StringIO(csv_output))]==times,'ordering uses raw offset text rather than UTC'
run('unicode-pretty',['report','--run-id','time','--color','never'])
for index,value in enumerate(['2026-99-99','2023-02-29','雪雪雪雪','18446744073709551615w','2026-04-02T00:00:60Z','2026-04-02T00:00:00-00:00']):
    for command in ['report','export']:
        invalid=run(f'invalid-{command}-{index}',[command,'--since',value],False)
        assert not invalid.stdout,'invalid filter emitted partial data'
for command in ['report','export']:
    run(f'missing-{command}',[command,'--run-id','absent'],False)
    run(f'reversed-{command}',[command,'--since','2026-04-03','--until','2026-04-02'],False)
    run(f'equal-{command}',[command,'--since','2026-04-02','--until','2026-04-02'],False)
for index,value in enumerate(['NaN','inf','-inf']):run(f'nonfinite-{index}',['diff','--old','alpha','--new','beta-empty','--threshold',value],False)
with sqlite3.connect(database) as conn:
    conn.execute("INSERT INTO sessions(run_id,start_ts,session_name) VALUES('c-empty','2026-04-02T11:00:00Z','beta-empty')")
ambiguous=run('ambiguous-name',['diff','--old','alpha','--new','beta-empty'],False)
assert 'b-empty' in ambiguous.stderr and 'c-empty' in ambiguous.stderr and 'exact run ID' in ambiguous.stderr,'ambiguity lacks actionable IDs'
latest=json.loads(run('deterministic-tie',['report','--latest','--json']).stdout)
assert latest['meta']['run_id']=='c-empty','equal-instant session tie not deterministic'
same=json.loads(run('zero-threshold-identical',['diff','--old','time','--new','time','--threshold','0','--json']).stdout)
assert not same['changed_domains'] and not same['provider_changes'],'identical sessions reported as changed'
legacy=root/'legacy.sqlite'
with sqlite3.connect(legacy) as conn:
    conn.executescript(schema.split('CREATE TABLE sessions')[0])
    conn.executemany("INSERT INTO events(ts,run_id,event,provider,remote_ip,domain) VALUES(?,?,'connect','unknown','127.0.0.1','legacy.test')",[
        ('2026-04-02T12:00:00+02:00','later-text'),('2026-04-02T10:30:00Z','later-utc'),('2026-04-02T09:00:00Z','later-text')])
latest=json.loads(run('legacy-interleaved',['report','--latest','--json'],db=legacy).stdout)
assert latest['meta']['run_id']=='later-utc','legacy fallback uses arbitrary or lexical event time'
broken=root/'bad-schema.sqlite'
with sqlite3.connect(broken) as conn:conn.execute('CREATE TABLE events(id INTEGER,event TEXT)')
run('schema-error-status',['status'],False,broken)
run('schema-error-report',['report','--json'],False,broken)
print('PASS UTC offsets/nanoseconds/order, missing/empty/named/ambiguous sessions, legacy fallback, Unicode, malformed/range/nonfinite/schema negatives',flush=True)

insights=root/'insights.sqlite'
timeline=[
 ('2026-01-01T00:59:59Z','connect','anthropic','a.test','1.1.1.1',999000),
 ('2026-01-01T01:00:00Z','connect','openai','b.test','2.2.2.2',None),
 ('2026-01-01T02:00:00+01:00','close','anthropic','a.test','1.1.1.1',0),
 ('2026-01-01T01:00:01Z','connect','anthropic','c.test','1.1.1.1',None),
 ('2026-01-01T01:00:02Z','close','openai','b.test','2.2.2.2',1000),
 ('2026-01-01T01:00:03Z','close','anthropic','c.test','1.1.1.1',2000),
]
with sqlite3.connect(insights) as conn:
    conn.executescript(schema)
    conn.execute("INSERT INTO sessions(run_id,start_ts,end_ts,connects,closes,session_name) VALUES('timeline','2026-01-01T00:59:59Z','2026-01-01T01:00:04Z',3,3,'timeline')")
    conn.executemany("INSERT INTO events(ts,event,provider,domain,remote_ip,duration_ms,run_id) VALUES(?,?,?,?,?,?,'timeline')",timeline)
def insight(label,bounds=(),run_id='timeline',db=insights):
    return json.loads(run(label,['report','--json','--run-id',run_id,*bounds],db=db).stdout)
full=insight('insights-full');summary=full['summary']
assert (summary['total_events'],summary['connects'],summary['closes'])==(6,3,3),'insight count regression'
assert (summary['avg_duration_ms'],summary['max_duration_ms'],summary['duration_samples'])==(1000,2000,3),'connect durations incorrectly included or valid zero excluded'
assert summary['peak_active']==2 and summary['peak_unavailable_reason'] is None and summary['peak_basis']=='max_per_session_stored_episode_balance','timeline peak/basis incorrect'
assert full['hourly_activity']==[{'hour':'2026-01-01T00:00:00Z','providers':{'anthropic':1}},{'hour':'2026-01-01T01:00:00Z','providers':{'anthropic':3,'openai':2}}],'hour bins use original offsets or wrong counts'
providers={row['provider']:row for row in full['providers']}
assert (providers['anthropic']['domains'],providers['anthropic']['ips'])==(2,1) and (providers['openai']['domains'],providers['openai']['ips'])==(1,1),'distinct provider counts incorrect'
clipped=insight('insights-clipped',['--since','2026-01-01T01:00:02Z','--until','2026-01-01T01:00:04Z'])
assert (clipped['summary']['connects'],clipped['summary']['closes'],clipped['summary']['peak_active'])==(0,2,2),'opening window balance was discarded'
assert clipped['summary']['avg_duration_ms']==1500 and clipped['summary']['duration_samples']==2,'duration window includes earlier closes'
assert clipped['meta']['metric_scope']=='selected_window' and clipped['meta']['session_metadata_scope']=='full_session' and clipped['session']['connects']==clipped['session']['closes']==3,'window metrics misrepresent full session metadata'
no_close=insight('insights-no-close',['--since','2026-01-01T00:59:59Z','--until','2026-01-01T01:00:00Z'])['summary']
assert no_close['avg_duration_ms'] is None and no_close['max_duration_ms'] is None and no_close['duration_samples']==0 and no_close['peak_active']==1,'no-close window invented duration zero'
zero=insight('insights-zero',['--since','2026-01-01T01:00:00Z','--until','2026-01-01T01:00:01Z'])['summary']
assert (zero['avg_duration_ms'],zero['max_duration_ms'],zero['duration_samples'])==(0,0,1),'legitimate zero duration is unavailable'
pretty=run('insights-pretty',['report','--run-id','timeline','--no-color'],db=insights).stdout
assert 'Close durations: avg=1000.000ms max=2000ms samples=3' in pretty and 'Observed event peak: 2' in pretty and 'Hourly Activity (UTC' in pretty,'pretty and JSON insight semantics differ'
with sqlite3.connect(insights) as conn:
    for name,count in [('independent-a',2),('independent-b',3)]:
        conn.executemany("INSERT INTO events(ts,event,provider,domain,remote_ip,run_id) VALUES('2026-01-02T00:00:00Z','connect','unknown','independent.test','3.3.3.3',?)",[(name,)]*count)
    conn.execute("INSERT INTO events(ts,event,provider,domain,remote_ip,run_id) VALUES('2026-01-03T00:00:00Z','close','unknown','orphan.test','4.4.4.4','orphan')")
independent=json.loads(run('insights-independent',['report','--json','--since','2026-01-02','--until','2026-01-03'],db=insights).stdout)
assert independent['summary']['peak_active']==3,'separate observers were added into one invented network peak'
orphan=insight('insights-orphan',run_id='orphan')['summary']
assert orphan['peak_active'] is None and orphan['peak_unavailable_reason']=='unmatched_close_in_history','missing opening history produced a confident peak'
with sqlite3.connect(insights) as conn:
    conn.executemany("INSERT INTO events(ts,event,provider,domain,remote_ip,run_id) VALUES('2026-01-04T00:00:00Z','connect',?,?,?,'ties')",[
        ('openai','z.test','2.2.2.2'),('anthropic','a.test','1.1.1.1'),('openai','a.test','2.2.2.2'),('anthropic','z.test','1.1.1.1')])
ties=insight('insights-ties',run_id='ties')
assert [row['provider'] for row in ties['providers']]==['anthropic','openai'],'provider count ties unstable'
assert [row['domain'] for row in ties['top_domains']]==['a.test','a.test','z.test','z.test'],'domain ties unstable'
assert [row['ip'] for row in ties['top_ips']]==['1.1.1.1','2.2.2.2'] and all(row['domain']=='a.test' for row in ties['top_ips']),'IP ties/domain representative arbitrary'
with sqlite3.connect(insights) as conn:conn.execute("INSERT INTO events(ts,event,provider,run_id,duration_ms) VALUES('bad-time','close','unknown','malformed',-1)")
malformed=insight('insights-malformed',run_id='malformed')
assert malformed['unbucketed_events']==1 and malformed['summary']['peak_active'] is None and malformed['summary']['peak_unavailable_reason']=='invalid_event_timestamps','invalid history silently became ordered activity'
assert malformed['summary']['avg_duration_ms'] is None and malformed['summary']['duration_samples']==0,'invalid negative duration accepted'
run('insights-malformed-range',['report','--json','--run-id','malformed','--since','2026-01-01'],False,insights)
no_duration=root/'no-duration.sqlite'
with sqlite3.connect(no_duration) as conn:
    conn.execute('CREATE TABLE events(ts TEXT,run_id TEXT,event TEXT,provider TEXT,remote_ip TEXT,domain TEXT)')
    conn.execute("INSERT INTO events VALUES('2026-01-01T00:00:00Z','minimal','connect','unknown','1.1.1.1','minimal.test')")
minimal=insight('insights-no-duration',run_id='minimal',db=no_duration)
assert minimal['summary']['avg_duration_ms'] is None and minimal['summary']['max_duration_ms'] is None and minimal['summary']['duration_samples']==0 and minimal['summary']['peak_active']==1,'missing duration metadata invented values or broke stable rowid ordering'
with sqlite3.connect(no_duration) as conn:conn.execute("INSERT INTO events(ts,run_id,event,provider,remote_ip,domain) VALUES('2026-01-05T00:00:00Z',NULL,'connect','unknown','2.2.2.2','unidentified.test')")
missing_identity=json.loads(run('insights-missing-identity',['report','--json'],db=no_duration).stdout)
assert missing_identity['summary']['peak_active'] is None and missing_identity['summary']['peak_unavailable_reason']=='run_identity_unavailable','unidentified history yielded a confident peak'
without_order=root/'without-order.sqlite'
with sqlite3.connect(without_order) as conn:
    conn.execute('CREATE TABLE events(ts TEXT PRIMARY KEY,run_id TEXT,event TEXT,provider TEXT,remote_ip TEXT,domain TEXT) WITHOUT ROWID')
    conn.execute("INSERT INTO events VALUES('2026-01-01T00:00:00Z','unordered','connect','unknown','1.1.1.1','minimal.test')")
unordered=insight('insights-without-order',run_id='unordered',db=without_order)
assert unordered['summary']['peak_active'] is None and unordered['summary']['peak_unavailable_reason']=='stable_event_order_unavailable','missing stable order fabricated a peak'
baseline=__import__('os').environ.get('RANO_REPORT_BASELINE')
if baseline:
    result=subprocess.run([baseline,'report','--sqlite',str(insights),'--run-id','timeline','--json'],capture_output=True,text=True,timeout=20)
    (root/'insights-baseline.stdout').write_text(result.stdout);(root/'insights-baseline.stderr').write_text(result.stderr)
    assert result.returncode==0 and 'avg_duration_ms' not in json.loads(result.stdout)['summary'] and 'hourly_activity' not in json.loads(result.stdout),'baseline no longer discriminates omitted report capability'
print('PASS independently seeded UTC hourly/duration/zero/no-close/peak/window/distinct/tie/malformed/minimal-schema report insights; no live-packet peak claimed',flush=True)
PY

e2e_section "Report from actual held and churning TCP sockets"
python3 - "${RANO_BIN}" "${TMP_DIR}" <<'PY' || e2e_fail "Live socket report insights failed"
import collections,datetime,json,os,pathlib,signal,socket,sqlite3,subprocess,sys,time
binary=sys.argv[1];root=pathlib.Path(sys.argv[2])/'live-report';root.mkdir();database=root/'events.sqlite'
listener=socket.socket();listener.bind(('127.0.0.1',0));listener.listen()
pairs=[]
def open_pair():
    client=socket.create_connection(listener.getsockname());server,_=listener.accept();pairs.append((client,server))
def counts():
    if not database.exists():return (0,0)
    try:
        with sqlite3.connect(database,timeout=1) as conn:
            return conn.execute("SELECT COUNT(CASE WHEN event='connect' THEN 1 END),COUNT(CASE WHEN event='close' THEN 1 END) FROM events").fetchone()
    except sqlite3.OperationalError:return (0,0)
def wait_counts(expected):
    deadline=time.monotonic()+20
    while time.monotonic()<deadline:
        assert monitor.poll() is None,'observer exited before the live workload completed'
        actual=counts()
        if actual==expected:return
        assert actual[0]<=expected[0] and actual[1]<=expected[1],f'unexpected socket counts {actual}, expected {expected}'
        time.sleep(.05)
    raise AssertionError(f'observer did not reach {expected}; got {counts()}')
monitor=None
with (root/'monitor.stdout').open('w') as stdout,(root/'monitor.stderr').open('w') as stderr:
    try:
        open_pair();open_pair()
        monitor=subprocess.Popen([binary,'--no-config','--pid',str(os.getpid()),'--no-descendants','--no-dns','--no-banner','--json',
            '--interval-ms','50','--stats-interval-ms','0','--db-flush-ms','50','--sqlite',str(database)],stdout=stdout,stderr=stderr)
        wait_counts((4,0))
        for sock in pairs.pop(0):sock.close()
        wait_counts((4,2))
        open_pair();wait_counts((6,2))
        for pair in pairs:
            for sock in pair:sock.close()
        pairs.clear();wait_counts((6,6))
        monitor.send_signal(signal.SIGINT)
        assert monitor.wait(timeout=20)==0,'live observer completed unhealthy'
    finally:
        for pair in pairs:
            for sock in pair:sock.close()
        listener.close()
        if monitor is not None and monitor.poll() is None:
            monitor.send_signal(signal.SIGINT);monitor.wait(timeout=20)
summaries=[row['summary'] for row in map(json.loads,(root/'monitor.stdout').read_text().splitlines()) if isinstance(row.get('summary'),dict)]
assert len(summaries)==1 and summaries[0]['sqlite_dropped']==0,'missing summary or lost durable events'
with sqlite3.connect(database) as conn:
    run_id=conn.execute('SELECT run_id FROM sessions').fetchone()[0]
    rows=conn.execute("SELECT id,ts,event,provider,duration_ms,remote_ip,domain FROM events WHERE event IN ('connect','close') ORDER BY id").fetchall()
assert len(rows)==12 and counts()==(6,6),'live socket ledger does not reconcile'
def utc(stamp):return datetime.datetime.fromisoformat(stamp.replace('Z','+00:00')).astimezone(datetime.timezone.utc)
balance=0;peak=0;durations=[];hours=collections.defaultdict(collections.Counter)
for event_id,stamp,event,provider,duration,ip,domain in sorted(rows,key=lambda row:(utc(row[1]),row[0])):
    balance+=1 if event=='connect' else -1
    assert balance>=0,'live close lacks an opening observation'
    peak=max(peak,balance)
    hours[utc(stamp).strftime('%Y-%m-%dT%H:00:00Z')][provider]+=1
    if event=='close':
        assert isinstance(duration,int) and duration>=0,'live close duration missing or invalid'
        durations.append(duration)
assert balance==0 and peak==4 and len(durations)==6,'controlled held/churning socket phases changed'
result=subprocess.run([binary,'report','--sqlite',str(database),'--run-id',run_id,'--json'],capture_output=True,text=True,timeout=20)
(root/'report.stdout').write_text(result.stdout);(root/'report.stderr').write_text(result.stderr)
assert result.returncode==0,result.stderr
report=json.loads(result.stdout);summary=report['summary']
assert (summary['connects'],summary['closes'],summary['peak_active'])==(6,6,4),'report differs from controlled live phases'
assert summary['duration_samples']==6 and abs(summary['avg_duration_ms']-sum(durations)/6)<.000001 and summary['max_duration_ms']==max(durations),'report durations differ from real stored closes'
assert report['hourly_activity']==[{'hour':hour,'providers':dict(providers)} for hour,providers in sorted(hours.items())],'live UTC bins differ from independently parsed ledger'
assert sum(row['events'] for row in report['providers'])==12 and sum(row['ips'] for row in report['providers'])==1,'live provider/IP totals changed'
print('PASS live sockets: six endpoint opens, six closes, observed ledger peak four, six real durations, UTC bins, healthy lossless writer',flush=True)
PY

e2e_section "Summary"
e2e_info "All report tests passed"
e2e_info "Tested: all data, JSON, --latest, --run-id, --top, --since, --until, pretty format, error handling"
