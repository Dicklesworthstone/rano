use libc;
use rusqlite::{params, Connection};
use serde::Deserialize;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::env;
use std::ffi::CStr;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::process::Command as ProcessCommand;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

mod pcap_capture;

static RUNNING: AtomicBool = AtomicBool::new(true);

const SQLITE_QUEUE_CAPACITY: usize = 10_000;
const SQLITE_BATCH_SIZE: usize = 200;
const SQLITE_FLUSH_INTERVAL_MS: u64 = 1000;
const SQLITE_DROP_WARN_INTERVAL_SECS: u64 = 10;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ColorMode {
    Auto,
    Always,
    Never,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DomainMode {
    Auto,
    Ptr,
    Pcap,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LogFormat {
    Auto,
    Pretty,
    Json,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Theme {
    Vivid,
    Mono,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StatsView {
    Provider,
    Domain,
    Port,
    Process,
}

struct Cli {
    command: Option<Command>,
    monitor: MonitorArgs,
}

enum Command {
    Update(UpdateCommand),
    Report(ReportArgs),
}

#[derive(Clone, Debug)]
struct ConfigPaths {
    kv_path: Option<PathBuf>,
    toml_path: Option<PathBuf>,
    use_config: bool,
}

#[derive(Clone, Debug)]
struct MonitorArgs {
    patterns: Vec<String>,
    exclude_patterns: Vec<String>,
    pids: Vec<u32>,
    no_descendants: bool,
    interval_ms: u64,
    json: bool,
    summary_only: bool,
    domain_mode: DomainMode,
    pcap: bool,
    no_dns: bool,
    include_udp: bool,
    include_listening: bool,
    log_file: Option<PathBuf>,
    log_dir: Option<PathBuf>,
    log_format: LogFormat,
    once: bool,
    color: ColorMode,
    sqlite_path: String,
    no_sqlite: bool,
    db_batch_size: usize,
    db_flush_ms: u64,
    db_queue_max: usize,
    stats_interval_ms: u64,
    stats_width: usize,
    stats_width_set: bool,
    stats_top: usize,
    stats_views: Vec<StatsView>,
    stats_cycle_ms: u64,
    no_banner: bool,
    theme: Theme,
}

impl Default for MonitorArgs {
    fn default() -> Self {
        Self {
            patterns: Vec::new(),
            exclude_patterns: Vec::new(),
            pids: Vec::new(),
            no_descendants: false,
            interval_ms: 1000,
            json: false,
            summary_only: false,
            domain_mode: DomainMode::Auto,
            pcap: false,
            no_dns: false,
            include_udp: true,
            include_listening: false,
            log_file: None,
            log_dir: None,
            log_format: LogFormat::Auto,
            once: false,
            color: ColorMode::Auto,
            sqlite_path: "observer.sqlite".to_string(),
            no_sqlite: false,
            db_batch_size: SQLITE_BATCH_SIZE,
            db_flush_ms: SQLITE_FLUSH_INTERVAL_MS,
            db_queue_max: SQLITE_QUEUE_CAPACITY,
            stats_interval_ms: 5000,
            stats_width: 40,
            stats_width_set: false,
            stats_top: 5,
            stats_views: Vec::new(),
            stats_cycle_ms: 0,
            no_banner: false,
            theme: Theme::Vivid,
        }
    }
}

#[derive(Clone, Debug)]
struct UpdateCommand {
    version: Option<String>,
    system: bool,
    easy_mode: bool,
    dest: Option<PathBuf>,
    from_source: bool,
    verify: bool,
    quiet: bool,
    no_gum: bool,
    owner: Option<String>,
    repo: Option<String>,
    branch: Option<String>,
}

#[derive(Clone, Debug)]
struct ReportArgs {
    sqlite_path: String,
    latest: bool,
    run_id: Option<String>,
    since: Option<String>,
    until: Option<String>,
    json: bool,
    top: usize,
    color: ColorMode,
}

impl Default for ReportArgs {
    fn default() -> Self {
        Self {
            sqlite_path: "observer.sqlite".to_string(),
            latest: false,
            run_id: None,
            since: None,
            until: None,
            json: false,
            top: 10,
            color: ColorMode::Auto,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
enum Proto {
    Tcp,
    Udp,
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
struct ConnKey {
    proto: Proto,
    local_ip: IpAddr,
    local_port: u16,
    remote_ip: IpAddr,
    remote_port: u16,
}

#[derive(Clone, Debug)]
struct ConnInfo {
    pid: u32,
    comm: String,
    cmdline: String,
    provider: Provider,
    domain: Option<String>,
    opened_at: SystemTime,
    last_seen: SystemTime,
}

#[derive(Clone, Debug)]
struct NetEntry {
    local_ip: IpAddr,
    local_port: u16,
    remote_ip: IpAddr,
    remote_port: u16,
    inode: u64,
    state: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
enum Provider {
    Anthropic,
    OpenAI,
    Google,
    Unknown,
}

impl Provider {
    fn label(self) -> &'static str {
        match self {
            Provider::Anthropic => "anthropic",
            Provider::OpenAI => "openai",
            Provider::Google => "google",
            Provider::Unknown => "unknown",
        }
    }
}

#[derive(Clone, Debug)]
struct ProviderMatcher {
    anthropic: Vec<String>,
    openai: Vec<String>,
    google: Vec<String>,
}

impl Default for ProviderMatcher {
    fn default() -> Self {
        Self {
            anthropic: vec!["claude".to_string(), "anthropic".to_string()],
            openai: vec!["codex".to_string(), "openai".to_string()],
            google: vec!["gemini".to_string(), "google".to_string()],
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProviderMode {
    Merge,
    Replace,
}

#[derive(Debug, Deserialize)]
struct TomlConfig {
    providers: Option<ProvidersConfig>,
}

#[derive(Debug, Deserialize)]
struct ProvidersConfig {
    mode: Option<String>,
    anthropic: Option<Vec<String>>,
    openai: Option<Vec<String>>,
    google: Option<Vec<String>>,
}

#[derive(Default)]
struct Stats {
    connects: u64,
    closes: u64,
    active: u64,
    peak_active: u64,
    sqlite_dropped: u64,
    per_ip: BTreeMap<IpAddr, u64>,
    per_port: BTreeMap<u16, u64>,
    per_domain: BTreeMap<String, u64>,
    per_pid: BTreeMap<u32, u64>,
    per_comm: BTreeMap<String, u64>,
    per_provider: BTreeMap<Provider, u64>,
    per_provider_domains: BTreeMap<Provider, HashSet<String>>,
    per_provider_ips: BTreeMap<Provider, HashSet<IpAddr>>,
    duration_ms_total: u64,
    duration_ms_max: u64,
    duration_ms_samples: u64,
}

#[derive(Clone)]
struct RunContext {
    run_id: String,
    start_ts: String,
    host: String,
    user: String,
    patterns: String,
    domain_label: String,
    args_snapshot: String,
    interval_ms: u64,
    stats_interval_ms: u64,
}

impl RunContext {
    fn new(args: &MonitorArgs, domain_label: &str) -> Self {
        let start_ts = now_rfc3339();
        let millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        let run_id = format!("{}-{}", std::process::id(), millis);
        let host = hostname();
        let user = env::var("USER").unwrap_or_else(|_| "unknown".to_string());
        let args_snapshot = env::args().collect::<Vec<_>>().join(" ");
        let patterns = args.patterns.join(", ");
        Self {
            run_id,
            start_ts,
            host,
            user,
            patterns,
            domain_label: domain_label.to_string(),
            args_snapshot,
            interval_ms: args.interval_ms,
            stats_interval_ms: args.stats_interval_ms,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code)]
enum AnsiColor {
    Red,
    Green,
    Yellow,
    Blue,
    Magenta,
    Cyan,
    White,
    BrightBlack,
    BrightRed,
    BrightGreen,
    BrightYellow,
    BrightBlue,
    BrightMagenta,
    BrightCyan,
    BrightWhite,
}

impl AnsiColor {
    fn code(self) -> &'static str {
        match self {
            AnsiColor::Red => "31",
            AnsiColor::Green => "32",
            AnsiColor::Yellow => "33",
            AnsiColor::Blue => "34",
            AnsiColor::Magenta => "35",
            AnsiColor::Cyan => "36",
            AnsiColor::White => "37",
            AnsiColor::BrightBlack => "90",
            AnsiColor::BrightRed => "91",
            AnsiColor::BrightGreen => "92",
            AnsiColor::BrightYellow => "93",
            AnsiColor::BrightBlue => "94",
            AnsiColor::BrightMagenta => "95",
            AnsiColor::BrightCyan => "96",
            AnsiColor::BrightWhite => "97",
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct OutputStyle {
    color: bool,
    theme: Theme,
}

impl OutputStyle {
    fn provider_color(self, provider: Provider) -> Option<AnsiColor> {
        if !self.color || self.theme == Theme::Mono {
            return None;
        }
        Some(match provider {
            Provider::Anthropic => AnsiColor::Magenta,
            Provider::OpenAI => AnsiColor::BrightGreen,
            Provider::Google => AnsiColor::BrightBlue,
            Provider::Unknown => AnsiColor::BrightBlack,
        })
    }

    fn event_color(self, event: &str) -> Option<AnsiColor> {
        if !self.color || self.theme == Theme::Mono {
            return None;
        }
        match event {
            "connect" => Some(AnsiColor::BrightGreen),
            "close" => Some(AnsiColor::BrightYellow),
            _ => Some(AnsiColor::BrightWhite),
        }
    }

    fn accent(self) -> Option<AnsiColor> {
        if !self.color || self.theme == Theme::Mono {
            return None;
        }
        Some(AnsiColor::BrightCyan)
    }
}

struct LogWriter {
    file: Mutex<std::fs::File>,
}

impl LogWriter {
    fn write_line(&self, line: &str) {
        if let Ok(mut file) = self.file.lock() {
            let _ = writeln!(file, "{}", line);
        }
    }
}

#[derive(Clone, Debug)]
struct SqliteEvent {
    ts: String,
    run_id: String,
    event: String,
    key: ConnKey,
    pid: u32,
    comm: String,
    cmdline: String,
    provider: Provider,
    domain: Option<String>,
    duration_ms: Option<u64>,
}

enum SqliteMsg {
    Event(SqliteEvent),
    Shutdown {
        run_id: String,
        connects: u64,
        closes: u64,
    },
}

struct DropState {
    last_warn: SystemTime,
    dropped_since_warn: u64,
}

struct SqliteWriter {
    sender: SyncSender<SqliteMsg>,
    handle: Option<std::thread::JoinHandle<()>>,
    dropped_total: Arc<std::sync::atomic::AtomicU64>,
    drop_state: Mutex<DropState>,
    log_writer: Option<Arc<LogWriter>>,
}

impl SqliteWriter {
    fn enqueue(&self, event: SqliteEvent) {
        match self.sender.try_send(SqliteMsg::Event(event)) {
            Ok(_) => {}
            Err(TrySendError::Full(_)) => {
                self.record_drop(1);
            }
            Err(TrySendError::Disconnected(_)) => {
                self.record_drop(1);
            }
        }
    }

    fn shutdown(mut self, run_id: String, connects: u64, closes: u64) -> u64 {
        let _ = self
            .sender
            .send(SqliteMsg::Shutdown { run_id, connects, closes });
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
        self.dropped_total.load(Ordering::Relaxed)
    }

    fn record_drop(&self, count: u64) {
        let total = self.dropped_total.fetch_add(count, Ordering::Relaxed) + count;
        let mut state = match self.drop_state.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        state.dropped_since_warn += count;
        let now = SystemTime::now();
        let warn_due = now
            .duration_since(state.last_warn)
            .map(|d| d >= Duration::from_secs(SQLITE_DROP_WARN_INTERVAL_SECS))
            .unwrap_or(true);
        if warn_due {
            let msg = format!(
                "warning: sqlite queue full, dropped {} events (total {})",
                state.dropped_since_warn, total
            );
            eprintln!("{}", msg);
            if let Some(writer) = self.log_writer.as_ref() {
                writer.write_line(&msg);
            }
            state.last_warn = now;
            state.dropped_since_warn = 0;
        }
    }
}

struct DnsCacheEntry {
    value: Option<String>,
    stored_at: SystemTime,
}

fn main() {
    let cli = match parse_cli() {
        Ok(cli) => cli,
        Err(err) => {
            eprintln!("error: {}", err);
            eprintln!("Run `rano --help` for usage.");
            std::process::exit(1);
        }
    };

    if let Some(command) = cli.command {
        match command {
            Command::Update(update) => {
                if let Err(err) = self_update(update) {
                    eprintln!("rano update failed: {}", err);
                    std::process::exit(1);
                }
                return;
            }
            Command::Report(report_args) => {
                if let Err(err) = run_report(report_args) {
                    eprintln!("error: {}", err);
                    std::process::exit(1);
                }
                return;
            }
        }
    }

    let mut args = cli.monitor;
    if args.pcap {
        args.domain_mode = DomainMode::Pcap;
    }
    if args.patterns.is_empty() && args.pids.is_empty() {
        args.patterns = default_patterns();
    }
    if args.stats_views.is_empty() {
        args.stats_views = vec![StatsView::Provider];
    }

    let cli_args: Vec<String> = env::args().collect();
    let config_paths = find_config_flag(&cli_args);
    let (provider_matcher, mut config_notes) = load_provider_matcher(&config_paths);

    let color_enabled = resolve_color_mode(args.color);
    let style = OutputStyle {
        color: color_enabled,
        theme: args.theme,
    };

    let (mut domain_mode, domain_note) = resolve_domain_mode(&args);
    let mut domain_notes: Vec<String> = Vec::new();
    if let Some(note) = domain_note {
        domain_notes.push(note);
    }

    setup_signal_handler();

    let mut pcap_handle: Option<pcap_capture::PcapHandle> = None;
    if domain_mode == DomainMode::Pcap {
        match pcap_capture::start_pcap_capture() {
            Ok(handle) => {
                pcap_handle = Some(handle);
            }
            Err(err) => {
                domain_notes.push(format!("pcap capture unavailable: {}", err));
                if let Some(hint) = pcap_permission_hint(&err) {
                    domain_notes.push(hint.to_string());
                }
                domain_mode = DomainMode::Ptr;
            }
        }
    }

    let ptr_enabled = !args.no_dns;
    if args.no_dns {
        domain_notes.push("PTR lookups disabled (--no-dns); PTR fallback disabled.".to_string());
    }
    domain_notes.append(&mut config_notes);
    let domain_label = if domain_mode == DomainMode::Pcap {
        "pcap"
    } else if ptr_enabled {
        "ptr"
    } else {
        "disabled"
    };

    let mut dns_cache: HashMap<IpAddr, DnsCacheEntry> = HashMap::new();
    let mut domain_cache = pcap_handle.as_ref().map(|_| pcap_capture::DomainCache::new());

    let mut active: HashMap<ConnKey, ConnInfo> = HashMap::new();
    let mut stats = Stats::default();

    let resolved_log_format = log_format_for_output(args.json, args.log_format);
    let log_writer = open_log_writer(&args, &domain_label, resolved_log_format);

    let run_ctx = RunContext::new(&args, domain_label);

    let sqlite_writer = if args.no_sqlite {
        None
    } else {
        start_sqlite_writer(&args, run_ctx.clone(), log_writer.clone())
    };

    if !args.no_banner {
        banner(&args, domain_label, &domain_notes, style, &log_writer);
    }

    let mut last_stats = SystemTime::now();
    let mut last_cycle = SystemTime::now();
    let mut stats_view_index: usize = 0;

    loop {
        if !RUNNING.load(Ordering::SeqCst) {
            break;
        }

        if let (Some(handle), Some(cache)) = (pcap_handle.as_ref(), domain_cache.as_mut()) {
            handle.drain_into(cache);
        }

        let roots = find_root_pids(&args.patterns, &args.exclude_patterns, &args.pids);
        let targets = if args.no_descendants {
            roots.iter().copied().collect::<HashSet<_>>()
        } else {
            collect_descendants(&roots)
        };
        let inode_to_pid = map_inodes(&targets);
        let pid_meta = build_pid_meta_map(&targets, &provider_matcher);

        let mut seen_keys: HashSet<ConnKey> = HashSet::new();
        let entries = gather_net_entries(args.include_udp);
        let now = SystemTime::now();

        for (proto, entry) in entries {
            if entry.remote_port == 0 {
                continue;
            }
            if !args.include_listening && entry.state == "0A" && proto == Proto::Tcp {
                continue;
            }

            let pid = match inode_to_pid.get(&entry.inode) {
                Some(pid) => *pid,
                None => continue,
            };
            if !targets.contains(&pid) {
                continue;
            }

            let key = ConnKey {
                proto,
                local_ip: entry.local_ip,
                local_port: entry.local_port,
                remote_ip: entry.remote_ip,
                remote_port: entry.remote_port,
            };

            seen_keys.insert(key.clone());

            if !active.contains_key(&key) {
                let domain = if let Some(cache) = domain_cache.as_mut() {
                    cache
                        .lookup(entry.remote_ip, entry.remote_port)
                        .or_else(|| {
                            if ptr_enabled {
                                resolve_domain(entry.remote_ip, &mut dns_cache)
                            } else {
                                None
                            }
                        })
                } else if ptr_enabled {
                    resolve_domain(entry.remote_ip, &mut dns_cache)
                } else {
                    None
                };
                let meta = pid_meta.get(&pid).cloned().unwrap_or_else(|| PidMeta {
                    comm: "unknown".to_string(),
                    cmdline: "".to_string(),
                    provider: Provider::Unknown,
                });

                let info = ConnInfo {
                    pid,
                    comm: meta.comm.clone(),
                    cmdline: meta.cmdline.clone(),
                    provider: meta.provider,
                    domain: domain.clone(),
                    opened_at: now,
                    last_seen: now,
                };
                active.insert(key.clone(), info);

                let ts = now_rfc3339();
                if let Some(writer) = sqlite_writer.as_ref() {
                    writer.enqueue(SqliteEvent {
                        ts: ts.clone(),
                        run_id: run_ctx.run_id.clone(),
                        event: "connect".to_string(),
                        key: key.clone(),
                        pid,
                        comm: meta.comm.clone(),
                        cmdline: meta.cmdline.clone(),
                        provider: meta.provider,
                        domain: domain.clone(),
                        duration_ms: None,
                    });
                }
                if !args.summary_only {
                    emit_event(
                        &ts,
                        "connect",
                        &run_ctx.run_id,
                        &key,
                        pid,
                        &meta.comm,
                        &meta.cmdline,
                        meta.provider,
                        domain.as_deref(),
                        None,
                        domain_label,
                        args.json,
                        style,
                        resolved_log_format,
                        log_writer.as_ref(),
                    );
                }

                stats.connects += 1;
                stats.active = stats.active.saturating_add(1);
                stats.peak_active = stats.peak_active.max(stats.active);
                *stats.per_ip.entry(entry.remote_ip).or_insert(0) += 1;
                *stats.per_port.entry(entry.remote_port).or_insert(0) += 1;
                *stats.per_pid.entry(pid).or_insert(0) += 1;
                *stats.per_comm.entry(meta.comm.clone()).or_insert(0) += 1;
                *stats.per_provider.entry(meta.provider).or_insert(0) += 1;
                stats
                    .per_provider_domains
                    .entry(meta.provider)
                    .or_default()
                    .extend(domain.iter().cloned());
                stats
                    .per_provider_ips
                    .entry(meta.provider)
                    .or_default()
                    .insert(entry.remote_ip);
                if let Some(name) = domain {
                    *stats.per_domain.entry(name).or_insert(0) += 1;
                }
            } else if let Some(info) = active.get_mut(&key) {
                info.last_seen = now;
            }
        }

        let stale_keys: Vec<ConnKey> = active
            .keys()
            .filter(|k| !seen_keys.contains(*k))
            .cloned()
            .collect();
        for key in stale_keys {
            if let Some(info) = active.remove(&key) {
                let duration_ms = now
                    .duration_since(info.opened_at)
                    .map(|d| d.as_millis() as u64)
                    .ok();
                let ts = now_rfc3339();
                if let Some(writer) = sqlite_writer.as_ref() {
                    writer.enqueue(SqliteEvent {
                        ts: ts.clone(),
                        run_id: run_ctx.run_id.clone(),
                        event: "close".to_string(),
                        key: key.clone(),
                        pid: info.pid,
                        comm: info.comm.clone(),
                        cmdline: info.cmdline.clone(),
                        provider: info.provider,
                        domain: info.domain.clone(),
                        duration_ms,
                    });
                }
                if !args.summary_only {
                    emit_event(
                        &ts,
                        "close",
                        &run_ctx.run_id,
                        &key,
                        info.pid,
                        &info.comm,
                        &info.cmdline,
                        info.provider,
                        info.domain.as_deref(),
                        duration_ms,
                        domain_label,
                        args.json,
                        style,
                        resolved_log_format,
                        log_writer.as_ref(),
                    );
                }
                stats.closes += 1;
                stats.active = stats.active.saturating_sub(1);
                if let Some(ms) = duration_ms {
                    stats.duration_ms_samples += 1;
                    stats.duration_ms_total = stats.duration_ms_total.saturating_add(ms);
                    stats.duration_ms_max = stats.duration_ms_max.max(ms);
                }
            }
        }

        if args.stats_interval_ms > 0 && !args.json {
            if let Ok(elapsed) = now.duration_since(last_stats) {
                if elapsed >= Duration::from_millis(args.stats_interval_ms) {
                    if args.stats_cycle_ms > 0
                        && args.stats_views.len() > 1
                        && !args.summary_only
                    {
                        let cycle_due = now
                            .duration_since(last_cycle)
                            .map(|d| d >= Duration::from_millis(args.stats_cycle_ms))
                            .unwrap_or(true);
                        if cycle_due {
                            stats_view_index = (stats_view_index + 1) % args.stats_views.len();
                            last_cycle = now;
                        }
                    }

                    let width = resolve_stats_width(&args);
                    let view = args
                        .stats_views
                        .get(stats_view_index)
                        .copied()
                        .unwrap_or(StatsView::Provider);
                    print_stats(&stats, width, args.stats_top, style, view);
                    last_stats = now;
                }
            }
        }

        if args.once {
            break;
        }
        std::thread::sleep(Duration::from_millis(args.interval_ms));
    }

    if let Some(writer) = sqlite_writer {
        stats.sqlite_dropped = writer.shutdown(run_ctx.run_id.clone(), stats.connects, stats.closes);
    }

    if let Some(handle) = pcap_handle.take() {
        handle.shutdown();
    }

    summary(
        &stats,
        args.json,
        args.stats_top,
        style,
        domain_label,
        log_writer.as_ref(),
    );
}

fn parse_cli() -> Result<Cli, String> {
    let args: Vec<String> = env::args().collect();
    if args.len() <= 1 {
        return Ok(Cli {
            command: None,
            monitor: load_monitor_args(&[])? ,
        });
    }

    match args[1].as_str() {
        "-h" | "--help" => {
            print_help();
            std::process::exit(0);
        }
        "-V" | "--version" => {
            print_version();
            std::process::exit(0);
        }
        "update" => {
            let update = parse_update_args(&args[2..])?;
            Ok(Cli {
                command: Some(Command::Update(update)),
                monitor: MonitorArgs::default(),
            })
        }
        "report" => {
            let report = parse_report_args(&args[2..])?;
            Ok(Cli {
                command: Some(Command::Report(report)),
                monitor: MonitorArgs::default(),
            })
        }
        _ => Ok(Cli {
            command: None,
            monitor: load_monitor_args(&args[1..])?,
        }),
    }
}

fn load_monitor_args(argv: &[String]) -> Result<MonitorArgs, String> {
    for arg in argv {
        if arg == "-h" || arg == "--help" {
            print_help();
            std::process::exit(0);
        }
        if arg == "-V" || arg == "--version" {
            print_version();
            std::process::exit(0);
        }
    }

    let config = find_config_flag(argv);
    let mut args = MonitorArgs::default();
    if config.use_config {
        if let Some(path) = config.kv_path.clone().or_else(default_config_path) {
            if path.exists() {
                apply_config_file(&path, &mut args)?;
            }
        }
    }

    let mut i = 0;
    while i < argv.len() {
        let arg = &argv[i];
        match arg.as_str() {
            "--pattern" => {
                i += 1;
                let value = require_value(argv, i, "--pattern")?;
                args.patterns.push(value.to_string());
                i += 1;
            }
            "--exclude-pattern" => {
                i += 1;
                let value = require_value(argv, i, "--exclude-pattern")?;
                args.exclude_patterns.push(value.to_string());
                i += 1;
            }
            "--pid" => {
                i += 1;
                let value = require_value(argv, i, "--pid")?;
                let pid = value.parse::<u32>().map_err(|_| "Invalid --pid value".to_string())?;
                args.pids.push(pid);
                i += 1;
            }
            "--no-descendants" => {
                args.no_descendants = true;
                i += 1;
            }
            "--interval-ms" => {
                i += 1;
                let value = require_value(argv, i, "--interval-ms")?;
                args.interval_ms = parse_u64(value, "--interval-ms")?;
                i += 1;
            }
            "--json" => {
                args.json = true;
                i += 1;
            }
            "--summary-only" => {
                args.summary_only = true;
                i += 1;
            }
            "--domain-mode" => {
                i += 1;
                let value = require_value(argv, i, "--domain-mode")?;
                args.domain_mode = parse_domain_mode(value)?;
                i += 1;
            }
            "--pcap" => {
                args.pcap = true;
                i += 1;
            }
            "--no-dns" => {
                args.no_dns = true;
                i += 1;
            }
            "--include-udp" => {
                args.include_udp = true;
                i += 1;
            }
            "--no-udp" => {
                args.include_udp = false;
                i += 1;
            }
            "--include-listening" => {
                args.include_listening = true;
                i += 1;
            }
            "--log-file" => {
                i += 1;
                let value = require_value(argv, i, "--log-file")?;
                args.log_file = Some(PathBuf::from(value));
                i += 1;
            }
            "--log-dir" => {
                i += 1;
                let value = require_value(argv, i, "--log-dir")?;
                args.log_dir = Some(PathBuf::from(value));
                i += 1;
            }
            "--log-format" => {
                i += 1;
                let value = require_value(argv, i, "--log-format")?;
                args.log_format = parse_log_format(value)?;
                i += 1;
            }
            "--once" => {
                args.once = true;
                i += 1;
            }
            "--color" => {
                i += 1;
                let value = require_value(argv, i, "--color")?;
                args.color = parse_color_mode(value)?;
                i += 1;
            }
            "--no-color" => {
                args.color = ColorMode::Never;
                i += 1;
            }
            "--sqlite" => {
                i += 1;
                let value = require_value(argv, i, "--sqlite")?;
                args.sqlite_path = value.to_string();
                i += 1;
            }
            "--no-sqlite" => {
                args.no_sqlite = true;
                i += 1;
            }
            "--db-batch-size" => {
                i += 1;
                let value = require_value(argv, i, "--db-batch-size")?;
                args.db_batch_size = parse_usize(value, "--db-batch-size")?;
                if args.db_batch_size == 0 {
                    return Err("--db-batch-size must be >= 1".to_string());
                }
                i += 1;
            }
            "--db-flush-ms" => {
                i += 1;
                let value = require_value(argv, i, "--db-flush-ms")?;
                args.db_flush_ms = parse_u64(value, "--db-flush-ms")?;
                if args.db_flush_ms == 0 {
                    return Err("--db-flush-ms must be >= 1".to_string());
                }
                i += 1;
            }
            "--db-queue-max" => {
                i += 1;
                let value = require_value(argv, i, "--db-queue-max")?;
                args.db_queue_max = parse_usize(value, "--db-queue-max")?;
                if args.db_queue_max == 0 {
                    return Err("--db-queue-max must be >= 1".to_string());
                }
                i += 1;
            }
            "--stats-interval-ms" => {
                i += 1;
                let value = require_value(argv, i, "--stats-interval-ms")?;
                args.stats_interval_ms = parse_u64(value, "--stats-interval-ms")?;
                i += 1;
            }
            "--stats-width" => {
                i += 1;
                let value = require_value(argv, i, "--stats-width")?;
                args.stats_width = parse_usize(value, "--stats-width")?;
                args.stats_width_set = true;
                i += 1;
            }
            "--stats-top" => {
                i += 1;
                let value = require_value(argv, i, "--stats-top")?;
                args.stats_top = parse_usize(value, "--stats-top")?;
                if args.stats_top == 0 {
                    return Err("--stats-top must be >= 1".to_string());
                }
                i += 1;
            }
            "--stats-view" => {
                i += 1;
                let value = require_value(argv, i, "--stats-view")?;
                let view = parse_stats_view(value)?;
                args.stats_views.push(view);
                i += 1;
            }
            "--stats-cycle-ms" => {
                i += 1;
                let value = require_value(argv, i, "--stats-cycle-ms")?;
                args.stats_cycle_ms = parse_u64(value, "--stats-cycle-ms")?;
                i += 1;
            }
            "--no-banner" => {
                args.no_banner = true;
                i += 1;
            }
            "--theme" => {
                i += 1;
                let value = require_value(argv, i, "--theme")?;
                args.theme = parse_theme(value)?;
                i += 1;
            }
            "--config" => {
                i += 2;
            }
            "--config-toml" => {
                i += 2;
            }
            "--no-config" => {
                i += 1;
            }
            other => {
                if other.starts_with('-') {
                    return Err(format!("Unknown flag: {}", other));
                }
                return Err(format!("Unexpected argument: {}", other));
            }
        }
    }

    if args.stats_top == 0 {
        args.stats_top = 1;
    }

    Ok(args)
}

fn parse_update_args(argv: &[String]) -> Result<UpdateCommand, String> {
    for arg in argv {
        if arg == "-h" || arg == "--help" {
            print_update_help();
            std::process::exit(0);
        }
        if arg == "-V" || arg == "--version" {
            print_version();
            std::process::exit(0);
        }
    }

    let mut cmd = UpdateCommand {
        version: None,
        system: false,
        easy_mode: false,
        dest: None,
        from_source: false,
        verify: false,
        quiet: false,
        no_gum: false,
        owner: None,
        repo: None,
        branch: None,
    };

    let mut i = 0;
    while i < argv.len() {
        let arg = &argv[i];
        match arg.as_str() {
            "--version" => {
                i += 1;
                let value = require_value(argv, i, "--version")?;
                cmd.version = Some(value.to_string());
                i += 1;
            }
            "--system" => {
                cmd.system = true;
                i += 1;
            }
            "--easy-mode" => {
                cmd.easy_mode = true;
                i += 1;
            }
            "--dest" => {
                i += 1;
                let value = require_value(argv, i, "--dest")?;
                cmd.dest = Some(PathBuf::from(value));
                i += 1;
            }
            "--from-source" => {
                cmd.from_source = true;
                i += 1;
            }
            "--verify" => {
                cmd.verify = true;
                i += 1;
            }
            "--quiet" => {
                cmd.quiet = true;
                i += 1;
            }
            "--no-gum" => {
                cmd.no_gum = true;
                i += 1;
            }
            "--owner" => {
                i += 1;
                let value = require_value(argv, i, "--owner")?;
                cmd.owner = Some(value.to_string());
                i += 1;
            }
            "--repo" => {
                i += 1;
                let value = require_value(argv, i, "--repo")?;
                cmd.repo = Some(value.to_string());
                i += 1;
            }
            "--branch" => {
                i += 1;
                let value = require_value(argv, i, "--branch")?;
                cmd.branch = Some(value.to_string());
                i += 1;
            }
            other => {
                if other.starts_with('-') {
                    return Err(format!("Unknown update flag: {}", other));
                }
                return Err(format!("Unexpected update argument: {}", other));
            }
        }
    }

    Ok(cmd)
}

fn parse_report_args(argv: &[String]) -> Result<ReportArgs, String> {
    for arg in argv {
        if arg == "-h" || arg == "--help" {
            print_report_help();
            std::process::exit(0);
        }
        if arg == "-V" || arg == "--version" {
            print_version();
            std::process::exit(0);
        }
    }

    let mut args = ReportArgs::default();

    let mut i = 0;
    while i < argv.len() {
        let arg = &argv[i];
        match arg.as_str() {
            "--sqlite" => {
                i += 1;
                let value = require_value(argv, i, "--sqlite")?;
                args.sqlite_path = value.to_string();
                i += 1;
            }
            "--latest" => {
                args.latest = true;
                i += 1;
            }
            "--run-id" => {
                i += 1;
                let value = require_value(argv, i, "--run-id")?;
                args.run_id = Some(value.to_string());
                i += 1;
            }
            "--since" => {
                i += 1;
                let value = require_value(argv, i, "--since")?;
                args.since = Some(value.to_string());
                i += 1;
            }
            "--until" => {
                i += 1;
                let value = require_value(argv, i, "--until")?;
                args.until = Some(value.to_string());
                i += 1;
            }
            "--json" => {
                args.json = true;
                i += 1;
            }
            "--top" => {
                i += 1;
                let value = require_value(argv, i, "--top")?;
                args.top = parse_usize(value, "--top")?;
                i += 1;
            }
            "--color" => {
                i += 1;
                let value = require_value(argv, i, "--color")?;
                args.color = parse_color_mode(value)?;
                i += 1;
            }
            "--no-color" => {
                args.color = ColorMode::Never;
                i += 1;
            }
            other => {
                if other.starts_with('-') {
                    return Err(format!("Unknown report flag: {}", other));
                }
                return Err(format!("Unexpected report argument: {}", other));
            }
        }
    }

    if args.latest && args.run_id.is_some() {
        return Err("--latest and --run-id are mutually exclusive".to_string());
    }

    Ok(args)
}

fn require_value<'a>(argv: &'a [String], index: usize, flag: &str) -> Result<&'a str, String> {
    argv.get(index)
        .map(|v| v.as_str())
        .ok_or_else(|| format!("Missing value for {}", flag))
}

fn parse_u64(value: &str, flag: &str) -> Result<u64, String> {
    value
        .parse::<u64>()
        .map_err(|_| format!("Invalid value for {}", flag))
}

fn parse_usize(value: &str, flag: &str) -> Result<usize, String> {
    value
        .parse::<usize>()
        .map_err(|_| format!("Invalid value for {}", flag))
}

fn parse_domain_mode(value: &str) -> Result<DomainMode, String> {
    match value.to_lowercase().as_str() {
        "auto" => Ok(DomainMode::Auto),
        "ptr" => Ok(DomainMode::Ptr),
        "pcap" => Ok(DomainMode::Pcap),
        _ => Err("Invalid --domain-mode (use auto|ptr|pcap)".to_string()),
    }
}

fn parse_color_mode(value: &str) -> Result<ColorMode, String> {
    match value.to_lowercase().as_str() {
        "auto" => Ok(ColorMode::Auto),
        "always" => Ok(ColorMode::Always),
        "never" => Ok(ColorMode::Never),
        _ => Err("Invalid --color (use auto|always|never)".to_string()),
    }
}

fn parse_log_format(value: &str) -> Result<LogFormat, String> {
    match value.to_lowercase().as_str() {
        "auto" => Ok(LogFormat::Auto),
        "pretty" => Ok(LogFormat::Pretty),
        "json" => Ok(LogFormat::Json),
        _ => Err("Invalid --log-format (use auto|pretty|json)".to_string()),
    }
}

fn parse_theme(value: &str) -> Result<Theme, String> {
    match value.to_lowercase().as_str() {
        "vivid" => Ok(Theme::Vivid),
        "mono" => Ok(Theme::Mono),
        _ => Err("Invalid --theme (use vivid|mono)".to_string()),
    }
}

fn parse_stats_view(value: &str) -> Result<StatsView, String> {
    match value.to_lowercase().as_str() {
        "provider" => Ok(StatsView::Provider),
        "domain" => Ok(StatsView::Domain),
        "port" => Ok(StatsView::Port),
        "process" => Ok(StatsView::Process),
        _ => Err("Invalid --stats-view (use provider|domain|port|process)".to_string()),
    }
}

fn find_config_flag(argv: &[String]) -> ConfigPaths {
    let mut config_path = None;
    let mut toml_path = None;
    let mut use_config = true;
    let mut i = 0;
    while i < argv.len() {
        match argv[i].as_str() {
            "--config" => {
                if let Some(path) = argv.get(i + 1) {
                    config_path = Some(PathBuf::from(path));
                }
                i += 2;
            }
            "--config-toml" => {
                if let Some(path) = argv.get(i + 1) {
                    toml_path = Some(PathBuf::from(path));
                }
                i += 2;
            }
            "--no-config" => {
                use_config = false;
                i += 1;
            }
            _ => i += 1,
        }
    }
    ConfigPaths {
        kv_path: config_path,
        toml_path,
        use_config,
    }
}

fn default_config_path() -> Option<PathBuf> {
    let home = env::var("HOME").ok()?;
    Some(PathBuf::from(home).join(".config/rano/config.conf"))
}

fn apply_config_file(path: &Path, args: &mut MonitorArgs) -> Result<(), String> {
    let contents = fs::read_to_string(path)
        .map_err(|e| format!("Failed to read config {}: {}", path.display(), e))?;
    for (idx, line) in contents.lines().enumerate() {
        let raw = line.split('#').next().unwrap_or("").trim();
        if raw.is_empty() {
            continue;
        }
        let mut parts = raw.splitn(2, '=');
        let key = parts.next().unwrap_or("").trim();
        let value = parts.next().unwrap_or("").trim();
        if key.is_empty() {
            continue;
        }
        if value.is_empty() {
            return Err(format!(
                "Config parse error at line {}: missing value for '{}'",
                idx + 1,
                key
            ));
        }
        match key {
            "pattern" => push_list_value(&mut args.patterns, value),
            "exclude_pattern" => push_list_value(&mut args.exclude_patterns, value),
            "pid" => {
                let pid = value
                    .parse::<u32>()
                    .map_err(|_| format!("Invalid pid at line {}", idx + 1))?;
                args.pids.push(pid);
            }
            "no_descendants" => args.no_descendants = parse_bool(value)?,
            "interval_ms" => args.interval_ms = parse_u64(value, "interval_ms")?,
            "json" => args.json = parse_bool(value)?,
            "summary_only" => args.summary_only = parse_bool(value)?,
            "domain_mode" => args.domain_mode = parse_domain_mode(value)?,
            "pcap" => args.pcap = parse_bool(value)?,
            "no_dns" => args.no_dns = parse_bool(value)?,
            "include_udp" => args.include_udp = parse_bool(value)?,
            "include_listening" => args.include_listening = parse_bool(value)?,
            "log_file" => args.log_file = Some(PathBuf::from(value)),
            "log_dir" => args.log_dir = Some(PathBuf::from(value)),
            "log_format" => args.log_format = parse_log_format(value)?,
            "once" => args.once = parse_bool(value)?,
            "color" => args.color = parse_color_mode(value)?,
            "sqlite" => args.sqlite_path = value.to_string(),
            "no_sqlite" => args.no_sqlite = parse_bool(value)?,
            "db_batch_size" => {
                args.db_batch_size = parse_usize(value, "db_batch_size")?;
                if args.db_batch_size == 0 {
                    return Err("db_batch_size must be >= 1".to_string());
                }
            }
            "db_flush_ms" => {
                args.db_flush_ms = parse_u64(value, "db_flush_ms")?;
                if args.db_flush_ms == 0 {
                    return Err("db_flush_ms must be >= 1".to_string());
                }
            }
            "db_queue_max" => {
                args.db_queue_max = parse_usize(value, "db_queue_max")?;
                if args.db_queue_max == 0 {
                    return Err("db_queue_max must be >= 1".to_string());
                }
            }
            "stats_interval_ms" => args.stats_interval_ms = parse_u64(value, "stats_interval_ms")?,
            "stats_width" => {
                args.stats_width = parse_usize(value, "stats_width")?;
                args.stats_width_set = true;
            }
            "stats_top" => args.stats_top = parse_usize(value, "stats_top")?,
            "stats_view" => {
                push_stats_views(&mut args.stats_views, value)?;
            }
            "stats_cycle_ms" => {
                args.stats_cycle_ms = parse_u64(value, "stats_cycle_ms")?;
            }
            "no_banner" => args.no_banner = parse_bool(value)?,
            "theme" => args.theme = parse_theme(value)?,
            _ => {
                eprintln!(
                    "warning: unknown config key '{}' in {}", key, path.display()
                );
            }
        }
    }
    Ok(())
}

fn push_list_value(target: &mut Vec<String>, value: &str) {
    for part in value.split(',') {
        let trimmed = part.trim();
        if !trimmed.is_empty() {
            target.push(trimmed.to_string());
        }
    }
}

fn push_stats_views(target: &mut Vec<StatsView>, value: &str) -> Result<(), String> {
    for part in value.split(',') {
        let trimmed = part.trim();
        if trimmed.is_empty() {
            continue;
        }
        let view = parse_stats_view(trimmed)?;
        target.push(view);
    }
    Ok(())
}

fn parse_bool(value: &str) -> Result<bool, String> {
    match value.to_lowercase().as_str() {
        "true" | "1" | "yes" | "on" => Ok(true),
        "false" | "0" | "no" | "off" => Ok(false),
        _ => Err(format!("Invalid boolean value '{}'.", value)),
    }
}

fn load_provider_matcher(config: &ConfigPaths) -> (ProviderMatcher, Vec<String>) {
    let mut notes = Vec::new();
    if !config.use_config {
        return (ProviderMatcher::default(), notes);
    }

    let (paths, mut path_notes) = provider_config_paths(config);
    notes.append(&mut path_notes);

    let mut matcher = ProviderMatcher::default();
    for path in paths {
        let contents = match fs::read_to_string(&path) {
            Ok(contents) => contents,
            Err(err) => {
                notes.push(format!(
                    "provider config: failed to read {}: {}",
                    path.display(),
                    err
                ));
                continue;
            }
        };

        let parsed: TomlConfig = match toml::from_str(&contents) {
            Ok(parsed) => parsed,
            Err(err) => {
                notes.push(format!(
                    "provider config: failed to parse {}: {}",
                    path.display(),
                    err
                ));
                continue;
            }
        };

        let Some(providers) = parsed.providers else {
            continue;
        };

        if let Err(err) = apply_provider_config(&mut matcher, providers) {
            notes.push(format!("provider config: {}", err));
        }
    }

    (matcher, notes)
}

fn provider_config_paths(config: &ConfigPaths) -> (Vec<PathBuf>, Vec<String>) {
    let mut notes = Vec::new();
    let mut paths = Vec::new();
    let mut seen: HashSet<PathBuf> = HashSet::new();

    for candidate in default_provider_config_paths() {
        if candidate.exists() {
            push_unique_path(&mut paths, &mut seen, candidate);
        }
    }

    if let Some(path) = config.toml_path.as_ref() {
        if path.exists() {
            push_unique_path(&mut paths, &mut seen, path.clone());
        } else {
            notes.push(format!(
                "provider config: --config-toml path not found: {}",
                path.display()
            ));
        }
    }

    if let Ok(env_path) = env::var("RANO_CONFIG_TOML") {
        let trimmed = env_path.trim();
        if trimmed.is_empty() {
            notes.push("provider config: RANO_CONFIG_TOML is set but empty".to_string());
        } else {
            let candidate = PathBuf::from(trimmed);
            if candidate.exists() {
                push_unique_path(&mut paths, &mut seen, candidate);
            } else {
                notes.push(format!(
                    "provider config: RANO_CONFIG_TOML path not found: {}",
                    candidate.display()
                ));
            }
        }
    }

    (paths, notes)
}

fn default_provider_config_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();
    if let Some(home) = home_dir() {
        paths.push(home.join(".rano.toml"));
    }
    if let Some(config_dir) = xdg_config_home() {
        paths.push(config_dir.join("rano").join("rano.toml"));
    }
    if let Ok(cwd) = env::current_dir() {
        paths.push(cwd.join("rano.toml"));
    }
    paths
}

fn push_unique_path(paths: &mut Vec<PathBuf>, seen: &mut HashSet<PathBuf>, path: PathBuf) {
    if seen.insert(path.clone()) {
        paths.push(path);
    }
}

fn xdg_config_home() -> Option<PathBuf> {
    if let Ok(path) = env::var("XDG_CONFIG_HOME") {
        if !path.trim().is_empty() {
            return Some(PathBuf::from(path));
        }
    }
    home_dir().map(|home| home.join(".config"))
}

fn home_dir() -> Option<PathBuf> {
    env::var("HOME").ok().map(PathBuf::from)
}

fn apply_provider_config(
    matcher: &mut ProviderMatcher,
    config: ProvidersConfig,
) -> Result<(), String> {
    let mode = match config.mode.as_deref() {
        Some(value) => parse_provider_mode(value)?,
        None => ProviderMode::Merge,
    };

    if mode == ProviderMode::Replace {
        *matcher = ProviderMatcher {
            anthropic: Vec::new(),
            openai: Vec::new(),
            google: Vec::new(),
        };
    }

    if let Some(patterns) = config.anthropic {
        let normalized = normalize_patterns(patterns);
        matcher.anthropic = merge_patterns(matcher.anthropic.clone(), normalized, mode);
    }
    if let Some(patterns) = config.openai {
        let normalized = normalize_patterns(patterns);
        matcher.openai = merge_patterns(matcher.openai.clone(), normalized, mode);
    }
    if let Some(patterns) = config.google {
        let normalized = normalize_patterns(patterns);
        matcher.google = merge_patterns(matcher.google.clone(), normalized, mode);
    }

    Ok(())
}

fn merge_patterns(mut base: Vec<String>, mut add: Vec<String>, mode: ProviderMode) -> Vec<String> {
    if mode == ProviderMode::Replace {
        return add;
    }
    let mut seen: HashSet<String> = base.iter().cloned().collect();
    for item in add.drain(..) {
        if seen.insert(item.clone()) {
            base.push(item);
        }
    }
    base
}

fn normalize_patterns(input: Vec<String>) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for item in input {
        let trimmed = item.trim();
        if trimmed.is_empty() {
            continue;
        }
        let lowered = trimmed.to_lowercase();
        if seen.insert(lowered.clone()) {
            out.push(lowered);
        }
    }
    out
}

fn parse_provider_mode(value: &str) -> Result<ProviderMode, String> {
    match value.to_lowercase().as_str() {
        "merge" => Ok(ProviderMode::Merge),
        "replace" => Ok(ProviderMode::Replace),
        _ => Err("Invalid providers.mode (use merge|replace)".to_string()),
    }
}

fn print_help() {
    println!(
        "rano - AI CLI network observer\n\nUSAGE:\n  rano [options]\n  rano report [options]\n  rano update [options]\n\nCOMMANDS:\n  report    Query SQLite event history (use --help for details)\n  update    Update the rano binary\n\nOPTIONS:\n  --pattern <str>           Process name or cmdline substring to match (repeatable)\n  --exclude-pattern <str>   Exclude processes matching substring (repeatable)\n  --pid <pid>               Monitor a specific PID (repeatable)\n  --no-descendants          Do not include descendant processes\n  --interval-ms <ms>        Poll interval (default: 1000)\n  --json                    Emit JSON lines to stdout\n  --summary-only            Suppress live events, show summary only\n  --domain-mode <mode>      auto|ptr|pcap (default: auto)\n  --pcap                    Force pcap mode (falls back with warning)\n  --no-dns                  Disable PTR lookups\n  --include-udp             Include UDP sockets (default: true)\n  --no-udp                  Disable UDP sockets\n  --include-listening       Include listening TCP sockets\n  --log-file <path>         Append output to log file\n  --log-dir <path>          Write per-run log files into directory\n  --log-format <fmt>        auto|pretty|json for log files (default: auto)\n  --once                    Emit a single poll and exit\n  --color <mode>            auto|always|never (default: auto)\n  --no-color                Disable ANSI color\n  --theme <name>            vivid|mono (default: vivid)\n  --sqlite <path>           SQLite file for persistent logging\n  --no-sqlite               Disable SQLite logging\n  --db-batch-size <n>       SQLite batch size (events per transaction)\n  --db-flush-ms <ms>        SQLite flush interval in ms\n  --db-queue-max <n>        SQLite queue capacity (events)\n  --stats-interval-ms <ms>  Live stats interval (0 disables)\n  --stats-width <n>         ASCII bar width\n  --stats-top <n>           Top-N domains/IPs in stats/summary\n  --stats-view <name>       Stats view: provider|domain|port|process (repeatable)\n  --stats-cycle-ms <ms>     Rotate stats views at this interval (0 disables)\n  --no-banner               Suppress startup banner\n  --config <path>           Load config file (key=value format)\n  --config-toml <path>      Load provider config (TOML)\n  --no-config               Ignore config files\n  -h, --help                Show this help\n  -V, --version             Show version\n"
    );
}

fn print_update_help() {
    println!(
        "rano update - update the binary\n\nUSAGE:\n  rano update [options]\n\nOPTIONS:\n  --version <v>     Install a specific version (e.g., v0.2.0)\n  --system          Install system-wide (/usr/local/bin)\n  --easy-mode       Auto-update PATH in shell rc files\n  --dest <path>     Install destination directory\n  --from-source     Build from source instead of downloading binaries\n  --verify          Verify installation after update\n  --quiet           Suppress non-error output\n  --no-gum          Disable gum formatting in installer\n  --owner <owner>   GitHub owner/org override\n  --repo <repo>     GitHub repo override\n  --branch <name>   GitHub branch (default: main)\n  -h, --help        Show this help\n  -V, --version     Show version\n"
    );
}

fn print_report_help() {
    println!(
        "rano report - query SQLite event history\n\n\
USAGE:\n  rano report [options]\n\n\
OPTIONS:\n\
  --sqlite <path>   SQLite database path (default: observer.sqlite)\n\
  --latest          Report on most recent session\n\
  --run-id <id>     Report on specific session by run_id\n\
  --since <ts>      Start of time range (RFC3339, date, or relative like 1h/24h/7d)\n\
  --until <ts>      End of time range (RFC3339, exclusive)\n\
  --json            Output as JSON\n\
  --top <n>         Limit top-N entries (default: 10)\n\
  --color <mode>    Color output: auto|always|never (default: auto)\n\
  --no-color        Disable color output\n\
  -h, --help        Show this help\n\
  -V, --version     Show version\n\n\
EXAMPLES:\n\
  rano report --latest                # Most recent session\n\
  rano report --since 24h             # Last 24 hours\n\
  rano report --run-id xyz --json     # Specific session as JSON\n"
    );
}

fn print_version() {
    println!("rano {}", env!("CARGO_PKG_VERSION"));
}

fn resolve_color_mode(mode: ColorMode) -> bool {
    match mode {
        ColorMode::Auto => stdout_is_tty(),
        ColorMode::Always => true,
        ColorMode::Never => false,
    }
}

fn resolve_stats_width(args: &MonitorArgs) -> usize {
    if args.stats_width_set {
        return args.stats_width.max(1);
    }
    if stdout_is_tty() {
        if let Ok(columns) = env::var("COLUMNS") {
            if let Ok(cols) = columns.trim().parse::<usize>() {
                let width = cols.saturating_sub(40).clamp(20, 80);
                return width.max(1);
            }
        }
    }
    args.stats_width.max(1)
}

fn stdout_is_tty() -> bool {
    #[cfg(unix)]
    unsafe {
        libc::isatty(libc::STDOUT_FILENO) == 1
    }
    #[cfg(not(unix))]
    {
        true
    }
}

fn paint(text: &str, color: Option<AnsiColor>, bold: bool, dim: bool, enabled: bool) -> String {
    if !enabled {
        return text.to_string();
    }
    let mut codes: Vec<&str> = Vec::new();
    if let Some(c) = color {
        codes.push(c.code());
    }
    if bold {
        codes.push("1");
    }
    if dim {
        codes.push("2");
    }
    if codes.is_empty() {
        return text.to_string();
    }
    format!("\x1b[{}m{}\x1b[0m", codes.join(";"), text)
}

fn default_patterns() -> Vec<String> {
    vec!["claude".to_string(), "codex".to_string(), "gemini".to_string()]
}

fn resolve_domain_mode(args: &MonitorArgs) -> (DomainMode, Option<String>) {
    let wants_pcap = args.pcap || matches!(args.domain_mode, DomainMode::Pcap);
    if wants_pcap {
        if !pcap_capture::pcap_supported() {
            return (
                DomainMode::Ptr,
                Some("pcap feature not enabled; falling back to PTR.".to_string()),
            );
        }
        return (DomainMode::Pcap, None);
    }

    match args.domain_mode {
        DomainMode::Auto => (DomainMode::Ptr, None),
        DomainMode::Ptr => (DomainMode::Ptr, None),
        DomainMode::Pcap => (
            DomainMode::Ptr,
            Some("pcap capture requested; falling back to PTR.".to_string()),
        ),
    }
}

fn pcap_permission_hint(err: &str) -> Option<&'static str> {
    let lower = err.to_lowercase();
    if lower.contains("permission") || lower.contains("denied") || lower.contains("not permitted") {
        Some("pcap capture requires elevated privileges (sudo or CAP_NET_RAW).")
    } else {
        None
    }
}

fn setup_signal_handler() {
    #[cfg(unix)]
    unsafe {
        extern "C" fn handle(_sig: i32) {
            RUNNING.store(false, Ordering::SeqCst);
        }
        libc::signal(libc::SIGINT, handle as libc::sighandler_t);
        libc::signal(libc::SIGTERM, handle as libc::sighandler_t);
    }
}

fn hostname() -> String {
    if let Ok(name) = env::var("HOSTNAME") {
        if !name.trim().is_empty() {
            return name;
        }
    }
    if let Ok(contents) = fs::read_to_string("/etc/hostname") {
        let trimmed = contents.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    "unknown".to_string()
}

fn now_rfc3339() -> String {
    system_time_to_rfc3339(SystemTime::now())
}

fn system_time_to_rfc3339(t: SystemTime) -> String {
    let dur = t.duration_since(UNIX_EPOCH).unwrap_or_default();
    let raw: libc::time_t = dur.as_secs() as libc::time_t;
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    #[cfg(unix)]
    unsafe {
        libc::gmtime_r(&raw, &mut tm);
    }
    #[cfg(not(unix))]
    unsafe {
        libc::gmtime_s(&mut tm, &raw);
    }
    let year = tm.tm_year + 1900;
    let mon = tm.tm_mon + 1;
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, mon, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec
    )
}

fn banner(
    args: &MonitorArgs,
    domain_label: &str,
    notes: &[String],
    style: OutputStyle,
    log_writer: &Option<Arc<LogWriter>>,
) {
    let patterns = if args.patterns.is_empty() {
        "claude, codex, gemini".to_string()
    } else {
        args.patterns.join(", ")
    };
    let headline = paint("rano", style.accent(), true, false, style.color);
    let line = format!(
        "{} patterns=[{}] interval={}ms json={} domain={} udp={} listening={} once={} sqlite={} stats={}ms log_file={} log_dir={}",
        headline,
        patterns,
        args.interval_ms,
        args.json,
        domain_label,
        args.include_udp,
        args.include_listening,
        args.once,
        if args.no_sqlite { "disabled" } else { &args.sqlite_path },
        args.stats_interval_ms,
        args.log_file.as_ref().map(|p| p.display().to_string()).unwrap_or_else(|| "-".to_string()),
        args.log_dir.as_ref().map(|p| p.display().to_string()).unwrap_or_else(|| "-".to_string()),
    );

    if args.json {
        eprintln!("{}", strip_ansi(&line));
    } else {
        println!("{}", line);
    }

    for note in notes {
        let warning = format!("warning: {}", note);
        if args.json {
            eprintln!("{}", warning);
        } else {
            println!("{}", paint(&warning, Some(AnsiColor::BrightYellow), true, false, style.color));
        }
        if let Some(writer) = log_writer.as_ref() {
            writer.write_line(&strip_ansi(&warning));
        }
    }
}

fn log_format_for_output(json_mode: bool, log_format: LogFormat) -> LogFormat {
    match log_format {
        LogFormat::Auto => {
            if json_mode {
                LogFormat::Json
            } else {
                LogFormat::Pretty
            }
        }
        other => other,
    }
}

fn emit_event(
    ts: &str,
    event: &str,
    run_id: &str,
    key: &ConnKey,
    pid: u32,
    comm: &str,
    cmdline: &str,
    provider: Provider,
    domain: Option<&str>,
    duration_ms: Option<u64>,
    domain_mode: &str,
    json_mode: bool,
    style: OutputStyle,
    log_format: LogFormat,
    log_writer: Option<&Arc<LogWriter>>,
) {
    let proto = match key.proto {
        Proto::Tcp => "tcp",
        Proto::Udp => "udp",
    };
    let local = format!("{}:{}", key.local_ip, key.local_port);
    let remote = format!("{}:{}", key.remote_ip, key.remote_port);
    let dom = domain.unwrap_or("unknown");

    if json_mode {
        let line = format_json_event(
            ts,
            run_id,
            event,
            pid,
            comm,
            cmdline,
            provider.label(),
            proto,
            &local,
            &remote,
            dom,
            domain_mode,
            duration_ms,
        );
        println!("{}", line);
        if let Some(writer) = log_writer {
            writer.write_line(&line);
        }
        return;
    }

    let line_plain = format_pretty_event(
        ts,
        event,
        pid,
        comm,
        proto,
        &local,
        &remote,
        dom,
        provider,
        duration_ms,
        None,
    );

    let line_colored = format_pretty_event(
        ts,
        event,
        pid,
        comm,
        proto,
        &local,
        &remote,
        dom,
        provider,
        duration_ms,
        Some(style),
    );

    println!("{}", line_colored);

    if let Some(writer) = log_writer {
        let output = match log_format {
            LogFormat::Json => format_json_event(
                ts,
                run_id,
                event,
                pid,
                comm,
                cmdline,
                provider.label(),
                proto,
                &local,
                &remote,
                dom,
                domain_mode,
                duration_ms,
            ),
            _ => strip_ansi(&line_plain),
        };
        writer.write_line(&output);
    }
}

fn format_pretty_event(
    ts: &str,
    event: &str,
    pid: u32,
    comm: &str,
    proto: &str,
    local: &str,
    remote: &str,
    domain: &str,
    provider: Provider,
    duration_ms: Option<u64>,
    style: Option<OutputStyle>,
) -> String {
    let style = style.unwrap_or(OutputStyle {
        color: false,
        theme: Theme::Mono,
    });

    let event_label = match event {
        "connect" => "+ connect",
        "close" => "- close",
        _ => event,
    };

    let event_text = paint(event_label, style.event_color(event), true, false, style.color);
    let provider_text = paint(
        provider.label(),
        style.provider_color(provider),
        true,
        false,
        style.color,
    );
    let pid_text = paint(&format!("pid={}", pid), Some(AnsiColor::BrightCyan), true, false, style.color);
    let comm_text = paint(comm, Some(AnsiColor::BrightWhite), true, false, style.color);
    let proto_text = paint(proto, Some(AnsiColor::BrightMagenta), true, false, style.color);
    let domain_text = if domain == "unknown" {
        paint(domain, Some(AnsiColor::BrightBlack), false, true, style.color)
    } else {
        paint(domain, Some(AnsiColor::BrightWhite), false, false, style.color)
    };
    let ts_text = if style.color {
        paint(ts, Some(AnsiColor::BrightBlack), false, true, style.color)
    } else {
        ts.to_string()
    };

    let duration_text = duration_ms.map(|ms| format!(" dur={}ms", ms)).unwrap_or_default();

    format!(
        "{} | {} | {} | {} | {} | {} | {} -> {} | domain={}{}",
        ts_text, event_text, provider_text, pid_text, comm_text, proto_text, local, remote, domain_text, duration_text
    )
}

fn format_json_event(
    ts: &str,
    run_id: &str,
    event: &str,
    pid: u32,
    comm: &str,
    cmdline: &str,
    provider: &str,
    proto: &str,
    local: &str,
    remote: &str,
    domain: &str,
    domain_mode: &str,
    duration_ms: Option<u64>,
) -> String {
    let mut out = String::new();
    out.push('{');
    push_json_str(&mut out, "ts", ts, true);
    push_json_str(&mut out, "run_id", run_id, false);
    push_json_str(&mut out, "event", event, false);
    push_json_num(&mut out, "pid", pid as i64, false);
    push_json_str(&mut out, "comm", comm, false);
    push_json_str(&mut out, "cmdline", cmdline, false);
    push_json_str(&mut out, "provider", provider, false);
    push_json_str(&mut out, "proto", proto, false);
    push_json_str(&mut out, "local", local, false);
    push_json_str(&mut out, "remote", remote, false);
    push_json_str(&mut out, "domain", domain, false);
    push_json_str(&mut out, "domain_mode", domain_mode, false);
    if let Some(ms) = duration_ms {
        push_json_num(&mut out, "duration_ms", ms as i64, false);
    }
    out.push('}');
    out
}

fn summary(
    stats: &Stats,
    json_mode: bool,
    stats_top: usize,
    style: OutputStyle,
    domain_mode: &str,
    log_writer: Option<&Arc<LogWriter>>,
) {
    if json_mode {
        let line = format_json_summary(stats, domain_mode);
        println!("{}", line);
        if let Some(writer) = log_writer {
            writer.write_line(&line);
        }
        return;
    }

    println!("{}", paint("Summary", style.accent(), true, false, style.color));
    println!(
        "  {} {}",
        paint("connects", Some(AnsiColor::BrightWhite), true, false, style.color),
        paint(&stats.connects.to_string(), Some(AnsiColor::BrightGreen), true, false, style.color)
    );
    println!(
        "  {} {}",
        paint("closes", Some(AnsiColor::BrightWhite), true, false, style.color),
        paint(&stats.closes.to_string(), Some(AnsiColor::BrightYellow), true, false, style.color)
    );
    println!(
        "  {} {} (peak={})",
        paint("active", Some(AnsiColor::BrightWhite), true, false, style.color),
        paint(&stats.active.to_string(), Some(AnsiColor::BrightCyan), true, false, style.color),
        stats.peak_active
    );
    if stats.sqlite_dropped > 0 {
        println!(
            "  {} {}",
            paint("sqlite_dropped", Some(AnsiColor::BrightWhite), true, false, style.color),
            paint(
                &stats.sqlite_dropped.to_string(),
                Some(AnsiColor::BrightRed),
                true,
                false,
                style.color
            )
        );
    }

    if stats.duration_ms_samples > 0 {
        let avg = stats.duration_ms_total / stats.duration_ms_samples;
        println!(
            "  {} {}ms (max={}ms)",
            paint("avg_duration", Some(AnsiColor::BrightWhite), true, false, style.color),
            paint(&avg.to_string(), Some(AnsiColor::BrightCyan), true, false, style.color),
            stats.duration_ms_max
        );
    }

    if !stats.per_provider.is_empty() {
        println!("{}", paint("  Providers", style.accent(), true, false, style.color));
        for (provider, count) in stats.per_provider.iter() {
            let name = paint(
                provider.label(),
                style.provider_color(*provider),
                true,
                false,
                style.color,
            );
            println!("    {} {}", count, name);
        }
    }

    if !stats.per_domain.is_empty() {
        println!("{}", paint("  Top Domains", style.accent(), true, false, style.color));
        for (name, count) in top_n_string(&stats.per_domain, stats_top) {
            println!("    {} {}", count, name);
        }
    }

    if !stats.per_ip.is_empty() {
        println!("{}", paint("  Top IPs", style.accent(), true, false, style.color));
        for (ip, count) in top_n_string(&stats.per_ip, stats_top) {
            println!("    {} {}", count, ip);
        }
    }

    if !stats.per_comm.is_empty() {
        println!("{}", paint("  Top Processes", style.accent(), true, false, style.color));
        for (comm, count) in top_n_string(&stats.per_comm, stats_top) {
            println!("    {} {}", count, comm);
        }
    }

    if let Some(writer) = log_writer {
        let line = format!(
            "summary connects={} closes={} active={} peak_active={} sqlite_dropped={}",
            stats.connects, stats.closes, stats.active, stats.peak_active, stats.sqlite_dropped
        );
        writer.write_line(&line);
    }
}

fn format_json_summary(stats: &Stats, domain_mode: &str) -> String {
    let mut out = String::new();
    out.push('{');
    out.push_str("\"summary\":{");
    push_json_num(&mut out, "connects", stats.connects as i64, true);
    push_json_num(&mut out, "closes", stats.closes as i64, false);
    push_json_num(&mut out, "active", stats.active as i64, false);
    push_json_num(&mut out, "peak_active", stats.peak_active as i64, false);
    push_json_num(&mut out, "sqlite_dropped", stats.sqlite_dropped as i64, false);
    if stats.duration_ms_samples > 0 {
        let avg = stats.duration_ms_total / stats.duration_ms_samples;
        push_json_num(&mut out, "avg_duration_ms", avg as i64, false);
        push_json_num(&mut out, "max_duration_ms", stats.duration_ms_max as i64, false);
    }
    push_json_map_ip(&mut out, "per_ip", &stats.per_ip, false);
    push_json_map_str(&mut out, "per_domain", &stats.per_domain, false);
    push_json_map_u32(&mut out, "per_pid", &stats.per_pid, false);
    push_json_map_str(&mut out, "per_comm", &stats.per_comm, false);
    push_json_map_provider(&mut out, "per_provider", &stats.per_provider, false);
    push_json_str(&mut out, "domain_mode", domain_mode, false);
    out.push('}');
    out.push('}');
    out
}

fn top_n_string<K: ToString + Ord>(map: &BTreeMap<K, u64>, n: usize) -> Vec<(String, u64)> {
    let mut items: Vec<(String, u64)> = map.iter().map(|(k, v)| (k.to_string(), *v)).collect();
    items.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    items.truncate(n);
    items
}

fn print_stats(stats: &Stats, width: usize, top: usize, style: OutputStyle, view: StatsView) {
    match view {
        StatsView::Provider => print_provider_stats(stats, width, style),
        StatsView::Domain => {
            let items = top_n_string(&stats.per_domain, top);
            print_stats_list("domain", &items, width, style, 48);
        }
        StatsView::Port => {
            let items = top_n_string(&stats.per_port, top);
            print_stats_list("port", &items, width, style, 8);
        }
        StatsView::Process => {
            let items = top_n_string(&stats.per_comm, top);
            print_stats_list("process", &items, width, style, 24);
        }
    }
}

fn print_provider_stats(stats: &Stats, width: usize, style: OutputStyle) {
    let total = stats
        .per_provider
        .values()
        .copied()
        .max()
        .unwrap_or(0)
        .max(1);
    let providers = [
        Provider::Anthropic,
        Provider::OpenAI,
        Provider::Google,
        Provider::Unknown,
    ];
    println!(
        "{}",
        paint("Live Stats [provider]", style.accent(), true, false, style.color)
    );
    for provider in providers {
        let count = *stats.per_provider.get(&provider).unwrap_or(&0);
        let bar_len = ((count as f64 / total as f64) * width as f64).round() as usize;
        let bar_plain = format!("{:width$}", "█".repeat(bar_len), width = width);
        let bar = if style.color {
            paint(&bar_plain, style.provider_color(provider), false, false, style.color)
        } else {
            bar_plain
        };
        let label = paint(
            provider.label(),
            style.provider_color(provider),
            true,
            false,
            style.color,
        );
        let domains = stats
            .per_provider_domains
            .get(&provider)
            .map(|s| s.len())
            .unwrap_or(0);
        let ips = stats
            .per_provider_ips
            .get(&provider)
            .map(|s| s.len())
            .unwrap_or(0);
        println!(
            "  {:<10} | {} {} (domains={}, ips={})",
            label, bar, count, domains, ips
        );
    }
    println!(
        "  active={} peak={} avg_dur={}ms",
        stats.active,
        stats.peak_active,
        if stats.duration_ms_samples > 0 {
            stats.duration_ms_total / stats.duration_ms_samples
        } else {
            0
        }
    );
}

fn print_stats_list(
    title: &str,
    items: &[(String, u64)],
    width: usize,
    style: OutputStyle,
    label_width: usize,
) {
    println!(
        "{}",
        paint(
            &format!("Live Stats [{}]", title),
            style.accent(),
            true,
            false,
            style.color
        )
    );
    if items.is_empty() {
        println!("  (no data)");
        return;
    }
    let max = items
        .iter()
        .map(|(_, count)| *count)
        .max()
        .unwrap_or(1)
        .max(1);
    for (label, count) in items {
        let bar = render_stats_bar(*count, max, width, style);
        let label = truncate_ascii(label, label_width);
        println!("  {:>6} {} {}", count, bar, label);
    }
}

fn render_stats_bar(count: u64, max: u64, width: usize, style: OutputStyle) -> String {
    if width == 0 {
        return String::new();
    }
    let bar_len = ((count as f64 / max as f64) * width as f64).round() as usize;
    let bar_plain = format!("{:width$}", "█".repeat(bar_len), width = width);
    paint(&bar_plain, style.accent(), false, false, style.color)
}

fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(ch) = chars.next() {
        if ch == '\x1b' {
            while let Some(next) = chars.next() {
                if next == 'm' {
                    break;
                }
            }
            continue;
        }
        out.push(ch);
    }
    out
}

fn open_log_writer(
    args: &MonitorArgs,
    domain_label: &str,
    resolved_format: LogFormat,
) -> Option<Arc<LogWriter>> {
    let path = if let Some(file) = &args.log_file {
        Some(file.clone())
    } else if let Some(dir) = &args.log_dir {
        let _ = fs::create_dir_all(dir);
        let ts = now_rfc3339().replace(':', "");
        let ext = match resolved_format {
            LogFormat::Json => "jsonl",
            _ => "log",
        };
        let filename = format!("rano-{}-{}.{}", ts, domain_label, ext);
        Some(dir.join(filename))
    } else {
        None
    };

    let path = match path {
        Some(p) => p,
        None => return None,
    };

    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .ok()?;

    Some(Arc::new(LogWriter {
        file: Mutex::new(file),
    }))
}

fn start_sqlite_writer(
    args: &MonitorArgs,
    run_ctx: RunContext,
    log_writer: Option<Arc<LogWriter>>,
) -> Option<SqliteWriter> {
    let queue_max = args.db_queue_max;
    let batch_size = args.db_batch_size;
    let flush_ms = args.db_flush_ms;
    let (sender, receiver) = mpsc::sync_channel(queue_max);
    let (ready_tx, ready_rx) = mpsc::sync_channel(1);
    let dropped_total = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let log_clone = log_writer.clone();
    let path = args.sqlite_path.to_string();
    let handle = std::thread::spawn(move || {
        sqlite_writer_loop(path, run_ctx, receiver, ready_tx, log_clone, batch_size, flush_ms);
    });

    let start_result = match ready_rx.recv() {
        Ok(result) => result,
        Err(_) => Err("sqlite writer failed to start".to_string()),
    };

    if let Err(err) = start_result {
        let msg = format!("warning: sqlite disabled ({})", err);
        eprintln!("{}", msg);
        if let Some(writer) = log_writer.as_ref() {
            writer.write_line(&msg);
        }
        return None;
    }

    let last_warn = SystemTime::now()
        .checked_sub(Duration::from_secs(SQLITE_DROP_WARN_INTERVAL_SECS))
        .unwrap_or_else(SystemTime::now);

    Some(SqliteWriter {
        sender,
        handle: Some(handle),
        dropped_total,
        drop_state: Mutex::new(DropState {
            last_warn,
            dropped_since_warn: 0,
        }),
        log_writer,
    })
}

fn sqlite_writer_loop(
    sqlite_path: String,
    run_ctx: RunContext,
    receiver: Receiver<SqliteMsg>,
    ready_tx: SyncSender<Result<(), String>>,
    log_writer: Option<Arc<LogWriter>>,
    batch_size: usize,
    flush_ms: u64,
) {
    let mut conn = match Connection::open(&sqlite_path) {
        Ok(conn) => conn,
        Err(err) => {
            let _ = ready_tx.send(Err(format!("sqlite open failed: {}", err)));
            return;
        }
    };

    if let Err(err) = init_sqlite(&mut conn) {
        let _ = ready_tx.send(Err(format!("sqlite init failed: {}", err)));
        return;
    }

    if let Err(err) = insert_session(&mut conn, &run_ctx) {
        let _ = ready_tx.send(Err(format!("sqlite session insert failed: {}", err)));
        return;
    }

    let _ = ready_tx.send(Ok(()));

    let mut batch: Vec<SqliteEvent> = Vec::with_capacity(batch_size);
    let mut last_flush = SystemTime::now();
    let flush_interval = Duration::from_millis(flush_ms);
    let mut shutdown: Option<(String, u64, u64)> = None;

    loop {
        match receiver.recv_timeout(flush_interval) {
            Ok(SqliteMsg::Event(event)) => {
                batch.push(event);
            }
            Ok(SqliteMsg::Shutdown {
                run_id,
                connects,
                closes,
            }) => {
                shutdown = Some((run_id, connects, closes));
                break;
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => break,
        }

        let now = SystemTime::now();
        if batch.len() >= batch_size
            || now
                .duration_since(last_flush)
                .map(|d| d >= flush_interval)
                .unwrap_or(true)
        {
            if let Err(err) = write_sqlite_batch(&mut conn, &batch) {
                let msg = format!("warning: sqlite batch write failed: {}", err);
                eprintln!("{}", msg);
                if let Some(writer) = log_writer.as_ref() {
                    writer.write_line(&msg);
                }
            }
            batch.clear();
            last_flush = now;
        }
    }

    while let Ok(msg) = receiver.try_recv() {
        match msg {
            SqliteMsg::Event(event) => batch.push(event),
            SqliteMsg::Shutdown {
                run_id,
                connects,
                closes,
            } => {
                shutdown = Some((run_id, connects, closes));
            }
        }
    }

    if let Err(err) = write_sqlite_batch(&mut conn, &batch) {
        let msg = format!("warning: sqlite batch write failed: {}", err);
        eprintln!("{}", msg);
        if let Some(writer) = log_writer.as_ref() {
            writer.write_line(&msg);
        }
    }

    if let Some((run_id, connects, closes)) = shutdown {
        if let Err(err) = finalize_session(&mut conn, &run_id, connects, closes) {
            let msg = format!("warning: sqlite finalize failed: {}", err);
            eprintln!("{}", msg);
            if let Some(writer) = log_writer.as_ref() {
                writer.write_line(&msg);
            }
        }
    }
}

fn write_sqlite_batch(conn: &mut Connection, batch: &[SqliteEvent]) -> rusqlite::Result<()> {
    if batch.is_empty() {
        return Ok(());
    }
    conn.execute_batch("BEGIN")?;
    for event in batch {
        if let Err(err) = log_sqlite_event(conn, event) {
            let _ = conn.execute_batch("ROLLBACK");
            return Err(err);
        }
    }
    if let Err(err) = conn.execute_batch("COMMIT") {
        let _ = conn.execute_batch("ROLLBACK");
        return Err(err);
    }
    Ok(())
}

fn self_update(update: UpdateCommand) -> Result<(), Box<dyn std::error::Error>> {
    let (owner, repo) = resolve_repo(&update)?;
    let branch = update
        .branch
        .clone()
        .or_else(|| env::var("RANO_BRANCH").ok())
        .unwrap_or_else(|| "main".to_string());

    if cfg!(windows) {
        return self_update_windows(&update, &owner, &repo, &branch);
    }

    self_update_unix(&update, &owner, &repo, &branch)
}

fn resolve_repo(update: &UpdateCommand) -> Result<(String, String), Box<dyn std::error::Error>> {
    const DEFAULT_OWNER: &str = "lumera-ai";
    const DEFAULT_REPO: &str = "rano";

    if update.owner.is_some() || update.repo.is_some() {
        let owner = update
            .owner
            .clone()
            .ok_or_else(|| "Missing --owner (both --owner and --repo are required when overriding).")?;
        let repo = update
            .repo
            .clone()
            .ok_or_else(|| "Missing --repo (both --owner and --repo are required when overriding).")?;
        return Ok((owner, repo));
    }
    if let (Ok(owner), Ok(repo)) = (env::var("RANO_OWNER"), env::var("RANO_REPO")) {
        return Ok((owner, repo));
    }
    if let Some((owner, repo)) = repo_from_git() {
        return Ok((owner, repo));
    }
    eprintln!(
        "Using default update repo {}/{} (set RANO_OWNER/RANO_REPO to override).",
        DEFAULT_OWNER, DEFAULT_REPO
    );
    Ok((DEFAULT_OWNER.to_string(), DEFAULT_REPO.to_string()))
}

fn repo_from_git() -> Option<(String, String)> {
    let output = ProcessCommand::new("git")
        .arg("config")
        .arg("--get")
        .arg("remote.origin.url")
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let url = String::from_utf8_lossy(&output.stdout).trim().to_string();
    parse_github_repo(&url)
}

fn parse_github_repo(url: &str) -> Option<(String, String)> {
    let trimmed = url.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Some(stripped) = trimmed.strip_prefix("git@github.com:") {
        return split_owner_repo(stripped);
    }
    if let Some(stripped) = trimmed.strip_prefix("https://github.com/") {
        return split_owner_repo(stripped);
    }
    if let Some(stripped) = trimmed.strip_prefix("ssh://git@github.com/") {
        return split_owner_repo(stripped);
    }
    None
}

fn split_owner_repo(input: &str) -> Option<(String, String)> {
    let trimmed = input.trim_end_matches(".git").trim_matches('/');
    let mut iter = trimmed.splitn(2, '/');
    let owner = iter.next()?.to_string();
    let repo = iter.next()?.to_string();
    if owner.is_empty() || repo.is_empty() {
        return None;
    }
    Some((owner, repo))
}

fn self_update_unix(
    update: &UpdateCommand,
    owner: &str,
    repo: &str,
    branch: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let script_url = format!(
        "https://raw.githubusercontent.com/{}/{}/{}/install.sh",
        owner, repo, branch
    );
    let mut args: Vec<String> = Vec::new();

    if let Some(version) = &update.version {
        args.push("--version".to_string());
        args.push(version.clone());
    }
    if update.system {
        args.push("--system".to_string());
    }
    if update.easy_mode {
        args.push("--easy-mode".to_string());
    }
    if let Some(dest) = &update.dest {
        args.push("--dest".to_string());
        args.push(dest.to_string_lossy().into_owned());
    }
    if update.from_source {
        args.push("--from-source".to_string());
    }
    if update.verify {
        args.push("--verify".to_string());
    }
    if update.quiet {
        args.push("--quiet".to_string());
    }
    if update.no_gum {
        args.push("--no-gum".to_string());
    }

    let mut escaped_args = String::new();
    for (idx, arg) in args.iter().enumerate() {
        if idx > 0 {
            escaped_args.push(' ');
        }
        escaped_args.push_str(&shell_escape_posix(arg));
    }

    let mut command = String::new();
    command.push_str("OWNER=");
    command.push_str(&shell_escape_posix(owner));
    command.push(' ');
    command.push_str("REPO=");
    command.push_str(&shell_escape_posix(repo));
    command.push(' ');
    if escaped_args.is_empty() {
        command.push_str(&format!(
            "curl -fsSL {} | bash -s --",
            shell_escape_posix(&script_url)
        ));
    } else {
        command.push_str(&format!(
            "curl -fsSL {} | bash -s -- {}",
            shell_escape_posix(&script_url),
            escaped_args
        ));
    }

    let status = ProcessCommand::new("sh").arg("-c").arg(command).status()?;
    if !status.success() {
        return Err(format!("Installer failed with status {status}").into());
    }
    Ok(())
}

fn self_update_windows(
    update: &UpdateCommand,
    owner: &str,
    repo: &str,
    branch: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    if update.system || update.from_source || update.quiet || update.no_gum {
        return Err(
            "Windows updater supports only --version, --dest, --easy-mode, and --verify.".into(),
        );
    }

    let script_url = format!(
        "https://raw.githubusercontent.com/{}/{}/{}/install.ps1",
        owner, repo, branch
    );
    let mut args: Vec<String> = Vec::new();

    args.push(format!("-Owner {}", shell_escape_powershell(owner)));
    args.push(format!("-Repo {}", shell_escape_powershell(repo)));

    if let Some(version) = &update.version {
        args.push(format!("-Version {}", shell_escape_powershell(version)));
    }
    if let Some(dest) = &update.dest {
        args.push(format!(
            "-Dest {}",
            shell_escape_powershell(&dest.to_string_lossy())
        ));
    }
    if update.easy_mode {
        args.push("-EasyMode".to_string());
    }
    if update.verify {
        args.push("-Verify".to_string());
    }

    let args_str = args.join(" ");

    let command = format!(
        "$ErrorActionPreference='Stop'; \
$url={url}; \
$script=(Invoke-WebRequest -UseBasicParsing $url).Content; \
$sb=[ScriptBlock]::Create($script); \
& $sb {args}",
        url = shell_escape_powershell(&script_url),
        args = args_str,
    );

    let status = ProcessCommand::new("powershell")
        .arg("-NoProfile")
        .arg("-ExecutionPolicy")
        .arg("Bypass")
        .arg("-Command")
        .arg(command)
        .status()?;

    if !status.success() {
        return Err(format!("Installer failed with status {status}").into());
    }
    Ok(())
}

fn shell_escape_posix(input: &str) -> String {
    if input.is_empty() {
        return "''".to_string();
    }
    if input
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || "-_./".contains(c))
    {
        return input.to_string();
    }
    format!("'{}'", input.replace('\'', "'\"'\"'"))
}

fn shell_escape_powershell(input: &str) -> String {
    format!("'{}'", input.replace('\'', "''"))
}

fn resolve_domain(ip: IpAddr, cache: &mut HashMap<IpAddr, DnsCacheEntry>) -> Option<String> {
    let now = SystemTime::now();
    let ttl = Duration::from_secs(600);
    if let Some(entry) = cache.get(&ip) {
        if now.duration_since(entry.stored_at).unwrap_or_default() < ttl {
            return entry.value.clone();
        }
    }

    let result = reverse_dns(ip);
    cache.insert(
        ip,
        DnsCacheEntry {
            value: result.clone(),
            stored_at: now,
        },
    );
    result
}

fn reverse_dns(ip: IpAddr) -> Option<String> {
    unsafe {
        let mut host = [0i8; libc::NI_MAXHOST as usize];
        let flags = libc::NI_NAMEREQD;
        match ip {
            IpAddr::V4(v4) => {
                let octets = v4.octets();
                let addr = libc::sockaddr_in {
                    sin_family: libc::AF_INET as u16,
                    sin_port: 0,
                    sin_addr: libc::in_addr {
                        s_addr: u32::from_be_bytes(octets),
                    },
                    sin_zero: [0; 8],
                };
                let ret = libc::getnameinfo(
                    &addr as *const _ as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_in>() as u32,
                    host.as_mut_ptr(),
                    host.len() as u32,
                    std::ptr::null_mut(),
                    0,
                    flags,
                );
                if ret == 0 {
                    return Some(CStr::from_ptr(host.as_ptr()).to_string_lossy().to_string());
                }
            }
            IpAddr::V6(v6) => {
                let addr = libc::sockaddr_in6 {
                    sin6_family: libc::AF_INET6 as u16,
                    sin6_port: 0,
                    sin6_flowinfo: 0,
                    sin6_addr: libc::in6_addr { s6_addr: v6.octets() },
                    sin6_scope_id: 0,
                };
                let ret = libc::getnameinfo(
                    &addr as *const _ as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_in6>() as u32,
                    host.as_mut_ptr(),
                    host.len() as u32,
                    std::ptr::null_mut(),
                    0,
                    flags,
                );
                if ret == 0 {
                    return Some(CStr::from_ptr(host.as_ptr()).to_string_lossy().to_string());
                }
            }
        }
    }
    None
}

#[derive(Clone, Debug)]
struct PidMeta {
    comm: String,
    cmdline: String,
    provider: Provider,
}

fn find_root_pids(patterns: &[String], exclude_patterns: &[String], explicit_pids: &[u32]) -> Vec<u32> {
    let lowered: Vec<String> = patterns.iter().map(|p| p.to_lowercase()).collect();
    let excluded: Vec<String> = exclude_patterns.iter().map(|p| p.to_lowercase()).collect();
    let mut roots = Vec::new();
    let mut seen: HashSet<u32> = HashSet::new();

    for pid in explicit_pids {
        if seen.insert(*pid) {
            roots.push(*pid);
        }
    }

    if lowered.is_empty() {
        return roots;
    }

    for pid in list_pids() {
        let comm = read_comm(pid).unwrap_or_default();
        let cmd = read_cmdline(pid).unwrap_or_default();
        let comm_l = comm.to_lowercase();
        let cmd_l = cmd.to_lowercase();
        if !excluded.is_empty() && excluded.iter().any(|p| comm_l.contains(p) || cmd_l.contains(p)) {
            continue;
        }
        if lowered.iter().any(|p| comm_l.contains(p) || cmd_l.contains(p)) {
            if seen.insert(pid) {
                roots.push(pid);
            }
        }
    }
    roots
}

fn collect_descendants(roots: &[u32]) -> HashSet<u32> {
    let mut parent_map: HashMap<u32, Vec<u32>> = HashMap::new();
    for pid in list_pids() {
        if let Some(ppid) = read_ppid(pid) {
            parent_map.entry(ppid).or_default().push(pid);
        }
    }

    let mut set: HashSet<u32> = HashSet::new();
    let mut stack: Vec<u32> = roots.to_vec();
    while let Some(pid) = stack.pop() {
        if !set.insert(pid) {
            continue;
        }
        if let Some(children) = parent_map.get(&pid) {
            for child in children {
                stack.push(*child);
            }
        }
    }
    set
}

fn map_inodes(targets: &HashSet<u32>) -> HashMap<u64, u32> {
    let mut map = HashMap::new();
    for pid in targets {
        let fd_dir = format!("/proc/{}/fd", pid);
        if let Ok(entries) = fs::read_dir(fd_dir) {
            for entry in entries.flatten() {
                if let Ok(link) = fs::read_link(entry.path()) {
                    let link_str = link.to_string_lossy();
                    if let Some(inode) = parse_socket_inode(&link_str) {
                        map.insert(inode, *pid);
                    }
                }
            }
        }
    }
    map
}

fn build_pid_meta_map(targets: &HashSet<u32>, matcher: &ProviderMatcher) -> HashMap<u32, PidMeta> {
    let mut map = HashMap::new();
    for pid in targets {
        let comm = read_comm(*pid).unwrap_or_else(|| "unknown".to_string());
        let cmdline = read_cmdline(*pid).unwrap_or_default();
        let provider = provider_from_text(&comm, &cmdline, matcher);
        map.insert(
            *pid,
            PidMeta {
                comm,
                cmdline,
                provider,
            },
        );
    }
    map
}

fn provider_from_text(comm: &str, cmdline: &str, matcher: &ProviderMatcher) -> Provider {
    let text = format!("{} {}", comm.to_lowercase(), cmdline.to_lowercase());
    if matcher.anthropic.iter().any(|p| text.contains(p)) {
        Provider::Anthropic
    } else if matcher.openai.iter().any(|p| text.contains(p)) {
        Provider::OpenAI
    } else if matcher.google.iter().any(|p| text.contains(p)) {
        Provider::Google
    } else {
        Provider::Unknown
    }
}

fn parse_socket_inode(link: &str) -> Option<u64> {
    if let Some(start) = link.find("socket:[") {
        let rest = &link[start + 8..];
        if let Some(end) = rest.find(']') {
            let inode_str = &rest[..end];
            return inode_str.parse::<u64>().ok();
        }
    }
    None
}

fn list_pids() -> Vec<u32> {
    let mut pids = Vec::new();
    if let Ok(entries) = fs::read_dir("/proc") {
        for entry in entries.flatten() {
            if let Some(name) = entry.file_name().to_str() {
                if let Ok(pid) = name.parse::<u32>() {
                    pids.push(pid);
                }
            }
        }
    }
    pids
}

fn read_comm(pid: u32) -> Option<String> {
    let path = format!("/proc/{}/comm", pid);
    fs::read_to_string(path).ok().map(|s| s.trim().to_string())
}

fn read_cmdline(pid: u32) -> Option<String> {
    let path = format!("/proc/{}/cmdline", pid);
    let mut data = Vec::new();
    if let Ok(mut file) = fs::File::open(path) {
        if file.read_to_end(&mut data).is_ok() {
            let cmd = data
                .split(|b| *b == 0)
                .filter(|s| !s.is_empty())
                .map(|s| String::from_utf8_lossy(s).to_string())
                .collect::<Vec<_>>()
                .join(" ");
            return Some(cmd);
        }
    }
    None
}

fn read_ppid(pid: u32) -> Option<u32> {
    let path = format!("/proc/{}/stat", pid);
    let content = fs::read_to_string(path).ok()?;
    let parts: Vec<&str> = content.split_whitespace().collect();
    if parts.len() > 3 {
        parts[3].parse::<u32>().ok()
    } else {
        None
    }
}

fn gather_net_entries(include_udp: bool) -> Vec<(Proto, NetEntry)> {
    let mut entries = Vec::new();
    entries.extend(read_net_file("/proc/net/tcp", Proto::Tcp, false));
    entries.extend(read_net_file("/proc/net/tcp6", Proto::Tcp, true));
    if include_udp {
        entries.extend(read_net_file("/proc/net/udp", Proto::Udp, false));
        entries.extend(read_net_file("/proc/net/udp6", Proto::Udp, true));
    }
    entries
}

fn read_net_file(path: &str, proto: Proto, ipv6: bool) -> Vec<(Proto, NetEntry)> {
    let mut result = Vec::new();
    if !Path::new(path).exists() {
        return result;
    }
    let content = fs::read_to_string(path).unwrap_or_default();
    for (idx, line) in content.lines().enumerate() {
        if idx == 0 {
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 10 {
            continue;
        }
        let local = parts[1];
        let remote = parts[2];
        let state = parts[3].to_string();
        let inode = parts[9].parse::<u64>().unwrap_or(0);

        let (local_ip, local_port) = match parse_addr_port(local, ipv6) {
            Some(v) => v,
            None => continue,
        };
        let (remote_ip, remote_port) = match parse_addr_port(remote, ipv6) {
            Some(v) => v,
            None => continue,
        };

        result.push((
            proto,
            NetEntry {
                local_ip,
                local_port,
                remote_ip,
                remote_port,
                inode,
                state,
            },
        ));
    }
    result
}

fn parse_addr_port(s: &str, ipv6: bool) -> Option<(IpAddr, u16)> {
    let mut iter = s.split(':');
    let addr_hex = iter.next()?;
    let port_hex = iter.next()?;
    let port = u16::from_str_radix(port_hex, 16).ok()?;
    let ip = if ipv6 {
        IpAddr::V6(parse_ipv6(addr_hex)?)
    } else {
        IpAddr::V4(parse_ipv4(addr_hex)?)
    };
    Some((ip, port))
}

fn parse_ipv4(hex: &str) -> Option<Ipv4Addr> {
    if hex.len() != 8 {
        return None;
    }
    let raw = u32::from_str_radix(hex, 16).ok()?;
    let bytes = raw.to_le_bytes();
    Some(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]))
}

fn parse_ipv6(hex: &str) -> Option<Ipv6Addr> {
    if hex.len() != 32 {
        return None;
    }
    let mut bytes = [0u8; 16];
    for i in 0..4 {
        let part = &hex[i * 8..(i + 1) * 8];
        let raw = u32::from_str_radix(part, 16).ok()?;
        let chunk = raw.to_le_bytes();
        bytes[i * 4..i * 4 + 4].copy_from_slice(&chunk);
    }
    Some(Ipv6Addr::from(bytes))
}

// ============================================================================
// Report Subcommand
// ============================================================================

fn run_report(args: ReportArgs) -> Result<(), String> {
    let path = Path::new(&args.sqlite_path);
    if !path.exists() {
        return Err(format!("SQLite file not found: {}", args.sqlite_path));
    }

    let conn = Connection::open(path)
        .map_err(|e| format!("Failed to open database: {}", e))?;

    // Check schema
    let has_events = table_exists(&conn, "events")?;
    if !has_events {
        return Err(format!(
            "Database does not contain rano event data (missing events table). {}",
            schema_hint(&args.sqlite_path)
        ));
    }
    let has_sessions = table_exists(&conn, "sessions")?;
    check_report_schema(&conn, &args.sqlite_path, has_sessions)?;

    let color_enabled = resolve_color_mode(args.color);

    // Determine run_id filter
    let run_id = if let Some(id) = args.run_id.clone() {
        Some(id)
    } else if args.latest {
        find_latest_session(&conn)?
    } else {
        None
    };

    // Parse time filters
    let since = parse_time_filter(&args.since)?;
    let until = parse_time_filter(&args.until)?;

    // Build filter context for queries
    let filter = ReportFilter {
        run_id: run_id.clone(),
        since,
        until,
    };

    if args.json {
        output_report_json(&conn, &filter, args.top, has_sessions)?;
    } else {
        output_report_pretty(&conn, &filter, args.top, has_sessions, color_enabled)?;
    }

    Ok(())
}

struct ReportFilter {
    run_id: Option<String>,
    since: Option<String>,
    until: Option<String>,
}

fn table_exists(conn: &Connection, table_name: &str) -> Result<bool, String> {
    let sql = "SELECT name FROM sqlite_master WHERE type='table' AND name=?";
    let result: Option<String> = conn
        .query_row(sql, [table_name], |row| row.get(0))
        .ok();
    Ok(result.is_some())
}

fn view_exists(conn: &Connection, view_name: &str) -> Result<bool, String> {
    let sql = "SELECT name FROM sqlite_master WHERE type='view' AND name=?";
    let result: Option<String> = conn
        .query_row(sql, [view_name], |row| row.get(0))
        .ok();
    Ok(result.is_some())
}

fn column_exists(conn: &Connection, table_name: &str, column: &str) -> Result<bool, String> {
    let pragma = format!("PRAGMA table_info({})", table_name);
    let mut stmt = conn
        .prepare(&pragma)
        .map_err(|e| format!("Failed to inspect schema: {}", e))?;
    let mut rows = stmt
        .query([])
        .map_err(|e| format!("Failed to read schema: {}", e))?;
    while let Some(row) = rows.next().map_err(|e| format!("Failed to read schema: {}", e))? {
        let name: String = row.get(1).map_err(|e| format!("Failed to read schema: {}", e))?;
        if name == column {
            return Ok(true);
        }
    }
    Ok(false)
}

fn check_report_schema(
    conn: &Connection,
    sqlite_path: &str,
    has_sessions: bool,
) -> Result<(), String> {
    let required_columns = ["ts", "event", "provider", "remote_ip", "domain", "run_id"];
    let mut missing_cols = Vec::new();
    for col in required_columns.iter() {
        if !column_exists(conn, "events", col)? {
            missing_cols.push(*col);
        }
    }
    if !missing_cols.is_empty() {
        return Err(format!(
            "Database schema missing columns in events table: {}. {}",
            missing_cols.join(", "),
            schema_hint(sqlite_path)
        ));
    }

    if !has_sessions {
        eprintln!(
            "warning: sessions table missing; session metadata will be unavailable. {}",
            schema_hint(sqlite_path)
        );
    }

    let expected_views = [
        "provider_counts",
        "provider_domains",
        "provider_ips",
        "provider_ports",
        "provider_processes",
        "provider_last_hour",
        "provider_hourly",
        "session_summary",
    ];
    let mut missing_views = Vec::new();
    for view in expected_views.iter() {
        if !view_exists(conn, view)? {
            missing_views.push(*view);
        }
    }
    if !missing_views.is_empty() {
        eprintln!(
            "warning: missing sqlite views ({}). Report will use fallback queries where possible. {}",
            missing_views.join(", "),
            schema_hint(sqlite_path)
        );
    }

    Ok(())
}

fn schema_hint(sqlite_path: &str) -> String {
    format!(
        "To regenerate the schema, run: rano --once --sqlite {} (with the current binary).",
        sqlite_path
    )
}

fn find_latest_session(conn: &Connection) -> Result<Option<String>, String> {
    let sql = "SELECT run_id FROM sessions ORDER BY start_ts DESC LIMIT 1";
    match conn.query_row(sql, [], |row| row.get::<_, String>(0)) {
        Ok(id) => Ok(Some(id)),
        Err(rusqlite::Error::QueryReturnedNoRows) => {
            // No sessions table or no sessions, try events
            let sql2 = "SELECT DISTINCT run_id FROM events WHERE run_id IS NOT NULL ORDER BY ts DESC LIMIT 1";
            match conn.query_row(sql2, [], |row| row.get::<_, String>(0)) {
                Ok(id) => Ok(Some(id)),
                Err(_) => Ok(None),
            }
        }
        Err(e) => Err(format!("Failed to query sessions: {}", e)),
    }
}

fn parse_time_filter(input: &Option<String>) -> Result<Option<String>, String> {
    let Some(s) = input else {
        return Ok(None);
    };

    // Check for relative time formats: 1h, 24h, 7d, 30m
    if let Some(ts) = parse_relative_time(s) {
        return Ok(Some(ts));
    }

    // Check for RFC3339 format
    if s.contains('T') && s.contains(':') {
        return Ok(Some(s.clone()));
    }

    // Check for date-only format (YYYY-MM-DD)
    if s.len() == 10 && s.chars().filter(|c| *c == '-').count() == 2 {
        return Ok(Some(format!("{}T00:00:00Z", s)));
    }

    Err(format!("Invalid timestamp format: {} (use RFC3339, YYYY-MM-DD, or relative like 1h/24h/7d)", s))
}

fn parse_relative_time(s: &str) -> Option<String> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }

    let (num_str, unit) = if s.ends_with('h') {
        (&s[..s.len()-1], "h")
    } else if s.ends_with('d') {
        (&s[..s.len()-1], "d")
    } else if s.ends_with('m') {
        (&s[..s.len()-1], "m")
    } else if s.ends_with('w') {
        (&s[..s.len()-1], "w")
    } else {
        return None;
    };

    let num: u64 = num_str.parse().ok()?;
    let secs = match unit {
        "m" => num * 60,
        "h" => num * 3600,
        "d" => num * 86400,
        "w" => num * 604800,
        _ => return None,
    };

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let target = now.as_secs().saturating_sub(secs);
    let dt = UNIX_EPOCH + Duration::from_secs(target);
    Some(system_time_to_rfc3339(dt))
}

fn output_report_json(
    conn: &Connection,
    filter: &ReportFilter,
    top: usize,
    has_sessions: bool,
) -> Result<(), String> {
    let mut out = String::from("{\n");

    // Meta section
    out.push_str("  \"meta\": {\n");
    out.push_str(&format!("    \"generated_at\": \"{}\",\n", system_time_to_rfc3339(SystemTime::now())));
    if let Some(ref run_id) = filter.run_id {
        out.push_str(&format!("    \"run_id\": \"{}\",\n", run_id));
    }
    if let Some(ref since) = filter.since {
        out.push_str(&format!("    \"since\": \"{}\",\n", since));
    }
    if let Some(ref until) = filter.until {
        out.push_str(&format!("    \"until\": \"{}\",\n", until));
    }
    out.push_str("    \"version\": \"1.0\"\n");
    out.push_str("  },\n");

    // Session info (if available and filtering by run_id)
    if has_sessions {
        if let Some(ref run_id) = filter.run_id {
            if let Some(session) = query_session(conn, run_id)? {
                out.push_str("  \"session\": {\n");
                out.push_str(&format!("    \"run_id\": \"{}\",\n", session.run_id));
                out.push_str(&format!("    \"start_ts\": \"{}\",\n", session.start_ts));
                if let Some(end) = &session.end_ts {
                    out.push_str(&format!("    \"end_ts\": \"{}\",\n", end));
                }
                if let Some(host) = &session.host {
                    out.push_str(&format!("    \"host\": \"{}\",\n", host));
                }
                if let Some(user) = &session.user {
                    out.push_str(&format!("    \"user\": \"{}\",\n", user));
                }
                if let Some(patterns) = &session.patterns {
                    out.push_str(&format!("    \"patterns\": \"{}\",\n", patterns));
                }
                out.push_str(&format!("    \"connects\": {},\n", session.connects.unwrap_or(0)));
                out.push_str(&format!("    \"closes\": {}\n", session.closes.unwrap_or(0)));
                out.push_str("  },\n");
            }
        }
    }

    // Summary statistics
    let summary = query_summary(conn, filter)?;
    out.push_str("  \"summary\": {\n");
    out.push_str(&format!("    \"total_events\": {},\n", summary.total_events));
    out.push_str(&format!("    \"connects\": {},\n", summary.connects));
    out.push_str(&format!("    \"closes\": {},\n", summary.closes));
    out.push_str(&format!("    \"active\": {}\n", summary.connects.saturating_sub(summary.closes)));
    out.push_str("  },\n");

    // Provider breakdown
    let providers = query_providers(conn, filter)?;
    out.push_str("  \"providers\": [\n");
    for (i, p) in providers.iter().enumerate() {
        out.push_str(&format!(
            "    {{\"provider\": \"{}\", \"events\": {}, \"connects\": {}, \"closes\": {}}}",
            p.provider, p.events, p.connects, p.closes
        ));
        if i < providers.len() - 1 {
            out.push_str(",");
        }
        out.push_str("\n");
    }
    out.push_str("  ],\n");

    // Top domains
    let domains = query_top_domains(conn, filter, top)?;
    out.push_str("  \"top_domains\": [\n");
    for (i, d) in domains.iter().enumerate() {
        out.push_str(&format!(
            "    {{\"domain\": \"{}\", \"events\": {}, \"provider\": \"{}\"}}",
            d.domain, d.events, d.provider
        ));
        if i < domains.len() - 1 {
            out.push_str(",");
        }
        out.push_str("\n");
    }
    out.push_str("  ],\n");

    // Top IPs
    let ips = query_top_ips(conn, filter, top)?;
    out.push_str("  \"top_ips\": [\n");
    for (i, ip) in ips.iter().enumerate() {
        let domain_str = ip.domain.as_deref().unwrap_or("unknown");
        out.push_str(&format!(
            "    {{\"ip\": \"{}\", \"events\": {}, \"domain\": \"{}\"}}",
            ip.ip, ip.events, domain_str
        ));
        if i < ips.len() - 1 {
            out.push_str(",");
        }
        out.push_str("\n");
    }
    out.push_str("  ]\n");

    out.push_str("}\n");
    print!("{}", out);
    Ok(())
}

fn output_report_pretty(
    conn: &Connection,
    filter: &ReportFilter,
    top: usize,
    has_sessions: bool,
    color: bool,
) -> Result<(), String> {
    // Title
    println!("\n{}", if color { "\x1b[1mrano report\x1b[0m" } else { "rano report" });
    println!("{}", "=".repeat(60));

    // Time range (if provided)
    if filter.since.is_some() || filter.until.is_some() {
        let now_display = now_rfc3339();
        let since = filter.since.as_deref().unwrap_or("beginning");
        let until = filter.until.as_deref().unwrap_or(&now_display);
        println!("\n{}", if color { "\x1b[1;36mRange\x1b[0m" } else { "Range" });
        println!("  {} .. {}", since, until);
    }

    // Session info
    if has_sessions {
        if let Some(ref run_id) = filter.run_id {
            if let Some(session) = query_session(conn, run_id)? {
                println!("\n{}", if color { "\x1b[1;36mSession\x1b[0m" } else { "Session" });
                println!("  Run ID:   {}", session.run_id);
                println!("  Started:  {}", session.start_ts);
                if let Some(end) = &session.end_ts {
                    println!("  Ended:    {}", end);
                    // Calculate and display duration
                    if let Some(duration) = format_session_duration(&session.start_ts, end) {
                        println!("  Duration: {}", duration);
                    }
                }
                if let Some(host) = &session.host {
                    println!("  Host:     {}", host);
                }
                if let Some(user) = &session.user {
                    println!("  User:     {}", user);
                }
                if let Some(patterns) = &session.patterns {
                    println!("  Patterns: {}", patterns);
                }
            }
        }
    }

    // Summary
    let summary = query_summary(conn, filter)?;
    println!("\n{}", if color { "\x1b[1;36mSummary\x1b[0m" } else { "Summary" });
    println!("  Events:  {} total ({} connects, {} closes)",
             summary.total_events, summary.connects, summary.closes);
    println!("  Active:  {} connections", summary.connects.saturating_sub(summary.closes));

    // Providers
    let providers = query_providers(conn, filter)?;
    if !providers.is_empty() {
        println!("\n{}", if color { "\x1b[1;36mProviders\x1b[0m" } else { "Providers" });
        let provider_width = providers
            .iter()
            .map(|p| p.provider.len())
            .max()
            .unwrap_or(8)
            .max("Provider".len());
        let events_width = providers
            .iter()
            .map(|p| p.events.to_string().len())
            .max()
            .unwrap_or(6)
            .max("Events".len());
        let connects_width = providers
            .iter()
            .map(|p| p.connects.to_string().len())
            .max()
            .unwrap_or(8)
            .max("Connects".len());
        let closes_width = providers
            .iter()
            .map(|p| p.closes.to_string().len())
            .max()
            .unwrap_or(6)
            .max("Closes".len());

        println!(
            "  {:<provider_width$}  {:>events_width$}  {:>connects_width$}  {:>closes_width$}",
            "Provider",
            "Events",
            "Connects",
            "Closes",
            provider_width = provider_width,
            events_width = events_width,
            connects_width = connects_width,
            closes_width = closes_width
        );
        println!(
            "  {}  {}  {}  {}",
            "-".repeat(provider_width),
            "-".repeat(events_width),
            "-".repeat(connects_width),
            "-".repeat(closes_width)
        );
        for p in &providers {
            let label = provider_label(&p.provider, color);
            let label = pad_right(&label, provider_width, p.provider.len());
            println!(
                "  {}  {:>events_width$}  {:>connects_width$}  {:>closes_width$}",
                label,
                p.events,
                p.connects,
                p.closes,
                events_width = events_width,
                connects_width = connects_width,
                closes_width = closes_width
            );
        }
    }

    // Top Domains
    let domains = query_top_domains(conn, filter, top)?;
    if !domains.is_empty() {
        println!("\n{}", if color { "\x1b[1;36mTop Domains\x1b[0m" } else { "Top Domains" });
        let provider_width = domains
            .iter()
            .map(|d| d.provider.len())
            .max()
            .unwrap_or(8)
            .max("Provider".len());
        let events_width = domains
            .iter()
            .map(|d| d.events.to_string().len())
            .max()
            .unwrap_or(6)
            .max("Events".len());
        let domain_width = 48usize;
        println!(
            "  {:>2}  {:<domain_width$}  {:>events_width$}  {:<provider_width$}",
            "#",
            "Domain",
            "Events",
            "Provider",
            domain_width = domain_width,
            events_width = events_width,
            provider_width = provider_width
        );
        println!(
            "  {}  {}  {}  {}",
            "-".repeat(2),
            "-".repeat(domain_width),
            "-".repeat(events_width),
            "-".repeat(provider_width)
        );
        for (i, d) in domains.iter().enumerate() {
            let domain = truncate_ascii(&d.domain, domain_width);
            let provider = provider_label(&d.provider, color);
            let provider = pad_right(&provider, provider_width, d.provider.len());
            println!(
                "  {:>2}  {:<domain_width$}  {:>events_width$}  {}",
                i + 1,
                domain,
                d.events,
                provider,
                domain_width = domain_width,
                events_width = events_width
            );
        }
    }

    // Top IPs
    let ips = query_top_ips(conn, filter, top)?;
    if !ips.is_empty() {
        println!("\n{}", if color { "\x1b[1;36mTop IPs\x1b[0m" } else { "Top IPs" });
        let events_width = ips
            .iter()
            .map(|ip| ip.events.to_string().len())
            .max()
            .unwrap_or(6)
            .max("Events".len());
        let ip_width = 39usize;
        let domain_width = 32usize;
        println!(
            "  {:>2}  {:<ip_width$}  {:>events_width$}  {:<domain_width$}",
            "#",
            "IP",
            "Events",
            "Domain",
            ip_width = ip_width,
            events_width = events_width,
            domain_width = domain_width
        );
        println!(
            "  {}  {}  {}  {}",
            "-".repeat(2),
            "-".repeat(ip_width),
            "-".repeat(events_width),
            "-".repeat(domain_width)
        );
        for (i, ip) in ips.iter().enumerate() {
            let domain = ip.domain.as_deref().unwrap_or("unknown");
            let domain = truncate_ascii(domain, domain_width);
            let ip_value = truncate_ascii(&ip.ip, ip_width);
            println!(
                "  {:>2}  {:<ip_width$}  {:>events_width$}  {:<domain_width$}",
                i + 1,
                ip_value,
                ip.events,
                domain,
                ip_width = ip_width,
                events_width = events_width,
                domain_width = domain_width
            );
        }
    }

    println!();
    Ok(())
}

fn provider_label(provider: &str, color: bool) -> String {
    if !color {
        return provider.to_string();
    }
    match provider {
        "anthropic" => format!("\x1b[35m{}\x1b[0m", provider),
        "openai" => format!("\x1b[92m{}\x1b[0m", provider),
        "google" => format!("\x1b[94m{}\x1b[0m", provider),
        _ => format!("\x1b[90m{}\x1b[0m", provider),
    }
}

fn pad_right(value: &str, width: usize, visible_len: usize) -> String {
    if width <= visible_len {
        return value.to_string();
    }
    let mut out = String::with_capacity(value.len() + (width - visible_len));
    out.push_str(value);
    out.push_str(&" ".repeat(width - visible_len));
    out
}

fn truncate_ascii(value: &str, max: usize) -> String {
    if value.len() <= max {
        return value.to_string();
    }
    if max <= 3 {
        return value.chars().take(max).collect();
    }
    let head = max - 3;
    let mut out = String::with_capacity(max);
    out.push_str(&value[..head]);
    out.push_str("...");
    out
}

/// Calculate duration between two RFC3339 timestamps and format as human-readable
fn format_session_duration(start: &str, end: &str) -> Option<String> {
    let start_secs = parse_rfc3339_secs(start)?;
    let end_secs = parse_rfc3339_secs(end)?;
    if end_secs < start_secs {
        return None;
    }
    let diff = end_secs - start_secs;
    Some(format_duration_human(diff))
}

/// Parse RFC3339 timestamp to Unix seconds (simplified)
fn parse_rfc3339_secs(ts: &str) -> Option<u64> {
    // Format: 2026-01-17T12:34:56Z or 2026-01-17T12:34:56.123Z
    if ts.len() < 19 {
        return None;
    }
    let year: i32 = ts.get(0..4)?.parse().ok()?;
    let month: u32 = ts.get(5..7)?.parse().ok()?;
    let day: u32 = ts.get(8..10)?.parse().ok()?;
    let hour: u32 = ts.get(11..13)?.parse().ok()?;
    let min: u32 = ts.get(14..16)?.parse().ok()?;
    let sec: u32 = ts.get(17..19)?.parse().ok()?;

    // Days since epoch using a simplified Gregorian calculation
    let y = if month <= 2 { year - 1 } else { year } as i64;
    let m = if month <= 2 { month + 12 } else { month } as i64;
    let d = day as i64;
    let days = 365 * y + y / 4 - y / 100 + y / 400 + (153 * (m - 3) + 2) / 5 + d - 719528;

    Some((days as u64) * 86400 + (hour as u64) * 3600 + (min as u64) * 60 + (sec as u64))
}

/// Format seconds into human-readable duration (e.g., "1h 25m 4s")
fn format_duration_human(secs: u64) -> String {
    if secs < 60 {
        return format!("{}s", secs);
    }
    let hours = secs / 3600;
    let mins = (secs % 3600) / 60;
    let s = secs % 60;
    if hours > 0 {
        if s > 0 {
            format!("{}h {}m {}s", hours, mins, s)
        } else if mins > 0 {
            format!("{}h {}m", hours, mins)
        } else {
            format!("{}h", hours)
        }
    } else if s > 0 {
        format!("{}m {}s", mins, s)
    } else {
        format!("{}m", mins)
    }
}

// Report query helper structs
struct SessionInfo {
    run_id: String,
    start_ts: String,
    end_ts: Option<String>,
    host: Option<String>,
    user: Option<String>,
    patterns: Option<String>,
    connects: Option<i64>,
    closes: Option<i64>,
}

struct SummaryStats {
    total_events: i64,
    connects: i64,
    closes: i64,
}

struct ProviderStats {
    provider: String,
    events: i64,
    connects: i64,
    closes: i64,
}

struct DomainStats {
    domain: String,
    events: i64,
    provider: String,
}

struct IpStats {
    ip: String,
    events: i64,
    domain: Option<String>,
}

fn query_session(conn: &Connection, run_id: &str) -> Result<Option<SessionInfo>, String> {
    let sql = "SELECT run_id, start_ts, end_ts, host, user, patterns, connects, closes
               FROM sessions WHERE run_id = ?";
    match conn.query_row(sql, [run_id], |row| {
        Ok(SessionInfo {
            run_id: row.get(0)?,
            start_ts: row.get(1)?,
            end_ts: row.get(2).ok(),
            host: row.get(3).ok(),
            user: row.get(4).ok(),
            patterns: row.get(5).ok(),
            connects: row.get(6).ok(),
            closes: row.get(7).ok(),
        })
    }) {
        Ok(s) => Ok(Some(s)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(format!("Failed to query session: {}", e)),
    }
}

fn query_summary(conn: &Connection, filter: &ReportFilter) -> Result<SummaryStats, String> {
    let (sql, params) = build_summary_query(filter);
    let params_refs: Vec<&dyn rusqlite::ToSql> = params.iter().map(|s| s as &dyn rusqlite::ToSql).collect();

    conn.query_row(&sql, params_refs.as_slice(), |row| {
        Ok(SummaryStats {
            total_events: row.get(0)?,
            connects: row.get(1)?,
            closes: row.get(2)?,
        })
    }).map_err(|e| format!("Failed to query summary: {}", e))
}

fn build_summary_query(filter: &ReportFilter) -> (String, Vec<String>) {
    let mut sql = String::from(
        "SELECT COUNT(*) as total,
                COALESCE(SUM(CASE WHEN event='connect' THEN 1 ELSE 0 END), 0) as connects,
                COALESCE(SUM(CASE WHEN event='close' THEN 1 ELSE 0 END), 0) as closes
         FROM events WHERE 1=1"
    );
    let mut params: Vec<String> = Vec::new();

    if let Some(ref run_id) = filter.run_id {
        sql.push_str(" AND run_id = ?");
        params.push(run_id.clone());
    }
    if let Some(ref since) = filter.since {
        sql.push_str(" AND ts >= ?");
        params.push(since.clone());
    }
    if let Some(ref until) = filter.until {
        sql.push_str(" AND ts < ?");
        params.push(until.clone());
    }

    (sql, params)
}

fn query_providers(conn: &Connection, filter: &ReportFilter) -> Result<Vec<ProviderStats>, String> {
    let (sql, params) = build_providers_query(filter);
    let params_refs: Vec<&dyn rusqlite::ToSql> = params.iter().map(|s| s as &dyn rusqlite::ToSql).collect();

    let mut stmt = conn.prepare(&sql)
        .map_err(|e| format!("Failed to prepare query: {}", e))?;

    let rows = stmt.query_map(params_refs.as_slice(), |row| {
        Ok(ProviderStats {
            provider: row.get(0)?,
            events: row.get(1)?,
            connects: row.get(2)?,
            closes: row.get(3)?,
        })
    }).map_err(|e| format!("Failed to query providers: {}", e))?;

    let mut results = Vec::new();
    for row in rows {
        results.push(row.map_err(|e| format!("Failed to read row: {}", e))?);
    }
    Ok(results)
}

fn build_providers_query(filter: &ReportFilter) -> (String, Vec<String>) {
    let mut sql = String::from(
        "SELECT provider,
                COUNT(*) as events,
                SUM(CASE WHEN event='connect' THEN 1 ELSE 0 END) as connects,
                SUM(CASE WHEN event='close' THEN 1 ELSE 0 END) as closes
         FROM events WHERE 1=1"
    );
    let mut params: Vec<String> = Vec::new();

    if let Some(ref run_id) = filter.run_id {
        sql.push_str(" AND run_id = ?");
        params.push(run_id.clone());
    }
    if let Some(ref since) = filter.since {
        sql.push_str(" AND ts >= ?");
        params.push(since.clone());
    }
    if let Some(ref until) = filter.until {
        sql.push_str(" AND ts < ?");
        params.push(until.clone());
    }

    sql.push_str(" GROUP BY provider ORDER BY events DESC");
    (sql, params)
}

fn query_top_domains(conn: &Connection, filter: &ReportFilter, top: usize) -> Result<Vec<DomainStats>, String> {
    let (sql, params) = build_domains_query(filter, top);
    let params_refs: Vec<&dyn rusqlite::ToSql> = params.iter().map(|s| s as &dyn rusqlite::ToSql).collect();

    let mut stmt = conn.prepare(&sql)
        .map_err(|e| format!("Failed to prepare query: {}", e))?;

    let rows = stmt.query_map(params_refs.as_slice(), |row| {
        Ok(DomainStats {
            domain: row.get(0)?,
            events: row.get(1)?,
            provider: row.get(2)?,
        })
    }).map_err(|e| format!("Failed to query domains: {}", e))?;

    let mut results = Vec::new();
    for row in rows {
        results.push(row.map_err(|e| format!("Failed to read row: {}", e))?);
    }
    Ok(results)
}

fn build_domains_query(filter: &ReportFilter, top: usize) -> (String, Vec<String>) {
    let mut sql = String::from(
        "SELECT COALESCE(domain, 'unknown') as domain,
                COUNT(*) as events,
                provider
         FROM events WHERE domain IS NOT NULL AND domain != ''"
    );
    let mut params: Vec<String> = Vec::new();

    if let Some(ref run_id) = filter.run_id {
        sql.push_str(" AND run_id = ?");
        params.push(run_id.clone());
    }
    if let Some(ref since) = filter.since {
        sql.push_str(" AND ts >= ?");
        params.push(since.clone());
    }
    if let Some(ref until) = filter.until {
        sql.push_str(" AND ts < ?");
        params.push(until.clone());
    }

    sql.push_str(&format!(" GROUP BY domain, provider ORDER BY events DESC LIMIT {}", top));
    (sql, params)
}

fn query_top_ips(conn: &Connection, filter: &ReportFilter, top: usize) -> Result<Vec<IpStats>, String> {
    let (sql, params) = build_ips_query(filter, top);
    let params_refs: Vec<&dyn rusqlite::ToSql> = params.iter().map(|s| s as &dyn rusqlite::ToSql).collect();

    let mut stmt = conn.prepare(&sql)
        .map_err(|e| format!("Failed to prepare query: {}", e))?;

    let rows = stmt.query_map(params_refs.as_slice(), |row| {
        Ok(IpStats {
            ip: row.get(0)?,
            events: row.get(1)?,
            domain: row.get(2).ok(),
        })
    }).map_err(|e| format!("Failed to query IPs: {}", e))?;

    let mut results = Vec::new();
    for row in rows {
        results.push(row.map_err(|e| format!("Failed to read row: {}", e))?);
    }
    Ok(results)
}

fn build_ips_query(filter: &ReportFilter, top: usize) -> (String, Vec<String>) {
    let mut sql = String::from(
        "SELECT remote_ip,
                COUNT(*) as events,
                domain
         FROM events WHERE remote_ip IS NOT NULL"
    );
    let mut params: Vec<String> = Vec::new();

    if let Some(ref run_id) = filter.run_id {
        sql.push_str(" AND run_id = ?");
        params.push(run_id.clone());
    }
    if let Some(ref since) = filter.since {
        sql.push_str(" AND ts >= ?");
        params.push(since.clone());
    }
    if let Some(ref until) = filter.until {
        sql.push_str(" AND ts < ?");
        params.push(until.clone());
    }

    sql.push_str(&format!(" GROUP BY remote_ip ORDER BY events DESC LIMIT {}", top));
    (sql, params)
}

fn init_sqlite(conn: &mut Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "
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
        CREATE VIEW IF NOT EXISTS provider_counts AS
            SELECT provider,
                   COUNT(*) AS events,
                   SUM(CASE WHEN event='connect' THEN 1 ELSE 0 END) AS connects,
                   SUM(CASE WHEN event='close' THEN 1 ELSE 0 END) AS closes
            FROM events GROUP BY provider;
        CREATE VIEW IF NOT EXISTS provider_domains AS
            SELECT provider, domain, COUNT(*) AS events
            FROM events WHERE domain IS NOT NULL AND domain != 'unknown'
            GROUP BY provider, domain;
        CREATE VIEW IF NOT EXISTS provider_ips AS
            SELECT provider, remote_ip, COUNT(*) AS events
            FROM events GROUP BY provider, remote_ip;
        CREATE VIEW IF NOT EXISTS provider_ports AS
            SELECT provider, remote_port, COUNT(*) AS events
            FROM events GROUP BY provider, remote_port;
        CREATE VIEW IF NOT EXISTS provider_processes AS
            SELECT provider, comm, COUNT(*) AS events
            FROM events GROUP BY provider, comm;
        CREATE VIEW IF NOT EXISTS provider_last_hour AS
            SELECT provider, COUNT(*) AS events
            FROM events
            WHERE ts >= datetime('now','-1 hour')
            GROUP BY provider;
        CREATE VIEW IF NOT EXISTS provider_hourly AS
            SELECT provider,
                   strftime('%Y-%m-%dT%H:00:00Z', ts) AS hour,
                   COUNT(*) AS events
            FROM events
            GROUP BY provider, hour;
        CREATE VIEW IF NOT EXISTS session_summary AS
            SELECT s.run_id,
                   s.start_ts,
                   s.end_ts,
                   s.patterns,
                   s.domain_mode,
                   COUNT(e.id) AS events,
                   SUM(CASE WHEN e.event='connect' THEN 1 ELSE 0 END) AS connects,
                   SUM(CASE WHEN e.event='close' THEN 1 ELSE 0 END) AS closes
            FROM sessions s LEFT JOIN events e ON e.run_id = s.run_id
            GROUP BY s.run_id;
        ",
    )?;
    ensure_column(conn, "events", "run_id", "TEXT")?;
    ensure_column(conn, "events", "duration_ms", "INTEGER")?;
    Ok(())
}

fn insert_session(conn: &mut Connection, ctx: &RunContext) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO sessions (run_id, start_ts, host, user, patterns, domain_mode, args, interval_ms, stats_interval_ms)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            &ctx.run_id,
            &ctx.start_ts,
            &ctx.host,
            &ctx.user,
            &ctx.patterns,
            &ctx.domain_label,
            &ctx.args_snapshot,
            ctx.interval_ms as i64,
            ctx.stats_interval_ms as i64,
        ],
    )?;
    Ok(())
}

fn finalize_session(conn: &mut Connection, run_id: &str, connects: u64, closes: u64) -> rusqlite::Result<()> {
    let end_ts = now_rfc3339();
    conn.execute(
        "UPDATE sessions SET end_ts = ?1, connects = ?2, closes = ?3 WHERE run_id = ?4",
        params![end_ts, connects as i64, closes as i64, run_id],
    )?;
    Ok(())
}

fn ensure_column(
    conn: &mut Connection,
    table: &str,
    column: &str,
    col_type: &str,
) -> rusqlite::Result<()> {
    let pragma = format!("PRAGMA table_info({})", table);
    let mut stmt = conn.prepare(&pragma)?;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        let name: String = row.get(1)?;
        if name == column {
            return Ok(());
        }
    }
    let sql = format!("ALTER TABLE {} ADD COLUMN {} {}", table, column, col_type);
    conn.execute(&sql, [])?;
    Ok(())
}

fn log_sqlite_event(conn: &mut Connection, event: &SqliteEvent) -> rusqlite::Result<()> {
    let proto = match event.key.proto {
        Proto::Tcp => "tcp",
        Proto::Udp => "udp",
    };
    let (is_private, ip_version) = ip_flags(event.key.remote_ip);
    conn.execute(
        "INSERT INTO events (ts, run_id, event, provider, pid, comm, cmdline, proto, local_ip, local_port, remote_ip, remote_port, domain, remote_is_private, ip_version, duration_ms)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
        params![
            &event.ts,
            &event.run_id,
            &event.event,
            event.provider.label(),
            event.pid,
            &event.comm,
            &event.cmdline,
            proto,
            event.key.local_ip.to_string(),
            event.key.local_port as i64,
            event.key.remote_ip.to_string(),
            event.key.remote_port as i64,
            event.domain.as_deref().unwrap_or("unknown"),
            if is_private { 1 } else { 0 },
            ip_version,
            event.duration_ms.map(|v| v as i64),
        ],
    )?;
    Ok(())
}

fn ip_flags(ip: IpAddr) -> (bool, i64) {
    match ip {
        IpAddr::V4(v4) => (v4.is_private(), 4),
        IpAddr::V6(v6) => (v6.is_unique_local(), 6),
    }
}

fn push_json_str(out: &mut String, key: &str, value: &str, first: bool) {
    if !first {
        out.push(',');
    }
    out.push('"');
    out.push_str(key);
    out.push_str("\":\"");
    out.push_str(&escape_json(value));
    out.push('"');
}

fn push_json_num(out: &mut String, key: &str, value: i64, first: bool) {
    if !first {
        out.push(',');
    }
    out.push('"');
    out.push_str(key);
    out.push_str("\":");
    out.push_str(&value.to_string());
}

fn push_json_map_str(out: &mut String, key: &str, map: &BTreeMap<String, u64>, first: bool) {
    if !first {
        out.push(',');
    }
    out.push('"');
    out.push_str(key);
    out.push_str("\":{");
    let mut first_entry = true;
    for (k, v) in map.iter() {
        if !first_entry {
            out.push(',');
        }
        first_entry = false;
        out.push('"');
        out.push_str(&escape_json(k));
        out.push_str("\":");
        out.push_str(&v.to_string());
    }
    out.push('}');
}

fn push_json_map_ip(out: &mut String, key: &str, map: &BTreeMap<IpAddr, u64>, first: bool) {
    if !first {
        out.push(',');
    }
    out.push('"');
    out.push_str(key);
    out.push_str("\":{");
    let mut first_entry = true;
    for (k, v) in map.iter() {
        if !first_entry {
            out.push(',');
        }
        first_entry = false;
        out.push('"');
        out.push_str(&escape_json(&k.to_string()));
        out.push_str("\":");
        out.push_str(&v.to_string());
    }
    out.push('}');
}

fn push_json_map_u32(out: &mut String, key: &str, map: &BTreeMap<u32, u64>, first: bool) {
    if !first {
        out.push(',');
    }
    out.push('"');
    out.push_str(key);
    out.push_str("\":{");
    let mut first_entry = true;
    for (k, v) in map.iter() {
        if !first_entry {
            out.push(',');
        }
        first_entry = false;
        out.push('"');
        out.push_str(&k.to_string());
        out.push_str("\":");
        out.push_str(&v.to_string());
    }
    out.push('}');
}

fn push_json_map_provider(out: &mut String, key: &str, map: &BTreeMap<Provider, u64>, first: bool) {
    if !first {
        out.push(',');
    }
    out.push('"');
    out.push_str(key);
    out.push_str("\":{");
    let mut first_entry = true;
    for (k, v) in map.iter() {
        if !first_entry {
            out.push(',');
        }
        first_entry = false;
        out.push('"');
        out.push_str(k.label());
        out.push_str("\":");
        out.push_str(&v.to_string());
    }
    out.push('}');
}

fn escape_json(input: &str) -> String {
    let mut out = String::with_capacity(input.len() + 2);
    for ch in input.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_patterns_lowercases_and_dedupes() {
        let patterns = vec![
            " Claude ".to_string(),
            "claude".to_string(),
            "OpenAI".to_string(),
            "".to_string(),
        ];
        let normalized = normalize_patterns(patterns);
        assert_eq!(normalized, vec!["claude".to_string(), "openai".to_string()]);
    }

    #[test]
    fn merge_mode_extends_defaults() {
        let config = ProvidersConfig {
            mode: Some("merge".to_string()),
            anthropic: Some(vec!["custom".to_string()]),
            openai: None,
            google: None,
        };
        let mut matcher = ProviderMatcher::default();
        apply_provider_config(&mut matcher, config).expect("config should apply");
        assert!(matcher.anthropic.contains(&"claude".to_string()));
        assert!(matcher.anthropic.contains(&"custom".to_string()));
        assert!(matcher.openai.contains(&"codex".to_string()));
    }

    #[test]
    fn replace_mode_overrides_defaults() {
        let config = ProvidersConfig {
            mode: Some("replace".to_string()),
            anthropic: Some(vec!["only".to_string()]),
            openai: None,
            google: None,
        };
        let mut matcher = ProviderMatcher::default();
        apply_provider_config(&mut matcher, config).expect("config should apply");
        assert_eq!(matcher.anthropic, vec!["only".to_string()]);
        assert!(matcher.openai.is_empty());
        assert!(matcher.google.is_empty());
    }

    #[test]
    fn provider_matcher_uses_custom_patterns() {
        let matcher = ProviderMatcher {
            anthropic: vec!["alpha".to_string()],
            openai: vec!["beta".to_string()],
            google: vec!["gamma".to_string()],
        };
        assert_eq!(
            provider_from_text("beta-runner", "", &matcher),
            Provider::OpenAI
        );
    }

    #[test]
    fn merge_mode_preserves_unspecified_providers() {
        // When merging, providers not mentioned in config should keep defaults
        let config = ProvidersConfig {
            mode: Some("merge".to_string()),
            anthropic: Some(vec!["acme-claude".to_string()]),
            openai: None,  // Should keep default "codex", "openai"
            google: None,  // Should keep default "gemini", "google"
        };
        let mut matcher = ProviderMatcher::default();
        apply_provider_config(&mut matcher, config).expect("config should apply");
        // anthropic should have both default + custom
        assert!(matcher.anthropic.contains(&"claude".to_string()));
        assert!(matcher.anthropic.contains(&"acme-claude".to_string()));
        // openai and google should have defaults
        assert!(matcher.openai.contains(&"codex".to_string()));
        assert!(matcher.google.contains(&"gemini".to_string()));
    }

    #[test]
    fn invalid_mode_returns_error() {
        let config = ProvidersConfig {
            mode: Some("invalid".to_string()),
            anthropic: None,
            openai: None,
            google: None,
        };
        let mut matcher = ProviderMatcher::default();
        let result = apply_provider_config(&mut matcher, config);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("Invalid providers.mode"));
    }

    #[test]
    fn empty_patterns_are_filtered_out() {
        let config = ProvidersConfig {
            mode: Some("replace".to_string()),
            anthropic: Some(vec!["valid".to_string(), "".to_string(), "  ".to_string()]),
            openai: None,
            google: None,
        };
        let mut matcher = ProviderMatcher::default();
        apply_provider_config(&mut matcher, config).expect("config should apply");
        assert_eq!(matcher.anthropic, vec!["valid".to_string()]);
    }

    #[test]
    fn provider_from_text_returns_unknown_for_no_match() {
        let matcher = ProviderMatcher::default();
        assert_eq!(
            provider_from_text("random-process", "/usr/bin/random", &matcher),
            Provider::Unknown
        );
    }

    #[test]
    fn provider_from_text_matches_case_insensitive() {
        let matcher = ProviderMatcher::default();
        assert_eq!(
            provider_from_text("CLAUDE", "/usr/bin/CLAUDE", &matcher),
            Provider::Anthropic
        );
        assert_eq!(
            provider_from_text("Codex", "/usr/bin/Codex", &matcher),
            Provider::OpenAI
        );
    }

    #[test]
    fn build_summary_query_includes_filters() {
        let filter = ReportFilter {
            run_id: Some("run-1".to_string()),
            since: Some("2026-01-01T00:00:00Z".to_string()),
            until: Some("2026-01-02T00:00:00Z".to_string()),
        };
        let (sql, params) = build_summary_query(&filter);
        assert!(sql.contains("run_id = ?"));
        assert!(sql.contains("ts >= ?"));
        assert!(sql.contains("ts < ?"));
        assert_eq!(
            params,
            vec![
                "run-1".to_string(),
                "2026-01-01T00:00:00Z".to_string(),
                "2026-01-02T00:00:00Z".to_string()
            ]
        );
    }

    #[test]
    fn build_domains_query_limits_and_filters() {
        let filter = ReportFilter {
            run_id: Some("run-2".to_string()),
            since: None,
            until: None,
        };
        let (sql, params) = build_domains_query(&filter, 5);
        assert!(sql.contains("run_id = ?"));
        assert!(sql.contains("LIMIT 5"));
        assert_eq!(params, vec!["run-2".to_string()]);
    }

    #[test]
    fn parse_time_filter_accepts_rfc3339_and_date() {
        let rfc = Some("2026-01-17T12:00:00Z".to_string());
        let parsed = parse_time_filter(&rfc).expect("rfc3339 should parse");
        assert_eq!(parsed, Some("2026-01-17T12:00:00Z".to_string()));

        let date = Some("2026-01-17".to_string());
        let parsed = parse_time_filter(&date).expect("date should parse");
        assert_eq!(parsed, Some("2026-01-17T00:00:00Z".to_string()));
    }

    #[test]
    fn parse_time_filter_accepts_relative() {
        let rel = Some("1h".to_string());
        let parsed = parse_time_filter(&rel).expect("relative should parse");
        let value = parsed.expect("relative should return value");
        assert!(value.contains('T'));
        assert!(value.ends_with('Z'));
    }

    #[test]
    fn parse_time_filter_rejects_invalid() {
        let invalid = Some("oops".to_string());
        assert!(parse_time_filter(&invalid).is_err());
    }

    // Batching unit tests

    fn create_test_event(ts: &str, event: &str, provider: Provider) -> SqliteEvent {
        SqliteEvent {
            ts: ts.to_string(),
            run_id: "test-run".to_string(),
            event: event.to_string(),
            key: ConnKey {
                proto: Proto::Tcp,
                local_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
                local_port: 12345,
                remote_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(8, 8, 8, 8)),
                remote_port: 443,
            },
            pid: 1234,
            comm: "testproc".to_string(),
            cmdline: "/usr/bin/testproc".to_string(),
            provider,
            domain: Some("test.example.com".to_string()),
            duration_ms: if event == "close" { Some(1000) } else { None },
        }
    }

    fn setup_test_db() -> Connection {
        let mut conn = Connection::open_in_memory().expect("failed to open in-memory db");
        init_sqlite(&mut conn).expect("failed to init schema");
        conn
    }

    #[test]
    fn write_sqlite_batch_handles_empty() {
        let mut conn = setup_test_db();
        let batch: Vec<SqliteEvent> = vec![];
        let result = write_sqlite_batch(&mut conn, &batch);
        assert!(result.is_ok());
    }

    #[test]
    fn write_sqlite_batch_writes_single_event() {
        let mut conn = setup_test_db();
        let event = create_test_event("2026-01-20T12:00:00Z", "connect", Provider::Anthropic);
        let batch = vec![event];

        let result = write_sqlite_batch(&mut conn, &batch);
        assert!(result.is_ok());

        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))
            .expect("count query failed");
        assert_eq!(count, 1);
    }

    #[test]
    fn write_sqlite_batch_writes_multiple_events() {
        let mut conn = setup_test_db();
        let batch = vec![
            create_test_event("2026-01-20T12:00:00Z", "connect", Provider::Anthropic),
            create_test_event("2026-01-20T12:00:01Z", "connect", Provider::OpenAI),
            create_test_event("2026-01-20T12:00:02Z", "connect", Provider::Google),
            create_test_event("2026-01-20T12:00:03Z", "close", Provider::Anthropic),
        ];

        let result = write_sqlite_batch(&mut conn, &batch);
        assert!(result.is_ok());

        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))
            .expect("count query failed");
        assert_eq!(count, 4);

        // Verify providers
        let providers: Vec<String> = {
            let mut stmt = conn.prepare("SELECT DISTINCT provider FROM events ORDER BY provider").unwrap();
            stmt.query_map([], |row| row.get(0))
                .unwrap()
                .filter_map(|r| r.ok())
                .collect()
        };
        assert_eq!(providers, vec!["anthropic", "google", "openai"]);
    }

    #[test]
    fn write_sqlite_batch_preserves_event_data() {
        let mut conn = setup_test_db();
        let event = create_test_event("2026-01-20T12:00:00Z", "connect", Provider::Unknown);
        let batch = vec![event];

        write_sqlite_batch(&mut conn, &batch).expect("batch write failed");

        let (ts, event_type, provider, pid, domain): (String, String, String, i64, String) = conn
            .query_row(
                "SELECT ts, event, provider, pid, domain FROM events LIMIT 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
            )
            .expect("query failed");

        assert_eq!(ts, "2026-01-20T12:00:00Z");
        assert_eq!(event_type, "connect");
        assert_eq!(provider, "unknown");
        assert_eq!(pid, 1234);
        assert_eq!(domain, "test.example.com");
    }

    #[test]
    fn write_sqlite_batch_stores_duration_for_close() {
        let mut conn = setup_test_db();
        let event = create_test_event("2026-01-20T12:00:00Z", "close", Provider::Anthropic);
        let batch = vec![event];

        write_sqlite_batch(&mut conn, &batch).expect("batch write failed");

        let duration: Option<i64> = conn
            .query_row("SELECT duration_ms FROM events LIMIT 1", [], |row| row.get(0))
            .expect("query failed");

        assert_eq!(duration, Some(1000));
    }

    #[test]
    fn write_sqlite_batch_multiple_calls_accumulate() {
        let mut conn = setup_test_db();

        // First batch
        let batch1 = vec![
            create_test_event("2026-01-20T12:00:00Z", "connect", Provider::Anthropic),
        ];
        write_sqlite_batch(&mut conn, &batch1).expect("batch1 write failed");

        // Second batch
        let batch2 = vec![
            create_test_event("2026-01-20T12:00:01Z", "connect", Provider::OpenAI),
            create_test_event("2026-01-20T12:00:02Z", "close", Provider::Anthropic),
        ];
        write_sqlite_batch(&mut conn, &batch2).expect("batch2 write failed");

        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))
            .expect("count query failed");
        assert_eq!(count, 3);
    }

    #[test]
    fn write_sqlite_batch_run_id_consistency() {
        let mut conn = setup_test_db();
        let batch = vec![
            create_test_event("2026-01-20T12:00:00Z", "connect", Provider::Anthropic),
            create_test_event("2026-01-20T12:00:01Z", "connect", Provider::OpenAI),
        ];

        write_sqlite_batch(&mut conn, &batch).expect("batch write failed");

        let distinct_run_ids: i64 = conn
            .query_row("SELECT COUNT(DISTINCT run_id) FROM events", [], |row| row.get(0))
            .expect("count query failed");
        assert_eq!(distinct_run_ids, 1);
    }
}
