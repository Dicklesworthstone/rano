// Allow clippy lints that require significant refactoring
#![allow(clippy::collapsible_if)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::large_enum_variant)]
#![allow(clippy::field_reassign_with_default)]
#![allow(clippy::map_entry)]
#![allow(clippy::unnecessary_lazy_evaluations)]
#![allow(clippy::while_let_loop)]
#![allow(clippy::manual_map)]
#![allow(clippy::needless_borrow)]

use rusqlite::{Connection, OptionalExtension, params};
use serde::Deserialize;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::env;
use std::ffi::CStr;
use std::fs::{self, OpenOptions};
use std::io::{self, BufRead, BufReader, BufWriter, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::process::Command as ProcessCommand;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

mod config_validation;
mod pcap_capture;

static RUNNING: AtomicBool = AtomicBool::new(true);

const SQLITE_QUEUE_CAPACITY: usize = 10_000;
const SQLITE_BATCH_SIZE: usize = 200;
const SQLITE_FLUSH_INTERVAL_MS: u64 = 1000;
const SQLITE_DROP_WARN_INTERVAL_SECS: u64 = 10;
const ANCESTRY_CACHE_TTL_SECS: u64 = 30;
const PTR_CACHE_MAX: usize = 1024;
const PTR_QUEUE_CAPACITY: usize = 64;
const PTR_WORKERS: usize = 2;
const PTR_TTL: Duration = Duration::from_secs(600);

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
    Colorblind,
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
    Export(ExportArgs),
    Config(ConfigArgs),
    Diff(DiffArgs),
    Status(StatusArgs),
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ConfigArgs {
    subcommand: ConfigSubcommand,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum ConfigSubcommand {
    Check { options: Vec<String> },
    Show { json: bool, options: Vec<String> },
    Paths,
}

#[derive(Clone, Debug)]
struct ConfigPaths {
    kv_path: Option<PathBuf>,
    toml_path: Option<PathBuf>,
    use_config: bool,
}

#[derive(Clone, Debug)]
struct ConfigSource {
    kind: &'static str,
    origin: String,
    keys: Vec<String>,
    provider_mode: Option<ProviderMode>,
}

struct ProviderResolution {
    matcher: ProviderMatcher,
    notes: Vec<String>,
    sources: Vec<ConfigSource>,
}

const PRESET_AUDIT: &str = "# Description: Security review / minimal noise\n\
summary_only=true\n\
stats_interval_ms=0\n\
include_udp=true\n\
no_dns=false\n\
log_format=json\n\
redact_cmdline=secrets\n";

const PRESET_QUIET: &str = "# Description: Reduce terminal output\n\
summary_only=true\n\
stats_interval_ms=0\n\
no_banner=true\n";

const PRESET_LIVE: &str = "# Description: Real-time monitoring focus\n\
stats_interval_ms=500\n\
stats_top=10\n\
stats_view=provider,domain\n\
stats_cycle_ms=5000\n";

const PRESET_VERBOSE: &str = "# Description: Maximum detail\n\
include_udp=true\n\
include_listening=true\n\
stats_interval_ms=1000\n\
stats_top=10\n";

enum PresetSource {
    Builtin,
    User(PathBuf),
}

struct PresetInfo {
    name: String,
    description: String,
    source: PresetSource,
}

struct PresetLoader {
    builtin_presets: HashMap<&'static str, &'static str>,
    user_preset_dirs: Vec<PathBuf>,
}

impl PresetLoader {
    fn new() -> Self {
        let mut builtin_presets = HashMap::new();
        builtin_presets.insert("audit", PRESET_AUDIT);
        builtin_presets.insert("quiet", PRESET_QUIET);
        builtin_presets.insert("live", PRESET_LIVE);
        builtin_presets.insert("verbose", PRESET_VERBOSE);

        let mut user_preset_dirs = Vec::new();
        if let Some(config_dir) = xdg_config_home() {
            user_preset_dirs.push(config_dir.join("rano/presets"));
        }

        Self {
            builtin_presets,
            user_preset_dirs,
        }
    }

    fn load_preset(&self, name: &str) -> Result<Vec<(String, String)>, String> {
        if name.is_empty()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        {
            return Err("Preset names must contain only letters, digits, '-' or '_'".to_string());
        }

        // Search user preset directories
        for dir in &self.user_preset_dirs {
            let path = dir.join(format!("{}.conf", name));
            if path.exists() {
                let content = fs::read_to_string(&path)
                    .map_err(|e| format!("Failed to read preset {}: {}", path.display(), e))?;
                return self.parse_preset_content(&content);
            }
        }

        if let Some(content) = self.builtin_presets.get(name) {
            return self.parse_preset_content(content);
        }

        // Preset not found - list available presets
        let available = self.list_preset_names();
        Err(format!(
            "Unknown preset '{}'. Available: {}",
            name,
            available.join(", ")
        ))
    }

    fn parse_preset_content(&self, content: &str) -> Result<Vec<(String, String)>, String> {
        let mut result = Vec::new();
        for (idx, line) in content.lines().enumerate() {
            let raw = line.split('#').next().unwrap_or("").trim();
            if raw.is_empty() {
                continue;
            }
            let mut parts = raw.splitn(2, '=');
            let key = parts.next().unwrap_or("").trim();
            let value = parts.next().unwrap_or("").trim();
            if key.is_empty() {
                return Err(format!("preset line {}: missing key", idx + 1));
            }
            if value.is_empty() {
                return Err(format!(
                    "preset line {}: missing value for '{}'",
                    idx + 1,
                    key
                ));
            }
            result.push((key.to_string(), value.to_string()));
        }
        Ok(result)
    }

    fn list_presets(&self) -> Vec<PresetInfo> {
        let mut presets = Vec::new();

        // Add built-in presets
        for (name, content) in &self.builtin_presets {
            let description = self.extract_description(content);
            presets.push(PresetInfo {
                name: name.to_string(),
                description,
                source: PresetSource::Builtin,
            });
        }

        // Add user presets
        for dir in &self.user_preset_dirs {
            if let Ok(entries) = fs::read_dir(dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.extension().is_some_and(|ext| ext == "conf") {
                        if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                            // Skip if this name is already a builtin (user overrides)
                            if self.builtin_presets.contains_key(stem) {
                                // Mark as user override
                                if let Some(preset) = presets.iter_mut().find(|p| p.name == stem) {
                                    preset.source = PresetSource::User(path.clone());
                                    if let Ok(content) = fs::read_to_string(&path) {
                                        preset.description = self.extract_description(&content);
                                    }
                                }
                                continue;
                            }
                            let description = if let Ok(content) = fs::read_to_string(&path) {
                                self.extract_description(&content)
                            } else {
                                String::from("(unable to read description)")
                            };
                            presets.push(PresetInfo {
                                name: stem.to_string(),
                                description,
                                source: PresetSource::User(path),
                            });
                        }
                    }
                }
            }
        }

        // Sort by name
        presets.sort_by(|a, b| a.name.cmp(&b.name));
        presets
    }

    fn list_preset_names(&self) -> Vec<String> {
        self.list_presets().into_iter().map(|p| p.name).collect()
    }

    fn extract_description(&self, content: &str) -> String {
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("# Description:") {
                return trimmed
                    .strip_prefix("# Description:")
                    .unwrap_or("")
                    .trim()
                    .to_string();
            }
        }
        String::new()
    }
}

fn apply_preset_values(values: &[(String, String)], args: &mut MonitorArgs) -> Result<(), String> {
    let mut seen = HashSet::new();
    for (key, value) in values {
        if seen.insert(key) {
            clear_config_list(key, args);
        }
        if !apply_config_value(key, value, args)? {
            args.warnings.push(format!("unknown key '{key}' in preset"));
        }
    }
    Ok(())
}

/// The typed setting parser used by runtime files, presets, CLI and validation.
/// Unknown keys are warnings at the source boundary; their values are not echoed.
fn apply_config_value(key: &str, value: &str, args: &mut MonitorArgs) -> Result<bool, String> {
    if key != "pcap_interface" && value.trim().is_empty() {
        return Err(format!("missing value for key '{key}'"));
    }
    if matches!(
        key,
        "pattern" | "exclude_pattern" | "alert_domain" | "stats_view"
    ) && value.split(',').all(|part| part.trim().is_empty())
    {
        return Err(format!("{key} must contain at least one value"));
    }
    let parsed: Result<bool, String> = (|| {
        match key {
            "pattern" => push_list_value(&mut args.patterns, value),
            "exclude_pattern" => push_list_value(&mut args.exclude_patterns, value),
            "pid" => {
                let pid = value
                    .parse::<u32>()
                    .map_err(|_| "pid must be a valid process ID (positive integer)".to_string())?;
                if pid == 0 {
                    return Err("pid must be >= 1".to_string());
                }
                args.pids.push(pid);
            }
            "no_descendants" => args.no_descendants = parse_bool(value)?,
            "interval_ms" => args.interval_ms = parse_u64(value, "interval_ms")?,
            "json" => args.json = parse_bool(value)?,
            "summary_only" => args.summary_only = parse_bool(value)?,
            "domain_mode" => {
                args.domain_mode = parse_domain_mode(value)?;
                args.pcap = false;
            }
            "pcap" => {
                args.pcap = parse_bool(value)?;
                if args.pcap {
                    args.domain_mode = DomainMode::Pcap;
                } else if args.domain_mode == DomainMode::Pcap {
                    args.domain_mode = DomainMode::Auto;
                }
            }
            "no_dns" => args.no_dns = parse_bool(value)?,
            "include_udp" => args.include_udp = parse_bool(value)?,
            "include_listening" => args.include_listening = parse_bool(value)?,
            "show_ancestry" => args.show_ancestry = parse_bool(value)?,
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
            "pcap_cache_max" => {
                let n = parse_usize(value, "pcap_cache_max")?;
                if n < PCAP_CACHE_MIN_ENTRIES {
                    return Err("pcap_cache_max (--pcap-cache-max) must be >= 100".to_string());
                }
                args.pcap_cache_max = Some(n);
            }
            "pcap_interface" => {
                set_pcap_interface(args, value, "pcap_interface / --pcap-interface")?
            }
            "stats_interval_ms" => args.stats_interval_ms = parse_u64(value, "stats_interval_ms")?,
            "stats_width" => {
                args.stats_width = parse_usize(value, "stats_width")?;
                args.stats_width_set = true;
            }
            "stats_top" => {
                args.stats_top = parse_usize(value, "stats_top")?;
                if args.stats_top == 0 {
                    return Err("stats_top must be >= 1".to_string());
                }
            }
            "stats_view" => {
                push_stats_views(&mut args.stats_views, value)?;
            }
            "stats_cycle_ms" => {
                args.stats_cycle_ms = parse_u64(value, "stats_cycle_ms")?;
            }
            "no_banner" => args.no_banner = parse_bool(value)?,
            "session_name" => args.session_name = Some(value.to_string()),
            "theme" => args.theme = parse_theme(value)?,
            "redact_cmdline" => args.redact_cmdline = parse_redact_mode(value)?,
            "alert_domain" => push_list_value(&mut args.alert.domain_patterns, value),
            "alert_max_connections" => {
                let n = parse_u64(value, "alert_max_connections")?;
                if n == 0 {
                    return Err("alert_max_connections must be >= 1".to_string());
                }
                args.alert.max_connections = Some(n);
            }
            "alert_max_per_provider" => {
                let n = parse_u64(value, "alert_max_per_provider")?;
                if n == 0 {
                    return Err("alert_max_per_provider must be >= 1".to_string());
                }
                args.alert.max_per_provider = Some(n);
            }
            "alert_duration_ms" => {
                let n = parse_u64(value, "alert_duration_ms")?;
                if n == 0 {
                    return Err("alert_duration_ms must be >= 1".to_string());
                }
                args.alert.duration_threshold_ms = Some(n);
            }
            "alert_unknown_domain" => args.alert.alert_unknown_domain = parse_bool(value)?,
            "alert_bell" => args.alert.bell = parse_bool(value)?,
            "alert_cooldown_ms" => args.alert.cooldown_ms = parse_u64(value, "alert_cooldown_ms")?,
            "no_alerts" => args.alert.no_alerts = parse_bool(value)?,
            "retry_threshold" => {
                let n = parse_usize(value, "retry_threshold")?;
                if n == 0 {
                    return Err("retry_threshold must be >= 1".to_string());
                }
                args.retry_threshold = n;
            }
            "retry_window_ms" => {
                let n = parse_u64(value, "retry_window_ms")?;
                if n == 0 {
                    return Err("retry_window_ms must be >= 1".to_string());
                }
                args.retry_window_ms = n;
            }
            _ => return Ok(false),
        }
        Ok(true)
    })();
    parsed.map_err(|error| format!("{key}: {error}"))
}

fn clear_config_list(key: &str, args: &mut MonitorArgs) {
    match key {
        "pattern" => args.patterns.clear(),
        "exclude_pattern" => args.exclude_patterns.clear(),
        "pid" => args.pids.clear(),
        "stats_view" => args.stats_views.clear(),
        "alert_domain" => args.alert.domain_patterns.clear(),
        _ => {}
    }
}

fn record_config_origin(key: &str, origin: &str, args: &mut MonitorArgs) {
    args.config_origins
        .insert(key.to_string(), origin.to_string());
    if matches!(key, "pcap" | "domain_mode") {
        args.config_origins
            .insert("pcap".to_string(), origin.to_string());
        args.config_origins
            .insert("domain_mode".to_string(), origin.to_string());
    }
}

fn print_presets_list(loader: &PresetLoader) {
    let presets = loader.list_presets();
    println!("Available presets:");
    println!();
    for preset in presets {
        let source_note = match preset.source {
            PresetSource::Builtin => String::new(),
            PresetSource::User(ref path) => format!(" (user: {})", path.display()),
        };
        let desc = if preset.description.is_empty() {
            String::from("(no description)")
        } else {
            preset.description.clone()
        };
        println!("  {:12} - {}{}", preset.name, desc, source_note);
    }
}

#[derive(Clone, Debug)]
struct MonitorArgs {
    config_sources: Vec<ConfigSource>,
    config_origins: BTreeMap<String, String>,
    provider_matcher: ProviderMatcher,
    warnings: Vec<String>,
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
    show_ancestry: bool,
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
    /// pcap capture interface (--pcap-interface); None uses libpcap default
    pcap_interface: Option<String>,
    /// pcap DNS/SNI cache cap (--pcap-cache-max); None uses built-in default
    pcap_cache_max: Option<usize>,
    stats_interval_ms: u64,
    stats_width: usize,
    stats_width_set: bool,
    stats_top: usize,
    stats_views: Vec<StatsView>,
    stats_cycle_ms: u64,
    no_banner: bool,
    theme: Theme,
    session_name: Option<String>,
    alert: AlertConfig,
    /// Retry detection threshold (number of connections in window to trigger warning)
    retry_threshold: usize,
    /// Cmdline masking for durable stores (SQLite, log files)
    redact_cmdline: RedactMode,
    /// Retry detection window in milliseconds
    retry_window_ms: u64,
}

/// Configuration for the alert system.
/// Enables active monitoring with thresholds and pattern matching.
#[derive(Clone, Debug)]
struct AlertConfig {
    /// Glob patterns for domain matching (case-insensitive)
    domain_patterns: Vec<String>,
    /// Alert when total active connections exceed this
    max_connections: Option<u64>,
    /// Alert when any single provider exceeds this
    max_per_provider: Option<u64>,
    /// Alert on connections longer than this (milliseconds)
    duration_threshold_ms: Option<u64>,
    /// Alert on connections with unresolved domain
    alert_unknown_domain: bool,
    /// Ring terminal bell on alert
    bell: bool,
    /// Cooldown between duplicate alerts (milliseconds)
    cooldown_ms: u64,
    /// Disable all alerting
    no_alerts: bool,
}

impl Default for AlertConfig {
    fn default() -> Self {
        Self {
            domain_patterns: Vec::new(),
            max_connections: None,
            max_per_provider: None,
            duration_threshold_ms: None,
            alert_unknown_domain: false,
            bell: false,
            cooldown_ms: 10_000,
            no_alerts: false,
        }
    }
}

impl AlertConfig {
    fn is_enabled(&self) -> bool {
        if self.no_alerts {
            return false;
        }
        !self.domain_patterns.is_empty()
            || self.max_connections.is_some()
            || self.max_per_provider.is_some()
            || self.duration_threshold_ms.is_some()
            || self.alert_unknown_domain
    }
}

/// Types of alerts that can be triggered.
#[derive(Clone, Debug)]
enum AlertKind {
    /// Domain matched a pattern
    DomainMatch { domain: String, pattern: String },
    /// Total connections exceeded threshold
    MaxConnections { current: u64, threshold: u64 },
    /// Provider connections exceeded threshold
    MaxPerProvider {
        provider: Provider,
        current: u64,
        threshold: u64,
    },
    /// Connection exceeded duration threshold
    LongDuration { duration_ms: u64, threshold_ms: u64 },
    /// Connection to unresolved domain
    UnknownDomain { remote_ip: IpAddr },
}

/// Severity level for alerts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AlertSeverity {
    Warning,  // Yellow - approaching threshold, unknown domain
    Critical, // Red - threshold exceeded, domain match
}

impl AlertSeverity {
    fn label(self) -> &'static str {
        match self {
            AlertSeverity::Warning => "WARNING",
            AlertSeverity::Critical => "CRITICAL",
        }
    }
}

/// Unique signature for deduplication (cooldown).
#[derive(Clone, Debug, Hash, Eq, PartialEq)]
enum AlertSignature {
    DomainMatch { domain: String, pattern: String },
    MaxConnections,
    MaxPerProvider { provider: Provider },
    LongDuration { conn_key: ConnKey },
    UnknownDomain { remote_ip: IpAddr },
}

/// State for tracking alert cooldowns and counts.
#[derive(Debug)]
struct AlertState {
    /// Last alert time per alert signature
    last_alert: HashMap<AlertSignature, SystemTime>,
    /// Total alerts triggered this session
    alert_count: u64,
    /// Alerts suppressed due to cooldown
    suppressed_count: u64,
}

/// Warning returned when a retry pattern is detected
#[derive(Clone, Debug)]
struct RetryWarning {
    /// Number of connections in the window
    count: usize,
    /// Window duration in seconds
    window_seconds: f64,
    /// The endpoint (remote IP and port)
    endpoint: (IpAddr, u16),
}

/// Tracks connection attempts per (remote_ip, remote_port, pid) for retry detection
struct RetryTracker {
    /// Recent connection timestamps: (remote_ip, remote_port, pid) -> Vec<Instant>
    recent: HashMap<(IpAddr, u16, u32), Vec<Instant>>,
    /// Per-source warning cooldown: (remote_ip, remote_port, pid) -> last emit time
    last_warn: HashMap<(IpAddr, u16, u32), Instant>,
    /// Number of connections that trigger a warning
    threshold: usize,
    /// Time window in milliseconds
    window_ms: u64,
}

impl RetryTracker {
    fn new(threshold: usize, window_ms: u64) -> Self {
        Self {
            recent: HashMap::new(),
            last_warn: HashMap::new(),
            threshold,
            window_ms,
        }
    }

    /// Track a connection close event and return a warning if retry pattern detected.
    /// Call this after a close event to detect rapid reconnection patterns.
    fn track_connection(
        &mut self,
        remote_ip: IpAddr,
        remote_port: u16,
        pid: u32,
    ) -> Option<RetryWarning> {
        // Bound memory: drop endpoints whose entries fully expired before tracking.
        self.prune_stale();

        let key = (remote_ip, remote_port, pid);
        let now = Instant::now();
        let window = Duration::from_millis(self.window_ms);

        // Get or create the entry
        let timestamps = self.recent.entry(key).or_default();

        // Add current timestamp
        timestamps.push(now);

        // Prune entries older than window_ms
        timestamps.retain(|ts| now.duration_since(*ts) < window);

        // Check if count >= threshold, honoring an endpoint-level cooldown equal to
        // the detection window so sustained storms do not re-warn on every close.
        if timestamps.len() >= self.threshold {
            if let Some(last) = self.last_warn.get(&key) {
                if now.duration_since(*last) < window {
                    return None;
                }
            }
            self.last_warn.insert(key, now);
            Some(RetryWarning {
                count: timestamps.len(),
                window_seconds: self.window_ms as f64 / 1000.0,
                endpoint: (remote_ip, remote_port),
            })
        } else {
            None
        }
    }

    /// Prune old entries from all tracked endpoints (bounds map growth over long sessions).
    fn prune_stale(&mut self) {
        let now = Instant::now();
        let window = Duration::from_millis(self.window_ms);

        self.recent.retain(|_, timestamps| {
            timestamps.retain(|ts| now.duration_since(*ts) < window);
            !timestamps.is_empty()
        });
        self.last_warn
            .retain(|_, timestamp| now.duration_since(*timestamp) < window);
    }
}

/// Build the stderr lines shown when the startup banner is suppressed: plain
/// "warning: ..." lines always, plus one structured JSON warning per note in --json mode.
fn suppressed_banner_note_lines(notes: &[String], json_mode: bool) -> Vec<String> {
    let mut lines: Vec<String> = notes.iter().map(|n| format!("warning: {}", n)).collect();
    if json_mode {
        for note in notes {
            lines.push(format!(
                "{{\"type\":\"warning\",\"scope\":\"domain_mode\",\"message\":\"{}\"}}",
                escape_json(note)
            ));
        }
    }
    lines
}

impl Default for MonitorArgs {
    fn default() -> Self {
        Self {
            config_sources: Vec::new(),
            config_origins: BTreeMap::new(),
            provider_matcher: ProviderMatcher::default(),
            warnings: Vec::new(),
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
            show_ancestry: false,
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
            session_name: None,
            alert: AlertConfig::default(),
            retry_threshold: 3,
            retry_window_ms: 60000,
            redact_cmdline: RedactMode::Off,
            pcap_interface: None,
            pcap_cache_max: None,
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ExportFormat {
    Csv,
    Jsonl,
}

#[derive(Clone, Debug)]
struct ExportArgs {
    format: ExportFormat,
    sqlite_path: String,
    since: Option<String>,
    until: Option<String>,
    run_id: Option<String>,
    providers: Vec<String>,
    domain_patterns: Vec<String>,
    fields: Option<Vec<String>>,
    no_header: bool,
    output: Option<PathBuf>,
}

impl Default for ExportArgs {
    fn default() -> Self {
        Self {
            format: ExportFormat::Csv,
            sqlite_path: "observer.sqlite".to_string(),
            since: None,
            until: None,
            run_id: None,
            providers: Vec::new(),
            domain_patterns: Vec::new(),
            fields: None,
            no_header: false,
            output: None,
        }
    }
}

/// Arguments for the session diff command.
#[derive(Clone, Debug)]
struct DiffArgs {
    /// Run ID or session name for the older/baseline session
    old_id: String,
    /// Run ID or session name for the newer session
    new_id: String,
    /// SQLite database path
    sqlite_path: String,
    /// Threshold percentage for "significant" count changes
    threshold_pct: f64,
    /// Output in JSON format
    json: bool,
    /// Color mode
    color: ColorMode,
}

impl Default for DiffArgs {
    fn default() -> Self {
        Self {
            old_id: String::new(),
            new_id: String::new(),
            sqlite_path: "observer.sqlite".to_string(),
            threshold_pct: 50.0,
            json: false,
            color: ColorMode::Auto,
        }
    }
}

/// Arguments for the status command (shell prompt integration).
#[derive(Clone, Debug)]
struct StatusArgs {
    /// Output in single-line format for prompt embedding
    one_line: bool,
    /// Custom format template
    format: Option<String>,
    /// SQLite database path
    sqlite_path: String,
}

impl Default for StatusArgs {
    fn default() -> Self {
        Self {
            one_line: false,
            format: None,
            sqlite_path: "observer.sqlite".to_string(),
        }
    }
}

/// Default format for status output
const STATUS_DEFAULT_FORMAT: &str = "{active} active | anthropic:{anthropic} openai:{openai}";

/// Result of comparing two sessions.
#[derive(Clone, Debug)]
struct DiffResult {
    /// Domains present in new session but not in old
    new_domains: Vec<String>,
    /// Domains present in old session but not in new
    removed_domains: Vec<String>,
    /// Domains with count change exceeding threshold: (domain, old_count, new_count)
    changed_domains: Vec<(String, i64, i64)>,
    /// Process names that appeared in new session
    new_processes: Vec<String>,
    /// Process names that were removed from old session
    removed_processes: Vec<String>,
    /// Provider count changes: provider -> (old_count, new_count)
    provider_changes: HashMap<String, (i64, i64)>,
    /// Old session run_id
    old_run_id: String,
    /// New session run_id
    new_run_id: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
enum Proto {
    Tcp,
    Udp,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
enum SocketKind {
    Connection,
    Listener,
    BoundUdp,
}

impl SocketKind {
    fn event(self) -> &'static str {
        match self {
            Self::Connection => "connect",
            Self::Listener => "listen",
            Self::BoundUdp => "bind",
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Connection => "endpoint",
            Self::Listener => "listener",
            Self::BoundUdp => "bound_udp",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
struct ConnKey {
    inode: u64,
    process: ProcessIdentity,
    root: ProcessIdentity,
    provider: Provider,
    provider_origin: Option<ProcessIdentity>,
    proto: Proto,
    socket_kind: SocketKind,
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
    log_cmdline: String,
    ownership_json: String,
    observation_id: String,
    capture_floor: SystemTime,
    domain_evidence: pcap_capture::DomainEvidence,
    provider: Provider,
    domain: Option<String>,
    domain_source: Option<String>,
    ancestry: Option<Vec<String>>,
    ancestry_path: Option<String>,
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

fn socket_kind(proto: Proto, entry: &NetEntry, args: &MonitorArgs) -> Option<SocketKind> {
    match proto {
        Proto::Tcp if entry.state == "0A" => args.include_listening.then_some(SocketKind::Listener),
        Proto::Tcp if entry.remote_port != 0 => Some(SocketKind::Connection),
        Proto::Tcp => None,
        Proto::Udp if !args.include_udp => None,
        Proto::Udp if entry.remote_port != 0 => Some(SocketKind::Connection),
        Proto::Udp => Some(SocketKind::BoundUdp),
    }
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
    listens: u64,
    binds: u64,
    closes: u64,
    socket_active: u64,
    socket_closes: u64,
    active: u64,
    peak_active: u64,
    sqlite_dropped: u64,
    sqlite_enabled: bool,
    sqlite_outcome: SqliteOutcome,
    log_failed: bool,
    observation_errors: u64,
    capture_health: Option<pcap_capture::CaptureHealth>,
    ptr_health: Option<PtrHealth>,
    per_ip: BTreeMap<IpAddr, u64>,
    per_port: BTreeMap<u16, u64>,
    per_domain: BTreeMap<String, u64>,
    per_pid: BTreeMap<u32, u64>,
    per_comm: BTreeMap<String, u64>,
    per_provider: BTreeMap<Provider, u64>,
    active_per_provider: BTreeMap<Provider, u64>,
    per_provider_domains: BTreeMap<Provider, BTreeMap<String, u64>>,
    per_provider_ips: BTreeMap<Provider, HashSet<IpAddr>>,
    duration_ms_total: u64,
    duration_ms_max: u64,
    duration_ms_samples: u64,
}

impl Stats {
    fn observed_open(&mut self, provider: Provider, kind: SocketKind) {
        self.socket_active += 1;
        match kind {
            SocketKind::Connection => {
                self.connects += 1;
                self.active += 1;
                *self.per_provider.entry(provider).or_default() += 1;
                *self.active_per_provider.entry(provider).or_default() += 1;
            }
            SocketKind::Listener => self.listens += 1,
            SocketKind::BoundUdp => self.binds += 1,
        }
    }

    fn observed_close(&mut self, provider: Provider, kind: SocketKind) {
        self.socket_closes += 1;
        self.socket_active = self.socket_active.saturating_sub(1);
        if kind != SocketKind::Connection {
            return;
        }
        self.closes += 1;
        self.active = self.active.saturating_sub(1);
        if let Some(count) = self.active_per_provider.get_mut(&provider) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                self.active_per_provider.remove(&provider);
            }
        }
    }
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
    session_name: String,
    observer: Option<ProcessIdentity>,
}

impl RunContext {
    fn new(args: &MonitorArgs, domain_label: &str, primary_provider: Option<Provider>) -> Self {
        let start_ts = now_rfc3339();
        let millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        let run_id = format!("{}-{}", std::process::id(), millis);
        let host = hostname();
        let user = env::var("USER").unwrap_or_else(|_| "unknown".to_string());
        let argv: Vec<_> = env::args().collect();
        let args_snapshot = redact_argv(&argv, args.redact_cmdline);
        let patterns = match args.redact_cmdline {
            RedactMode::Off => args.patterns.join(", "),
            RedactMode::Secrets => args
                .patterns
                .iter()
                .map(|p| mask_token(p))
                .collect::<Vec<_>>()
                .join(", "),
            RedactMode::All => format!("<redacted:{} patterns>", args.patterns.len()),
        };
        // Generate session name or use override
        let session_name = args.session_name.clone().unwrap_or_else(|| {
            let patterns: Vec<_> = args
                .patterns
                .iter()
                .map(|pattern| match args.redact_cmdline {
                    RedactMode::Off => pattern.clone(),
                    RedactMode::Secrets => mask_token(pattern),
                    RedactMode::All => REDACTED_PLACEHOLDER.to_string(),
                })
                .collect();
            generate_session_name(&patterns, primary_provider.unwrap_or(Provider::Unknown))
        });
        let session_name = match args.redact_cmdline {
            RedactMode::Off => session_name,
            RedactMode::Secrets => mask_token(&session_name),
            RedactMode::All => REDACTED_PLACEHOLDER.to_string(),
        };
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
            session_name,
            observer: read_proc_stat(std::process::id()).map(|stat| stat.identity),
        }
    }
}

/// Generate a human-friendly session name based on time, provider, and pattern.
/// Format: '{time}-{provider}-{pattern}-{date}'
fn generate_session_name(patterns: &[String], primary_provider: Provider) -> String {
    // Get current local time using libc
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as libc::time_t;

    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    unsafe {
        libc::localtime_r(&now_secs, &mut tm);
    }

    let hour = tm.tm_hour as u32;

    // Time of day
    let time_of_day = match hour {
        0..=5 => "night",
        6..=11 => "morning",
        12..=17 => "afternoon",
        _ => "evening",
    };

    // Provider label
    let provider_label = match primary_provider {
        Provider::Anthropic => "anthropic",
        Provider::OpenAI => "openai",
        Provider::Google => "google",
        Provider::Unknown => "mixed",
    };

    // First pattern or 'default'
    let pattern = patterns
        .first()
        .map(|p| p.to_lowercase())
        .unwrap_or_else(|| "default".to_string());

    // Date in YYYY-MM-DD format
    let year = tm.tm_year + 1900;
    let month = tm.tm_mon + 1;
    let day = tm.tm_mday;
    let date = format!("{:04}-{:02}-{:02}", year, month, day);

    format!("{}-{}-{}-{}", time_of_day, provider_label, pattern, date)
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
        // Colorblind theme uses high-contrast, distinguishable colors:
        // Blue/Orange/White are typically safe for most color vision deficiencies
        if self.theme == Theme::Colorblind {
            return Some(match provider {
                Provider::Anthropic => AnsiColor::BrightBlue, // Bright blue
                Provider::OpenAI => AnsiColor::Yellow,        // Orange-ish (yellow in ANSI)
                Provider::Google => AnsiColor::White,         // White/light gray
                Provider::Unknown => AnsiColor::BrightBlack,  // Dark gray
            });
        }
        Some(match provider {
            Provider::Anthropic => AnsiColor::Magenta,
            Provider::OpenAI => AnsiColor::BrightGreen,
            Provider::Google => AnsiColor::BrightBlue,
            Provider::Unknown => AnsiColor::BrightBlack,
        })
    }

    /// Returns a distinctive symbol for each provider (used in colorblind theme)
    fn provider_symbol(self, provider: Provider) -> &'static str {
        match provider {
            Provider::Anthropic => "●", // Filled circle
            Provider::OpenAI => "◆",    // Diamond
            Provider::Google => "▲",    // Triangle
            Provider::Unknown => "○",   // Empty circle
        }
    }

    /// Returns the bar fill character for a provider (used in colorblind theme)
    fn provider_bar_char(self, provider: Provider) -> char {
        if self.theme == Theme::Colorblind {
            match provider {
                Provider::Anthropic => '█', // Solid
                Provider::OpenAI => '▓',    // Dense shade
                Provider::Google => '▒',    // Medium shade
                Provider::Unknown => '░',   // Light shade
            }
        } else {
            '█'
        }
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
    format: LogFormat,
    failed: AtomicBool,
}

impl LogWriter {
    fn write_line(&self, line: &str) {
        let result = self
            .file
            .lock()
            .map_err(|_| "file log lock poisoned".to_string())
            .and_then(|mut file| {
                writeln!(file, "{}", line).map_err(|err| format!("file log write failed: {}", err))
            });
        if let Err(err) = result {
            self.record_failure(&err);
        }
    }

    fn record_failure(&self, error: &str) {
        if !self.failed.swap(true, Ordering::Relaxed) {
            eprintln!("error: {}", error);
        }
    }

    fn flush(&self) {
        let result = self
            .file
            .lock()
            .map_err(|_| "file log lock poisoned".to_string())
            .and_then(|mut file| {
                file.flush()
                    .map_err(|err| format!("file log flush failed: {}", err))
            });
        if let Err(err) = result {
            self.record_failure(&err);
        }
    }

    fn write_record(&self, json: &str, pretty: &str) {
        match self.format {
            LogFormat::Json => self.write_line(json),
            _ => self.write_line(&strip_ansi(pretty)),
        }
    }

    fn warning(&self, message: &str) {
        self.write_record(
            &format!(
                "{{\"type\":\"warning\",\"message\":\"{}\"}}",
                escape_json(message)
            ),
            message,
        );
    }
}

/// How aggressively to mask cmdlines in durable stores (SQLite, log files,
/// exports). Attribution and live display always see the original cmdline.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
enum RedactMode {
    #[default]
    Off,
    /// Mask key=value assignments, --flag value secret pairs, token-shaped
    /// and high-entropy arguments.
    Secrets,
    /// Replace the whole cmdline with `<redacted:N args>`.
    All,
}

impl RedactMode {
    fn parse(value: &str) -> Result<Self, String> {
        match value.to_lowercase().as_str() {
            "off" => Ok(Self::Off),
            "secrets" => Ok(Self::Secrets),
            "all" => Ok(Self::All),
            _ => Err("Invalid --redact-cmdline (use off|secrets|all)".to_string()),
        }
    }
}

const REDACTED_PLACEHOLDER: &str = "<redacted>";

/// Flags whose separate value argument is a credential.
fn is_secret_flag(token: &str) -> bool {
    if !token.starts_with('-') || token.contains('=') {
        return false;
    }
    let name = token.trim_start_matches('-').to_ascii_lowercase();
    matches!(
        name.as_str(),
        "api-key"
            | "apikey"
            | "token"
            | "with-token"
            | "access-token"
            | "password"
            | "passwd"
            | "secret"
    )
}

fn looks_like_secret_key(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    upper.contains("KEY")
        || upper.contains("TOKEN")
        || upper.contains("SECRET")
        || upper.contains("PASSWORD")
        || upper.contains("PASSWD")
        || upper.contains("CREDENTIAL")
}

fn high_entropy_token(token: &str) -> bool {
    if token.len() < 20 {
        return false;
    }
    let has_digit = token.chars().any(|c| c.is_ascii_digit());
    let has_alpha = token.chars().any(|c| c.is_ascii_alphabetic());
    let mixed_case =
        token.chars().any(|c| c.is_uppercase()) && token.chars().any(|c| c.is_lowercase());
    has_digit && has_alpha && mixed_case
}

fn mask_token(token: &str) -> String {
    // KEY=value assignment style
    if let Some(eq) = token.find('=') {
        let name = &token[..eq];
        if looks_like_secret_key(name.trim_start_matches('-')) {
            return format!("{name}={REDACTED_PLACEHOLDER}");
        }
    }
    // Known credential prefixes
    const PREFIXES: [&str; 4] = ["sk-", "ghp_", "xox", "AKIA"];
    if PREFIXES.iter().any(|p| token.starts_with(p)) && token.len() >= 16 {
        return REDACTED_PLACEHOLDER.to_string();
    }
    // JWT-like three dot-separated base64url segments
    let dots = token.matches('.').count();
    if dots == 2
        && token.len() >= 20
        && token
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-')
    {
        return REDACTED_PLACEHOLDER.to_string();
    }
    if high_entropy_token(token) {
        return REDACTED_PLACEHOLDER.to_string();
    }
    token.to_string()
}

/// Preserve argument boundaries until masking is complete, then format for storage.
fn redact_argv<S: AsRef<str>>(argv: &[S], mode: RedactMode) -> String {
    match mode {
        RedactMode::Off => return argv.iter().map(AsRef::as_ref).collect::<Vec<_>>().join(" "),
        RedactMode::All => {
            return format!("<redacted:{} args>", argv.len());
        }
        RedactMode::Secrets => {}
    }

    let mut out: Vec<String> = Vec::with_capacity(argv.len());
    let mut i = 0;
    while i < argv.len() {
        let token = argv[i].as_ref();
        if is_secret_flag(token) && i + 1 < argv.len() {
            out.push(token.to_string());
            out.push(REDACTED_PLACEHOLDER.to_string());
            i += 2;
            continue;
        }
        out.push(mask_token(token));
        i += 1;
    }
    out.join(" ")
}

fn parse_redact_mode(value: &str) -> Result<RedactMode, String> {
    RedactMode::parse(value)
}

#[derive(Clone, Debug)]
struct SqliteEvent {
    ts: String,
    run_id: String,
    event: String,
    key: ConnKey,
    pid: Option<u32>,
    comm: String,
    cmdline: String,
    provider: Provider,
    domain: Option<String>,
    domain_source: Option<String>,
    ancestry_path: Option<String>,
    duration_ms: Option<u64>,
    alert: bool,
    retry_count: Option<usize>,
    ownership_json: Option<String>,
    observation_id: Option<String>,
}

enum SqliteMsg {
    Event(SqliteEvent),
    Poll(SessionPoll),
    DomainUpdate(SqliteDomainUpdate),
    Shutdown {
        run_id: String,
        connects: u64,
        closes: u64,
    },
}

struct SqliteDomainUpdate {
    run_id: String,
    observation_id: String,
    domain: Option<String>,
    domain_source: Option<String>,
    ownership_json: String,
    alert: bool,
}

struct SessionPoll {
    run_id: String,
    ts: String,
    active: u64,
    valid: bool,
    domain_mode: String,
}

struct DropState {
    last_warn: SystemTime,
    dropped_since_warn: u64,
}

#[derive(Default)]
struct SqliteOutcome {
    observed: u64,
    persisted: u64,
    queue_lost: u64,
    write_lost: u64,
    metadata_lost: u64,
    failed: bool,
    error: Option<String>,
}

#[derive(Default)]
struct SqliteCounters {
    observed: AtomicU64,
    persisted: AtomicU64,
    queue_lost: AtomicU64,
    write_lost: AtomicU64,
    metadata_lost: AtomicU64,
    failed: AtomicBool,
    error: Mutex<Option<String>>,
}

impl SqliteCounters {
    fn failure(&self, message: String, log_writer: Option<&Arc<LogWriter>>) {
        let first = !self.failed.swap(true, Ordering::Relaxed);
        {
            let mut error = self
                .error
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            match error.as_mut() {
                Some(previous) if !previous.contains(&message) => {
                    previous.push_str("; ");
                    previous.push_str(&message);
                }
                None => *error = Some(message.clone()),
                _ => {}
            }
        }
        if first {
            eprintln!("error: {}", message);
            if let Some(writer) = log_writer {
                writer.warning(&message);
            }
        }
    }

    fn outcome(&self) -> SqliteOutcome {
        let observed = self.observed.load(Ordering::Relaxed);
        let persisted = self.persisted.load(Ordering::Relaxed);
        let queue_lost = self.queue_lost.load(Ordering::Relaxed);
        let metadata_lost = self.metadata_lost.load(Ordering::Relaxed);
        // A panicked/disconnected writer may leave accepted events in its queue.
        let write_lost = self.write_lost.load(Ordering::Relaxed).max(
            observed
                .saturating_sub(persisted)
                .saturating_sub(queue_lost),
        );
        SqliteOutcome {
            observed,
            persisted,
            queue_lost,
            write_lost,
            metadata_lost,
            failed: self.failed.load(Ordering::Relaxed)
                || queue_lost > 0
                || write_lost > 0
                || metadata_lost > 0,
            error: self
                .error
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone(),
        }
    }
}

struct SqliteWriter {
    sender: SyncSender<SqliteMsg>,
    handle: Option<std::thread::JoinHandle<()>>,
    counters: Arc<SqliteCounters>,
    drop_state: Mutex<DropState>,
    log_writer: Option<Arc<LogWriter>>,
}

impl SqliteWriter {
    fn correct_domain(&self, update: SqliteDomainUpdate) {
        if let Err(error) = self.sender.try_send(SqliteMsg::DomainUpdate(update)) {
            self.counters.metadata_lost.fetch_add(1, Ordering::Relaxed);
            self.counters.failure(
                format!("sqlite hostname correction publication failed: {}", error),
                self.log_writer.as_ref(),
            );
        }
    }

    fn publish_poll(
        &self,
        run_id: &str,
        active: u64,
        valid: bool,
        observed_at: SystemTime,
        domain_mode: &str,
    ) {
        let poll = SessionPoll {
            run_id: run_id.to_string(),
            ts: system_time_to_rfc3339(observed_at),
            active,
            valid: valid && !self.counters.failed.load(Ordering::Relaxed),
            domain_mode: domain_mode.to_string(),
        };
        if let Err(error) = self.sender.try_send(SqliteMsg::Poll(poll)) {
            self.counters.metadata_lost.fetch_add(1, Ordering::Relaxed);
            self.counters.failure(
                format!("sqlite poll-state publication failed: {}", error),
                self.log_writer.as_ref(),
            );
        }
    }

    fn enqueue(&self, event: SqliteEvent) {
        self.counters.observed.fetch_add(1, Ordering::Relaxed);
        match self.sender.try_send(SqliteMsg::Event(event)) {
            Ok(_) => {}
            Err(TrySendError::Full(_)) => {
                self.record_drop(1);
            }
            Err(TrySendError::Disconnected(_)) => {
                self.record_drop(1);
                self.counters.failure(
                    "sqlite writer disconnected while enqueueing an event".to_string(),
                    self.log_writer.as_ref(),
                );
            }
        }
    }

    fn shutdown(mut self, run_id: String, connects: u64, closes: u64) -> SqliteOutcome {
        if self
            .sender
            .send(SqliteMsg::Shutdown {
                run_id,
                connects,
                closes,
            })
            .is_err()
        {
            self.counters.failure(
                "sqlite writer disconnected before shutdown".to_string(),
                self.log_writer.as_ref(),
            );
        }
        if let Some(handle) = self.handle.take() {
            if let Err(payload) = handle.join() {
                let detail = payload
                    .downcast_ref::<String>()
                    .map(String::as_str)
                    .or_else(|| payload.downcast_ref::<&str>().copied())
                    .unwrap_or("non-string panic payload");
                self.counters.failure(
                    format!("sqlite writer thread panicked: {}", detail),
                    self.log_writer.as_ref(),
                );
            }
        }
        self.counters.outcome()
    }

    fn record_drop(&self, count: u64) {
        let total = self.counters.queue_lost.fetch_add(count, Ordering::Relaxed) + count;
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
                writer.warning(&msg);
            }
            state.last_warn = now;
            state.dropped_since_warn = 0;
        }
    }
}

struct DnsCacheEntry {
    value: Option<String>,
    stored_at: Instant,
}

#[derive(Clone, Default)]
struct PtrHealth {
    requested: u64,
    completed: u64,
    unresolved: u64,
    deferred: u64,
    expired: u64,
    evicted: u64,
    pending: usize,
    cached: usize,
    oldest_pending_ms: u128,
    failed: bool,
}

struct PtrResult {
    ip: IpAddr,
    requested_at: Instant,
    value: Option<String>,
}

struct PtrResolver {
    requests: SyncSender<(IpAddr, Instant)>,
    results: Receiver<PtrResult>,
    pending: HashMap<IpAddr, Instant>,
    cache: HashMap<IpAddr, DnsCacheEntry>,
    health: PtrHealth,
}

impl PtrResolver {
    fn new() -> Self {
        Self::with_lookup(reverse_dns)
    }

    fn with_lookup(lookup: impl Fn(IpAddr) -> Option<String> + Send + Sync + 'static) -> Self {
        let (requests, receive_requests) =
            mpsc::sync_channel::<(IpAddr, Instant)>(PTR_QUEUE_CAPACITY);
        let (send_results, results) = mpsc::sync_channel(PTR_QUEUE_CAPACITY);
        let receive_requests = Arc::new(Mutex::new(receive_requests));
        let lookup = Arc::new(lookup);
        for _ in 0..PTR_WORKERS {
            let receive = Arc::clone(&receive_requests);
            let send = send_results.clone();
            let lookup = Arc::clone(&lookup);
            std::thread::spawn(move || {
                loop {
                    // Hold the receiver lock only while receiving, never during
                    // the potentially blocking system resolver call.
                    let request = match receive.lock() {
                        Ok(receiver) => receiver.recv(),
                        Err(_) => break,
                    };
                    let Ok((ip, requested_at)) = request else {
                        break;
                    };
                    let value = if requested_at.elapsed() < PTR_TTL {
                        lookup(ip)
                    } else {
                        None
                    };
                    if send
                        .send(PtrResult {
                            ip,
                            requested_at,
                            value,
                        })
                        .is_err()
                    {
                        break;
                    }
                }
            });
        }
        Self {
            requests,
            results,
            pending: HashMap::new(),
            cache: HashMap::new(),
            health: PtrHealth::default(),
        }
    }

    fn maintain(&mut self) {
        let now = Instant::now();
        let before = self.cache.len();
        self.cache
            .retain(|_, entry| now.duration_since(entry.stored_at) < PTR_TTL);
        self.health.expired += (before - self.cache.len()) as u64;
        loop {
            match self.results.try_recv() {
                Ok(result) => {
                    if self.pending.remove(&result.ip) != Some(result.requested_at) {
                        continue;
                    }
                    self.health.completed += 1;
                    if now.duration_since(result.requested_at) >= PTR_TTL {
                        self.health.expired += 1;
                        continue;
                    }
                    if result.value.is_none() {
                        self.health.unresolved += 1;
                    }
                    if self.cache.len() == PTR_CACHE_MAX {
                        let oldest = self
                            .cache
                            .iter()
                            .min_by_key(|(ip, entry)| (entry.stored_at, **ip))
                            .map(|(ip, _)| *ip);
                        if let Some(ip) = oldest {
                            self.cache.remove(&ip);
                            self.health.evicted += 1;
                        }
                    }
                    self.cache.insert(
                        result.ip,
                        DnsCacheEntry {
                            value: result.value,
                            stored_at: now,
                        },
                    );
                }
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => {
                    self.health.failed = true;
                    break;
                }
            }
        }
    }

    fn resolve(&mut self, ip: IpAddr) -> Option<String> {
        if let Some(entry) = self.cache.get(&ip) {
            return entry.value.clone();
        }
        if self.pending.contains_key(&ip) || self.health.failed {
            return None;
        }
        // Include the two running requests in the pending limit. A resolver
        // stall cannot grow the queue, pending map or number of worker threads.
        if self.pending.len() >= PTR_QUEUE_CAPACITY + PTR_WORKERS {
            self.health.deferred += 1;
            return None;
        }
        let now = Instant::now();
        match self.requests.try_send((ip, now)) {
            Ok(()) => {
                self.pending.insert(ip, now);
                self.health.requested += 1;
            }
            Err(TrySendError::Full(_)) => self.health.deferred += 1,
            Err(TrySendError::Disconnected(_)) => self.health.failed = true,
        }
        None
    }

    fn health(&self) -> PtrHealth {
        let mut health = self.health.clone();
        health.pending = self.pending.len();
        health.cached = self.cache.len();
        health.oldest_pending_ms = self
            .pending
            .values()
            .map(|start| start.elapsed().as_millis())
            .max()
            .unwrap_or(0);
        health
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
struct ProcessIdentity {
    pid: u32,
    start_time: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ProcStat {
    identity: ProcessIdentity,
    ppid: u32,
    comm: String,
}

#[derive(Default)]
struct ProcessSnapshot {
    stat: HashMap<u32, ProcStat>,
    meta: HashMap<u32, PidMeta>,
}

struct AncestryEntry {
    chain: Vec<(u32, String)>,
    identities: Vec<ProcessIdentity>,
    stored_at: Instant,
}

struct AncestryCache {
    cache: HashMap<u32, AncestryEntry>,
    ttl: Duration,
}

impl AncestryCache {
    fn new(ttl: Duration) -> Self {
        Self {
            cache: HashMap::new(),
            ttl,
        }
    }

    fn get_or_compute(&mut self, pid: u32, snapshot: &ProcessSnapshot) -> Vec<(u32, String)> {
        let now = Instant::now();
        let identities = ancestry_identities(pid, snapshot);
        let chain: Vec<_> = identities
            .iter()
            .filter_map(|id| {
                snapshot
                    .stat
                    .get(&id.pid)
                    .map(|stat| (id.pid, stat.comm.clone()))
            })
            .collect();
        if let Some(entry) = self.cache.get(&pid) {
            let expired = now.duration_since(entry.stored_at) >= self.ttl;
            if !expired && entry.identities == identities && entry.chain == chain {
                return entry.chain.clone();
            }
        }
        self.cache.insert(
            pid,
            AncestryEntry {
                chain: chain.clone(),
                identities,
                stored_at: now,
            },
        );
        chain
    }

    fn retain_live(&mut self, snapshot: &ProcessSnapshot) {
        let now = Instant::now();
        self.cache.retain(|pid, entry| {
            now.duration_since(entry.stored_at) < self.ttl
                && snapshot.stat.get(pid).map(|stat| stat.identity)
                    == entry.identities.last().copied()
        });
    }
}

fn ancestry_identities(pid: u32, snapshot: &ProcessSnapshot) -> Vec<ProcessIdentity> {
    let mut chain = Vec::new();
    let mut current = pid;
    let mut seen: HashSet<u32> = HashSet::new();

    loop {
        if !seen.insert(current) {
            break;
        }
        let Some(stat) = snapshot.stat.get(&current) else {
            break;
        };
        chain.push(stat.identity);
        let ppid = stat.ppid;
        if ppid == 0 {
            break;
        }
        current = ppid;
    }

    chain.reverse();
    chain
}

#[allow(dead_code)]
fn format_ancestry(chain: &[(u32, String)]) -> String {
    let list = format_ancestry_list(chain);
    truncate_ancestry_list(&list).join(" \u{2192} ")
}

fn format_ancestry_list(chain: &[(u32, String)]) -> Vec<String> {
    if chain.is_empty() {
        return Vec::new();
    }
    chain
        .iter()
        .map(|(pid, comm)| format!("{}({})", comm, pid))
        .collect()
}

fn truncate_ancestry_list(list: &[String]) -> Vec<String> {
    if list.is_empty() {
        return Vec::new();
    }
    if list.len() <= 1 {
        return vec![list[0].clone()];
    }
    if list.len() > 5 {
        let tail = list[list.len().saturating_sub(2)..].to_vec();
        return vec![String::from("..."), tail[0].clone(), tail[1].clone()];
    }
    list.to_vec()
}

fn ancestry_chain_to_path(chain: &[(u32, String)]) -> String {
    let mut out = Vec::with_capacity(chain.len());
    for (pid, comm) in chain {
        let comm = comm
            .replace('%', "%25")
            .replace(',', "%2c")
            .replace(':', "%3a")
            .replace('\n', "%0a")
            .replace('\r', "%0d");
        out.push(format!("{}:{}", comm, pid));
    }
    out.join(",")
}

fn check_monitor_backend(
    platform: &str,
    proc_root: &Path,
    include_udp: bool,
) -> Result<(), String> {
    if platform != "linux" {
        return Err(format!(
            "Native monitoring requires Linux /proc; platform '{platform}' has no observation backend. Use Linux, WSL2 or a Linux VM. History and configuration commands do not require this backend."
        ));
    }
    let unavailable = |path: &Path, detail: String| {
        format!(
            "Linux /proc monitoring unavailable at {}: {detail}. Mount a readable procfs for this process and network namespace; history/config commands do not require it.",
            path.display()
        )
    };
    let stat_path = proc_root.join("self/stat");
    let content = fs::read(&stat_path)
        .map_err(|error| unavailable(&stat_path, format!("{:?}: {error}", error.kind())))?;
    let stat = parse_proc_stat(&String::from_utf8_lossy(&content))
        .ok_or_else(|| unavailable(&stat_path, "invalid Linux process identity".to_string()))?;
    if stat.identity.pid != std::process::id() {
        return Err(unavailable(
            &stat_path,
            "procfs process identity does not match this observer".to_string(),
        ));
    }
    let fd_path = proc_root.join("self/fd");
    fs::read_dir(&fd_path)
        .and_then(|mut entries| entries.next().transpose())
        .map_err(|error| unavailable(&fd_path, format!("{:?}: {error}", error.kind())))?;
    let namespace_path = proc_root.join("self/ns/net");
    fs::read_link(&namespace_path)
        .map_err(|error| unavailable(&namespace_path, format!("{:?}: {error}", error.kind())))?;
    let tables: &[&str] = if include_udp {
        &["tcp", "tcp6", "udp", "udp6"]
    } else {
        &["tcp", "tcp6"]
    };
    for table in tables {
        let path = proc_root.join("net").join(table);
        let file = fs::File::open(&path)
            .map_err(|error| unavailable(&path, format!("{:?}: {error}", error.kind())))?;
        let header = BufReader::new(file)
            .lines()
            .next()
            .transpose()
            .map_err(|error| unavailable(&path, format!("{:?}: {error}", error.kind())))?;
        if header.as_ref().is_none_or(|header| {
            !header
                .split_ascii_whitespace()
                .any(|word| word == "local_address")
                || !header.split_ascii_whitespace().any(|word| word == "inode")
        }) {
            return Err(unavailable(
                &path,
                "invalid Linux socket-table header".to_string(),
            ));
        }
    }
    Ok(())
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
            Command::Export(export_args) => {
                if let Err(err) = run_export(export_args) {
                    eprintln!("error: {}", err);
                    std::process::exit(1);
                }
                return;
            }
            Command::Config(config_args) => {
                let exit_code = run_config(config_args);
                std::process::exit(exit_code);
            }
            Command::Diff(diff_args) => {
                if let Err(err) = run_diff(diff_args) {
                    eprintln!("error: {}", err);
                    std::process::exit(1);
                }
                return;
            }
            Command::Status(status_args) => {
                if let Err(err) = run_status(status_args) {
                    eprintln!("error: {}", err);
                    std::process::exit(1);
                }
                return;
            }
        }
    }

    let args = cli.monitor;
    if let Err(error) = check_monitor_backend(env::consts::OS, Path::new("/proc"), args.include_udp)
    {
        if args.json {
            eprintln!(
                "{{\"type\":\"backend_unavailable\",\"message\":\"{}\"}}",
                escape_json(&error)
            );
        } else {
            eprintln!("error: {error}");
        }
        std::process::exit(1);
    }
    let provider_matcher = args.provider_matcher.clone();

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
        match pcap_capture::start_pcap_capture(pcap_options_from_args(&args)) {
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
    let mut domain_label = if domain_mode == DomainMode::Pcap {
        "pcap"
    } else if ptr_enabled {
        "ptr"
    } else {
        "disabled"
    };

    let mut dns_cache = ptr_enabled.then(PtrResolver::new);
    let mut domain_cache = pcap_handle.as_ref().map(|_| {
        pcap_capture::DomainCache::with_max_entries(
            args.pcap_cache_max
                .unwrap_or(pcap_capture::DEFAULT_CACHE_MAX_ENTRIES),
        )
    });
    let mut ancestry_cache = AncestryCache::new(Duration::from_secs(ANCESTRY_CACHE_TTL_SECS));

    let mut active: HashMap<ConnKey, ConnInfo> = HashMap::new();
    let mut stats = Stats::default();
    let mut alert_state = AlertState {
        last_alert: HashMap::new(),
        alert_count: 0,
        suppressed_count: 0,
    };
    let mut retry_tracker = RetryTracker::new(args.retry_threshold, args.retry_window_ms);

    let resolved_log_format = log_format_for_output(args.json, args.log_format);
    let log_writer = match open_log_writer(&args, &domain_label, resolved_log_format) {
        Ok(writer) => writer,
        Err(err) => {
            eprintln!("error: {}", err);
            if args.json {
                println!(
                    "{{\"type\":\"error\",\"message\":\"{}\"}}",
                    escape_json(&err)
                );
            }
            std::process::exit(1);
        }
    };
    for warning in &args.warnings {
        eprintln!("{}", warning);
        if let Some(writer) = &log_writer {
            writer.warning(warning);
        }
    }

    let run_ctx = RunContext::new(&args, domain_label, None);

    stats.sqlite_enabled = !args.no_sqlite;
    let sqlite_writer = if args.no_sqlite {
        None
    } else {
        match start_sqlite_writer(&args, run_ctx.clone(), log_writer.clone()) {
            Ok(writer) => Some(writer),
            Err(err) => {
                eprintln!("error: {}", err);
                if let Some(writer) = &log_writer {
                    writer.warning(&err);
                }
                stats.sqlite_outcome.failed = true;
                stats.sqlite_outcome.error = Some(err);
                None
            }
        }
    };

    if !args.no_banner {
        banner(&args, domain_label, &domain_notes, style, &log_writer);
    } else {
        // Banner suppressed: domain-mode notes (pcap fallback, PTR disabled) would be
        // invisible. Emit them on stderr so degradation is never silent; stdout stays a
        // pure event stream.
        for line in suppressed_banner_note_lines(&domain_notes, args.json) {
            eprintln!("{}", line);
        }
        if let Some(writer) = &log_writer {
            for note in &domain_notes {
                writer.warning(&format!("warning: {}", note));
            }
        }
    }

    let mut last_stats = SystemTime::now();
    let mut last_cycle = SystemTime::now();
    let mut stats_view_index: usize = 0;
    let mut reported_observation_errors = HashSet::new();
    let mut first_poll = true;
    let mut previous_poll_started = UNIX_EPOCH;

    loop {
        if !RUNNING.load(Ordering::SeqCst) {
            break;
        }

        if let (Some(handle), Some(cache)) = (pcap_handle.as_ref(), domain_cache.as_mut()) {
            handle.drain_into(cache);
        }
        if let Some(handle) = &pcap_handle {
            let health = handle.health();
            if health.unhealthy()
                && stats.capture_health.as_ref().is_none_or(|previous| {
                    previous.mapping_lost != health.mapping_lost
                        || previous.kernel_dropped != health.kernel_dropped
                        || previous.interface_dropped != health.interface_dropped
                        || previous.error != health.error
                })
            {
                let message = format!(
                    "pcap capture degraded: mapping_lost={} kernel_dropped={} interface_dropped={} error={}; falling back to {}",
                    health.mapping_lost,
                    health.kernel_dropped,
                    health.interface_dropped,
                    health.error.as_deref().unwrap_or("none"),
                    if ptr_enabled {
                        "PTR"
                    } else {
                        "unresolved hostnames"
                    }
                );
                if args.json {
                    eprintln!(
                        "{{\"type\":\"warning\",\"message\":\"{}\"}}",
                        escape_json(&message)
                    );
                } else {
                    eprintln!("warning: {}", message);
                }
                if let Some(writer) = &log_writer {
                    writer.warning(&message);
                }
                handle.stop_capture();
                domain_cache = None;
                domain_label = if ptr_enabled { "ptr" } else { "disabled" };
            }
            stats.capture_health = Some(health);
        }

        let poll_started = SystemTime::now();
        if let Some(resolver) = &mut dns_cache {
            resolver.maintain();
        }
        retry_tracker.prune_stale();
        let capture_floor = previous_poll_started;
        previous_poll_started = poll_started;
        let snapshot = collect_process_snapshot_for_scope(&provider_matcher, &args);
        ancestry_cache.retain_live(&snapshot);
        let excluded = excluded_processes(&args.exclude_patterns, &snapshot);
        let roots = find_root_pids(&args.patterns, &excluded, &args.pids, &snapshot);
        let monitored_roots = monitored_roots(&roots, args.no_descendants, &snapshot, &excluded);
        let targets: HashSet<_> = monitored_roots.keys().copied().collect();
        let InodeScan {
            owners: inode_owners,
            errors: inode_errors,
        } = map_inodes(&targets, &snapshot);
        let mut unobservable: HashSet<_> = inode_errors.iter().map(|(pid, _)| *pid).collect();
        let mut observation_errors: Vec<_> =
            inode_errors.into_iter().map(|(_, error)| error).collect();
        for pid in &args.pids {
            if !snapshot.stat.contains_key(pid)
                && !excluded.contains(pid)
                && (first_poll || Path::new(&format!("/proc/{}", pid)).exists())
            {
                unobservable.insert(*pid);
                observation_errors.push(format!("cannot observe requested PID {}: process absent, unreadable or changed during poll", pid));
            }
        }
        let pid_meta = resolve_provider_meta(&monitored_roots, &snapshot);

        let mut seen_keys = preserve_unobservable_keys(active.keys(), &unobservable, &snapshot);
        let mut table_failed = false;
        let entries = match gather_net_entries(args.include_udp) {
            Ok(entries) => entries,
            Err(error) => {
                table_failed = true;
                observation_errors.push(error);
                Vec::new()
            }
        };
        for error in observation_errors {
            stats.observation_errors += 1;
            if reported_observation_errors.insert(error.clone()) {
                if args.json {
                    eprintln!(
                        "{{\"type\":\"observation_error\",\"message\":\"{}\"}}",
                        escape_json(&error)
                    );
                } else {
                    eprintln!("warning: {}", error);
                }
                if let Some(writer) = &log_writer {
                    writer.warning(&error);
                }
            }
        }
        first_poll = false;
        if table_failed {
            // Missing evidence cannot establish that an earlier socket closed.
            break;
        }
        let now = SystemTime::now();

        for (proto, entry) in entries {
            let Some(kind) = socket_kind(proto, &entry, &args) else {
                continue;
            };

            let owners = match inode_owners.get(&entry.inode) {
                Some(owners) if !owners.is_empty() => owners,
                None => continue,
                _ => continue,
            };
            // Lowest PID is the deterministic primary owner of an inherited/shared fd.
            let identity = owners[0];
            let pid = identity.pid;
            if !targets.contains(&pid) {
                continue;
            }
            let Some(meta) = pid_meta.get(&pid) else {
                continue;
            };

            let key = ConnKey {
                inode: entry.inode,
                process: identity,
                root: monitored_roots[&pid],
                provider: meta.provider,
                provider_origin: meta.provider_origin,
                proto,
                socket_kind: kind,
                local_ip: entry.local_ip,
                local_port: entry.local_port,
                remote_ip: entry.remote_ip,
                remote_port: entry.remote_port,
            };

            seen_keys.insert(key.clone());

            let mut domain_evidence = match active.get(&key) {
                Some(info)
                    if kind != SocketKind::Connection
                        || (domain_cache.is_none() && (!ptr_enabled || info.domain.is_some())) =>
                {
                    info.domain_evidence.clone()
                }
                Some(info) => {
                    let evidence = resolve_observed_domain(
                        &key,
                        Some(&info.domain_evidence),
                        domain_cache.as_mut(),
                        &mut dns_cache,
                        ptr_enabled,
                        info.capture_floor,
                    );
                    if info.domain_evidence.source == Some(pcap_capture::DomainSource::Sni)
                        && evidence.source != Some(pcap_capture::DomainSource::Sni)
                        && !evidence.sni_ambiguous
                    {
                        // The same held inode retains its actual earlier SNI even
                        // after that mapping's cache TTL expires.
                        info.domain_evidence.clone()
                    } else {
                        evidence
                    }
                }
                None => resolve_observed_domain(
                    &key,
                    None,
                    domain_cache.as_mut(),
                    &mut dns_cache,
                    ptr_enabled,
                    capture_floor,
                ),
            };
            if kind != SocketKind::Connection {
                domain_evidence.scope = "not-applicable";
            }
            let domain = domain_evidence.hostname.clone();
            let domain_source = domain_evidence
                .source
                .map(pcap_capture::DomainSource::label);
            let evidence_json = format_domain_evidence_json(&domain_evidence);

            if !active.contains_key(&key) {
                let observation_id = format!(
                    "{}:{}",
                    run_ctx.run_id,
                    stats.connects + stats.listens + stats.binds
                );
                let (ancestry, ancestry_path) = if args.show_ancestry {
                    let chain = ancestry_cache.get_or_compute(pid, &snapshot);
                    (
                        Some(format_ancestry_list(&chain)),
                        Some(ancestry_chain_to_path(&chain)),
                    )
                } else {
                    (None, None)
                };

                // Durable sinks get the masked cmdline; display keeps the original.
                let log_cmdline = redact_argv(&meta.argv, args.redact_cmdline);
                let ownership_json = format_socket_ownership_json(
                    entry.inode,
                    identity,
                    monitored_roots[&pid],
                    owners,
                    meta.provider_origin,
                    kind,
                    &entry.state,
                    Some(&evidence_json),
                    Some(&observation_id),
                );

                let info = ConnInfo {
                    pid,
                    comm: meta.comm.clone(),
                    cmdline: meta.cmdline.clone(),
                    log_cmdline: log_cmdline.clone(),
                    ownership_json: ownership_json.clone(),
                    observation_id: observation_id.clone(),
                    capture_floor,
                    domain_evidence,
                    provider: meta.provider,
                    domain: domain.clone(),
                    domain_source: domain_source.map(str::to_string),
                    ancestry: ancestry.clone(),
                    ancestry_path: ancestry_path.clone(),
                    opened_at: now,
                    last_seen: now,
                };

                active.insert(key.clone(), info);

                let ts = now_rfc3339();
                if !args.summary_only {
                    emit_event(
                        &ts,
                        kind.event(),
                        &run_ctx.run_id,
                        &key,
                        pid,
                        &meta.comm,
                        &meta.cmdline,
                        Some(&log_cmdline),
                        meta.provider,
                        domain.as_deref(),
                        domain_source,
                        ancestry.as_deref(),
                        None,
                        Some(&ownership_json),
                        domain_label,
                        args.json,
                        style,
                        resolved_log_format,
                        log_writer.as_ref(),
                    );
                }

                stats.observed_open(meta.provider, kind);
                if kind == SocketKind::Connection {
                    *stats.per_ip.entry(entry.remote_ip).or_insert(0) += 1;
                    *stats.per_port.entry(entry.remote_port).or_insert(0) += 1;
                }
                *stats.per_pid.entry(pid).or_insert(0) += 1;
                *stats.per_comm.entry(meta.comm.clone()).or_insert(0) += 1;
                if let Some(name) = &domain {
                    *stats
                        .per_provider_domains
                        .entry(meta.provider)
                        .or_default()
                        .entry(name.clone())
                        .or_default() += 1;
                }
                if kind == SocketKind::Connection {
                    stats
                        .per_provider_ips
                        .entry(meta.provider)
                        .or_default()
                        .insert(entry.remote_ip);
                }
                if let Some(name) = domain.clone() {
                    *stats.per_domain.entry(name).or_insert(0) += 1;
                }

                // Single decision point for connection-level alerts: consults
                // AlertState cooldowns so suppressed alerts never flag the row.
                let conn_alert_emitted = match active.get(&key) {
                    Some(conn_info) if kind == SocketKind::Connection => check_connection_alerts(
                        &args.alert,
                        &mut alert_state,
                        &key,
                        conn_info,
                        args.json,
                        style,
                        log_writer.as_ref(),
                    ),
                    _ => false,
                };

                if stats.sqlite_enabled {
                    stats.sqlite_outcome.observed += 1;
                }

                if let Some(writer) = sqlite_writer.as_ref() {
                    writer.enqueue(SqliteEvent {
                        ts: ts.clone(),
                        run_id: run_ctx.run_id.clone(),
                        event: kind.event().to_string(),
                        key: key.clone(),
                        cmdline: log_cmdline.clone(),
                        pid: Some(pid),
                        comm: meta.comm.clone(),
                        provider: meta.provider,
                        domain: domain.clone(),
                        domain_source: domain_source.map(str::to_string),
                        ancestry_path: ancestry_path.clone(),
                        duration_ms: None,
                        alert: conn_alert_emitted,
                        retry_count: None,
                        ownership_json: Some(ownership_json),
                        observation_id: Some(observation_id),
                    });
                }
            } else if let Some(info) = active.get_mut(&key) {
                info.last_seen = now;
                let association_changed = info.domain != domain
                    || info.domain_source.as_deref() != domain_source
                    || info.domain_evidence.dns_candidates != domain_evidence.dns_candidates
                    || info.domain_evidence.dns_candidate_count
                        != domain_evidence.dns_candidate_count
                    || info.domain_evidence.sni_ambiguous != domain_evidence.sni_ambiguous;
                if association_changed {
                    if let Some(previous) = &info.domain {
                        if let Some(count) = stats.per_domain.get_mut(previous) {
                            *count = count.saturating_sub(1);
                            if *count == 0 {
                                stats.per_domain.remove(previous);
                            }
                        }
                        if let Some(names) = stats.per_provider_domains.get_mut(&info.provider) {
                            if let Some(count) = names.get_mut(previous) {
                                *count = count.saturating_sub(1);
                                if *count == 0 {
                                    names.remove(previous);
                                }
                            }
                        }
                    }
                    if let Some(current) = &domain {
                        *stats.per_domain.entry(current.clone()).or_default() += 1;
                        *stats
                            .per_provider_domains
                            .entry(info.provider)
                            .or_default()
                            .entry(current.clone())
                            .or_default() += 1;
                    }
                    info.domain = domain.clone();
                    info.domain_source = domain_source.map(str::to_string);
                    info.domain_evidence = domain_evidence;
                }
                info.ownership_json = format_socket_ownership_json(
                    entry.inode,
                    identity,
                    monitored_roots[&pid],
                    owners,
                    meta.provider_origin,
                    kind,
                    &entry.state,
                    Some(&evidence_json),
                    Some(&info.observation_id),
                );
                if args.show_ancestry {
                    let chain = ancestry_cache.get_or_compute(pid, &snapshot);
                    info.ancestry = Some(format_ancestry_list(&chain));
                    info.ancestry_path = Some(ancestry_chain_to_path(&chain));
                }
                if association_changed {
                    let ts = now_rfc3339();
                    if !args.summary_only {
                        emit_event(
                            &ts,
                            "domain_update",
                            &run_ctx.run_id,
                            &key,
                            info.pid,
                            &info.comm,
                            &info.cmdline,
                            Some(&info.log_cmdline),
                            info.provider,
                            info.domain.as_deref(),
                            info.domain_source.as_deref(),
                            info.ancestry.as_deref(),
                            None,
                            Some(&info.ownership_json),
                            domain_label,
                            args.json,
                            style,
                            resolved_log_format,
                            log_writer.as_ref(),
                        );
                    }
                    let alert = check_connection_alerts(
                        &args.alert,
                        &mut alert_state,
                        &key,
                        info,
                        args.json,
                        style,
                        log_writer.as_ref(),
                    );
                    if let Some(writer) = &sqlite_writer {
                        writer.correct_domain(SqliteDomainUpdate {
                            run_id: run_ctx.run_id.clone(),
                            observation_id: info.observation_id.clone(),
                            domain: info.domain.clone(),
                            domain_source: info.domain_source.clone(),
                            ownership_json: info.ownership_json.clone(),
                            alert,
                        });
                    }
                }
            }
        }

        let stale_keys: Vec<ConnKey> = active
            .keys()
            .filter(|k| !seen_keys.contains(*k))
            .cloned()
            .collect();
        for key in stale_keys {
            if let Some(info) = active.remove(&key) {
                if !active.keys().any(|other| {
                    other.inode == key.inode && socket_flow(other) == socket_flow(&key)
                }) {
                    if let Some(cache) = &mut domain_cache {
                        cache.retire_flow(socket_flow(&key), key.inode, now);
                    }
                }
                let duration_ms = now
                    .duration_since(info.opened_at)
                    .map(|d| d.as_millis() as u64)
                    .ok();

                let ts = now_rfc3339();
                // Track retry pattern on close events
                let retry_warning = (key.socket_kind == SocketKind::Connection)
                    .then(|| {
                        retry_tracker.track_connection(key.remote_ip, key.remote_port, info.pid)
                    })
                    .flatten();
                let retry_count = retry_warning.as_ref().map(|w| w.count);

                // Emit retry warning if detected
                if let Some(ref warning) = retry_warning {
                    if !args.summary_only {
                        let ip_str = key.remote_ip.to_string();
                        let domain_str = info.domain.as_deref().unwrap_or(&ip_str);
                        let msg = format!(
                            "\u{26A0} Retry pattern: {} connections to {}:{} in {}s",
                            warning.count, domain_str, key.remote_port, warning.window_seconds
                        );
                        let json = format_json_retry_warning(warning);
                        if args.json {
                            // JSON retry warnings join alert/event objects on stdout so
                            // machine consumers read one stream; stderr stays human-only.
                            println!("{}", json);
                        } else {
                            let styled_msg = if style.color {
                                format!("\x1b[33m{}\x1b[0m", msg)
                            } else {
                                msg.clone()
                            };
                            eprintln!("{}", styled_msg);
                        }
                        if let Some(ref writer) = log_writer {
                            writer.write_record(&json, &msg);
                        }
                    }
                }

                // Durable sinks get the masked cmdline; display keeps the original.
                let close_log_cmdline = &info.log_cmdline;

                if !args.summary_only {
                    emit_event(
                        &ts,
                        "close",
                        &run_ctx.run_id,
                        &key,
                        info.pid,
                        &info.comm,
                        &info.cmdline,
                        Some(close_log_cmdline),
                        info.provider,
                        info.domain.as_deref(),
                        info.domain_source.as_deref(),
                        info.ancestry.as_deref(),
                        duration_ms,
                        Some(&info.ownership_json),
                        domain_label,
                        args.json,
                        style,
                        resolved_log_format,
                        log_writer.as_ref(),
                    );
                }
                stats.observed_close(info.provider, key.socket_kind);

                // Single decision point for duration alerts: consults AlertState
                // cooldowns so suppressed alerts never flag the row.
                let mut close_alert_emitted = false;
                if let Some(ms) = duration_ms.filter(|_| key.socket_kind == SocketKind::Connection)
                {
                    stats.duration_ms_samples += 1;
                    stats.duration_ms_total = stats.duration_ms_total.saturating_add(ms);
                    stats.duration_ms_max = stats.duration_ms_max.max(ms);

                    close_alert_emitted = check_duration_alert(
                        &args.alert,
                        &mut alert_state,
                        &key,
                        &info,
                        ms,
                        args.json,
                        style,
                        log_writer.as_ref(),
                    );
                }

                if stats.sqlite_enabled {
                    stats.sqlite_outcome.observed += 1;
                }
                if let Some(writer) = sqlite_writer.as_ref() {
                    writer.enqueue(SqliteEvent {
                        ts: ts.clone(),
                        run_id: run_ctx.run_id.clone(),
                        event: "close".to_string(),
                        key: key.clone(),
                        pid: Some(info.pid),
                        comm: info.comm.clone(),
                        cmdline: close_log_cmdline.clone(),
                        provider: info.provider,
                        domain: info.domain.clone(),
                        domain_source: info.domain_source.clone(),
                        ancestry_path: info.ancestry_path.clone(),
                        duration_ms,
                        alert: close_alert_emitted,
                        retry_count,
                        ownership_json: Some(info.ownership_json.clone()),
                        observation_id: Some(info.observation_id.clone()),
                    });
                }
            }
        }

        // Reconcile opens and closes before observing a concurrent threshold or peak.
        // Ongoing breaches repeat only when their configured cooldown permits it.
        stats.peak_active = stats.peak_active.max(stats.active);
        let threshold_rows = check_threshold_alerts(
            &args.alert,
            &mut alert_state,
            &stats,
            &run_ctx.run_id,
            &now_rfc3339(),
            args.json,
            style,
            log_writer.as_ref(),
        );
        if stats.sqlite_enabled {
            stats.sqlite_outcome.observed += threshold_rows.len() as u64;
        }
        if let Some(writer) = sqlite_writer.as_ref() {
            for row in threshold_rows {
                writer.enqueue(row);
            }
        }

        if let Some(writer) = &sqlite_writer {
            writer.publish_poll(
                &run_ctx.run_id,
                stats.active,
                stats.observation_errors == 0,
                poll_started,
                domain_label,
            );
        }

        if args.stats_interval_ms > 0 && !args.json {
            if let Ok(elapsed) = now.duration_since(last_stats) {
                if elapsed >= Duration::from_millis(args.stats_interval_ms) {
                    if args.stats_cycle_ms > 0 && args.stats_views.len() > 1 && !args.summary_only {
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

    if let Some(resolver) = &mut dns_cache {
        resolver.maintain();
        stats.ptr_health = Some(resolver.health());
    }
    if let Some(writer) = sqlite_writer {
        stats.sqlite_outcome =
            writer.shutdown(run_ctx.run_id.clone(), stats.connects, stats.closes);
        stats.sqlite_dropped = stats.sqlite_outcome.queue_lost + stats.sqlite_outcome.write_lost;
    } else if stats.sqlite_enabled {
        stats.sqlite_outcome.write_lost = stats.sqlite_outcome.observed;
        stats.sqlite_dropped = stats.sqlite_outcome.write_lost;
    }

    if let Some(handle) = pcap_handle.take() {
        stats.capture_health = Some(handle.shutdown(domain_cache.as_mut()));
    }

    summary(
        &mut stats,
        args.json,
        args.stats_top,
        style,
        domain_label,
        log_writer.as_ref(),
        alert_state.alert_count,
        alert_state.suppressed_count,
    );
    if stats.sqlite_outcome.failed
        || stats.log_failed
        || stats.observation_errors > 0
        || stats
            .capture_health
            .as_ref()
            .is_some_and(pcap_capture::CaptureHealth::unhealthy)
    {
        std::process::exit(1);
    }
}

fn parse_cli() -> Result<Cli, String> {
    let args: Vec<String> = env::args().collect();
    if args.len() <= 1 {
        return Ok(Cli {
            command: None,
            monitor: load_monitor_args(&[])?,
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
        "export" => {
            let export = parse_export_args(&args[2..])?;
            Ok(Cli {
                command: Some(Command::Export(export)),
                monitor: MonitorArgs::default(),
            })
        }
        "config" => {
            let config = parse_config_args(&args[2..])?;
            Ok(Cli {
                command: Some(Command::Config(config)),
                monitor: MonitorArgs::default(),
            })
        }
        "diff" => {
            let diff = parse_diff_args(&args[2..])?;
            Ok(Cli {
                command: Some(Command::Diff(diff)),
                monitor: MonitorArgs::default(),
            })
        }
        "status" => {
            let status = parse_status_args(&args[2..])?;
            Ok(Cli {
                command: Some(Command::Status(status)),
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
    for index in monitor_option_indices(argv) {
        let arg = &argv[index];
        if arg == "-h" || arg == "--help" {
            print_help();
            std::process::exit(0);
        }
        if arg == "-V" || arg == "--version" {
            print_version();
            std::process::exit(0);
        }
        if arg == "--list-presets" {
            let loader = PresetLoader::new();
            print_presets_list(&loader);
            std::process::exit(0);
        }
    }

    let config = find_config_flag(argv);
    let mut args = MonitorArgs::default();
    if let Some(path) = selected_config_path(&config)? {
        apply_config_file(&path, &mut args)?;
    }

    // Load presets (in order specified on CLI)
    let preset_names = find_preset_flags(argv);
    if !preset_names.is_empty() {
        let loader = PresetLoader::new();
        for name in preset_names {
            let values = loader.load_preset(&name)?;
            apply_preset_values(&values, &mut args)?;
            let path = loader
                .user_preset_dirs
                .iter()
                .map(|dir| dir.join(format!("{name}.conf")))
                .find(|path| path.exists());
            let origin = path.as_ref().map_or_else(
                || format!("builtin:{name}"),
                |path| path.display().to_string(),
            );
            let mut keys: Vec<_> = values.iter().map(|(key, _)| key.clone()).collect();
            keys.sort();
            keys.dedup();
            for key in &keys {
                if config_validation::KNOWN_CONFIG_KEYS.contains(&key.as_str()) {
                    record_config_origin(key, &origin, &mut args);
                }
            }
            args.config_sources.push(ConfigSource {
                kind: if path.is_some() {
                    "user_preset"
                } else {
                    "builtin_preset"
                },
                origin,
                keys,
                provider_mode: None,
            });
        }
    }

    let mut args = apply_monitor_cli(argv, args)?;
    let providers = load_provider_matcher(&config)?;
    args.provider_matcher = providers.matcher;
    args.warnings.extend(providers.notes);
    args.config_sources.extend(providers.sources);
    Ok(args)
}

fn apply_monitor_cli(argv: &[String], mut args: MonitorArgs) -> Result<MonitorArgs, String> {
    let mut i = 0;
    let mut cli_keys = HashSet::new();
    while i < argv.len() {
        let arg = &argv[i];
        let key = match arg.as_str() {
            "--no-udp" => "include_udp".to_string(),
            "--no-color" => "color".to_string(),
            other => other.trim_start_matches('-').replace('-', "_"),
        };
        if config_validation::KNOWN_CONFIG_KEYS.contains(&key.as_str()) {
            if cli_keys.insert(key.clone()) {
                clear_config_list(&key, &mut args);
            }
            record_config_origin(&key, "cli", &mut args);
        }
        match arg.as_str() {
            "--pattern" => {
                i += 1;
                let value = require_value(argv, i, "--pattern")?;
                apply_config_value("pattern", value, &mut args)?;
                i += 1;
            }
            "--exclude-pattern" => {
                i += 1;
                let value = require_value(argv, i, "--exclude-pattern")?;
                apply_config_value("exclude_pattern", value, &mut args)?;
                i += 1;
            }
            "--pid" => {
                i += 1;
                let value = require_value(argv, i, "--pid")?;
                apply_config_value("pid", value, &mut args)?;
                i += 1;
            }
            "--no-descendants" => {
                apply_config_value("no_descendants", "true", &mut args)?;
                i += 1;
            }
            "--interval-ms" => {
                i += 1;
                let value = require_value(argv, i, "--interval-ms")?;
                apply_config_value("interval_ms", value, &mut args)?;
                i += 1;
            }
            "--json" => {
                apply_config_value("json", "true", &mut args)?;
                i += 1;
            }
            "--summary-only" => {
                apply_config_value("summary_only", "true", &mut args)?;
                i += 1;
            }
            "--domain-mode" => {
                i += 1;
                let value = require_value(argv, i, "--domain-mode")?;
                apply_config_value("domain_mode", value, &mut args)?;
                i += 1;
            }
            "--pcap" => {
                apply_config_value("pcap", "true", &mut args)?;
                i += 1;
            }
            "--no-dns" => {
                apply_config_value("no_dns", "true", &mut args)?;
                i += 1;
            }
            "--include-udp" => {
                apply_config_value("include_udp", "true", &mut args)?;
                i += 1;
            }
            "--no-udp" => {
                apply_config_value("include_udp", "false", &mut args)?;
                i += 1;
            }
            "--include-listening" => {
                apply_config_value("include_listening", "true", &mut args)?;
                i += 1;
            }
            "--show-ancestry" => {
                apply_config_value("show_ancestry", "true", &mut args)?;
                i += 1;
            }
            "--redact-cmdline" => {
                // Optional value: --redact-cmdline [off|secrets|all]; bare flag = secrets
                let next = argv.get(i + 1).map(|s| s.as_str());
                let (value, consumed) = match next {
                    Some(v @ ("off" | "secrets" | "all")) => (v, 1),
                    _ => ("secrets", 0),
                };
                apply_config_value("redact_cmdline", value, &mut args)?;
                i += 1 + consumed;
            }
            "--log-file" => {
                i += 1;
                let value = require_value(argv, i, "--log-file")?;
                apply_config_value("log_file", value, &mut args)?;
                i += 1;
            }
            "--theme" => {
                i += 1;
                let value = require_value(argv, i, "--theme")?;
                apply_config_value("theme", value, &mut args)?;
                i += 1;
            }
            "--log-dir" => {
                i += 1;
                let value = require_value(argv, i, "--log-dir")?;
                apply_config_value("log_dir", value, &mut args)?;
                i += 1;
            }
            "--log-format" => {
                i += 1;
                let value = require_value(argv, i, "--log-format")?;
                apply_config_value("log_format", value, &mut args)?;
                i += 1;
            }
            "--once" => {
                apply_config_value("once", "true", &mut args)?;
                i += 1;
            }
            "--color" => {
                i += 1;
                let value = require_value(argv, i, "--color")?;
                apply_config_value("color", value, &mut args)?;
                i += 1;
            }
            "--no-color" => {
                apply_config_value("color", "never", &mut args)?;
                i += 1;
            }
            "--sqlite" => {
                i += 1;
                let value = require_value(argv, i, "--sqlite")?;
                apply_config_value("sqlite", value, &mut args)?;
                i += 1;
            }
            "--no-sqlite" => {
                apply_config_value("no_sqlite", "true", &mut args)?;
                i += 1;
            }
            "--db-batch-size" => {
                i += 1;
                let value = require_value(argv, i, "--db-batch-size")?;
                apply_config_value("db_batch_size", value, &mut args)?;
                i += 1;
            }
            "--db-flush-ms" => {
                i += 1;
                let value = require_value(argv, i, "--db-flush-ms")?;
                apply_config_value("db_flush_ms", value, &mut args)?;
                i += 1;
            }
            "--db-queue-max" => {
                i += 1;
                let value = require_value(argv, i, "--db-queue-max")?;
                apply_config_value("db_queue_max", value, &mut args)?;
                i += 1;
            }
            "--stats-interval-ms" => {
                i += 1;
                let value = require_value(argv, i, "--stats-interval-ms")?;
                apply_config_value("stats_interval_ms", value, &mut args)?;
                i += 1;
            }
            "--pcap-cache-max" => {
                i += 1;
                let value = require_value(argv, i, "--pcap-cache-max")?;
                apply_config_value("pcap_cache_max", value, &mut args)?;
                i += 1;
            }
            "--pcap-interface" => {
                i += 1;
                let value = require_value(argv, i, "--pcap-interface")?;
                apply_config_value("pcap_interface", value, &mut args)?;
                i += 1;
            }
            "--stats-top" => {
                i += 1;
                let value = require_value(argv, i, "--stats-top")?;
                apply_config_value("stats_top", value, &mut args)?;
                i += 1;
            }
            "--stats-view" => {
                i += 1;
                let value = require_value(argv, i, "--stats-view")?;
                apply_config_value("stats_view", value, &mut args)?;
                i += 1;
            }
            "--stats-width" => {
                i += 1;
                let value = require_value(argv, i, "--stats-width")?;
                apply_config_value("stats_width", value, &mut args)?;
                i += 1;
            }
            "--stats-cycle-ms" => {
                i += 1;
                let value = require_value(argv, i, "--stats-cycle-ms")?;
                apply_config_value("stats_cycle_ms", value, &mut args)?;
                i += 1;
            }
            "--no-banner" => {
                apply_config_value("no_banner", "true", &mut args)?;
                i += 1;
            }
            "--session-name" => {
                i += 1;
                let value = require_value(argv, i, "--session-name")?;
                apply_config_value("session_name", value, &mut args)?;
                i += 1;
            }
            "--alert-domain" => {
                i += 1;
                let value = require_value(argv, i, "--alert-domain")?;
                apply_config_value("alert_domain", value, &mut args)?;
                i += 1;
            }
            "--alert-max-connections" => {
                i += 1;
                let value = require_value(argv, i, "--alert-max-connections")?;
                apply_config_value("alert_max_connections", value, &mut args)?;
                i += 1;
            }
            "--alert-max-per-provider" => {
                i += 1;
                let value = require_value(argv, i, "--alert-max-per-provider")?;
                apply_config_value("alert_max_per_provider", value, &mut args)?;
                i += 1;
            }
            "--alert-duration-ms" => {
                i += 1;
                let value = require_value(argv, i, "--alert-duration-ms")?;
                apply_config_value("alert_duration_ms", value, &mut args)?;
                i += 1;
            }
            "--alert-unknown-domain" => {
                apply_config_value("alert_unknown_domain", "true", &mut args)?;
                i += 1;
            }
            "--alert-bell" => {
                apply_config_value("alert_bell", "true", &mut args)?;
                i += 1;
            }
            "--alert-cooldown-ms" => {
                i += 1;
                let value = require_value(argv, i, "--alert-cooldown-ms")?;
                apply_config_value("alert_cooldown_ms", value, &mut args)?;
                i += 1;
            }
            "--no-alerts" => {
                apply_config_value("no_alerts", "true", &mut args)?;
                i += 1;
            }
            "--retry-threshold" => {
                i += 1;
                let value = require_value(argv, i, "--retry-threshold")?;
                apply_config_value("retry_threshold", value, &mut args)?;
                i += 1;
            }
            "--retry-window-ms" => {
                i += 1;
                let value = require_value(argv, i, "--retry-window-ms")?;
                apply_config_value("retry_window_ms", value, &mut args)?;
                i += 1;
            }
            "--preset" => {
                i += 1;
                let _ = require_value(argv, i, "--preset")?;
                i += 1;
            }
            "--list-presets" => {
                // Already handled in early check
                i += 1;
            }
            "--config" => {
                i += 1;
                let _ = require_value(argv, i, "--config")?;
                i += 1;
            }
            "--config-toml" => {
                i += 1;
                let _ = require_value(argv, i, "--config-toml")?;
                i += 1;
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

    if args.patterns.is_empty() && args.pids.is_empty() {
        args.patterns = default_patterns();
    }
    if args.stats_views.is_empty() {
        args.stats_views.push(StatsView::Provider);
    }
    if !cli_keys.is_empty() {
        let mut keys: Vec<_> = cli_keys.into_iter().collect();
        keys.sort();
        args.config_sources.push(ConfigSource {
            kind: "cli",
            origin: "cli".to_string(),
            keys,
            provider_mode: None,
        });
    }

    Ok(args)
}

fn parse_update_args(argv: &[String]) -> Result<UpdateCommand, String> {
    for arg in argv {
        if arg == "-h" || arg == "--help" {
            print_update_help();
            std::process::exit(0);
        }
        // --version selects an installer release here; only -V displays rano's version.
        if arg == "-V" {
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

/// Validate option syntax without opening sources or starting an observer.
fn parse_config_check_args(argv: &[String]) -> Result<ConfigArgs, String> {
    apply_monitor_cli(argv, MonitorArgs::default())?;
    Ok(ConfigArgs {
        subcommand: ConfigSubcommand::Check {
            options: argv.to_vec(),
        },
    })
}

fn parse_config_args(argv: &[String]) -> Result<ConfigArgs, String> {
    if argv
        .first()
        .is_some_and(|arg| matches!(arg.as_str(), "-h" | "--help"))
    {
        print_config_help();
        std::process::exit(0);
    }
    if argv
        .first()
        .is_some_and(|arg| matches!(arg.as_str(), "-V" | "--version"))
    {
        print_version();
        std::process::exit(0);
    }
    for index in monitor_option_indices(argv.get(1..).unwrap_or_default()) {
        let arg = &argv[index + 1];
        if arg == "-h" || arg == "--help" {
            print_config_help();
            std::process::exit(0);
        }
        if arg == "-V" || arg == "--version" {
            print_version();
            std::process::exit(0);
        }
    }

    if argv.is_empty() {
        print_config_help();
        std::process::exit(0);
    }

    let subcommand = match argv[0].as_str() {
        "check" => parse_config_check_args(&argv[1..])?.subcommand,
        "show" => {
            let mut json = false;
            let mut options = Vec::new();
            let tail = &argv[1..];
            let positions: HashSet<_> = monitor_option_indices(tail).into_iter().collect();
            let mut monitor_tail = false;
            for (index, arg) in tail.iter().enumerate() {
                if arg == "--" && positions.contains(&index) && !monitor_tail {
                    monitor_tail = true;
                } else if arg == "--json" && positions.contains(&index) && !monitor_tail {
                    json = true;
                } else {
                    options.push(arg.clone());
                }
            }
            apply_monitor_cli(&options, MonitorArgs::default())?;
            ConfigSubcommand::Show { json, options }
        }
        "paths" => {
            if argv.len() > 1 {
                return Err(format!(
                    "Unexpected argument for 'rano config paths': '{}'. Use 'rano config --help' for usage.",
                    argv[1]
                ));
            }
            ConfigSubcommand::Paths
        }
        other => {
            return Err(format!(
                "Unknown config subcommand: '{}'. Use 'rano config --help' for usage.",
                other
            ));
        }
    };

    Ok(ConfigArgs { subcommand })
}

fn parse_export_args(argv: &[String]) -> Result<ExportArgs, String> {
    for arg in argv {
        if arg == "-h" || arg == "--help" {
            print_export_help();
            std::process::exit(0);
        }
        if arg == "-V" || arg == "--version" {
            print_version();
            std::process::exit(0);
        }
    }

    let mut args = ExportArgs::default();
    let mut format_set = false;

    let mut i = 0;
    while i < argv.len() {
        let arg = &argv[i];
        match arg.as_str() {
            "--format" => {
                i += 1;
                let value = require_value(argv, i, "--format")?;
                args.format = parse_export_format(value)?;
                format_set = true;
                i += 1;
            }
            "--sqlite" => {
                i += 1;
                let value = require_value(argv, i, "--sqlite")?;
                args.sqlite_path = value.to_string();
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
            "--run-id" => {
                i += 1;
                let value = require_value(argv, i, "--run-id")?;
                args.run_id = Some(value.to_string());
                i += 1;
            }
            "--provider" => {
                i += 1;
                let value = require_value(argv, i, "--provider")?;
                args.providers.push(value.to_string());
                i += 1;
            }
            "--domain" => {
                i += 1;
                let value = require_value(argv, i, "--domain")?;
                args.domain_patterns.push(value.to_string());
                i += 1;
            }
            "--fields" => {
                i += 1;
                let value = require_value(argv, i, "--fields")?;
                args.fields = Some(parse_fields_list(value)?);
                i += 1;
            }
            "--no-header" => {
                args.no_header = true;
                i += 1;
            }
            "--output" | "-o" => {
                i += 1;
                let value = require_value(argv, i, "--output")?;
                args.output = Some(PathBuf::from(value));
                i += 1;
            }
            other => {
                if other.starts_with('-') {
                    return Err(format!("Unknown export flag: {}", other));
                }
                return Err(format!("Unexpected export argument: {}", other));
            }
        }
    }

    if !format_set {
        return Err("--format is required (use csv or jsonl)".to_string());
    }

    Ok(args)
}

fn parse_diff_args(argv: &[String]) -> Result<DiffArgs, String> {
    for arg in argv {
        if arg == "-h" || arg == "--help" {
            print_diff_help();
            std::process::exit(0);
        }
        if arg == "-V" || arg == "--version" {
            print_version();
            std::process::exit(0);
        }
    }

    let mut args = DiffArgs::default();
    let mut old_set = false;
    let mut new_set = false;

    let mut i = 0;
    while i < argv.len() {
        let arg = &argv[i];
        match arg.as_str() {
            "--old" => {
                i += 1;
                let value = require_value(argv, i, "--old")?;
                args.old_id = value.to_string();
                old_set = true;
                i += 1;
            }
            "--new" => {
                i += 1;
                let value = require_value(argv, i, "--new")?;
                args.new_id = value.to_string();
                new_set = true;
                i += 1;
            }
            "--sqlite" => {
                i += 1;
                let value = require_value(argv, i, "--sqlite")?;
                args.sqlite_path = value.to_string();
                i += 1;
            }
            "--threshold" => {
                i += 1;
                let value = require_value(argv, i, "--threshold")?;
                args.threshold_pct = value
                    .parse::<f64>()
                    .map_err(|_| "Invalid --threshold value".to_string())?;
                if !args.threshold_pct.is_finite() || !(0.0..=100.0).contains(&args.threshold_pct) {
                    return Err("--threshold must be finite and between 0 and 100".to_string());
                }
                i += 1;
            }
            "--json" => {
                args.json = true;
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
                    return Err(format!("Unknown diff flag: {}", other));
                }
                return Err(format!("Unexpected diff argument: {}", other));
            }
        }
    }

    if !old_set {
        return Err("--old <run-id> is required".to_string());
    }
    if !new_set {
        return Err("--new <run-id> is required".to_string());
    }

    Ok(args)
}

fn parse_status_args(argv: &[String]) -> Result<StatusArgs, String> {
    for arg in argv {
        if arg == "-h" || arg == "--help" {
            print_status_help();
            std::process::exit(0);
        }
        if arg == "-V" || arg == "--version" {
            print_version();
            std::process::exit(0);
        }
    }

    let mut args = StatusArgs::default();
    // Default to one_line since this is the primary use case
    args.one_line = true;

    let mut i = 0;
    while i < argv.len() {
        let arg = &argv[i];
        match arg.as_str() {
            "--one-line" => {
                args.one_line = true;
                i += 1;
            }
            "--format" => {
                i += 1;
                let value = require_value(argv, i, "--format")?;
                args.format = Some(value.to_string());
                i += 1;
            }
            "--sqlite" => {
                i += 1;
                let value = require_value(argv, i, "--sqlite")?;
                args.sqlite_path = value.to_string();
                i += 1;
            }
            other => {
                if other.starts_with('-') {
                    return Err(format!("Unknown status flag: {}", other));
                }
                return Err(format!("Unexpected status argument: {}", other));
            }
        }
    }

    Ok(args)
}

/// Minimum accepted value for --pcap-cache-max / `pcap_cache_max` config key.
const PCAP_CACHE_MIN_ENTRIES: usize = 100;

/// Validate and store a pcap interface name from CLI or config sources.
fn set_pcap_interface(args: &mut MonitorArgs, value: &str, source: &str) -> Result<(), String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(format!("{source} must be a non-empty interface name"));
    }
    args.pcap_interface = Some(trimmed.to_string());
    Ok(())
}
/// Build pcap capture options from parsed monitor arguments.
fn pcap_options_from_args(args: &MonitorArgs) -> pcap_capture::PcapOptions {
    pcap_capture::PcapOptions {
        interface: args.pcap_interface.clone(),
    }
}

fn require_value<'a>(argv: &'a [String], index: usize, flag: &str) -> Result<&'a str, String> {
    argv.get(index)
        .map(|v| v.as_str())
        .ok_or_else(|| format!("Missing value for {}", flag))
}

fn parse_u64(value: &str, flag: &str) -> Result<u64, String> {
    value
        .parse::<u64>()
        .map_err(|_| format!("'{flag}' must be a non-negative integer"))
}

fn parse_usize(value: &str, flag: &str) -> Result<usize, String> {
    value
        .parse::<usize>()
        .map_err(|_| format!("'{flag}' must be a non-negative integer"))
}

fn parse_domain_mode(value: &str) -> Result<DomainMode, String> {
    match value.to_lowercase().as_str() {
        "auto" => Ok(DomainMode::Auto),
        "ptr" => Ok(DomainMode::Ptr),
        "pcap" => Ok(DomainMode::Pcap),
        _ => Err("domain_mode must be one of [auto, ptr, pcap]".to_string()),
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

fn parse_export_format(value: &str) -> Result<ExportFormat, String> {
    match value.to_lowercase().as_str() {
        "csv" => Ok(ExportFormat::Csv),
        "jsonl" => Ok(ExportFormat::Jsonl),
        _ => Err("Invalid --format (use csv|jsonl)".to_string()),
    }
}

fn parse_theme(value: &str) -> Result<Theme, String> {
    match value.to_lowercase().as_str() {
        "vivid" => Ok(Theme::Vivid),
        "mono" => Ok(Theme::Mono),
        "colorblind" => Ok(Theme::Colorblind),
        _ => Err("Invalid --theme (use vivid|mono|colorblind)".to_string()),
    }
}

fn parse_fields_list(value: &str) -> Result<Vec<String>, String> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for part in value.split(',') {
        let trimmed = part.trim();
        if trimmed.is_empty() {
            continue;
        }
        let lowered = trimmed.to_lowercase();
        if seen.insert(lowered.clone()) {
            out.push(lowered);
        }
    }
    if out.is_empty() {
        return Err("--fields must include at least one field".to_string());
    }
    Ok(out)
}

fn parse_stats_view(value: &str) -> Result<StatsView, String> {
    match value.to_lowercase().as_str() {
        "provider" => Ok(StatsView::Provider),
        "domain" => Ok(StatsView::Domain),
        "port" => Ok(StatsView::Port),
        "process" => Ok(StatsView::Process),
        _ => Err(
            "stats_view contains invalid value (valid: provider, domain, port, process)"
                .to_string(),
        ),
    }
}

fn find_config_flag(argv: &[String]) -> ConfigPaths {
    let mut config_path = None;
    let mut toml_path = None;
    let mut use_config = true;
    for i in monitor_option_indices(argv) {
        match argv[i].as_str() {
            "--config" => {
                if let Some(path) = argv.get(i + 1) {
                    config_path = Some(PathBuf::from(path));
                }
            }
            "--config-toml" => {
                if let Some(path) = argv.get(i + 1) {
                    toml_path = Some(PathBuf::from(path));
                }
            }
            "--no-config" => {
                use_config = false;
            }
            _ => {}
        }
    }
    ConfigPaths {
        kv_path: config_path,
        toml_path,
        use_config,
    }
}

fn find_preset_flags(argv: &[String]) -> Vec<String> {
    let mut presets = Vec::new();
    for i in monitor_option_indices(argv) {
        if argv[i] == "--preset" {
            if let Some(name) = argv.get(i + 1) {
                presets.push(name.to_string());
            }
        }
    }
    presets
}

fn monitor_option_indices(argv: &[String]) -> Vec<usize> {
    let mut indices = Vec::new();
    let mut index = 0;
    while index < argv.len() {
        indices.push(index);
        let flag = argv[index].as_str();
        let bare = matches!(
            flag,
            "-h" | "--help"
                | "-V"
                | "--version"
                | "--list-presets"
                | "--no-config"
                | "--no-descendants"
                | "--json"
                | "--summary-only"
                | "--pcap"
                | "--no-dns"
                | "--include-udp"
                | "--no-udp"
                | "--include-listening"
                | "--show-ancestry"
                | "--once"
                | "--no-color"
                | "--no-sqlite"
                | "--no-banner"
                | "--alert-unknown-domain"
                | "--alert-bell"
                | "--no-alerts"
        );
        let consumes_value = if flag == "--redact-cmdline" {
            argv.get(index + 1)
                .is_some_and(|value| matches!(value.as_str(), "off" | "secrets" | "all"))
        } else {
            flag.starts_with('-') && !bare
        };
        index += if consumes_value { 2 } else { 1 };
    }
    indices
}

fn default_config_path() -> Option<PathBuf> {
    xdg_config_home().map(|dir| dir.join("rano/config.conf"))
}

fn selected_config_path(config: &ConfigPaths) -> Result<Option<PathBuf>, String> {
    if !config.use_config {
        return Ok(None);
    }
    let selected = if let Some(path) = &config.kv_path {
        Some((path.clone(), "--config"))
    } else if let Ok(value) = env::var("RANO_CONFIG") {
        if value.trim().is_empty() {
            return Err("RANO_CONFIG is set but empty".to_string());
        }
        Some((PathBuf::from(value.trim()), "RANO_CONFIG"))
    } else {
        None
    };
    if let Some((path, source)) = selected {
        if !path.is_file() {
            return Err(format!(
                "{source} path not found or not a regular file: {}",
                path.display()
            ));
        }
        return Ok(Some(path));
    }
    Ok(default_config_path().filter(|path| path.exists()))
}

fn apply_config_file(path: &Path, args: &mut MonitorArgs) -> Result<(), String> {
    let contents = fs::read_to_string(path)
        .map_err(|e| format!("Failed to read config {}: {}", path.display(), e))?;
    let mut keys = HashSet::new();
    for (idx, line) in contents.lines().enumerate() {
        let raw = line.split('#').next().unwrap_or("").trim();
        if raw.is_empty() {
            continue;
        }
        let mut parts = raw.splitn(2, '=');
        let key = parts.next().unwrap_or("").trim();
        let value = parts.next().unwrap_or("").trim();
        if key.is_empty() {
            return Err(format!("{}:{}: missing key", path.display(), idx + 1));
        }
        if value.is_empty() {
            return Err(format!(
                "Config parse error at line {}: missing value for '{}'",
                idx + 1,
                key
            ));
        }
        if keys.insert(key.to_string()) {
            clear_config_list(key, args);
        }
        if !apply_config_value(key, value, args)
            .map_err(|error| format!("{}:{}: {error}", path.display(), idx + 1))?
        {
            args.warnings.push(format!(
                "unknown key '{}' in config {}",
                key,
                path.display()
            ));
        } else {
            record_config_origin(key, &path.display().to_string(), args);
        }
    }
    let mut keys: Vec<_> = keys.into_iter().collect();
    keys.sort();
    args.config_sources.push(ConfigSource {
        kind: "kv",
        origin: path.display().to_string(),
        keys,
        provider_mode: None,
    });
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
        _ => Err("must be a boolean (true/false/yes/no/on/off/1/0)".to_string()),
    }
}

fn load_provider_matcher(config: &ConfigPaths) -> Result<ProviderResolution, String> {
    let mut notes = Vec::new();
    let mut sources = Vec::new();
    if !config.use_config {
        return Ok(ProviderResolution {
            matcher: ProviderMatcher::default(),
            notes,
            sources,
        });
    }

    let (paths, mut path_notes) = provider_config_paths(config);
    if !path_notes.is_empty() {
        return Err(path_notes.join("; "));
    }
    notes.append(&mut path_notes);

    let mut matcher = ProviderMatcher::default();
    for path in paths {
        let contents = fs::read_to_string(&path).map_err(|error| {
            format!(
                "provider config: failed to read {}: {error}",
                path.display()
            )
        })?;
        let validation = config_validation::validate_toml_contents(&path, &contents);
        if !validation.is_valid() {
            return Err(validation
                .errors
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("; "));
        }
        notes.extend(validation.warnings.iter().map(ToString::to_string));
        let parsed: TomlConfig = toml::from_str(&contents)
            .map_err(|_| format!("TOML parse error in {}", path.display()))?;

        let Some(providers) = parsed.providers else {
            sources.push(ConfigSource {
                kind: "providers",
                origin: path.display().to_string(),
                keys: Vec::new(),
                provider_mode: None,
            });
            continue;
        };

        let mode = providers
            .mode
            .as_deref()
            .map(parse_provider_mode)
            .transpose()?
            .unwrap_or(ProviderMode::Merge);
        let mut keys = Vec::new();
        if providers
            .mode
            .as_deref()
            .is_some_and(|mode| mode.eq_ignore_ascii_case("replace"))
        {
            keys.extend(
                [
                    "providers.anthropic",
                    "providers.openai",
                    "providers.google",
                ]
                .map(str::to_string),
            );
        } else {
            if providers.anthropic.is_some() {
                keys.push("providers.anthropic".to_string());
            }
            if providers.openai.is_some() {
                keys.push("providers.openai".to_string());
            }
            if providers.google.is_some() {
                keys.push("providers.google".to_string());
            }
        }
        apply_provider_config(&mut matcher, providers)
            .map_err(|error| format!("{}: {error}", path.display()))?;
        sources.push(ConfigSource {
            kind: "providers",
            origin: path.display().to_string(),
            keys,
            provider_mode: Some(mode),
        });
    }

    Ok(ProviderResolution {
        matcher,
        notes,
        sources,
    })
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
    if !seen.insert(path.clone()) {
        paths.retain(|previous| previous != &path);
    }
    paths.push(path);
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
        _ => Err("Invalid providers.mode: must be one of [merge, replace]".to_string()),
    }
}

fn top_level_help_text() -> &'static str {
    "rano - AI CLI network observer\n\n\
USAGE:\n  rano [options]\n  rano report [options]\n  rano export [options]\n  rano diff --old <id> --new <id> [options]\n  rano status [options]\n  rano config <subcommand>\n  rano update [options]\n\n\
COMMANDS:\n  report    Query SQLite event history (use --help for details)\n  export    Export SQLite event history\n  diff      Compare two monitoring sessions\n  status    One-line status for shell prompt integration\n  config    Validate and inspect configuration\n  update    Update the rano binary\n\n\
OPTIONS:\n\
  --pattern <str>           Process name or cmdline substring to match (repeatable)\n\
  --exclude-pattern <str>   Exclude processes matching substring (repeatable)\n\
  --pid <pid>               Monitor a specific PID (repeatable)\n\
  --no-descendants          Do not include descendant processes\n\
  --interval-ms <ms>        Poll interval (default: 1000)\n\
  --json                    Emit JSON lines to stdout\n\
  --summary-only            Suppress live events, show summary only\n\
  --domain-mode <mode>      auto|ptr|pcap (default: auto)\n\
  --pcap                    Force pcap mode (falls back with warning)\n\
  --pcap-interface <name>   Capture interface for pcap mode (default: auto)\n\
  --pcap-cache-max <n>      DNS/SNI cache cap, >= 100 (default: 10000)\n\
  --no-dns                  Disable PTR lookups\n\
  --include-udp             Include UDP sockets (default: true)\n\
  --no-udp                  Disable UDP sockets\n\
  --include-listening       Include listening TCP sockets\n\
  --show-ancestry           Include process ancestry chain in output\n\
  --log-file <path>         Append output to log file\n\
  --log-dir <path>          Write per-run log files into directory\n\
  --log-format <fmt>        auto|pretty|json for log files (default: auto)\n\
  --once                    Emit a single poll and exit\n\
  --color <mode>            auto|always|never (default: auto)\n\
  --no-color                Disable ANSI color\n\
  --theme <name>            vivid|mono|colorblind (default: vivid)\n\
  --sqlite <path>           SQLite file for persistent logging\n\
  --no-sqlite               Disable SQLite logging\n\
  --db-batch-size <n>       SQLite batch size (events per transaction)\n\
  --db-flush-ms <ms>        SQLite flush interval in ms\n\
  --db-queue-max <n>        SQLite queue capacity (events)\n\
  --stats-interval-ms <ms>  Live stats interval (0 disables)\n\
  --stats-width <n>         ASCII bar width\n\
  --stats-top <n>           Top-N domains/IPs in stats/summary\n\
  --stats-view <name>       Stats view: provider|domain|port|process (repeatable)\n\
  --stats-cycle-ms <ms>     Rotate stats views at this interval (0 disables)\n\
  --session-name <name>     Override auto-generated session name\n\
  --no-banner               Suppress startup banner\n\n\
ALERT OPTIONS:\n\
  --alert-domain <pattern>       Alert on domains matching glob pattern (repeatable)\n\
  --alert-max-connections <n>    Alert when total active connections reach N\n\
  --alert-max-per-provider <n>   Alert when any provider reaches N connections\n\
  --alert-duration-ms <ms>       Alert on connections lasting longer than N ms\n\
  --alert-unknown-domain         Alert on connections to unresolved domains\n\
  --alert-bell                   Ring terminal bell on alerts\n\
  --alert-cooldown-ms <ms>       Suppress duplicate alerts within window (default: 10000)\n\
  --no-alerts                    Disable all alerting\n\n\
RETRY DETECTION:\n\
  --retry-threshold <n>          Connections in window to trigger warning (default: 3)\n\
  --retry-window-ms <ms>         Retry detection window in ms (default: 60000)\n\n\
SECRETS & PRIVACY:\n\
  --redact-cmdline [mode]        Mask cmdlines in durable stores (SQLite, log\n\
                                 files, exports): off|secrets|all (bare flag\n\
                                 = secrets; default: off). Attribution and\n\
                                 live display always see the original.\n\n\
  --preset <name>           Load named preset (repeatable, merged in order)\n\
  --list-presets            List available presets and exit\n\
  --config <path>           Load config file (key=value format)\n\
  --config-toml <path>      Load provider config (TOML)\n\
  --no-config               Ignore config files\n\
  -h, --help                Show this help\n\
  -V, --version             Show version\n\n\
EXAMPLES:\n\
  rano --preset audit                                   # Use audit preset\n\
  rano --preset quiet --preset audit                    # Merge presets\n\
  rano --alert-domain '*.evil.com' --alert-max-connections 100\n\
  rano --pattern claude --alert-unknown-domain\n"
}

fn print_help() {
    println!("{}", top_level_help_text());
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

fn print_export_help() {
    println!(
        "rano export - export SQLite event history\n\n\
USAGE:\n  rano export [options]\n\n\
OPTIONS:\n\
  --format <fmt>    Output format: csv|jsonl (required)\n\
  --sqlite <path>   SQLite database path (default: observer.sqlite)\n\
  --since <ts>      Start of time range (RFC3339, date, or relative like 1h/24h/7d)\n\
  --until <ts>      End of time range (RFC3339, exclusive)\n\
  --run-id <id>     Export specific session by run_id\n\
  --provider <name> Filter by provider (repeatable)\n\
  --domain <glob>   Filter by domain glob pattern (repeatable)\n\
  --fields <list>   Comma-separated field list override\n\
  --no-header       Omit header row (CSV only)\n\
  --output <path>   Output file (default: stdout)\n\
  -o <path>         Shorthand for --output\n\
  -h, --help        Show this help\n\
  -V, --version     Show version\n\n\
EXAMPLES:\n\
  rano export --format csv\n\
  rano export --format jsonl --since 24h\n\
  rano export --format csv --fields ts,provider,remote_ip,domain\n"
    );
}

fn print_config_help() {
    println!(
        "rano config - validate and inspect configuration\n\n\
USAGE:\n  rano config <subcommand> [options]\n\n\
SUBCOMMANDS:\n\
  check [options]    Validate all configuration sources\n\
    Monitor options are accepted, including --config, --config-toml,\n\
    ordered --preset flags and --no-config. Selected source errors fail.\n\
  show [--json] [monitor options]  Display effective settings and origins\n\
    --json formats this output; use -- --json to inspect JSON monitoring.\n\
  paths              Show config file search locations\n\n\
OPTIONS:\n\
  -h, --help        Show this help\n\
  -V, --version     Show version\n\n\
EXAMPLES:\n\
  rano config check                # Validate all config files\n\
  rano config check --config-toml custom.toml  # Check the same merged sources\n\
  rano config show                 # Show resolved config\n\
  rano config show --json          # Show config as JSON\n\
  rano config show --json --preset live --interval-ms 100  # Inspect overrides\n\
  rano config paths                # List config search paths\n"
    );
}

fn print_diff_help() {
    println!(
        "rano diff - compare two monitoring sessions\n\n\
USAGE:\n  rano diff --old <id> --new <id> [options]\n\n\
OPTIONS:\n\
  --old <id>        Run ID or session name for baseline session (required)\n\
  --new <id>        Run ID or session name for comparison session (required)\n\
  --sqlite <path>   SQLite database path (default: observer.sqlite)\n\
  --threshold <N>   Percentage change threshold for 'significant' (default: 50)\n\
  --json            Output in JSON format\n\
  --color <mode>    Color output: auto|always|never (default: auto)\n\
  --no-color        Disable color output\n\
  -h, --help        Show this help\n\
  -V, --version     Show version\n\n\
OUTPUT SECTIONS:\n\
  New domains       Domains in new session but not in old\n\
  Removed domains   Domains in old session but not in new\n\
  Changed domains   Domains with count change exceeding threshold\n\
  New processes     Process names that appeared in new session\n\
  Provider changes  Significant count changes per provider\n\n\
EXAMPLES:\n\
  rano diff --old abc123 --new def456\n\
  rano diff --old morning-claude-audit-2026-01-20 --new afternoon-claude-audit-2026-01-20\n\
  rano diff --old abc123 --new def456 --threshold 25 --json\n"
    );
}

fn print_status_help() {
    println!(
        "rano status - one-line status for shell prompt integration\n\n\
USAGE:\n  rano status [options]\n\n\
OPTIONS:\n\
  --one-line        Output compact format for prompt embedding (default)\n\
  --format <tpl>    Custom format template string\n\
  --sqlite <path>   SQLite database path (default: observer.sqlite)\n\
  -h, --help        Show this help\n\
  -V, --version     Show version\n\n\
TEMPLATE VARIABLES:\n\
  {{active}}        Fresh observed endpoint count (zero when unavailable)\n\
  {{state}}         fresh/ended/stale/degraded/unverified/unavailable\n\
  {{total}}         Historical connection observations this session\n\
  {{anthropic}}     Historical Anthropic connection observations\n\
  {{openai}}        Historical OpenAI connection observations\n\
  {{google}}        Historical Google connection observations\n\
  {{session_name}}  Current session name (if available)\n\n\
DEFAULT FORMAT:\n\
  {}\n\n\
EXAMPLES:\n\
  rano status                              # Default one-line format\n\
  rano status --format '{{active}}/{{total}}'    # Custom format\n\
  rano status --sqlite /tmp/rano.sqlite    # Custom database\n\n\
SHELL INTEGRATION:\n\
  # Bash PS1:\n\
  PS1='$(rano status 2>/dev/null) \\$ '\n\
  # Starship/Zsh:\n\
  RPROMPT='$(rano status 2>/dev/null)'\n",
        STATUS_DEFAULT_FORMAT
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
    vec![
        "claude".to_string(),
        "codex".to_string(),
        "gemini".to_string(),
    ]
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
            // Reaching this arm means the caller wanted pcap but capture init failed
            // upstream; degrade to PTR with an explanation rather than silently.
            DomainMode::Ptr,
            Some("pcap capture requested; falling back to PTR.".to_string()),
        ),
    }
}

fn pcap_permission_hint(err: &str) -> Option<&'static str> {
    let lower = err.to_lowercase();
    if lower.contains("permission")
        || lower.contains("denied")
        || lower.contains("not permitted")
        // libpcap words unprivileged socket-creation failures this way instead of
        // EPERM-style: "Attempt to create packet socket failed - CAP_NET_RAW may
        // be required".
        || lower.contains("cap_net_raw")
    {
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
        libc::signal(libc::SIGINT, handle as *const () as libc::sighandler_t);
        libc::signal(libc::SIGTERM, handle as *const () as libc::sighandler_t);
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
        if args.no_sqlite {
            "disabled"
        } else {
            &args.sqlite_path
        },
        args.stats_interval_ms,
        args.log_file
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "-".to_string()),
        args.log_dir
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "-".to_string()),
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
            println!(
                "{}",
                paint(
                    &warning,
                    Some(AnsiColor::BrightYellow),
                    true,
                    false,
                    style.color
                )
            );
        }
        if let Some(writer) = log_writer.as_ref() {
            writer.warning(&warning);
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

// --- Alert System Functions ---

/// Check if an alert should be emitted (respecting cooldown).
fn should_emit_alert(state: &mut AlertState, sig: &AlertSignature, cooldown_ms: u64) -> bool {
    let now = SystemTime::now();

    // Prevent memory leak from stale keys
    if state.last_alert.len() > 5000 {
        let window = Duration::from_millis(cooldown_ms);
        state
            .last_alert
            .retain(|_, ts| now.duration_since(*ts).unwrap_or_default() < window);
    }

    if let Some(last) = state.last_alert.get(sig) {
        if let Ok(elapsed) = now.duration_since(*last) {
            if elapsed.as_millis() < cooldown_ms as u128 {
                state.suppressed_count += 1;
                return false;
            }
        }
    }
    state.last_alert.insert(sig.clone(), now);
    state.alert_count += 1;
    true
}

/// Simple glob pattern match (supports * and ?).
fn glob_match(pattern: &str, text: &str) -> bool {
    let pattern = pattern.to_lowercase();
    let text = text.to_lowercase();
    glob_match_impl(pattern.as_bytes(), text.as_bytes())
}

fn glob_match_impl(pattern: &[u8], text: &[u8]) -> bool {
    let mut p_idx = 0;
    let mut t_idx = 0;
    let mut star_p_idx: Option<usize> = None;
    let mut star_t_idx: usize = 0;

    while t_idx < text.len() {
        if p_idx < pattern.len() && (pattern[p_idx] == b'?' || pattern[p_idx] == text[t_idx]) {
            p_idx += 1;
            t_idx += 1;
        } else if p_idx < pattern.len() && pattern[p_idx] == b'*' {
            star_p_idx = Some(p_idx);
            star_t_idx = t_idx;
            p_idx += 1;
        } else if let Some(sp) = star_p_idx {
            p_idx = sp + 1;
            star_t_idx += 1;
            t_idx = star_t_idx;
        } else {
            return false;
        }
    }

    while p_idx < pattern.len() && pattern[p_idx] == b'*' {
        p_idx += 1;
    }
    p_idx == pattern.len()
}

/// Check domain against alert patterns.
fn check_domain_patterns(domain: Option<&str>, patterns: &[String]) -> Option<String> {
    let domain = domain?;
    for pattern in patterns {
        if glob_match(pattern, domain) {
            return Some(pattern.clone());
        }
    }
    None
}

/// Emit an alert to stderr (and optionally ring bell).
fn emit_alert(
    kind: &AlertKind,
    severity: AlertSeverity,
    conn_key: Option<&ConnKey>,
    conn_info: Option<&ConnInfo>,
    bell: bool,
    json_mode: bool,
    style: OutputStyle,
    log_writer: Option<&Arc<LogWriter>>,
) {
    let ts = now_rfc3339();
    let json = format_json_alert(&ts, kind, severity, conn_key, conn_info);
    let line = format_pretty_alert(&ts, kind, severity, conn_key, conn_info, style);

    if json_mode {
        println!("{}", json);
    } else {
        eprintln!("{}", line);
    }
    if let Some(writer) = log_writer {
        writer.write_record(&json, &line);
    }

    if bell {
        eprint!("\x07"); // Bell character
    }
}

fn format_json_alert(
    ts: &str,
    kind: &AlertKind,
    severity: AlertSeverity,
    conn_key: Option<&ConnKey>,
    conn_info: Option<&ConnInfo>,
) -> String {
    let mut parts = vec![
        format!("\"ts\":\"{}\"", escape_json(ts)),
        "\"type\":\"alert\"".to_string(),
    ];

    let (kind_str, extra) = match kind {
        AlertKind::DomainMatch { domain, pattern } => (
            "domain_match",
            format!(
                ",\"pattern\":\"{}\",\"domain\":\"{}\"",
                escape_json(pattern),
                escape_json(domain)
            ),
        ),
        AlertKind::MaxConnections { current, threshold } => (
            "max_connections",
            format!(",\"threshold\":{},\"actual\":{}", threshold, current),
        ),
        AlertKind::MaxPerProvider {
            provider,
            current,
            threshold,
        } => (
            "max_per_provider",
            format!(
                ",\"provider\":\"{}\",\"threshold\":{},\"actual\":{}",
                provider.label(),
                threshold,
                current
            ),
        ),
        AlertKind::LongDuration {
            duration_ms,
            threshold_ms,
        } => (
            "long_duration",
            format!(
                ",\"duration_ms\":{},\"threshold_ms\":{}",
                duration_ms, threshold_ms
            ),
        ),
        AlertKind::UnknownDomain { remote_ip } => (
            "unknown_domain",
            format!(",\"remote_ip\":\"{}\"", remote_ip),
        ),
    };

    parts.push(format!("\"kind\":\"{}\"", kind_str));
    parts.push(format!(
        "\"severity\":\"{}\"",
        severity.label().to_lowercase()
    ));

    if let Some(key) = conn_key {
        let proto = match key.proto {
            Proto::Tcp => "tcp",
            Proto::Udp => "udp",
        };
        parts.push(format!("\"proto\":\"{}\"", proto));
        parts.push(format!("\"local\":\"{}:{}\"", key.local_ip, key.local_port));
        parts.push(format!(
            "\"remote\":\"{}:{}\"",
            key.remote_ip, key.remote_port
        ));
    }

    if let Some(info) = conn_info {
        parts.push(format!("\"pid\":{}", info.pid));
        parts.push(format!("\"comm\":\"{}\"", escape_json(&info.comm)));
    }

    format!("{{{}{}}}", parts.join(","), extra)
}

fn format_pretty_alert(
    ts: &str,
    kind: &AlertKind,
    severity: AlertSeverity,
    conn_key: Option<&ConnKey>,
    conn_info: Option<&ConnInfo>,
    style: OutputStyle,
) -> String {
    let alert_prefix = if style.color {
        "\x1b[31m[ALERT]\x1b[0m"
    } else {
        "[ALERT]"
    };

    let severity_str = match (severity, style.color) {
        (AlertSeverity::Critical, true) => "\x1b[1;31mCRITICAL\x1b[0m",
        (AlertSeverity::Warning, true) => "\x1b[1;33mWARNING\x1b[0m",
        (_, false) => severity.label(),
    };

    let kind_str = match kind {
        AlertKind::DomainMatch { domain, pattern } => {
            format!("domain_match | {} matched {}", domain, pattern)
        }
        AlertKind::MaxConnections { current, threshold } => {
            format!(
                "max_connections | {}/{} active connections",
                current, threshold
            )
        }
        AlertKind::MaxPerProvider {
            provider,
            current,
            threshold,
        } => {
            format!(
                "max_per_provider | {}: {}/{} connections",
                provider.label(),
                current,
                threshold
            )
        }
        AlertKind::LongDuration {
            duration_ms,
            threshold_ms,
        } => {
            format!("long_duration | {}ms > {}ms", duration_ms, threshold_ms)
        }
        AlertKind::UnknownDomain { remote_ip } => {
            format!("unknown_domain | unresolved: {}", remote_ip)
        }
    };

    let conn_str = if let (Some(key), Some(info)) = (conn_key, conn_info) {
        let proto = match key.proto {
            Proto::Tcp => "tcp",
            Proto::Udp => "udp",
        };
        format!(
            " | pid={} | {} | {} | {}:{} -> {}:{}",
            info.pid,
            info.comm,
            proto,
            key.local_ip,
            key.local_port,
            key.remote_ip,
            key.remote_port
        )
    } else {
        String::new()
    };

    format!(
        "{} {} | {} | {}{}",
        alert_prefix, ts, severity_str, kind_str, conn_str
    )
}

/// A connection-level alert condition resolved without consulting cooldown state.
enum ConnectionAlertTrigger {
    DomainPattern { domain: String, pattern: String },
    UnknownDomain { remote_ip: std::net::IpAddr },
}

/// Pure predicate: which connection-level alert (if any) applies to this
/// connection. The single decision point in `check_connection_alerts` consumes
/// this before consulting `AlertState`.
fn connection_alert_trigger(
    alert_config: &AlertConfig,
    domain: Option<&str>,
    remote_ip: std::net::IpAddr,
) -> Option<ConnectionAlertTrigger> {
    if !alert_config.is_enabled() {
        return None;
    }

    // Check domain patterns
    if let Some(pattern) = check_domain_patterns(domain, &alert_config.domain_patterns) {
        return Some(ConnectionAlertTrigger::DomainPattern {
            domain: domain.unwrap_or_default().to_string(),
            pattern,
        });
    }

    // Check unknown domain
    if alert_config.alert_unknown_domain && domain.is_none() {
        return Some(ConnectionAlertTrigger::UnknownDomain { remote_ip });
    }

    None
}

/// Check connection-level alerts (domain pattern, unknown domain). Returns true
/// only when an alert actually emitted; cooldown-suppressed alerts return false
/// so the durable event row is flagged solely for alerts the operator saw.
fn check_connection_alerts(
    alert_config: &AlertConfig,
    alert_state: &mut AlertState,
    key: &ConnKey,
    info: &ConnInfo,
    json_mode: bool,
    style: OutputStyle,
    log_writer: Option<&Arc<LogWriter>>,
) -> bool {
    let trigger =
        match connection_alert_trigger(alert_config, info.domain.as_deref(), key.remote_ip) {
            Some(trigger) => trigger,
            None => return false,
        };

    match trigger {
        ConnectionAlertTrigger::DomainPattern { domain, pattern } => {
            let sig = AlertSignature::DomainMatch {
                domain: domain.clone(),
                pattern: pattern.clone(),
            };
            if should_emit_alert(alert_state, &sig, alert_config.cooldown_ms) {
                emit_alert(
                    &AlertKind::DomainMatch { domain, pattern },
                    AlertSeverity::Critical,
                    Some(key),
                    Some(info),
                    alert_config.bell,
                    json_mode,
                    style,
                    log_writer,
                );
                true
            } else {
                false
            }
        }
        ConnectionAlertTrigger::UnknownDomain { remote_ip } => {
            let sig = AlertSignature::UnknownDomain { remote_ip };
            if should_emit_alert(alert_state, &sig, alert_config.cooldown_ms) {
                emit_alert(
                    &AlertKind::UnknownDomain { remote_ip },
                    AlertSeverity::Warning,
                    Some(key),
                    Some(info),
                    alert_config.bell,
                    json_mode,
                    style,
                    log_writer,
                );
                true
            } else {
                false
            }
        }
    }
}

/// Check threshold-level alerts (max connections, max per provider). Returns one
/// synthesized `event='alert'` row per emitted breach so threshold kinds are
/// queryable via `WHERE alert=1` alongside connect/close flags.
fn check_threshold_alerts(
    alert_config: &AlertConfig,
    alert_state: &mut AlertState,
    stats: &Stats,
    run_id: &str,
    ts: &str,
    json_mode: bool,
    style: OutputStyle,
    log_writer: Option<&Arc<LogWriter>>,
) -> Vec<SqliteEvent> {
    if !alert_config.is_enabled() {
        return Vec::new();
    }

    let mut rows = Vec::new();

    // Check max connections threshold
    if let Some(threshold) = alert_config.max_connections {
        if stats.active >= threshold {
            let sig = AlertSignature::MaxConnections;
            if should_emit_alert(alert_state, &sig, alert_config.cooldown_ms) {
                emit_alert(
                    &AlertKind::MaxConnections {
                        current: stats.active,
                        threshold,
                    },
                    AlertSeverity::Warning,
                    None,
                    None,
                    alert_config.bell,
                    json_mode,
                    style,
                    log_writer,
                );
                rows.push(synthesized_alert_event(ts, run_id, Provider::Unknown));
            }
        }
    }

    // Check max per provider threshold
    if let Some(threshold) = alert_config.max_per_provider {
        for (provider, count) in &stats.active_per_provider {
            if *count >= threshold {
                let sig = AlertSignature::MaxPerProvider {
                    provider: *provider,
                };
                if should_emit_alert(alert_state, &sig, alert_config.cooldown_ms) {
                    emit_alert(
                        &AlertKind::MaxPerProvider {
                            provider: *provider,
                            current: *count,
                            threshold,
                        },
                        AlertSeverity::Warning,
                        None,
                        None,
                        alert_config.bell,
                        json_mode,
                        style,
                        log_writer,
                    );
                    rows.push(synthesized_alert_event(ts, run_id, *provider));
                }
            }
        }
    }

    rows
}

/// Threshold breaches have no natural per-connection row; synthesize one carrying
/// `alert=1` with NULL pid and zeroed endpoint columns.
fn synthesized_alert_event(ts: &str, run_id: &str, provider: Provider) -> SqliteEvent {
    SqliteEvent {
        ts: ts.to_string(),
        run_id: run_id.to_string(),
        event: "alert".to_string(),
        key: ConnKey {
            inode: 0,
            process: ProcessIdentity::default(),
            root: ProcessIdentity::default(),
            provider,
            provider_origin: None,
            proto: Proto::Tcp,
            socket_kind: SocketKind::Connection,
            local_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            local_port: 0,
            remote_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            remote_port: 0,
        },
        pid: None,
        comm: String::new(),
        cmdline: String::new(),
        provider,
        domain: None,
        domain_source: None,
        ancestry_path: None,
        duration_ms: None,
        alert: true,
        retry_count: None,
        ownership_json: None,
        observation_id: None,
    }
}

/// Check if a close event would trigger a duration alert (without emitting).
fn would_trigger_duration_alert(alert_config: &AlertConfig, duration_ms: Option<u64>) -> bool {
    if !alert_config.is_enabled() {
        return false;
    }

    if let (Some(threshold_ms), Some(ms)) = (alert_config.duration_threshold_ms, duration_ms) {
        return ms > threshold_ms;
    }

    false
}

/// Check duration alerts on connection close. Returns true only when the alert
/// actually emitted; cooldown-suppressed alerts return false so the durable
/// close row is flagged solely for alerts the operator saw.
fn check_duration_alert(
    alert_config: &AlertConfig,
    alert_state: &mut AlertState,
    key: &ConnKey,
    info: &ConnInfo,
    duration_ms: u64,
    json_mode: bool,
    style: OutputStyle,
    log_writer: Option<&Arc<LogWriter>>,
) -> bool {
    if !would_trigger_duration_alert(alert_config, Some(duration_ms)) {
        return false;
    }

    let threshold_ms = match alert_config.duration_threshold_ms {
        Some(threshold) => threshold,
        None => return false,
    };

    let sig = AlertSignature::LongDuration {
        conn_key: key.clone(),
    };
    if should_emit_alert(alert_state, &sig, alert_config.cooldown_ms) {
        emit_alert(
            &AlertKind::LongDuration {
                duration_ms,
                threshold_ms,
            },
            AlertSeverity::Warning,
            Some(key),
            Some(info),
            alert_config.bell,
            json_mode,
            style,
            log_writer,
        );
        true
    } else {
        false
    }
}

fn format_json_retry_warning(warning: &RetryWarning) -> String {
    format!(
        r#"{{"type":"retry_warning","count":{},"endpoint":"{}:{}","window_seconds":{}}}"#,
        warning.count, warning.endpoint.0, warning.endpoint.1, warning.window_seconds
    )
}

fn emit_event(
    ts: &str,
    event: &str,
    run_id: &str,
    key: &ConnKey,
    pid: u32,
    comm: &str,
    cmdline: &str,
    log_cmdline: Option<&str>,
    provider: Provider,
    domain: Option<&str>,
    domain_source: Option<&str>,
    ancestry: Option<&[String]>,
    duration_ms: Option<u64>,
    ownership_json: Option<&str>,
    domain_mode: &str,
    json_mode: bool,
    style: OutputStyle,
    log_format: LogFormat,
    log_writer: Option<&Arc<LogWriter>>,
) {
    // Cmdline shown on stdout; the durable file line may use a masked variant.
    let cmdline_for_log = log_cmdline.unwrap_or(cmdline);

    let proto = match key.proto {
        Proto::Tcp => "tcp",
        Proto::Udp => "udp",
    };
    let local = format!("{}:{}", key.local_ip, key.local_port);
    let remote = if key.socket_kind == SocketKind::Connection {
        format!("{}:{}", key.remote_ip, key.remote_port)
    } else {
        "none".to_string()
    };
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
            domain_source,
            domain_mode,
            ancestry,
            duration_ms,
            ownership_json,
        );
        println!("{}", line);
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
        ancestry,
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
        ancestry,
        duration_ms,
        Some(style),
    );

    if !json_mode {
        println!("{}", line_colored);
    }

    if let Some(writer) = log_writer {
        let output = match log_format {
            LogFormat::Json => format_json_event(
                ts,
                run_id,
                event,
                pid,
                comm,
                cmdline_for_log,
                provider.label(),
                proto,
                &local,
                &remote,
                dom,
                domain_source,
                domain_mode,
                ancestry,
                duration_ms,
                ownership_json,
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
    ancestry: Option<&[String]>,
    duration_ms: Option<u64>,
    style: Option<OutputStyle>,
) -> String {
    let style = style.unwrap_or(OutputStyle {
        color: false,
        theme: Theme::Mono,
    });

    let event_label = match event {
        "connect" => "+ connect",
        "listen" => "+ listen",
        "bind" => "+ bind",
        "close" => "- close",
        _ => event,
    };

    let event_text = paint(
        event_label,
        style.event_color(event),
        true,
        false,
        style.color,
    );
    let provider_text = paint(
        provider.label(),
        style.provider_color(provider),
        true,
        false,
        style.color,
    );
    let pid_text = paint(
        &format!("pid={}", pid),
        Some(AnsiColor::BrightCyan),
        true,
        false,
        style.color,
    );
    let comm_text = paint(comm, Some(AnsiColor::BrightWhite), true, false, style.color);
    let proto_text = paint(
        proto,
        Some(AnsiColor::BrightMagenta),
        true,
        false,
        style.color,
    );
    let domain_text = if domain == "unknown" {
        paint(
            domain,
            Some(AnsiColor::BrightBlack),
            false,
            true,
            style.color,
        )
    } else {
        paint(
            domain,
            Some(AnsiColor::BrightWhite),
            false,
            false,
            style.color,
        )
    };
    let ts_text = if style.color {
        paint(ts, Some(AnsiColor::BrightBlack), false, true, style.color)
    } else {
        ts.to_string()
    };

    let duration_text = duration_ms
        .map(|ms| format!(" dur={}ms", ms))
        .unwrap_or_default();
    let process_text = if let Some(chain) = ancestry {
        if chain.is_empty() {
            format!("{} | {}", pid_text, comm_text)
        } else {
            let display = truncate_ancestry_list(chain);
            let joined = display.join(" \u{2192} ");
            paint(
                &joined,
                Some(AnsiColor::BrightWhite),
                true,
                false,
                style.color,
            )
        }
    } else {
        format!("{} | {}", pid_text, comm_text)
    };

    format!(
        "{} | {} | {} | {} | {} | {} <-> {} | domain={}{}",
        ts_text,
        event_text,
        provider_text,
        process_text,
        proto_text,
        local,
        remote,
        domain_text,
        duration_text,
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
    domain_source: Option<&str>,
    domain_mode: &str,
    ancestry: Option<&[String]>,
    duration_ms: Option<u64>,
    ownership_json: Option<&str>,
) -> String {
    let mut out = String::new();
    out.push('{');
    push_json_str(&mut out, "ts", ts, true);
    push_json_str(&mut out, "run_id", run_id, false);
    push_json_str(&mut out, "event", event, false);
    push_json_num(&mut out, "pid", pid as i64, false);
    push_json_str(&mut out, "comm", comm, false);
    push_json_str(&mut out, "cmdline", cmdline, false);
    if let Some(ownership) = ownership_json {
        push_json_str(&mut out, "ownership_json", ownership, false);
    }
    push_json_str(&mut out, "provider", provider, false);
    push_json_str(&mut out, "proto", proto, false);
    push_json_str(&mut out, "local", local, false);
    push_json_str(&mut out, "remote", remote, false);
    push_json_str(&mut out, "domain", domain, false);
    if let Some(source) = domain_source {
        push_json_str(&mut out, "domain_source", source, false);
    }
    push_json_str(&mut out, "domain_mode", domain_mode, false);
    if let Some(list) = ancestry {
        push_json_array(&mut out, "ancestry", list, false);
    }
    if let Some(ms) = duration_ms {
        push_json_num(&mut out, "duration_ms", ms as i64, false);
    }
    out.push('}');
    out
}

fn summary(
    stats: &mut Stats,
    json_mode: bool,
    stats_top: usize,
    style: OutputStyle,
    domain_mode: &str,
    log_writer: Option<&Arc<LogWriter>>,
    alert_count: u64,
    suppressed_count: u64,
) {
    if let Some(writer) = log_writer {
        writer.flush();
        stats.log_failed = writer.failed.load(Ordering::Relaxed);
        writer.write_record(
            &format_json_summary(stats, domain_mode, alert_count, suppressed_count),
            &format!(
                "summary connects={} closes={} active={} peak_active={} sqlite_dropped={} alerts={} suppressed={} sqlite_observed={} sqlite_persisted={} sqlite_queue_lost={} sqlite_write_lost={} sqlite_metadata_lost={} sqlite_failed={} log_failed={} listens={} binds={} observation_errors={} socket_active={} socket_closes={} capture_health={} ptr_health={}",
                stats.connects,
                stats.closes,
                stats.active,
                stats.peak_active,
                stats.sqlite_dropped,
                alert_count,
                suppressed_count,
                stats.sqlite_outcome.observed, stats.sqlite_outcome.persisted,
                stats.sqlite_outcome.queue_lost, stats.sqlite_outcome.write_lost,
                stats.sqlite_outcome.metadata_lost,
                stats.sqlite_outcome.failed, stats.log_failed, stats.listens, stats.binds, stats.observation_errors, stats.socket_active, stats.socket_closes,
                stats.capture_health.as_ref().map(format_capture_health_json).unwrap_or_else(|| "null".to_string()),
                stats.ptr_health.as_ref().map(format_ptr_health_json).unwrap_or_else(|| "null".to_string())
            ),
        );
        writer.flush();
        stats.log_failed = writer.failed.load(Ordering::Relaxed);
    }
    if json_mode {
        let line = format_json_summary(stats, domain_mode, alert_count, suppressed_count);
        println!("{}", line);
        return;
    }

    println!(
        "{}",
        paint("Summary", style.accent(), true, false, style.color)
    );
    println!(
        "  {} {}",
        paint(
            "connects",
            Some(AnsiColor::BrightWhite),
            true,
            false,
            style.color
        ),
        paint(
            &stats.connects.to_string(),
            Some(AnsiColor::BrightGreen),
            true,
            false,
            style.color
        )
    );
    println!(
        "  {} {}",
        paint(
            "closes",
            Some(AnsiColor::BrightWhite),
            true,
            false,
            style.color
        ),
        paint(
            &stats.closes.to_string(),
            Some(AnsiColor::BrightYellow),
            true,
            false,
            style.color
        )
    );
    println!(
        "  {} {} (peak={})",
        paint(
            "active",
            Some(AnsiColor::BrightWhite),
            true,
            false,
            style.color
        ),
        paint(
            &stats.active.to_string(),
            Some(AnsiColor::BrightCyan),
            true,
            false,
            style.color
        ),
        stats.peak_active
    );
    if stats.sqlite_dropped > 0 {
        println!(
            "  {} {}",
            paint(
                "sqlite_dropped",
                Some(AnsiColor::BrightWhite),
                true,
                false,
                style.color
            ),
            paint(
                &stats.sqlite_dropped.to_string(),
                Some(AnsiColor::BrightRed),
                true,
                false,
                style.color
            )
        );
    }
    if stats.sqlite_enabled {
        println!(
            "  sqlite observed={} persisted={} queue_lost={} write_lost={} metadata_lost={} failed={}",
            stats.sqlite_outcome.observed,
            stats.sqlite_outcome.persisted,
            stats.sqlite_outcome.queue_lost,
            stats.sqlite_outcome.write_lost,
            stats.sqlite_outcome.metadata_lost,
            stats.sqlite_outcome.failed
        );
    }
    if stats.log_failed {
        println!("  file log failed");
    }
    if let Some(health) = &stats.capture_health {
        println!("  pcap {}", format_capture_health_json(health));
    }
    if let Some(health) = &stats.ptr_health {
        println!("  ptr {}", format_ptr_health_json(health));
    }
    println!(
        "  listens={} binds={} observation_errors={}",
        stats.listens, stats.binds, stats.observation_errors
    );

    if alert_count > 0 || suppressed_count > 0 {
        let alert_text = if suppressed_count > 0 {
            format!("{} ({} suppressed)", alert_count, suppressed_count)
        } else {
            alert_count.to_string()
        };
        println!(
            "  {} {}",
            paint(
                "alerts",
                Some(AnsiColor::BrightWhite),
                true,
                false,
                style.color
            ),
            paint(
                &alert_text,
                Some(AnsiColor::BrightRed),
                true,
                false,
                style.color
            )
        );
    }

    if stats.duration_ms_samples > 0 {
        let avg = stats
            .duration_ms_total
            .checked_div(stats.duration_ms_samples)
            .unwrap_or(0);
        println!(
            "  {} {}ms (max={}ms)",
            paint(
                "avg_duration",
                Some(AnsiColor::BrightWhite),
                true,
                false,
                style.color
            ),
            paint(
                &avg.to_string(),
                Some(AnsiColor::BrightCyan),
                true,
                false,
                style.color
            ),
            stats.duration_ms_max
        );
    }

    if !stats.per_provider.is_empty() {
        println!(
            "{}",
            paint("  Providers", style.accent(), true, false, style.color)
        );
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
        println!(
            "{}",
            paint("  Top Domains", style.accent(), true, false, style.color)
        );
        for (name, count) in top_n_string(&stats.per_domain, stats_top) {
            println!("    {} {}", count, name);
        }
    }

    if !stats.per_ip.is_empty() {
        println!(
            "{}",
            paint("  Top IPs", style.accent(), true, false, style.color)
        );
        for (ip, count) in top_n_string(&stats.per_ip, stats_top) {
            println!("    {} {}", count, ip);
        }
    }

    if !stats.per_comm.is_empty() {
        println!(
            "{}",
            paint("  Top Processes", style.accent(), true, false, style.color)
        );
        for (comm, count) in top_n_string(&stats.per_comm, stats_top) {
            println!("    {} {}", count, comm);
        }
    }
}

fn format_ptr_health_json(health: &PtrHealth) -> String {
    format!(
        "{{\"requested\":{},\"completed\":{},\"unresolved\":{},\"deferred\":{},\"expired\":{},\"evicted\":{},\"pending\":{},\"cached\":{},\"oldest_pending_ms\":{},\"failed\":{},\"cache_max\":{},\"queue_capacity\":{},\"workers\":{}}}",
        health.requested,
        health.completed,
        health.unresolved,
        health.deferred,
        health.expired,
        health.evicted,
        health.pending,
        health.cached,
        health.oldest_pending_ms,
        health.failed,
        PTR_CACHE_MAX,
        PTR_QUEUE_CAPACITY,
        PTR_WORKERS
    )
}

fn format_capture_health_json(health: &pcap_capture::CaptureHealth) -> String {
    let mut out = format!(
        "{{\"state\":\"{}\",\"offline\":{},\"packets\":{},\"rejected_frames\":{},\"mappings\":{},\"delivered\":{},\"drained\":{},\"mapping_lost\":{},\"kernel_dropped\":{},\"interface_dropped\":{},\"idle_polls\":{},\"unhealthy\":{}",
        health.state,
        health.offline,
        health.packets,
        health.rejected_frames,
        health.mappings,
        health.delivered,
        health.drained,
        health.mapping_lost,
        health.kernel_dropped,
        health.interface_dropped,
        health.idle_polls,
        health.unhealthy()
    );
    if let Some(error) = &health.error {
        push_json_str(&mut out, "error", error, false);
    }
    out.push('}');
    out
}

fn format_json_summary(
    stats: &Stats,
    domain_mode: &str,
    alert_count: u64,
    suppressed_count: u64,
) -> String {
    let mut out = String::new();
    out.push('{');
    out.push_str("\"summary\":{");
    push_json_num(&mut out, "connects", stats.connects as i64, true);
    push_json_num(&mut out, "listens", stats.listens as i64, false);
    push_json_num(&mut out, "binds", stats.binds as i64, false);
    push_json_num(&mut out, "socket_active", stats.socket_active as i64, false);
    push_json_num(&mut out, "socket_closes", stats.socket_closes as i64, false);
    push_json_num(
        &mut out,
        "observation_errors",
        stats.observation_errors as i64,
        false,
    );
    push_json_num(&mut out, "closes", stats.closes as i64, false);
    push_json_num(&mut out, "active", stats.active as i64, false);
    push_json_num(&mut out, "peak_active", stats.peak_active as i64, false);
    push_json_num(
        &mut out,
        "sqlite_dropped",
        stats.sqlite_dropped as i64,
        false,
    );
    out.push_str(",\"sqlite\":{");
    out.push_str(&format!("\"enabled\":{},\"observed\":{},\"persisted\":{},\"queue_lost\":{},\"write_lost\":{},\"metadata_lost\":{},\"failed\":{}",
        stats.sqlite_enabled, stats.sqlite_outcome.observed, stats.sqlite_outcome.persisted,
        stats.sqlite_outcome.queue_lost, stats.sqlite_outcome.write_lost, stats.sqlite_outcome.metadata_lost, stats.sqlite_outcome.failed));
    if let Some(error) = &stats.sqlite_outcome.error {
        push_json_str(&mut out, "error", error, false);
    }
    out.push('}');
    out.push_str(&format!(",\"log_failed\":{}", stats.log_failed));
    if let Some(health) = &stats.capture_health {
        out.push_str(",\"pcap\":");
        out.push_str(&format_capture_health_json(health));
    }
    if let Some(health) = &stats.ptr_health {
        out.push_str(",\"ptr\":");
        out.push_str(&format_ptr_health_json(health));
    }
    push_json_num(&mut out, "alerts", alert_count as i64, false);
    push_json_num(
        &mut out,
        "alerts_suppressed",
        suppressed_count as i64,
        false,
    );
    if stats.duration_ms_samples > 0 {
        let avg = stats
            .duration_ms_total
            .checked_div(stats.duration_ms_samples)
            .unwrap_or(0);
        push_json_num(&mut out, "avg_duration_ms", avg as i64, false);
        push_json_num(
            &mut out,
            "max_duration_ms",
            stats.duration_ms_max as i64,
            false,
        );
    }
    push_json_map_ip(&mut out, "per_ip", &stats.per_ip, false);
    push_json_map_str(&mut out, "per_domain", &stats.per_domain, false);
    push_json_map_u32(&mut out, "per_pid", &stats.per_pid, false);
    push_json_map_str(&mut out, "per_comm", &stats.per_comm, false);
    push_json_map_provider(&mut out, "per_provider", &stats.per_provider, false);
    push_json_map_provider(
        &mut out,
        "active_per_provider",
        &stats.active_per_provider,
        false,
    );
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
        paint(
            "Live Stats [provider]",
            style.accent(),
            true,
            false,
            style.color
        )
    );
    for provider in providers {
        let count = *stats.per_provider.get(&provider).unwrap_or(&0);
        // `total` is `.max(1)`'d at its binding site so division is safe,
        // but clamp bar_len to width to guarantee the repeat allocation
        // stays bounded even if future callers drop that invariant or
        // `count > total` via a stale snapshot between reads.
        let bar_len = ((count as f64 / total as f64) * width as f64).round() as usize;
        let bar_len = bar_len.min(width);
        let bar_char = style.provider_bar_char(provider);
        let bar_plain = format!(
            "{:width$}",
            bar_char.to_string().repeat(bar_len),
            width = width
        );
        let bar = if style.color {
            paint(
                &bar_plain,
                style.provider_color(provider),
                false,
                false,
                style.color,
            )
        } else {
            bar_plain
        };
        // Include symbol prefix for colorblind theme
        let symbol = if style.theme == Theme::Colorblind {
            format!("{} ", style.provider_symbol(provider))
        } else {
            String::new()
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
            "  {}{:<10} | {} {} (domains={}, ips={})",
            symbol, label, bar, count, domains, ips
        );
    }
    println!(
        "  active={} peak={} avg_dur={}ms",
        stats.active,
        stats.peak_active,
        stats
            .duration_ms_total
            .checked_div(stats.duration_ms_samples)
            .unwrap_or(0)
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
    // Guard against max == 0: without this, `count / 0` is infinity (or
    // NaN when count is also 0), `(inf).round() as usize` saturates to
    // `usize::MAX` on current stable Rust, and `"█".repeat(usize::MAX)`
    // then tries to allocate ~3 × usize::MAX bytes and aborts the
    // process. The single in-tree caller already `.max(1)`s before
    // passing, so this is defense in depth — but any future caller that
    // forgets that invariant shouldn't be able to crash the binary.
    if max == 0 {
        return " ".repeat(width);
    }
    let bar_len = ((count as f64 / max as f64) * width as f64).round() as usize;
    // Clamp bar_len to width. `f64::round() as usize` can saturate to
    // `usize::MAX` on non-finite inputs (count == 0 && max == 0 was
    // handled above, but infinities from transitional arithmetic on
    // oddly-shaped callers are still possible), and it would
    // additionally be nonsensical to render a bar longer than the
    // total width even for sane inputs where count > max.
    let bar_len = bar_len.min(width);
    let bar_plain = format!("{:width$}", "█".repeat(bar_len), width = width);
    paint(&bar_plain, style.accent(), false, false, style.color)
}

fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(ch) = chars.next() {
        if ch == '\x1b' {
            for next in chars.by_ref() {
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
) -> Result<Option<Arc<LogWriter>>, String> {
    let path = if let Some(file) = &args.log_file {
        Some(file.clone())
    } else if let Some(dir) = &args.log_dir {
        fs::create_dir_all(dir)
            .map_err(|err| format!("cannot create log directory {}: {}", dir.display(), err))?;
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

    let Some(path) = path else {
        return Ok(None);
    };

    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|err| format!("cannot open requested log {}: {}", path.display(), err))?;

    Ok(Some(Arc::new(LogWriter {
        file: Mutex::new(file),
        format: resolved_format,
        failed: AtomicBool::new(false),
    })))
}

fn start_sqlite_writer(
    args: &MonitorArgs,
    run_ctx: RunContext,
    log_writer: Option<Arc<LogWriter>>,
) -> Result<SqliteWriter, String> {
    let queue_max = args.db_queue_max;
    let batch_size = args.db_batch_size;
    let flush_ms = args.db_flush_ms;
    let (sender, receiver) = mpsc::sync_channel(queue_max);
    let (ready_tx, ready_rx) = mpsc::sync_channel(1);
    let counters = Arc::new(SqliteCounters::default());
    let counters_clone = counters.clone();
    let log_clone = log_writer.clone();
    let path = args.sqlite_path.to_string();
    let handle = std::thread::spawn(move || {
        sqlite_writer_loop(
            path,
            run_ctx,
            receiver,
            ready_tx,
            log_clone,
            batch_size,
            flush_ms,
            counters_clone,
        );
    });

    let start_result = match ready_rx.recv() {
        Ok(result) => result,
        Err(_) => Err("sqlite writer failed to start".to_string()),
    };

    if let Err(err) = start_result {
        if handle.join().is_err() {
            return Err(format!("{}; sqlite writer thread panicked", err));
        }
        return Err(err);
    }

    let last_warn = SystemTime::now()
        .checked_sub(Duration::from_secs(SQLITE_DROP_WARN_INTERVAL_SECS))
        .unwrap_or_else(SystemTime::now);

    Ok(SqliteWriter {
        sender,
        handle: Some(handle),
        counters,
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
    counters: Arc<SqliteCounters>,
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

    if let Err(err) = conn.busy_timeout(Duration::from_millis(250)) {
        let _ = ready_tx.send(Err(format!("sqlite retry policy setup failed: {}", err)));
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
            Ok(SqliteMsg::Poll(poll)) => {
                flush_sqlite_batch(&mut conn, &batch, &counters, log_writer.as_ref());
                batch.clear();
                publish_session_poll(&mut conn, &poll, &counters, log_writer.as_ref());
                last_flush = SystemTime::now();
            }
            Ok(SqliteMsg::DomainUpdate(update)) => {
                flush_sqlite_batch(&mut conn, &batch, &counters, log_writer.as_ref());
                batch.clear();
                write_domain_update(&mut conn, &update, &counters, log_writer.as_ref());
                last_flush = SystemTime::now();
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
            flush_sqlite_batch(&mut conn, &batch, &counters, log_writer.as_ref());
            batch.clear();
            last_flush = now;
        }
    }

    while let Ok(msg) = receiver.try_recv() {
        match msg {
            SqliteMsg::Event(event) => batch.push(event),
            SqliteMsg::Poll(poll) => {
                flush_sqlite_batch(&mut conn, &batch, &counters, log_writer.as_ref());
                batch.clear();
                publish_session_poll(&mut conn, &poll, &counters, log_writer.as_ref());
            }
            SqliteMsg::DomainUpdate(update) => {
                flush_sqlite_batch(&mut conn, &batch, &counters, log_writer.as_ref());
                batch.clear();
                write_domain_update(&mut conn, &update, &counters, log_writer.as_ref());
            }
            SqliteMsg::Shutdown {
                run_id,
                connects,
                closes,
            } => {
                shutdown = Some((run_id, connects, closes));
            }
        }
    }

    flush_sqlite_batch(&mut conn, &batch, &counters, log_writer.as_ref());

    if let Some((run_id, connects, closes)) = shutdown {
        if let Err(err) = finalize_session(&mut conn, &run_id, connects, closes) {
            counters.failure(
                format!("sqlite finalize failed: {}", err),
                log_writer.as_ref(),
            );
        }
    }
}

fn write_domain_update(
    conn: &mut Connection,
    update: &SqliteDomainUpdate,
    counters: &SqliteCounters,
    log_writer: Option<&Arc<LogWriter>>,
) {
    let mut failure = String::new();
    for attempt in 0..3 {
        let result = conn.execute("UPDATE events SET domain=?1,domain_source=?2,ownership_json=?3,alert=CASE WHEN ?4 THEN 1 ELSE alert END WHERE run_id=?5 AND observation_id=?6 AND event='connect'",
            params![update.domain.as_deref().unwrap_or("unknown"), update.domain_source, update.ownership_json,
                update.alert, update.run_id, update.observation_id]);
        match result {
            Ok(1) => return,
            Ok(count) => {
                failure = format!(
                    "hostname correction expected one socket observation, found {}",
                    count
                );
                break;
            }
            Err(error) => {
                let retryable = matches!(&error, rusqlite::Error::SqliteFailure(code, _) if matches!(code.code, rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked));
                failure = error.to_string();
                if !retryable || attempt == 2 {
                    break;
                }
                std::thread::sleep(Duration::from_millis(25 * (attempt + 1)));
            }
        }
    }
    counters.metadata_lost.fetch_add(1, Ordering::Relaxed);
    counters.failure(
        format!("sqlite hostname correction failed: {}", failure),
        log_writer,
    );
}

fn publish_session_poll(
    conn: &mut Connection,
    poll: &SessionPoll,
    counters: &SqliteCounters,
    log_writer: Option<&Arc<LogWriter>>,
) {
    let mut failure = None;
    for attempt in 0..3 {
        let result = conn.execute(
            "UPDATE sessions SET last_poll_ts=?1, active_at_poll=?2, poll_valid=?3, domain_mode=?5 WHERE run_id=?4",
            params![
                poll.ts,
                poll.active as i64,
                poll.valid && !counters.failed.load(Ordering::Relaxed),
                poll.run_id,
                poll.domain_mode
            ],
        );
        match result {
            Ok(1) => return,
            Ok(_) => {
                failure =
                    Some("monitoring session missing during poll-state publication".to_string());
                break;
            }
            Err(error) => {
                let retryable = matches!(&error, rusqlite::Error::SqliteFailure(code, _) if matches!(code.code, rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked));
                failure = Some(error.to_string());
                if !retryable || attempt == 2 {
                    break;
                }
                std::thread::sleep(Duration::from_millis(25 * (attempt + 1)));
            }
        }
    }
    counters.metadata_lost.fetch_add(1, Ordering::Relaxed);
    counters.failure(
        format!(
            "sqlite poll-state write failed: {}",
            failure.unwrap_or_else(|| "unknown failure".to_string())
        ),
        log_writer,
    );
}

fn flush_sqlite_batch(
    conn: &mut Connection,
    batch: &[SqliteEvent],
    counters: &SqliteCounters,
    log_writer: Option<&Arc<LogWriter>>,
) {
    if batch.is_empty() {
        return;
    }
    for attempt in 0..3 {
        match write_sqlite_batch(conn, batch) {
            Ok(()) => {
                counters
                    .persisted
                    .fetch_add(batch.len() as u64, Ordering::Relaxed);
                return;
            }
            Err(err) => {
                let retriable = matches!(
                    err.sqlite_error_code(),
                    Some(rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked)
                );
                if retriable && attempt < 2 {
                    std::thread::sleep(Duration::from_millis(25 * (attempt + 1)));
                    continue;
                }
                counters
                    .write_lost
                    .fetch_add(batch.len() as u64, Ordering::Relaxed);
                counters.failure(
                    format!(
                        "sqlite batch write failed after {} attempt(s): {}",
                        attempt + 1,
                        err
                    ),
                    log_writer,
                );
                return;
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

    self_update_unix(&update, &owner, &repo, &branch)
}

fn resolve_repo(update: &UpdateCommand) -> Result<(String, String), Box<dyn std::error::Error>> {
    const DEFAULT_OWNER: &str = "Dicklesworthstone";
    const DEFAULT_REPO: &str = "rano";

    if update.owner.is_some() || update.repo.is_some() {
        let owner = update.owner.clone().ok_or_else(
            || "Missing --owner (both --owner and --repo are required when overriding).",
        )?;
        let repo = update.repo.clone().ok_or_else(
            || "Missing --repo (both --owner and --repo are required when overriding).",
        )?;
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

fn update_installer_command(update: &UpdateCommand, owner: &str, repo: &str) -> ProcessCommand {
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

    let mut command = ProcessCommand::new("bash");
    command
        .args(["-s", "--"])
        .args(&args)
        .env("OWNER", owner)
        .env("REPO", repo)
        .stdin(std::process::Stdio::piped());
    command
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
    // Finish and verify the transport before starting an installer. A pipeline
    // can otherwise hide curl's failure behind a successful empty bash process.
    let download = ProcessCommand::new("curl")
        .args([
            "-fsSL",
            "--user-agent",
            "OpenAI File Downloader, XaiImageApiFetch/1.0",
            "--url",
            &script_url,
        ])
        .output()?;
    if !download.status.success() {
        return Err(format!(
            "Installer download failed with status {}: {}",
            download.status,
            String::from_utf8_lossy(&download.stderr).trim()
        )
        .into());
    }
    if download.stdout.is_empty() {
        return Err("Installer download was empty; refusing execution".into());
    }
    let mut installer = update_installer_command(update, owner, repo).spawn()?;
    let write_result = match installer.stdin.take() {
        Some(mut input) => input.write_all(&download.stdout),
        None => Err(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "Installer input pipe unavailable",
        )),
    };
    let status = installer.wait()?;
    write_result?;
    if !status.success() {
        return Err(format!("Installer failed with status {status}").into());
    }
    Ok(())
}

fn reverse_dns(ip: IpAddr) -> Option<String> {
    unsafe {
        let mut host = [0 as libc::c_char; libc::NI_MAXHOST as usize];
        let flags = libc::NI_NAMEREQD;
        match ip {
            IpAddr::V4(v4) => {
                let octets = v4.octets();
                // BSD-derived systems (macOS, FreeBSD, etc.) have sin_len field and u8 sin_family
                #[cfg(any(
                    target_os = "macos",
                    target_os = "freebsd",
                    target_os = "openbsd",
                    target_os = "netbsd",
                    target_os = "dragonfly"
                ))]
                let addr = libc::sockaddr_in {
                    sin_len: std::mem::size_of::<libc::sockaddr_in>() as u8,
                    sin_family: libc::AF_INET as u8,
                    sin_port: 0,
                    sin_addr: libc::in_addr {
                        s_addr: u32::from_ne_bytes(octets),
                    },
                    sin_zero: [0; 8],
                };
                // Linux and other POSIX systems use u16 sin_family and no sin_len
                #[cfg(not(any(
                    target_os = "macos",
                    target_os = "freebsd",
                    target_os = "openbsd",
                    target_os = "netbsd",
                    target_os = "dragonfly"
                )))]
                let addr = libc::sockaddr_in {
                    sin_family: libc::AF_INET as u16,
                    sin_port: 0,
                    sin_addr: libc::in_addr {
                        s_addr: u32::from_ne_bytes(octets),
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
                // BSD-derived systems have sin6_len field and u8 sin6_family
                #[cfg(any(
                    target_os = "macos",
                    target_os = "freebsd",
                    target_os = "openbsd",
                    target_os = "netbsd",
                    target_os = "dragonfly"
                ))]
                let addr = libc::sockaddr_in6 {
                    sin6_len: std::mem::size_of::<libc::sockaddr_in6>() as u8,
                    sin6_family: libc::AF_INET6 as u8,
                    sin6_port: 0,
                    sin6_flowinfo: 0,
                    sin6_addr: libc::in6_addr {
                        s6_addr: v6.octets(),
                    },
                    sin6_scope_id: 0,
                };
                // Linux and other POSIX systems
                #[cfg(not(any(
                    target_os = "macos",
                    target_os = "freebsd",
                    target_os = "openbsd",
                    target_os = "netbsd",
                    target_os = "dragonfly"
                )))]
                let addr = libc::sockaddr_in6 {
                    sin6_family: libc::AF_INET6 as u16,
                    sin6_port: 0,
                    sin6_flowinfo: 0,
                    sin6_addr: libc::in6_addr {
                        s6_addr: v6.octets(),
                    },
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
    argv: Vec<String>,
    provider: Provider,
    provider_origin: Option<ProcessIdentity>,
}

fn find_root_pids(
    patterns: &[String],
    excluded: &HashSet<u32>,
    explicit_pids: &[u32],
    snapshot: &ProcessSnapshot,
) -> Vec<u32> {
    let lowered: Vec<String> = patterns.iter().map(|p| p.to_lowercase()).collect();
    let mut roots = Vec::new();
    let mut seen: HashSet<u32> = HashSet::new();

    for pid in explicit_pids {
        if snapshot.stat.contains_key(pid) && !excluded.contains(pid) && seen.insert(*pid) {
            roots.push(*pid);
        }
    }

    if lowered.is_empty() {
        return roots;
    }

    for (&pid, meta) in &snapshot.meta {
        if !excluded.contains(&pid) && matches_process(meta, &lowered) && seen.insert(pid) {
            roots.push(pid);
        }
    }
    roots.sort_unstable();
    roots
}

fn matches_process(meta: &PidMeta, patterns: &[String]) -> bool {
    let comm = meta.comm.to_lowercase();
    let cmdline = meta.cmdline.to_lowercase();
    patterns
        .iter()
        .any(|pattern| comm.contains(pattern) || cmdline.contains(pattern))
}

fn excluded_processes(patterns: &[String], snapshot: &ProcessSnapshot) -> HashSet<u32> {
    if patterns.is_empty() {
        return HashSet::new();
    }
    let lowered: Vec<_> = patterns.iter().map(|p| p.to_lowercase()).collect();
    let roots: Vec<_> = snapshot
        .meta
        .iter()
        .filter_map(|(&pid, meta)| matches_process(meta, &lowered).then_some(pid))
        .collect();
    collect_descendants(&roots, snapshot)
}

fn collect_descendants(roots: &[u32], snapshot: &ProcessSnapshot) -> HashSet<u32> {
    let mut parent_map: HashMap<u32, Vec<u32>> = HashMap::new();
    for (&pid, stat) in &snapshot.stat {
        parent_map.entry(stat.ppid).or_default().push(pid);
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

fn monitored_roots(
    roots: &[u32],
    no_descendants: bool,
    snapshot: &ProcessSnapshot,
    excluded: &HashSet<u32>,
) -> HashMap<u32, ProcessIdentity> {
    let root_set: HashSet<_> = roots.iter().copied().collect();
    let candidates = if no_descendants {
        root_set.clone()
    } else {
        collect_descendants(roots, snapshot)
    };
    let mut result = HashMap::new();
    for pid in candidates {
        if excluded.contains(&pid) {
            continue;
        }
        let mut current = pid;
        let mut seen = HashSet::new();
        while seen.insert(current) {
            let Some(stat) = snapshot.stat.get(&current) else {
                break;
            };
            if root_set.contains(&current) {
                result.insert(pid, stat.identity);
                break;
            }
            current = stat.ppid;
        }
    }
    result
}

fn preserve_unobservable_keys<'a>(
    keys: impl Iterator<Item = &'a ConnKey>,
    unobservable: &HashSet<u32>,
    snapshot: &ProcessSnapshot,
) -> HashSet<ConnKey> {
    keys.filter(|key| {
        unobservable.contains(&key.process.pid)
            && snapshot
                .stat
                .get(&key.process.pid)
                .is_none_or(|stat| stat.identity == key.process)
    })
    .cloned()
    .collect()
}

struct InodeScan {
    owners: HashMap<u64, Vec<ProcessIdentity>>,
    errors: Vec<(u32, String)>,
}

fn map_inodes(targets: &HashSet<u32>, snapshot: &ProcessSnapshot) -> InodeScan {
    let mut map: HashMap<u64, Vec<ProcessIdentity>> = HashMap::new();
    let mut errors = Vec::new();
    let own_namespace = fs::read_link("/proc/self/ns/net");
    for pid in targets {
        let Some(stat) = snapshot.stat.get(pid) else {
            continue;
        };
        if read_proc_stat(*pid).as_ref() != Some(stat) {
            if Path::new(&format!("/proc/{}", pid)).exists() {
                errors.push((*pid, format!("PID {} identity/topology changed or became unreadable before fd scan; poll snapshot rejected", pid)));
            }
            continue;
        }
        match (
            own_namespace.as_ref(),
            fs::read_link(format!("/proc/{}/ns/net", pid)),
        ) {
            (Ok(ours), Ok(theirs))
                if ours.as_os_str().is_empty() || theirs.as_os_str().is_empty() =>
            {
                errors.push((
                    *pid,
                    format!(
                        "cannot inspect network namespace for PID {}: inaccessible namespace link",
                        pid
                    ),
                ));
                continue;
            }
            (Ok(ours), Ok(theirs)) if *ours == theirs => {}
            (_, Err(error)) if error.kind() == io::ErrorKind::NotFound => continue,
            (Ok(_), Ok(_)) => {
                errors.push((*pid, format!("PID {} is in another network namespace; this /proc backend cannot observe its endpoints", pid)));
                continue;
            }
            (ours, theirs) => {
                errors.push((
                    *pid,
                    format!(
                        "cannot inspect network namespace for PID {}: {:?}, {:?}",
                        pid,
                        ours.err(),
                        theirs.err()
                    ),
                ));
                continue;
            }
        }
        let fd_dir = format!("/proc/{}/fd", pid);
        let entries = match fs::read_dir(&fd_dir) {
            Ok(entries) => entries,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => {
                errors.push((*pid, format!("cannot inspect {}: {}", fd_dir, error)));
                continue;
            }
        };
        let mut process_inodes = Vec::new();
        for entry in entries {
            let entry = match entry {
                Ok(entry) => entry,
                Err(error) => {
                    errors.push((*pid, format!("cannot enumerate {}: {}", fd_dir, error)));
                    continue;
                }
            };
            match fs::read_link(entry.path()) {
                Ok(link) => {
                    if let Some(inode) = parse_socket_inode(&link.to_string_lossy()) {
                        process_inodes.push(inode);
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => errors.push((
                    *pid,
                    format!("cannot inspect {}: {}", entry.path().display(), error),
                )),
            }
        }
        if read_proc_stat(*pid).as_ref() != Some(stat) {
            if Path::new(&format!("/proc/{}", pid)).exists() {
                errors.push((*pid, format!("PID {} identity/topology changed or became unreadable during fd scan; socket ownership rejected", pid)));
            }
            continue;
        }
        for inode in process_inodes {
            map.entry(inode).or_default().push(stat.identity);
        }
    }
    canonicalize_inode_owners(&mut map);
    InodeScan {
        owners: map,
        errors,
    }
}

fn canonicalize_inode_owners(map: &mut HashMap<u64, Vec<ProcessIdentity>>) {
    for owners in map.values_mut() {
        owners.sort_unstable();
        owners.dedup();
    }
}

fn collect_process_snapshot(matcher: &ProviderMatcher) -> ProcessSnapshot {
    let mut snapshot = ProcessSnapshot::default();
    for pid in list_pids() {
        snapshot_process(pid, matcher, &mut snapshot);
    }
    snapshot
}

fn collect_process_snapshot_for_scope(
    matcher: &ProviderMatcher,
    args: &MonitorArgs,
) -> ProcessSnapshot {
    if !args.no_descendants || !args.patterns.is_empty() || args.pids.is_empty() {
        return collect_process_snapshot(matcher);
    }
    // An explicit PID without descendants needs only its own identity and the
    // ancestor chains used by exclusions/ancestry. Scanning every unrelated
    // process can delay a poll past the existing status freshness boundary.
    let mut snapshot = ProcessSnapshot::default();
    let mut pending = args.pids.clone();
    let mut seen = HashSet::new();
    while let Some(pid) = pending.pop() {
        if pid != 0 && seen.insert(pid) {
            if let Some(parent) = snapshot_process(pid, matcher, &mut snapshot) {
                pending.push(parent);
            }
        }
    }
    snapshot
}

fn snapshot_process(
    pid: u32,
    matcher: &ProviderMatcher,
    snapshot: &mut ProcessSnapshot,
) -> Option<u32> {
    let before = read_proc_stat(pid)?;
    let argv = read_argv(pid).unwrap_or_default();
    let after = read_proc_stat(pid)?;
    if before != after {
        return None;
    }
    let comm = after.comm.clone();
    let cmdline = argv.join(" ");
    let provider = provider_from_text(&comm, &cmdline, matcher);
    let provider_origin = (provider != Provider::Unknown).then_some(after.identity);
    let parent = after.ppid;
    snapshot.stat.insert(pid, after);
    snapshot.meta.insert(
        pid,
        PidMeta {
            comm,
            cmdline,
            argv,
            provider,
            provider_origin,
        },
    );
    Some(parent)
}

fn provider_from_text(comm: &str, cmdline: &str, matcher: &ProviderMatcher) -> Provider {
    let text = format!("{} {}", comm.to_lowercase(), cmdline.to_lowercase());
    let matches: Vec<_> = [
        (Provider::Anthropic, &matcher.anthropic),
        (Provider::OpenAI, &matcher.openai),
        (Provider::Google, &matcher.google),
    ]
    .into_iter()
    .filter_map(|(provider, patterns)| {
        patterns
            .iter()
            .any(|pattern| text.contains(pattern))
            .then_some(provider)
    })
    .collect();
    if matches.len() == 1 {
        matches[0]
    } else {
        Provider::Unknown
    }
}

fn resolve_provider_meta(
    monitored: &HashMap<u32, ProcessIdentity>,
    snapshot: &ProcessSnapshot,
) -> HashMap<u32, PidMeta> {
    let mut resolved = HashMap::new();
    for &pid in monitored.keys() {
        let Some(original) = snapshot.meta.get(&pid) else {
            continue;
        };
        let mut meta = original.clone();
        if meta.provider == Provider::Unknown {
            let mut current = snapshot.stat.get(&pid).map(|stat| stat.ppid).unwrap_or(0);
            let mut seen = HashSet::from([pid]);
            while monitored.contains_key(&current) && seen.insert(current) {
                let Some(stat) = snapshot.stat.get(&current) else {
                    break;
                };
                if let Some(ancestor) = snapshot.meta.get(&current) {
                    if ancestor.provider != Provider::Unknown {
                        meta.provider = ancestor.provider;
                        meta.provider_origin = Some(stat.identity);
                        break;
                    }
                }
                current = stat.ppid;
            }
        }
        resolved.insert(pid, meta);
    }
    resolved
}

fn parse_socket_inode(link: &str) -> Option<u64> {
    let inode = link.strip_prefix("socket:[")?.strip_suffix(']')?;
    if !inode.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    inode.parse().ok()
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

fn decode_argv(data: &[u8]) -> Vec<String> {
    if data.is_empty() {
        return Vec::new();
    }
    let data = data.strip_suffix(&[0]).unwrap_or(data);
    data.split(|b| *b == 0)
        .map(|s| String::from_utf8_lossy(s).into_owned())
        .collect()
}

fn read_argv(pid: u32) -> Option<Vec<String>> {
    let path = format!("/proc/{}/cmdline", pid);
    let mut data = Vec::new();
    if let Ok(mut file) = fs::File::open(path) {
        if file.read_to_end(&mut data).is_ok() {
            return Some(decode_argv(&data));
        }
    }
    None
}

fn read_proc_stat(pid: u32) -> Option<ProcStat> {
    let path = format!("/proc/{}/stat", pid);
    let content = fs::read(path).ok()?;
    let stat = parse_proc_stat(&String::from_utf8_lossy(&content))?;
    (stat.identity.pid == pid).then_some(stat)
}

fn parse_proc_stat(content: &str) -> Option<ProcStat> {
    let (pid, rest) = content.split_once(' ')?;
    let pid = pid.parse::<u32>().ok()?;
    let rest = rest.strip_prefix('(')?;
    let end = rest.rfind(')')?;
    let comm = rest[..end].to_string();
    if !rest[end + 1..].starts_with(' ') {
        return None;
    }
    let fields: Vec<_> = rest[end + 1..].split_ascii_whitespace().collect();
    if fields.first()?.len() != 1 || !fields[0].as_bytes()[0].is_ascii_alphabetic() {
        return None;
    }
    let ppid = fields.get(1)?.parse().ok()?;
    let start_time = fields.get(19)?.parse().ok()?;
    Some(ProcStat {
        identity: ProcessIdentity { pid, start_time },
        ppid,
        comm,
    })
}

fn format_ownership_json(
    inode: u64,
    process: ProcessIdentity,
    root: ProcessIdentity,
    owners: &[ProcessIdentity],
    provider_origin: Option<ProcessIdentity>,
) -> String {
    let owners: Vec<_> = owners
        .iter()
        .map(|owner| {
            format!(
                "{{\"pid\":{},\"start_time\":\"{}\"}}",
                owner.pid, owner.start_time
            )
        })
        .collect();
    let origin = provider_origin
        .map(|origin| {
            format!(
                "{{\"pid\":{},\"start_time\":\"{}\",\"kind\":\"{}\"}}",
                origin.pid,
                origin.start_time,
                if origin == process {
                    "direct"
                } else {
                    "ancestor"
                }
            )
        })
        .unwrap_or_else(|| "null".to_string());
    format!(
        "{{\"inode\":\"{}\",\"pid\":{},\"start_time\":\"{}\",\"root_pid\":{},\"root_start_time\":\"{}\",\"owners\":[{}],\"provider_origin\":{}}}",
        inode,
        process.pid,
        process.start_time,
        root.pid,
        root.start_time,
        owners.join(","),
        origin
    )
}

fn socket_flow(key: &ConnKey) -> pcap_capture::FlowKey {
    pcap_capture::FlowKey {
        local_ip: key.local_ip,
        local_port: key.local_port,
        remote_ip: key.remote_ip,
        remote_port: key.remote_port,
    }
}

fn resolve_observed_domain(
    key: &ConnKey,
    previous: Option<&pcap_capture::DomainEvidence>,
    cache: Option<&mut pcap_capture::DomainCache>,
    dns: &mut Option<PtrResolver>,
    ptr_enabled: bool,
    not_before: SystemTime,
) -> pcap_capture::DomainEvidence {
    if key.socket_kind != SocketKind::Connection {
        return pcap_capture::DomainEvidence::default();
    }
    let mut evidence = cache
        .map(|cache| cache.lookup(socket_flow(key), key.inode, not_before))
        .unwrap_or_default();
    if evidence.hostname.is_none() && ptr_enabled {
        evidence.hostname = dns
            .as_mut()
            .and_then(|resolver| resolver.resolve(key.remote_ip));
        if evidence.hostname.is_none() {
            // Cache pressure/expiry must not erase a PTR name actually observed
            // on this same held socket while its refresh is still unresolved.
            // Preserve current DNS/SNI ambiguity; the old name remains reverse-IP
            // evidence, never promoted to a captured flow hostname.
            evidence.hostname = previous
                .filter(|previous| previous.source == Some(pcap_capture::DomainSource::Ptr))
                .and_then(|previous| previous.hostname.clone());
        }
        if evidence.hostname.is_some() {
            evidence.source = Some(pcap_capture::DomainSource::Ptr);
            evidence.scope = "reverse-ip";
            evidence.captured_at = None;
            evidence.offline = false;
        }
    }
    evidence
}

fn format_domain_evidence_json(evidence: &pcap_capture::DomainEvidence) -> String {
    let mut json = String::from("{");
    push_json_str(&mut json, "scope", evidence.scope, true);
    push_json_str(
        &mut json,
        "capture_kind",
        if evidence.captured_at.is_none() {
            "none"
        } else if evidence.offline {
            "offline"
        } else {
            "live"
        },
        false,
    );
    if let Some(time) = evidence
        .captured_at
        .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
    {
        if let Ok(seconds) = i64::try_from(time.as_secs()) {
            if let Ok(timestamp) = format_utc_seconds(seconds, time.subsec_nanos()) {
                push_json_str(&mut json, "captured_at", &timestamp, false);
            }
        }
    }
    json.push_str(&format!(
        ",\"dns_ambiguous\":{},\"sni_ambiguous\":{},\"dns_candidate_count\":{},\"dns_candidates\":[{}]}}",
        evidence.dns_candidate_count > 1,
        evidence.sni_ambiguous,
        evidence.dns_candidate_count,
        evidence
            .dns_candidates
            .iter()
            .map(|name| format!("\"{}\"", escape_json(name)))
            .collect::<Vec<_>>()
            .join(",")
    ));
    json
}

fn format_socket_ownership_json(
    inode: u64,
    process: ProcessIdentity,
    root: ProcessIdentity,
    owners: &[ProcessIdentity],
    provider_origin: Option<ProcessIdentity>,
    kind: SocketKind,
    state: &str,
    domain_evidence: Option<&str>,
    observation_id: Option<&str>,
) -> String {
    let mut json = format_ownership_json(inode, process, root, owners, provider_origin);
    json.pop();
    json.push_str(&format!(",\"socket_kind\":\"{}\",\"kernel_state\":\"{}\",\"direction\":\"unknown\",\"remote_present\":{}}}",
        kind.label(), escape_json(state), kind == SocketKind::Connection));
    json.pop();
    if let Some(evidence) = domain_evidence {
        json.push_str(",\"domain_evidence\":");
        json.push_str(evidence);
    }
    if let Some(id) = observation_id {
        push_json_str(&mut json, "observation_id", id, false);
    }
    json.push('}');
    json
}

fn gather_net_entries(include_udp: bool) -> Result<Vec<(Proto, NetEntry)>, String> {
    let mut entries = Vec::new();
    entries.extend(read_net_file("/proc/net/tcp", Proto::Tcp, false)?);
    entries.extend(read_net_file("/proc/net/tcp6", Proto::Tcp, true)?);
    if include_udp {
        entries.extend(read_net_file("/proc/net/udp", Proto::Udp, false)?);
        entries.extend(read_net_file("/proc/net/udp6", Proto::Udp, true)?);
    }
    Ok(entries)
}

fn read_net_file(path: &str, proto: Proto, ipv6: bool) -> Result<Vec<(Proto, NetEntry)>, String> {
    let mut result = Vec::new();
    let file =
        fs::File::open(path).map_err(|error| format!("cannot observe {}: {}", path, error))?;
    let reader = BufReader::new(file);

    for (idx, line_result) in reader.lines().enumerate() {
        if idx == 0 {
            continue;
        }
        let line = line_result.map_err(|error| format!("cannot read {}: {}", path, error))?;
        let entry = parse_net_entry(&line, ipv6)
            .ok_or_else(|| format!("malformed socket row in {} at line {}", path, idx + 1))?;
        result.push((proto, entry));
    }
    Ok(result)
}

fn parse_net_entry(line: &str, ipv6: bool) -> Option<NetEntry> {
    let parts: Vec<_> = line.split_ascii_whitespace().collect();
    if parts.len() < 10
        || parts[3].len() != 2
        || !parts[3].bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return None;
    }
    let (local_ip, local_port) = parse_addr_port(parts[1], ipv6)?;
    let (remote_ip, remote_port) = parse_addr_port(parts[2], ipv6)?;
    Some(NetEntry {
        local_ip,
        local_port,
        remote_ip,
        remote_port,
        inode: parts[9].parse().ok()?,
        state: parts[3].to_ascii_uppercase(),
    })
}

fn parse_addr_port(s: &str, ipv6: bool) -> Option<(IpAddr, u16)> {
    let mut iter = s.split(':');
    let addr_hex = iter.next()?;
    let port_hex = iter.next()?;
    if iter.next().is_some() || port_hex.len() != 4 {
        return None;
    }
    let port = u16::from_str_radix(port_hex, 16).ok()?;
    let ip = if ipv6 {
        IpAddr::V6(parse_ipv6(addr_hex)?)
    } else {
        IpAddr::V4(parse_ipv4(addr_hex)?)
    };
    Some((ip, port))
}

fn parse_ipv4(hex: &str) -> Option<Ipv4Addr> {
    if hex.len() != 8 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let raw = u32::from_str_radix(hex, 16).ok()?;
    let bytes = raw.to_le_bytes();
    Some(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]))
}

fn parse_ipv6(hex: &str) -> Option<Ipv6Addr> {
    if hex.len() != 32 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
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
// Export Subcommand
// ============================================================================

const EXPORT_FIELDS: &[&str] = &[
    "ts",
    "run_id",
    "event",
    "provider",
    "pid",
    "comm",
    "cmdline",
    "proto",
    "local_ip",
    "local_port",
    "remote_ip",
    "remote_port",
    "domain",
    "domain_source",
    "ancestry_path",
    "duration_ms",
    "alert",
    "retry_count",
    "ownership_json",
];

const PROVIDER_LABELS: &[&str] = &["anthropic", "openai", "google", "unknown"];

#[derive(Clone, Copy)]
enum FieldType {
    String,
    Integer,
}

#[derive(Clone, Debug, PartialEq)]
enum FieldValue {
    String(String),
    Integer(i64),
    Null,
}

// ============================================================================
// Config subcommand implementation
// ============================================================================

fn run_config(args: ConfigArgs) -> i32 {
    match args.subcommand {
        ConfigSubcommand::Check { options } => run_config_check(&options),
        ConfigSubcommand::Show { json, options } => run_config_show(json, &options),
        ConfigSubcommand::Paths => run_config_paths(),
    }
}

#[derive(Clone)]
struct ExportFilter {
    run_id: Option<String>,
    since: Option<String>,
    until: Option<String>,
    providers: Vec<String>,
    domain_patterns: Vec<String>,
}

fn redact_config_text(value: &str) -> String {
    if value.split_whitespace().any(|part| {
        part.starts_with('-')
            && looks_like_secret_key(part.trim_start_matches('-').split('=').next().unwrap_or(""))
    }) {
        return REDACTED_PLACEHOLDER.to_string();
    }
    let mut result = String::new();
    for part in value.split_inclusive(char::is_whitespace) {
        let token = part.trim_end_matches(char::is_whitespace);
        if Path::new(token).is_absolute() || token.starts_with("./") || token.starts_with("../") {
            result.push_str(token);
        } else {
            result.push_str(&mask_token(token));
        }
        result.push_str(&part[token.len()..]);
    }
    result
}

fn config_json_text(value: &str) -> String {
    format!("\"{}\"", escape_json(&redact_config_text(value)))
}

fn config_json_path(value: &str) -> String {
    format!("\"{}\"", escape_json(value))
}

fn config_json_list(values: &[String]) -> String {
    format!(
        "[{}]",
        values
            .iter()
            .map(|value| config_json_text(value))
            .collect::<Vec<_>>()
            .join(",")
    )
}

fn effective_config_values(args: &MonitorArgs) -> BTreeMap<&'static str, String> {
    fn optional(value: Option<String>) -> String {
        value.map_or_else(|| "null".to_string(), |value| config_json_text(&value))
    }
    fn optional_path(value: Option<&Path>) -> String {
        value.map_or_else(
            || "null".to_string(),
            |value| config_json_path(&value.to_string_lossy()),
        )
    }
    let stats_views: Vec<_> = args
        .stats_views
        .iter()
        .map(|view| format!("{view:?}").to_lowercase())
        .collect();
    BTreeMap::from([
        ("pattern", config_json_list(&args.patterns)),
        ("exclude_pattern", config_json_list(&args.exclude_patterns)),
        (
            "pid",
            format!(
                "[{}]",
                args.pids
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(",")
            ),
        ),
        ("no_descendants", args.no_descendants.to_string()),
        ("interval_ms", args.interval_ms.to_string()),
        ("json", args.json.to_string()),
        ("summary_only", args.summary_only.to_string()),
        (
            "domain_mode",
            config_json_text(&format!("{:?}", args.domain_mode).to_lowercase()),
        ),
        ("pcap", args.pcap.to_string()),
        ("no_dns", args.no_dns.to_string()),
        ("include_udp", args.include_udp.to_string()),
        ("include_listening", args.include_listening.to_string()),
        ("show_ancestry", args.show_ancestry.to_string()),
        ("log_file", optional_path(args.log_file.as_deref())),
        ("log_dir", optional_path(args.log_dir.as_deref())),
        (
            "log_format",
            config_json_text(&format!("{:?}", args.log_format).to_lowercase()),
        ),
        ("once", args.once.to_string()),
        (
            "color",
            config_json_text(&format!("{:?}", args.color).to_lowercase()),
        ),
        ("sqlite", config_json_path(&args.sqlite_path)),
        ("no_sqlite", args.no_sqlite.to_string()),
        ("db_batch_size", args.db_batch_size.to_string()),
        ("db_flush_ms", args.db_flush_ms.to_string()),
        ("db_queue_max", args.db_queue_max.to_string()),
        ("pcap_interface", optional(args.pcap_interface.clone())),
        (
            "pcap_cache_max",
            args.pcap_cache_max
                .unwrap_or(pcap_capture::DEFAULT_CACHE_MAX_ENTRIES)
                .to_string(),
        ),
        ("stats_interval_ms", args.stats_interval_ms.to_string()),
        ("stats_width", args.stats_width.to_string()),
        ("stats_top", args.stats_top.to_string()),
        ("stats_view", config_json_list(&stats_views)),
        ("stats_cycle_ms", args.stats_cycle_ms.to_string()),
        ("no_banner", args.no_banner.to_string()),
        (
            "theme",
            config_json_text(&format!("{:?}", args.theme).to_lowercase()),
        ),
        ("session_name", optional(args.session_name.clone())),
        (
            "alert_domain",
            config_json_list(&args.alert.domain_patterns),
        ),
        (
            "alert_max_connections",
            args.alert
                .max_connections
                .map_or_else(|| "null".to_string(), |value| value.to_string()),
        ),
        (
            "alert_max_per_provider",
            args.alert
                .max_per_provider
                .map_or_else(|| "null".to_string(), |value| value.to_string()),
        ),
        (
            "alert_duration_ms",
            args.alert
                .duration_threshold_ms
                .map_or_else(|| "null".to_string(), |value| value.to_string()),
        ),
        (
            "alert_unknown_domain",
            args.alert.alert_unknown_domain.to_string(),
        ),
        ("alert_bell", args.alert.bell.to_string()),
        ("alert_cooldown_ms", args.alert.cooldown_ms.to_string()),
        ("no_alerts", args.alert.no_alerts.to_string()),
        (
            "redact_cmdline",
            config_json_text(&format!("{:?}", args.redact_cmdline).to_lowercase()),
        ),
        ("retry_threshold", args.retry_threshold.to_string()),
        ("retry_window_ms", args.retry_window_ms.to_string()),
    ])
}

fn format_effective_config_json(args: &MonitorArgs) -> String {
    let effective = effective_config_values(args);
    let entries: Vec<_> = effective
        .iter()
        .map(|(key, value)| format!("{}:{value}", config_json_text(key)))
        .collect();
    let mut origins: Vec<_> = effective
        .keys()
        .map(|key| {
            format!(
                "{}:{}",
                config_json_text(key),
                config_json_path(
                    args.config_origins
                        .get(*key)
                        .map_or("defaults", String::as_str)
                )
            )
        })
        .collect();
    let mut provider_origins = BTreeMap::from([
        ("providers.anthropic", vec!["defaults".to_string()]),
        ("providers.openai", vec!["defaults".to_string()]),
        ("providers.google", vec!["defaults".to_string()]),
    ]);
    for source in &args.config_sources {
        if source.provider_mode == Some(ProviderMode::Replace) {
            for values in provider_origins.values_mut() {
                values.clear();
            }
        }
        for key in &source.keys {
            if let Some(values) = provider_origins.get_mut(key.as_str()) {
                values.push(source.origin.clone());
            }
        }
    }
    origins.extend(provider_origins.into_iter().map(|(key, values)| {
        format!(
            "{}:[{}]",
            config_json_text(key),
            values
                .iter()
                .map(|value| config_json_path(value))
                .collect::<Vec<_>>()
                .join(",")
        )
    }));
    let mut sources = vec!["{\"kind\":\"defaults\",\"origin\":\"defaults\"}".to_string()];
    sources.extend(args.config_sources.iter().map(|source| {
        format!(
            "{{\"kind\":{},\"origin\":{},\"keys\":{},\"provider_mode\":{}}}",
            config_json_text(source.kind),
            config_json_path(&source.origin),
            config_json_list(&source.keys),
            source.provider_mode.map_or_else(
                || "null".to_string(),
                |mode| config_json_text(&format!("{mode:?}").to_lowercase())
            )
        )
    }));
    format!(
        "{{\"effective\":{{{}}},\"origins\":{{{}}},\"providers\":{{\"anthropic\":{},\"openai\":{},\"google\":{}}},\"sources\":[{}],\"warnings\":{},\"introspection_redacted\":true,\"pcap_supported\":{}}}",
        entries.join(","),
        origins.join(","),
        config_json_list(&args.provider_matcher.anthropic),
        config_json_list(&args.provider_matcher.openai),
        config_json_list(&args.provider_matcher.google),
        sources.join(","),
        config_json_list(&args.warnings),
        pcap_capture::pcap_supported()
    )
}

fn run_config_show(json: bool, options: &[String]) -> i32 {
    let args = match load_monitor_args(options) {
        Ok(args) => args,
        Err(error) => {
            eprintln!("error: {}", redact_config_text(&error));
            return 1;
        }
    };
    if json {
        println!("{}", format_effective_config_json(&args));
    } else {
        println!("Effective configuration (credential masking applies):");
        for (key, value) in effective_config_values(&args) {
            println!(
                "{key}={value} (origin={})",
                config_json_path(
                    args.config_origins
                        .get(key)
                        .map_or("defaults", String::as_str)
                )
            );
        }
        println!(
            "Provider matcher: anthropic={} openai={} google={}",
            config_json_list(&args.provider_matcher.anthropic),
            config_json_list(&args.provider_matcher.openai),
            config_json_list(&args.provider_matcher.google)
        );
        for source in &args.config_sources {
            println!(
                "Source {}: {}",
                source.kind,
                config_json_path(&source.origin)
            );
        }
        for warning in &args.warnings {
            println!("{}", config_json_text(warning));
        }
    }
    0
}

fn run_config_paths() -> i32 {
    println!("Configuration file search locations:\n");

    if let Some(kv_path) = default_config_path() {
        let exists = kv_path.exists();
        let marker = if exists { "[found]" } else { "[not found]" };
        println!("  {} {}", kv_path.display(), marker);
    }

    println!();

    // TOML provider config paths
    println!("TOML provider config (rano.toml):");
    for toml_path in default_provider_config_paths() {
        let exists = toml_path.exists();
        let marker = if exists { "[found]" } else { "[not found]" };
        println!("  {} {}", toml_path.display(), marker);
    }

    println!();

    // Environment variables
    println!("Environment variables:");
    println!("  RANO_CONFIG       Override key-value config path");
    println!("  RANO_CONFIG_TOML  Override TOML config path");
    0
}

/// Validate every configured source: the default discovery paths plus any
/// explicit `--config` / `--config-toml` overrides and `RANO_CONFIG_TOML`,
/// mirroring what a monitor run actually loads.
fn run_config_check(options: &[String]) -> i32 {
    match load_monitor_args(options) {
        Ok(args) => {
            println!("Configuration is valid.");
            for source in &args.config_sources {
                println!(
                    "  [ok] {} {}",
                    source.kind,
                    config_json_text(&source.origin)
                );
            }
            for warning in &args.warnings {
                println!("warning: {}", redact_config_text(warning));
            }
            0
        }
        Err(error) => {
            eprintln!("error: {}", redact_config_text(&error));
            1
        }
    }
}

fn run_export(args: ExportArgs) -> Result<(), String> {
    let path = Path::new(&args.sqlite_path);
    if !path.exists() {
        return Err(format!("SQLite file not found: {}", args.sqlite_path));
    }

    let conn = Connection::open(path).map_err(|e| format!("Failed to open database: {}", e))?;
    configure_query_connection(&conn)
        .map_err(|error| format!("Failed to configure SQLite queries: {}", error))?;
    // Late-added columns: migrate idempotently so exports from older
    // databases still prepare their default-field SELECT.
    let mut conn = conn;
    let _ = ensure_column(&mut conn, "events", "domain_source", "TEXT");
    let _ = ensure_column(&mut conn, "events", "retry_count", "INTEGER");
    let _ = ensure_column(&mut conn, "events", "alert", "INTEGER");
    let _ = ensure_column(&mut conn, "events", "ancestry_path", "TEXT");
    let _ = ensure_column(&mut conn, "events", "ownership_json", "TEXT");

    let has_events = table_exists(&conn, "events")?;
    if !has_events {
        return Err(format!(
            "Database does not contain rano event data (missing events table). {}",
            schema_hint(&args.sqlite_path)
        ));
    }

    let fields = match args.fields.clone() {
        Some(fields) => fields,
        None => default_export_fields(),
    };
    validate_fields(&fields)?;

    let since = parse_time_filter(&args.since)?;
    let until = parse_time_filter(&args.until)?;
    validate_time_range(&since, &until)?;

    let providers = normalize_providers(&args.providers)?;
    let domain_patterns = normalize_domain_patterns(&args.domain_patterns)?;

    let filter = ExportFilter {
        run_id: args
            .run_id
            .as_ref()
            .map(|reference| resolve_session_reference(&conn, reference))
            .transpose()?,
        since,
        until,
        providers,
        domain_patterns,
    };

    let (sql, params) = build_export_query(&filter, &fields);

    setup_signal_handler();

    let mut writer = open_export_output(&args.output)?;
    if args.format == ExportFormat::Csv && !args.no_header {
        let header = format_csv_header(&fields);
        writer
            .write_all(header.as_bytes())
            .map_err(|e| format!("Write error: {}", e))?;
    }

    let mut stmt = conn
        .prepare(&sql)
        .map_err(|e| format!("Query error: {}", e))?;
    let params_refs: Vec<&dyn rusqlite::ToSql> =
        params.iter().map(|s| s as &dyn rusqlite::ToSql).collect();
    let mut rows = stmt
        .query(params_refs.as_slice())
        .map_err(|e| format!("Query error: {}", e))?;

    let mut row_count: usize = 0;
    while let Some(row) = rows
        .next()
        .map_err(|e| format!("Failed to read row: {}", e))?
    {
        if !RUNNING.load(Ordering::SeqCst) {
            break;
        }
        let values =
            row_to_values(row, &fields).map_err(|e| format!("Failed to read row: {}", e))?;
        let line = match args.format {
            ExportFormat::Csv => format_csv_row(&values),
            ExportFormat::Jsonl => format_jsonl_row(&values),
        };
        writer
            .write_all(line.as_bytes())
            .map_err(|e| format!("Write error: {}", e))?;
        row_count += 1;
        #[allow(clippy::manual_is_multiple_of)]
        if row_count % 1000 == 0 {
            writer.flush().map_err(|e| format!("Write error: {}", e))?;
        }
    }

    writer.flush().map_err(|e| format!("Write error: {}", e))?;
    Ok(())
}

fn default_export_fields() -> Vec<String> {
    EXPORT_FIELDS.iter().map(|f| f.to_string()).collect()
}

fn validate_fields(fields: &[String]) -> Result<(), String> {
    if fields.is_empty() {
        return Err("At least one field must be selected".to_string());
    }
    for field in fields {
        if !EXPORT_FIELDS.contains(&field.as_str()) {
            return Err(format!(
                "Unknown field '{}'. Valid fields: {}",
                field,
                EXPORT_FIELDS.join(", ")
            ));
        }
    }
    Ok(())
}

fn normalize_providers(values: &[String]) -> Result<Vec<String>, String> {
    if values.is_empty() {
        return Ok(Vec::new());
    }
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for value in values {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return Err("Invalid --provider value (empty)".to_string());
        }
        let lowered = trimmed.to_lowercase();
        if !PROVIDER_LABELS.contains(&lowered.as_str()) {
            return Err(format!(
                "Invalid provider '{}'. Use: {}",
                trimmed,
                PROVIDER_LABELS.join(", ")
            ));
        }
        if seen.insert(lowered.clone()) {
            out.push(lowered);
        }
    }
    Ok(out)
}

fn normalize_domain_patterns(values: &[String]) -> Result<Vec<String>, String> {
    if values.is_empty() {
        return Ok(Vec::new());
    }
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for value in values {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return Err("Invalid --domain value (empty)".to_string());
        }
        let lowered = trimmed.to_lowercase();
        if seen.insert(lowered.clone()) {
            out.push(lowered);
        }
    }
    Ok(out)
}

fn field_type(field: &str) -> FieldType {
    match field {
        "pid" | "local_port" | "remote_port" | "duration_ms" | "retry_count" | "alert" => {
            FieldType::Integer
        }
        _ => FieldType::String,
    }
}

fn row_to_values(
    row: &rusqlite::Row<'_>,
    fields: &[String],
) -> rusqlite::Result<Vec<(String, FieldValue)>> {
    let mut out = Vec::with_capacity(fields.len());
    for (idx, field) in fields.iter().enumerate() {
        let value = match field_type(field.as_str()) {
            FieldType::String => {
                let raw: Option<String> = row.get(idx)?;
                raw.map(FieldValue::String).unwrap_or(FieldValue::Null)
            }
            FieldType::Integer => {
                let raw: Option<i64> = row.get(idx)?;
                raw.map(FieldValue::Integer).unwrap_or(FieldValue::Null)
            }
        };
        out.push((field.clone(), value));
    }
    Ok(out)
}

fn format_csv_header(fields: &[String]) -> String {
    let mut line = fields.join(",");
    line.push_str("\r\n");
    line
}

fn format_csv_row(values: &[(String, FieldValue)]) -> String {
    let mut parts = Vec::with_capacity(values.len());
    for (_, value) in values {
        let text = match value {
            FieldValue::String(s) => s.clone(),
            FieldValue::Integer(n) => n.to_string(),
            FieldValue::Null => String::new(),
        };
        parts.push(csv_escape(&text));
    }
    let mut line = parts.join(",");
    line.push_str("\r\n");
    line
}

fn csv_escape(value: &str) -> String {
    if value.is_empty() {
        return String::new();
    }
    let needs_quotes =
        value.contains(',') || value.contains('"') || value.contains('\n') || value.contains('\r');
    if needs_quotes {
        let escaped = value.replace('"', "\"\"");
        format!("\"{}\"", escaped)
    } else {
        value.to_string()
    }
}

fn format_jsonl_row(values: &[(String, FieldValue)]) -> String {
    let mut map: BTreeMap<&str, &FieldValue> = BTreeMap::new();
    for (name, value) in values {
        map.insert(name.as_str(), value);
    }

    let mut parts: Vec<String> = Vec::new();
    for (name, value) in map {
        let json_value = match value {
            FieldValue::String(s) => Some(format!("\"{}\"", escape_json(s))),
            FieldValue::Integer(n) => Some(n.to_string()),
            FieldValue::Null => None,
        };
        if let Some(value_str) = json_value {
            parts.push(format!("\"{}\":{}", name, value_str));
        }
    }

    let mut line = String::from("{");
    line.push_str(&parts.join(","));
    line.push('}');
    line.push('\n');
    line
}

fn build_export_query(filter: &ExportFilter, fields: &[String]) -> (String, Vec<String>) {
    let field_list = fields.join(", ");
    let mut sql = format!("SELECT {} FROM events WHERE 1=1", field_list);
    let mut params: Vec<String> = Vec::new();

    if let Some(ref run_id) = filter.run_id {
        sql.push_str(" AND run_id = ?");
        params.push(run_id.clone());
    }
    if let Some(ref since) = filter.since {
        sql.push_str(" AND rano_utc(ts) >= rano_utc(?)");
        params.push(since.clone());
    }
    if let Some(ref until) = filter.until {
        sql.push_str(" AND rano_utc(ts) < rano_utc(?)");
        params.push(until.clone());
    }

    if !filter.providers.is_empty() {
        let placeholders: Vec<&str> = filter.providers.iter().map(|_| "?").collect();
        sql.push_str(&format!(
            " AND LOWER(provider) IN ({})",
            placeholders.join(",")
        ));
        params.extend(filter.providers.clone());
    }

    if !filter.domain_patterns.is_empty() {
        let conditions: Vec<String> = filter
            .domain_patterns
            .iter()
            .map(|_| "LOWER(domain) LIKE ? ESCAPE '\\'".to_string())
            .collect();
        sql.push_str(&format!(" AND ({})", conditions.join(" OR ")));
        for pattern in &filter.domain_patterns {
            params.push(glob_to_sql_like(pattern));
        }
    }

    sql.push_str(" ORDER BY rano_utc(ts) ASC, id ASC");
    (sql, params)
}

fn glob_to_sql_like(pattern: &str) -> String {
    let mut out = String::new();
    for ch in pattern.chars() {
        match ch {
            '%' | '_' | '\\' => {
                out.push('\\');
                out.push(ch);
            }
            '*' => out.push('%'),
            '?' => out.push('_'),
            _ => out.push(ch),
        }
    }
    out
}

fn open_export_output(path: &Option<PathBuf>) -> Result<Box<dyn Write>, String> {
    if let Some(output_path) = path {
        let file = fs::File::create(output_path)
            .map_err(|e| format!("Failed to create output file: {}", e))?;
        Ok(Box::new(BufWriter::new(file)))
    } else {
        Ok(Box::new(BufWriter::new(std::io::stdout())))
    }
}

// ============================================================================
// Diff Subcommand
// ============================================================================

fn run_diff(args: DiffArgs) -> Result<(), String> {
    let path = Path::new(&args.sqlite_path);
    if !path.exists() {
        return Err(format!("SQLite file not found: {}", args.sqlite_path));
    }

    let conn = Connection::open(path).map_err(|e| format!("Failed to open database: {}", e))?;
    configure_query_connection(&conn)
        .map_err(|error| format!("Failed to configure SQLite queries: {}", error))?;

    let has_events = table_exists(&conn, "events")?;
    if !has_events {
        return Err(format!(
            "Database does not contain rano event data (missing events table). {}",
            schema_hint(&args.sqlite_path)
        ));
    }

    // Compute the diff
    let result = compute_session_diff(&conn, &args.old_id, &args.new_id, args.threshold_pct)?;

    // Output
    let color_enabled = resolve_color_mode(args.color);
    if args.json {
        output_diff_json(&result)?;
    } else {
        output_diff_pretty(&result, color_enabled)?;
    }

    Ok(())
}

/// Compute a diff between two sessions identified by run_id.
fn compute_session_diff(
    conn: &Connection,
    old_id: &str,
    new_id: &str,
    threshold_pct: f64,
) -> Result<DiffResult, String> {
    if !threshold_pct.is_finite() || !(0.0..=100.0).contains(&threshold_pct) {
        return Err("diff threshold must be finite and between 0 and 100".to_string());
    }
    let old_id = resolve_session_reference(conn, old_id)?;
    let new_id = resolve_session_reference(conn, new_id)?;

    // Get domain counts for each session
    let old_domains = get_session_domain_counts(conn, &old_id)?;
    let new_domains = get_session_domain_counts(conn, &new_id)?;

    // Get process names for each session
    let old_processes = get_session_processes(conn, &old_id)?;
    let new_processes = get_session_processes(conn, &new_id)?;

    // Get provider counts for each session
    let old_providers = get_session_provider_counts(conn, &old_id)?;
    let new_providers = get_session_provider_counts(conn, &new_id)?;

    // Compute domain diffs
    let old_domain_set: HashSet<&String> = old_domains.keys().collect();
    let new_domain_set: HashSet<&String> = new_domains.keys().collect();

    let mut added_domains: Vec<String> = new_domain_set
        .difference(&old_domain_set)
        .filter_map(|d| {
            // Filter out empty/null domains
            if d.is_empty() || *d == "unknown" {
                None
            } else {
                Some((*d).clone())
            }
        })
        .collect();

    let mut removed_domains: Vec<String> = old_domain_set
        .difference(&new_domain_set)
        .filter_map(|d| {
            if d.is_empty() || *d == "unknown" {
                None
            } else {
                Some((*d).clone())
            }
        })
        .collect();

    // Find domains with significant count changes
    let mut changed_domains = Vec::new();
    for domain in old_domain_set.intersection(&new_domain_set) {
        let old_count = *old_domains.get(*domain).unwrap_or(&0);
        let new_count = *new_domains.get(*domain).unwrap_or(&0);
        if old_count > 0 {
            let change_pct =
                ((new_count as f64 - old_count as f64) / old_count as f64).abs() * 100.0;
            if old_count != new_count && change_pct >= threshold_pct {
                changed_domains.push(((*domain).clone(), old_count, new_count));
            }
        } else if new_count > 0 {
            // Old was 0, new is non-zero -> 100% change
            changed_domains.push(((*domain).clone(), old_count, new_count));
        }
    }
    changed_domains.sort_by(|a, b| {
        let a_diff = (a.2 - a.1).abs();
        let b_diff = (b.2 - b.1).abs();
        b_diff.cmp(&a_diff).then_with(|| a.0.cmp(&b.0))
    });

    // Compute process diffs
    let mut added_processes: Vec<String> =
        new_processes.difference(&old_processes).cloned().collect();
    let mut removed_processes: Vec<String> =
        old_processes.difference(&new_processes).cloned().collect();
    added_domains.sort();
    removed_domains.sort();
    added_processes.sort();
    removed_processes.sort();

    // Compute provider changes
    let mut provider_changes: HashMap<String, (i64, i64)> = HashMap::new();
    let all_providers: HashSet<&String> =
        old_providers.keys().chain(new_providers.keys()).collect();
    for provider in all_providers {
        let old_count = *old_providers.get(provider).unwrap_or(&0);
        let new_count = *new_providers.get(provider).unwrap_or(&0);
        if old_count != new_count {
            provider_changes.insert(provider.clone(), (old_count, new_count));
        }
    }

    Ok(DiffResult {
        new_domains: added_domains,
        removed_domains,
        changed_domains,
        new_processes: added_processes,
        removed_processes,
        provider_changes,
        old_run_id: old_id.to_string(),
        new_run_id: new_id.to_string(),
    })
}

fn resolve_session_reference(conn: &Connection, reference: &str) -> Result<String, String> {
    let has_sessions = table_exists(conn, "sessions")?;
    if has_sessions {
        let exists: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sessions WHERE run_id=?)",
                [reference],
                |row| row.get(0),
            )
            .map_err(|error| format!("Failed to query session metadata: {}", error))?;
        if exists {
            return Ok(reference.to_string());
        }
    }
    if table_exists(conn, "events")? {
        let exists: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM events WHERE run_id=?)",
                [reference],
                |row| row.get(0),
            )
            .map_err(|error| format!("Failed to query session events: {}", error))?;
        if exists {
            return Ok(reference.to_string());
        }
    }
    if has_sessions && column_exists(conn, "sessions", "session_name")? {
        let mut stmt = conn
            .prepare("SELECT run_id FROM sessions WHERE session_name=? ORDER BY run_id LIMIT 2")
            .map_err(|error| format!("Failed to prepare session-name query: {}", error))?;
        let matches: Vec<String> = stmt
            .query_map([reference], |row| row.get(0))
            .map_err(|error| format!("Failed to query session names: {}", error))?
            .collect::<rusqlite::Result<_>>()
            .map_err(|error| format!("Failed to read session names: {}", error))?;
        match matches.as_slice() {
            [id] => return Ok(id.clone()),
            [first, second] => {
                return Err(format!(
                    "Ambiguous session name '{}': at least '{}' and '{}' match; use an exact run ID",
                    reference, first, second
                ));
            }
            _ => {}
        }
    }
    Err(format!(
        "Session '{}' not found; use a stored run ID or an unambiguous session name",
        reference
    ))
}

fn get_session_domain_counts(
    conn: &Connection,
    run_id: &str,
) -> Result<HashMap<String, i64>, String> {
    let sql =
        "SELECT COALESCE(domain, 'unknown'), COUNT(*) FROM events WHERE run_id = ? GROUP BY domain";
    let mut stmt = conn
        .prepare(sql)
        .map_err(|e| format!("Failed to prepare query: {}", e))?;

    let rows = stmt
        .query_map([run_id], |row| {
            let domain: String = row.get(0)?;
            let count: i64 = row.get(1)?;
            Ok((domain, count))
        })
        .map_err(|e| format!("Failed to query domains: {}", e))?;

    let mut result = HashMap::new();
    for row in rows {
        let (domain, count) = row.map_err(|e| format!("Failed to read row: {}", e))?;
        result.insert(domain, count);
    }
    Ok(result)
}

fn get_session_processes(conn: &Connection, run_id: &str) -> Result<HashSet<String>, String> {
    let sql = "SELECT DISTINCT COALESCE(comm, 'unknown') FROM events WHERE run_id = ?";
    let mut stmt = conn
        .prepare(sql)
        .map_err(|e| format!("Failed to prepare query: {}", e))?;

    let rows = stmt
        .query_map([run_id], |row| row.get::<_, String>(0))
        .map_err(|e| format!("Failed to query processes: {}", e))?;

    let mut result = HashSet::new();
    for row in rows {
        let comm = row.map_err(|e| format!("Failed to read row: {}", e))?;
        if !comm.is_empty() && comm != "unknown" {
            result.insert(comm);
        }
    }
    Ok(result)
}

fn get_session_provider_counts(
    conn: &Connection,
    run_id: &str,
) -> Result<HashMap<String, i64>, String> {
    let sql = "SELECT COALESCE(provider, 'unknown'), COUNT(*) FROM events WHERE run_id = ? GROUP BY provider";
    let mut stmt = conn
        .prepare(sql)
        .map_err(|e| format!("Failed to prepare query: {}", e))?;

    let rows = stmt
        .query_map([run_id], |row| {
            let provider: String = row.get(0)?;
            let count: i64 = row.get(1)?;
            Ok((provider, count))
        })
        .map_err(|e| format!("Failed to query providers: {}", e))?;

    let mut result = HashMap::new();
    for row in rows {
        let (provider, count) = row.map_err(|e| format!("Failed to read row: {}", e))?;
        result.insert(provider, count);
    }
    Ok(result)
}

fn output_diff_pretty(result: &DiffResult, color_enabled: bool) -> Result<(), String> {
    let green = if color_enabled { "\x1b[32m" } else { "" };
    let red = if color_enabled { "\x1b[31m" } else { "" };
    let yellow = if color_enabled { "\x1b[33m" } else { "" };
    let cyan = if color_enabled { "\x1b[36m" } else { "" };
    let bold = if color_enabled { "\x1b[1m" } else { "" };
    let reset = if color_enabled { "\x1b[0m" } else { "" };

    println!(
        "{}Session Diff{}\n  old: {}\n  new: {}\n",
        bold, reset, result.old_run_id, result.new_run_id
    );

    // Provider changes
    if !result.provider_changes.is_empty() {
        println!("{}Provider Changes:{}", cyan, reset);
        let mut sorted_providers: Vec<_> = result.provider_changes.iter().collect();
        sorted_providers.sort_by(|a, b| a.0.cmp(b.0));
        for (provider, (old, new)) in sorted_providers {
            let diff = new - old;
            let sign = if diff > 0 { "+" } else { "" };
            let color = if diff > 0 { green } else { red };
            println!(
                "  {}: {} → {} ({}{}{}{})",
                provider, old, new, color, sign, diff, reset
            );
        }
        println!();
    }

    // New domains
    if !result.new_domains.is_empty() {
        println!(
            "{}New Domains:{} ({} added)",
            green,
            reset,
            result.new_domains.len()
        );
        for domain in &result.new_domains {
            println!("  {}+{} {}", green, reset, domain);
        }
        println!();
    }

    // Removed domains
    if !result.removed_domains.is_empty() {
        println!(
            "{}Removed Domains:{} ({} removed)",
            red,
            reset,
            result.removed_domains.len()
        );
        for domain in &result.removed_domains {
            println!("  {}-{} {}", red, reset, domain);
        }
        println!();
    }

    // Changed domains (significant count changes)
    if !result.changed_domains.is_empty() {
        println!("{}Changed Domains:{} (count changes)", yellow, reset);
        for (domain, old, new) in &result.changed_domains {
            let diff = new - old;
            let sign = if diff > 0 { "+" } else { "" };
            let color = if diff > 0 { green } else { red };
            println!(
                "  {}: {} → {} ({}{}{}{})",
                domain, old, new, color, sign, diff, reset
            );
        }
        println!();
    }

    // New processes
    if !result.new_processes.is_empty() {
        println!(
            "{}New Processes:{} ({} appeared)",
            green,
            reset,
            result.new_processes.len()
        );
        for proc in &result.new_processes {
            println!("  {}+{} {}", green, reset, proc);
        }
        println!();
    }

    // Removed processes
    if !result.removed_processes.is_empty() {
        println!(
            "{}Removed Processes:{} ({} disappeared)",
            red,
            reset,
            result.removed_processes.len()
        );
        for proc in &result.removed_processes {
            println!("  {}-{} {}", red, reset, proc);
        }
        println!();
    }

    // Summary
    let has_changes = !result.new_domains.is_empty()
        || !result.removed_domains.is_empty()
        || !result.changed_domains.is_empty()
        || !result.new_processes.is_empty()
        || !result.removed_processes.is_empty()
        || !result.provider_changes.is_empty();

    if !has_changes {
        println!("{}No significant differences found.{}", cyan, reset);
    }

    Ok(())
}

fn output_diff_json(result: &DiffResult) -> Result<(), String> {
    // Manually construct JSON to avoid adding serde_json dependency
    let mut json = String::from("{\n");

    json.push_str(&format!(
        "  \"old_run_id\": \"{}\",\n",
        escape_json(&result.old_run_id)
    ));
    json.push_str(&format!(
        "  \"new_run_id\": \"{}\",\n",
        escape_json(&result.new_run_id)
    ));

    // new_domains array
    json.push_str("  \"new_domains\": [");
    for (i, domain) in result.new_domains.iter().enumerate() {
        if i > 0 {
            json.push_str(", ");
        }
        json.push_str(&format!("\"{}\"", escape_json(domain)));
    }
    json.push_str("],\n");

    // removed_domains array
    json.push_str("  \"removed_domains\": [");
    for (i, domain) in result.removed_domains.iter().enumerate() {
        if i > 0 {
            json.push_str(", ");
        }
        json.push_str(&format!("\"{}\"", escape_json(domain)));
    }
    json.push_str("],\n");

    // changed_domains array of objects
    json.push_str("  \"changed_domains\": [");
    for (i, (domain, old, new)) in result.changed_domains.iter().enumerate() {
        if i > 0 {
            json.push_str(", ");
        }
        json.push_str(&format!(
            "{{\"domain\": \"{}\", \"old_count\": {}, \"new_count\": {}}}",
            escape_json(domain),
            old,
            new
        ));
    }
    json.push_str("],\n");

    // new_processes array
    json.push_str("  \"new_processes\": [");
    for (i, proc) in result.new_processes.iter().enumerate() {
        if i > 0 {
            json.push_str(", ");
        }
        json.push_str(&format!("\"{}\"", escape_json(proc)));
    }
    json.push_str("],\n");

    // removed_processes array
    json.push_str("  \"removed_processes\": [");
    for (i, proc) in result.removed_processes.iter().enumerate() {
        if i > 0 {
            json.push_str(", ");
        }
        json.push_str(&format!("\"{}\"", escape_json(proc)));
    }
    json.push_str("],\n");

    // provider_changes object
    json.push_str("  \"provider_changes\": {");
    let mut sorted_providers: Vec<_> = result.provider_changes.iter().collect();
    sorted_providers.sort_by(|a, b| a.0.cmp(b.0));
    for (i, (provider, (old, new))) in sorted_providers.iter().enumerate() {
        if i > 0 {
            json.push_str(", ");
        }
        json.push_str(&format!(
            "\"{}\": {{\"old_count\": {}, \"new_count\": {}}}",
            escape_json(provider),
            old,
            new
        ));
    }
    json.push_str("}\n");

    json.push_str("}\n");

    print!("{}", json);
    Ok(())
}

fn escape_json(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
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

// ============================================================================
// Status Subcommand (shell prompt integration)
// ============================================================================

/// Status data retrieved from SQLite for template expansion.
#[derive(Default)]
struct StatusData {
    active: i64,
    total: i64,
    anthropic: i64,
    openai: i64,
    google: i64,
    session_name: Option<String>,
    state: Option<&'static str>,
}

fn run_status(args: StatusArgs) -> Result<(), String> {
    let path = Path::new(&args.sqlite_path);

    // If no database exists yet, output zeros quietly
    if !path.exists() {
        let data = StatusData::default();
        let format = args.format.as_deref().unwrap_or(STATUS_DEFAULT_FORMAT);
        let output = expand_status_template(format, &data);
        println!("{}", output);
        return Ok(());
    }

    let conn = Connection::open(path).map_err(|e| format!("Failed to open database: {}", e))?;
    configure_query_connection(&conn)
        .map_err(|error| format!("Failed to configure SQLite queries: {}", error))?;

    // Check if events table exists
    let has_events = table_exists(&conn, "events")?;
    if !has_events {
        let data = StatusData::default();
        let format = args.format.as_deref().unwrap_or(STATUS_DEFAULT_FORMAT);
        let output = expand_status_template(format, &data);
        println!("{}", output);
        return Ok(());
    }

    // Get the latest session's data
    let data = get_status_data(&conn)?;

    // Expand template and output
    let format = args.format.as_deref().unwrap_or(STATUS_DEFAULT_FORMAT);
    let output = expand_status_template(format, &data);
    println!("{}", output);

    Ok(())
}

/// Query SQLite for the latest session's status data.
fn get_status_data(conn: &Connection) -> Result<StatusData, String> {
    // Counts, name and published activity must come from one SQLite snapshot
    // while the monitor continues committing new events and poll metadata.
    let snapshot = conn
        .unchecked_transaction()
        .map_err(|error| format!("Failed to begin status read snapshot: {}", error))?;
    let conn: &Connection = &snapshot;
    let mut data = StatusData::default();

    let run_id = match find_latest_session(conn)? {
        Some(id) => id,
        None => return Ok(data), // No events yet
    };

    // Get total connections for this session (count of connect events)
    let total: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM events WHERE run_id = ? AND event = 'connect'",
            [&run_id],
            |row| row.get(0),
        )
        .map_err(|error| format!("Failed to query historical status total: {}", error))?;
    data.total = total;

    let (active, state) = current_session_activity(conn, &run_id)?;
    data.active = active;
    data.state = Some(state);

    // Get per-provider counts (connect events only)
    let provider_sql = "SELECT COALESCE(provider, 'unknown'), COUNT(*) FROM events \
                        WHERE run_id = ? AND event = 'connect' GROUP BY provider";
    let mut stmt = conn
        .prepare(provider_sql)
        .map_err(|error| format!("Failed to prepare provider status: {}", error))?;
    let rows = stmt
        .query_map([&run_id], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        })
        .map_err(|error| format!("Failed to query provider status: {}", error))?;
    for row in rows {
        let (provider, count) =
            row.map_err(|error| format!("Failed to read provider status: {}", error))?;
        match provider.to_lowercase().as_str() {
            "anthropic" => data.anthropic = count,
            "openai" => data.openai = count,
            "google" => data.google = count,
            _ => {}
        }
    }

    // Try to get session name from sessions table (if it exists)
    if table_exists(conn, "sessions")? && column_exists(conn, "sessions", "session_name")? {
        data.session_name = conn
            .query_row(
                "SELECT session_name FROM sessions WHERE run_id = ?",
                [&run_id],
                |row| row.get::<_, Option<String>>(0),
            )
            .optional()
            .map_err(|error| format!("Failed to query status session name: {}", error))?
            .flatten();
    }

    Ok(data)
}

struct SessionActivity {
    host: Option<String>,
    pid: Option<i64>,
    start: Option<String>,
    poll: Option<String>,
    active: Option<i64>,
    valid: Option<bool>,
    interval_ms: Option<i64>,
}

fn current_session_activity(
    conn: &Connection,
    run_id: &str,
) -> Result<(i64, &'static str), String> {
    if !table_exists(conn, "sessions")? {
        return Ok((0, "unverified"));
    }
    if column_exists(conn, "sessions", "end_ts")? {
        let end: Option<Option<String>> = conn
            .query_row(
                "SELECT end_ts FROM sessions WHERE run_id=?",
                [run_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| format!("Failed to query session completion: {}", error))?;
        if end.flatten().is_some() {
            return Ok((0, "ended"));
        }
    }
    for column in [
        "host",
        "observer_pid",
        "observer_start_time",
        "last_poll_ts",
        "active_at_poll",
        "poll_valid",
        "interval_ms",
    ] {
        if !column_exists(conn, "sessions", column)? {
            return Ok((0, "unverified"));
        }
    }
    let activity = conn.query_row("SELECT host,observer_pid,observer_start_time,last_poll_ts,active_at_poll,poll_valid,interval_ms FROM sessions WHERE run_id=?", [run_id], |row| {
        Ok(SessionActivity { host: row.get(0)?, pid: row.get(1)?, start: row.get(2)?, poll: row.get(3)?, active: row.get(4)?, valid: row.get(5)?, interval_ms: row.get(6)? })
    }).optional().map_err(|error| format!("Failed to query current session proof: {}", error))?;
    let Some(activity) = activity else {
        return Ok((0, "unverified"));
    };
    if activity.valid == Some(false) {
        return Ok((0, "degraded"));
    }
    let (Some(pid), Some(start), Some(poll), Some(active), Some(interval)) = (
        activity.pid,
        activity.start,
        activity.poll,
        activity.active,
        activity.interval_ms,
    ) else {
        return Ok((0, "unverified"));
    };
    if activity.valid != Some(true) {
        return Ok((0, "unverified"));
    }
    if active < 0 || interval < 0 {
        return Err("Invalid negative session activity/interval".to_string());
    }
    let pid =
        u32::try_from(pid).map_err(|_| "Invalid observer PID in session metadata".to_string())?;
    let start = start
        .parse::<u64>()
        .map_err(|_| "Invalid observer start time in session metadata".to_string())?;
    if activity.host.as_deref() != Some(hostname().as_str())
        || read_proc_stat(pid).map(|stat| stat.identity)
            != Some(ProcessIdentity {
                pid,
                start_time: start,
            })
    {
        return Ok((0, "stale"));
    }
    let (seconds, nanos) = parse_utc_timestamp(&poll)?;
    let timestamp = i128::from(seconds) * 1_000_000_000 + i128::from(nanos);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| format!("Cannot establish current UTC time: {}", error))?;
    let age = now.as_nanos() as i128 - timestamp;
    let freshness_ms = (interval as u64).saturating_mul(3).max(5000);
    if age < 0 || age > i128::from(freshness_ms) * 1_000_000 {
        return Ok((0, "stale"));
    }
    Ok((active, "fresh"))
}

/// Expand a status template string with data values.
/// Template variables: {active}, {state}, {total}, {anthropic}, {openai}, {google}, {session_name}
fn expand_status_template(template: &str, data: &StatusData) -> String {
    let mut result = template.to_string();

    result = result.replace("{active}", &data.active.to_string());
    result = result.replace("{total}", &data.total.to_string());
    result = result.replace("{anthropic}", &data.anthropic.to_string());
    result = result.replace("{openai}", &data.openai.to_string());
    result = result.replace("{google}", &data.google.to_string());
    result = result.replace("{state}", data.state.unwrap_or("unavailable"));
    result = result.replace("{session_name}", data.session_name.as_deref().unwrap_or(""));

    result
}

// ============================================================================
// Report Subcommand
// ============================================================================

fn run_report(args: ReportArgs) -> Result<(), String> {
    let path = Path::new(&args.sqlite_path);
    if !path.exists() {
        return Err(format!("SQLite file not found: {}", args.sqlite_path));
    }

    let mut conn = Connection::open(path).map_err(|e| format!("Failed to open database: {}", e))?;
    configure_query_connection(&conn)
        .map_err(|error| format!("Failed to configure SQLite queries: {}", error))?;

    // Late-added column: migrate idempotently so reports on pre-provenance
    // databases still prepare their queries.
    let _ = ensure_column(&mut conn, "events", "domain_source", "TEXT");

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
    let has_ancestry = column_exists(&conn, "events", "ancestry_path")?;
    if !has_ancestry {
        eprintln!(
            "warning: ancestry_path column missing; ancestry report section will be unavailable. {}",
            schema_hint(&args.sqlite_path)
        );
    }

    let snapshot = conn
        .transaction()
        .map_err(|error| format!("Failed to start report snapshot: {error}"))?;
    let conn = &snapshot;
    let color_enabled = resolve_color_mode(args.color);

    // Determine run_id filter
    let run_id = if let Some(id) = args.run_id.clone() {
        Some(resolve_session_reference(&conn, &id)?)
    } else if args.latest {
        Some(
            find_latest_session(&conn)?
                .ok_or_else(|| "No monitoring sessions found for --latest".to_string())?,
        )
    } else {
        None
    };

    // Parse time filters
    let since = parse_time_filter(&args.since)?;
    let until = parse_time_filter(&args.until)?;
    validate_time_range(&since, &until)?;

    // Build filter context for queries
    let filter = ReportFilter {
        run_id: run_id.clone(),
        since,
        until,
    };

    if args.json {
        output_report_json(&conn, &filter, args.top, has_sessions, has_ancestry)?;
    } else {
        output_report_pretty(
            &conn,
            &filter,
            args.top,
            has_sessions,
            has_ancestry,
            color_enabled,
        )?;
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
    conn.query_row(sql, [table_name], |row| row.get::<_, String>(0))
        .optional()
        .map(|result| result.is_some())
        .map_err(|error| format!("Failed to inspect tables: {}", error))
}

fn view_exists(conn: &Connection, view_name: &str) -> Result<bool, String> {
    let sql = "SELECT name FROM sqlite_master WHERE type='view' AND name=?";
    conn.query_row(sql, [view_name], |row| row.get::<_, String>(0))
        .optional()
        .map(|result| result.is_some())
        .map_err(|error| format!("Failed to inspect views: {}", error))
}

fn column_exists(conn: &Connection, table_name: &str, column: &str) -> Result<bool, String> {
    let pragma = format!("PRAGMA table_info({})", table_name);
    let mut stmt = conn
        .prepare(&pragma)
        .map_err(|e| format!("Failed to inspect schema: {}", e))?;
    let mut rows = stmt
        .query([])
        .map_err(|e| format!("Failed to read schema: {}", e))?;
    while let Some(row) = rows
        .next()
        .map_err(|e| format!("Failed to read schema: {}", e))?
    {
        let name: String = row
            .get(1)
            .map_err(|e| format!("Failed to read schema: {}", e))?;
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
    if table_exists(conn, "sessions")? {
        let latest = conn
            .query_row(
                "SELECT run_id FROM sessions ORDER BY rano_utc(start_ts) DESC, run_id DESC LIMIT 1",
                [],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|error| format!("Failed to query latest session metadata: {}", error))?;
        if latest.is_some() {
            return Ok(latest);
        }
    }
    if !table_exists(conn, "events")? {
        return Ok(None);
    }
    conn.query_row("SELECT run_id FROM events WHERE run_id IS NOT NULL GROUP BY run_id ORDER BY MAX(rano_utc(ts)) DESC, run_id DESC LIMIT 1", [], |row| row.get(0))
        .optional().map_err(|error| format!("Failed to query latest legacy session: {}", error))
}

fn parse_time_filter(input: &Option<String>) -> Result<Option<String>, String> {
    let Some(s) = input else {
        return Ok(None);
    };

    // Check for relative time formats: 1h, 24h, 7d, 30m
    if let Some(ts) = parse_relative_time(s) {
        return Ok(Some(ts));
    }

    normalize_utc_timestamp(s).map(Some)
}

// Proleptic Gregorian calendar arithmetic; Euclidean division also covers dates
// before the Unix epoch. All query timestamps use fixed nanosecond UTC precision.
fn calendar_days(year: i64, month: i64, day: i64) -> i64 {
    let year = year - i64::from(month <= 2);
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let shifted_month = month + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * shifted_month + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146097 + day_of_era - 719468
}

fn format_utc_seconds(seconds: i64, nanos: u32) -> Result<String, String> {
    let days = seconds.div_euclid(86400);
    let time = seconds.rem_euclid(86400);
    let shifted = days + 719468;
    let era = shifted.div_euclid(146097);
    let day_of_era = shifted - era * 146097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36524 - day_of_era / 146096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * shifted_month + 2) / 5 + 1;
    let month = shifted_month + if shifted_month < 10 { 3 } else { -9 };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    if !(0..=9999).contains(&year) || nanos >= 1_000_000_000 {
        return Err(
            "UTC timestamp is outside years 0000..9999 or nanosecond precision".to_string(),
        );
    }
    Ok(format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:09}Z",
        year,
        month,
        day,
        time / 3600,
        time % 3600 / 60,
        time % 60,
        nanos
    ))
}

fn normalize_utc_timestamp(input: &str) -> Result<String, String> {
    let (seconds, nanos) = parse_utc_timestamp(input)?;
    format_utc_seconds(seconds, nanos)
}

fn parse_utc_timestamp(input: &str) -> Result<(i64, u32), String> {
    let text = input.trim();
    let invalid = || {
        format!(
            "Invalid UTC timestamp '{}': use a real YYYY-MM-DD or RFC3339 date/time with a known offset and at most 9 fractional digits",
            input
        )
    };
    if !text.is_ascii() || text.len() < 10 {
        return Err(invalid());
    }
    let bytes = text.as_bytes();
    let number = |start: usize, len: usize| -> Result<i64, String> {
        let digits = bytes.get(start..start + len).ok_or_else(&invalid)?;
        if !digits.iter().all(u8::is_ascii_digit) {
            return Err(invalid());
        }
        text[start..start + len].parse().map_err(|_| invalid())
    };
    if bytes[4] != b'-' || bytes[7] != b'-' {
        return Err(invalid());
    }
    let year = number(0, 4)?;
    let month = number(5, 2)?;
    let day = number(8, 2)?;
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days_in_month = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return Err(invalid()),
    };
    if !(1..=days_in_month).contains(&day) {
        return Err(invalid());
    }
    let date_seconds = calendar_days(year, month, day) * 86400;
    if text.len() == 10 {
        return Ok((date_seconds, 0));
    }
    if text.len() < 20
        || !matches!(bytes[10], b'T' | b't')
        || bytes[13] != b':'
        || bytes[16] != b':'
    {
        return Err(invalid());
    }
    let hour = number(11, 2)?;
    let minute = number(14, 2)?;
    let second = number(17, 2)?;
    if hour > 23 || minute > 59 || second > 59 {
        return Err(format!("{}; leap-second inputs are unsupported", invalid()));
    }
    let mut cursor = 19;
    let mut nanos = 0;
    if bytes.get(cursor) == Some(&b'.') {
        cursor += 1;
        let start = cursor;
        while bytes.get(cursor).is_some_and(u8::is_ascii_digit) {
            cursor += 1;
        }
        let len = cursor - start;
        if !(1..=9).contains(&len) {
            return Err(invalid());
        }
        nanos = number(start, len)? as u32 * 10u32.pow(9 - len as u32);
    }
    let offset = match bytes.get(cursor) {
        Some(b'Z' | b'z') if cursor + 1 == bytes.len() => 0,
        Some(sign @ (b'+' | b'-')) if cursor + 6 == bytes.len() && bytes[cursor + 3] == b':' => {
            let hours = number(cursor + 1, 2)?;
            let minutes = number(cursor + 4, 2)?;
            if hours > 23 || minutes > 59 || (*sign == b'-' && hours == 0 && minutes == 0) {
                return Err(format!("{}; -00:00 denotes an unknown offset", invalid()));
            }
            (hours * 3600 + minutes * 60) * if *sign == b'-' { -1 } else { 1 }
        }
        _ => return Err(invalid()),
    };
    let seconds = date_seconds + hour * 3600 + minute * 60 + second - offset;
    if seconds < calendar_days(0, 1, 1) * 86400 || seconds >= calendar_days(10000, 1, 1) * 86400 {
        return Err("UTC offset moves timestamp outside years 0000..9999".to_string());
    }
    Ok((seconds, nanos))
}

fn validate_time_range(since: &Option<String>, until: &Option<String>) -> Result<(), String> {
    if let (Some(since), Some(until)) = (since, until) {
        if since >= until {
            return Err(
                "--since must precede --until (inclusive start, exclusive end)".to_string(),
            );
        }
    }
    Ok(())
}

fn parse_relative_time(s: &str) -> Option<String> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }

    let (num_str, unit) = if let Some(stripped) = s.strip_suffix('h') {
        (stripped, "h")
    } else if let Some(stripped) = s.strip_suffix('d') {
        (stripped, "d")
    } else if let Some(stripped) = s.strip_suffix('m') {
        (stripped, "m")
    } else {
        let stripped = s.strip_suffix('w')?;
        (stripped, "w")
    };

    if num_str.is_empty() || !num_str.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let num: u64 = num_str.parse().ok()?;
    let multiplier = match unit {
        "m" => 60,
        "h" => 3600,
        "d" => 86400,
        "w" => 604800,
        _ => return None,
    };
    let secs = num.checked_mul(multiplier)?;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let target = now.as_secs().checked_sub(secs)?;
    format_utc_seconds(i64::try_from(target).ok()?, 0).ok()
}

fn output_report_json(
    conn: &Connection,
    filter: &ReportFilter,
    top: usize,
    has_sessions: bool,
    has_ancestry: bool,
) -> Result<(), String> {
    print!(
        "{}",
        format_report_json(conn, filter, top, has_sessions, has_ancestry)?
    );
    Ok(())
}

fn format_report_json(
    conn: &Connection,
    filter: &ReportFilter,
    top: usize,
    has_sessions: bool,
    has_ancestry: bool,
) -> Result<String, String> {
    let mut out = String::from("{\n");

    // Meta section
    out.push_str("  \"meta\": {\n");
    out.push_str(&format!(
        "    \"generated_at\": \"{}\",\n",
        system_time_to_rfc3339(SystemTime::now())
    ));
    if let Some(ref run_id) = filter.run_id {
        out.push_str(&format!("    \"run_id\": \"{}\",\n", escape_json(run_id)));
    }
    if let Some(ref since) = filter.since {
        out.push_str(&format!("    \"since\": \"{}\",\n", escape_json(since)));
    }
    if let Some(ref until) = filter.until {
        out.push_str(&format!("    \"until\": \"{}\",\n", escape_json(until)));
    }
    out.push_str(&format!(
        "    \"metric_scope\": \"{}\",\n",
        if filter.since.is_some() || filter.until.is_some() {
            "selected_window"
        } else {
            "selected_sessions"
        }
    ));
    out.push_str("    \"session_metadata_scope\": \"full_session\",\n");
    out.push_str("    \"version\": \"2.0\"\n");
    out.push_str("  },\n");

    // Session info (if available and filtering by run_id)
    if has_sessions
        && let Some(ref run_id) = filter.run_id
        && let Some(session) = query_session(conn, run_id)?
    {
        out.push_str("  \"session\": {\n");
        out.push_str(&format!(
            "    \"run_id\": \"{}\",\n",
            escape_json(&session.run_id)
        ));
        out.push_str(&format!(
            "    \"start_ts\": \"{}\",\n",
            escape_json(&session.start_ts)
        ));
        if let Some(end) = &session.end_ts {
            out.push_str(&format!("    \"end_ts\": \"{}\",\n", escape_json(end)));
        }
        if let Some(host) = &session.host {
            out.push_str(&format!("    \"host\": \"{}\",\n", escape_json(host)));
        }
        if let Some(user) = &session.user {
            out.push_str(&format!("    \"user\": \"{}\",\n", escape_json(user)));
        }
        if let Some(patterns) = &session.patterns {
            out.push_str(&format!(
                "    \"patterns\": \"{}\",\n",
                escape_json(patterns)
            ));
        }
        out.push_str(&format!(
            "    \"connects\": {},\n",
            session.connects.unwrap_or(0)
        ));
        out.push_str(&format!(
            "    \"closes\": {}\n",
            session.closes.unwrap_or(0)
        ));
        out.push_str("  },\n");
    }

    // Summary statistics
    let summary = query_summary(conn, filter)?;
    out.push_str("  \"summary\": {\n");
    out.push_str(&format!(
        "    \"total_events\": {},\n",
        summary.total_events
    ));
    out.push_str(&format!("    \"connects\": {},\n", summary.connects));
    out.push_str(&format!("    \"closes\": {},\n", summary.closes));
    out.push_str(&format!(
        "    \"active\": {},\n",
        summary.connects.saturating_sub(summary.closes)
    ));
    out.push_str(&format!(
        "    \"avg_duration_ms\": {},\n",
        summary
            .avg_duration_ms
            .map_or_else(|| "null".to_string(), |value| value.to_string())
    ));
    out.push_str(&format!(
        "    \"max_duration_ms\": {},\n",
        summary
            .max_duration_ms
            .map_or_else(|| "null".to_string(), |value| value.to_string())
    ));
    out.push_str(&format!(
        "    \"duration_samples\": {},\n",
        summary.duration_samples
    ));
    out.push_str(&format!(
        "    \"peak_active\": {},\n",
        summary
            .peak_active
            .map_or_else(|| "null".to_string(), |value| value.to_string())
    ));
    out.push_str("    \"peak_basis\": \"max_per_session_stored_episode_balance\",\n");
    out.push_str("    \"peak_order\": \"utc_then_event_id_or_rowid\",\n");
    out.push_str(&format!(
        "    \"peak_unavailable_reason\": {}\n",
        summary
            .peak_unavailable
            .map_or_else(|| "null".to_string(), |reason| format!("\"{reason}\""))
    ));
    out.push_str("  },\n");

    // Provider breakdown
    let providers = query_providers(conn, filter)?;
    out.push_str("  \"providers\": [\n");
    for (i, p) in providers.iter().enumerate() {
        out.push_str(&format!(
            "    {{\"provider\": \"{}\", \"events\": {}, \"connects\": {}, \"closes\": {}, \"domains\": {}, \"ips\": {}}}",
            escape_json(&p.provider),
            p.events,
            p.connects,
            p.closes,
            p.domains,
            p.ips
        ));
        if i < providers.len() - 1 {
            out.push(',');
        }
        out.push('\n');
    }
    out.push_str("  ],\n");

    let (hours, unbucketed) = query_hourly_activity(conn, filter)?;
    out.push_str("  \"hourly_activity\": [\n");
    for (index, hour) in hours.iter().enumerate() {
        let providers: Vec<_> = hour
            .providers
            .iter()
            .map(|(provider, count)| format!("\"{}\":{count}", escape_json(provider)))
            .collect();
        out.push_str(&format!(
            "    {{\"hour\":\"{}\",\"providers\":{{{}}}}}{}\n",
            escape_json(&hour.hour),
            providers.join(","),
            if index + 1 < hours.len() { "," } else { "" }
        ));
    }
    out.push_str(&format!("  ],\n  \"unbucketed_events\": {unbucketed},\n"));

    // Top domains
    let domains = query_top_domains(conn, filter, top)?;
    out.push_str("  \"top_domains\": [\n");
    for (i, d) in domains.iter().enumerate() {
        out.push_str(&format!(
            "    {{\"domain\": \"{}\", \"events\": {}, \"provider\": \"{}\", \"source\": {}}}",
            escape_json(&d.domain),
            d.events,
            escape_json(&d.provider),
            match d.source.as_deref() {
                Some(s) => format!("\"{}\"", escape_json(s)),
                None => "null".to_string(),
            }
        ));
        if i < domains.len() - 1 {
            out.push(',');
        }
        out.push('\n');
    }
    out.push_str("  ],\n");

    // Top IPs
    let ips = query_top_ips(conn, filter, top)?;
    out.push_str("  \"top_ips\": [\n");
    for (i, ip) in ips.iter().enumerate() {
        let domain_str = ip.domain.as_deref().unwrap_or("unknown");
        out.push_str(&format!(
            "    {{\"ip\": \"{}\", \"events\": {}, \"domain\": \"{}\"}}",
            escape_json(&ip.ip),
            ip.events,
            escape_json(domain_str)
        ));
        if i < ips.len() - 1 {
            out.push(',');
        }
        out.push('\n');
    }
    out.push_str("  ]");

    if has_ancestry {
        let roots = query_ancestry_roots(conn, filter, top, has_ancestry)?;
        out.push_str(",\n  \"ancestry_roots\": [\n");
        for (i, root) in roots.iter().enumerate() {
            out.push_str(&format!(
                "    {{\"root\": \"{}\", \"connects\": {}}}",
                escape_json(&root.root),
                root.connects
            ));
            if i < roots.len() - 1 {
                out.push(',');
            }
            out.push('\n');
        }
        out.push_str("  ]\n");
    } else {
        out.push('\n');
    }

    out.push_str("}\n");
    Ok(out)
}

fn output_report_pretty(
    conn: &Connection,
    filter: &ReportFilter,
    top: usize,
    has_sessions: bool,
    has_ancestry: bool,
    color: bool,
) -> Result<(), String> {
    // Title
    println!(
        "\n{}",
        if color {
            "\x1b[1mrano report\x1b[0m"
        } else {
            "rano report"
        }
    );
    println!("{}", "=".repeat(60));

    // Time range (if provided)
    if filter.since.is_some() || filter.until.is_some() {
        let now_display = now_rfc3339();
        let since = filter.since.as_deref().unwrap_or("beginning");
        let until = filter.until.as_deref().unwrap_or(&now_display);
        println!(
            "\n{}",
            if color {
                "\x1b[1;36mRange\x1b[0m"
            } else {
                "Range"
            }
        );
        println!("  {} .. {}", since, until);
    }

    // Session info
    if has_sessions
        && let Some(ref run_id) = filter.run_id
        && let Some(session) = query_session(conn, run_id)?
    {
        println!(
            "\n{}",
            if color {
                "\x1b[1;36mSession\x1b[0m"
            } else {
                "Session"
            }
        );
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

    // Summary
    let summary = query_summary(conn, filter)?;
    println!(
        "\n{}",
        if color {
            "\x1b[1;36mSummary\x1b[0m"
        } else {
            "Summary"
        }
    );
    println!(
        "  Events:  {} total ({} connects, {} closes)",
        summary.total_events, summary.connects, summary.closes
    );
    println!(
        "  Observed connect-close balance: {} (filtered history)",
        summary.connects.saturating_sub(summary.closes)
    );
    println!(
        "  Metrics: {} (session metadata covers the full session)",
        if filter.since.is_some() || filter.until.is_some() {
            "selected window"
        } else {
            "selected sessions"
        }
    );
    match summary.peak_active {
        Some(peak) => println!(
            "  Observed event peak: {peak} (maximum per-session stored balance; UTC/event ID order)"
        ),
        None => println!(
            "  Observed event peak: unavailable ({})",
            summary.peak_unavailable.unwrap_or("unknown")
        ),
    }
    match (summary.avg_duration_ms, summary.max_duration_ms) {
        (Some(average), Some(maximum)) => println!(
            "  Close durations: avg={average:.3}ms max={maximum}ms samples={}",
            summary.duration_samples
        ),
        _ => println!(
            "  Close durations: unavailable (no valid nonnegative integer close durations)"
        ),
    }

    // Providers
    let providers = query_providers(conn, filter)?;
    if !providers.is_empty() {
        println!(
            "\n{}",
            if color {
                "\x1b[1;36mProviders\x1b[0m"
            } else {
                "Providers"
            }
        );
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
        let domains_width = providers
            .iter()
            .map(|provider| provider.domains.to_string().len())
            .max()
            .unwrap_or(0)
            .max("Domains".len());
        let ips_width = providers
            .iter()
            .map(|provider| provider.ips.to_string().len())
            .max()
            .unwrap_or(0)
            .max("IPs".len());

        println!(
            "  {:<provider_width$}  {:>events_width$}  {:>connects_width$}  {:>closes_width$}  {:>domains_width$}  {:>ips_width$}",
            "Provider",
            "Events",
            "Connects",
            "Closes",
            "Domains",
            "IPs",
            provider_width = provider_width,
            events_width = events_width,
            connects_width = connects_width,
            closes_width = closes_width,
            domains_width = domains_width,
            ips_width = ips_width
        );
        println!(
            "  {}  {}  {}  {}  {}  {}",
            "-".repeat(provider_width),
            "-".repeat(events_width),
            "-".repeat(connects_width),
            "-".repeat(closes_width),
            "-".repeat(domains_width),
            "-".repeat(ips_width)
        );
        for p in &providers {
            let label = provider_label(&p.provider, color);
            let label = pad_right(&label, provider_width, p.provider.len());
            println!(
                "  {}  {:>events_width$}  {:>connects_width$}  {:>closes_width$}  {:>domains_width$}  {:>ips_width$}",
                label,
                p.events,
                p.connects,
                p.closes,
                p.domains,
                p.ips,
                events_width = events_width,
                connects_width = connects_width,
                closes_width = closes_width,
                domains_width = domains_width,
                ips_width = ips_width
            );
        }
    }

    let (hours, unbucketed) = query_hourly_activity(conn, filter)?;
    if !hours.is_empty() {
        println!("\nHourly Activity (UTC, selected event counts)");
        for hour in hours {
            let counts: Vec<_> = hour
                .providers
                .iter()
                .map(|(provider, count)| format!("{provider}:{count}"))
                .collect();
            println!("  {}  {}", hour.hour, counts.join(", "));
        }
    }
    if unbucketed > 0 {
        println!("  Unbucketed events (invalid timestamps): {unbucketed}");
    }

    // Spawned From (ancestry roots)
    if has_ancestry {
        let roots = query_ancestry_roots(conn, filter, top, has_ancestry)?;
        if !roots.is_empty() {
            println!(
                "\n{}",
                if color {
                    "\x1b[1;36mSpawned From\x1b[0m"
                } else {
                    "Spawned From"
                }
            );
            for root in roots {
                println!("  {}: {} connections", root.root, root.connects);
            }
        }
    }

    // Top Domains
    let domains = query_top_domains(conn, filter, top)?;
    if !domains.is_empty() {
        println!(
            "\n{}",
            if color {
                "\x1b[1;36mTop Domains\x1b[0m"
            } else {
                "Top Domains"
            }
        );
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
            let domain = match d.source.as_deref() {
                Some(source) => format!("{} [{}]", truncate_ascii(&d.domain, domain_width), source),
                None => truncate_ascii(&d.domain, domain_width),
            };
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
        println!(
            "\n{}",
            if color {
                "\x1b[1;36mTop IPs\x1b[0m"
            } else {
                "Top IPs"
            }
        );
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
    let mut head = if max <= 3 { max } else { max - 3 };
    while !value.is_char_boundary(head) {
        head -= 1;
    }
    if max <= 3 {
        return value[..head].to_string();
    }
    let mut out = String::with_capacity(max);
    out.push_str(&value[..head]);
    out.push_str("...");
    out
}

/// Calculate duration between two RFC3339 timestamps and format as human-readable
fn format_session_duration(start: &str, end: &str) -> Option<String> {
    let (start_secs, start_nanos) = parse_utc_timestamp(start).ok()?;
    let (end_secs, end_nanos) = parse_utc_timestamp(end).ok()?;
    let start = i128::from(start_secs) * 1_000_000_000 + i128::from(start_nanos);
    let end = i128::from(end_secs) * 1_000_000_000 + i128::from(end_nanos);
    if end < start {
        return None;
    }
    Some(format_duration_human(
        u64::try_from((end - start) / 1_000_000_000).ok()?,
    ))
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
    avg_duration_ms: Option<f64>,
    max_duration_ms: Option<i64>,
    duration_samples: i64,
    peak_active: Option<i64>,
    peak_unavailable: Option<&'static str>,
}

struct ProviderStats {
    provider: String,
    events: i64,
    connects: i64,
    closes: i64,
    domains: i64,
    ips: i64,
}

struct HourlyActivity {
    hour: String,
    providers: BTreeMap<String, i64>,
}

fn append_report_filter(sql: &mut String, params: &mut Vec<String>, filter: &ReportFilter) {
    if let Some(run_id) = &filter.run_id {
        sql.push_str(" AND run_id=?");
        params.push(run_id.clone());
    }
    if let Some(since) = &filter.since {
        sql.push_str(" AND rano_utc(ts)>=rano_utc(?)");
        params.push(since.clone());
    }
    if let Some(until) = &filter.until {
        sql.push_str(" AND rano_utc(ts)<rano_utc(?)");
        params.push(until.clone());
    }
}

fn query_hourly_activity(
    conn: &Connection,
    filter: &ReportFilter,
) -> Result<(Vec<HourlyActivity>, i64), String> {
    let mut sql = String::from(
        "SELECT substr(rano_report_utc(ts),1,13)||':00:00Z',provider,COUNT(*) FROM events WHERE rano_report_utc(ts) IS NOT NULL",
    );
    let mut params = Vec::new();
    append_report_filter(&mut sql, &mut params, filter);
    sql.push_str(" GROUP BY 1,provider ORDER BY 1 ASC,provider ASC");
    let refs: Vec<&dyn rusqlite::ToSql> = params
        .iter()
        .map(|value| value as &dyn rusqlite::ToSql)
        .collect();
    let mut statement = conn
        .prepare(&sql)
        .map_err(|error| format!("Failed to prepare hourly activity: {error}"))?;
    let rows = statement
        .query_map(refs.as_slice(), |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
            ))
        })
        .map_err(|error| format!("Failed to query hourly activity: {error}"))?;
    let mut hours: BTreeMap<String, BTreeMap<String, i64>> = BTreeMap::new();
    for row in rows {
        let (hour, provider, count) =
            row.map_err(|error| format!("Failed to read hourly activity: {error}"))?;
        hours.entry(hour).or_default().insert(provider, count);
    }
    let mut invalid_sql =
        String::from("SELECT COUNT(*) FROM events WHERE rano_report_utc(ts) IS NULL");
    let mut invalid_params = Vec::new();
    append_report_filter(&mut invalid_sql, &mut invalid_params, filter);
    let refs: Vec<&dyn rusqlite::ToSql> = invalid_params
        .iter()
        .map(|value| value as &dyn rusqlite::ToSql)
        .collect();
    let unbucketed = conn
        .query_row(&invalid_sql, refs.as_slice(), |row| row.get(0))
        .map_err(|error| format!("Failed to count unbucketed events: {error}"))?;
    Ok((
        hours
            .into_iter()
            .map(|(hour, providers)| HourlyActivity { hour, providers })
            .collect(),
        unbucketed,
    ))
}

/// Reconstruct a stored episode ledger, separately for every monitoring run.
/// Earlier rows carry the opening window balance; independent runs are never
/// added together. This does not reconstruct packet activity missed by polling.
fn query_observed_peak(
    conn: &Connection,
    filter: &ReportFilter,
) -> Result<(Option<i64>, Option<&'static str>), String> {
    let since = parse_time_filter(&filter.since)?;
    let until = parse_time_filter(&filter.until)?;
    let mut sql = String::from(
        "SELECT rano_report_utc(ts),run_id,event FROM events WHERE event IN ('connect','close')",
    );
    let mut params = Vec::new();
    if let Some(run_id) = &filter.run_id {
        sql.push_str(" AND run_id=?");
        params.push(run_id.clone());
    }
    // Include earlier observations to establish the window's opening ledger.
    let sequence = if column_exists(conn, "events", "id")? {
        "id"
    } else {
        "rowid"
    };
    sql.push_str(&format!(" ORDER BY rano_report_utc(ts) ASC,{sequence} ASC"));
    let refs: Vec<&dyn rusqlite::ToSql> = params
        .iter()
        .map(|value| value as &dyn rusqlite::ToSql)
        .collect();
    let mut statement = match conn.prepare(&sql) {
        Ok(statement) => statement,
        Err(error) => {
            let message = error.to_string();
            if message.contains("no such column") && message.contains("rowid") {
                return Ok((None, Some("stable_event_order_unavailable")));
            }
            return Err(format!("Failed to prepare observed peak: {error}"));
        }
    };
    let mut rows = statement
        .query(refs.as_slice())
        .map_err(|error| format!("Failed to query observed peak: {error}"))?;
    let mut balances: HashMap<String, i64> = HashMap::new();
    let mut peak: Option<i64> = None;
    while let Some(row) = rows
        .next()
        .map_err(|error| format!("Failed to read observed peak: {error}"))?
    {
        let Some(ts) = row
            .get::<_, Option<String>>(0)
            .map_err(|error| format!("Failed to read peak timestamp: {error}"))?
        else {
            return Ok((None, Some("invalid_event_timestamps")));
        };
        if until.as_ref().is_some_and(|until| ts >= *until) {
            break;
        }
        let Some(run) = row
            .get::<_, Option<String>>(1)
            .map_err(|error| format!("Failed to read peak run: {error}"))?
        else {
            return Ok((None, Some("run_identity_unavailable")));
        };
        if run.is_empty() {
            return Ok((None, Some("run_identity_unavailable")));
        }
        let event: String = row
            .get(2)
            .map_err(|error| format!("Failed to read peak event: {error}"))?;
        let balance = balances.entry(run).or_default();
        let before = *balance;
        *balance = balance
            .checked_add(if event == "connect" { 1 } else { -1 })
            .ok_or_else(|| "Observed episode balance overflow".to_string())?;
        if *balance < 0 {
            return Ok((None, Some("unmatched_close_in_history")));
        }
        if since.as_ref().is_none_or(|since| ts >= *since) {
            let value = before.max(*balance);
            peak = Some(peak.unwrap_or(0).max(value));
        }
    }
    Ok((
        peak,
        peak.is_none().then_some("no_selected_endpoint_events"),
    ))
}

struct AncestryRootStats {
    root: String,
    connects: i64,
}

struct DomainStats {
    domain: String,
    events: i64,
    provider: String,
    source: Option<String>,
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
    let has_duration = column_exists(conn, "events", "duration_ms")?;
    let (sql, params) = build_summary_query(filter, has_duration);
    let params_refs: Vec<&dyn rusqlite::ToSql> =
        params.iter().map(|s| s as &dyn rusqlite::ToSql).collect();

    let mut summary = conn
        .query_row(&sql, params_refs.as_slice(), |row| {
            Ok(SummaryStats {
                total_events: row.get(0)?,
                connects: row.get(1)?,
                closes: row.get(2)?,
                avg_duration_ms: row.get(3)?,
                max_duration_ms: row.get(4)?,
                duration_samples: row.get(5)?,
                peak_active: None,
                peak_unavailable: None,
            })
        })
        .map_err(|e| format!("Failed to query summary: {}", e))?;
    let (peak, reason) = query_observed_peak(conn, filter)?;
    summary.peak_active = peak;
    summary.peak_unavailable = reason;
    Ok(summary)
}

fn build_summary_query(filter: &ReportFilter, has_duration: bool) -> (String, Vec<String>) {
    let duration = if has_duration { "duration_ms" } else { "NULL" };
    let eligible = format!("event='close' AND typeof({duration})='integer' AND {duration}>=0");
    let mut sql = format!(
        "SELECT COUNT(*) as total,
                COALESCE(SUM(CASE WHEN event='connect' THEN 1 ELSE 0 END), 0) as connects,
                COALESCE(SUM(CASE WHEN event='close' THEN 1 ELSE 0 END), 0) as closes,
                AVG(CASE WHEN {eligible} THEN {duration} END),
                MAX(CASE WHEN {eligible} THEN {duration} END),
                COUNT(CASE WHEN {eligible} THEN 1 END)
         FROM events WHERE 1=1",
    );
    let mut params: Vec<String> = Vec::new();

    if let Some(ref run_id) = filter.run_id {
        sql.push_str(" AND run_id = ?");
        params.push(run_id.clone());
    }
    if let Some(ref since) = filter.since {
        sql.push_str(" AND rano_utc(ts) >= rano_utc(?)");
        params.push(since.clone());
    }
    if let Some(ref until) = filter.until {
        sql.push_str(" AND rano_utc(ts) < rano_utc(?)");
        params.push(until.clone());
    }

    (sql, params)
}

fn query_providers(conn: &Connection, filter: &ReportFilter) -> Result<Vec<ProviderStats>, String> {
    let (sql, params) = build_providers_query(filter);
    let params_refs: Vec<&dyn rusqlite::ToSql> =
        params.iter().map(|s| s as &dyn rusqlite::ToSql).collect();

    let mut stmt = conn
        .prepare(&sql)
        .map_err(|e| format!("Failed to prepare query: {}", e))?;

    let rows = stmt
        .query_map(params_refs.as_slice(), |row| {
            Ok(ProviderStats {
                provider: row.get(0)?,
                events: row.get(1)?,
                connects: row.get(2)?,
                closes: row.get(3)?,
                domains: row.get(4)?,
                ips: row.get(5)?,
            })
        })
        .map_err(|e| format!("Failed to query providers: {}", e))?;

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
                SUM(CASE WHEN event='close' THEN 1 ELSE 0 END) as closes,
                COUNT(DISTINCT CASE WHEN event IN ('connect','close') AND domain IS NOT NULL AND domain NOT IN ('','unknown') THEN domain END),
                COUNT(DISTINCT CASE WHEN event IN ('connect','close') AND remote_ip IS NOT NULL AND remote_ip NOT IN ('','0.0.0.0','::') THEN remote_ip END)
         FROM events WHERE 1=1",
    );
    let mut params: Vec<String> = Vec::new();

    if let Some(ref run_id) = filter.run_id {
        sql.push_str(" AND run_id = ?");
        params.push(run_id.clone());
    }
    if let Some(ref since) = filter.since {
        sql.push_str(" AND rano_utc(ts) >= rano_utc(?)");
        params.push(since.clone());
    }
    if let Some(ref until) = filter.until {
        sql.push_str(" AND rano_utc(ts) < rano_utc(?)");
        params.push(until.clone());
    }

    sql.push_str(" GROUP BY provider ORDER BY events DESC, provider ASC");
    (sql, params)
}

fn query_ancestry_roots(
    conn: &Connection,
    filter: &ReportFilter,
    top: usize,
    has_ancestry: bool,
) -> Result<Vec<AncestryRootStats>, String> {
    if !has_ancestry {
        return Ok(Vec::new());
    }
    let (sql, params) = build_ancestry_roots_query(filter, top);
    let params_refs: Vec<&dyn rusqlite::ToSql> =
        params.iter().map(|s| s as &dyn rusqlite::ToSql).collect();

    let mut stmt = conn
        .prepare(&sql)
        .map_err(|e| format!("Failed to prepare query: {}", e))?;

    let rows = stmt
        .query_map(params_refs.as_slice(), |row| {
            let root_seg: String = row.get(0)?;
            let connects: i64 = row.get(1)?;
            let root = root_seg
                .split_once(':')
                .map(|(comm, _)| comm.to_string())
                .unwrap_or(root_seg);
            let root = root
                .replace("%2c", ",")
                .replace("%3a", ":")
                .replace("%0a", "\n")
                .replace("%0d", "\r")
                .replace("%25", "%");
            Ok(AncestryRootStats { root, connects })
        })
        .map_err(|e| format!("Failed to query ancestry roots: {}", e))?;

    let mut results = Vec::new();
    for row in rows {
        results.push(row.map_err(|e| format!("Failed to read row: {}", e))?);
    }
    Ok(results)
}

fn build_ancestry_roots_query(filter: &ReportFilter, top: usize) -> (String, Vec<String>) {
    let root_seg = "CASE \
        WHEN instr(ancestry_path, ',') > 0 THEN substr(ancestry_path, 1, instr(ancestry_path, ',') - 1) \
        ELSE ancestry_path END";
    let mut sql = format!(
        "SELECT {root_seg} as root_seg,
                SUM(CASE WHEN event='connect' THEN 1 ELSE 0 END) as connects
         FROM events WHERE NULLIF(ancestry_path, '') IS NOT NULL",
        root_seg = root_seg
    );
    let mut params: Vec<String> = Vec::new();

    if let Some(ref run_id) = filter.run_id {
        sql.push_str(" AND run_id = ?");
        params.push(run_id.clone());
    }
    if let Some(ref since) = filter.since {
        sql.push_str(" AND rano_utc(ts) >= rano_utc(?)");
        params.push(since.clone());
    }
    if let Some(ref until) = filter.until {
        sql.push_str(" AND rano_utc(ts) < rano_utc(?)");
        params.push(until.clone());
    }

    sql.push_str(&format!(
        " GROUP BY root_seg ORDER BY connects DESC, root_seg ASC LIMIT {}",
        top
    ));
    (sql, params)
}

fn query_top_domains(
    conn: &Connection,
    filter: &ReportFilter,
    top: usize,
) -> Result<Vec<DomainStats>, String> {
    let (sql, params) = build_domains_query(filter, top);
    let params_refs: Vec<&dyn rusqlite::ToSql> =
        params.iter().map(|s| s as &dyn rusqlite::ToSql).collect();

    let mut stmt = conn
        .prepare(&sql)
        .map_err(|e| format!("Failed to prepare query: {}", e))?;

    let rows = stmt
        .query_map(params_refs.as_slice(), |row| {
            Ok(DomainStats {
                domain: row.get(0)?,
                events: row.get(1)?,
                provider: row.get(2)?,
                source: row.get(3)?,
            })
        })
        .map_err(|e| format!("Failed to query domains: {}", e))?;

    let mut results = Vec::new();
    for row in rows {
        results.push(row.map_err(|e| format!("Failed to read row: {}", e))?);
    }
    Ok(results)
}

fn build_domains_query(filter: &ReportFilter, top: usize) -> (String, Vec<String>) {
    // A mixed group must not promote every event to its strongest source.
    let mut sql = String::from(
        "SELECT COALESCE(domain, 'unknown') as domain,
                COUNT(*) as events,
                provider,
                CASE WHEN COUNT(DISTINCT CASE WHEN domain_source IN ('sni','dns','ptr') THEN domain_source ELSE 'none' END)>1 THEN 'mixed'
                     ELSE MAX(CASE WHEN domain_source IN ('sni','dns','ptr') THEN domain_source END) END as source
         FROM events WHERE domain IS NOT NULL AND domain != ''",
    );
    let mut params: Vec<String> = Vec::new();

    if let Some(ref run_id) = filter.run_id {
        sql.push_str(" AND run_id = ?");
        params.push(run_id.clone());
    }
    if let Some(ref since) = filter.since {
        sql.push_str(" AND rano_utc(ts) >= rano_utc(?)");
        params.push(since.clone());
    }
    if let Some(ref until) = filter.until {
        sql.push_str(" AND rano_utc(ts) < rano_utc(?)");
        params.push(until.clone());
    }

    sql.push_str(&format!(
        " GROUP BY domain, provider ORDER BY events DESC, domain ASC, provider ASC LIMIT {}",
        top
    ));
    (sql, params)
}

fn query_top_ips(
    conn: &Connection,
    filter: &ReportFilter,
    top: usize,
) -> Result<Vec<IpStats>, String> {
    let (sql, params) = build_ips_query(filter, top);
    let params_refs: Vec<&dyn rusqlite::ToSql> =
        params.iter().map(|s| s as &dyn rusqlite::ToSql).collect();

    let mut stmt = conn
        .prepare(&sql)
        .map_err(|e| format!("Failed to prepare query: {}", e))?;

    let rows = stmt
        .query_map(params_refs.as_slice(), |row| {
            Ok(IpStats {
                ip: row.get(0)?,
                events: row.get(1)?,
                domain: row.get(2).ok(),
            })
        })
        .map_err(|e| format!("Failed to query IPs: {}", e))?;

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
                MIN(CASE WHEN domain IS NOT NULL AND domain!='' AND domain!='unknown' THEN domain END)
         FROM events WHERE remote_ip IS NOT NULL AND remote_ip NOT IN ('','0.0.0.0','::')",
    );
    let mut params: Vec<String> = Vec::new();

    if let Some(ref run_id) = filter.run_id {
        sql.push_str(" AND run_id = ?");
        params.push(run_id.clone());
    }
    if let Some(ref since) = filter.since {
        sql.push_str(" AND rano_utc(ts) >= rano_utc(?)");
        params.push(since.clone());
    }
    if let Some(ref until) = filter.until {
        sql.push_str(" AND rano_utc(ts) < rano_utc(?)");
        params.push(until.clone());
    }

    sql.push_str(&format!(
        " GROUP BY remote_ip ORDER BY events DESC, remote_ip ASC LIMIT {}",
        top
    ));
    (sql, params)
}

fn init_sqlite(conn: &mut Connection) -> rusqlite::Result<()> {
    configure_query_connection(conn)?;
    // Phase 1: pragmas + base tables only. Must not reference columns that older
    // databases may lack, or CREATE INDEX/VIEW would fail before migration runs.
    conn.execute_batch(
        "
        PRAGMA journal_mode=WAL;
        PRAGMA synchronous=NORMAL;
        PRAGMA busy_timeout=5000;
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
            ancestry_path TEXT,
            remote_is_private INTEGER,
            ip_version INTEGER,
            duration_ms INTEGER,
            alert INTEGER,
            retry_count INTEGER
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
            closes INTEGER,
            session_name TEXT
        );
        ",
    )?;

    // Phase 2: migrate columns added after the original schema so any historical DB
    // opens cleanly (missing columns previously caused insert failures that disabled
    ensure_column(conn, "events", "domain_source", "TEXT")?;
    ensure_column(conn, "events", "run_id", "TEXT")?;
    ensure_column(conn, "events", "duration_ms", "INTEGER")?;
    ensure_column(conn, "events", "ancestry_path", "TEXT")?;
    ensure_column(conn, "events", "alert", "INTEGER")?;
    ensure_column(conn, "events", "remote_is_private", "INTEGER")?;
    ensure_column(conn, "events", "ip_version", "INTEGER")?;
    ensure_column(conn, "events", "retry_count", "INTEGER")?;
    ensure_column(conn, "events", "ownership_json", "TEXT")?;
    ensure_column(conn, "events", "observation_id", "TEXT")?;
    ensure_column(conn, "sessions", "session_name", "TEXT")?;

    // Phase 3: indexes and views (safe now that all columns exist).
    ensure_column(conn, "sessions", "observer_pid", "INTEGER")?;
    ensure_column(conn, "sessions", "observer_start_time", "TEXT")?;
    ensure_column(conn, "sessions", "last_poll_ts", "TEXT")?;
    ensure_column(conn, "sessions", "active_at_poll", "INTEGER")?;
    ensure_column(conn, "sessions", "poll_valid", "INTEGER")?;
    conn.execute_batch(
        "
        CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
        CREATE INDEX IF NOT EXISTS idx_events_run_id ON events(run_id);
        CREATE INDEX IF NOT EXISTS idx_events_observation_id ON events(run_id, observation_id, event);
        CREATE INDEX IF NOT EXISTS idx_events_provider ON events(provider);
        CREATE INDEX IF NOT EXISTS idx_events_remote_ip ON events(remote_ip);
        CREATE INDEX IF NOT EXISTS idx_events_domain ON events(domain);
        CREATE INDEX IF NOT EXISTS idx_events_ancestry_path ON events(ancestry_path);
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
        CREATE VIEW IF NOT EXISTS provider_domain_sources AS
            SELECT provider, domain, domain_source, COUNT(*) AS events
            FROM events WHERE domain IS NOT NULL AND domain != 'unknown'
            GROUP BY provider, domain, domain_source;
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
    Ok(())
}

/// Allow concurrent readers (report/export/diff/status) to wait briefly instead of
/// failing with SQLITE_BUSY while the monitor's writer thread holds the database.
fn configure_query_connection(conn: &Connection) -> rusqlite::Result<()> {
    conn.busy_timeout(Duration::from_millis(5000))?;
    conn.create_scalar_function(
        "rano_utc",
        1,
        rusqlite::functions::FunctionFlags::SQLITE_UTF8
            | rusqlite::functions::FunctionFlags::SQLITE_DETERMINISTIC,
        |context| {
            let value: Option<String> = context.get(0)?;
            value
                .map(|value| {
                    normalize_utc_timestamp(&value).map_err(|message| {
                        rusqlite::Error::UserFunctionError(Box::new(io::Error::new(
                            io::ErrorKind::InvalidData,
                            message,
                        )))
                    })
                })
                .transpose()
        },
    )?;
    // Unfiltered reports retain malformed legacy rows in their totals, while
    // explicitly marking chronology-based metrics unavailable. Time filters
    // still use the strict function above and refuse unorderable timestamps.
    conn.create_scalar_function(
        "rano_report_utc",
        1,
        rusqlite::functions::FunctionFlags::SQLITE_UTF8
            | rusqlite::functions::FunctionFlags::SQLITE_DETERMINISTIC,
        |context| {
            let value: Option<String> = context.get(0)?;
            Ok(value.and_then(|value| normalize_utc_timestamp(&value).ok()))
        },
    )
}
fn insert_session(conn: &mut Connection, ctx: &RunContext) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO sessions (run_id, start_ts, host, user, patterns, domain_mode, args, interval_ms, stats_interval_ms, session_name, observer_pid, observer_start_time)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
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
            &ctx.session_name,
            ctx.observer.map(|identity| identity.pid),
            ctx.observer.map(|identity| identity.start_time.to_string()),
        ],
    )?;
    Ok(())
}

fn finalize_session(
    conn: &mut Connection,
    run_id: &str,
    connects: u64,
    closes: u64,
) -> rusqlite::Result<()> {
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
    let domain = (event.key.socket_kind == SocketKind::Connection)
        .then(|| event.domain.as_deref().unwrap_or("unknown"));
    conn.execute(
        "INSERT INTO events (ts, run_id, event, provider, pid, comm, cmdline, proto, local_ip, local_port, remote_ip, remote_port, domain, domain_source, ancestry_path, remote_is_private, ip_version, duration_ms, alert, retry_count, ownership_json, observation_id)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22)",
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
            domain,
            event.domain_source.as_deref(),
            event.ancestry_path.as_deref(),
            if is_private { 1 } else { 0 },
            ip_version,
            event.duration_ms.map(|v| v as i64),
            if event.alert { 1 } else { 0 },
            event.retry_count.map(|v| v as i64),
            event.ownership_json.as_deref(),
            event.observation_id.as_deref(),
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

fn push_json_array(out: &mut String, key: &str, values: &[String], first: bool) {
    if !first {
        out.push(',');
    }
    out.push('"');
    out.push_str(key);
    out.push_str("\":[");
    for (idx, value) in values.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        out.push('"');
        out.push_str(&escape_json(value));
        out.push('"');
    }
    out.push(']');
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

#[cfg(test)]
mod tests {
    #[test]
    fn ptr_cache_expires_positive_and_negative_results_and_evicts_oldest() {
        let (requests, _receive_requests) = mpsc::sync_channel(PTR_QUEUE_CAPACITY);
        let (send_results, results) = mpsc::sync_channel(PTR_QUEUE_CAPACITY);
        let mut resolver = PtrResolver {
            requests,
            results,
            pending: HashMap::new(),
            cache: HashMap::new(),
            health: PtrHealth::default(),
        };
        let now = Instant::now();
        for index in 0..PTR_CACHE_MAX {
            let ip = IpAddr::V4(Ipv4Addr::from(index as u32));
            resolver.cache.insert(
                ip,
                DnsCacheEntry {
                    value: Some(format!("host-{index}")),
                    stored_at: now - Duration::from_secs((PTR_CACHE_MAX - index) as u64 / 4),
                },
            );
        }
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        resolver.pending.insert(ip, now);
        send_results
            .send(PtrResult {
                ip,
                requested_at: now,
                value: None,
            })
            .unwrap();
        resolver.maintain();
        assert_eq!(resolver.cache.len(), PTR_CACHE_MAX);
        assert!(
            !resolver
                .cache
                .contains_key(&IpAddr::V4(Ipv4Addr::UNSPECIFIED))
        );
        assert_eq!(resolver.health.evicted, 1);
        assert!(resolver.resolve(ip).is_none());
        assert_eq!(
            resolver.health.requested, 0,
            "negative results must be cached"
        );
        for entry in resolver.cache.values_mut() {
            entry.stored_at = Instant::now() - PTR_TTL;
        }
        resolver.maintain();
        assert!(resolver.cache.is_empty());
        assert_eq!(resolver.health.expired, PTR_CACHE_MAX as u64);
        let expired = Instant::now() - PTR_TTL;
        resolver.pending.insert(ip, expired);
        send_results
            .send(PtrResult {
                ip,
                requested_at: expired,
                value: Some("stale".to_string()),
            })
            .unwrap();
        resolver.maintain();
        assert!(resolver.cache.is_empty());
        assert!(resolver.pending.is_empty());
        assert_eq!(resolver.health.expired, PTR_CACHE_MAX as u64 + 1);
    }

    #[test]
    fn stalled_ptr_workers_leave_poll_requests_nonblocking_bounded_and_deduplicated() {
        let (started, receive_started) = mpsc::channel();
        let release = Arc::new((Mutex::new(false), std::sync::Condvar::new()));
        let worker_release = Arc::clone(&release);
        let mut resolver = PtrResolver::with_lookup(move |ip| {
            started.send(ip).unwrap();
            let (lock, condition) = &*worker_release;
            let _guard = condition
                .wait_while(lock.lock().unwrap(), |released| !*released)
                .unwrap();
            Some(format!("resolved-{ip}"))
        });
        let first = IpAddr::V4(Ipv4Addr::LOCALHOST);
        assert!(resolver.resolve(first).is_none());
        receive_started
            .recv_timeout(Duration::from_secs(5))
            .unwrap();
        let second = IpAddr::V4(Ipv4Addr::from(2));
        resolver.resolve(second);
        receive_started
            .recv_timeout(Duration::from_secs(5))
            .unwrap();
        let timer = Instant::now();
        for index in 3..10_000 {
            resolver.resolve(IpAddr::V4(Ipv4Addr::from(index)));
        }
        // Release even before assertions so failed checks cannot leave a test worker blocked.
        let elapsed = timer.elapsed();
        *release.0.lock().unwrap() = true;
        release.1.notify_all();
        assert!(
            elapsed < Duration::from_secs(1),
            "requests waited on stalled workers: {elapsed:?}"
        );
        assert!(resolver.pending.len() <= PTR_QUEUE_CAPACITY + PTR_WORKERS);
        assert!(resolver.health.deferred > 0);
        let requested = resolver.health.requested;
        resolver.resolve(first);
        assert_eq!(resolver.health.requested, requested);
        let deadline = Instant::now() + Duration::from_secs(5);
        while !resolver.pending.is_empty() && Instant::now() < deadline {
            resolver.maintain();
            std::thread::yield_now();
        }
        assert!(resolver.pending.is_empty());
        assert_eq!(
            resolver.resolve(first),
            Some("resolved-127.0.0.1".to_string())
        );
        assert_eq!(resolver.health.requested, resolver.health.completed);
    }

    #[test]
    fn ptr_results_correct_unknown_held_flows_without_claiming_capture_provenance() {
        let (requests, receive_requests) = mpsc::sync_channel(PTR_QUEUE_CAPACITY);
        let (send_results, results) = mpsc::sync_channel(PTR_QUEUE_CAPACITY);
        let mut resolver = Some(PtrResolver {
            requests,
            results,
            pending: HashMap::new(),
            cache: HashMap::new(),
            health: PtrHealth::default(),
        });
        let mut key = create_test_event("2026-01-01T00:00:00Z", "connect", Provider::Unknown).key;
        key.remote_ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let initial = resolve_observed_domain(&key, None, None, &mut resolver, true, UNIX_EPOCH);
        assert!(initial.hostname.is_none());
        let (ip, requested_at) = receive_requests
            .recv_timeout(Duration::from_secs(1))
            .unwrap();
        send_results
            .send(PtrResult {
                ip,
                requested_at,
                value: Some("localhost".to_string()),
            })
            .unwrap();
        resolver.as_mut().unwrap().maintain();
        let later = resolve_observed_domain(&key, None, None, &mut resolver, true, UNIX_EPOCH);
        assert_eq!(later.hostname.as_deref(), Some("localhost"));
        assert_eq!(later.source, Some(pcap_capture::DomainSource::Ptr));
        assert_eq!(later.scope, "reverse-ip");
        assert!(later.captured_at.is_none());
        assert_eq!(resolver.as_ref().unwrap().health.requested, 1);
        let json = format_ptr_health_json(&resolver.as_ref().unwrap().health());
        assert!(json.contains("\"pending\":0"));
        assert!(json.contains("\"completed\":1"));
        resolver.as_mut().unwrap().cache.clear();
        let retained =
            resolve_observed_domain(&key, Some(&later), None, &mut resolver, true, UNIX_EPOCH);
        assert_eq!(
            retained.hostname, later.hostname,
            "scratch eviction erased observed held PTR"
        );
        assert_eq!(retained.source, Some(pcap_capture::DomainSource::Ptr));
        assert_eq!(retained.scope, "reverse-ip");
        assert!(retained.captured_at.is_none());
        let fresh_unknown =
            resolve_observed_domain(&key, None, None, &mut resolver, true, UNIX_EPOCH);
        assert!(
            fresh_unknown.hostname.is_none(),
            "new observations must not invent a prior hostname"
        );
    }

    #[test]
    fn updater_passes_literal_arguments_and_repo_environment_to_installer() {
        let destination = "/tmp/quoted '$PATH;\ninstaller";
        let update = UpdateCommand {
            version: Some("v0.2.1".to_string()),
            system: true,
            easy_mode: true,
            dest: Some(PathBuf::from(destination)),
            from_source: true,
            verify: true,
            quiet: true,
            no_gum: true,
            owner: None,
            repo: None,
            branch: None,
        };
        let command = update_installer_command(&update, "custom-owner", "custom-repo");
        assert_eq!(command.get_program(), "bash");
        let args: Vec<_> = command
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            args,
            [
                "-s",
                "--",
                "--version",
                "v0.2.1",
                "--system",
                "--easy-mode",
                "--dest",
                destination,
                "--from-source",
                "--verify",
                "--quiet",
                "--no-gum"
            ]
        );
        let environment: BTreeMap<_, _> = command
            .get_envs()
            .map(|(key, value)| {
                (
                    key.to_string_lossy().into_owned(),
                    value.unwrap().to_string_lossy().into_owned(),
                )
            })
            .collect();
        assert_eq!(
            environment,
            BTreeMap::from([
                ("OWNER".to_string(), "custom-owner".to_string()),
                ("REPO".to_string(), "custom-repo".to_string())
            ])
        );
    }

    #[test]
    fn monitor_backend_rejects_unsupported_platforms_before_reading_proc() {
        for platform in ["macos", "freebsd", "windows", "unknown"] {
            let error =
                check_monitor_backend(platform, Path::new("/nonexistent-proc"), true).unwrap_err();
            assert!(error.contains(platform));
            assert!(error.contains("requires Linux /proc"));
            assert!(error.contains("History and configuration commands"));
            assert!(!error.contains("NotFound"));
        }
    }

    #[test]
    fn monitor_backend_classifies_missing_and_invalid_proc_identity() {
        let root = tempfile::tempdir().unwrap().keep();
        let error = check_monitor_backend("linux", &root, true).unwrap_err();
        assert!(error.contains("self/stat"));
        assert!(error.contains("NotFound"));
        assert!(error.contains("Mount a readable procfs"));
        fs::create_dir(root.join("self")).unwrap();
        fs::write(root.join("self/stat"), "not a Linux stat record").unwrap();
        let error = check_monitor_backend("linux", &root, false).unwrap_err();
        assert!(error.contains("invalid Linux process identity"));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn monitor_backend_checks_real_proc_and_refuses_missing_socket_tables() {
        check_monitor_backend("linux", Path::new("/proc"), true).unwrap();
        let root = tempfile::tempdir().unwrap().keep();
        fs::create_dir(root.join("self")).unwrap();
        fs::create_dir(root.join("self/ns")).unwrap();
        fs::create_dir(root.join("self/fd")).unwrap();
        fs::write(root.join("self/stat"), fs::read("/proc/self/stat").unwrap()).unwrap();
        std::os::unix::fs::symlink("net:[fixture]", root.join("self/ns/net")).unwrap();
        let error = check_monitor_backend("linux", &root, false).unwrap_err();
        assert!(error.contains("net/tcp") && error.contains("NotFound"));
        fs::create_dir(root.join("net")).unwrap();
        fs::write(root.join("net/tcp"), "not a socket table\n").unwrap();
        let error = check_monitor_backend("linux", &root, false).unwrap_err();
        assert!(error.contains("invalid Linux socket-table header"));
        fs::write(root.join("net/tcp"), "sl local_address inode\n").unwrap();
        fs::write(root.join("net/tcp6"), "sl local_address inode\n").unwrap();
        check_monitor_backend("linux", &root, false).unwrap();
        let error = check_monitor_backend("linux", &root, true).unwrap_err();
        assert!(error.contains("net/udp") && error.contains("NotFound"));
        fs::write(root.join("net/udp"), "sl local_address inode\n").unwrap();
        fs::write(root.join("net/udp6"), "sl local_address inode\n").unwrap();
        check_monitor_backend("linux", &root, true).unwrap();
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn real_socket_owner_scan_rejects_stale_process_generation_and_topology() {
        use std::os::fd::AsRawFd;
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let inode = parse_socket_inode(
            &fs::read_link(format!("/proc/self/fd/{}", listener.as_raw_fd()))
                .unwrap()
                .to_string_lossy(),
        )
        .unwrap();
        let pid = std::process::id();
        let actual = read_proc_stat(pid).unwrap();
        let mut snapshot = ProcessSnapshot::default();
        snapshot.stat.insert(pid, actual.clone());
        let targets = HashSet::from([pid]);
        let scan = map_inodes(&targets, &snapshot);
        assert_eq!(scan.owners[&inode], vec![actual.identity]);
        assert!(scan.errors.is_empty());
        let mut stale_generation = actual.clone();
        stale_generation.identity.start_time += 1;
        let mut stale_parent = actual.clone();
        stale_parent.ppid = stale_parent.ppid.saturating_add(1);
        let mut stale_comm = actual;
        stale_comm.comm.push_str("-changed");
        for stale in [stale_generation, stale_parent, stale_comm] {
            snapshot.stat.insert(pid, stale);
            let rejected = map_inodes(&targets, &snapshot);
            assert!(!rejected.owners.contains_key(&inode));
            assert!(!rejected.errors.is_empty());
        }
    }

    #[test]
    fn socket_admission_preserves_endpoints_and_requested_local_sockets() {
        let mut args = MonitorArgs::default();
        for ip in ["0.0.0.0", "::"] {
            let mut entry = NetEntry {
                local_ip: ip.parse().unwrap(),
                local_port: 1234,
                remote_ip: ip.parse().unwrap(),
                remote_port: 0,
                inode: 42,
                state: "0A".to_string(),
            };
            assert_eq!(socket_kind(Proto::Tcp, &entry, &args), None);
            args.include_listening = true;
            assert_eq!(
                socket_kind(Proto::Tcp, &entry, &args),
                Some(SocketKind::Listener)
            );
            entry.state = "01".to_string();
            assert_eq!(socket_kind(Proto::Tcp, &entry, &args), None);
            assert_eq!(
                socket_kind(Proto::Udp, &entry, &args),
                Some(SocketKind::BoundUdp)
            );
            entry.remote_port = 443;
            assert_eq!(
                socket_kind(Proto::Tcp, &entry, &args),
                Some(SocketKind::Connection)
            );
            assert_eq!(
                socket_kind(Proto::Udp, &entry, &args),
                Some(SocketKind::Connection)
            );
            args.include_udp = false;
            assert_eq!(socket_kind(Proto::Udp, &entry, &args), None);
            args.include_udp = true;
            args.include_listening = false;
        }
    }

    #[test]
    fn socket_row_parser_checks_addresses_states_and_inode_without_panicking() {
        let row = "0: 0100007F:3039 0200007F:01BB 01 0:0 0:0 0 1000 0 42";
        let entry = parse_net_entry(row, false).unwrap();
        assert_eq!(entry.local_ip, "127.0.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(entry.remote_port, 443);
        assert_eq!(entry.inode, 42);
        let row6 = "0: 00000000000000000000000001000000:3039 00000000000000000000000001000000:0000 0a 0:0 0:0 0 1000 0 43";
        assert_eq!(parse_net_entry(row6, true).unwrap().state, "0A");
        for row in [
            "",
            "bad row",
            "0: BAD:1 0100007F:0000 0A 0:0 0:0 0 1000 0 42",
            "0: 0100007F:3039 0200007F:01BB XX 0:0 0:0 0 1000 0 42",
            "0: 0100007F:3039 0200007F:01BB 01 0:0 0:0 0 1000 0 bad",
        ] {
            assert!(parse_net_entry(row, false).is_none());
        }
        assert!(parse_addr_port("0100007F:01BB:extra", false).is_none());
        assert!(parse_ipv6("éééééééééééééééé").is_none());
        assert!(read_net_file("/proc/net/rano-nonexistent-table", Proto::Tcp, false).is_err());
    }

    #[test]
    fn local_socket_observations_do_not_invent_connections_or_provider_breaches() {
        let mut stats = Stats::default();
        stats.observed_open(Provider::Anthropic, SocketKind::Listener);
        stats.observed_open(Provider::Anthropic, SocketKind::BoundUdp);
        assert_eq!(
            (
                stats.connects,
                stats.active,
                stats.listens,
                stats.binds,
                stats.socket_active
            ),
            (0, 0, 1, 1, 2)
        );
        assert!(stats.active_per_provider.is_empty());
        stats.observed_close(Provider::Anthropic, SocketKind::Listener);
        assert_eq!(
            (stats.closes, stats.socket_closes, stats.socket_active),
            (0, 1, 1)
        );
        let json = format_socket_ownership_json(
            42,
            ProcessIdentity::default(),
            ProcessIdentity::default(),
            &[],
            None,
            SocketKind::BoundUdp,
            "07",
            None,
            None,
        );
        assert!(json.contains("\"socket_kind\":\"bound_udp\""));
        assert!(json.contains("\"remote_present\":false"));
        assert!(json.contains("\"direction\":\"unknown\""));
    }

    #[test]
    fn durable_local_socket_has_no_hostname_and_endpoint_unknown_is_preserved() {
        let mut conn = setup_test_db();
        let mut bound = create_test_event("2026-10-13T20:00:00Z", "bind", Provider::Anthropic);
        bound.key.socket_kind = SocketKind::BoundUdp;
        bound.key.remote_port = 0;
        bound.domain = Some("must-not-be-attributed.test".to_string());
        log_sqlite_event(&mut conn, &bound).unwrap();
        let domain: Option<String> = conn
            .query_row("SELECT domain FROM events WHERE event='bind'", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(domain, None);
        let mut endpoint =
            create_test_event("2026-10-13T20:00:01Z", "connect", Provider::Anthropic);
        endpoint.domain = None;
        log_sqlite_event(&mut conn, &endpoint).unwrap();
        let domain: String = conn
            .query_row(
                "SELECT domain FROM events WHERE event='connect'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(domain, "unknown");
    }

    #[test]
    fn incomplete_owner_scan_preserves_existing_episode_but_pid_reuse_does_not() {
        let event = create_test_event("2026-10-13T20:00:00Z", "connect", Provider::Anthropic);
        let key = event.key;
        let keys = [key.clone()];
        let mut snapshot =
            topology_fixture(&[(key.process.pid, 0, key.process.start_time, "helper")]);
        let inaccessible = HashSet::from([key.process.pid]);
        assert!(preserve_unobservable_keys(keys.iter(), &inaccessible, &snapshot).contains(&key));
        assert!(preserve_unobservable_keys(keys.iter(), &HashSet::new(), &snapshot).is_empty());
        snapshot
            .stat
            .get_mut(&key.process.pid)
            .unwrap()
            .identity
            .start_time += 1;
        assert!(preserve_unobservable_keys(keys.iter(), &inaccessible, &snapshot).is_empty());
        assert!(
            preserve_unobservable_keys(keys.iter(), &inaccessible, &ProcessSnapshot::default())
                .contains(&key)
        );
    }

    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn file_records_honor_format_independently_of_stdout() {
        let style = OutputStyle {
            color: false,
            theme: Theme::Mono,
        };
        let event = create_test_event("2026-01-20T12:00:00Z", "connect", Provider::Anthropic);
        for json_stdout in [false, true] {
            for requested in [LogFormat::Auto, LogFormat::Pretty, LogFormat::Json] {
                let file = NamedTempFile::new().unwrap();
                let format = log_format_for_output(json_stdout, requested);
                let writer = Arc::new(LogWriter {
                    file: Mutex::new(file.reopen().unwrap()),
                    format,
                    failed: AtomicBool::new(false),
                });
                emit_event(
                    &event.ts,
                    "connect",
                    "run\"\\\n雪",
                    &event.key,
                    1234,
                    "claude",
                    "--token secret",
                    Some("--token [REDACTED]"),
                    Provider::Anthropic,
                    Some("quote\"\\\t.example"),
                    Some("dns"),
                    None,
                    None,
                    None,
                    "ptr",
                    json_stdout,
                    style,
                    format,
                    Some(&writer),
                );
                emit_alert(
                    &AlertKind::MaxConnections {
                        current: 2,
                        threshold: 1,
                    },
                    AlertSeverity::Warning,
                    None,
                    None,
                    false,
                    json_stdout,
                    style,
                    Some(&writer),
                );
                writer.warning("warning: quote\"\\\n\0雪");
                let mut stats = Stats {
                    connects: 2,
                    active: 2,
                    ..Stats::default()
                };
                summary(
                    &mut stats,
                    json_stdout,
                    5,
                    style,
                    "ptr",
                    Some(&writer),
                    1,
                    0,
                );
                let text = fs::read_to_string(file.path()).unwrap();
                if format == LogFormat::Json {
                    let lines: Vec<_> = text.lines().collect();
                    assert_eq!(
                        lines.len(),
                        4,
                        "stdout={json_stdout}, requested={requested:?}"
                    );
                    assert!(lines[0].contains("[REDACTED]"));
                    assert!(!text.contains("--token secret"));
                    assert!(lines[1].contains("\"type\":\"alert\""));
                    assert!(lines[2].contains("\\u0000"));
                    assert!(lines[3].contains("\"summary\""));
                    assert!(
                        lines
                            .iter()
                            .all(|line| line.starts_with('{') && line.ends_with('}'))
                    );
                } else {
                    assert!(text.starts_with("2026-01-20T12:00:00Z"));
                    assert!(text.contains("[ALERT]"));
                    assert!(text.contains("summary connects=2"));
                    assert!(!text.contains("\"type\":\"alert\""));
                }
            }
        }
    }

    #[test]
    fn report_escapes_all_database_metadata_and_filter_strings() {
        let hostile = "quote\"\\\n\r\t\0雪";
        let mut conn = setup_test_db();
        let mut ctx = RunContext::new(&MonitorArgs::default(), "ptr", None);
        ctx.run_id = hostile.to_string();
        ctx.start_ts = hostile.to_string();
        ctx.host = hostile.to_string();
        ctx.user = hostile.to_string();
        ctx.patterns = hostile.to_string();
        insert_session(&mut conn, &ctx).unwrap();
        let mut event = create_test_event("2026-01-20T12:00:00Z", "connect", Provider::Anthropic);
        event.run_id = ctx.run_id.clone();
        event.domain = Some(hostile.to_string());
        event.domain_source = Some(hostile.to_string());
        write_sqlite_batch(&mut conn, &[event]).unwrap();
        conn.execute("UPDATE events SET provider=?1, remote_ip=?1", [hostile])
            .unwrap();
        conn.execute("UPDATE sessions SET end_ts=?1", [hostile])
            .unwrap();
        let filter = ReportFilter {
            run_id: Some(hostile.to_string()),
            since: None,
            until: None,
        };
        let output = format_report_json(&conn, &filter, 10, true, true).unwrap();
        let escaped = escape_json(hostile);
        for field in [
            "run_id", "start_ts", "end_ts", "host", "user", "patterns", "provider", "domain", "ip",
        ] {
            assert!(
                output.contains(&format!("\"{field}\": \"{escaped}\"")),
                "{field}: {output}"
            );
        }
        assert!(!output.contains(hostile));
        // Unknown source labels are normalized to null by the provenance query.
        assert!(output.contains("\"source\": null"));
        conn.execute("UPDATE events SET domain_source='sni'", [])
            .unwrap();
        assert!(
            format_report_json(&conn, &filter, 10, true, true)
                .unwrap()
                .contains("\"source\": \"sni\"")
        );
    }

    #[test]
    fn json_escaping_covers_control_characters_and_preserves_unicode() {
        for byte in 0u8..=31 {
            assert!(!escape_json(&char::from(byte).to_string()).contains(char::from(byte)));
        }
        assert_eq!(escape_json("雪/\"\\"), "雪/\\\"\\\\");
        assert_eq!(escape_json("\u{7f}\u{85}"), "\\u007f\\u0085");
    }

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
            openai: None, // Should keep default "codex", "openai"
            google: None, // Should keep default "gemini", "google"
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
    fn csv_escape_quotes_and_commas() {
        assert_eq!(csv_escape("plain"), "plain");
        assert_eq!(csv_escape("a,b"), "\"a,b\"");
        assert_eq!(csv_escape("say \"hi\""), "\"say \"\"hi\"\"\"");
        assert_eq!(csv_escape("line1\nline2"), "\"line1\nline2\"");
        assert_eq!(csv_escape(""), "");
    }

    #[test]
    fn glob_to_sql_like_converts_wildcards() {
        assert_eq!(glob_to_sql_like("api.*"), "api.%");
        assert_eq!(glob_to_sql_like("a?c"), "a_c");
        assert_eq!(glob_to_sql_like("100%"), "100\\%");
        assert_eq!(glob_to_sql_like("x_y"), "x\\_y");
    }

    #[test]
    fn validate_fields_rejects_unknown() {
        let fields = vec!["ts".to_string(), "nope".to_string()];
        assert!(validate_fields(&fields).is_err());
    }

    #[test]
    fn truncate_ancestry_list_limits_depth() {
        let list = vec![
            "a(1)".to_string(),
            "b(2)".to_string(),
            "c(3)".to_string(),
            "d(4)".to_string(),
            "e(5)".to_string(),
            "f(6)".to_string(),
        ];
        let truncated = truncate_ancestry_list(&list);
        assert_eq!(
            truncated,
            vec!["...".to_string(), "e(5)".to_string(), "f(6)".to_string()]
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
        let (sql, params) = build_summary_query(&filter, true);
        assert!(sql.contains("run_id = ?"));
        assert!(sql.contains("rano_utc(ts) >= rano_utc(?)"));
        assert!(sql.contains("rano_utc(ts) < rano_utc(?)"));
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
        assert_eq!(parsed, Some("2026-01-17T12:00:00.000000000Z".to_string()));

        let date = Some("2026-01-17".to_string());
        let parsed = parse_time_filter(&date).expect("date should parse");
        assert_eq!(parsed, Some("2026-01-17T00:00:00.000000000Z".to_string()));
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

    #[test]
    fn utc_calendar_offsets_and_nanoseconds_preserve_exact_instants() {
        assert_eq!(calendar_days(1970, 1, 1), 0);
        assert_eq!(
            parse_utc_timestamp("1969-12-31T23:59:59Z").unwrap(),
            (-1, 0)
        );
        for (input, expected) in [
            ("2000-02-29", "2000-02-29T00:00:00.000000000Z"),
            (
                "2024-03-01T00:15:00+01:00",
                "2024-02-29T23:15:00.000000000Z",
            ),
            (
                "2026-01-01t00:00:00.123456789+02:30",
                "2025-12-31T21:30:00.123456789Z",
            ),
            (
                "2025-12-31T23:30:00.5-01:00",
                "2026-01-01T00:30:00.500000000Z",
            ),
            ("0000-02-29T00:00:00z", "0000-02-29T00:00:00.000000000Z"),
            (
                "9999-12-31T23:59:59.999999999Z",
                "9999-12-31T23:59:59.999999999Z",
            ),
        ] {
            assert_eq!(normalize_utc_timestamp(input).unwrap(), expected);
        }
        assert_eq!(
            format_session_duration("1969-12-31T23:59:59.9Z", "1970-01-01T00:00:01.1Z"),
            Some("1s".to_string())
        );
        assert_eq!(
            format_session_duration("2026-01-01T12:00:00+02:00", "2026-01-01T10:00:01Z"),
            Some("1s".to_string())
        );
    }

    #[test]
    fn malformed_calendar_and_duration_bounds_fail_without_panicking() {
        for input in [
            "2026-99-99",
            "1900-02-29",
            "2023-02-29",
            "2026-04-31",
            "2026-01-00",
            "2026-01-01T24:00:00Z",
            "2026-01-01T12:60:00Z",
            "2026-01-01T12:00:60Z",
            "2026-01-01T12:00:00-00:00",
            "2026-01-01T12:00:00+24:00",
            "2026-01-01T12:00:00",
            "2026-01-01T12:00:00.Z",
            "2026-01-01T12:00:00.1234567890Z",
            "2026-01-01T12:00:00Zjunk",
            "雪雪雪雪雪雪雪",
            "0000-01-01T00:00:00+01:00",
            "9999-12-31T23:59:59-01:00",
        ] {
            assert!(normalize_utc_timestamp(input).is_err(), "accepted {input}");
        }
        for input in [
            "18446744073709551615w",
            "18446744073709551615m",
            "99999999999999999999h",
            "999999999999d",
            "+1h",
        ] {
            assert!(
                parse_time_filter(&Some(input.to_string())).is_err(),
                "accepted {input}"
            );
        }
        let same = Some("2026-01-01T00:00:00.000000000Z".to_string());
        assert!(validate_time_range(&same, &same).is_err());
        assert!(
            validate_time_range(&Some("2026-02-01T00:00:00.000000000Z".to_string()), &same)
                .is_err()
        );
        assert!(validate_time_range(&same, &None).is_ok());
    }

    #[test]
    fn normalized_sql_filters_keep_inclusive_start_exclusive_end_and_fraction_order() {
        let mut conn = setup_test_db();
        let rows = [
            create_test_event(
                "2026-01-01T01:00:00.000000001+01:00",
                "connect",
                Provider::Anthropic,
            ),
            create_test_event(
                "2026-01-01T00:00:00.000000002Z",
                "connect",
                Provider::OpenAI,
            ),
            create_test_event(
                "2025-12-31T19:00:00.000000003-05:00",
                "close",
                Provider::Anthropic,
            ),
        ];
        write_sqlite_batch(&mut conn, &rows).unwrap();
        let filter = ReportFilter {
            run_id: Some("test-run".to_string()),
            since: Some("2026-01-01T00:00:00.000000001Z".to_string()),
            until: Some("2026-01-01T00:00:00.000000003Z".to_string()),
        };
        let result = query_summary(&conn, &filter).unwrap();
        assert_eq!(
            (result.total_events, result.connects, result.closes),
            (2, 2, 0)
        );
        let export_filter = ExportFilter {
            run_id: filter.run_id,
            since: None,
            until: None,
            providers: Vec::new(),
            domain_patterns: Vec::new(),
        };
        let (sql, params) = build_export_query(&export_filter, &["ts".to_string()]);
        let mut stmt = conn.prepare(&sql).unwrap();
        let times: Vec<String> = stmt
            .query_map(params![params[0]], |row| row.get(0))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        assert_eq!(
            times,
            rows.iter().map(|row| row.ts.clone()).collect::<Vec<_>>()
        );
    }

    #[test]
    fn report_insights_use_utc_bins_close_durations_and_carried_window_balance() {
        let mut conn = setup_test_db();
        let cases = [
            (
                "2026-01-01T00:59:59Z",
                "connect",
                Provider::Anthropic,
                "a.test",
                "1.1.1.1",
                Some(999_000),
            ),
            (
                "2026-01-01T01:00:00Z",
                "connect",
                Provider::OpenAI,
                "b.test",
                "2.2.2.2",
                None,
            ),
            (
                "2026-01-01T02:00:00+01:00",
                "close",
                Provider::Anthropic,
                "a.test",
                "1.1.1.1",
                Some(0),
            ),
            (
                "2026-01-01T01:00:01Z",
                "connect",
                Provider::Anthropic,
                "c.test",
                "1.1.1.1",
                None,
            ),
            (
                "2026-01-01T01:00:02Z",
                "close",
                Provider::OpenAI,
                "b.test",
                "2.2.2.2",
                Some(1000),
            ),
            (
                "2026-01-01T01:00:03Z",
                "close",
                Provider::Anthropic,
                "c.test",
                "1.1.1.1",
                Some(2000),
            ),
        ];
        let events: Vec<_> = cases
            .into_iter()
            .map(|(ts, kind, provider, domain, ip, duration)| {
                let mut event = create_test_event(ts, kind, provider);
                event.domain = Some(domain.to_string());
                event.key.remote_ip = ip.parse().unwrap();
                event.duration_ms = duration;
                event
            })
            .collect();
        write_sqlite_batch(&mut conn, &events).unwrap();
        let filter = ReportFilter {
            run_id: Some("test-run".to_string()),
            since: None,
            until: None,
        };
        let summary = query_summary(&conn, &filter).unwrap();
        assert_eq!(
            (summary.total_events, summary.connects, summary.closes),
            (6, 3, 3)
        );
        assert_eq!(
            (
                summary.avg_duration_ms,
                summary.max_duration_ms,
                summary.duration_samples
            ),
            (Some(1000.0), Some(2000), 3)
        );
        assert_eq!(summary.peak_active, Some(2));
        assert_eq!(summary.peak_unavailable, None);
        let (hours, unbucketed) = query_hourly_activity(&conn, &filter).unwrap();
        assert_eq!(unbucketed, 0);
        assert_eq!(hours.len(), 2);
        assert_eq!(hours[0].hour, "2026-01-01T00:00:00Z");
        assert_eq!(hours[0].providers["anthropic"], 1);
        assert_eq!(hours[1].hour, "2026-01-01T01:00:00Z");
        assert_eq!(hours[1].providers["anthropic"], 3);
        assert_eq!(hours[1].providers["openai"], 2);
        let providers = query_providers(&conn, &filter).unwrap();
        assert_eq!(
            (
                providers[0].provider.as_str(),
                providers[0].domains,
                providers[0].ips
            ),
            ("anthropic", 2, 1)
        );
        let clipped = ReportFilter {
            run_id: filter.run_id.clone(),
            since: Some("2026-01-01T01:00:02Z".to_string()),
            until: Some("2026-01-01T01:00:04Z".to_string()),
        };
        let summary = query_summary(&conn, &clipped).unwrap();
        assert_eq!(
            (summary.connects, summary.closes, summary.peak_active),
            (0, 2, Some(2))
        );
        assert_eq!(
            (summary.avg_duration_ms, summary.duration_samples),
            (Some(1500.0), 2)
        );
        let no_close = ReportFilter {
            run_id: filter.run_id.clone(),
            since: Some("2026-01-01T00:59:59Z".to_string()),
            until: Some("2026-01-01T01:00:00Z".to_string()),
        };
        let summary = query_summary(&conn, &no_close).unwrap();
        assert_eq!(
            (
                summary.avg_duration_ms,
                summary.max_duration_ms,
                summary.duration_samples,
                summary.peak_active
            ),
            (None, None, 0, Some(1))
        );
        let zero = ReportFilter {
            run_id: filter.run_id,
            since: Some("2026-01-01T01:00:00Z".to_string()),
            until: Some("2026-01-01T01:00:01Z".to_string()),
        };
        let summary = query_summary(&conn, &zero).unwrap();
        assert_eq!(
            (
                summary.avg_duration_ms,
                summary.max_duration_ms,
                summary.duration_samples
            ),
            (Some(0.0), Some(0), 1)
        );
    }

    #[test]
    fn report_peak_does_not_add_runs_or_invent_missing_history() {
        let mut conn = setup_test_db();
        let mut events = Vec::new();
        for (run, count) in [("first", 2), ("second", 3)] {
            for _ in 0..count {
                let mut event =
                    create_test_event("2026-01-01T00:00:00Z", "connect", Provider::Anthropic);
                event.run_id = run.to_string();
                events.push(event);
            }
        }
        write_sqlite_batch(&mut conn, &events).unwrap();
        let filter = ReportFilter {
            run_id: None,
            since: None,
            until: None,
        };
        assert_eq!(
            query_observed_peak(&conn, &filter).unwrap(),
            (Some(3), None)
        );
        let mut orphan = create_test_event("2026-01-01T00:00:01Z", "close", Provider::OpenAI);
        orphan.run_id = "orphan".to_string();
        write_sqlite_batch(&mut conn, &[orphan]).unwrap();
        assert_eq!(
            query_observed_peak(&conn, &filter).unwrap(),
            (None, Some("unmatched_close_in_history"))
        );
        let empty = ReportFilter {
            run_id: Some("empty".to_string()),
            since: None,
            until: None,
        };
        assert_eq!(
            query_observed_peak(&conn, &empty).unwrap(),
            (None, Some("no_selected_endpoint_events"))
        );
    }

    #[test]
    fn report_ranks_ties_stably_and_invalid_time_duration_remain_explicit() {
        let mut conn = setup_test_db();
        let mut events = Vec::new();
        for (domain, ip, provider) in [
            ("z.test", "2.2.2.2", Provider::OpenAI),
            ("a.test", "1.1.1.1", Provider::Anthropic),
        ] {
            let mut event = create_test_event("2026-01-01T00:00:00Z", "connect", provider);
            event.domain = Some(domain.to_string());
            event.key.remote_ip = ip.parse().unwrap();
            events.push(event);
        }
        write_sqlite_batch(&mut conn, &events).unwrap();
        let filter = ReportFilter {
            run_id: Some("test-run".to_string()),
            since: None,
            until: None,
        };
        assert_eq!(
            query_providers(&conn, &filter).unwrap()[0].provider,
            "anthropic"
        );
        assert_eq!(
            query_top_domains(&conn, &filter, 10).unwrap()[0].domain,
            "a.test"
        );
        assert_eq!(query_top_ips(&conn, &filter, 10).unwrap()[0].ip, "1.1.1.1");
        conn.execute("INSERT INTO events(ts,run_id,event,provider,duration_ms) VALUES('invalid-time','test-run','close','anthropic',-1)",[]).unwrap();
        let summary = query_summary(&conn, &filter).unwrap();
        assert_eq!(
            (
                summary.avg_duration_ms,
                summary.max_duration_ms,
                summary.duration_samples
            ),
            (None, None, 0)
        );
        assert_eq!(summary.peak_unavailable, Some("invalid_event_timestamps"));
        assert_eq!(query_hourly_activity(&conn, &filter).unwrap().1, 1);
    }

    #[test]
    fn latest_empty_metadata_wins_over_later_old_events_and_names_resolve() {
        let mut conn = setup_test_db();
        let mut older = RunContext::new(&MonitorArgs::default(), "off", None);
        older.run_id = "older".to_string();
        older.start_ts = "2026-01-01T23:00:00-01:00".to_string();
        older.session_name = "old-name".to_string();
        insert_session(&mut conn, &older).unwrap();
        let mut newer = older.clone();
        newer.run_id = "empty".to_string();
        newer.start_ts = "2026-01-02T01:00:00Z".to_string();
        newer.session_name = "empty-name".to_string();
        insert_session(&mut conn, &newer).unwrap();
        let mut event = create_test_event("2026-01-03T00:00:00Z", "connect", Provider::Anthropic);
        event.run_id = older.run_id;
        write_sqlite_batch(&mut conn, &[event]).unwrap();
        assert_eq!(
            find_latest_session(&conn).unwrap().as_deref(),
            Some("empty")
        );
        assert_eq!(
            resolve_session_reference(&conn, "empty-name").unwrap(),
            "empty"
        );
        let status = get_status_data(&conn).unwrap();
        assert_eq!(status.session_name.as_deref(), Some("empty-name"));
        assert_eq!((status.total, status.active), (0, 0));
        assert!(compute_session_diff(&conn, "old-name", "empty-name", 10.0).is_ok());
        assert!(resolve_session_reference(&conn, "missing").is_err());
        newer.run_id = "duplicate".to_string();
        insert_session(&mut conn, &newer).unwrap();
        let error = resolve_session_reference(&conn, "empty-name").unwrap_err();
        assert!(
            error.contains("Ambiguous") && error.contains("duplicate") && error.contains("empty")
        );
        assert_eq!(
            find_latest_session(&conn).unwrap().as_deref(),
            Some("empty")
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn current_status_requires_fresh_alive_identity_and_keeps_history_after_end() {
        let mut conn = setup_test_db();
        let mut ctx = RunContext::new(&MonitorArgs::default(), "off", None);
        ctx.run_id = "current".to_string();
        insert_session(&mut conn, &ctx).unwrap();
        let mut event = create_test_event(&ctx.start_ts, "connect", Provider::Anthropic);
        event.run_id = ctx.run_id.clone();
        write_sqlite_batch(&mut conn, &[event]).unwrap();
        let counters = SqliteCounters::default();
        let poll = SessionPoll {
            run_id: ctx.run_id.clone(),
            ts: now_rfc3339(),
            active: 7,
            valid: true,
            domain_mode: "off".to_string(),
        };
        publish_session_poll(&mut conn, &poll, &counters, None);
        let status = get_status_data(&conn).unwrap();
        assert_eq!(
            (status.active, status.total, status.state),
            (7, 1, Some("fresh"))
        );
        conn.execute(
            "UPDATE sessions SET last_poll_ts='1970-01-01T00:00:00Z'",
            [],
        )
        .unwrap();
        assert_eq!(get_status_data(&conn).unwrap().state, Some("stale"));
        publish_session_poll(&mut conn, &poll, &counters, None);
        conn.execute("UPDATE sessions SET observer_start_time='0'", [])
            .unwrap();
        assert_eq!(get_status_data(&conn).unwrap().active, 0);
        conn.execute(
            "UPDATE sessions SET observer_start_time=?1,poll_valid=0",
            [ctx.observer.unwrap().start_time.to_string()],
        )
        .unwrap();
        assert_eq!(get_status_data(&conn).unwrap().state, Some("degraded"));
        finalize_session(&mut conn, &ctx.run_id, 1, 0).unwrap();
        let status = get_status_data(&conn).unwrap();
        assert_eq!(
            (status.active, status.total, status.state),
            (0, 1, Some("ended"))
        );
        assert_eq!(
            conn.query_row(
                "SELECT COUNT(*) FROM events WHERE event='close'",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
            0
        );
    }

    #[test]
    fn missing_poll_metadata_and_nonfinite_diff_thresholds_are_explicit() {
        let mut conn = setup_test_db();
        let counters = SqliteCounters::default();
        publish_session_poll(
            &mut conn,
            &SessionPoll {
                run_id: "absent".to_string(),
                ts: now_rfc3339(),
                active: 1,
                valid: true,
                domain_mode: "off".to_string(),
            },
            &counters,
            None,
        );
        let outcome = counters.outcome();
        assert!(outcome.failed);
        assert_eq!(outcome.metadata_lost, 1);
        assert_eq!(outcome.observed, 0);
        for threshold in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            assert!(compute_session_diff(&conn, "old", "new", threshold).is_err());
        }
        let mut event = create_test_event("2026-01-01T00:00:00Z", "connect", Provider::Anthropic);
        event.run_id = "same".to_string();
        write_sqlite_batch(&mut conn, &[event]).unwrap();
        assert!(
            compute_session_diff(&conn, "same", "same", 0.0)
                .unwrap()
                .changed_domains
                .is_empty()
        );
    }

    #[test]
    fn poll_publication_preserves_observation_time_and_accounts_metadata_queue_loss() {
        let (sender, receiver) = mpsc::sync_channel(1);
        let counters = Arc::new(SqliteCounters::default());
        let writer = SqliteWriter {
            sender,
            handle: None,
            counters: counters.clone(),
            drop_state: Mutex::new(DropState {
                last_warn: SystemTime::now(),
                dropped_since_warn: 0,
            }),
            log_writer: None,
        };
        let observed = UNIX_EPOCH + Duration::from_secs(1);
        writer.publish_poll("test", 2, true, observed, "off");
        writer.publish_poll("test", 3, true, observed, "off");
        let outcome = counters.outcome();
        assert_eq!(
            (
                outcome.observed,
                outcome.queue_lost,
                outcome.write_lost,
                outcome.metadata_lost
            ),
            (0, 0, 0, 1)
        );
        assert!(outcome.failed);
        let message = receiver.try_recv().unwrap();
        assert!(matches!(&message, SqliteMsg::Poll(_)));
        if let SqliteMsg::Poll(poll) = message {
            assert_eq!(poll.ts, "1970-01-01T00:00:01Z");
            assert_eq!(poll.active, 2);
            assert!(poll.valid);
        }
    }

    #[test]
    fn unicode_report_truncation_and_literal_session_names_are_preserved() {
        assert_eq!(truncate_ascii("長長長", 6), "長...");
        assert_eq!(truncate_ascii("長長長", 4), "...");
        assert_eq!(truncate_ascii("長長", 2), "");
        assert_eq!(truncate_ascii("abcdef", 4), "a...");
        let data = StatusData {
            state: Some("fresh"),
            session_name: Some("{state}:{active}".to_string()),
            ..StatusData::default()
        };
        assert_eq!(
            expand_status_template("{state}|{session_name}", &data),
            "fresh|{state}:{active}"
        );
    }

    #[test]
    fn hostname_corrections_update_one_observation_without_extra_connections() {
        let mut conn = setup_test_db();
        let mut first = create_test_event("2026-01-01T00:00:00Z", "connect", Provider::Anthropic);
        first.observation_id = Some("socket-old".to_string());
        let mut second = first.clone();
        second.observation_id = Some("socket-new".to_string());
        write_sqlite_batch(&mut conn, &[first, second]).unwrap();
        let counters = SqliteCounters::default();
        write_domain_update(
            &mut conn,
            &SqliteDomainUpdate {
                run_id: "test-run".to_string(),
                observation_id: "socket-old".to_string(),
                domain: Some("late.test".to_string()),
                domain_source: Some("sni".to_string()),
                ownership_json: "{\"proof\":\"late\"}".to_string(),
                alert: true,
            },
            &counters,
            None,
        );
        let counts: (i64, i64, i64) = conn
            .query_row(
                "SELECT COUNT(*),SUM(event='connect'),SUM(provider='anthropic') FROM events",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(counts, (2, 2, 2));
        assert!(!counters.outcome().failed);
        let corrected: (String, String, bool) = conn
            .query_row(
                "SELECT domain,domain_source,alert FROM events WHERE observation_id='socket-old'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(
            corrected,
            ("late.test".to_string(), "sni".to_string(), true)
        );
        let unaffected: String = conn
            .query_row(
                "SELECT domain FROM events WHERE observation_id='socket-new'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(unaffected, "test.example.com");
    }

    #[test]
    fn hostname_correction_failure_and_missing_identity_are_visible_without_event_loss() {
        let mut conn = setup_test_db();
        let mut event = create_test_event("2026-01-01T00:00:00Z", "connect", Provider::Anthropic);
        event.observation_id = Some("held".to_string());
        write_sqlite_batch(&mut conn, &[event]).unwrap();
        conn.execute_batch("CREATE TRIGGER reject_hostname BEFORE UPDATE OF domain ON events BEGIN SELECT RAISE(ABORT,'forced hostname write failure'); END;").unwrap();
        for observation_id in ["held", "missing"] {
            let counters = SqliteCounters::default();
            write_domain_update(
                &mut conn,
                &SqliteDomainUpdate {
                    run_id: "test-run".to_string(),
                    observation_id: observation_id.to_string(),
                    domain: Some("late.test".to_string()),
                    domain_source: Some("sni".to_string()),
                    ownership_json: "{}".to_string(),
                    alert: false,
                },
                &counters,
                None,
            );
            let outcome = counters.outcome();
            assert!(outcome.failed);
            assert_eq!(
                (
                    outcome.observed,
                    outcome.persisted,
                    outcome.queue_lost,
                    outcome.write_lost,
                    outcome.metadata_lost
                ),
                (0, 0, 0, 0, 1)
            );
            assert!(outcome.error.is_some());
        }
        assert_eq!(
            conn.query_row(
                "SELECT COUNT(*) FROM events WHERE domain='test.example.com'",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
            1
        );
    }

    #[test]
    fn report_mixed_sources_never_promote_weaker_observations_to_sni() {
        let mut conn = setup_test_db();
        let mut first = create_test_event("2026-01-01T00:00:00Z", "connect", Provider::Anthropic);
        first.domain_source = Some("sni".to_string());
        let mut second = first.clone();
        second.domain_source = Some("dns".to_string());
        write_sqlite_batch(&mut conn, &[first, second]).unwrap();
        let filter = ReportFilter {
            run_id: Some("test-run".to_string()),
            since: None,
            until: None,
        };
        let domains = query_top_domains(&conn, &filter, 10).unwrap();
        assert_eq!(domains.len(), 1);
        assert_eq!(domains[0].source.as_deref(), Some("mixed"));
        assert_eq!(domains[0].events, 2);
    }

    // Batching unit tests

    fn create_test_event(ts: &str, event: &str, provider: Provider) -> SqliteEvent {
        SqliteEvent {
            ts: ts.to_string(),
            run_id: "test-run".to_string(),
            event: event.to_string(),
            key: ConnKey {
                inode: 0,
                process: ProcessIdentity {
                    pid: 1234,
                    start_time: 1,
                },
                root: ProcessIdentity {
                    pid: 1234,
                    start_time: 1,
                },
                provider,
                provider_origin: None,
                proto: Proto::Tcp,
                socket_kind: SocketKind::Connection,
                local_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
                local_port: 12345,
                remote_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(8, 8, 8, 8)),
                remote_port: 443,
            },
            pid: Some(1234),
            comm: "testproc".to_string(),
            cmdline: "/usr/bin/testproc".to_string(),
            provider,
            domain: Some("test.example.com".to_string()),
            domain_source: None,
            ancestry_path: Some("init:1,testproc:1234".to_string()),
            duration_ms: if event == "close" { Some(1000) } else { None },
            alert: false,
            retry_count: None,
            ownership_json: None,
            observation_id: None,
        }
    }

    fn setup_test_db() -> Connection {
        let mut conn = Connection::open_in_memory().expect("failed to open in-memory db");
        init_sqlite(&mut conn).expect("failed to init schema");
        conn
    }

    #[test]
    fn sqlite_failed_transaction_counts_the_entire_rolled_back_batch() {
        let mut conn = setup_test_db();
        conn.execute_batch("CREATE TRIGGER fail_close BEFORE INSERT ON events WHEN NEW.event='close' BEGIN SELECT RAISE(ABORT, 'forced constraint failure'); END;").unwrap();
        let batch = [
            create_test_event("2026-01-20T12:00:00Z", "connect", Provider::Anthropic),
            create_test_event("2026-01-20T12:00:01Z", "close", Provider::Anthropic),
        ];
        let counters = SqliteCounters::default();
        counters.observed.store(2, Ordering::Relaxed);
        flush_sqlite_batch(&mut conn, &batch, &counters, None);
        let outcome = counters.outcome();
        assert_eq!(
            conn.query_row("SELECT count(*) FROM events", [], |row| row
                .get::<_, i64>(0))
                .unwrap(),
            0
        );
        assert_eq!(
            (
                outcome.observed,
                outcome.persisted,
                outcome.queue_lost,
                outcome.write_lost
            ),
            (2, 0, 0, 2)
        );
        assert!(outcome.failed);
        assert!(
            outcome
                .error
                .unwrap()
                .contains("after 1 attempt(s): forced constraint failure")
        );
    }

    #[test]
    fn sqlite_contention_has_bounded_retry_and_exact_exhaustion_accounting() {
        let (_file, path) = NamedTempFile::new().unwrap().keep().unwrap();
        let mut conn = Connection::open(&path).unwrap();
        init_sqlite(&mut conn).unwrap();
        conn.busy_timeout(Duration::from_millis(20)).unwrap();
        let blocker = Connection::open(&path).unwrap();
        blocker.execute_batch("BEGIN IMMEDIATE").unwrap();
        let counters = SqliteCounters::default();
        counters.observed.store(1, Ordering::Relaxed);
        let batch = [create_test_event(
            "2026-01-20T12:00:00Z",
            "connect",
            Provider::Anthropic,
        )];
        let start = Instant::now();
        flush_sqlite_batch(&mut conn, &batch, &counters, None);
        assert!(start.elapsed() < Duration::from_secs(2));
        assert_eq!(counters.outcome().write_lost, 1);
        assert!(
            counters
                .outcome()
                .error
                .unwrap()
                .contains("after 3 attempt(s)")
        );
        blocker.execute_batch("ROLLBACK").unwrap();
        let recovered = SqliteCounters::default();
        recovered.observed.store(1, Ordering::Relaxed);
        flush_sqlite_batch(&mut conn, &batch, &recovered, None);
        assert_eq!(recovered.outcome().persisted, 1);
        assert!(!recovered.outcome().failed);
    }

    #[test]
    fn sqlite_startup_and_finalization_errors_reach_the_caller() {
        let args = MonitorArgs {
            sqlite_path: "/dev/null/unavailable.sqlite".to_string(),
            ..MonitorArgs::default()
        };
        let ctx = RunContext::new(&args, "ptr", None);
        assert!(
            start_sqlite_writer(&args, ctx, None)
                .err()
                .unwrap()
                .contains("sqlite open failed")
        );
        let (_file, path) = NamedTempFile::new().unwrap().keep().unwrap();
        let args = MonitorArgs {
            sqlite_path: path.to_string_lossy().into_owned(),
            ..MonitorArgs::default()
        };
        let ctx = RunContext::new(&args, "ptr", None);
        let writer =
            start_sqlite_writer(&args, ctx.clone(), None).unwrap_or_else(|err| panic!("{err}"));
        let conn = Connection::open(path).unwrap();
        conn.execute_batch("CREATE TRIGGER fail_finalize BEFORE UPDATE ON sessions BEGIN SELECT RAISE(ABORT, 'forced finalization failure'); END;").unwrap();
        writer.enqueue(create_test_event(
            "2026-01-20T12:00:00Z",
            "connect",
            Provider::Anthropic,
        ));
        let outcome = writer.shutdown(ctx.run_id, 1, 0);
        assert_eq!(
            (outcome.observed, outcome.persisted, outcome.write_lost),
            (1, 1, 0)
        );
        assert!(outcome.failed);
        assert!(
            outcome
                .error
                .unwrap()
                .contains("forced finalization failure")
        );
    }

    #[test]
    fn sqlite_queue_saturation_and_disconnection_reconcile_all_observations() {
        let (sender, receiver) = mpsc::sync_channel(1);
        let writer = SqliteWriter {
            sender,
            handle: None,
            counters: Arc::new(SqliteCounters::default()),
            drop_state: Mutex::new(DropState {
                last_warn: SystemTime::now(),
                dropped_since_warn: 0,
            }),
            log_writer: None,
        };
        writer.enqueue(create_test_event(
            "2026-01-20T12:00:00Z",
            "connect",
            Provider::Anthropic,
        ));
        writer.enqueue(create_test_event(
            "2026-01-20T12:00:01Z",
            "close",
            Provider::Anthropic,
        ));
        assert_eq!(writer.counters.queue_lost.load(Ordering::Relaxed), 1);
        drop(receiver);
        let outcome = writer.shutdown("test-run".to_string(), 1, 1);
        assert_eq!(
            (
                outcome.observed,
                outcome.persisted,
                outcome.queue_lost,
                outcome.write_lost
            ),
            (2, 0, 1, 1)
        );
        assert!(outcome.failed);
    }

    #[test]
    fn requested_file_sink_errors_are_observable() {
        let args = MonitorArgs {
            log_file: Some(PathBuf::from("/dev/null/unavailable.log")),
            ..MonitorArgs::default()
        };
        assert!(open_log_writer(&args, "ptr", LogFormat::Json).is_err());
        let writer = LogWriter {
            file: Mutex::new(OpenOptions::new().write(true).open("/dev/full").unwrap()),
            format: LogFormat::Json,
            failed: AtomicBool::new(false),
        };
        writer.warning("controlled write failure");
        writer.flush();
        assert!(writer.failed.load(Ordering::Relaxed));
    }

    #[test]
    fn sqlite_writer_panic_is_not_a_zero_loss_success() {
        let (sender, receiver) = mpsc::sync_channel(1);
        let handle = std::thread::spawn(move || {
            let _ = receiver.recv().unwrap();
            panic!("forced writer failure");
        });
        let writer = SqliteWriter {
            sender,
            handle: Some(handle),
            counters: Arc::new(SqliteCounters::default()),
            drop_state: Mutex::new(DropState {
                last_warn: SystemTime::now(),
                dropped_since_warn: 0,
            }),
            log_writer: None,
        };
        writer.enqueue(create_test_event(
            "2026-01-20T12:00:00Z",
            "connect",
            Provider::Anthropic,
        ));
        let outcome = writer.shutdown("test-run".to_string(), 1, 0);
        assert_eq!(
            (outcome.observed, outcome.persisted, outcome.write_lost),
            (1, 0, 1)
        );
        assert!(outcome.failed);
        assert!(outcome.error.unwrap().contains("forced writer failure"));
    }

    #[test]
    fn init_sqlite_migrates_legacy_schema() {
        // Schema as shipped by older rano builds: missing run_id/duration_ms/ancestry_path/
        // alert/remote_is_private/ip_version/retry_count on events and session_name on
        // sessions. Before the migration these DBs caused insert failures that disabled
        // SQLite logging entirely ("sqlite session insert failed: table sessions has no
        // column named session_name").
        let mut conn = Connection::open_in_memory().expect("failed to open in-memory db");
        conn.execute_batch(
            "
            CREATE TABLE events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
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
                domain TEXT
            );
            CREATE TABLE sessions (
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
            ",
        )
        .expect("legacy schema creation failed");

        init_sqlite(&mut conn).expect("migration of legacy schema failed");

        let ctx = RunContext::new(&MonitorArgs::default(), "ptr", None);
        insert_session(&mut conn, &ctx).expect("session insert failed on migrated legacy db");

        let event = create_test_event("2026-01-20T12:00:00Z", "connect", Provider::Anthropic);
        write_sqlite_batch(&mut conn, &[event]).expect("event insert failed on migrated legacy db");

        let name: Option<String> = conn
            .query_row("SELECT session_name FROM sessions LIMIT 1", [], |row| {
                row.get(0)
            })
            .expect("session_name query failed");
        assert!(
            name.is_some(),
            "session_name should be populated after migration"
        );
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
            let mut stmt = conn
                .prepare("SELECT DISTINCT provider FROM events ORDER BY provider")
                .unwrap();
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
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
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
            .query_row("SELECT duration_ms FROM events LIMIT 1", [], |row| {
                row.get(0)
            })
            .expect("query failed");

        assert_eq!(duration, Some(1000));
    }

    #[test]
    fn sqlite_roundtrips_domain_source_provenance() {
        let mut conn = setup_test_db();

        let mut sni_event = create_test_event("2026-01-20T12:00:00Z", "connect", Provider::OpenAI);
        sni_event.domain = Some("api.openai.com".to_string());
        sni_event.domain_source = Some("sni".to_string());

        let mut ptr_event = create_test_event("2026-01-20T12:00:01Z", "connect", Provider::Unknown);
        ptr_event.domain = Some("ip-93-184-216-34.example.net".to_string());
        ptr_event.domain_source = Some("ptr".to_string());

        let mut no_source = create_test_event("2026-01-20T12:00:02Z", "connect", Provider::Google);
        no_source.domain = None;

        write_sqlite_batch(&mut conn, &[sni_event, ptr_event, no_source])
            .expect("batch write failed");

        let sni: Option<String> = conn
            .query_row(
                "SELECT domain_source FROM events WHERE domain = 'api.openai.com'",
                [],
                |row| row.get(0),
            )
            .expect("sni query failed");
        assert_eq!(sni.as_deref(), Some("sni"));

        let ptr: Option<String> = conn
            .query_row(
                "SELECT domain_source FROM events WHERE domain_source = 'ptr'",
                [],
                |row| row.get(0),
            )
            .expect("ptr query failed");
        assert_eq!(ptr.as_deref(), Some("ptr"));

        // PTR-less/unattributed rows store NULL.
        let none: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM events WHERE domain_source IS NULL",
                [],
                |row| row.get(0),
            )
            .expect("null query failed");
        assert_eq!(none, 1);
    }

    #[test]
    fn export_roundtrips_alert_retry_and_null_ancestry() {
        let mut conn = setup_test_db();

        let mut flagged = create_test_event("2026-01-20T12:00:00Z", "close", Provider::Anthropic);
        flagged.alert = true;
        flagged.retry_count = Some(3);
        flagged.ancestry_path = Some("init:1,claude:42".to_string());

        let mut plain = create_test_event("2026-01-20T12:00:01Z", "connect", Provider::Google);
        plain.ancestry_path = None; // --show-ancestry disabled => NULL, not ''

        write_sqlite_batch(&mut conn, &[flagged, plain]).expect("batch write failed");

        let fields = default_export_fields();
        let filter = ExportFilter {
            run_id: Some("test-run".to_string()),
            since: None,
            until: None,
            providers: Vec::new(),
            domain_patterns: Vec::new(),
        };
        let (sql, params) = build_export_query(&filter, &fields);
        let mut stmt = conn.prepare(&sql).expect("prepare failed");
        let params_refs: Vec<&dyn rusqlite::ToSql> =
            params.iter().map(|s| s as &dyn rusqlite::ToSql).collect();
        let rows: Vec<Vec<(String, FieldValue)>> = stmt
            .query_map(params_refs.as_slice(), |row| row_to_values(row, &fields))
            .expect("query failed")
            .map(|r| r.expect("row failed"))
            .collect();
        assert_eq!(rows.len(), 2);

        for values in &rows {
            // CSV round-trips alert/retry_count and renders NULL ancestry empty.
            let csv = format_csv_row(values);
            assert!(csv.contains("test-run"));

            let get = |name: &str| {
                values
                    .iter()
                    .find(|(f, _)| f == name)
                    .map(|(_, v)| v.clone())
                    .expect("field missing")
            };
            match get("event") {
                FieldValue::String(ref e) if e == "close" => {
                    assert_eq!(get("alert"), FieldValue::Integer(1));
                    assert_eq!(get("retry_count"), FieldValue::Integer(3));
                    assert!(csv.contains("init:1,claude:42"));
                }
                _ => {
                    assert_eq!(get("alert"), FieldValue::Integer(0));
                    assert_eq!(get("retry_count"), FieldValue::Null);
                    assert_eq!(get("ancestry_path"), FieldValue::Null);
                }
            }

            // JSONL omits NULL keys entirely.
            if values
                .iter()
                .any(|(f, v)| f == "ancestry_path" && matches!(v, FieldValue::Null))
            {
                let jsonl = format_jsonl_row(values);
                assert!(!jsonl.contains("ancestry_path"));
                assert!(!jsonl.contains("retry_count"));
            }
        }
    }

    #[test]
    fn write_sqlite_batch_multiple_calls_accumulate() {
        let mut conn = setup_test_db();

        // First batch
        let batch1 = vec![create_test_event(
            "2026-01-20T12:00:00Z",
            "connect",
            Provider::Anthropic,
        )];
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
            .query_row("SELECT COUNT(DISTINCT run_id) FROM events", [], |row| {
                row.get(0)
            })
            .expect("count query failed");
        assert_eq!(distinct_run_ids, 1);
    }

    // Alert system unit tests

    #[test]
    fn alert_domain_pattern_match() {
        // Test glob pattern matching for domain alerts
        assert!(glob_match("*.evil.com", "malware.evil.com"));
        assert!(glob_match("*.evil.com", "sub.domain.evil.com"));
        assert!(!glob_match("*.evil.com", "evil.com"));
        assert!(!glob_match("*.evil.com", "noevil.com"));

        // Test single-character wildcard
        assert!(glob_match("api?.example.com", "api1.example.com"));
        assert!(glob_match("api?.example.com", "api2.example.com"));
        assert!(!glob_match("api?.example.com", "api12.example.com"));

        // Test exact match (no wildcards)
        assert!(glob_match("exact.domain.com", "exact.domain.com"));
        assert!(!glob_match("exact.domain.com", "other.domain.com"));
    }

    #[test]
    fn alert_config_is_enabled() {
        // Empty config should be disabled
        let empty_config = AlertConfig {
            domain_patterns: vec![],
            max_connections: None,
            max_per_provider: None,
            duration_threshold_ms: None,
            alert_unknown_domain: false,
            bell: false,
            cooldown_ms: 10000,
            no_alerts: false,
        };
        assert!(!empty_config.is_enabled());

        // Config with domain pattern should be enabled
        let domain_config = AlertConfig {
            domain_patterns: vec!["*.evil.com".to_string()],
            max_connections: None,
            max_per_provider: None,
            duration_threshold_ms: None,
            alert_unknown_domain: false,
            bell: false,
            cooldown_ms: 10000,
            no_alerts: false,
        };
        assert!(domain_config.is_enabled());

        // Config with max_connections should be enabled
        let conn_config = AlertConfig {
            domain_patterns: vec![],
            max_connections: Some(100),
            max_per_provider: None,
            duration_threshold_ms: None,
            alert_unknown_domain: false,
            bell: false,
            cooldown_ms: 10000,
            no_alerts: false,
        };
        assert!(conn_config.is_enabled());

        // Config with no_alerts should be disabled regardless of other settings
        let disabled_config = AlertConfig {
            domain_patterns: vec!["*.evil.com".to_string()],
            max_connections: Some(100),
            max_per_provider: None,
            duration_threshold_ms: None,
            alert_unknown_domain: false,
            bell: false,
            cooldown_ms: 10000,
            no_alerts: true,
        };
        assert!(!disabled_config.is_enabled());
    }

    #[test]
    fn alert_connection_alert_trigger_predicate() {
        let config = AlertConfig {
            domain_patterns: vec!["*.malicious.com".to_string()],
            alert_unknown_domain: true,
            ..AlertConfig::default()
        };

        let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(1, 2, 3, 4));

        // Domain pattern match should trigger with the matched pattern
        match connection_alert_trigger(&config, Some("evil.malicious.com"), ip) {
            Some(ConnectionAlertTrigger::DomainPattern { pattern, .. }) => {
                assert_eq!(pattern, "*.malicious.com");
            }
            _ => panic!("expected DomainPattern trigger"),
        }

        // Non-matching domain should not trigger
        assert!(connection_alert_trigger(&config, Some("safe.example.com"), ip).is_none());

        // Unknown domain should trigger (when alert_unknown_domain is true)
        match connection_alert_trigger(&config, None, ip) {
            Some(ConnectionAlertTrigger::UnknownDomain { remote_ip }) => {
                assert_eq!(remote_ip, ip);
            }
            _ => panic!("expected UnknownDomain trigger"),
        }
    }

    #[test]
    fn alert_cooldown_suppresses_sqlite_flag_and_counts_suppression() {
        let config = AlertConfig {
            domain_patterns: vec!["*.malicious.com".to_string()],
            cooldown_ms: 60_000,
            ..AlertConfig::default()
        };
        let mut state = AlertState {
            last_alert: HashMap::new(),
            alert_count: 0,
            suppressed_count: 0,
        };
        let key = ConnKey {
            inode: 0,
            process: ProcessIdentity {
                pid: 4242,
                start_time: 1,
            },
            root: ProcessIdentity {
                pid: 4242,
                start_time: 1,
            },
            provider: Provider::Anthropic,
            provider_origin: None,
            proto: Proto::Tcp,
            socket_kind: SocketKind::Connection,
            local_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
            local_port: 40000,
            remote_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(93, 184, 216, 34)),
            remote_port: 443,
        };
        let mk_info = || ConnInfo {
            pid: 4242,
            comm: "claude".to_string(),
            cmdline: "claude".to_string(),
            log_cmdline: "claude".to_string(),
            ownership_json: String::new(),
            observation_id: "test-observation".to_string(),
            capture_floor: UNIX_EPOCH,
            domain_evidence: pcap_capture::DomainEvidence::default(),
            provider: Provider::Anthropic,
            domain: Some("evil.malicious.com".to_string()),
            domain_source: Some("dns".to_string()),
            ancestry: None,
            ancestry_path: None,
            opened_at: std::time::SystemTime::now(),
            last_seen: std::time::SystemTime::now(),
        };
        let style = OutputStyle {
            color: false,
            theme: Theme::Mono,
        };

        // First occurrence emits and is flagged.
        assert!(check_connection_alerts(
            &config,
            &mut state,
            &key,
            &mk_info(),
            false,
            style,
            None
        ));
        assert_eq!(state.alert_count, 1);
        assert_eq!(state.suppressed_count, 0);

        // Immediate repeat is cooldown-suppressed: no emission, no durable flag.
        assert!(!check_connection_alerts(
            &config,
            &mut state,
            &key,
            &mk_info(),
            false,
            style,
            None
        ));
        assert_eq!(state.alert_count, 1);
        assert_eq!(state.suppressed_count, 1);

        // Durable rows mirror what the operator saw: exactly one flagged row.
        let mk_row = |alert: bool| {
            let mut ev = create_test_event("2026-01-20T12:00:00Z", "connect", Provider::Anthropic);
            ev.alert = alert;
            ev.domain = Some("evil.malicious.com".to_string());
            ev
        };
        let mut conn = setup_test_db();
        write_sqlite_batch(&mut conn, &[mk_row(true), mk_row(false)]).expect("batch write failed");
        let flagged: i64 = conn
            .query_row("SELECT COUNT(*) FROM events WHERE alert = 1", [], |row| {
                row.get(0)
            })
            .expect("flagged count query failed");
        assert_eq!(flagged, 1);
        let unflagged: i64 = conn
            .query_row("SELECT COUNT(*) FROM events WHERE alert = 0", [], |row| {
                row.get(0)
            })
            .expect("unflagged count query failed");
        assert_eq!(unflagged, 1);
    }

    #[test]
    fn alert_threshold_breach_writes_queryable_synthesized_row() {
        let config = AlertConfig {
            max_connections: Some(1),
            ..AlertConfig::default()
        };
        let mut state = AlertState {
            last_alert: HashMap::new(),
            alert_count: 0,
            suppressed_count: 0,
        };
        let stats = Stats {
            connects: 0,
            listens: 0,
            binds: 0,
            closes: 0,
            socket_active: 0,
            socket_closes: 0,
            active: 5,
            peak_active: 5,
            sqlite_dropped: 0,
            sqlite_enabled: false,
            sqlite_outcome: SqliteOutcome::default(),
            log_failed: false,
            observation_errors: 0,
            capture_health: None,
            ptr_health: None,
            per_ip: BTreeMap::new(),
            per_port: BTreeMap::new(),
            per_domain: BTreeMap::new(),
            per_pid: BTreeMap::new(),
            per_comm: BTreeMap::new(),
            per_provider: BTreeMap::new(),
            active_per_provider: BTreeMap::new(),
            per_provider_domains: BTreeMap::new(),
            per_provider_ips: BTreeMap::new(),
            duration_ms_total: 0,
            duration_ms_max: 0,
            duration_ms_samples: 0,
        };
        let style = OutputStyle {
            color: false,
            theme: Theme::Mono,
        };

        // Breach emits once and synthesizes a queryable alert row with NULL pid.
        let rows = check_threshold_alerts(
            &config,
            &mut state,
            &stats,
            "run-x",
            "2026-01-20T12:00:00Z",
            false,
            style,
            None,
        );
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].event, "alert");
        assert!(rows[0].alert);
        assert_eq!(rows[0].pid, None);
        assert_eq!(rows[0].provider.label(), "unknown");

        // Immediate re-check is cooldown-suppressed: no extra rows.
        let rows2 = check_threshold_alerts(
            &config,
            &mut state,
            &stats,
            "run-x",
            "2026-01-20T12:00:01Z",
            false,
            style,
            None,
        );
        assert!(rows2.is_empty());
        assert_eq!(state.suppressed_count, 1);

        let mut conn = setup_test_db();
        write_sqlite_batch(&mut conn, &rows).expect("synthetic alert insert failed");
        let n: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM events WHERE alert=1 AND event='alert' AND pid IS NULL",
                [],
                |row| row.get(0),
            )
            .expect("synthetic alert query failed");
        assert_eq!(n, 1);
    }

    #[test]
    fn provider_threshold_uses_concurrent_counts_and_exact_boundary() {
        let mut stats = Stats::default();
        for _ in 0..10 {
            stats.observed_open(Provider::Anthropic, SocketKind::Connection);
            stats.observed_close(Provider::Anthropic, SocketKind::Connection);
        }
        assert_eq!(stats.per_provider[&Provider::Anthropic], 10);
        assert_eq!(stats.active, 0);
        let config = AlertConfig {
            max_per_provider: Some(2),
            ..AlertConfig::default()
        };
        let mut state = AlertState {
            last_alert: HashMap::new(),
            alert_count: 0,
            suppressed_count: 0,
        };
        let style = OutputStyle {
            color: false,
            theme: Theme::Mono,
        };
        let check = |stats: &Stats, state: &mut AlertState| {
            check_threshold_alerts(
                &config,
                state,
                stats,
                "run",
                "2026-01-20T12:00:00Z",
                true,
                style,
                None,
            )
        };
        assert!(check(&stats, &mut state).is_empty());
        stats.observed_open(Provider::Anthropic, SocketKind::Connection);
        assert!(check(&stats, &mut state).is_empty());
        stats.observed_open(Provider::Anthropic, SocketKind::Connection);
        assert_eq!(check(&stats, &mut state).len(), 1);
        assert!(check(&stats, &mut state).is_empty());
        assert_eq!(state.suppressed_count, 1);
        stats.observed_close(Provider::Anthropic, SocketKind::Connection);
        assert!(check(&stats, &mut state).is_empty());
        stats.observed_open(Provider::Google, SocketKind::Connection);
        assert!(check(&stats, &mut state).is_empty());
        assert_eq!(stats.active_per_provider[&Provider::Anthropic], 1);
        assert_eq!(stats.active_per_provider[&Provider::Google], 1);
    }

    #[test]
    fn simultaneous_thresholds_repeat_after_cooldown_and_respect_no_alerts() {
        let mut stats = Stats::default();
        stats.observed_open(Provider::OpenAI, SocketKind::Connection);
        stats.observed_open(Provider::OpenAI, SocketKind::Connection);
        let config = AlertConfig {
            max_connections: Some(2),
            max_per_provider: Some(2),
            cooldown_ms: 1000,
            ..AlertConfig::default()
        };
        let mut state = AlertState {
            last_alert: HashMap::new(),
            alert_count: 0,
            suppressed_count: 0,
        };
        let style = OutputStyle {
            color: false,
            theme: Theme::Mono,
        };
        assert_eq!(
            check_threshold_alerts(&config, &mut state, &stats, "run", "ts", true, style, None)
                .len(),
            2
        );
        assert!(
            check_threshold_alerts(&config, &mut state, &stats, "run", "ts", true, style, None)
                .is_empty()
        );
        for timestamp in state.last_alert.values_mut() {
            *timestamp = SystemTime::now() - Duration::from_secs(2);
        }
        assert_eq!(
            check_threshold_alerts(&config, &mut state, &stats, "run", "ts", true, style, None)
                .len(),
            2
        );
        let disabled = AlertConfig {
            no_alerts: true,
            ..config
        };
        assert!(
            check_threshold_alerts(
                &disabled, &mut state, &stats, "run", "ts", true, style, None
            )
            .is_empty()
        );
        stats.observed_open(Provider::OpenAI, SocketKind::Connection);
        stats.observed_close(Provider::OpenAI, SocketKind::Connection);
        assert_eq!(
            stats.active, 2,
            "a same-poll replacement must be evaluated only after closes"
        );
    }

    #[test]
    fn alert_would_trigger_duration_alert() {
        let config = AlertConfig {
            domain_patterns: vec![],
            max_connections: None,
            max_per_provider: None,
            duration_threshold_ms: Some(30000), // 30 seconds
            alert_unknown_domain: false,
            bell: false,
            cooldown_ms: 10000,
            no_alerts: false,
        };

        // Duration exceeding threshold should trigger
        assert!(would_trigger_duration_alert(&config, Some(40000)));

        // Duration at exactly threshold should not trigger (must exceed)
        assert!(!would_trigger_duration_alert(&config, Some(30000)));

        // Duration under threshold should not trigger
        assert!(!would_trigger_duration_alert(&config, Some(10000)));

        // No duration should not trigger
        assert!(!would_trigger_duration_alert(&config, None));
    }

    #[test]
    fn alert_cooldown_prevents_spam() {
        let mut state = AlertState {
            last_alert: HashMap::new(),
            alert_count: 0,
            suppressed_count: 0,
        };

        let sig = AlertSignature::MaxConnections;
        let cooldown_ms = 10000; // 10 seconds

        // First alert should emit
        assert!(should_emit_alert(&mut state, &sig, cooldown_ms));
        assert_eq!(state.alert_count, 1);
        assert_eq!(state.suppressed_count, 0);

        // Immediate second alert should be suppressed
        assert!(!should_emit_alert(&mut state, &sig, cooldown_ms));
        assert_eq!(state.alert_count, 1);
        assert_eq!(state.suppressed_count, 1);

        // Different alert type should still emit
        let sig2 = AlertSignature::MaxPerProvider {
            provider: Provider::Anthropic,
        };
        assert!(should_emit_alert(&mut state, &sig2, cooldown_ms));
        assert_eq!(state.alert_count, 2);
    }

    #[test]
    fn alert_check_domain_patterns() {
        let patterns = vec!["*.evil.com".to_string(), "malware.*.org".to_string()];

        // Match first pattern
        let result = check_domain_patterns(Some("sub.evil.com"), &patterns);
        assert!(result.is_some());
        assert_eq!(result.unwrap(), "*.evil.com");

        // Match second pattern
        let result = check_domain_patterns(Some("malware.distribution.org"), &patterns);
        assert!(result.is_some());
        assert_eq!(result.unwrap(), "malware.*.org");

        // No match
        let result = check_domain_patterns(Some("safe.example.com"), &patterns);
        assert!(result.is_none());

        // None domain returns None (never matches patterns)
        let result = check_domain_patterns(None, &patterns);
        assert!(result.is_none());

        // Empty patterns never match
        let result = check_domain_patterns(Some("anything.com"), &[]);
        assert!(result.is_none());
    }

    #[test]
    fn alert_sqlite_stores_alert_flag() {
        let mut conn = setup_test_db();

        // Create event with alert=true
        let mut alert_event =
            create_test_event("2026-01-20T12:00:00Z", "connect", Provider::Unknown);
        alert_event.alert = true;
        alert_event.domain = Some("evil.malicious.com".to_string());

        // Create event with alert=false
        let normal_event =
            create_test_event("2026-01-20T12:00:01Z", "connect", Provider::Anthropic);

        let batch = vec![alert_event, normal_event];
        write_sqlite_batch(&mut conn, &batch).expect("batch write failed");

        // Query and verify alert flags
        let alert_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM events WHERE alert = 1", [], |row| {
                row.get(0)
            })
            .expect("count query failed");
        assert_eq!(alert_count, 1);

        let normal_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM events WHERE alert = 0", [], |row| {
                row.get(0)
            })
            .expect("count query failed");
        assert_eq!(normal_count, 1);

        // Verify the alert event has the expected domain
        let alert_domain: String = conn
            .query_row("SELECT domain FROM events WHERE alert = 1", [], |row| {
                row.get(0)
            })
            .expect("domain query failed");
        assert_eq!(alert_domain, "evil.malicious.com");
    }

    // Export functionality unit tests (bd-uj6)

    #[test]
    fn csv_escape_handles_quotes() {
        // Quotes must be doubled (RFC 4180)
        assert_eq!(csv_escape("say \"hello\""), "\"say \"\"hello\"\"\"");
        assert_eq!(csv_escape("\"quoted\""), "\"\"\"quoted\"\"\"");
        assert_eq!(csv_escape("a\"b\"c"), "\"a\"\"b\"\"c\"");
    }

    #[test]
    fn csv_escape_handles_commas() {
        assert_eq!(csv_escape("a,b,c"), "\"a,b,c\"");
        assert_eq!(csv_escape("foo, bar"), "\"foo, bar\"");
        assert_eq!(csv_escape(",leading"), "\",leading\"");
        assert_eq!(csv_escape("trailing,"), "\"trailing,\"");
    }

    #[test]
    fn csv_escape_handles_newlines() {
        assert_eq!(csv_escape("line1\nline2"), "\"line1\nline2\"");
        assert_eq!(csv_escape("line1\r\nline2"), "\"line1\r\nline2\"");
        assert_eq!(csv_escape("has\rcarriage"), "\"has\rcarriage\"");
    }

    #[test]
    fn csv_escape_combined_special_chars() {
        // Combined: commas, quotes, and newlines
        assert_eq!(csv_escape("a,\"b\"\nc"), "\"a,\"\"b\"\"\nc\"");
    }

    #[test]
    fn csv_header_has_correct_field_order() {
        let fields = vec![
            "ts".to_string(),
            "run_id".to_string(),
            "event".to_string(),
            "provider".to_string(),
        ];
        let header = format_csv_header(&fields);
        assert_eq!(header, "ts,run_id,event,provider\r\n");
    }

    #[test]
    fn csv_row_formats_correctly() {
        let values: Vec<(String, FieldValue)> = vec![
            (
                "ts".to_string(),
                FieldValue::String("2026-01-21T12:00:00Z".to_string()),
            ),
            ("pid".to_string(), FieldValue::Integer(1234)),
            ("domain".to_string(), FieldValue::Null),
        ];
        let row = format_csv_row(&values);
        assert_eq!(row, "2026-01-21T12:00:00Z,1234,\r\n");
    }

    #[test]
    fn jsonl_row_is_valid_json() {
        let values: Vec<(String, FieldValue)> = vec![
            (
                "ts".to_string(),
                FieldValue::String("2026-01-21T12:00:00Z".to_string()),
            ),
            ("pid".to_string(), FieldValue::Integer(1234)),
            ("comm".to_string(), FieldValue::String("test".to_string())),
        ];
        let row = format_jsonl_row(&values);
        // Should be valid JSON ending with newline
        assert!(row.ends_with('\n'));
        // Remove trailing newline and parse
        let json_str = row.trim_end();
        // Verify it starts with { and ends with }
        assert!(json_str.starts_with('{'));
        assert!(json_str.ends_with('}'));
        // Verify expected fields are present
        assert!(json_str.contains("\"ts\":\"2026-01-21T12:00:00Z\""));
        assert!(json_str.contains("\"pid\":1234"));
    }

    #[test]
    fn jsonl_row_omits_null_values() {
        let values: Vec<(String, FieldValue)> = vec![
            (
                "ts".to_string(),
                FieldValue::String("2026-01-21T12:00:00Z".to_string()),
            ),
            ("domain".to_string(), FieldValue::Null),
            ("pid".to_string(), FieldValue::Integer(42)),
        ];
        let row = format_jsonl_row(&values);
        // domain should not appear since it's null
        assert!(!row.contains("domain"));
        assert!(row.contains("ts"));
        assert!(row.contains("pid"));
    }

    #[test]
    fn jsonl_row_escapes_special_json_chars() {
        let values: Vec<(String, FieldValue)> = vec![(
            "comm".to_string(),
            FieldValue::String("test\nwith\ttabs".to_string()),
        )];
        let row = format_jsonl_row(&values);
        // Newlines and tabs must be escaped in JSON
        assert!(row.contains("\\n") || row.contains("\\t") || !row.contains('\t'));
    }

    #[test]
    fn export_query_builds_with_no_filters() {
        let filter = ExportFilter {
            run_id: None,
            since: None,
            until: None,
            providers: vec![],
            domain_patterns: vec![],
        };
        let fields = vec!["ts".to_string(), "event".to_string()];
        let (sql, params) = build_export_query(&filter, &fields);
        assert!(sql.contains("SELECT ts, event FROM events"));
        assert!(sql.contains("WHERE 1=1"));
        assert!(params.is_empty());
    }

    #[test]
    fn export_query_builds_with_run_id_filter() {
        let filter = ExportFilter {
            run_id: Some("run-123".to_string()),
            since: None,
            until: None,
            providers: vec![],
            domain_patterns: vec![],
        };
        let fields = vec!["ts".to_string()];
        let (sql, params) = build_export_query(&filter, &fields);
        assert!(sql.contains("run_id = ?"));
        assert_eq!(params, vec!["run-123"]);
    }

    #[test]
    fn export_query_builds_with_time_filters() {
        let filter = ExportFilter {
            run_id: None,
            since: Some("2026-01-20T00:00:00Z".to_string()),
            until: Some("2026-01-21T00:00:00Z".to_string()),
            providers: vec![],
            domain_patterns: vec![],
        };
        let fields = vec!["ts".to_string()];
        let (sql, params) = build_export_query(&filter, &fields);
        assert!(sql.contains("rano_utc(ts) >= rano_utc(?)"));
        assert!(sql.contains("rano_utc(ts) < rano_utc(?)"));
        assert_eq!(params.len(), 2);
    }

    #[test]
    fn export_query_builds_with_provider_filter() {
        let filter = ExportFilter {
            run_id: None,
            since: None,
            until: None,
            providers: vec!["anthropic".to_string(), "openai".to_string()],
            domain_patterns: vec![],
        };
        let fields = vec!["ts".to_string()];
        let (sql, params) = build_export_query(&filter, &fields);
        assert!(sql.contains("LOWER(provider) IN (?,?)"));
        assert!(params.contains(&"anthropic".to_string()));
        assert!(params.contains(&"openai".to_string()));
    }

    #[test]
    fn export_query_builds_with_domain_filter() {
        let filter = ExportFilter {
            run_id: None,
            since: None,
            until: None,
            providers: vec![],
            domain_patterns: vec!["*.example.com".to_string()],
        };
        let fields = vec!["ts".to_string()];
        let (sql, params) = build_export_query(&filter, &fields);
        assert!(sql.contains("LOWER(domain) LIKE ? ESCAPE"));
        assert!(params.contains(&"%.example.com".to_string()));
    }

    #[test]
    fn validate_fields_accepts_valid_fields() {
        let fields = vec![
            "ts".to_string(),
            "event".to_string(),
            "provider".to_string(),
            "domain".to_string(),
        ];
        assert!(validate_fields(&fields).is_ok());
    }

    #[test]
    fn validate_fields_rejects_invalid_field() {
        let fields = vec!["ts".to_string(), "invalid_field".to_string()];
        assert!(validate_fields(&fields).is_err());
    }

    // =========================================================================
    // Ancestry Tests
    // =========================================================================

    #[test]
    fn format_ancestry_empty_chain() {
        let chain: Vec<(u32, String)> = vec![];
        let result = format_ancestry(&chain);
        assert_eq!(result, "");
    }

    #[test]
    fn format_ancestry_single_process() {
        let chain = vec![(1234, "myprocess".to_string())];
        let result = format_ancestry(&chain);
        assert_eq!(result, "myprocess(1234)");
    }

    #[test]
    fn format_ancestry_two_processes() {
        let chain = vec![(1, "init".to_string()), (1234, "myprocess".to_string())];
        let result = format_ancestry(&chain);
        assert_eq!(result, "init(1) \u{2192} myprocess(1234)");
    }

    #[test]
    fn format_ancestry_three_processes() {
        let chain = vec![
            (1, "init".to_string()),
            (500, "bash".to_string()),
            (1234, "myprocess".to_string()),
        ];
        let result = format_ancestry(&chain);
        assert_eq!(
            result,
            "init(1) \u{2192} bash(500) \u{2192} myprocess(1234)"
        );
    }

    #[test]
    fn format_ancestry_five_processes_no_truncation() {
        let chain = vec![
            (1, "init".to_string()),
            (100, "systemd".to_string()),
            (200, "sshd".to_string()),
            (300, "bash".to_string()),
            (400, "app".to_string()),
        ];
        let result = format_ancestry(&chain);
        assert!(result.contains("init(1)"));
        assert!(result.contains("app(400)"));
        // 5 processes should not truncate
        assert!(!result.contains("..."));
    }

    #[test]
    fn format_ancestry_six_processes_truncates() {
        let chain = vec![
            (1, "init".to_string()),
            (100, "systemd".to_string()),
            (200, "sshd".to_string()),
            (300, "bash".to_string()),
            (400, "python".to_string()),
            (500, "app".to_string()),
        ];
        let result = format_ancestry(&chain);
        // Should truncate to: ... → python(400) → app(500)
        assert!(result.contains("..."));
        assert!(result.contains("python(400)"));
        assert!(result.contains("app(500)"));
        // Should NOT contain the early processes
        assert!(!result.contains("init(1)"));
        assert!(!result.contains("systemd(100)"));
    }

    #[test]
    fn format_ancestry_list_empty() {
        let chain: Vec<(u32, String)> = vec![];
        let result = format_ancestry_list(&chain);
        assert!(result.is_empty());
    }

    #[test]
    fn format_ancestry_list_formats_correctly() {
        let chain = vec![(1, "init".to_string()), (1234, "claude".to_string())];
        let result = format_ancestry_list(&chain);
        assert_eq!(result, vec!["init(1)", "claude(1234)"]);
    }

    #[test]
    fn truncate_ancestry_list_empty() {
        let list: Vec<String> = vec![];
        let result = truncate_ancestry_list(&list);
        assert!(result.is_empty());
    }

    #[test]
    fn truncate_ancestry_list_single() {
        let list = vec!["init(1)".to_string()];
        let result = truncate_ancestry_list(&list);
        assert_eq!(result, vec!["init(1)"]);
    }

    #[test]
    fn truncate_ancestry_list_five_no_truncation() {
        let list = vec![
            "a(1)".to_string(),
            "b(2)".to_string(),
            "c(3)".to_string(),
            "d(4)".to_string(),
            "e(5)".to_string(),
        ];
        let result = truncate_ancestry_list(&list);
        assert_eq!(result.len(), 5);
        assert_eq!(result, list);
    }

    #[test]
    fn truncate_ancestry_list_six_truncates() {
        let list = vec![
            "a(1)".to_string(),
            "b(2)".to_string(),
            "c(3)".to_string(),
            "d(4)".to_string(),
            "e(5)".to_string(),
            "f(6)".to_string(),
        ];
        let result = truncate_ancestry_list(&list);
        assert_eq!(result.len(), 3);
        assert_eq!(result[0], "...");
        assert_eq!(result[1], "e(5)");
        assert_eq!(result[2], "f(6)");
    }

    #[test]
    fn truncate_ancestry_list_ten_truncates() {
        let list: Vec<String> = (1..=10).map(|i| format!("p{i}({i})")).collect();
        let result = truncate_ancestry_list(&list);
        assert_eq!(result.len(), 3);
        assert_eq!(result[0], "...");
        assert_eq!(result[1], "p9(9)");
        assert_eq!(result[2], "p10(10)");
    }

    #[test]
    fn ancestry_chain_to_path_empty() {
        let chain: Vec<(u32, String)> = vec![];
        let result = ancestry_chain_to_path(&chain);
        assert_eq!(result, "");
    }

    #[test]
    fn ancestry_chain_to_path_single() {
        let chain = vec![(1234, "app".to_string())];
        let result = ancestry_chain_to_path(&chain);
        assert_eq!(result, "app:1234");
    }

    #[test]
    fn ancestry_chain_to_path_multiple() {
        let chain = vec![
            (1, "init".to_string()),
            (500, "bash".to_string()),
            (1234, "claude".to_string()),
        ];
        let result = ancestry_chain_to_path(&chain);
        assert_eq!(result, "init:1,bash:500,claude:1234");
    }

    #[test]
    fn ancestry_cache_new_has_empty_cache() {
        let cache = AncestryCache::new(Duration::from_secs(30));
        assert!(cache.cache.is_empty());
    }

    #[test]
    fn ancestry_cache_ttl_is_set() {
        let ttl = Duration::from_secs(60);
        let cache = AncestryCache::new(ttl);
        assert_eq!(cache.ttl, ttl);
    }

    #[test]
    fn proc_stat_parses_complete_comm_and_kernel_identity() {
        let tail = "R 42 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 987";
        for comm in ["normal", "odd name)", " ) nested (comm)\n"] {
            let stat = parse_proc_stat(&format!("123 ({comm}) {tail}")).unwrap();
            assert_eq!(stat.comm, comm);
            assert_eq!(stat.ppid, 42);
            assert_eq!(
                stat.identity,
                ProcessIdentity {
                    pid: 123,
                    start_time: 987
                }
            );
        }
        let max = parse_proc_stat(
            "4294967295 () S 0 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 18446744073709551615",
        )
        .unwrap();
        assert_eq!(max.identity.pid, u32::MAX);
        assert_eq!(max.identity.start_time, u64::MAX);
        for malformed in [
            "",
            "123",
            "123 (incomplete",
            "-1 (name) R 0",
            "1 (name)R 0",
            "1 (name) ?? 0 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 1",
            "1 (name) R bad 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 1",
        ] {
            assert!(
                parse_proc_stat(malformed).is_none(),
                "malformed stat accepted"
            );
        }
    }

    #[test]
    fn socket_inode_requires_the_kernel_link_shape() {
        assert_eq!(parse_socket_inode("socket:[42]"), Some(42));
        assert_eq!(
            parse_socket_inode("socket:[18446744073709551615]"),
            Some(u64::MAX)
        );
        for link in [
            "/tmp/socket:[42]",
            "socket:[42]suffix",
            "socket:[]",
            "socket:[+42]",
            "socket:[x]",
            "socket:[18446744073709551616]",
        ] {
            assert_eq!(
                parse_socket_inode(link),
                None,
                "non-socket descriptor accepted"
            );
        }
    }

    fn topology_fixture(rows: &[(u32, u32, u64, &str)]) -> ProcessSnapshot {
        let mut snapshot = ProcessSnapshot::default();
        for &(pid, ppid, start_time, comm) in rows {
            snapshot.stat.insert(
                pid,
                ProcStat {
                    identity: ProcessIdentity { pid, start_time },
                    ppid,
                    comm: comm.to_string(),
                },
            );
            snapshot.meta.insert(
                pid,
                PidMeta {
                    comm: comm.to_string(),
                    cmdline: comm.to_string(),
                    argv: vec![comm.to_string()],
                    provider: Provider::Unknown,
                    provider_origin: None,
                },
            );
        }
        snapshot
    }

    #[test]
    fn exclusions_prune_subtrees_including_explicit_and_nested_roots() {
        let snapshot = topology_fixture(&[
            (1, 0, 1, "init"),
            (2, 1, 2, "claude"),
            (3, 2, 3, "skip-this"),
            (4, 3, 4, "claude"),
            (5, 2, 5, "worker"),
        ]);
        let excluded = excluded_processes(&["SKIP".to_string()], &snapshot);
        assert_eq!(excluded, HashSet::from([3, 4]));
        let roots = find_root_pids(&["claude".to_string()], &excluded, &[4], &snapshot);
        assert_eq!(roots, [2]);
        let monitored = monitored_roots(&roots, false, &snapshot, &excluded);
        assert_eq!(
            monitored.keys().copied().collect::<HashSet<_>>(),
            HashSet::from([2, 5])
        );
        assert_eq!(monitored[&5], snapshot.stat[&2].identity);
        assert_eq!(
            monitored_roots(&roots, true, &snapshot, &excluded)
                .keys()
                .copied()
                .collect::<Vec<_>>(),
            [2]
        );
    }

    #[test]
    fn nested_roots_choose_the_nearest_and_ignore_unrelated_processes() {
        let snapshot = topology_fixture(&[
            (1, 0, 1, "init"),
            (2, 1, 2, "root"),
            (3, 2, 3, "nested"),
            (4, 3, 4, "worker"),
            (5, 1, 5, "unrelated"),
        ]);
        let monitored = monitored_roots(&[3, 2], false, &snapshot, &HashSet::new());
        assert_eq!(monitored[&2], snapshot.stat[&2].identity);
        assert_eq!(monitored[&3], snapshot.stat[&3].identity);
        assert_eq!(monitored[&4], snapshot.stat[&3].identity);
        assert!(!monitored.contains_key(&5));
    }

    fn classify_fixture(snapshot: &mut ProcessSnapshot, matcher: &ProviderMatcher) {
        for (&pid, meta) in &mut snapshot.meta {
            meta.provider = provider_from_text(&meta.comm, &meta.cmdline, matcher);
            meta.provider_origin =
                (meta.provider != Provider::Unknown).then_some(snapshot.stat[&pid].identity);
        }
    }

    #[test]
    fn unknown_leaves_inherit_each_provider_without_changing_original_argv() {
        for (name, provider) in [
            ("claude", Provider::Anthropic),
            ("codex", Provider::OpenAI),
            ("gemini", Provider::Google),
        ] {
            let mut snapshot = topology_fixture(&[
                (1, 0, 1, "init"),
                (2, 1, 2, name),
                (3, 2, 3, "socket-helper"),
            ]);
            snapshot.meta.get_mut(&3).unwrap().argv = vec![
                "socket-helper".to_string(),
                "--password".to_string(),
                "FAKE WORDS CREDENTIAL".to_string(),
            ];
            classify_fixture(&mut snapshot, &ProviderMatcher::default());
            let monitored = monitored_roots(&[2], false, &snapshot, &HashSet::new());
            let resolved = resolve_provider_meta(&monitored, &snapshot);
            assert_eq!(resolved[&3].provider, provider);
            assert_eq!(
                resolved[&3].provider_origin,
                Some(snapshot.stat[&2].identity)
            );
            assert_eq!(resolved[&3].argv, snapshot.meta[&3].argv);
            assert_eq!(
                redact_argv(&resolved[&3].argv, RedactMode::Secrets),
                "socket-helper --password <redacted>"
            );
        }
    }

    #[test]
    fn direct_unique_provider_wins_and_nested_origins_stay_distinct() {
        let mut snapshot = topology_fixture(&[
            (1, 0, 1, "init"),
            (2, 1, 2, "claude"),
            (3, 2, 3, "codex"),
            (4, 3, 4, "helper"),
            (5, 2, 5, "gemini"),
            (6, 1, 6, "unrelated"),
        ]);
        classify_fixture(&mut snapshot, &ProviderMatcher::default());
        let monitored = monitored_roots(&[2, 3, 6], false, &snapshot, &HashSet::new());
        let resolved = resolve_provider_meta(&monitored, &snapshot);
        assert_eq!(resolved[&3].provider, Provider::OpenAI);
        assert_eq!(
            resolved[&3].provider_origin,
            Some(snapshot.stat[&3].identity)
        );
        assert_eq!(resolved[&4].provider, Provider::OpenAI);
        assert_eq!(
            resolved[&4].provider_origin,
            Some(snapshot.stat[&3].identity)
        );
        assert_eq!(resolved[&5].provider, Provider::Google);
        assert_eq!(
            resolved[&5].provider_origin,
            Some(snapshot.stat[&5].identity)
        );
        assert_eq!(resolved[&6].provider, Provider::Unknown);
        assert_eq!(resolved[&6].provider_origin, None);
        let isolated = monitored_roots(&[4], true, &snapshot, &HashSet::new());
        assert_eq!(
            resolve_provider_meta(&isolated, &snapshot)[&4].provider,
            Provider::Unknown,
            "unmonitored ancestors cannot supply provider attribution"
        );
    }

    #[test]
    fn ambiguous_leaf_inherits_unique_ancestor_and_custom_patterns_apply() {
        let matcher = ProviderMatcher {
            anthropic: vec!["custom-root".to_string()],
            openai: vec!["open-marker".to_string()],
            google: vec!["other-marker".to_string()],
        };
        let mut snapshot = topology_fixture(&[
            (1, 0, 1, "init"),
            (2, 1, 2, "CUSTOM-ROOT"),
            (3, 2, 3, "open-marker other-marker"),
        ]);
        classify_fixture(&mut snapshot, &matcher);
        assert_eq!(snapshot.meta[&3].provider, Provider::Unknown);
        let monitored = monitored_roots(&[2], false, &snapshot, &HashSet::new());
        let resolved = resolve_provider_meta(&monitored, &snapshot);
        assert_eq!(resolved[&3].provider, Provider::Anthropic);
        assert_eq!(
            resolved[&3].provider_origin,
            Some(snapshot.stat[&2].identity)
        );
        assert_eq!(
            provider_from_text("helper", "claude codex", &ProviderMatcher::default()),
            Provider::Unknown
        );
    }

    #[test]
    fn ancestry_cache_invalidates_identical_comm_pid_reuse_and_reparenting() {
        let original = topology_fixture(&[
            (1, 0, 1, "init"),
            (2, 1, 2, "old-parent"),
            (3, 2, 3, "same-name"),
        ]);
        let mut cache = AncestryCache::new(Duration::from_secs(30));
        assert_eq!(
            cache.get_or_compute(3, &original),
            [
                (1, "init".to_string()),
                (2, "old-parent".to_string()),
                (3, "same-name".to_string())
            ]
        );
        let reused = topology_fixture(&[
            (1, 0, 1, "init"),
            (4, 1, 4, "new-parent"),
            (3, 4, 30, "same-name"),
        ]);
        let chain = cache.get_or_compute(3, &reused);
        assert_eq!(chain[1], (4, "new-parent".to_string()));
        assert_eq!(cache.cache[&3].identities.last().unwrap().start_time, 30);
        let reparented = topology_fixture(&[(1, 0, 1, "init"), (3, 1, 30, "same-name")]);
        assert_eq!(cache.get_or_compute(3, &reparented).len(), 2);
        cache.retain_live(&ProcessSnapshot::default());
        assert!(cache.cache.is_empty());
    }

    #[test]
    fn shared_inode_owners_are_sorted_deduplicated_and_identity_bound() {
        let mut owners = HashMap::from([(
            99,
            vec![
                ProcessIdentity {
                    pid: 5,
                    start_time: 50,
                },
                ProcessIdentity {
                    pid: 2,
                    start_time: 20,
                },
                ProcessIdentity {
                    pid: 2,
                    start_time: 20,
                },
            ],
        )]);
        canonicalize_inode_owners(&mut owners);
        assert_eq!(
            owners[&99],
            [
                ProcessIdentity {
                    pid: 2,
                    start_time: 20
                },
                ProcessIdentity {
                    pid: 5,
                    start_time: 50
                }
            ]
        );
        let json = format_ownership_json(
            99,
            owners[&99][0],
            ProcessIdentity {
                pid: 1,
                start_time: 10,
            },
            &owners[&99],
            None,
        );
        assert_eq!(
            json,
            "{\"inode\":\"99\",\"pid\":2,\"start_time\":\"20\",\"root_pid\":1,\"root_start_time\":\"10\",\"owners\":[{\"pid\":2,\"start_time\":\"20\"},{\"pid\":5,\"start_time\":\"50\"}],\"provider_origin\":null}"
        );
        let first = ConnKey {
            inode: 99,
            process: owners[&99][0],
            root: ProcessIdentity {
                pid: 1,
                start_time: 10,
            },
            provider: Provider::Unknown,
            provider_origin: None,
            proto: Proto::Tcp,
            socket_kind: SocketKind::Connection,
            local_ip: "127.0.0.1".parse().unwrap(),
            local_port: 123,
            remote_ip: "127.0.0.1".parse().unwrap(),
            remote_port: 456,
        };
        let reused = ConnKey {
            process: ProcessIdentity {
                pid: 2,
                start_time: 21,
            },
            ..first.clone()
        };
        let replaced_socket = ConnKey {
            inode: 100,
            ..first.clone()
        };
        assert_ne!(first, reused);
        assert_ne!(first, replaced_socket);
    }

    #[test]
    fn format_ancestry_special_chars_in_comm() {
        // Process names with special characters
        let chain = vec![(1, "init".to_string()), (1234, "my-proc_v2".to_string())];
        let result = format_ancestry(&chain);
        assert_eq!(result, "init(1) \u{2192} my-proc_v2(1234)");
    }

    #[test]
    fn ancestry_chain_to_path_special_chars_in_comm() {
        let chain = vec![(1, "init".to_string()), (1234, "my-proc_v2".to_string())];
        let result = ancestry_chain_to_path(&chain);
        assert_eq!(result, "init:1,my-proc_v2:1234");
    }

    #[test]
    fn ancestry_reserved_delimiters_roundtrip_into_report_roots() {
        let name = "root%2c,part:role\n雪";
        let path = ancestry_chain_to_path(&[(1, name.to_string()), (2, "child".to_string())]);
        assert_eq!(path, "root%252c%2cpart%3arole%0a雪:1,child:2");
        let mut conn = setup_test_db();
        let mut event = create_test_event("2026-01-20T12:00:00Z", "connect", Provider::Anthropic);
        event.ancestry_path = Some(path);
        write_sqlite_batch(&mut conn, &[event]).unwrap();
        let roots = query_ancestry_roots(
            &conn,
            &ReportFilter {
                run_id: None,
                since: None,
                until: None,
            },
            10,
            true,
        )
        .unwrap();
        assert_eq!(roots[0].root, name);
        assert_eq!(roots[0].connects, 1);
    }

    // =========================================================================
    // Preset Tests
    // =========================================================================

    #[test]
    fn config_sources_preserve_ordered_lists_aliases_and_cli_precedence() {
        let mut args = MonitorArgs::default();
        let loader = PresetLoader::new();
        let first = loader
            .parse_preset_content(
                "pattern=first\npattern=second\nstats_view=domain\npcap=true\ndomain_mode=ptr\n",
            )
            .unwrap();
        apply_preset_values(&first, &mut args).unwrap();
        assert_eq!(args.patterns, ["first", "second"]);
        assert_eq!(args.domain_mode, DomainMode::Ptr);
        assert!(!args.pcap);
        let second = loader
            .parse_preset_content("pattern=third\nstats_view=port,process\n")
            .unwrap();
        apply_preset_values(&second, &mut args).unwrap();
        assert_eq!(args.patterns, ["third"]);
        assert_eq!(args.stats_views, [StatsView::Port, StatsView::Process]);
        let args = apply_monitor_cli(
            &[
                "--pattern".to_string(),
                "cli-a".to_string(),
                "--pattern".to_string(),
                "cli-b".to_string(),
                "--stats-view".to_string(),
                "provider".to_string(),
                "--pcap".to_string(),
                "--domain-mode".to_string(),
                "ptr".to_string(),
            ],
            args,
        )
        .unwrap();
        assert_eq!(args.patterns, ["cli-a", "cli-b"]);
        assert_eq!(args.stats_views, [StatsView::Provider]);
        assert_eq!(args.domain_mode, DomainMode::Ptr);
        assert!(!args.pcap);
        assert_eq!(args.config_origins["pattern"], "cli");
    }

    #[test]
    fn user_preset_overrides_builtin_and_preserves_repeated_keys() {
        let directory = tempfile::tempdir().unwrap().keep();
        fs::write(
            directory.join("audit.conf"),
            "summary_only=false\ninclude_udp=false\npattern=first\npattern=second\n",
        )
        .unwrap();
        let mut loader = PresetLoader::new();
        loader.user_preset_dirs = vec![directory];
        let values = loader.load_preset("audit").unwrap();
        let mut args = MonitorArgs::default();
        apply_preset_values(&values, &mut args).unwrap();
        assert!(!args.summary_only && !args.include_udp);
        assert_eq!(args.patterns, ["first", "second"]);
        assert!(loader.load_preset("../audit").is_err());
    }

    #[test]
    fn config_flag_values_are_never_reinterpreted_as_control_options() {
        let options: Vec<_> = [
            "--pattern",
            "--no-config",
            "--config",
            "actual.conf",
            "--preset",
            "live",
        ]
        .into_iter()
        .map(str::to_string)
        .collect();
        let paths = find_config_flag(&options);
        assert!(paths.use_config);
        assert_eq!(paths.kv_path, Some(PathBuf::from("actual.conf")));
        assert_eq!(find_preset_flags(&options), ["live"]);
        let args = load_monitor_args(&[
            "--no-config".to_string(),
            "--pattern".to_string(),
            "--help".to_string(),
        ])
        .unwrap();
        assert_eq!(args.patterns, ["--help"]);
        let request = parse_config_args(&[
            "show".to_string(),
            "--json".to_string(),
            "--no-config".to_string(),
            "--pattern".to_string(),
            "--json".to_string(),
        ])
        .unwrap();
        assert_eq!(
            request.subcommand,
            ConfigSubcommand::Show {
                json: true,
                options: ["--no-config", "--pattern", "--json"]
                    .into_iter()
                    .map(str::to_string)
                    .collect()
            }
        );
    }

    #[test]
    fn effective_configuration_has_typed_defaults_and_masks_introspection() {
        let mut args = load_monitor_args(&["--no-config".to_string()]).unwrap();
        let values = effective_config_values(&args);
        for key in config_validation::KNOWN_CONFIG_KEYS {
            assert!(values.contains_key(key), "missing supported setting {key}");
        }
        assert_eq!(values["db_flush_ms"], "1000");
        assert_eq!(values["include_udp"], "true");
        assert_eq!(values["stats_view"], "[\"provider\"]");
        assert_eq!(values["pcap_cache_max"], "10000");
        args.patterns = vec![
            "claude --password multi word secret".to_string(),
            "  two  spaces \t".to_string(),
            "sk-ant-api03-not-a-real-credential".to_string(),
        ];
        args.session_name = Some("API_KEY=not-a-real-secret".to_string());
        args.log_file = Some(PathBuf::from(
            "/tmp/ConfigSource12345678901234567890/actual.jsonl",
        ));
        args.sqlite_path = "/tmp/ConfigSource12345678901234567890/actual.sqlite".to_string();
        args.config_origins.insert(
            "pattern".to_string(),
            "/tmp/ConfigSource12345678901234567890/actual.conf".to_string(),
        );
        let rendered = format_effective_config_json(&args);
        for secret in [
            "multi word secret",
            "sk-ant-api03-not-a-real-credential",
            "not-a-real-secret",
        ] {
            assert!(
                !rendered.contains(secret),
                "introspection disclosed credential"
            );
        }
        assert!(rendered.contains("  two  spaces \\t"));
        assert!(rendered.contains("<redacted>"));
        for path in [
            "/tmp/ConfigSource12345678901234567890/actual.jsonl",
            "/tmp/ConfigSource12345678901234567890/actual.sqlite",
            "/tmp/ConfigSource12345678901234567890/actual.conf",
        ] {
            assert!(
                rendered.contains(path),
                "ordinary diagnostic path was masked"
            );
        }
        assert_eq!(args.patterns[0], "claude --password multi word secret");
        assert_eq!(config_json_text("quote\"\n\\"), "\"quote\\\"\\n\\\\\"");
    }

    #[test]
    fn typed_config_bounds_reject_zero_overflow_and_invalid_values() {
        for (key, value) in [
            ("pid", "0"),
            ("pid", "4294967296"),
            ("db_flush_ms", "0"),
            ("db_batch_size", "0"),
            ("db_queue_max", "0"),
            ("stats_top", "0"),
            ("pcap_cache_max", "99"),
            ("retry_threshold", "0"),
            ("retry_window_ms", "0"),
            ("alert_max_connections", "0"),
            ("alert_max_per_provider", "0"),
            ("alert_duration_ms", "0"),
            ("interval_ms", "18446744073709551616"),
            ("interval_ms", "-1"),
            ("json", "maybe"),
            ("domain_mode", "invalid"),
            ("stats_view", "port,invalid"),
            ("pcap_interface", "   "),
            ("pattern", ""),
            ("log_format", "xml"),
        ] {
            assert!(
                apply_config_value(key, value, &mut MonitorArgs::default()).is_err(),
                "accepted {key}={value}"
            );
        }
        let mut args = MonitorArgs::default();
        for (key, value) in [
            ("pid", "4294967295"),
            ("interval_ms", "18446744073709551615"),
            ("stats_interval_ms", "0"),
            ("stats_cycle_ms", "0"),
            ("alert_cooldown_ms", "0"),
            ("pcap_cache_max", "100"),
        ] {
            assert!(
                apply_config_value(key, value, &mut args).unwrap(),
                "rejected {key}={value}"
            );
        }
        assert_eq!(args.interval_ms, u64::MAX);
        assert_eq!(args.pids, [u32::MAX]);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn explicit_pid_snapshot_retains_real_ancestors_and_omits_unselected_children() {
        let mut child = ProcessCommand::new("sleep").arg("10").spawn().unwrap();
        let args = MonitorArgs {
            pids: vec![std::process::id()],
            no_descendants: true,
            ..MonitorArgs::default()
        };
        let snapshot = collect_process_snapshot_for_scope(&ProviderMatcher::default(), &args);
        let target = snapshot
            .stat
            .get(&std::process::id())
            .map(|stat| stat.identity);
        let child_present = snapshot.stat.contains_key(&child.id());
        let ancestry = ancestry_identities(std::process::id(), &snapshot);
        child.kill().unwrap();
        child.wait().unwrap();
        assert!(target.is_some(), "requested live process absent");
        assert!(!child_present, "no-descendants included an actual child");
        assert_eq!(ancestry.last().copied(), target);
        assert_eq!(
            snapshot.stat.len(),
            ancestry.len(),
            "unrelated processes entered scoped snapshot"
        );
    }

    #[test]
    fn preset_loader_has_builtin_presets() {
        let loader = PresetLoader::new();
        assert!(loader.builtin_presets.contains_key("audit"));
        assert!(loader.builtin_presets.contains_key("quiet"));
        assert!(loader.builtin_presets.contains_key("live"));
        assert!(loader.builtin_presets.contains_key("verbose"));
    }

    #[test]
    fn preset_loader_loads_audit_preset() {
        let loader = PresetLoader::new();
        let values = loader
            .load_preset("audit")
            .expect("audit preset should exist");
        let values: BTreeMap<_, _> = values.into_iter().collect();
        assert_eq!(values.get("summary_only"), Some(&"true".to_string()));
        assert_eq!(values.get("stats_interval_ms"), Some(&"0".to_string()));
    }

    #[test]
    fn preset_loader_loads_quiet_preset() {
        let loader = PresetLoader::new();
        let values = loader
            .load_preset("quiet")
            .expect("quiet preset should exist");
        let values: BTreeMap<_, _> = values.into_iter().collect();
        assert_eq!(values.get("summary_only"), Some(&"true".to_string()));
        assert_eq!(values.get("no_banner"), Some(&"true".to_string()));
    }

    #[test]
    fn preset_loader_loads_live_preset() {
        let loader = PresetLoader::new();
        let values = loader
            .load_preset("live")
            .expect("live preset should exist");
        let values: BTreeMap<_, _> = values.into_iter().collect();
        assert_eq!(values.get("stats_interval_ms"), Some(&"500".to_string()));
        assert_eq!(values.get("stats_top"), Some(&"10".to_string()));
    }

    #[test]
    fn preset_loader_loads_verbose_preset() {
        let loader = PresetLoader::new();
        let values = loader
            .load_preset("verbose")
            .expect("verbose preset should exist");
        let values: BTreeMap<_, _> = values.into_iter().collect();
        assert_eq!(values.get("include_udp"), Some(&"true".to_string()));
        assert_eq!(values.get("include_listening"), Some(&"true".to_string()));
    }

    #[test]
    fn preset_loader_unknown_preset_returns_error() {
        let loader = PresetLoader::new();
        let result = loader.load_preset("nonexistent");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("Unknown preset 'nonexistent'"));
        assert!(err.contains("audit")); // Should list available presets
    }

    #[test]
    fn preset_loader_list_presets_includes_all_builtins() {
        let loader = PresetLoader::new();
        let presets = loader.list_presets();
        let names: Vec<&str> = presets.iter().map(|p| p.name.as_str()).collect();
        assert!(names.contains(&"audit"));
        assert!(names.contains(&"quiet"));
        assert!(names.contains(&"live"));
        assert!(names.contains(&"verbose"));
    }

    #[test]
    fn preset_loader_extracts_description() {
        let loader = PresetLoader::new();
        let presets = loader.list_presets();
        let audit = presets
            .iter()
            .find(|p| p.name == "audit")
            .expect("audit preset should exist");
        assert_eq!(audit.description, "Security review / minimal noise");
    }

    #[test]
    fn preset_parse_content_handles_empty_lines() {
        let loader = PresetLoader::new();
        let content = "# Comment\n\nkey1=value1\n\n# Another comment\nkey2=value2\n";
        let values = loader
            .parse_preset_content(content)
            .expect("parse should succeed");
        let values: BTreeMap<_, _> = values.into_iter().collect();
        assert_eq!(values.get("key1"), Some(&"value1".to_string()));
        assert_eq!(values.get("key2"), Some(&"value2".to_string()));
    }

    #[test]
    fn preset_parse_content_strips_inline_comments() {
        let loader = PresetLoader::new();
        let content = "key1=value1 # inline comment\n";
        let values = loader
            .parse_preset_content(content)
            .expect("parse should succeed");
        let values: BTreeMap<_, _> = values.into_iter().collect();
        // Note: current implementation treats everything after # as comment
        // so "value1 " (with trailing space) is the value
        assert!(values.contains_key("key1"));
    }

    #[test]
    fn apply_preset_values_sets_summary_only() {
        let mut args = MonitorArgs::default();
        let values = vec![("summary_only".to_string(), "true".to_string())];

        apply_preset_values(&values, &mut args).expect("apply should succeed");
        assert!(args.summary_only);
    }

    #[test]
    fn apply_preset_values_sets_stats_interval() {
        let mut args = MonitorArgs::default();
        let values = vec![("stats_interval_ms".to_string(), "5000".to_string())];

        apply_preset_values(&values, &mut args).expect("apply should succeed");
        assert_eq!(args.stats_interval_ms, 5000);
    }

    #[test]
    fn apply_preset_values_sets_include_udp() {
        let mut args = MonitorArgs::default();
        let values = vec![("include_udp".to_string(), "true".to_string())];

        apply_preset_values(&values, &mut args).expect("apply should succeed");
        assert!(args.include_udp);
    }

    #[test]
    fn apply_preset_values_multiple_values() {
        let mut args = MonitorArgs::default();
        let values = vec![
            ("summary_only".to_string(), "true".to_string()),
            ("no_banner".to_string(), "true".to_string()),
            ("stats_interval_ms".to_string(), "0".to_string()),
        ];

        apply_preset_values(&values, &mut args).expect("apply should succeed");
        assert!(args.summary_only);
        assert!(args.no_banner);
        assert_eq!(args.stats_interval_ms, 0);
    }

    #[test]
    fn apply_preset_values_ignores_unknown_keys() {
        let mut args = MonitorArgs::default();
        let values = vec![("unknown_key_xyz".to_string(), "some_value".to_string())];

        // Should not error, just warn (to stderr)
        let result = apply_preset_values(&values, &mut args);
        assert!(result.is_ok());
    }

    #[test]
    fn preset_loader_list_preset_names() {
        let loader = PresetLoader::new();
        let names = loader.list_preset_names();
        assert!(names.contains(&"audit".to_string()));
        assert!(names.contains(&"quiet".to_string()));
        assert!(names.contains(&"live".to_string()));
        assert!(names.contains(&"verbose".to_string()));
    }

    #[test]
    fn test_retry_detection_triggers_at_threshold() {
        let mut tracker = RetryTracker::new(3, 60000);
        let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(8, 8, 8, 8));
        let port = 443;
        let pid = 1234;

        // First two connections should not trigger warning
        let w1 = tracker.track_connection(ip, port, pid);
        assert!(w1.is_none(), "First connection should not trigger warning");

        let w2 = tracker.track_connection(ip, port, pid);
        assert!(w2.is_none(), "Second connection should not trigger warning");

        // Third connection (at threshold) should trigger warning
        let w3 = tracker.track_connection(ip, port, pid);
        assert!(w3.is_some(), "Third connection should trigger warning");
        let warning = w3.unwrap();
        assert_eq!(warning.count, 3);
        assert_eq!(warning.endpoint, (ip, port));
        assert_eq!(warning.window_seconds, 60.0);
    }

    #[test]
    fn test_retry_detection_window_expiry() {
        // Use a 100ms window for testing
        let mut tracker = RetryTracker::new(3, 100);
        let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(8, 8, 8, 8));
        let port = 443;
        let pid = 1234;

        // Add two connections
        tracker.track_connection(ip, port, pid);
        tracker.track_connection(ip, port, pid);

        // Wait for window to expire
        std::thread::sleep(std::time::Duration::from_millis(150));

        // This should be treated as first connection after expiry
        let w = tracker.track_connection(ip, port, pid);
        assert!(
            w.is_none(),
            "Connection after window expiry should not trigger warning"
        );
    }

    #[test]
    fn test_retry_detection_per_endpoint() {
        let mut tracker = RetryTracker::new(3, 60000);
        let ip1 = std::net::IpAddr::V4(std::net::Ipv4Addr::new(8, 8, 8, 8));
        let ip2 = std::net::IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, 1));
        let port1 = 443;
        let port2 = 80;
        let pid1 = 1234;
        let pid2 = 5678;

        // Different IPs should be tracked separately
        tracker.track_connection(ip1, port1, pid1);
        tracker.track_connection(ip1, port1, pid1);
        tracker.track_connection(ip2, port1, pid1);
        let w = tracker.track_connection(ip2, port1, pid1);
        assert!(w.is_none(), "Different IPs should not cross-trigger");

        // Different ports should be tracked separately
        tracker.track_connection(ip1, port2, pid1);
        let w2 = tracker.track_connection(ip1, port1, pid1);
        assert!(w2.is_some(), "Same IP:port should trigger");
        assert_eq!(w2.unwrap().count, 3);

        // Different PIDs should be tracked separately
        tracker.track_connection(ip1, port1, pid2);
        tracker.track_connection(ip1, port1, pid2);
        let w3 = tracker.track_connection(ip1, port1, pid2);
        assert!(
            w3.is_some(),
            "Same endpoint with different PID should trigger at threshold"
        );
        assert_eq!(w3.unwrap().count, 3);
    }

    #[test]
    fn retry_cooldown_suppresses_repeated_warnings() {
        let mut tracker = RetryTracker::new(2, 40);
        let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(9, 9, 9, 9));
        let port = 443;
        let pid = 7;

        assert!(tracker.track_connection(ip, port, pid).is_none());
        assert!(
            tracker.track_connection(ip, port, pid).is_some(),
            "first breach warns"
        );
        // Sustained storm: cooldown equal to window suppresses immediate re-warnings.
        assert!(
            tracker.track_connection(ip, port, pid).is_none(),
            "cooldown suppresses"
        );
        assert!(
            tracker.track_connection(ip, port, pid).is_none(),
            "cooldown suppresses"
        );
        std::thread::sleep(std::time::Duration::from_millis(60));
        // Cooldown AND detection window have both elapsed: fresh storm re-warns.
        assert!(tracker.track_connection(ip, port, pid).is_none());
        assert!(
            tracker.track_connection(ip, port, pid).is_some(),
            "warning re-emits after cooldown elapses"
        );
    }
    #[test]
    fn retry_tracker_bounds_endpoint_map_growth() {
        // Zero-width window expires every entry immediately: map must stay empty no
        // matter how many distinct endpoints are tracked (prune_stale wired in).
        let mut tracker = RetryTracker::new(1, 0);
        for i in 0..200u32 {
            let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, (i >> 8) as u8, i as u8));
            let _ = tracker.track_connection(ip, 80, i);
        }
        assert!(
            tracker.recent.values().all(Vec::is_empty),
            "expired endpoints must not accumulate timestamps"
        );
        tracker.prune_stale();
        assert!(
            tracker.last_warn.is_empty(),
            "expired warning cooldowns must not accumulate"
        );

        // Live entries are retained.
        let mut live = RetryTracker::new(1, 60_000);
        let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 1, 1, 1));
        let _ = live.track_connection(ip, 443, 1);
        assert_eq!(live.recent.len(), 1);
    }

    #[test]
    fn format_json_alert_escapes_quotes_in_strings() {
        let kind = AlertKind::DomainMatch {
            domain: "evil\".com".to_string(),
            pattern: "*.ev\"il.com\\x".to_string(),
        };
        let json = format_json_alert(
            "2026-08-23T00:00:00Z",
            &kind,
            AlertSeverity::Critical,
            None,
            None,
        );
        assert!(
            !json.contains("evil\".com"),
            "raw quote must not leak into JSON"
        );
        assert!(json.contains("evil\\\".com"), "quote must be escaped");
        assert!(
            json.contains("*.ev\\\"il.com\\\\x"),
            "backslash must be escaped"
        );
    }

    #[test]
    fn suppressed_banner_note_lines_plain_and_json() {
        let notes = vec!["pcap capture unavailable: perm".to_string()];
        let plain = suppressed_banner_note_lines(&notes, false);
        assert_eq!(
            plain,
            vec!["warning: pcap capture unavailable: perm".to_string()]
        );

        let quoted = vec!["note with \"quote\"".to_string()];
        let json_lines = suppressed_banner_note_lines(&quoted, true);
        assert_eq!(json_lines.len(), 2);
        assert_eq!(json_lines[0], "warning: note with \"quote\"");
        assert!(
            json_lines[1].contains("note with \\\"quote\\\""),
            "json message must escape quotes: {}",
            json_lines[1]
        );
    }

    // ============================================================
    // Stats Panel Tests - Aggregation and Rendering
    // ============================================================

    #[test]
    fn test_top_n_string_sorts_descending_by_count() {
        let mut map: BTreeMap<String, u64> = BTreeMap::new();
        map.insert("alpha".to_string(), 10);
        map.insert("beta".to_string(), 50);
        map.insert("gamma".to_string(), 30);
        map.insert("delta".to_string(), 20);

        let result = top_n_string(&map, 4);

        assert_eq!(result.len(), 4);
        assert_eq!(result[0], ("beta".to_string(), 50));
        assert_eq!(result[1], ("gamma".to_string(), 30));
        assert_eq!(result[2], ("delta".to_string(), 20));
        assert_eq!(result[3], ("alpha".to_string(), 10));
    }

    #[test]
    fn test_top_n_string_truncates_to_n() {
        let mut map: BTreeMap<String, u64> = BTreeMap::new();
        map.insert("a".to_string(), 100);
        map.insert("b".to_string(), 90);
        map.insert("c".to_string(), 80);
        map.insert("d".to_string(), 70);
        map.insert("e".to_string(), 60);

        let result = top_n_string(&map, 3);

        assert_eq!(result.len(), 3);
        assert_eq!(result[0].0, "a");
        assert_eq!(result[1].0, "b");
        assert_eq!(result[2].0, "c");
    }

    #[test]
    fn test_top_n_string_ties_sorted_by_key() {
        let mut map: BTreeMap<String, u64> = BTreeMap::new();
        map.insert("zebra".to_string(), 50);
        map.insert("apple".to_string(), 50);
        map.insert("mango".to_string(), 50);

        let result = top_n_string(&map, 3);

        // Same count, should sort by key ascending
        assert_eq!(result[0].0, "apple");
        assert_eq!(result[1].0, "mango");
        assert_eq!(result[2].0, "zebra");
    }

    #[test]
    fn test_top_n_string_empty_map() {
        let map: BTreeMap<String, u64> = BTreeMap::new();
        let result = top_n_string(&map, 5);
        assert!(result.is_empty());
    }

    #[test]
    fn test_top_n_string_with_port_keys() {
        let mut map: BTreeMap<u16, u64> = BTreeMap::new();
        map.insert(443, 100);
        map.insert(80, 80);
        map.insert(8080, 50);

        let result = top_n_string(&map, 3);

        assert_eq!(result[0], ("443".to_string(), 100));
        assert_eq!(result[1], ("80".to_string(), 80));
        assert_eq!(result[2], ("8080".to_string(), 50));
    }

    #[test]
    fn test_render_stats_bar_full_bar() {
        let style = OutputStyle {
            color: false,
            theme: Theme::Vivid,
        };
        let bar = render_stats_bar(100, 100, 10, style);
        assert_eq!(bar, "██████████");
    }

    #[test]
    fn test_render_stats_bar_half_bar() {
        let style = OutputStyle {
            color: false,
            theme: Theme::Vivid,
        };
        let bar = render_stats_bar(50, 100, 10, style);
        // 50/100 = 0.5, 0.5 * 10 = 5 blocks
        assert_eq!(bar.trim_end(), "█████");
    }

    #[test]
    fn test_render_stats_bar_zero_count() {
        let style = OutputStyle {
            color: false,
            theme: Theme::Vivid,
        };
        let bar = render_stats_bar(0, 100, 10, style);
        // Should be all spaces (width padding)
        assert_eq!(bar.len(), 10);
        assert!(bar.chars().all(|c| c == ' '));
    }

    #[test]
    fn test_render_stats_bar_zero_width() {
        let style = OutputStyle {
            color: false,
            theme: Theme::Vivid,
        };
        let bar = render_stats_bar(50, 100, 0, style);
        assert!(bar.is_empty());
    }

    #[test]
    fn test_render_stats_bar_zero_max_is_bounded() {
        // Regression: `render_stats_bar(count, 0, width, …)` used to hit a
        // floating-point divide by zero, round the resulting `+inf` to
        // `usize::MAX`, and then `"█".repeat(usize::MAX)` would abort the
        // process trying to allocate ~3 × usize::MAX bytes. The function
        // now emits a width-padded blank string for `max == 0`.
        let style = OutputStyle {
            color: false,
            theme: Theme::Vivid,
        };
        let bar = render_stats_bar(5, 0, 10, style);
        assert_eq!(bar.len(), 10, "zero-max output must be width-padded");
        assert!(
            bar.chars().all(|c| c == ' '),
            "zero-max output must contain no bar characters, got {bar:?}"
        );
    }

    #[test]
    fn test_render_stats_bar_count_exceeds_max_is_clamped() {
        // Regression: `count > max` is possible under non-atomic stats
        // snapshots (e.g. a stats thread reading per-provider counts and
        // the max independently). The rendered bar must not exceed the
        // requested width, and the repeat allocation must stay bounded.
        let style = OutputStyle {
            color: false,
            theme: Theme::Vivid,
        };
        let bar = render_stats_bar(1_000, 10, 10, style);
        // Bar is clamped to width; the full-width bar is 10 block chars.
        assert_eq!(
            bar.chars().filter(|c| *c == '█').count(),
            10,
            "oversized count must saturate at width, got {bar:?}"
        );
    }

    #[test]
    fn test_render_stats_bar_with_color() {
        let style = OutputStyle {
            color: true,
            theme: Theme::Vivid,
        };
        let bar = render_stats_bar(100, 100, 5, style);
        // Should contain ANSI escape sequences
        assert!(bar.contains("\x1b["));
        // Should still have the right block count when stripped
        let stripped = strip_ansi(&bar);
        assert_eq!(stripped, "█████");
    }

    #[test]
    fn test_strip_ansi_removes_color_codes() {
        let colored = "\x1b[31mred text\x1b[0m";
        let stripped = strip_ansi(colored);
        assert_eq!(stripped, "red text");
    }

    #[test]
    fn test_strip_ansi_handles_multiple_codes() {
        let colored = "\x1b[1;31mbold red\x1b[0m normal \x1b[32mgreen\x1b[0m";
        let stripped = strip_ansi(colored);
        assert_eq!(stripped, "bold red normal green");
    }

    #[test]
    fn test_strip_ansi_preserves_plain_text() {
        let plain = "no color codes here";
        let stripped = strip_ansi(plain);
        assert_eq!(stripped, plain);
    }

    #[test]
    fn test_strip_ansi_empty_string() {
        let empty = "";
        let stripped = strip_ansi(empty);
        assert!(stripped.is_empty());
    }

    #[test]
    fn test_paint_no_color_returns_plain() {
        let result = paint("hello", None, false, false, false);
        assert_eq!(result, "hello");
    }

    #[test]
    fn test_paint_with_color() {
        let result = paint("hello", Some(AnsiColor::Red), false, false, true);
        assert!(result.starts_with("\x1b["));
        assert!(result.contains("31")); // Red color code
        assert!(result.ends_with("\x1b[0m"));
        assert!(result.contains("hello"));
    }

    #[test]
    fn test_paint_with_bold() {
        let result = paint("hello", None, true, false, true);
        assert!(result.contains("1m") || result.contains(";1")); // Bold code
    }

    #[test]
    fn test_paint_disabled_returns_plain() {
        let result = paint("hello", Some(AnsiColor::Blue), true, true, false);
        assert_eq!(result, "hello");
    }

    #[test]
    fn test_stats_view_parse() {
        assert_eq!(parse_stats_view("provider"), Ok(StatsView::Provider));
        assert_eq!(parse_stats_view("domain"), Ok(StatsView::Domain));
        assert_eq!(parse_stats_view("port"), Ok(StatsView::Port));
        assert_eq!(parse_stats_view("process"), Ok(StatsView::Process));
        assert!(parse_stats_view("invalid").is_err());
    }

    #[test]
    fn test_provider_label() {
        assert_eq!(Provider::Anthropic.label(), "anthropic");
        assert_eq!(Provider::OpenAI.label(), "openai");
        assert_eq!(Provider::Google.label(), "google");
        assert_eq!(Provider::Unknown.label(), "unknown");
    }

    #[test]
    fn test_output_style_provider_color() {
        let style = OutputStyle {
            color: true,
            theme: Theme::Vivid,
        };
        assert_eq!(
            style.provider_color(Provider::Anthropic),
            Some(AnsiColor::Magenta)
        );
        assert_eq!(
            style.provider_color(Provider::OpenAI),
            Some(AnsiColor::BrightGreen)
        );
        assert_eq!(
            style.provider_color(Provider::Google),
            Some(AnsiColor::BrightBlue)
        );
        assert_eq!(
            style.provider_color(Provider::Unknown),
            Some(AnsiColor::BrightBlack)
        );
    }

    #[test]
    fn test_output_style_accent_color() {
        let style_color = OutputStyle {
            color: true,
            theme: Theme::Vivid,
        };
        let style_no_color = OutputStyle {
            color: false,
            theme: Theme::Vivid,
        };
        assert_eq!(style_color.accent(), Some(AnsiColor::BrightCyan));
        assert_eq!(style_no_color.accent(), None);
    }

    #[test]
    fn test_stats_default() {
        let stats = Stats::default();
        assert_eq!(stats.connects, 0);
        assert_eq!(stats.closes, 0);
        assert_eq!(stats.active, 0);
        assert_eq!(stats.peak_active, 0);
        assert!(stats.per_provider.is_empty());
        assert!(stats.per_domain.is_empty());
        assert!(stats.per_port.is_empty());
        assert!(stats.per_comm.is_empty());
    }

    #[test]
    fn test_stats_aggregation_per_provider() {
        let mut stats = Stats::default();

        // Simulate aggregating provider stats
        *stats.per_provider.entry(Provider::Anthropic).or_insert(0) += 1;
        *stats.per_provider.entry(Provider::Anthropic).or_insert(0) += 1;
        *stats.per_provider.entry(Provider::OpenAI).or_insert(0) += 1;

        assert_eq!(stats.per_provider.get(&Provider::Anthropic), Some(&2));
        assert_eq!(stats.per_provider.get(&Provider::OpenAI), Some(&1));
        assert_eq!(stats.per_provider.get(&Provider::Google), None);
    }

    #[test]
    fn test_stats_aggregation_per_domain() {
        let mut stats = Stats::default();

        *stats
            .per_domain
            .entry("api.anthropic.com".to_string())
            .or_insert(0) += 5;
        *stats
            .per_domain
            .entry("api.openai.com".to_string())
            .or_insert(0) += 3;
        *stats
            .per_domain
            .entry("api.anthropic.com".to_string())
            .or_insert(0) += 2;

        assert_eq!(stats.per_domain.get("api.anthropic.com"), Some(&7));
        assert_eq!(stats.per_domain.get("api.openai.com"), Some(&3));
    }

    #[test]
    fn test_stats_aggregation_per_port() {
        let mut stats = Stats::default();

        *stats.per_port.entry(443).or_insert(0) += 10;
        *stats.per_port.entry(80).or_insert(0) += 5;
        *stats.per_port.entry(443).or_insert(0) += 3;

        assert_eq!(stats.per_port.get(&443), Some(&13));
        assert_eq!(stats.per_port.get(&80), Some(&5));
    }

    #[test]
    fn test_stats_aggregation_per_comm() {
        let mut stats = Stats::default();

        *stats.per_comm.entry("claude-code".to_string()).or_insert(0) += 20;
        *stats.per_comm.entry("codex".to_string()).or_insert(0) += 10;

        let items = top_n_string(&stats.per_comm, 2);
        assert_eq!(items[0], ("claude-code".to_string(), 20));
        assert_eq!(items[1], ("codex".to_string(), 10));
    }

    #[test]
    fn test_ansi_color_codes() {
        assert_eq!(AnsiColor::Red.code(), "31");
        assert_eq!(AnsiColor::Green.code(), "32");
        assert_eq!(AnsiColor::BrightCyan.code(), "96");
        assert_eq!(AnsiColor::BrightBlack.code(), "90");
    }

    // Colorblind theme tests

    #[test]
    fn test_colorblind_theme_provider_symbols() {
        let style = OutputStyle {
            color: true,
            theme: Theme::Colorblind,
        };
        // Each provider should have a distinct symbol
        assert_eq!(style.provider_symbol(Provider::Anthropic), "●"); // Filled circle
        assert_eq!(style.provider_symbol(Provider::OpenAI), "◆"); // Diamond
        assert_eq!(style.provider_symbol(Provider::Google), "▲"); // Triangle
        assert_eq!(style.provider_symbol(Provider::Unknown), "○"); // Empty circle
    }

    #[test]
    fn test_colorblind_theme_bar_chars() {
        let style_colorblind = OutputStyle {
            color: true,
            theme: Theme::Colorblind,
        };
        let style_vivid = OutputStyle {
            color: true,
            theme: Theme::Vivid,
        };

        // Colorblind theme uses different fill chars per provider
        assert_eq!(style_colorblind.provider_bar_char(Provider::Anthropic), '█');
        assert_eq!(style_colorblind.provider_bar_char(Provider::OpenAI), '▓');
        assert_eq!(style_colorblind.provider_bar_char(Provider::Google), '▒');
        assert_eq!(style_colorblind.provider_bar_char(Provider::Unknown), '░');

        // Vivid theme uses same char for all providers
        assert_eq!(style_vivid.provider_bar_char(Provider::Anthropic), '█');
        assert_eq!(style_vivid.provider_bar_char(Provider::OpenAI), '█');
        assert_eq!(style_vivid.provider_bar_char(Provider::Google), '█');
        assert_eq!(style_vivid.provider_bar_char(Provider::Unknown), '█');
    }

    #[test]
    fn test_colorblind_theme_high_contrast_colors() {
        let style = OutputStyle {
            color: true,
            theme: Theme::Colorblind,
        };

        // Colorblind theme uses high-contrast colors (blue/yellow/white/gray)
        assert_eq!(
            style.provider_color(Provider::Anthropic),
            Some(AnsiColor::BrightBlue)
        );
        assert_eq!(
            style.provider_color(Provider::OpenAI),
            Some(AnsiColor::Yellow)
        );
        assert_eq!(
            style.provider_color(Provider::Google),
            Some(AnsiColor::White)
        );
        assert_eq!(
            style.provider_color(Provider::Unknown),
            Some(AnsiColor::BrightBlack)
        );
    }

    #[test]
    fn test_vivid_theme_provider_colors() {
        let style = OutputStyle {
            color: true,
            theme: Theme::Vivid,
        };

        // Vivid theme uses distinct saturated colors
        assert_eq!(
            style.provider_color(Provider::Anthropic),
            Some(AnsiColor::Magenta)
        );
        assert_eq!(
            style.provider_color(Provider::OpenAI),
            Some(AnsiColor::BrightGreen)
        );
        assert_eq!(
            style.provider_color(Provider::Google),
            Some(AnsiColor::BrightBlue)
        );
        assert_eq!(
            style.provider_color(Provider::Unknown),
            Some(AnsiColor::BrightBlack)
        );
    }

    #[test]
    fn test_mono_theme_no_colors() {
        let style = OutputStyle {
            color: true,
            theme: Theme::Mono,
        };

        // Mono theme returns None for all providers
        assert_eq!(style.provider_color(Provider::Anthropic), None);
        assert_eq!(style.provider_color(Provider::OpenAI), None);
        assert_eq!(style.provider_color(Provider::Google), None);
        assert_eq!(style.provider_color(Provider::Unknown), None);
    }

    #[test]
    fn test_parse_theme_colorblind() {
        assert!(matches!(parse_theme("colorblind"), Ok(Theme::Colorblind)));
        assert!(matches!(parse_theme("COLORBLIND"), Ok(Theme::Colorblind)));
        assert!(matches!(parse_theme("Colorblind"), Ok(Theme::Colorblind)));
    }

    #[test]
    fn test_parse_theme_all_values() {
        assert!(matches!(parse_theme("vivid"), Ok(Theme::Vivid)));
        assert!(matches!(parse_theme("mono"), Ok(Theme::Mono)));
        assert!(matches!(parse_theme("colorblind"), Ok(Theme::Colorblind)));
        assert!(parse_theme("invalid").is_err());
    }

    #[test]
    fn test_top_level_help_lists_all_subcommands() {
        let help = top_level_help_text();

        let usage_entries = [
            "rano report [options]",
            "rano export [options]",
            "rano diff --old <id> --new <id> [options]",
            "rano status [options]",
            "rano config <subcommand>",
            "rano update [options]",
        ];
        for usage in usage_entries {
            assert!(
                help.contains(usage),
                "top-level help missing usage entry: {}",
                usage
            );
        }

        let command_entries = ["report", "export", "diff", "status", "config", "update"];
        for command in command_entries {
            assert!(
                help.contains(&format!("\n  {}", command)),
                "top-level help missing command entry: {}",
                command
            );
        }
    }

    // Session diff tests

    #[test]
    fn test_diff_result_empty() {
        let result = DiffResult {
            new_domains: vec![],
            removed_domains: vec![],
            changed_domains: vec![],
            new_processes: vec![],
            removed_processes: vec![],
            provider_changes: HashMap::new(),
            old_run_id: "old-123".to_string(),
            new_run_id: "new-456".to_string(),
        };

        assert!(result.new_domains.is_empty());
        assert!(result.removed_domains.is_empty());
        assert!(result.changed_domains.is_empty());
        assert!(result.new_processes.is_empty());
        assert!(result.removed_processes.is_empty());
        assert!(result.provider_changes.is_empty());
    }

    #[test]
    fn test_diff_result_with_changes() {
        let mut provider_changes = HashMap::new();
        provider_changes.insert("anthropic".to_string(), (10, 20));
        provider_changes.insert("openai".to_string(), (5, 3));

        let result = DiffResult {
            new_domains: vec!["new.example.com".to_string()],
            removed_domains: vec!["old.example.com".to_string()],
            changed_domains: vec![("api.anthropic.com".to_string(), 100, 150)],
            new_processes: vec!["new-process".to_string()],
            removed_processes: vec!["old-process".to_string()],
            provider_changes,
            old_run_id: "session-a".to_string(),
            new_run_id: "session-b".to_string(),
        };

        assert_eq!(result.new_domains.len(), 1);
        assert_eq!(result.removed_domains.len(), 1);
        assert_eq!(result.changed_domains.len(), 1);
        assert_eq!(result.new_processes.len(), 1);
        assert_eq!(result.removed_processes.len(), 1);
        assert_eq!(result.provider_changes.len(), 2);

        // Verify provider changes
        assert_eq!(result.provider_changes.get("anthropic"), Some(&(10, 20)));
        assert_eq!(result.provider_changes.get("openai"), Some(&(5, 3)));

        // Verify changed domain tuple
        let (domain, old, new) = &result.changed_domains[0];
        assert_eq!(domain, "api.anthropic.com");
        assert_eq!(*old, 100);
        assert_eq!(*new, 150);
    }

    #[test]
    fn test_diff_result_run_ids() {
        let result = DiffResult {
            new_domains: vec![],
            removed_domains: vec![],
            changed_domains: vec![],
            new_processes: vec![],
            removed_processes: vec![],
            provider_changes: HashMap::new(),
            old_run_id: "1234-1705512345000".to_string(),
            new_run_id: "5678-1705598745000".to_string(),
        };

        assert_eq!(result.old_run_id, "1234-1705512345000");
        assert_eq!(result.new_run_id, "5678-1705598745000");
    }

    #[test]
    fn test_diff_args_default() {
        let args = DiffArgs::default();
        assert!(args.old_id.is_empty());
        assert!(args.new_id.is_empty());
        assert_eq!(args.sqlite_path, "observer.sqlite");
        assert!((args.threshold_pct - 50.0).abs() < f64::EPSILON);
        assert!(!args.json);
        assert_eq!(args.color, ColorMode::Auto);
    }

    #[test]
    fn test_parse_diff_args_flags() {
        let args = parse_diff_args(&[
            "--old".to_string(),
            "run-1".to_string(),
            "--new".to_string(),
            "run-2".to_string(),
            "--no-color".to_string(),
            "--threshold".to_string(),
            "25".to_string(),
            "--json".to_string(),
        ])
        .expect("should parse diff args");

        assert_eq!(args.old_id, "run-1");
        assert_eq!(args.new_id, "run-2");
        assert_eq!(args.color, ColorMode::Never);
        assert!((args.threshold_pct - 25.0).abs() < f64::EPSILON);
        assert!(args.json);
    }

    // Session name generation tests

    #[test]
    fn test_generate_session_name_format() {
        let patterns = vec!["claude".to_string()];
        let name = generate_session_name(&patterns, Provider::Anthropic);

        // Should be in format: {time}-{provider}-{pattern}-{date}
        let parts: Vec<&str> = name.split('-').collect();
        assert!(
            parts.len() >= 4,
            "Expected at least 4 parts separated by '-', got: {}",
            name
        );

        // First part should be time of day
        let time_parts = ["night", "morning", "afternoon", "evening"];
        assert!(
            time_parts.contains(&parts[0]),
            "Expected time of day (night/morning/afternoon/evening), got: {}",
            parts[0]
        );
    }

    #[test]
    fn test_generate_session_name_provider_labels() {
        let patterns = vec!["test".to_string()];

        let name_anthropic = generate_session_name(&patterns, Provider::Anthropic);
        assert!(
            name_anthropic.contains("-anthropic-"),
            "Anthropic should have 'anthropic' label"
        );

        let name_openai = generate_session_name(&patterns, Provider::OpenAI);
        assert!(
            name_openai.contains("-openai-"),
            "OpenAI should have 'openai' label"
        );

        let name_google = generate_session_name(&patterns, Provider::Google);
        assert!(
            name_google.contains("-google-"),
            "Google should have 'google' label"
        );

        let name_unknown = generate_session_name(&patterns, Provider::Unknown);
        assert!(
            name_unknown.contains("-mixed-"),
            "Unknown should have 'mixed' label"
        );
    }

    #[test]
    fn test_generate_session_name_pattern() {
        let patterns = vec!["MyApp".to_string()];
        let name = generate_session_name(&patterns, Provider::Anthropic);
        // Pattern should be lowercase
        assert!(name.contains("-myapp-"), "Pattern should be lowercased");
    }

    #[test]
    fn test_generate_session_name_default_pattern() {
        let patterns: Vec<String> = vec![];
        let name = generate_session_name(&patterns, Provider::Anthropic);
        assert!(
            name.contains("-default-"),
            "Empty patterns should use 'default'"
        );
    }

    #[test]
    fn test_generate_session_name_date_format() {
        let patterns = vec!["test".to_string()];
        let name = generate_session_name(&patterns, Provider::Anthropic);

        // Last part should be YYYY-MM-DD date format
        let parts: Vec<&str> = name.split('-').collect();
        let year_part = parts[parts.len() - 3];
        let month_part = parts[parts.len() - 2];
        let day_part = parts[parts.len() - 1];

        // Year should be 4 digits
        assert_eq!(year_part.len(), 4, "Year should be 4 digits");
        assert!(
            year_part.chars().all(|c| c.is_ascii_digit()),
            "Year should be all digits"
        );

        // Month should be 2 digits
        assert_eq!(month_part.len(), 2, "Month should be 2 digits");
        let month: u32 = month_part.parse().expect("Month should be numeric");
        assert!((1..=12).contains(&month), "Month should be 1-12");

        // Day should be 2 digits
        assert_eq!(day_part.len(), 2, "Day should be 2 digits");
        let day: u32 = day_part.parse().expect("Day should be numeric");
        assert!((1..=31).contains(&day), "Day should be 1-31");
    }

    // Status template expansion tests

    #[test]
    fn test_expand_status_template_basic() {
        let data = StatusData {
            active: 5,
            total: 100,
            anthropic: 50,
            openai: 30,
            google: 20,
            session_name: Some("morning-anthropic-claude-2026-01-21".to_string()),
            state: None,
        };

        let output = expand_status_template("{active} active | total:{total}", &data);
        assert_eq!(output, "5 active | total:100");
    }

    #[test]
    fn test_expand_status_template_providers() {
        let data = StatusData {
            active: 10,
            total: 50,
            anthropic: 25,
            openai: 15,
            google: 10,
            session_name: None,
            state: None,
        };

        let output = expand_status_template("A:{anthropic} O:{openai} G:{google}", &data);
        assert_eq!(output, "A:25 O:15 G:10");
    }

    #[test]
    fn test_expand_status_template_session_name() {
        let data = StatusData {
            active: 0,
            total: 0,
            anthropic: 0,
            openai: 0,
            google: 0,
            session_name: Some("my-session".to_string()),
            state: None,
        };

        let output = expand_status_template("session: {session_name}", &data);
        assert_eq!(output, "session: my-session");
    }

    #[test]
    fn test_expand_status_template_session_name_none() {
        let data = StatusData {
            active: 0,
            total: 0,
            anthropic: 0,
            openai: 0,
            google: 0,
            session_name: None,
            state: None,
        };

        let output = expand_status_template("session: {session_name}", &data);
        assert_eq!(output, "session: ");
    }

    #[test]
    fn test_expand_status_template_default_format() {
        let data = StatusData {
            active: 3,
            total: 10,
            anthropic: 5,
            openai: 3,
            google: 2,
            session_name: None,
            state: None,
        };

        let output = expand_status_template(STATUS_DEFAULT_FORMAT, &data);
        assert_eq!(output, "3 active | anthropic:5 openai:3");
    }

    #[test]
    fn test_status_data_default() {
        let data = StatusData::default();
        assert_eq!(data.active, 0);
        assert_eq!(data.total, 0);
        assert_eq!(data.anthropic, 0);
        assert_eq!(data.openai, 0);
        assert_eq!(data.google, 0);
        assert!(data.session_name.is_none());
    }

    #[test]
    fn test_status_args_default() {
        let args = StatusArgs::default();
        assert!(!args.one_line);
        assert!(args.format.is_none());
        assert_eq!(args.sqlite_path, "observer.sqlite");
    }

    #[test]
    fn test_parse_status_args_flags() {
        let args = parse_status_args(&[
            "--one-line".to_string(),
            "--format".to_string(),
            "{active} conns | {anthropic} anthropic".to_string(),
            "--sqlite".to_string(),
            "/tmp/test.sqlite".to_string(),
        ])
        .expect("should parse status args");

        assert!(args.one_line);
        assert_eq!(
            args.format.as_deref(),
            Some("{active} conns | {anthropic} anthropic")
        );
        assert_eq!(args.sqlite_path, "/tmp/test.sqlite");
    }

    #[test]
    fn pcap_cli_rejects_small_cache_max() {
        let err = load_monitor_args(&["--pcap-cache-max".to_string(), "50".to_string()])
            .expect_err("cache max below 100 must be rejected");
        assert!(err.contains("--pcap-cache-max"), "unexpected error: {err}");
    }

    #[test]
    fn pcap_cli_accepts_valid_knobs() {
        let args = load_monitor_args(&[
            "--pcap-cache-max".to_string(),
            "250".to_string(),
            "--pcap-interface".to_string(),
            "lo".to_string(),
        ])
        .expect("valid pcap knobs must parse");
        assert_eq!(args.pcap_cache_max, Some(250));
        assert_eq!(args.pcap_interface.as_deref(), Some("lo"));
    }

    #[test]
    fn pcap_cli_rejects_empty_interface() {
        let err = load_monitor_args(&["--pcap-interface".to_string(), String::new()])
            .expect_err("empty interface name must be rejected");
        assert!(
            err.contains("--pcap-interface must be a non-empty"),
            "unexpected error: {err}"
        );
    }

    #[cfg(feature = "pcap")]
    #[test]
    fn pcap_options_plumb_from_monitor_args() {
        let args = load_monitor_args(&[
            "--pcap-interface".to_string(),
            "eth9".to_string(),
            "--pcap-cache-max".to_string(),
            "1000".to_string(),
        ])
        .expect("valid knobs must parse");
        let opts = pcap_options_from_args(&args);
        assert_eq!(opts.interface.as_deref(), Some("eth9"));

        // Default stays None so the libpcap default device applies.
        assert!(
            pcap_options_from_args(&MonitorArgs::default())
                .interface
                .is_none()
        );
    }

    #[test]
    fn pcap_cache_with_max_entries_respects_cap() {
        let mut cache = pcap_capture::DomainCache::with_max_entries(120);
        for i in 0..150u32 {
            let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::from_bits(i));
            cache.apply_msg(pcap_capture::PcapMsg::DnsMapping {
                ip,
                hostname: format!("host{i}.example.com"),
                captured_at: SystemTime::now(),
                ttl_seconds: 300,
                offline: false,
            });
        }
        assert!(
            cache
                .lookup(
                    pcap_capture::FlowKey {
                        local_ip: "127.0.0.1".parse().unwrap(),
                        local_port: 12345,
                        remote_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::from_bits(149)),
                        remote_port: 0
                    },
                    1,
                    UNIX_EPOCH
                )
                .hostname
                .is_some(),
            "newest entry survives pruning"
        );
    }

    #[test]
    fn config_check_reports_invalid_override_path() {
        let file = NamedTempFile::new().expect("tempfile failed");
        std::fs::write(file.path(), "interval_ms=notanumber\n").expect("write failed");
        let code = run_config_check(&[
            "--config".to_string(),
            file.path().to_string_lossy().into_owned(),
        ]);
        assert_eq!(code, 1, "invalid override must exit nonzero");
    }

    #[test]
    fn config_check_accepts_valid_override_path() {
        let file = NamedTempFile::new().expect("tempfile failed");
        std::fs::write(file.path(), "interval_ms=1000\njson=true\n").expect("write failed");
        let code = run_config_check(&[
            "--config".to_string(),
            file.path().to_string_lossy().into_owned(),
        ]);
        assert_eq!(code, 0, "valid override must pass");
    }

    #[test]
    fn config_check_missing_override_path_is_error() {
        let missing = std::path::Path::new("/nonexistent/rano-test-does-not-exist.conf");
        assert_ne!(
            run_config_check(&[
                "--config".to_string(),
                missing.to_string_lossy().into_owned()
            ]),
            0
        );
    }

    #[test]
    fn parse_config_check_args_flags() {
        let args = parse_config_check_args(&[
            "--config".to_string(),
            "/tmp/a.conf".to_string(),
            "--config-toml".to_string(),
            "/tmp/b.toml".to_string(),
        ])
        .expect("flags should parse");
        match args.subcommand {
            ConfigSubcommand::Check { options } => {
                assert_eq!(
                    options,
                    ["--config", "/tmp/a.conf", "--config-toml", "/tmp/b.toml"]
                );
            }
            other => panic!("unexpected subcommand: {other:?}"),
        }

        assert!(parse_config_check_args(&["--bogus".to_string()]).is_err());
    }

    #[test]
    fn test_parse_config_args_subcommands() {
        let args_show = parse_config_args(&["show".to_string(), "--json".to_string()])
            .expect("should parse show --json");
        assert_eq!(
            args_show.subcommand,
            ConfigSubcommand::Show {
                json: true,
                options: Vec::new()
            }
        );

        let args_paths = parse_config_args(&["paths".to_string()]).expect("should parse paths");
        assert_eq!(args_paths.subcommand, ConfigSubcommand::Paths);

        let err_show = parse_config_args(&["show".to_string(), "--unknown".to_string()]);
        assert!(err_show.is_err());

        let err_paths = parse_config_args(&["paths".to_string(), "extra".to_string()]);
        assert!(err_paths.is_err());

        let err_sub = parse_config_args(&["unknown-cmd".to_string()]);
        assert!(err_sub.is_err());
    }

    #[test]
    fn redact_secrets_masks_credentials_but_not_normal_args() {
        let cases: &[(&str, &str)] = &[
            // env-prefix style assignments
            (
                "ANTHROPIC_API_KEY=sk-ant-api03-abcdef claude --model opus",
                "ANTHROPIC_API_KEY=<redacted> claude --model opus",
            ),
            // secret flag with separate value
            (
                "codex --api-key sk-proj-0123456789abcdefghij serve",
                "codex --api-key <redacted> serve",
            ),
            // --flag=value form
            (
                "tool --token=ghp_0123456789abcdefghijklmnopqrstuvwxyz run",
                "tool --token=<redacted> run",
            ),
            // JWT-shaped bearer token
            (
                "curl -H eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJVadQssw5c api",
                "curl -H <redacted> api",
            ),
            // ordinary argv must survive untouched
            (
                "claude --model opus --verbose",
                "claude --model opus --verbose",
            ),
            ("codex serve --port 8080", "codex serve --port 8080"),
        ];
        for (input, expected) in cases {
            let argv: Vec<_> = input.split_whitespace().collect();
            assert_eq!(&redact_argv(&argv, RedactMode::Secrets), expected);
        }
    }

    #[test]
    fn redact_all_replaces_whole_cmdline() {
        assert_eq!(
            redact_argv(&["claude", "--model", "opus"], RedactMode::All),
            "<redacted:3 args>"
        );
    }

    #[test]
    fn argv_boundaries_preserve_empty_and_non_utf8_arguments() {
        let argv = decode_argv(b"claude\0\0--password\0FAKE WORDS\nCREDENTIAL\xff\0");
        assert_eq!(argv.len(), 4);
        assert_eq!(argv[1], "");
        assert!(argv[3].ends_with('\u{fffd}'));
        assert_eq!(
            redact_argv(&argv, RedactMode::Secrets),
            "claude  --password <redacted>"
        );
        assert_eq!(redact_argv(&argv, RedactMode::All), "<redacted:4 args>");
        assert_eq!(redact_argv(&argv, RedactMode::Off), argv.join(" "));
        assert!(decode_argv(b"").is_empty());
        assert_eq!(decode_argv(b"\0"), [""]);
        assert_eq!(decode_argv(b"claude\0\0"), ["claude", ""]);
    }

    #[test]
    fn secrets_mask_complete_values_without_changing_benign_arguments() {
        let argv = [
            "claude",
            "--password",
            "FAKE WORDS\n雪 CREDENTIAL",
            "--model",
            "two words",
            "API_KEY=FAKE WORDS VALUE",
            "--token=FAKE WORDS VALUE",
            "",
        ];
        assert_eq!(
            redact_argv(&argv, RedactMode::Secrets),
            "claude --password <redacted> --model two words API_KEY=<redacted> --token=<redacted> "
        );
        assert_eq!(redact_argv(&argv, RedactMode::All), "<redacted:8 args>");
        assert_eq!(redact_argv::<&str>(&[], RedactMode::Secrets), "");
        assert_eq!(
            redact_argv(&["--password"], RedactMode::Secrets),
            "--password"
        );
    }

    #[test]
    fn redacted_session_metadata_does_not_reintroduce_pattern_credentials() {
        let fake = "sk-ant-api03-FAKE0123456789abcdef";
        let args = MonitorArgs {
            patterns: vec![fake.to_string()],
            redact_cmdline: RedactMode::Secrets,
            ..MonitorArgs::default()
        };
        let ctx = RunContext::new(&args, "ptr", None);
        assert_eq!(ctx.patterns, REDACTED_PLACEHOLDER);
        assert!(!ctx.session_name.contains(fake));
        let all = RunContext::new(
            &MonitorArgs {
                redact_cmdline: RedactMode::All,
                ..args
            },
            "ptr",
            None,
        );
        assert_eq!(all.patterns, "<redacted:1 patterns>");
        assert_eq!(all.session_name, REDACTED_PLACEHOLDER);
        assert!(all.args_snapshot.starts_with("<redacted:"));
    }

    #[test]
    fn redact_off_is_identity() {
        let raw = "ANTHROPIC_API_KEY=sk-123 claude";
        assert_eq!(
            redact_argv(&["ANTHROPIC_API_KEY=sk-123", "claude"], RedactMode::Off),
            raw
        );
    }

    #[test]
    fn provider_classification_uses_original_cmdline_before_redaction() {
        let raw = "ANTHROPIC_API_KEY=sk-ant-api03-secret claude --model opus";
        let matcher = ProviderMatcher::default();
        assert_eq!(
            provider_from_text("claude", raw, &matcher),
            Provider::Anthropic,
            "attribution must classify on the original argv"
        );

        let masked = redact_argv(
            &raw.split_whitespace().collect::<Vec<_>>(),
            RedactMode::Secrets,
        );
        assert!(masked.contains("<redacted>"));
        assert!(masked.contains("claude"));
    }

    #[test]
    fn test_load_monitor_args_extended_flags() {
        let args = load_monitor_args(&[
            "--no-config".to_string(),
            "--no-udp".to_string(),
            "--include-listening".to_string(),
            "--show-ancestry".to_string(),
            "--stats-top".to_string(),
            "7".to_string(),
            "--stats-view".to_string(),
            "domain".to_string(),
            "--stats-width".to_string(),
            "65".to_string(),
            "--stats-cycle-ms".to_string(),
            "3500".to_string(),
        ])
        .expect("should parse flags");

        assert!(!args.include_udp);
        assert!(args.include_listening);
        assert!(args.show_ancestry);
        assert_eq!(args.stats_top, 7);
        assert_eq!(args.stats_views, vec![StatsView::Domain]);
        assert_eq!(args.stats_width, 65);
        assert!(args.stats_width_set);
        assert_eq!(args.stats_cycle_ms, 3500);

        // Missing value errors
        assert!(load_monitor_args(&["--config".to_string()]).is_err());
        assert!(load_monitor_args(&["--config-toml".to_string()]).is_err());
        assert!(load_monitor_args(&["--preset".to_string()]).is_err());
    }

    #[test]
    fn test_parse_report_args_flags() {
        let args = parse_report_args(&[
            "--sqlite".to_string(),
            "/tmp/custom-report.sqlite".to_string(),
            "--latest".to_string(),
            "--since".to_string(),
            "2026-01-01".to_string(),
            "--until".to_string(),
            "2026-01-02".to_string(),
            "--json".to_string(),
            "--top".to_string(),
            "15".to_string(),
            "--no-color".to_string(),
        ])
        .expect("should parse report args");

        assert_eq!(args.sqlite_path, "/tmp/custom-report.sqlite");
        assert!(args.latest);
        assert_eq!(args.since.as_deref(), Some("2026-01-01"));
        assert_eq!(args.until.as_deref(), Some("2026-01-02"));
        assert!(args.json);
        assert_eq!(args.top, 15);
        assert_eq!(args.color, ColorMode::Never);

        // Mutually exclusive latest and run-id
        let err = parse_report_args(&[
            "--latest".to_string(),
            "--run-id".to_string(),
            "run-123".to_string(),
        ])
        .expect_err("should reject mutually exclusive latest and run-id");
        assert!(err.contains("mutually exclusive"));
    }

    #[test]
    fn test_parse_export_args_flags() {
        let args = parse_export_args(&[
            "--format".to_string(),
            "csv".to_string(),
            "--sqlite".to_string(),
            "/tmp/custom-export.sqlite".to_string(),
            "--since".to_string(),
            "1h".to_string(),
            "--until".to_string(),
            "now".to_string(),
            "--run-id".to_string(),
            "run-abc".to_string(),
            "--provider".to_string(),
            "anthropic".to_string(),
            "--provider".to_string(),
            "openai".to_string(),
            "--domain".to_string(),
            "*.anthropic.com".to_string(),
            "--fields".to_string(),
            "ts,provider,domain".to_string(),
            "--no-header".to_string(),
            "-o".to_string(),
            "/tmp/out.csv".to_string(),
        ])
        .expect("should parse export args");

        assert_eq!(args.format, ExportFormat::Csv);
        assert_eq!(args.sqlite_path, "/tmp/custom-export.sqlite");
        assert_eq!(args.since.as_deref(), Some("1h"));
        assert_eq!(args.until.as_deref(), Some("now"));
        assert_eq!(args.run_id.as_deref(), Some("run-abc"));
        assert_eq!(args.providers, vec!["anthropic", "openai"]);
        assert_eq!(args.domain_patterns, vec!["*.anthropic.com"]);
        assert_eq!(
            args.fields.as_deref(),
            Some(
                &[
                    "ts".to_string(),
                    "provider".to_string(),
                    "domain".to_string()
                ][..]
            )
        );
        assert!(args.no_header);
        assert_eq!(args.output, Some(PathBuf::from("/tmp/out.csv")));

        // Missing format error
        let err = parse_export_args(&["--sqlite".to_string(), "test.sqlite".to_string()])
            .expect_err("should require --format");
        assert!(err.contains("--format is required"));
    }

    #[test]
    fn test_parse_update_args_flags() {
        let cmd = parse_update_args(&[
            "--version".to_string(),
            "v0.3.0".to_string(),
            "--system".to_string(),
            "--easy-mode".to_string(),
            "--dest".to_string(),
            "/custom/bin".to_string(),
            "--from-source".to_string(),
            "--verify".to_string(),
            "--quiet".to_string(),
            "--no-gum".to_string(),
            "--owner".to_string(),
            "custom-owner".to_string(),
            "--repo".to_string(),
            "custom-repo".to_string(),
            "--branch".to_string(),
            "main".to_string(),
        ])
        .expect("should parse update args");

        assert_eq!(cmd.version.as_deref(), Some("v0.3.0"));
        assert!(cmd.system);
        assert!(cmd.easy_mode);
        assert_eq!(cmd.dest, Some(PathBuf::from("/custom/bin")));
        assert!(cmd.from_source);
        assert!(cmd.verify);
        assert!(cmd.quiet);
        assert!(cmd.no_gum);
        assert_eq!(cmd.owner.as_deref(), Some("custom-owner"));
        assert_eq!(cmd.repo.as_deref(), Some("custom-repo"));
        assert_eq!(cmd.branch.as_deref(), Some("main"));
    }
}
