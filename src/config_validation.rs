//! Configuration validation module for rano.
//!
//! Provides comprehensive validation of configuration files before runtime:
//! - Key-value config files (config.conf)
//! - TOML provider configuration (rano.toml)
//! - Path validation (log directories, SQLite paths)
//! - Pattern validation (glob/regex compilation)

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

/// Known keys for key-value config files (config.conf format).
/// These are the valid keys that can appear in configuration files.
pub const KNOWN_CONFIG_KEYS: &[&str] = &[
    "pattern",
    "exclude_pattern",
    "pid",
    "no_descendants",
    "interval_ms",
    "json",
    "summary_only",
    "domain_mode",
    "pcap",
    "no_dns",
    "include_udp",
    "include_listening",
    "show_ancestry",
    "log_file",
    "log_dir",
    "log_format",
    "once",
    "color",
    "sqlite",
    "no_sqlite",
    "db_batch_size",
    "db_flush_ms",
    "db_queue_max",
    "stats_interval_ms",
    "stats_width",
    "stats_top",
    "stats_view",
    "stats_cycle_ms",
    "no_banner",
    "theme",
    "alert_domain",
    "alert_max_connections",
    "alert_max_per_provider",
    "alert_duration_ms",
    "alert_unknown_domain",
    "alert_bell",
    "alert_cooldown_ms",
    "no_alerts",
];

/// Valid values for enum-like configuration options.
pub const VALID_DOMAIN_MODES: &[&str] = &["auto", "ptr", "pcap"];
pub const VALID_LOG_FORMATS: &[&str] = &["auto", "pretty", "json"];
pub const VALID_COLOR_MODES: &[&str] = &["auto", "always", "never"];
pub const VALID_THEMES: &[&str] = &["vivid", "mono"];
pub const VALID_STATS_VIEWS: &[&str] = &["provider", "domain", "port", "process"];
pub const VALID_PROVIDER_MODES: &[&str] = &["merge", "replace"];

/// Represents a single configuration error.
#[derive(Debug, Clone)]
pub struct ConfigError {
    pub file: PathBuf,
    pub line: Option<usize>,
    pub message: String,
}

impl ConfigError {
    pub fn new(file: impl Into<PathBuf>, line: Option<usize>, message: impl Into<String>) -> Self {
        Self {
            file: file.into(),
            line,
            message: message.into(),
        }
    }
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.line {
            Some(line) => write!(f, "{}:{}: {}", self.file.display(), line, self.message),
            None => write!(f, "{}: {}", self.file.display(), self.message),
        }
    }
}

/// Represents a single configuration warning.
#[derive(Debug, Clone)]
pub struct ConfigWarning {
    pub file: PathBuf,
    pub line: Option<usize>,
    pub message: String,
}

impl ConfigWarning {
    pub fn new(file: impl Into<PathBuf>, line: Option<usize>, message: impl Into<String>) -> Self {
        Self {
            file: file.into(),
            line,
            message: message.into(),
        }
    }
}

impl std::fmt::Display for ConfigWarning {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.line {
            Some(line) => write!(f, "{}:{}: {}", self.file.display(), line, self.message),
            None => write!(f, "{}: {}", self.file.display(), self.message),
        }
    }
}

/// The result of validating configuration files.
#[derive(Debug, Default)]
pub struct ValidationResult {
    pub errors: Vec<ConfigError>,
    pub warnings: Vec<ConfigWarning>,
}

impl ValidationResult {
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns true if there are no errors.
    pub fn is_valid(&self) -> bool {
        self.errors.is_empty()
    }

    /// Returns true if there are warnings but no errors.
    pub fn has_warnings(&self) -> bool {
        !self.warnings.is_empty() && self.errors.is_empty()
    }

    /// Merge another ValidationResult into this one.
    pub fn merge(&mut self, other: ValidationResult) {
        self.errors.extend(other.errors);
        self.warnings.extend(other.warnings);
    }

    fn add_error(&mut self, file: impl Into<PathBuf>, line: Option<usize>, message: impl Into<String>) {
        self.errors.push(ConfigError::new(file, line, message));
    }

    fn add_warning(&mut self, file: impl Into<PathBuf>, line: Option<usize>, message: impl Into<String>) {
        self.warnings.push(ConfigWarning::new(file, line, message));
    }
}

/// Main entry point for validating a key-value config file.
pub fn validate_config_file(path: &Path) -> ValidationResult {
    let mut result = ValidationResult::new();

    // Check file exists
    if !path.exists() {
        result.add_error(path, None, "file not found");
        return result;
    }

    // Read file contents
    let contents = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => {
            result.add_error(path, None, format!("failed to read file: {}", e));
            return result;
        }
    };

    // Parse and validate each line
    let known_keys: HashSet<&str> = KNOWN_CONFIG_KEYS.iter().copied().collect();

    for (idx, line) in contents.lines().enumerate() {
        let line_num = idx + 1;
        let raw = line.split('#').next().unwrap_or("").trim();

        if raw.is_empty() {
            continue;
        }

        // Parse key=value
        let mut parts = raw.splitn(2, '=');
        let key = parts.next().unwrap_or("").trim();
        let value = parts.next().map(|v| v.trim());

        if key.is_empty() {
            continue;
        }

        // Check for missing value
        if value.is_none() || value.unwrap().is_empty() {
            result.add_error(path, Some(line_num), format!("missing value for key '{}'", key));
            continue;
        }

        let value = value.unwrap();

        // Check for unknown keys
        if !known_keys.contains(key) {
            result.add_warning(
                path,
                Some(line_num),
                format!("unknown key '{}' (possible typo?)", key),
            );
            continue;
        }

        // Validate value types based on key
        validate_config_value(path, line_num, key, value, &mut result);
    }

    result
}

/// Validate a single config value based on its key.
fn validate_config_value(
    path: &Path,
    line: usize,
    key: &str,
    value: &str,
    result: &mut ValidationResult,
) {
    match key {
        // Boolean values
        "no_descendants" | "json" | "summary_only" | "pcap" | "no_dns" | "include_udp"
        | "include_listening" | "show_ancestry" | "once" | "no_sqlite" | "no_banner"
        | "alert_unknown_domain" | "alert_bell" | "no_alerts" => {
            if !is_valid_bool(value) {
                result.add_error(
                    path,
                    Some(line),
                    format!("'{}' must be a boolean (true/false/yes/no/1/0), got '{}'", key, value),
                );
            }
        }

        // Positive integer values
        "pid" => {
            if value.parse::<u32>().is_err() {
                result.add_error(
                    path,
                    Some(line),
                    format!("'{}' must be a valid process ID (positive integer), got '{}'", key, value),
                );
            }
        }

        // Positive u64 values
        "interval_ms" | "db_flush_ms" | "stats_interval_ms" | "stats_cycle_ms"
        | "alert_cooldown_ms" => {
            if value.parse::<u64>().is_err() {
                result.add_error(
                    path,
                    Some(line),
                    format!("'{}' must be a non-negative integer, got '{}'", key, value),
                );
            }
        }

        // Positive u64 values that must be >= 1
        "alert_max_connections" | "alert_max_per_provider" | "alert_duration_ms" => {
            match value.parse::<u64>() {
                Ok(0) => {
                    result.add_error(
                        path,
                        Some(line),
                        format!("'{}' must be >= 1, got 0", key),
                    );
                }
                Err(_) => {
                    result.add_error(
                        path,
                        Some(line),
                        format!("'{}' must be a positive integer, got '{}'", key, value),
                    );
                }
                Ok(_) => {}
            }
        }

        // Positive usize values that must be >= 1
        "db_batch_size" | "db_queue_max" => {
            match value.parse::<usize>() {
                Ok(0) => {
                    result.add_error(
                        path,
                        Some(line),
                        format!("'{}' must be >= 1, got 0", key),
                    );
                }
                Err(_) => {
                    result.add_error(
                        path,
                        Some(line),
                        format!("'{}' must be a positive integer, got '{}'", key, value),
                    );
                }
                Ok(_) => {}
            }
        }

        // Non-negative usize values
        "stats_width" | "stats_top" => {
            if value.parse::<usize>().is_err() {
                result.add_error(
                    path,
                    Some(line),
                    format!("'{}' must be a non-negative integer, got '{}'", key, value),
                );
            }
        }

        // Enum values
        "domain_mode" => {
            if !VALID_DOMAIN_MODES.contains(&value.to_lowercase().as_str()) {
                result.add_error(
                    path,
                    Some(line),
                    format!(
                        "'{}' must be one of [{}], got '{}'",
                        key,
                        VALID_DOMAIN_MODES.join(", "),
                        value
                    ),
                );
            }
        }

        "log_format" => {
            if !VALID_LOG_FORMATS.contains(&value.to_lowercase().as_str()) {
                result.add_error(
                    path,
                    Some(line),
                    format!(
                        "'{}' must be one of [{}], got '{}'",
                        key,
                        VALID_LOG_FORMATS.join(", "),
                        value
                    ),
                );
            }
        }

        "color" => {
            if !VALID_COLOR_MODES.contains(&value.to_lowercase().as_str()) {
                result.add_error(
                    path,
                    Some(line),
                    format!(
                        "'{}' must be one of [{}], got '{}'",
                        key,
                        VALID_COLOR_MODES.join(", "),
                        value
                    ),
                );
            }
        }

        "theme" => {
            if !VALID_THEMES.contains(&value.to_lowercase().as_str()) {
                result.add_error(
                    path,
                    Some(line),
                    format!(
                        "'{}' must be one of [{}], got '{}'",
                        key,
                        VALID_THEMES.join(", "),
                        value
                    ),
                );
            }
        }

        "stats_view" => {
            // stats_view can be comma-separated
            for part in value.split(',') {
                let trimmed = part.trim().to_lowercase();
                if !trimmed.is_empty() && !VALID_STATS_VIEWS.contains(&trimmed.as_str()) {
                    result.add_error(
                        path,
                        Some(line),
                        format!(
                            "'stats_view' contains invalid value '{}' (valid: [{}])",
                            part.trim(),
                            VALID_STATS_VIEWS.join(", ")
                        ),
                    );
                }
            }
        }

        // Path values - just check they're not empty
        "log_file" | "log_dir" | "sqlite" => {
            if value.is_empty() {
                result.add_error(path, Some(line), format!("'{}' cannot be empty", key));
            }
        }

        // String/pattern values - no validation needed for syntax
        "pattern" | "exclude_pattern" | "alert_domain" => {
            // These are string values that allow comma-separated lists
            // We could validate glob patterns here in the future
        }

        _ => {
            // Should not reach here if KNOWN_CONFIG_KEYS is complete
        }
    }
}

/// Check if a value is a valid boolean representation.
fn is_valid_bool(value: &str) -> bool {
    matches!(
        value.to_lowercase().as_str(),
        "true" | "false" | "1" | "0" | "yes" | "no" | "on" | "off"
    )
}

/// Validate a TOML provider configuration file.
pub fn validate_toml_config(path: &Path) -> ValidationResult {
    let mut result = ValidationResult::new();

    // Check file exists
    if !path.exists() {
        result.add_error(path, None, "file not found");
        return result;
    }

    // Read file contents
    let contents = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => {
            result.add_error(path, None, format!("failed to read file: {}", e));
            return result;
        }
    };

    // Parse as TOML
    let parsed: toml::Value = match toml::from_str(&contents) {
        Ok(v) => v,
        Err(e) => {
            // Try to extract line number from TOML error
            let msg = e.to_string();
            result.add_error(path, None, format!("TOML parse error: {}", msg));
            return result;
        }
    };

    // Validate structure
    let table = match parsed.as_table() {
        Some(t) => t,
        None => {
            result.add_error(path, None, "TOML root must be a table");
            return result;
        }
    };

    // Check for unknown top-level keys
    for key in table.keys() {
        if key != "providers" {
            result.add_warning(
                path,
                None,
                format!("unknown top-level key '{}' (only 'providers' is supported)", key),
            );
        }
    }

    // Validate [providers] section if present
    if let Some(providers) = table.get("providers") {
        validate_providers_section(path, providers, &mut result);
    }

    result
}

/// Validate the [providers] section of a TOML config.
fn validate_providers_section(path: &Path, providers: &toml::Value, result: &mut ValidationResult) {
    let table = match providers.as_table() {
        Some(t) => t,
        None => {
            result.add_error(path, None, "[providers] must be a table");
            return;
        }
    };

    let valid_provider_keys: HashSet<&str> = ["mode", "anthropic", "openai", "google"]
        .iter()
        .copied()
        .collect();

    for (key, value) in table {
        if !valid_provider_keys.contains(key.as_str()) {
            result.add_warning(
                path,
                None,
                format!(
                    "unknown key '{}' in [providers] (valid: mode, anthropic, openai, google)",
                    key
                ),
            );
            continue;
        }

        match key.as_str() {
            "mode" => {
                if let Some(mode_str) = value.as_str() {
                    if !VALID_PROVIDER_MODES.contains(&mode_str.to_lowercase().as_str()) {
                        result.add_error(
                            path,
                            None,
                            format!(
                                "providers.mode must be one of [{}], got '{}'",
                                VALID_PROVIDER_MODES.join(", "),
                                mode_str
                            ),
                        );
                    }
                } else {
                    result.add_error(path, None, "providers.mode must be a string");
                }
            }
            "anthropic" | "openai" | "google" => {
                if let Some(arr) = value.as_array() {
                    for (idx, item) in arr.iter().enumerate() {
                        if item.as_str().is_none() {
                            result.add_error(
                                path,
                                None,
                                format!("providers.{}[{}] must be a string", key, idx),
                            );
                        }
                    }
                } else {
                    result.add_error(
                        path,
                        None,
                        format!("providers.{} must be an array of strings", key),
                    );
                }
            }
            _ => {}
        }
    }
}

/// Validate that referenced paths exist or can be created.
pub fn validate_paths(
    log_dir: Option<&Path>,
    log_file: Option<&Path>,
    sqlite_path: Option<&Path>,
) -> ValidationResult {
    let mut result = ValidationResult::new();

    // Validate log_dir
    if let Some(dir) = log_dir {
        if dir.exists() {
            if !dir.is_dir() {
                result.add_error(
                    dir,
                    None,
                    "log_dir exists but is not a directory",
                );
            }
        } else {
            // Check if parent exists (directory can be created)
            if let Some(parent) = dir.parent() {
                if !parent.exists() {
                    result.add_warning(
                        dir,
                        None,
                        format!("log_dir parent '{}' does not exist (will be created)", parent.display()),
                    );
                }
            }
        }
    }

    // Validate log_file
    if let Some(file) = log_file {
        if let Some(parent) = file.parent() {
            if !parent.as_os_str().is_empty() && !parent.exists() {
                result.add_error(
                    file,
                    None,
                    format!("log_file parent directory '{}' does not exist", parent.display()),
                );
            }
        }
    }

    // Validate sqlite_path
    if let Some(db_path) = sqlite_path {
        if let Some(parent) = db_path.parent() {
            if !parent.as_os_str().is_empty() && !parent.exists() {
                result.add_error(
                    db_path,
                    None,
                    format!("sqlite parent directory '{}' does not exist", parent.display()),
                );
            }
        }
    }

    result
}

/// Validate glob/pattern syntax.
/// Returns warnings for patterns that might not work as expected.
pub fn validate_patterns(patterns: &[String], pattern_type: &str) -> ValidationResult {
    let mut result = ValidationResult::new();

    for pattern in patterns {
        // Check for common mistakes
        if pattern.is_empty() {
            result.add_warning(
                PathBuf::from("<patterns>"),
                None,
                format!("{}: empty pattern will match nothing", pattern_type),
            );
            continue;
        }

        // Check for unescaped regex special chars that might be mistakes
        if pattern.contains(".*") && !pattern.contains("\\.*") {
            // This is likely intentional for glob patterns
        }

        // Check for patterns that look like paths but might be intended as globs
        if pattern.starts_with('/') && !pattern.contains('*') && !pattern.contains('?') {
            result.add_warning(
                PathBuf::from("<patterns>"),
                None,
                format!(
                    "{}: pattern '{}' looks like a path but contains no wildcards",
                    pattern_type, pattern
                ),
            );
        }
    }

    result
}

/// ConfigValidator provides a unified interface for validating all configuration.
#[derive(Debug, Default)]
pub struct ConfigValidator {
    pub errors: Vec<ConfigError>,
    pub warnings: Vec<ConfigWarning>,
}

impl ConfigValidator {
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns true if there are no errors.
    pub fn is_valid(&self) -> bool {
        self.errors.is_empty()
    }

    /// Returns true if there are warnings but no errors.
    pub fn has_warnings(&self) -> bool {
        !self.warnings.is_empty() && self.errors.is_empty()
    }

    /// Validate a key-value config file.
    pub fn validate_config_file(&mut self, path: &Path) {
        let result = validate_config_file(path);
        self.errors.extend(result.errors);
        self.warnings.extend(result.warnings);
    }

    /// Validate a TOML provider config file.
    pub fn validate_toml_config(&mut self, path: &Path) {
        let result = validate_toml_config(path);
        self.errors.extend(result.errors);
        self.warnings.extend(result.warnings);
    }

    /// Validate paths referenced in configuration.
    pub fn validate_paths(
        &mut self,
        log_dir: Option<&Path>,
        log_file: Option<&Path>,
        sqlite_path: Option<&Path>,
    ) {
        let result = validate_paths(log_dir, log_file, sqlite_path);
        self.errors.extend(result.errors);
        self.warnings.extend(result.warnings);
    }

    /// Validate patterns/globs.
    pub fn validate_patterns(&mut self, patterns: &[String], pattern_type: &str) {
        let result = validate_patterns(patterns, pattern_type);
        self.errors.extend(result.errors);
        self.warnings.extend(result.warnings);
    }

    /// Get a summary suitable for display.
    pub fn summary(&self) -> String {
        let mut lines = Vec::new();

        if self.errors.is_empty() && self.warnings.is_empty() {
            lines.push("Configuration is valid.".to_string());
        } else {
            if !self.errors.is_empty() {
                lines.push(format!("{} error(s) found:", self.errors.len()));
                for err in &self.errors {
                    lines.push(format!("  ✗ {}", err));
                }
            }
            if !self.warnings.is_empty() {
                lines.push(format!("{} warning(s) found:", self.warnings.len()));
                for warn in &self.warnings {
                    lines.push(format!("  ⚠ {}", warn));
                }
            }
        }

        lines.join("\n")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn write_temp_file(content: &str) -> NamedTempFile {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(content.as_bytes()).unwrap();
        file
    }

    #[test]
    fn test_validate_config_file_valid() {
        let file = write_temp_file(
            r#"
# Comment line
pattern=claude,codex
interval_ms=1000
json=true
no_banner=false
"#,
        );
        let result = validate_config_file(file.path());
        assert!(result.is_valid(), "Expected valid, got errors: {:?}", result.errors);
        assert!(result.warnings.is_empty());
    }

    #[test]
    fn test_validate_config_file_unknown_key() {
        let file = write_temp_file("unknown_key=value\n");
        let result = validate_config_file(file.path());
        assert!(result.is_valid()); // Warnings don't make it invalid
        assert_eq!(result.warnings.len(), 1);
        assert!(result.warnings[0].message.contains("unknown key"));
    }

    #[test]
    fn test_validate_config_file_missing_value() {
        let file = write_temp_file("pattern=\n");
        let result = validate_config_file(file.path());
        assert!(!result.is_valid());
        assert!(result.errors[0].message.contains("missing value"));
    }

    #[test]
    fn test_validate_config_file_invalid_bool() {
        let file = write_temp_file("json=maybe\n");
        let result = validate_config_file(file.path());
        assert!(!result.is_valid());
        assert!(result.errors[0].message.contains("boolean"));
    }

    #[test]
    fn test_validate_config_file_invalid_number() {
        let file = write_temp_file("interval_ms=abc\n");
        let result = validate_config_file(file.path());
        assert!(!result.is_valid());
        assert!(result.errors[0].message.contains("integer"));
    }

    #[test]
    fn test_validate_config_file_invalid_enum() {
        let file = write_temp_file("domain_mode=invalid\n");
        let result = validate_config_file(file.path());
        assert!(!result.is_valid());
        assert!(result.errors[0].message.contains("auto, ptr, pcap"));
    }

    #[test]
    fn test_validate_config_file_zero_not_allowed() {
        let file = write_temp_file("db_batch_size=0\n");
        let result = validate_config_file(file.path());
        assert!(!result.is_valid());
        assert!(result.errors[0].message.contains("must be >= 1"));
    }

    #[test]
    fn test_validate_toml_config_valid() {
        let file = write_temp_file(
            r#"
[providers]
mode = "merge"
anthropic = ["claude", "acme-claude"]
openai = ["codex"]
"#,
        );
        let result = validate_toml_config(file.path());
        assert!(result.is_valid(), "Expected valid, got errors: {:?}", result.errors);
    }

    #[test]
    fn test_validate_toml_config_invalid_mode() {
        let file = write_temp_file(
            r#"
[providers]
mode = "invalid"
"#,
        );
        let result = validate_toml_config(file.path());
        assert!(!result.is_valid());
        assert!(result.errors[0].message.contains("merge, replace"));
    }

    #[test]
    fn test_validate_toml_config_invalid_pattern_type() {
        let file = write_temp_file(
            r#"
[providers]
anthropic = "not-an-array"
"#,
        );
        let result = validate_toml_config(file.path());
        assert!(!result.is_valid());
        assert!(result.errors[0].message.contains("array"));
    }

    #[test]
    fn test_validate_toml_config_unknown_key() {
        let file = write_temp_file(
            r#"
[providers]
unknown_provider = ["test"]
"#,
        );
        let result = validate_toml_config(file.path());
        assert!(result.is_valid()); // Warnings don't make it invalid
        assert!(!result.warnings.is_empty());
    }

    #[test]
    fn test_validate_toml_config_parse_error() {
        let file = write_temp_file("invalid toml {{{\n");
        let result = validate_toml_config(file.path());
        assert!(!result.is_valid());
        assert!(result.errors[0].message.contains("TOML parse error"));
    }

    #[test]
    fn test_validate_paths_missing_parent() {
        let result = validate_paths(
            None,
            Some(Path::new("/nonexistent/path/logfile.log")),
            None,
        );
        assert!(!result.is_valid());
        assert!(result.errors[0].message.contains("does not exist"));
    }

    #[test]
    fn test_config_validator_accumulates() {
        let mut validator = ConfigValidator::new();

        let file1 = write_temp_file("interval_ms=abc\n");
        let file2 = write_temp_file("json=maybe\n");

        validator.validate_config_file(file1.path());
        validator.validate_config_file(file2.path());

        assert_eq!(validator.errors.len(), 2);
    }

    #[test]
    fn test_is_valid_bool() {
        assert!(is_valid_bool("true"));
        assert!(is_valid_bool("false"));
        assert!(is_valid_bool("TRUE"));
        assert!(is_valid_bool("False"));
        assert!(is_valid_bool("1"));
        assert!(is_valid_bool("0"));
        assert!(is_valid_bool("yes"));
        assert!(is_valid_bool("no"));
        assert!(is_valid_bool("on"));
        assert!(is_valid_bool("off"));
        assert!(!is_valid_bool("maybe"));
        assert!(!is_valid_bool("2"));
        assert!(!is_valid_bool(""));
    }

    #[test]
    fn test_stats_view_validation() {
        let file = write_temp_file("stats_view=provider,domain,invalid\n");
        let result = validate_config_file(file.path());
        assert!(!result.is_valid());
        assert!(result.errors[0].message.contains("invalid value"));
    }
}
