//! Configuration mechanics for honeypot infrastructure.
//!
//! This module defines the **wiring** of your deception operation:
//! - WHERE things run (paths, instances)
//! - HOW things connect (I/O, logging)
//! - WHAT capabilities are enabled
//!
//! This does NOT define decision-making (see [`crate::policy`]).

use crate::defaults::*;
use crate::errors::{self, *};
use crate::tags::RootTag;
use crate::validation::ValidationMode;
use crate::CONFIG_VERSION;
use palisade_errors::Result;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Master configuration - the MECHANICS of your deception operation.
#[derive(Debug, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct Config {
    /// Configuration schema version
    #[serde(default = "default_version")]
    pub version: u32,

    /// Agent identity and runtime configuration
    pub agent: AgentConfig,

    /// Deception artifact configuration (contains secrets)
    pub deception: DeceptionConfig,

    /// Telemetry collection configuration
    pub telemetry: TelemetryConfig,

    /// Logging configuration
    pub logging: LoggingConfig,
}

/// Agent identity and runtime configuration.
#[derive(Debug, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct AgentConfig {
    /// Unique instance identifier (for correlation)
    #[serde(skip, default)]
    pub instance_id: ProtectedString,

    /// Working directory for agent state
    #[serde(skip, default)]
    pub work_dir: ProtectedPath,

    /// Optional environment label (dev, staging, prod)
    #[serde(default)]
    pub environment: Option<String>,

    /// Hostname for tag derivation (defaults to system hostname)
    #[serde(default)]
    pub hostname: Option<String>,

    // Serialization helpers (convert on load/save)
    #[serde(rename = "instance_id")]
    instance_id_raw: String,
    #[serde(rename = "work_dir")]
    work_dir_raw: String,
}

/// Deception artifact configuration.
#[derive(Debug, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct DeceptionConfig {
    /// Paths where decoy files will be placed (immutable after load)
    #[serde(default)]
    #[zeroize(skip)]
    pub decoy_paths: Box<[PathBuf]>,

    /// Types of credentials to generate (aws, ssh, etc.) (immutable after load)
    #[serde(deserialize_with = "deserialize_boxed_strings")]
    pub credential_types: Box<[String]>,

    /// Number of honeytokens to generate
    #[serde(default = "default_honeytoken_count")]
    pub honeytoken_count: usize,

    /// Root cryptographic tag for tag derivation hierarchy
    pub root_tag: RootTag,

    /// Unix permissions for created artifacts (octal)
    #[serde(default = "default_artifact_permissions")]
    pub artifact_permissions: u32,
}

/// Deserialize Vec<String> to Box<[String]> for memory efficiency.
fn deserialize_boxed_strings<'de, D>(deserializer: D) -> std::result::Result<Box<[String]>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let vec = Vec::<String>::deserialize(deserializer)?;
    Ok(vec.into_boxed_slice())
}

/// Telemetry collection configuration.
#[derive(Debug, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct TelemetryConfig {
    /// Paths to monitor for file access (immutable after load)
    #[zeroize(skip)]
    pub watch_paths: Box<[PathBuf]>,

    /// Event buffer size (ring buffer capacity)
    #[serde(default = "default_event_buffer_size")]
    pub event_buffer_size: usize,

    /// Enable syscall-level monitoring (high overhead)
    #[serde(default)]
    pub enable_syscall_monitor: bool,
}

/// Logging configuration.
#[derive(Debug, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct LoggingConfig {
    /// Path to log file
    #[zeroize(skip)]
    pub log_path: PathBuf,

    /// Log format (json or text)
    #[serde(default = "default_log_format")]
    pub format: LogFormat,

    /// Rotate logs at this size (bytes)
    #[serde(default = "default_rotate_size")]
    pub rotate_size_bytes: u64,

    /// Maximum number of rotated log files to keep
    #[serde(default = "default_max_log_files")]
    pub max_log_files: usize,

    /// Minimum log level
    #[serde(default = "default_log_level")]
    pub level: LogLevel,
}

/// Log output format.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    /// JSON format (machine-parseable)
    Json,
    /// Plain text format (human-readable)
    Text,
}

/// Log severity level.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "UPPERCASE")]
pub enum LogLevel {
    /// Debug messages
    Debug,
    /// Informational messages
    Info,
    /// Warning messages
    Warn,
    /// Error messages
    Error,
}

/// Protected string with automatic zeroization.
#[derive(Zeroize, ZeroizeOnDrop, Default)]
pub struct ProtectedString {
    #[zeroize(skip)]
    inner: String,
}

impl ProtectedString {
    /// Create from string (takes ownership).
    #[inline]
    pub fn new(s: String) -> Self {
        Self { inner: s }
    }

    /// Access the inner string by reference.
    #[inline]
    pub fn as_str(&self) -> &str {
        &self.inner
    }

    /// Consume and return inner string.
    #[inline]
    pub fn into_inner(mut self) -> String {
        std::mem::take(&mut self.inner)
    }
}

impl std::fmt::Debug for ProtectedString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ProtectedString([REDACTED])")
    }
}

/// Protected path with automatic zeroization.
#[derive(Zeroize, ZeroizeOnDrop, Default)]
pub struct ProtectedPath {
    #[zeroize(skip)]
    inner: PathBuf,
}

impl ProtectedPath {
    /// Create from PathBuf (takes ownership).
    #[inline]
    pub fn new(path: PathBuf) -> Self {
        Self { inner: path }
    }

    /// Access the inner path by reference.
    #[inline]
    pub fn as_path(&self) -> &Path {
        &self.inner
    }

    /// Consume and return inner PathBuf.
    #[inline]
    pub fn into_inner(mut self) -> PathBuf {
        std::mem::replace(&mut self.inner, PathBuf::new())
    }
}

impl std::fmt::Debug for ProtectedPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ProtectedPath([REDACTED])")
    }
}

impl Config {
    /// Load configuration from TOML file with standard validation (async).
    ///
    /// # Errors
    ///
    /// Returns error if file cannot be read, TOML is invalid, or validation fails.
    pub async fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        Self::from_file_with_mode(path, ValidationMode::Standard).await
    }

    /// Load configuration with specific validation mode (async to prevent thread exhaustion).
    ///
    /// # Errors
    ///
    /// Returns error if file cannot be read, TOML is invalid, or validation fails.
    pub async fn from_file_with_mode<P: AsRef<Path>>(path: P, mode: ValidationMode) -> Result<Self> {
        let path = path.as_ref();

        // Platform-aware permission validation
        Self::validate_file_permissions(path)?;

        let contents = tokio::fs::read_to_string(path).await
            .map_err(|e| errors::io_read_error("load_config", path, e))?;

        let mut config: Config = toml::from_str(&contents).map_err(|e| {
            let location = e
                .span()
                .map(|s| format!("line {}", contents[..s.start].matches('\n').count() + 1))
                .unwrap_or_else(|| "unknown location".to_string());

            errors::parse_error(
                "parse_config_toml",
                format!("Invalid TOML syntax at {}: {}", location, e),
            )
        })?;

        // Convert raw fields to protected types
        config.agent.instance_id =
            ProtectedString::new(std::mem::take(&mut config.agent.instance_id_raw));
        config.agent.work_dir =
            ProtectedPath::new(PathBuf::from(std::mem::take(&mut config.agent.work_dir_raw)));

        // Version validation
        if config.version != CONFIG_VERSION {
            let message = if config.version > CONFIG_VERSION {
                "Configuration version too new - upgrade agent"
            } else {
                "Configuration version outdated - update config"
            };

            return Err(errors::version_error(
                "validate_config_version",
                config.version,
                CONFIG_VERSION,
                message,
            ));
        }

        config.validate_with_mode(mode)?;

        Ok(config)
    }

    /// Validate configuration with specific mode.
    fn validate_with_mode(&self, mode: ValidationMode) -> Result<()> {
        self.validate_agent()?;
        self.validate_deception(mode)?;
        self.validate_telemetry(mode)?;
        self.validate_logging(mode)?;
        Ok(())
    }

    /// Validate configuration (standard mode).
    pub fn validate(&self) -> Result<()> {
        self.validate_with_mode(ValidationMode::Standard)
    }

    #[cfg(unix)]
    fn validate_file_permissions(path: &Path) -> Result<()> {
        use std::os::unix::fs::PermissionsExt;

        let metadata = std::fs::metadata(path)
            .map_err(|e| errors::io_metadata_error("validate_config_file", path, e))?;

        let mode = metadata.permissions().mode();

        // Config file MUST NOT be world-readable or group-writable
        if (mode & 0o077) != 0 {
            return Err(UnixPermissionError::insecure_permissions(mode, "0o600"));
        }

        Ok(())
    }

    #[cfg(not(unix))]
    fn validate_file_permissions(_path: &Path) -> Result<()> {
        // Windows: Rely on NTFS ACLs (validated externally)
        Ok(())
    }

    fn validate_agent(&self) -> Result<()> {
        if self.agent.instance_id.as_str().is_empty() {
            return Err(errors::missing_required(
                "validate_agent",
                "agent.instance_id",
                "no_telemetry_correlation",
            ));
        }

        if !self.agent.work_dir.as_path().is_absolute() {
            return Err(PathValidationError::not_absolute(
                "agent.work_dir",
                "validate_agent",
            ));
        }

        Ok(())
    }

    fn validate_deception(&self, mode: ValidationMode) -> Result<()> {
        if self.deception.decoy_paths.is_empty() {
            return Err(CollectionValidationError::empty(
                "deception.decoy_paths",
                "no_deception",
                "validate_deception",
            ));
        }

        for (idx, path) in self.deception.decoy_paths.iter().enumerate() {
            if !path.is_absolute() {
                return Err(PathValidationError::not_absolute(
                    "deception.decoy_paths",
                    "validate_deception",
                ));
            }

            if mode == ValidationMode::Strict {
                if let Some(parent) = path.parent() {
                    if !parent.exists() {
                        return Err(PathValidationError::parent_missing(
                            "deception.decoy_paths",
                            Some(idx),
                            "validate_deception",
                        ));
                    }
                }
            }
        }

        if self.deception.credential_types.is_empty() {
            return Err(CollectionValidationError::empty(
                "deception.credential_types",
                "no_credential_types",
                "validate_deception",
            ));
        }

        if self.deception.honeytoken_count == 0 || self.deception.honeytoken_count > 100 {
            return Err(RangeValidationError::out_of_range(
                "deception.honeytoken_count",
                self.deception.honeytoken_count,
                1,
                100,
                "validate_deception",
            ));
        }

        if self.deception.artifact_permissions > 0o777 {
            return Err(RangeValidationError::above_maximum(
                "deception.artifact_permissions",
                format!("{:o}", self.deception.artifact_permissions),
                "0o777".to_string(),
                "validate_deception",
            ));
        }

        Ok(())
    }

    fn validate_telemetry(&self, mode: ValidationMode) -> Result<()> {
        if self.telemetry.watch_paths.is_empty() {
            return Err(CollectionValidationError::empty(
                "telemetry.watch_paths",
                "no_monitoring",
                "validate_telemetry",
            ));
        }

        for (idx, path) in self.telemetry.watch_paths.iter().enumerate() {
            if !path.is_absolute() {
                return Err(PathValidationError::not_absolute(
                    "telemetry.watch_paths",
                    "validate_telemetry",
                ));
            }

            if mode == ValidationMode::Strict && !path.exists() {
                return Err(PathValidationError::not_found(
                    "telemetry.watch_paths",
                    Some(idx),
                    "validate_telemetry",
                ));
            }
        }

        if self.telemetry.event_buffer_size < 100 {
            return Err(RangeValidationError::below_minimum(
                "telemetry.event_buffer_size",
                self.telemetry.event_buffer_size,
                100,
                "validate_telemetry",
            ));
        }

        Ok(())
    }

    fn validate_logging(&self, mode: ValidationMode) -> Result<()> {
        if !self.logging.log_path.is_absolute() {
            return Err(PathValidationError::not_absolute(
                "logging.log_path",
                "validate_logging",
            ));
        }

        if mode == ValidationMode::Strict {
            if let Some(parent) = self.logging.log_path.parent() {
                if !parent.exists() {
                    return Err(PathValidationError::parent_missing(
                        "logging.log_path",
                        None,
                        "validate_logging",
                    ));
                }

                let test_file = parent.join(".palisade-write-test");
                std::fs::write(&test_file, b"test")
                    .map_err(|e| errors::io_write_error("test_log_directory_write", &test_file, e))?;
                let _ = std::fs::remove_file(&test_file);
            }
        }

        if self.logging.rotate_size_bytes < 1024 * 1024 {
            return Err(RangeValidationError::below_minimum(
                "logging.rotate_size_bytes",
                self.logging.rotate_size_bytes,
                1024 * 1024,
                "validate_logging",
            ));
        }

        if self.logging.max_log_files == 0 {
            return Err(errors::invalid_value(
                "validate_logging",
                "logging.max_log_files",
                "logging.max_log_files cannot be zero",
            ));
        }

        Ok(())
    }

    /// Get effective hostname for tag derivation (returns reference to avoid cloning).
    #[must_use]
    pub fn hostname(&self) -> std::borrow::Cow<'_, str> {
        match &self.agent.hostname {
            Some(h) => std::borrow::Cow::Borrowed(h.as_str()),
            None => {
                // Only allocate if we need to fetch system hostname
                let system_hostname = hostname::get()
                    .ok()
                    .and_then(|h| h.into_string().ok())
                    .unwrap_or_else(|| "unknown-host".to_string());
                std::borrow::Cow::Owned(system_hostname)
            }
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        let default_instance_id = hostname::get()
            .ok()
            .and_then(|h| h.into_string().ok())
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

        Self {
            version: CONFIG_VERSION,
            agent: AgentConfig {
                instance_id: ProtectedString::new(default_instance_id.clone()),
                work_dir: ProtectedPath::new(PathBuf::from("/var/lib/palisade-agent")),
                environment: None,
                hostname: None,
                instance_id_raw: default_instance_id,
                work_dir_raw: "/var/lib/palisade-agent".to_string(),
            },
            deception: DeceptionConfig {
                decoy_paths: vec![
                    PathBuf::from("/tmp/.credentials"),
                    PathBuf::from("/opt/.backup"),
                ]
                .into_boxed_slice(),
                credential_types: vec!["aws".to_string(), "ssh".to_string()].into_boxed_slice(),
                honeytoken_count: 5,
                root_tag: RootTag::generate().expect("Failed to generate root tag - system entropy failure"),
                artifact_permissions: 0o600,
            },
            telemetry: TelemetryConfig {
                watch_paths: vec![PathBuf::from("/tmp")].into_boxed_slice(),
                event_buffer_size: 10_000,
                enable_syscall_monitor: false,
            },
            logging: LoggingConfig {
                log_path: PathBuf::from("/var/log/palisade-agent.log"),
                format: LogFormat::Json,
                rotate_size_bytes: 100 * 1024 * 1024,
                max_log_files: 10,
                level: LogLevel::Info,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_validates() {
        let config = Config::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn hostname_fallback() {
        let config = Config::default();
        let hostname = config.hostname();
        assert!(!hostname.is_empty());
    }

    #[test]
    fn protected_string_redacts_in_debug() {
        let protected = ProtectedString::new("secret123".to_string());
        let debug = format!("{:?}", protected);
        assert!(!debug.contains("secret123"));
        assert!(debug.contains("REDACTED"));
    }

    #[test]
    fn protected_path_redacts_in_debug() {
        let protected = ProtectedPath::new(PathBuf::from("/etc/shadow"));
        let debug = format!("{:?}", protected);
        assert!(!debug.contains("shadow"));
        assert!(debug.contains("REDACTED"));
    }

    #[test]
    fn validation_catches_empty_instance_id() {
        let mut config = Config::default();
        config.agent.instance_id = ProtectedString::new(String::new());

        let result = config.validate();
        assert!(result.is_err());

        if let Err(err) = result {
            assert!(err.to_string().contains("Configuration"));
        }
    }

    #[test]
    fn validation_catches_relative_work_dir() {
        let mut config = Config::default();
        config.agent.work_dir = ProtectedPath::new(PathBuf::from("relative/path"));

        let result = config.validate();
        assert!(result.is_err());
    }

    #[test]
    fn validation_catches_empty_decoy_paths() {
        let mut config = Config::default();
        config.deception.decoy_paths = Box::new([]);
        assert!(config.validate().is_err());
    }

    #[test]
    fn validation_catches_invalid_honeytoken_count() {
        let mut config = Config::default();
        config.deception.honeytoken_count = 0;
        assert!(config.validate().is_err());

        let mut config = Config::default();
        config.deception.honeytoken_count = 101;
        assert!(config.validate().is_err());
    }
}