//! Configuration mechanics for honeypot infrastructure.
//!
//! This module defines the **wiring** of your deception operation:
//! - WHERE things run (paths, instances)
//! - HOW things connect (I/O, logging)
//! - WHAT capabilities are enabled
//!
//! This does NOT define decision-making (see [`crate::policy`]).

use crate::defaults::{
    default_artifact_permissions, default_event_buffer_size, default_honeytoken_count,
    default_log_format, default_log_level, default_max_log_files, default_rotate_size,
    default_version,
};
use crate::secure_fs::{RestrictedInputKind, read_restricted_file};
use crate::tags::RootTag;
use crate::timing::{TimingOperation, enforce_operation_min_timing};
use crate::validation::ValidationMode;
use crate::{AgentError, CONFIG_VERSION, Result};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::path::{Path, PathBuf};
use std::time::Instant;
use zeroize::{Zeroize, ZeroizeOnDrop};

const CFG_PARSE_FAILED: u16 = 100;
const CFG_VALIDATION_FAILED: u16 = 101;
const CFG_MISSING_REQUIRED: u16 = 102;
const CFG_INVALID_VALUE: u16 = 103;
const CFG_VERSION_MISMATCH: u16 = 106;
const IO_WRITE_FAILED: u16 = 801;

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
    #[serde(
        serialize_with = "serialize_protected_string",
        deserialize_with = "deserialize_protected_string"
    )]
    pub instance_id: ProtectedString,

    /// Working directory for agent state
    #[serde(
        serialize_with = "serialize_protected_path",
        deserialize_with = "deserialize_protected_path"
    )]
    pub work_dir: ProtectedPath,

    /// Optional environment label (dev, staging, prod)
    #[serde(default)]
    pub environment: Option<String>,

    /// Hostname for tag derivation (defaults to system hostname)
    #[serde(default)]
    pub hostname: Option<String>,
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
fn deserialize_boxed_strings<'de, D>(
    deserializer: D,
) -> std::result::Result<Box<[String]>, D::Error>
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
    #[must_use]
    pub fn new(s: String) -> Self {
        Self { inner: s }
    }

    /// Access the inner string by reference.
    #[inline]
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.inner
    }

    /// Consume and return inner string.
    #[inline]
    #[must_use]
    pub fn into_inner(mut self) -> String {
        std::mem::take(&mut self.inner)
    }
}

fn serialize_protected_string<S>(
    value: &ProtectedString,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(value.as_str())
}

fn deserialize_protected_string<'de, D>(deserializer: D) -> std::result::Result<ProtectedString, D::Error>
where
    D: Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    Ok(ProtectedString::new(value))
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
    /// Create from `PathBuf` (takes ownership).
    #[inline]
    #[must_use]
    pub fn new(path: PathBuf) -> Self {
        Self { inner: path }
    }

    /// Access the inner path by reference.
    #[inline]
    #[must_use]
    pub fn as_path(&self) -> &Path {
        &self.inner
    }

    /// Consume and return inner `PathBuf`.
    #[inline]
    #[must_use]
    pub fn into_inner(mut self) -> PathBuf {
        std::mem::replace(&mut self.inner, PathBuf::new())
    }
}

fn serialize_protected_path<S>(
    value: &ProtectedPath,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&value.as_path().to_string_lossy())
}

fn deserialize_protected_path<'de, D>(deserializer: D) -> std::result::Result<ProtectedPath, D::Error>
where
    D: Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    Ok(ProtectedPath::new(PathBuf::from(value)))
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
        Self::from_file_with_mode(path, &ValidationMode::Standard).await
    }

    /// Load configuration with specific validation mode (async to prevent thread exhaustion).
    ///
    /// # Errors
    ///
    /// Returns error if file cannot be read, TOML is invalid, or validation fails.
    pub async fn from_file_with_mode<P: AsRef<Path>>(
        path: P,
        mode: &ValidationMode,
    ) -> Result<Self> {
        let started = Instant::now();
        let path = path.as_ref();
        let result = async {
            let contents = read_restricted_file(path, RestrictedInputKind::Config).await?;
            Self::from_toml_str_with_mode(&contents, mode)
        }
        .await;
        enforce_operation_min_timing(started, TimingOperation::ConfigLoad);
        result
    }

    pub(crate) fn from_toml_str_with_mode(contents: &str, mode: &ValidationMode) -> Result<Self> {
        let config: Config = toml::from_str(contents).map_err(|e| {
            let location = e.span().map_or_else(
                || "unknown location".to_string(),
                |s| format!("line {}", contents[..s.start].matches('\n').count() + 1),
            );

            AgentError::new(
                CFG_PARSE_FAILED,
                "Configuration input could not be parsed",
                format!("operation=parse_config_toml; Invalid TOML syntax at {location}: {e}"),
                "",
            )
        })?;

        if config.version != CONFIG_VERSION {
            let message = if config.version > CONFIG_VERSION {
                "Configuration version too new - upgrade agent"
            } else {
                "Configuration version outdated - update config"
            };

            return Err(AgentError::new(
                CFG_VERSION_MISMATCH,
                "Configuration version is not supported",
                format!(
                    "operation=validate_config_version; {message}; file_version={}; expected_version={CONFIG_VERSION}",
                    config.version
                ),
                "",
            ));
        }

        config.validate_with_mode(mode)?;
        Ok(config)
    }

    /// Validate configuration with specific mode.
    pub(crate) fn validate_with_mode(&self, mode: &ValidationMode) -> Result<()> {
        let started = Instant::now();
        let result = (|| {
            self.validate_agent()?;
            self.validate_deception(mode)?;
            self.validate_telemetry(mode)?;
            self.validate_logging(mode)?;
            Ok(())
        })();
        enforce_operation_min_timing(
            started,
            match mode {
                &ValidationMode::Standard => TimingOperation::ConfigValidateStandard,
                &ValidationMode::Strict => TimingOperation::ConfigValidateStrict,
            },
        );
        result
    }

    /// Validate configuration (standard mode).
    pub fn validate(&self) -> Result<()> {
        self.validate_with_mode(&ValidationMode::Standard)
    }

    fn validate_agent(&self) -> Result<()> {
        if self.agent.instance_id.as_str().is_empty() {
            return Err(AgentError::new(
                CFG_MISSING_REQUIRED,
                "Required configuration is missing",
                "operation=validate_agent; agent.instance_id cannot be empty; impact=no_telemetry_correlation",
                "agent.instance_id",
            ));
        }

        if !self.agent.work_dir.as_path().is_absolute() {
            return Err(AgentError::new(
                CFG_INVALID_VALUE,
                "Configuration contains an invalid value",
                "operation=validate_agent; field=agent.work_dir; agent.work_dir must be an absolute path",
                "agent.work_dir",
            ));
        }

        Ok(())
    }

    fn validate_deception(&self, mode: &ValidationMode) -> Result<()> {
        if self.deception.decoy_paths.is_empty() {
            return Err(AgentError::new(
                CFG_MISSING_REQUIRED,
                "Required configuration is missing",
                "operation=validate_deception; deception.decoy_paths cannot be empty; impact=no_deception",
                "deception.decoy_paths",
            ));
        }

        for (idx, path) in self.deception.decoy_paths.iter().enumerate() {
            if !path.is_absolute() {
                return Err(AgentError::new(
                    CFG_INVALID_VALUE,
                    "Configuration contains an invalid value",
                    "operation=validate_deception; field=deception.decoy_paths; deception.decoy_paths must be an absolute path",
                    "deception.decoy_paths",
                ));
            }

            if matches!(mode, ValidationMode::Strict)
                && let Some(parent) = path.parent()
                && !parent.exists()
            {
                return Err(AgentError::new(
                    CFG_VALIDATION_FAILED,
                    "Configuration validation failed",
                    format!(
                        "operation=validate_deception; deception.decoy_paths parent directory does not exist; path_index={idx}"
                    ),
                    "deception.decoy_paths",
                ));
            }
        }

        if self.deception.credential_types.is_empty() {
            return Err(AgentError::new(
                CFG_MISSING_REQUIRED,
                "Required configuration is missing",
                "operation=validate_deception; deception.credential_types cannot be empty; impact=no_credential_types",
                "deception.credential_types",
            ));
        }

        if self.deception.honeytoken_count == 0 || self.deception.honeytoken_count > 100 {
            return Err(AgentError::new(
                CFG_INVALID_VALUE,
                "Configuration contains an invalid value",
                format!(
                    "operation=validate_deception; field=deception.honeytoken_count; reason=deception.honeytoken_count must be within valid range; actual_value={}; expected_range=1-100",
                    self.deception.honeytoken_count
                ),
                "deception.honeytoken_count",
            ));
        }

        if self.deception.artifact_permissions > 0o777 {
            return Err(AgentError::new(
                CFG_INVALID_VALUE,
                "Configuration contains an invalid value",
                format!(
                    "operation=validate_deception; field=deception.artifact_permissions; reason=deception.artifact_permissions exceeds maximum threshold; actual_value={:o}; expected_range=maximum: 0o777",
                    self.deception.artifact_permissions
                ),
                "deception.artifact_permissions",
            ));
        }

        Ok(())
    }

    fn validate_telemetry(&self, mode: &ValidationMode) -> Result<()> {
        if self.telemetry.watch_paths.is_empty() {
            return Err(AgentError::new(
                CFG_MISSING_REQUIRED,
                "Required configuration is missing",
                "operation=validate_telemetry; telemetry.watch_paths cannot be empty; impact=no_monitoring",
                "telemetry.watch_paths",
            ));
        }

        for (idx, path) in self.telemetry.watch_paths.iter().enumerate() {
            if !path.is_absolute() {
                return Err(AgentError::new(
                    CFG_INVALID_VALUE,
                    "Configuration contains an invalid value",
                    "operation=validate_telemetry; field=telemetry.watch_paths; telemetry.watch_paths must be an absolute path",
                    "telemetry.watch_paths",
                ));
            }

            if matches!(mode, ValidationMode::Strict) && !path.exists() {
                return Err(AgentError::new(
                    CFG_VALIDATION_FAILED,
                    "Configuration validation failed",
                    format!(
                        "operation=validate_telemetry; telemetry.watch_paths does not exist; path_index={idx}"
                    ),
                    "telemetry.watch_paths",
                ));
            }
        }

        if self.telemetry.event_buffer_size < 100 {
            return Err(AgentError::new(
                CFG_INVALID_VALUE,
                "Configuration contains an invalid value",
                format!(
                    "operation=validate_telemetry; field=telemetry.event_buffer_size; reason=telemetry.event_buffer_size below minimum threshold; actual_value={}; expected_range=minimum: 100",
                    self.telemetry.event_buffer_size
                ),
                "telemetry.event_buffer_size",
            ));
        }

        Ok(())
    }

    fn validate_logging(&self, mode: &ValidationMode) -> Result<()> {
        if !self.logging.log_path.is_absolute() {
            return Err(AgentError::new(
                CFG_INVALID_VALUE,
                "Configuration contains an invalid value",
                "operation=validate_logging; field=logging.log_path; logging.log_path must be an absolute path",
                "logging.log_path",
            ));
        }

        if matches!(mode, ValidationMode::Strict)
            && let Some(parent) = self.logging.log_path.parent()
        {
            if !parent.exists() {
                return Err(AgentError::new(
                    CFG_VALIDATION_FAILED,
                    "Configuration validation failed",
                    "operation=validate_logging; logging.log_path parent directory does not exist",
                    "logging.log_path",
                ));
            }

            let test_file = parent.join(".palisade-write-test");
            std::fs::write(&test_file, b"test").map_err(|e| {
                AgentError::new(
                    IO_WRITE_FAILED,
                    "Configuration output could not be written",
                    format!(
                        "operation=test_log_directory_write; io_kind={}; write failed",
                        e.kind()
                    ),
                    test_file.display().to_string(),
                )
            })?;
            let _ = std::fs::remove_file(&test_file);
        }

        if self.logging.rotate_size_bytes < 1024 * 1024 {
            return Err(AgentError::new(
                CFG_INVALID_VALUE,
                "Configuration contains an invalid value",
                format!(
                    "operation=validate_logging; field=logging.rotate_size_bytes; reason=logging.rotate_size_bytes below minimum threshold; actual_value={}; expected_range=minimum: {}",
                    self.logging.rotate_size_bytes,
                    1024 * 1024
                ),
                "logging.rotate_size_bytes",
            ));
        }

        if self.logging.max_log_files == 0 {
            return Err(AgentError::new(
                CFG_INVALID_VALUE,
                "Configuration contains an invalid value",
                "operation=validate_logging; field=logging.max_log_files; logging.max_log_files cannot be zero",
                "logging.max_log_files",
            ));
        }

        Ok(())
    }

    /// Get effective hostname for tag derivation (returns reference to avoid cloning).
    #[must_use]
    pub fn hostname(&self) -> std::borrow::Cow<'_, str> {
        let started = Instant::now();
        let hostname = if let Some(h) = &self.agent.hostname {
            std::borrow::Cow::Borrowed(h.as_str())
        } else {
            // Only allocate if we need to fetch system hostname
            let system_hostname = hostname::get()
                .ok()
                .and_then(|h| h.into_string().ok())
                .unwrap_or_else(|| "unknown-host".to_string());
            std::borrow::Cow::Owned(system_hostname)
        };
        enforce_operation_min_timing(started, TimingOperation::ConfigHostname);
        hostname
    }
}

impl Default for Config {
    fn default() -> Self {
        let mut default_instance_id = hostname::get()
            .ok()
            .and_then(|h| h.into_string().ok())
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

        Self {
            version: CONFIG_VERSION,
            agent: AgentConfig {
                instance_id: ProtectedString::new(std::mem::take(&mut default_instance_id)),
                work_dir: ProtectedPath::new(PathBuf::from("/var/lib/palisade-agent")),
                environment: None,
                hostname: None,
            },
            deception: DeceptionConfig {
                decoy_paths: vec![
                    PathBuf::from("/tmp/.credentials"),
                    PathBuf::from("/opt/.backup"),
                ]
                .into_boxed_slice(),
                credential_types: vec!["aws".to_string(), "ssh".to_string()].into_boxed_slice(),
                honeytoken_count: 5,
                root_tag: RootTag::generate()
                    .expect("Failed to generate root tag - system entropy failure"),
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
            assert_eq!(err.to_string(), "Required configuration is missing");
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
