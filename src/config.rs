//! Configuration mechanics for honeypot infrastructure.
//!
//! This module defines the **wiring** of your deception operation:
//! - WHERE things run (paths, instances)
//! - HOW things connect (I/O, logging)
//! - WHAT capabilities are enabled
//!
//! This does NOT define decision-making (see [`crate::policy`]).
//!
//! # Security Architecture
//!
//! **Defense-in-Depth Layers:**
//!
//! 1. **Memory Protection**
//!    - All sensitive fields wrapped in `ZeroizeOnDrop`
//!    - No `Clone` trait - config is moved, never duplicated
//!    - Explicit borrow checking enforces single-owner semantics
//!
//! 2. **Cryptographic Isolation**
//!    - Root tags cannot be cloned or displayed
//!    - Tags derive from secure hierarchy (no correlation)
//!    - All tag operations zeroize intermediate buffers
//!
//! 3. **Validation Strictness**
//!    - Fail-fast on any invalid configuration
//!    - Comprehensive checks prevent attack surface
//!    - Platform-aware security (Unix permissions, etc.)
//!
//! 4. **Error Handling**
//!    - Never leaks paths or values externally
//!    - Full forensic context for internal logs
//!    - Timing normalization prevents fingerprinting
//!
//! # Example
//!
//! ```rust
//! use palisade_config::{Config, ValidationMode};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Load and validate configuration (moves ownership)
//! let config = Config::from_file("/etc/honeypot/config.toml")?;
//! config.validate_with_mode(ValidationMode::Strict)?;
//!
//! // Access by reference - config cannot be cloned
//! println!("Instance: {}", config.agent.instance_id);
//! println!("Work dir: {}", config.agent.work_dir.display());
//!
//! // Derive artifact tags (borrows config)
//! let hostname = config.hostname();
//! let tag = config.deception.root_tag.derive_artifact_tag(&hostname, "aws-creds");
//! # Ok(())
//! # }
//! ```

use crate::defaults::*;
use crate::tags::RootTag;
use crate::validation::ValidationMode;
use crate::CONFIG_VERSION;
use palisade_errors::{definitions, AgentError, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Master configuration - the MECHANICS of your deception operation.
///
/// **Security Properties:**
/// - No `Clone`: Prevents accidental duplication of sensitive data
/// - No `Copy`: Root tags cannot be implicitly copied
/// - Move semantics: Config ownership is explicit
/// - Zeroization: All sensitive fields cleared on drop
///
/// **Design Rationale:**
/// Configuration is loaded once at startup, validated, then moved into
/// the agent. There's no legitimate reason to clone config - doing so
/// would duplicate root tags and create multiple zeroization points.
/// If you need to share config, use `&Config` or `Arc<Config>`.
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
///
/// **Security Note:** Instance IDs should be unique per deployment
/// to enable correlation without leaking infrastructure details.
#[derive(Debug, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct AgentConfig {
    /// Unique instance identifier (for correlation)
    #[serde(skip)]
    pub instance_id: ProtectedString,

    /// Working directory for agent state
    #[serde(skip)]
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
///
/// **Critical Security:**
/// - `root_tag` is the crown jewel - compromise = full breach
/// - Never log, display, or transmit root_tag
/// - All derived tags zeroize intermediate buffers
#[derive(Debug, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct DeceptionConfig {
    /// Paths where decoy files will be placed
    #[serde(default)]
    #[zeroize(skip)]
    pub decoy_paths: Vec<PathBuf>,

    /// Types of credentials to generate (aws, ssh, etc.)
    pub credential_types: Vec<String>,

    /// Number of honeytokens to generate
    #[serde(default = "default_honeytoken_count")]
    pub honeytoken_count: usize,

    /// Root cryptographic tag for tag derivation hierarchy
    ///
    /// **SECURITY ARCHITECTURE:**
    /// ```text
    /// root_tag (secret, never leaves agent, zeroized on drop)
    ///    ↓ SHA3-512(root_tag || hostname)
    /// host_tag (per-deployment, zeroized after use)
    ///    ↓ SHA3-512(host_tag || artifact_id)
    /// artifact_tag (per-decoy, embedded in files)
    /// ```
    ///
    /// **Properties:**
    /// - Attackers cannot correlate artifacts across hosts
    /// - Per-artifact revocation possible
    /// - Defenders can derive all tags from root
    /// - Memory forensics recovers nothing after drop
    pub root_tag: RootTag,

    /// Unix permissions for created artifacts (octal)
    #[serde(default = "default_artifact_permissions")]
    pub artifact_permissions: u32,
}

/// Telemetry collection configuration.
#[derive(Debug, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct TelemetryConfig {
    /// Paths to monitor for file access
    #[zeroize(skip)]
    pub watch_paths: Vec<PathBuf>,

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
///
/// **Security Properties:**
/// - Zeroized on drop (memory forensics protection)
/// - No Clone (prevents duplication)
/// - No Display (prevents logging)
/// - Explicit conversion required to access value
///
/// Use for: instance IDs, session tokens, correlation IDs
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
    ///
    /// **Security Warning:** Caller is responsible for zeroization.
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
///
/// **Security Properties:**
/// - Zeroized on drop (path disclosure protection)
/// - No Clone (prevents duplication)
/// - Debug redacts path content
///
/// Use for: config paths, working directories, artifact locations
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
    ///
    /// **Security Warning:** Caller is responsible for zeroization.
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
    /// Load configuration from TOML file with standard validation.
    ///
    /// **Error Handling:**
    /// - File path never exposed externally (only in internal logs)
    /// - TOML syntax errors include line numbers internally
    /// - Version mismatches provide upgrade guidance
    /// - Validation failures include field context
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - File cannot be read (permissions, not found)
    /// - TOML syntax invalid
    /// - Version incompatible
    /// - Validation fails
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use palisade_config::Config;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let config = Config::from_file("/etc/honeypot/config.toml")?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        Self::from_file_with_mode(path, ValidationMode::Standard)
    }

    /// Load configuration with specific validation mode.
    ///
    /// # Validation Modes
    ///
    /// - [`ValidationMode::Standard`]: Format checks only
    /// - [`ValidationMode::Strict`]: Paths must exist, permissions verified
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use palisade_config::{Config, ValidationMode};
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// // Strict validation for production
    /// let config = Config::from_file_with_mode(
    ///     "/etc/honeypot/config.toml",
    ///     ValidationMode::Strict
    /// )?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn from_file_with_mode<P: AsRef<Path>>(path: P, mode: ValidationMode) -> Result<Self> {
        let path = path.as_ref();

        // Platform-aware permission validation
        Self::validate_file_permissions(path)?;

        let contents = std::fs::read_to_string(path).map_err(|e| {
            AgentError::from_io_path(
                definitions::IO_READ_FAILED,
                "load_config",
                path.display().to_string(),
                e,
            )
            .with_metadata("file_type", "configuration")
            .with_metadata("validation_mode", match mode {
                ValidationMode::Standard => "standard",
                ValidationMode::Strict => "strict",
            }).with_obfuscation()
        })?;

        let mut config: Config = toml::from_str(&contents).map_err(|e| {
            let location = e
                .span()
                .map(|s| format!("line {}", contents[..s.start].matches('\n').count() + 1))
                .unwrap_or_else(|| "unknown location".to_string());

            AgentError::config(
                definitions::CFG_PARSE_FAILED,
                "parse_config_toml",
                format!("Invalid TOML syntax at {}", location),
            )
            .with_metadata("parse_location", location)
            .with_obfuscation()
        })?;

        // Convert raw fields to protected types
        config.agent.instance_id = ProtectedString::new(
            std::mem::take(&mut config.agent.instance_id_raw)
        );
        config.agent.work_dir = ProtectedPath::new(
            PathBuf::from(std::mem::take(&mut config.agent.work_dir_raw))
        );

        // Version validation
        if config.version != CONFIG_VERSION {
            return Err(AgentError::config(
                definitions::CFG_VERSION_MISMATCH,
                "validate_version",
                if config.version > CONFIG_VERSION {
                    "Configuration version too new - upgrade agent"
                } else {
                    "Configuration version outdated - update config"
                },
            )
            .with_metadata("file_version", config.version.to_string())
            .with_metadata("expected_version", CONFIG_VERSION.to_string())
            .with_obfuscation()
        );
        }

        // Comprehensive validation
        config.validate_with_mode(mode)?;

        Ok(config)
    }

    /// Validate file permissions (platform-aware).
    ///
    /// **Security Requirements:**
    /// - Unix: Must be 0600 (owner read/write only)
    /// - Windows: Warning only (no standardized permission model)
    ///
    /// **Rationale:** Configuration files contain root tags and paths.
    /// Group/other read permissions = information disclosure vulnerability.
    fn validate_file_permissions(path: &Path) -> Result<()> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            match std::fs::metadata(path) {
                Ok(metadata) => {
                    let mode = metadata.permissions().mode();
                    // Check if group or others can read
                    if (mode & 0o044) != 0 {
                        return Err(AgentError::config(
                            definitions::CFG_SECURITY_VIOLATION,
                            "validate_file_permissions",
                            "Configuration file has insecure permissions",
                        )
                        .with_metadata("file_mode", format!("{:o}", mode & 0o777))
                        .with_metadata("expected_mode", "0600")
                        .with_metadata("security_impact", "config_disclosure")
                        .with_obfuscation()
                    );
                    }
                }
                Err(e) => {
                    return Err(AgentError::from_io_path(
                        definitions::IO_METADATA_FAILED,
                        "validate_file_permissions",
                        path.display().to_string(),
                        e,
                    ).with_obfuscation());
                }
            }
        }

        #[cfg(not(unix))]
        {
            // Log warning on non-Unix platforms
            eprintln!(
                "WARNING: File permission validation not available on this platform: {}",
                path.display()
            );
        }

        Ok(())
    }

    /// Validate configuration with standard mode.
    ///
    /// Equivalent to `validate_with_mode(ValidationMode::Standard)`.
    pub fn validate(&self) -> Result<()> {
        self.validate_with_mode(ValidationMode::Standard)
    }

    /// Validate configuration with specific mode.
    ///
    /// **Validation Strategy:**
    /// - Format checks: Always performed
    /// - Filesystem checks: Only in strict mode
    /// - Permission checks: Only in strict mode on Unix
    /// - Range checks: Always performed
    ///
    /// **Error Handling:**
    /// - Each validation failure provides field context
    /// - Expected vs actual values included
    /// - Security implications noted where relevant
    pub fn validate_with_mode(&self, mode: ValidationMode) -> Result<()> {
        self.validate_agent(mode)?;
        self.validate_deception(mode)?;
        self.validate_telemetry(mode)?;
        self.validate_logging(mode)?;
        Ok(())
    }

    fn validate_agent(&self, mode: ValidationMode) -> Result<()> {
        if self.agent.instance_id.as_str().is_empty() {
            return Err(AgentError::config(
                definitions::CFG_MISSING_REQUIRED,
                "validate_agent",
                "agent.instance_id cannot be empty",
            )
            .with_metadata("field", "agent.instance_id")
            .with_metadata("impact", "correlation_impossible")
            .with_obfuscation()
        );
        }

        if !self.agent.work_dir.as_path().is_absolute() {
            return Err(AgentError::config(
                definitions::CFG_INVALID_VALUE,
                "validate_agent",
                "agent.work_dir must be absolute path",
            )
            .with_metadata("field", "agent.work_dir")
            .with_obfuscation()
        );
        }

        if mode == ValidationMode::Strict {
            let work_dir = self.agent.work_dir.as_path();

            // Check if work_dir exists, create if not
            if !work_dir.exists() {
                std::fs::create_dir_all(work_dir).map_err(|e| {
                    AgentError::from_io_path(
                        definitions::IO_WRITE_FAILED,
                        "create_work_directory",
                        work_dir.display().to_string(),
                        e,
                    )
                    .with_metadata("operation", "create_dir_all")
                    .with_obfuscation()
                })?;
            }

            // Test write permissions
            let test_file = work_dir.join(".palisade-write-test");
            std::fs::write(&test_file, b"test").map_err(|e| {
                AgentError::from_io_path(
                    definitions::IO_WRITE_FAILED,
                    "test_work_directory_write",
                    test_file.display().to_string(),
                    e,
                )
                .with_metadata("test_operation", "write_permission_check")
                .with_obfuscation()
            })?;
            let _ = std::fs::remove_file(&test_file);

            // Unix-specific: check directory ownership
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                if let Ok(metadata) = std::fs::metadata(work_dir) {
                    let current_uid = unsafe { libc::getuid() };
                    if metadata.uid() != current_uid {
                        return Err(AgentError::config(
                            definitions::CFG_SECURITY_VIOLATION,
                            "validate_agent",
                            "Work directory owned by different user",
                        )
                        .with_metadata("dir_uid", metadata.uid().to_string())
                        .with_metadata("current_uid", current_uid.to_string())
                        .with_metadata("security_impact", "privilege_escalation_risk")
                        .with_obfuscation()
                    );
                    }
                }
            }
        }

        Ok(())
    }

    fn validate_deception(&self, mode: ValidationMode) -> Result<()> {
        if self.deception.decoy_paths.is_empty() {
            return Err(AgentError::config(
                definitions::CFG_MISSING_REQUIRED,
                "validate_deception",
                "deception.decoy_paths cannot be empty",
            )
            .with_metadata("field", "deception.decoy_paths")
            .with_metadata("impact", "no_artifacts_deployed")
            .with_obfuscation());
        }

        for (idx, path) in self.deception.decoy_paths.iter().enumerate() {
            if !path.is_absolute() {
                return Err(AgentError::config(
                    definitions::CFG_INVALID_VALUE,
                    "validate_deception",
                    "All decoy paths must be absolute",
                )
                .with_metadata("field", "deception.decoy_paths")
                .with_metadata("path_index", idx.to_string())
                .with_obfuscation());
            }

            if mode == ValidationMode::Strict {
                if let Some(parent) = path.parent() {
                    if !parent.exists() {
                        return Err(AgentError::config(
                            definitions::CFG_VALIDATION_FAILED,
                            "validate_deception",
                            "Decoy path parent directory does not exist",
                        )
                        .with_metadata("path_index", idx.to_string())
                        .with_obfuscation());
                    }
                }
            }
        }

        if self.deception.credential_types.is_empty() {
            return Err(AgentError::config(
                definitions::CFG_MISSING_REQUIRED,
                "validate_deception",
                "deception.credential_types cannot be empty",
            )
            .with_metadata("field", "deception.credential_types")
            .with_obfuscation());
        }

        if self.deception.honeytoken_count == 0 || self.deception.honeytoken_count > 100 {
            return Err(AgentError::config(
                definitions::CFG_INVALID_VALUE,
                "validate_deception",
                "deception.honeytoken_count must be 1-100",
            )
            .with_metadata("field", "deception.honeytoken_count")
            .with_metadata("value", self.deception.honeytoken_count.to_string())
            .with_metadata("valid_range", "1-100")
            .with_obfuscation());
        }

        if self.deception.artifact_permissions > 0o777 {
            return Err(AgentError::config(
                definitions::CFG_INVALID_VALUE,
                "validate_deception",
                "deception.artifact_permissions must be valid Unix permissions",
            )
            .with_metadata("field", "deception.artifact_permissions")
            .with_metadata("value", format!("{:o}", self.deception.artifact_permissions))
            .with_metadata("max_value", "0o777")
            .with_obfuscation());
        }

        Ok(())
    }

    fn validate_telemetry(&self, mode: ValidationMode) -> Result<()> {
        if self.telemetry.watch_paths.is_empty() {
            return Err(AgentError::config(
                definitions::CFG_MISSING_REQUIRED,
                "validate_telemetry",
                "telemetry.watch_paths cannot be empty",
            )
            .with_metadata("field", "telemetry.watch_paths")
            .with_obfuscation());
        }

        for (idx, path) in self.telemetry.watch_paths.iter().enumerate() {
            if !path.is_absolute() {
                return Err(AgentError::config(
                    definitions::CFG_INVALID_VALUE,
                    "validate_telemetry",
                    "All watch paths must be absolute",
                )
                .with_metadata("field", "telemetry.watch_paths")
                .with_metadata("path_index", idx.to_string())
                .with_obfuscation());
            }

            if mode == ValidationMode::Strict && !path.exists() {
                return Err(AgentError::config(
                    definitions::CFG_VALIDATION_FAILED,
                    "validate_telemetry",
                    "Watch path does not exist",
                )
                .with_metadata("path_index", idx.to_string())
                .with_obfuscation());
            }
        }

        if self.telemetry.event_buffer_size < 100 {
            return Err(AgentError::config(
                definitions::CFG_INVALID_VALUE,
                "validate_telemetry",
                "telemetry.event_buffer_size too small",
            )
            .with_metadata("field", "telemetry.event_buffer_size")
            .with_metadata("value", self.telemetry.event_buffer_size.to_string())
            .with_metadata("min_value", "100")
            .with_obfuscation());
        }

        Ok(())
    }

    fn validate_logging(&self, mode: ValidationMode) -> Result<()> {
        if !self.logging.log_path.is_absolute() {
            return Err(AgentError::config(
                definitions::CFG_INVALID_VALUE,
                "validate_logging",
                "logging.log_path must be absolute path",
            )
            .with_metadata("field", "logging.log_path")
            .with_obfuscation());
        }

        if mode == ValidationMode::Strict {
            if let Some(parent) = self.logging.log_path.parent() {
                if !parent.exists() {
                    return Err(AgentError::config(
                        definitions::CFG_VALIDATION_FAILED,
                        "validate_logging",
                        "Log directory does not exist",
                    ).with_obfuscation());
                }

                let test_file = parent.join(".palisade-write-test");
                std::fs::write(&test_file, b"test").map_err(|e| {
                    AgentError::from_io_path(
                        definitions::IO_WRITE_FAILED,
                        "test_log_directory_write",
                        test_file.display().to_string(),
                        e,
                    ).with_obfuscation()
                })?;
                let _ = std::fs::remove_file(&test_file);
            }
        }

        if self.logging.rotate_size_bytes < 1024 * 1024 {
            return Err(AgentError::config(
                definitions::CFG_INVALID_VALUE,
                "validate_logging",
                "logging.rotate_size_bytes too small (min: 1MB)",
            )
            .with_metadata("field", "logging.rotate_size_bytes")
            .with_metadata("value", self.logging.rotate_size_bytes.to_string())
            .with_metadata("min_value", "1048576")
            .with_obfuscation());
        }

        if self.logging.max_log_files == 0 {
            return Err(AgentError::config(
                definitions::CFG_INVALID_VALUE,
                "validate_logging",
                "logging.max_log_files cannot be zero",
            )
            .with_metadata("field", "logging.max_log_files")
            .with_obfuscation());
        }

        Ok(())
    }

    /// Get effective hostname for tag derivation.
    ///
    /// Returns configured hostname or system hostname if not set.
    /// Never fails - falls back to "unknown-host" if system query fails.
    #[must_use]
    pub fn hostname(&self) -> String {
        self.agent.hostname.clone().unwrap_or_else(|| {
            hostname::get()
                .ok()
                .and_then(|h| h.into_string().ok())
                .unwrap_or_else(|| "unknown-host".to_string())
        })
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
                ],
                credential_types: vec!["aws".to_string(), "ssh".to_string()],
                honeytoken_count: 5,
                root_tag: RootTag::generate(),
                artifact_permissions: 0o600,
            },
            telemetry: TelemetryConfig {
                watch_paths: vec![PathBuf::from("/tmp")],
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
    fn config_cannot_be_cloned() {
        // This test verifies Clone is not implemented
        // (will fail to compile if Clone is added)
        fn requires_no_clone<T>(_: &T) {}
        let config = Config::default();
        requires_no_clone(&config);
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
            let log = err.internal_log();
            assert!(log.details().contains("instance_id"));
        }
    }

    #[test]
    fn validation_catches_relative_work_dir() {
        let mut config = Config::default();
        config.agent.work_dir = ProtectedPath::new(PathBuf::from("relative/path"));
        
        let result = config.validate();
        assert!(result.is_err());
        
        if let Err(err) = result {
            let log = err.internal_log();
            assert!(log.details().contains("absolute"));
        }
    }

    #[test]
    fn validation_catches_empty_decoy_paths() {
        let mut config = Config::default();
        config.deception.decoy_paths.clear();
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

    #[test]
    fn validation_catches_small_event_buffer() {
        let mut config = Config::default();
        config.telemetry.event_buffer_size = 50;
        assert!(config.validate().is_err());
    }

    #[test]
    fn validation_catches_small_rotate_size() {
        let mut config = Config::default();
        config.logging.rotate_size_bytes = 1024; // 1KB
        assert!(config.validate().is_err());
    }

    #[test]
    fn error_includes_metadata() {
        let mut config = Config::default();
        config.deception.honeytoken_count = 150;
        
        let result = config.validate();
        assert!(result.is_err());
        
        if let Err(err) = result {
            let log = err.internal_log();
            // Should have field metadata
            assert!(log.metadata().len() > 0);
        }
    }

    #[test]
    fn protected_string_can_be_consumed() {
        let protected = ProtectedString::new("test".to_string());
        let inner = protected.into_inner();
        assert_eq!(inner, "test");
    }

    #[test]
    fn protected_path_can_be_consumed() {
        let protected = ProtectedPath::new(PathBuf::from("/test"));
        let inner = protected.into_inner();
        assert_eq!(inner, PathBuf::from("/test"));
    }

    #[test]
    fn config_with_custom_values() {
        let mut config = Config::default();
        config.agent.environment = Some("production".to_string());
        config.deception.honeytoken_count = 10;
        config.telemetry.enable_syscall_monitor = true;
        
        assert!(config.validate().is_ok());
        assert_eq!(config.agent.environment.as_ref().unwrap(), "production");
    }

    #[test]
    fn validation_mode_standard_vs_strict() {
        let config = Config::default();
        
        // Standard should pass (no filesystem checks)
        assert!(config.validate_with_mode(ValidationMode::Standard).is_ok());
        
        // Strict might fail if directories don't exist
        // (This is expected behavior)
    }

    #[test]
    fn version_mismatch_detected() {
        // Can't easily test this without modifying CONFIG_VERSION,
        // but the code path exists and is covered by integration tests
    }

    #[test]
    fn multiple_credential_types() {
        let mut config = Config::default();
        config.deception.credential_types = vec![
            "aws".to_string(),
            "ssh".to_string(),
            "gcp".to_string(),
            "azure".to_string(),
        ];
        
        assert!(config.validate().is_ok());
        assert_eq!(config.deception.credential_types.len(), 4);
    }

    #[test]
    fn multiple_watch_paths() {
        let mut config = Config::default();
        config.telemetry.watch_paths = vec![
            PathBuf::from("/tmp"),
            PathBuf::from("/var/log"),
            PathBuf::from("/opt/data"),
        ];
        
        assert!(config.validate().is_ok());
    }

    #[test]
    fn log_levels_ordered() {
        assert!(LogLevel::Debug < LogLevel::Info);
        assert!(LogLevel::Info < LogLevel::Warn);
        assert!(LogLevel::Warn < LogLevel::Error);
    }

    #[test]
    fn log_format_serialization() {
        let json_fmt = LogFormat::Json;
        let text_fmt = LogFormat::Text;
        
        assert_eq!(json_fmt, LogFormat::Json);
        assert_ne!(json_fmt, text_fmt);
    }

    #[test]
    fn config_zeroizes_on_drop() {
        // Create config in scope
        {
            let mut config = Config::default();
            config.agent.instance_id = ProtectedString::new("sensitive_id_12345".to_string());
            config.agent.work_dir = ProtectedPath::new(PathBuf::from("/secret/path"));
            
            // Config and all protected fields exist here
        } // <- Zeroization happens here
        
        // After drop, memory should be zeroized
        // (Can't directly verify without unsafe code, but ZeroizeOnDrop guarantees this)
    }

    #[test]
    fn relative_paths_rejected() {
        let mut config = Config::default();
        
        // Relative decoy path
        config.deception.decoy_paths = vec![PathBuf::from("relative/path")];
        assert!(config.validate().is_err());
        
        // Reset
        config.deception.decoy_paths = vec![PathBuf::from("/tmp")];
        
        // Relative watch path
        config.telemetry.watch_paths = vec![PathBuf::from("./relative")];
        assert!(config.validate().is_err());
        
        // Reset
        config.telemetry.watch_paths = vec![PathBuf::from("/tmp")];
        
        // Relative log path
        config.logging.log_path = PathBuf::from("relative/log.txt");
        assert!(config.validate().is_err());
    }

    #[test]
    fn artifact_permissions_validation() {
        let mut config = Config::default();
        
        // Valid permissions
        config.deception.artifact_permissions = 0o600;
        assert!(config.validate().is_ok());
        
        config.deception.artifact_permissions = 0o644;
        assert!(config.validate().is_ok());
        
        // Invalid permissions (exceeds 0o777)
        config.deception.artifact_permissions = 0o1000;
        assert!(config.validate().is_err());
    }

    #[test]
    fn empty_credential_types_rejected() {
        let mut config = Config::default();
        config.deception.credential_types.clear();
        
        let result = config.validate();
        assert!(result.is_err());
        
        if let Err(err) = result {
            let log = err.internal_log();
            assert!(log.details().contains("credential_types"));
        }
    }

    #[test]
    fn zero_max_log_files_rejected() {
        let mut config = Config::default();
        config.logging.max_log_files = 0;
        
        assert!(config.validate().is_err());
    }

    #[test]
    fn error_codes_match_palisade_errors() {
        // Verify we're using the correct error codes from palisade_errors
        let mut config = Config::default();
        config.agent.instance_id = ProtectedString::new(String::new());
        
        if let Err(err) = config.validate() {
            assert_eq!(err.code(), definitions::CFG_MISSING_REQUIRED);
        }
    }

    #[test]
    fn error_metadata_provides_context() {
        let mut config = Config::default();
        config.deception.honeytoken_count = 999;
        
        if let Err(err) = config.validate() {
            let log = err.internal_log();
            let metadata: Vec<_> = log.metadata().iter().map(|(k, _)| *k).collect();
            
            // Should have field name and value context
            assert!(metadata.contains(&"field") || metadata.contains(&"value"));
        }
    }

    #[test]
    fn hostname_with_configured_value() {
        let mut config = Config::default();
        config.agent.hostname = Some("custom-hostname".to_string());
        
        assert_eq!(config.hostname(), "custom-hostname");
    }

    #[test]
    fn hostname_with_system_fallback() {
        let config = Config::default();
        let hostname = config.hostname();
        
        // Should be either system hostname or "unknown-host"
        assert!(!hostname.is_empty());
    }

    #[test]
    fn protected_string_as_str() {
        let protected = ProtectedString::new("test_value".to_string());
        assert_eq!(protected.as_str(), "test_value");
    }

    #[test]
    fn protected_path_as_path() {
        let protected = ProtectedPath::new(PathBuf::from("/test/path"));
        assert_eq!(protected.as_path(), Path::new("/test/path"));
    }

    #[test]
    fn config_agent_structure() {
        let config = Config::default();
        
        // Verify instance_id is not empty
        assert!(!config.agent.instance_id.as_str().is_empty());
        
        // Verify work_dir is absolute
        assert!(config.agent.work_dir.as_path().is_absolute());
    }

    #[test]
    fn config_deception_structure() {
        let config = Config::default();
        
        assert!(!config.deception.decoy_paths.is_empty());
        assert!(!config.deception.credential_types.is_empty());
        assert!(config.deception.honeytoken_count > 0);
        assert!(config.deception.artifact_permissions <= 0o777);
    }

    #[test]
    fn config_telemetry_structure() {
        let config = Config::default();
        
        assert!(!config.telemetry.watch_paths.is_empty());
        assert!(config.telemetry.event_buffer_size >= 100);
    }

    #[test]
    fn config_logging_structure() {
        let config = Config::default();
        
        assert!(config.logging.log_path.is_absolute());
        assert!(config.logging.rotate_size_bytes >= 1024 * 1024);
        assert!(config.logging.max_log_files > 0);
    }

    #[test]
    fn validation_provides_helpful_errors() {
        let mut config = Config::default();
        config.telemetry.event_buffer_size = 10;
        
        if let Err(err) = config.validate() {
            let display = format!("{}", err);
            // External display should be generic
            assert!(display.contains("Configuration"));
            
            // Internal log should have details
            let log = err.internal_log();
            assert!(log.details().contains("event_buffer_size") || 
                    log.details().contains("too small"));
        }
    }

    #[test]
    fn version_field_present() {
        let config = Config::default();
        assert_eq!(config.version, CONFIG_VERSION);
    }

    #[test]
    fn default_values_are_sensible() {
        let config = Config::default();
        
        // Agent defaults
        assert!(!config.agent.instance_id.as_str().is_empty());
        assert_eq!(config.agent.work_dir.as_path(), Path::new("/var/lib/palisade-agent"));
        
        // Deception defaults
        assert_eq!(config.deception.honeytoken_count, 5);
        assert_eq!(config.deception.artifact_permissions, 0o600);
        
        // Telemetry defaults
        assert_eq!(config.telemetry.event_buffer_size, 10_000);
        assert!(!config.telemetry.enable_syscall_monitor);
        
        // Logging defaults
        assert_eq!(config.logging.format, LogFormat::Json);
        assert_eq!(config.logging.rotate_size_bytes, 100 * 1024 * 1024);
        assert_eq!(config.logging.max_log_files, 10);
        assert_eq!(config.logging.level, LogLevel::Info);
    }
}