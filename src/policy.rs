//! Policy configuration for honeypot decision-making.
//!
//! This module defines the **decision plane** of your security operation:
//! - WHEN to alert (thresholds, scoring)
//! - HOW to respond (actions, conditions)
//! - WHICH behaviors are suspicious
//!
//! This does NOT define infrastructure (see [`crate::config`]).
//!
//! # Policy vs Configuration
//!
//! - **Policy:** Hot-reloadable, defines behavior and detection
//! - **Config:** Requires deployment, defines infrastructure
//!
//! This separation enables:
//! - Blue team governance without infrastructure changes
//! - A/B testing of detection strategies
//! - Environment-specific tuning (dev vs prod)
//!
//! # Example
//!
//! ```rust
//! use palisade_config::PolicyConfig;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Load policy
//! let policy = PolicyConfig::from_file("/etc/honeypot/policy.toml")?;
//!
//! // Check if process is suspicious (zero-allocation)
//! if policy.is_suspicious_process("mimikatz.exe") {
//!     println!("Threat detected!");
//! }
//!
//! // Get alert threshold
//! println!("Alert threshold: {}", policy.scoring.alert_threshold);
//! # Ok(())
//! # }
//! ```

use crate::defaults::*;
use crate::POLICY_VERSION;
use palisade_errors::{definitions, AgentError, Result};
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

/// Policy configuration - the DECISION PLANE of your security operation.
///
/// Defines behavioral concerns:
/// - Scoring weights and alert thresholds
/// - Response rules and conditions
/// - Suspicious process patterns
/// - Time-based scoring adjustments
///
/// For infrastructure (paths, buffers), see [`Config`](crate::Config).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConfig {
    /// Policy schema version
    #[serde(default = "default_policy_version")]
    pub version: u32,

    /// Scoring configuration
    pub scoring: ScoringPolicy,

    /// Response configuration
    pub response: ResponsePolicy,

    /// Deception detection patterns
    pub deception: DeceptionPolicy,

    /// Registered custom condition handlers (for validation)
    ///
    /// SECURITY: Custom conditions must be pre-registered to prevent
    /// policy injection attacks. Only registered names are allowed.
    #[serde(default)]
    pub registered_custom_conditions: HashSet<String>,
}

/// Scoring policy for threat assessment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoringPolicy {
    /// Time window for event correlation (seconds)
    #[serde(default = "default_correlation_window")]
    pub correlation_window_secs: u64,

    /// Confidence score threshold for alerting
    #[serde(default = "default_alert_threshold")]
    pub alert_threshold: f64,

    /// Maximum events to retain in correlation window
    #[serde(default = "default_max_events")]
    pub max_events_in_memory: usize,

    /// Enable time-of-day scoring adjustments
    #[serde(default = "default_true")]
    pub enable_time_scoring: bool,

    /// Enable process ancestry tracking
    #[serde(default = "default_true")]
    pub enable_ancestry_tracking: bool,

    /// Scoring weights for different signal types
    #[serde(default)]
    pub weights: ScoringWeights,

    /// Business hours start (24-hour format)
    #[serde(default = "default_business_hours_start")]
    pub business_hours_start: u8,

    /// Business hours end (24-hour format)
    #[serde(default = "default_business_hours_end")]
    pub business_hours_end: u8,
}

/// Scoring weights for threat signals.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoringWeights {
    /// Base score for accessing deception artifact
    #[serde(default = "default_artifact_access_weight")]
    pub artifact_access: f64,

    /// Additional score for suspicious process name
    #[serde(default = "default_suspicious_process_weight")]
    pub suspicious_process: f64,

    /// Additional score for rapid enumeration
    #[serde(default = "default_rapid_enum_weight")]
    pub rapid_enumeration: f64,

    /// Additional score for off-hours activity
    #[serde(default = "default_off_hours_weight")]
    pub off_hours_activity: f64,

    /// Additional score for suspicious process ancestry
    #[serde(default = "default_ancestry_suspicious_weight")]
    pub ancestry_suspicious: f64,
}

impl Default for ScoringWeights {
    fn default() -> Self {
        Self {
            artifact_access: 50.0,
            suspicious_process: 30.0,
            rapid_enumeration: 20.0,
            off_hours_activity: 15.0,
            ancestry_suspicious: 10.0,
        }
    }
}

/// Response policy for incident handling.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponsePolicy {
    /// Response rules with conditions
    pub rules: Vec<ResponseRule>,

    /// Minimum time between responses (prevents alert storms)
    #[serde(default = "default_cooldown")]
    pub cooldown_secs: u64,

    /// Maximum processes to kill per incident (safety limit)
    #[serde(default = "default_max_kills")]
    pub max_kills_per_incident: usize,

    /// Dry-run mode (log actions but don't execute)
    #[serde(default)]
    pub dry_run: bool,
}

/// Response rule with conditional execution.
///
/// Enables context-aware responses:
/// - "Kill process ONLY IF not parented by systemd"
/// - "Isolate host ONLY IF confidence > 90 AND multiple signals"
/// - "Alert ONLY IF not during maintenance window"
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseRule {
    /// Severity level that triggers this rule
    pub severity: Severity,

    /// Conditions that must ALL be satisfied (AND logic)
    #[serde(default)]
    pub conditions: Vec<ResponseCondition>,

    /// Action to execute
    pub action: ActionType,
}

/// Response execution conditions.
///
/// SECURITY NOTE: Custom conditions are an extensibility point but also
/// a potential policy injection surface. See validation in [`PolicyConfig::validate`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ResponseCondition {
    /// Confidence score must exceed threshold
    MinConfidence { threshold: f64 },

    /// Process must not be child of specific parent
    NotParentedBy { process_name: String },

    /// Incident must involve multiple distinct signals
    MinSignalTypes { count: usize },

    /// Repeated incidents within time window
    RepeatCount { count: usize, window_secs: u64 },

    /// Current time must be within window (24-hour clock)
    TimeWindow { start_hour: u8, end_hour: u8 },

    /// Custom condition (MUST be pre-registered)
    ///
    /// SECURITY: To prevent policy injection attacks:
    /// 1. Only registered condition names are allowed
    /// 2. Validation fails if name not in registered_custom_conditions
    /// 3. Consider feature-gating if paranoid
    Custom {
        name: String,
        params: HashMap<String, String>,
    },
}

/// Incident severity level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum Severity {
    /// Low severity (informational)
    Low,
    /// Medium severity (warning)
    Medium,
    /// High severity (critical)
    High,
    /// Critical severity (emergency)
    Critical,
}

impl Severity {
    /// Determine severity from confidence score.
    ///
    /// # Mapping
    ///
    /// - `score >= 80.0` → Critical
    /// - `score >= 60.0` → High
    /// - `score >= 40.0` → Medium
    /// - `score < 40.0` → Low
    #[must_use]
    pub fn from_score(score: f64) -> Self {
        if score >= 80.0 {
            Self::Critical
        } else if score >= 60.0 {
            Self::High
        } else if score >= 40.0 {
            Self::Medium
        } else {
            Self::Low
        }
    }
}

/// Action type for incident response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionType {
    /// Log the incident
    Log,
    /// Send alert to monitoring system
    Alert,
    /// Terminate the offending process
    KillProcess,
    /// Isolate the host from network
    IsolateHost,
    /// Execute custom script
    CustomScript { path: PathBuf },
}

/// Deception detection policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeceptionPolicy {
    /// Process names that trigger elevated scoring (pre-normalized to lowercase)
    ///
    /// PERFORMANCE: Stored lowercase for zero-allocation matching at runtime.
    #[serde(default, deserialize_with = "deserialize_lowercase_vec")]
    pub suspicious_processes: Vec<String>,

    /// File patterns that indicate reconnaissance
    #[serde(default)]
    pub suspicious_patterns: Vec<String>,
}

/// Deserialize Vec<String> and normalize to lowercase for efficient matching.
fn deserialize_lowercase_vec<'de, D>(deserializer: D) -> std::result::Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let vec = Vec::<String>::deserialize(deserializer)?;
    Ok(vec.into_iter().map(|s| s.to_lowercase()).collect())
}

impl PolicyConfig {
    /// Load policy from TOML file.
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - File cannot be read
    /// - TOML syntax invalid
    /// - Version incompatible
    /// - Validation fails
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use palisade_config::PolicyConfig;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let policy = PolicyConfig::from_file("/etc/honeypot/policy.toml")?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();
        let path_str = path.display().to_string();

        let contents = std::fs::read_to_string(path).map_err(|e| {
            AgentError::from_io_path(
                definitions::IO_READ_FAILED,
                "load_policy",
                path_str,
                e,
            ).with_obfuscation()
        })?;

        let policy: PolicyConfig = toml::from_str(&contents).map_err(|e| {
            AgentError::config(
                definitions::CFG_PARSE_FAILED,
                "parse_policy_toml",
                format!("Policy TOML syntax error: {}", e),
            ).with_obfuscation()
        })?;

        // Version validation (symmetric with config)
        if policy.version > POLICY_VERSION {
            return Err(AgentError::config(
                definitions::CFG_VALIDATION_FAILED,
                "validate_policy_version",
                format!(
                    "Policy version too new (agent: {}, policy: {}). Upgrade agent",
                    POLICY_VERSION, policy.version
                ),
            ).with_obfuscation());
        }

        if policy.version < POLICY_VERSION {
            eprintln!(
                "WARNING: Policy version is older (policy: {}, agent: {}). Consider updating.",
                policy.version, POLICY_VERSION
            );
        }

        policy.validate()?;

        Ok(policy)
    }

    /// Validate policy configuration.
    ///
    /// # Validation Checks
    ///
    /// - Scoring: thresholds in valid ranges
    /// - Response: rules not empty, no duplicate severities
    /// - Custom conditions: all registered
    ///
    /// # Errors
    ///
    /// Returns error if any validation check fails.
    pub fn validate(&self) -> Result<()> {
        // Validate scoring policy
        if !(0.0..=100.0).contains(&self.scoring.alert_threshold) {
            return Err(AgentError::config(
                definitions::CFG_INVALID_VALUE,
                "validate_policy",
                "scoring.alert_threshold must be 0-100",
            ).with_obfuscation());
        }

        if self.scoring.correlation_window_secs == 0
            || self.scoring.correlation_window_secs > 3600
        {
            return Err(AgentError::config(
                definitions::CFG_INVALID_VALUE,
                "validate_policy",
                "scoring.correlation_window_secs must be 1-3600",
            ).with_obfuscation());
        }

        // Validate response policy
        if self.response.rules.is_empty() {
            return Err(AgentError::config(
                definitions::CFG_MISSING_REQUIRED,
                "validate_policy",
                "response.rules cannot be empty",
            ).with_obfuscation());
        }

        if self.response.cooldown_secs == 0 {
            return Err(AgentError::config(
                definitions::CFG_INVALID_VALUE,
                "validate_policy",
                "response.cooldown_secs cannot be zero",
            ).with_obfuscation());
        }

        // Check for duplicate severity mappings
        let mut seen = HashSet::new();
        for rule in &self.response.rules {
            if !seen.insert(rule.severity) {
                return Err(AgentError::config(
                    definitions::CFG_VALIDATION_FAILED,
                    "validate_policy",
                    format!("Duplicate response rule for severity: {:?}", rule.severity),
                ).with_obfuscation());
            }

            // CRITICAL: Validate custom conditions against whitelist
            for condition in &rule.conditions {
                if let ResponseCondition::Custom { name, .. } = condition {
                    if !self.registered_custom_conditions.contains(name) {
                        return Err(AgentError::config(
                            definitions::CFG_VALIDATION_FAILED,
                            "validate_policy",
                            format!(
                                "Custom condition '{}' not in registered_custom_conditions. \
                                 Register it to prevent policy injection attacks.",
                                name
                            ),
                        ).with_obfuscation());
                    }
                }
            }
        }

        Ok(())
    }

    /// Check if process name is suspicious (optimized, zero-allocation hot path).
    ///
    /// PERFORMANCE: suspicious_processes pre-normalized to lowercase at load time.
    /// This function only allocates once (for input conversion), then scans.
    ///
    /// # Example
    ///
    /// ```rust
    /// use palisade_config::PolicyConfig;
    ///
    /// let policy = PolicyConfig::default();
    ///
    /// assert!(policy.is_suspicious_process("MIMIKATZ.exe"));
    /// assert!(policy.is_suspicious_process("mimikatz"));
    /// assert!(!policy.is_suspicious_process("firefox"));
    /// ```
    #[inline]
    #[must_use]
    pub fn is_suspicious_process(&self, name: &str) -> bool {
        // Convert input to lowercase (single allocation)
        let name_lower = name.to_lowercase();

        // Scan pre-normalized patterns (no allocations)
        self.deception
            .suspicious_processes
            .iter()
            .any(|pattern| name_lower.contains(pattern))
    }
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            version: POLICY_VERSION,
            scoring: ScoringPolicy {
                correlation_window_secs: 300,
                alert_threshold: 50.0,
                max_events_in_memory: 10_000,
                enable_time_scoring: true,
                enable_ancestry_tracking: true,
                weights: ScoringWeights::default(),
                business_hours_start: 9,
                business_hours_end: 17,
            },
            response: ResponsePolicy {
                rules: vec![
                    ResponseRule {
                        severity: Severity::Low,
                        conditions: vec![],
                        action: ActionType::Log,
                    },
                    ResponseRule {
                        severity: Severity::Medium,
                        conditions: vec![],
                        action: ActionType::Alert,
                    },
                    ResponseRule {
                        severity: Severity::High,
                        conditions: vec![ResponseCondition::MinConfidence { threshold: 70.0 }],
                        action: ActionType::KillProcess,
                    },
                    ResponseRule {
                        severity: Severity::Critical,
                        conditions: vec![
                            ResponseCondition::MinConfidence { threshold: 85.0 },
                            ResponseCondition::MinSignalTypes { count: 2 },
                        ],
                        action: ActionType::IsolateHost,
                    },
                ],
                cooldown_secs: 60,
                max_kills_per_incident: 10,
                dry_run: false,
            },
            deception: DeceptionPolicy {
                suspicious_processes: vec![
                    "mimikatz".to_string(),
                    "procdump".to_string(),
                    "lazagne".to_string(),
                ],
                suspicious_patterns: vec![],
            },
            registered_custom_conditions: HashSet::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_policy_validates() {
        let policy = PolicyConfig::default();
        assert!(policy.validate().is_ok());
    }

    #[test]
    fn test_severity_from_score() {
        assert_eq!(Severity::from_score(90.0), Severity::Critical);
        assert_eq!(Severity::from_score(70.0), Severity::High);
        assert_eq!(Severity::from_score(50.0), Severity::Medium);
        assert_eq!(Severity::from_score(30.0), Severity::Low);
    }

    #[test]
    fn test_suspicious_process_zero_alloc() {
        let policy = PolicyConfig::default();

        // Only one allocation (name.to_lowercase())
        assert!(policy.is_suspicious_process("MIMIKATZ.exe"));
        assert!(policy.is_suspicious_process("mimikatz"));
        assert!(!policy.is_suspicious_process("firefox"));
    }

    #[test]
    fn test_custom_condition_validation() {
        let mut policy = PolicyConfig::default();

        // Remove existing Medium rule to avoid duplicate severity
        policy.response.rules.retain(|r| r.severity != Severity::Medium);

        // Add rule with unregistered custom condition (using Medium severity)
        policy.response.rules.push(ResponseRule {
            severity: Severity::Medium,
            conditions: vec![ResponseCondition::Custom {
                name: "unregistered".to_string(),
                params: HashMap::new(),
            }],
            action: ActionType::Log,
        });

        // Should fail validation (unregistered custom condition)
        assert!(policy.validate().is_err());

        // Register the condition
        policy
            .registered_custom_conditions
            .insert("unregistered".to_string());

        // Should now pass
        assert!(policy.validate().is_ok());
    }

    #[test]
    fn test_validation_catches_invalid_threshold() {
        let mut policy = PolicyConfig::default();
        policy.scoring.alert_threshold = 150.0;
        assert!(policy.validate().is_err());
    }

    #[test]
    fn test_validation_catches_duplicate_severity() {
        let mut policy = PolicyConfig::default();
        policy.response.rules.push(ResponseRule {
            severity: Severity::Low,
            conditions: vec![],
            action: ActionType::Alert,
        });
        assert!(policy.validate().is_err());
    }
}