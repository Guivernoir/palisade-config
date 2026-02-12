//! Policy configuration for honeypot decision-making.

use crate::defaults::*;
use crate::errors::{self, PolicyValidationError, RangeValidationError};
use crate::POLICY_VERSION;
use palisade_errors::Result;
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

/// Policy configuration - the DECISION PLANE of your security operation.
#[derive(Debug, Serialize, Deserialize)]
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
    #[serde(default)]
    pub registered_custom_conditions: HashSet<String>,
}

/// Scoring policy for threat assessment.
#[derive(Debug, Serialize, Deserialize)]
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
#[derive(Debug, Serialize, Deserialize)]
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
#[derive(Debug, Serialize, Deserialize)]
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
#[derive(Debug, Serialize, Deserialize)]
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
#[derive(Debug, Serialize, Deserialize)]
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

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Low => write!(f, "Low"),
            Self::Medium => write!(f, "Medium"),
            Self::High => write!(f, "High"),
            Self::Critical => write!(f, "Critical"),
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
#[derive(Debug, Serialize, Deserialize)]
pub struct DeceptionPolicy {
    /// Process names that trigger elevated scoring (pre-normalized to lowercase, immutable)
    #[serde(default, deserialize_with = "deserialize_lowercase_boxed")]
    pub suspicious_processes: Box<[String]>,

    /// File patterns that indicate reconnaissance (immutable)
    #[serde(default, deserialize_with = "deserialize_boxed")]
    pub suspicious_patterns: Box<[String]>,
}

/// Deserialize Vec<String>, normalize to lowercase, and convert to Box<[String]> for memory efficiency.
fn deserialize_lowercase_boxed<'de, D>(deserializer: D) -> std::result::Result<Box<[String]>, D::Error>
where
    D: Deserializer<'de>,
{
    let vec = Vec::<String>::deserialize(deserializer)?;
    Ok(vec.into_iter().map(|s| s.to_lowercase()).collect())
}

/// Deserialize Vec<String> and convert to Box<[String]> for memory efficiency.
fn deserialize_boxed<'de, D>(deserializer: D) -> std::result::Result<Box<[String]>, D::Error>
where
    D: Deserializer<'de>,
{
    let vec = Vec::<String>::deserialize(deserializer)?;
    Ok(vec.into_boxed_slice())
}

impl PolicyConfig {
    /// Load policy from TOML file (async to prevent thread exhaustion attacks).
    ///
    /// # Errors
    ///
    /// Returns error if file cannot be read, TOML is invalid, or validation fails.
    pub async fn from_file<P: AsRef<std::path::Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();

        let contents = tokio::fs::read_to_string(path).await
            .map_err(|e| errors::io_read_error("load_policy", path, e))?;

        let policy: PolicyConfig = toml::from_str(&contents)
            .map_err(|e| errors::parse_error("parse_policy_toml", format!("Policy TOML syntax error: {}", e)))?;

        // Version validation
        if policy.version > POLICY_VERSION {
            return Err(errors::version_error(
                "validate_policy_version",
                policy.version,
                POLICY_VERSION,
                format!(
                    "Policy version too new (agent: {}, policy: {}). Upgrade agent",
                    POLICY_VERSION, policy.version
                ),
            ));
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
    pub fn validate(&self) -> Result<()> {
        // Validate scoring policy
        if !(0.0..=100.0).contains(&self.scoring.alert_threshold) {
            return Err(RangeValidationError::out_of_range(
                "scoring.alert_threshold",
                self.scoring.alert_threshold,
                0.0,
                100.0,
                "validate_policy_scoring",
            ));
        }

        if self.scoring.correlation_window_secs == 0 || self.scoring.correlation_window_secs > 3600 {
            return Err(RangeValidationError::out_of_range(
                "scoring.correlation_window_secs",
                self.scoring.correlation_window_secs,
                1,
                3600,
                "validate_policy_scoring",
            ));
        }

        // CRITICAL: Prevent memory exhaustion attacks via unbounded event buffer
        if self.scoring.max_events_in_memory > 100_000 {
            return Err(RangeValidationError::out_of_range(
                "scoring.max_events_in_memory",
                self.scoring.max_events_in_memory,
                1,
                100_000,
                "validate_policy_scoring",
            ));
        }

        // Validate response policy
        if self.response.rules.is_empty() {
            return Err(errors::missing_required(
                "validate_policy_response",
                "response.rules",
                "no_response_actions",
            ));
        }

        if self.response.cooldown_secs == 0 {
            return Err(errors::invalid_value(
                "validate_policy_response",
                "response.cooldown_secs",
                "response.cooldown_secs cannot be zero",
            ));
        }

        // Check for duplicate severity mappings
        let mut seen = HashSet::new();
        for rule in &self.response.rules {
            if !seen.insert(rule.severity) {
                return Err(PolicyValidationError::duplicate_severity(&rule.severity.to_string()));
            }

            // Validate custom conditions against whitelist
            for condition in &rule.conditions {
                if let ResponseCondition::Custom { name, .. } = condition {
                    if !self.registered_custom_conditions.contains(name) {
                        return Err(PolicyValidationError::unregistered_condition(name));
                    }
                }
            }
        }

        Ok(())
    }

    /// Check if process name is suspicious (case-insensitive, optimized hot path).
    ///
    /// PERFORMANCE: This is called on EVERY process access event (thousands/sec under attack).
    /// Uses case-insensitive contains without allocation via iterator chaining.
    #[inline]
    #[must_use]
    pub fn is_suspicious_process(&self, name: &str) -> bool {
        // Convert to lowercase only once per character during comparison
        // Patterns are pre-lowercased during deserialization
        let name_lower = name.to_ascii_lowercase();
        self.deception
            .suspicious_processes
            .iter()
            .any(|pattern| name_lower.contains(pattern.as_str()))
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
                ]
                .into_boxed_slice(),
                suspicious_patterns: Box::new([]),
            },
            registered_custom_conditions: HashSet::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_default_policy_validates() {
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
    fn test_suspicious_process_case_insensitive() {
        let policy = PolicyConfig::default();

        assert!(policy.is_suspicious_process("MIMIKATZ.exe"));
        assert!(policy.is_suspicious_process("mimikatz"));
        assert!(policy.is_suspicious_process("MiMiKaTz"));
        assert!(!policy.is_suspicious_process("firefox"));
    }

    #[test]
    fn test_custom_condition_validation() {
        let mut policy = PolicyConfig::default();
        policy.response.rules.retain(|r| r.severity != Severity::Medium);

        policy.response.rules.push(ResponseRule {
            severity: Severity::Medium,
            conditions: vec![ResponseCondition::Custom {
                name: "unregistered".to_string(),
                params: HashMap::new(),
            }],
            action: ActionType::Log,
        });

        assert!(policy.validate().is_err());

        policy.registered_custom_conditions.insert("unregistered".to_string());
        assert!(policy.validate().is_ok());
    }

    #[test]
    fn test_max_events_validation() {
        let mut policy = PolicyConfig::default();
        policy.scoring.max_events_in_memory = 150_000;
        assert!(policy.validate().is_err());

        policy.scoring.max_events_in_memory = 50_000;
        assert!(policy.validate().is_ok());
    }
}