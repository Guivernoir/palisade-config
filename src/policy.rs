//! Policy configuration for honeypot decision-making.

use crate::defaults::{
    default_alert_threshold, default_ancestry_suspicious_weight, default_artifact_access_weight,
    default_business_hours_end, default_business_hours_start, default_cooldown,
    default_correlation_window, default_max_events, default_max_kills, default_off_hours_weight,
    default_policy_version, default_rapid_enum_weight, default_suspicious_process_weight,
    default_true,
};
use crate::secure_fs::{RestrictedInputKind, read_restricted_file};
use crate::timing::{TimingOperation, enforce_operation_min_timing};
use crate::{AgentError, POLICY_VERSION, Result};
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::time::Instant;

const CFG_PARSE_FAILED: u16 = 100;
const CFG_VALIDATION_FAILED: u16 = 101;
const CFG_MISSING_REQUIRED: u16 = 102;
const CFG_INVALID_VALUE: u16 = 103;
const CFG_VERSION_MISMATCH: u16 = 106;
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
    MinConfidence {
        /// Minimum confidence score required for the condition to match.
        threshold: f64,
    },

    /// Process must not be child of specific parent
    NotParentedBy {
        /// Parent process name that disqualifies the action when matched.
        process_name: String,
    },

    /// Incident must involve multiple distinct signals
    MinSignalTypes {
        /// Minimum number of distinct signals required for the condition to match.
        count: usize,
    },

    /// Repeated incidents within time window
    RepeatCount {
        /// Minimum number of repeated incidents required within the time window.
        count: usize,
        /// Window size, in seconds, used for the repeat-count check.
        window_secs: u64,
    },

    /// Current time must be within window (24-hour clock)
    TimeWindow {
        /// Inclusive start hour for the allowed 24-hour window.
        start_hour: u8,
        /// Exclusive end hour for the allowed 24-hour window.
        end_hour: u8,
    },

    /// Custom condition (MUST be pre-registered)
    Custom {
        /// Registered custom-condition identifier.
        name: String,
        /// String parameters passed to the custom-condition evaluator.
        params: HashMap<String, String>,
    },
}

/// Incident severity level.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
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
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
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
    CustomScript {
        /// Absolute path to the custom script to execute.
        path: PathBuf,
    },
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
fn deserialize_lowercase_boxed<'de, D>(
    deserializer: D,
) -> std::result::Result<Box<[String]>, D::Error>
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
        let started = Instant::now();
        let path = path.as_ref();
        let result = async {
            let contents = read_restricted_file(path, RestrictedInputKind::Policy).await?;
            Self::from_toml_str(&contents)
        }
        .await;
        enforce_operation_min_timing(started, TimingOperation::PolicyLoad);
        result
    }

    pub(crate) fn from_toml_str(contents: &str) -> Result<Self> {
        let policy: PolicyConfig = toml::from_str(contents).map_err(|e| {
            AgentError::new(
                CFG_PARSE_FAILED,
                "Configuration input could not be parsed",
                format!("operation=parse_policy_toml; Policy TOML syntax error: {e}"),
                "",
            )
        })?;

        if policy.version > POLICY_VERSION {
            return Err(AgentError::new(
                CFG_VERSION_MISMATCH,
                "Configuration version is not supported",
                format!(
                    "operation=validate_policy_version; Policy version too new (agent: {POLICY_VERSION}, policy: {}). Upgrade agent; file_version={}; expected_version={POLICY_VERSION}",
                    policy.version, policy.version
                ),
                "",
            ));
        }

        policy.validate()?;
        Ok(policy)
    }

    /// Validate policy configuration.
    pub fn validate(&self) -> Result<()> {
        let started = Instant::now();
        let result = (|| {
            // Validate scoring policy
            if !(0.0..=100.0).contains(&self.scoring.alert_threshold) {
                return Err(AgentError::new(
                    CFG_INVALID_VALUE,
                    "Configuration contains an invalid value",
                    format!(
                        "operation=validate_policy_scoring; field=scoring.alert_threshold; reason=scoring.alert_threshold must be within valid range; actual_value={}; expected_range=0-100",
                        self.scoring.alert_threshold
                    ),
                    "scoring.alert_threshold",
                ));
            }

            if self.scoring.correlation_window_secs == 0
                || self.scoring.correlation_window_secs > 3600
            {
                return Err(AgentError::new(
                    CFG_INVALID_VALUE,
                    "Configuration contains an invalid value",
                    format!(
                        "operation=validate_policy_scoring; field=scoring.correlation_window_secs; reason=scoring.correlation_window_secs must be within valid range; actual_value={}; expected_range=1-3600",
                        self.scoring.correlation_window_secs
                    ),
                    "scoring.correlation_window_secs",
                ));
            }

            // CRITICAL: Prevent memory exhaustion and invalid zero-capacity buffers.
            if self.scoring.max_events_in_memory == 0 || self.scoring.max_events_in_memory > 100_000
            {
                return Err(AgentError::new(
                    CFG_INVALID_VALUE,
                    "Configuration contains an invalid value",
                    format!(
                        "operation=validate_policy_scoring; field=scoring.max_events_in_memory; reason=scoring.max_events_in_memory must be within valid range; actual_value={}; expected_range=1-100000",
                        self.scoring.max_events_in_memory
                    ),
                    "scoring.max_events_in_memory",
                ));
            }

            // Validate response policy
            if self.response.rules.is_empty() {
                return Err(AgentError::new(
                    CFG_MISSING_REQUIRED,
                    "Required configuration is missing",
                    "operation=validate_policy_response; response.rules cannot be empty; impact=no_response_actions",
                    "response.rules",
                ));
            }

            if self.response.cooldown_secs == 0 {
                return Err(AgentError::new(
                    CFG_INVALID_VALUE,
                    "Configuration contains an invalid value",
                    "operation=validate_policy_response; field=response.cooldown_secs; response.cooldown_secs cannot be zero",
                    "response.cooldown_secs",
                ));
            }

            // Check for duplicate severity mappings
            for idx in 0..self.response.rules.len() {
                for prev in 0..idx {
                    if self.response.rules[idx].severity == self.response.rules[prev].severity {
                        return Err(AgentError::new(
                            CFG_VALIDATION_FAILED,
                            "Configuration validation failed",
                            format!(
                                "operation=validate_policy; Duplicate response rule for severity: {}",
                                self.response.rules[idx].severity
                            ),
                            "",
                        ));
                    }
                }

                let rule = &self.response.rules[idx];

                // Validate custom conditions against whitelist
                for condition in &rule.conditions {
                    if let ResponseCondition::Custom { name, .. } = condition
                        && !self.registered_custom_conditions.contains(name)
                    {
                        return Err(AgentError::new(
                            CFG_VALIDATION_FAILED,
                            "Configuration validation failed",
                            format!(
                                "operation=validate_policy; Custom condition '{name}' not in registered_custom_conditions. Register it to prevent policy injection attacks."
                            ),
                            "",
                        ));
                    }
                }
            }

            Ok(())
        })();
        enforce_operation_min_timing(started, TimingOperation::PolicyValidate);
        result
    }

    /// Check if process name is suspicious (case-insensitive, optimized hot path).
    ///
    /// PERFORMANCE: This is called on EVERY process access event (thousands/sec under attack).
    /// Uses case-insensitive contains without allocation via iterator chaining.
    #[inline]
    #[must_use]
    pub fn is_suspicious_process(&self, name: &str) -> bool {
        let started = Instant::now();
        let found = self
            .deception
            .suspicious_processes
            .iter()
            .any(|pattern| contains_ascii_case_insensitive(name, pattern.as_str()));
        enforce_operation_min_timing(started, TimingOperation::PolicySuspiciousCheckLegacy);
        found
    }
}

#[inline]
fn contains_ascii_case_insensitive(haystack: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return true;
    }
    let h = haystack.as_bytes();
    let n = needle.as_bytes();
    if n.len() > h.len() {
        return false;
    }
    for start in 0..=(h.len() - n.len()) {
        let mut matched = true;
        for i in 0..n.len() {
            if !h[start + i].eq_ignore_ascii_case(&n[i]) {
                matched = false;
                break;
            }
        }
        if matched {
            return true;
        }
    }
    false
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
        policy
            .response
            .rules
            .retain(|r| r.severity != Severity::Medium);

        policy.response.rules.push(ResponseRule {
            severity: Severity::Medium,
            conditions: vec![ResponseCondition::Custom {
                name: "unregistered".to_string(),
                params: HashMap::new(),
            }],
            action: ActionType::Log,
        });

        assert!(policy.validate().is_err());

        policy
            .registered_custom_conditions
            .insert("unregistered".to_string());
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
