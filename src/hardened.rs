//! Hardened fixed-capacity admission types for production runtime loading.

use crate::config::{LogFormat, LogLevel};
use crate::defaults::{
    default_alert_threshold, default_ancestry_suspicious_weight, default_artifact_access_weight,
    default_artifact_permissions, default_business_hours_end, default_business_hours_start,
    default_cooldown, default_correlation_window, default_event_buffer_size, default_honeytoken_count,
    default_log_format, default_log_level, default_max_events, default_max_kills,
    default_max_log_files, default_off_hours_weight, default_policy_version,
    default_rapid_enum_weight, default_rotate_size, default_suspicious_process_weight,
    default_true, default_version,
};
use crate::policy::Severity;
use crate::runtime::{
    MAX_CREDENTIAL_TYPES, MAX_CUSTOM_CONDITIONS, MAX_LABEL_LEN, MAX_PATH_ENTRIES, MAX_PATH_LEN,
    MAX_SUSPICIOUS_PATTERNS, MAX_SUSPICIOUS_PROCESSES, RuntimeConfig, RuntimePolicy,
};
use crate::tags::RootTag;
use crate::validation::ValidationMode;
use crate::{AgentError, CONFIG_VERSION, POLICY_VERSION, Result};
use heapless::{String as HString, Vec as HVec};
use serde::Deserialize;
use serde::de::IgnoredAny;

const CFG_PARSE_FAILED: u16 = 100;
const CFG_VALIDATION_FAILED: u16 = 101;
const CFG_MISSING_REQUIRED: u16 = 102;
const CFG_INVALID_VALUE: u16 = 103;
const CFG_VERSION_MISMATCH: u16 = 106;

const MAX_RESPONSE_RULES: usize = 32;
const MAX_RULE_CONDITIONS: usize = 8;
const MAX_ENV_LEN: usize = 32;
const MAX_FILE_BYTES: usize = 16 * 1024;
const MAX_POLICY_FILE_BYTES: usize = 32 * 1024;

pub(crate) const MAX_HARDENED_CONFIG_BYTES: usize = MAX_FILE_BYTES;
pub(crate) const MAX_HARDENED_POLICY_BYTES: usize = MAX_POLICY_FILE_BYTES;

/// Fixed-capacity admitted configuration for hardened runtime loading.
#[derive(Debug, Deserialize)]
pub struct HardenedConfig {
    #[serde(default = "default_version")]
    version: u32,
    agent: HardenedAgentConfig,
    deception: HardenedDeceptionConfig,
    telemetry: HardenedTelemetryConfig,
    logging: HardenedLoggingConfig,
}

#[derive(Debug, Deserialize)]
struct HardenedAgentConfig {
    instance_id: HString<MAX_LABEL_LEN>,
    work_dir: HString<MAX_PATH_LEN>,
    #[serde(default)]
    environment: Option<HString<MAX_ENV_LEN>>,
    hostname: HString<MAX_LABEL_LEN>,
}

#[derive(Debug, Deserialize)]
struct HardenedDeceptionConfig {
    #[serde(default)]
    decoy_paths: HVec<HString<MAX_PATH_LEN>, MAX_PATH_ENTRIES>,
    #[serde(default)]
    credential_types: HVec<HString<MAX_LABEL_LEN>, MAX_CREDENTIAL_TYPES>,
    #[serde(default = "default_honeytoken_count")]
    honeytoken_count: usize,
    root_tag: RootTag,
    #[serde(default = "default_artifact_permissions")]
    artifact_permissions: u32,
}

#[derive(Debug, Deserialize)]
struct HardenedTelemetryConfig {
    #[serde(default)]
    watch_paths: HVec<HString<MAX_PATH_LEN>, MAX_PATH_ENTRIES>,
    #[serde(default = "default_event_buffer_size")]
    event_buffer_size: usize,
    #[serde(default)]
    enable_syscall_monitor: bool,
}

#[derive(Debug, Deserialize)]
struct HardenedLoggingConfig {
    log_path: HString<MAX_PATH_LEN>,
    #[serde(default = "default_log_format")]
    format: LogFormat,
    #[serde(default = "default_rotate_size")]
    rotate_size_bytes: u64,
    #[serde(default = "default_max_log_files")]
    max_log_files: usize,
    #[serde(default = "default_log_level")]
    level: LogLevel,
}

impl HardenedConfig {
    pub(crate) fn from_str_with_mode(contents: &str, mode: &ValidationMode) -> Result<Self> {
        let config: Self = toml::from_str(contents).map_err(|error| {
            AgentError::new(
                CFG_PARSE_FAILED,
                "Configuration input could not be parsed",
                format!("operation=parse_hardened_config_toml; {error}"),
                "",
            )
        })?;

        config.validate(mode)?;
        Ok(config)
    }

    pub(crate) fn validate(&self, mode: &ValidationMode) -> Result<()> {
        if self.version != CONFIG_VERSION {
            return Err(AgentError::new(
                CFG_VERSION_MISMATCH,
                "Configuration version is not supported",
                "operation=validate_hardened_config_version; file_version mismatch",
                "",
            ));
        }

        if self.agent.instance_id.is_empty() {
            return Err(AgentError::new(
                CFG_MISSING_REQUIRED,
                "Required configuration is missing",
                "operation=validate_hardened_agent; agent.instance_id cannot be empty",
                "agent.instance_id",
            ));
        }

        if self.agent.hostname.is_empty() {
            return Err(AgentError::new(
                CFG_MISSING_REQUIRED,
                "Required configuration is missing",
                "operation=validate_hardened_agent; agent.hostname is required in hardened mode",
                "agent.hostname",
            ));
        }

        validate_absolute_path(self.agent.work_dir.as_str(), "agent.work_dir")?;

        if self.deception.decoy_paths.is_empty() {
            return Err(AgentError::new(
                CFG_MISSING_REQUIRED,
                "Required configuration is missing",
                "operation=validate_hardened_deception; deception.decoy_paths cannot be empty",
                "deception.decoy_paths",
            ));
        }

        for path in &self.deception.decoy_paths {
            validate_absolute_path(path.as_str(), "deception.decoy_paths")?;
            if matches!(mode, ValidationMode::Strict)
                && let Some(parent) = std::path::Path::new(path.as_str()).parent()
                && !parent.exists()
            {
                return Err(AgentError::new(
                    CFG_VALIDATION_FAILED,
                    "Configuration validation failed",
                    "operation=validate_hardened_deception; decoy path parent missing",
                    "deception.decoy_paths",
                ));
            }
        }

        if self.deception.credential_types.is_empty() {
            return Err(AgentError::new(
                CFG_MISSING_REQUIRED,
                "Required configuration is missing",
                "operation=validate_hardened_deception; deception.credential_types cannot be empty",
                "deception.credential_types",
            ));
        }

        if self.deception.honeytoken_count == 0 || self.deception.honeytoken_count > 100 {
            return Err(AgentError::new(
                CFG_INVALID_VALUE,
                "Configuration contains an invalid value",
                "operation=validate_hardened_deception; honeytoken_count out of range",
                "deception.honeytoken_count",
            ));
        }

        if self.deception.artifact_permissions > 0o777 {
            return Err(AgentError::new(
                CFG_INVALID_VALUE,
                "Configuration contains an invalid value",
                "operation=validate_hardened_deception; artifact_permissions out of range",
                "deception.artifact_permissions",
            ));
        }

        if self.telemetry.watch_paths.is_empty() {
            return Err(AgentError::new(
                CFG_MISSING_REQUIRED,
                "Required configuration is missing",
                "operation=validate_hardened_telemetry; telemetry.watch_paths cannot be empty",
                "telemetry.watch_paths",
            ));
        }

        for path in &self.telemetry.watch_paths {
            validate_absolute_path(path.as_str(), "telemetry.watch_paths")?;
            if matches!(mode, ValidationMode::Strict) && !std::path::Path::new(path.as_str()).exists()
            {
                return Err(AgentError::new(
                    CFG_VALIDATION_FAILED,
                    "Configuration validation failed",
                    "operation=validate_hardened_telemetry; watch path missing",
                    "telemetry.watch_paths",
                ));
            }
        }

        if self.telemetry.event_buffer_size < 100 {
            return Err(AgentError::new(
                CFG_INVALID_VALUE,
                "Configuration contains an invalid value",
                "operation=validate_hardened_telemetry; event_buffer_size below minimum",
                "telemetry.event_buffer_size",
            ));
        }

        validate_absolute_path(self.logging.log_path.as_str(), "logging.log_path")?;
        if matches!(mode, ValidationMode::Strict)
            && let Some(parent) = std::path::Path::new(self.logging.log_path.as_str()).parent()
            && !parent.exists()
        {
            return Err(AgentError::new(
                CFG_VALIDATION_FAILED,
                "Configuration validation failed",
                "operation=validate_hardened_logging; log path parent missing",
                "logging.log_path",
            ));
        }

        let _ = &self.agent.environment;
        let _ = self.logging.rotate_size_bytes;
        let _ = self.logging.max_log_files;
        let _ = &self.logging.level;
        let _ = &self.logging.format;
        let _ = self.telemetry.enable_syscall_monitor;

        Ok(())
    }

    /// Convert the admitted hardened configuration into the fixed-capacity runtime form.
    pub fn into_runtime(self) -> RuntimeConfig {
        let host_tag = self
            .deception
            .root_tag
            .derive_host_tag_bytes(self.agent.hostname.as_str());

        RuntimeConfig::from_parts(
            self.agent.hostname,
            host_tag,
            self.deception.decoy_paths,
            self.telemetry.watch_paths,
            self.deception.credential_types,
            self.deception.honeytoken_count,
            self.deception.artifact_permissions,
        )
    }
}

/// Fixed-capacity admitted policy for hardened runtime loading.
#[derive(Debug, Deserialize)]
pub struct HardenedPolicy {
    #[serde(default = "default_policy_version")]
    version: u32,
    scoring: HardenedScoringPolicy,
    response: HardenedResponsePolicy,
    deception: HardenedPolicyDeception,
    #[serde(default)]
    registered_custom_conditions: HVec<HString<MAX_LABEL_LEN>, MAX_CUSTOM_CONDITIONS>,
}

#[derive(Debug, Deserialize)]
struct HardenedScoringPolicy {
    #[serde(default = "default_correlation_window")]
    correlation_window_secs: u64,
    #[serde(default = "default_alert_threshold")]
    alert_threshold: f64,
    #[serde(default = "default_max_events")]
    max_events_in_memory: usize,
    #[serde(default = "default_true")]
    enable_time_scoring: bool,
    #[serde(default = "default_true")]
    enable_ancestry_tracking: bool,
    #[serde(default)]
    weights: HardenedScoringWeights,
    #[serde(default = "default_business_hours_start")]
    business_hours_start: u8,
    #[serde(default = "default_business_hours_end")]
    business_hours_end: u8,
}

#[derive(Debug, Deserialize)]
struct HardenedScoringWeights {
    #[serde(default = "default_artifact_access_weight")]
    artifact_access: f64,
    #[serde(default = "default_suspicious_process_weight")]
    suspicious_process: f64,
    #[serde(default = "default_rapid_enum_weight")]
    rapid_enumeration: f64,
    #[serde(default = "default_off_hours_weight")]
    off_hours_activity: f64,
    #[serde(default = "default_ancestry_suspicious_weight")]
    ancestry_suspicious: f64,
}

impl Default for HardenedScoringWeights {
    fn default() -> Self {
        Self {
            artifact_access: default_artifact_access_weight(),
            suspicious_process: default_suspicious_process_weight(),
            rapid_enumeration: default_rapid_enum_weight(),
            off_hours_activity: default_off_hours_weight(),
            ancestry_suspicious: default_ancestry_suspicious_weight(),
        }
    }
}

#[derive(Debug, Deserialize)]
struct HardenedResponsePolicy {
    rules: HVec<HardenedResponseRule, MAX_RESPONSE_RULES>,
    #[serde(default = "default_cooldown")]
    cooldown_secs: u64,
    #[serde(default = "default_max_kills")]
    max_kills_per_incident: usize,
    #[serde(default)]
    dry_run: bool,
}

#[derive(Debug, Deserialize)]
struct HardenedResponseRule {
    severity: Severity,
    #[serde(default)]
    conditions: HVec<HardenedResponseCondition, MAX_RULE_CONDITIONS>,
    action: HardenedActionType,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum HardenedActionType {
    Log,
    Alert,
    KillProcess,
    IsolateHost,
    CustomScript { path: HString<MAX_PATH_LEN> },
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum HardenedResponseCondition {
    MinConfidence { threshold: f64 },
    NotParentedBy { process_name: HString<MAX_LABEL_LEN> },
    MinSignalTypes { count: usize },
    RepeatCount { count: usize, window_secs: u64 },
    TimeWindow { start_hour: u8, end_hour: u8 },
    Custom {
        name: HString<MAX_LABEL_LEN>,
        #[serde(default)]
        params: Option<IgnoredAny>,
    },
}

#[derive(Debug, Deserialize)]
struct HardenedPolicyDeception {
    #[serde(default)]
    suspicious_processes: HVec<HString<MAX_LABEL_LEN>, MAX_SUSPICIOUS_PROCESSES>,
    #[serde(default)]
    suspicious_patterns: HVec<HString<MAX_LABEL_LEN>, MAX_SUSPICIOUS_PATTERNS>,
}

impl HardenedPolicy {
    pub(crate) fn from_str(contents: &str) -> Result<Self> {
        let policy: Self = toml::from_str(contents).map_err(|error| {
            AgentError::new(
                CFG_PARSE_FAILED,
                "Configuration input could not be parsed",
                format!("operation=parse_hardened_policy_toml; {error}"),
                "",
            )
        })?;

        policy.validate()?;
        Ok(policy)
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if self.version != POLICY_VERSION {
            return Err(AgentError::new(
                CFG_VERSION_MISMATCH,
                "Configuration version is not supported",
                "operation=validate_hardened_policy_version; file_version mismatch",
                "",
            ));
        }

        if !(0.0..=100.0).contains(&self.scoring.alert_threshold) {
            return Err(AgentError::new(
                CFG_INVALID_VALUE,
                "Configuration contains an invalid value",
                "operation=validate_hardened_policy_scoring; alert_threshold out of range",
                "scoring.alert_threshold",
            ));
        }

        if self.scoring.correlation_window_secs == 0 || self.scoring.correlation_window_secs > 3600
        {
            return Err(AgentError::new(
                CFG_INVALID_VALUE,
                "Configuration contains an invalid value",
                "operation=validate_hardened_policy_scoring; correlation_window_secs out of range",
                "scoring.correlation_window_secs",
            ));
        }

        if self.scoring.max_events_in_memory == 0 || self.scoring.max_events_in_memory > 100_000 {
            return Err(AgentError::new(
                CFG_INVALID_VALUE,
                "Configuration contains an invalid value",
                "operation=validate_hardened_policy_scoring; max_events_in_memory out of range",
                "scoring.max_events_in_memory",
            ));
        }

        if self.response.rules.is_empty() {
            return Err(AgentError::new(
                CFG_MISSING_REQUIRED,
                "Required configuration is missing",
                "operation=validate_hardened_policy_response; response.rules cannot be empty",
                "response.rules",
            ));
        }

        if self.response.cooldown_secs == 0 {
            return Err(AgentError::new(
                CFG_INVALID_VALUE,
                "Configuration contains an invalid value",
                "operation=validate_hardened_policy_response; cooldown_secs cannot be zero",
                "response.cooldown_secs",
            ));
        }

        for idx in 0..self.response.rules.len() {
            for prev in 0..idx {
                if self.response.rules[idx].severity == self.response.rules[prev].severity {
                    return Err(AgentError::new(
                        CFG_VALIDATION_FAILED,
                        "Configuration validation failed",
                        "operation=validate_hardened_policy; duplicate severity rule",
                        "response.rules",
                    ));
                }
            }

            for condition in &self.response.rules[idx].conditions {
                if let HardenedResponseCondition::Custom { name, .. } = condition
                    && !self
                        .registered_custom_conditions
                        .iter()
                        .any(|registered| registered == name)
                {
                    return Err(AgentError::new(
                        CFG_VALIDATION_FAILED,
                        "Configuration validation failed",
                        "operation=validate_hardened_policy; unregistered custom condition",
                        "registered_custom_conditions",
                    ));
                }
            }
        }

        let _ = self.scoring.enable_time_scoring;
        let _ = self.scoring.enable_ancestry_tracking;
        let _ = self.scoring.business_hours_start;
        let _ = self.scoring.business_hours_end;
        let _ = self.scoring.weights.artifact_access;
        let _ = self.scoring.weights.suspicious_process;
        let _ = self.scoring.weights.rapid_enumeration;
        let _ = self.scoring.weights.off_hours_activity;
        let _ = self.scoring.weights.ancestry_suspicious;
        let _ = self.response.max_kills_per_incident;
        let _ = self.response.dry_run;

        for rule in &self.response.rules {
            match &rule.action {
                HardenedActionType::Log
                | HardenedActionType::Alert
                | HardenedActionType::KillProcess
                | HardenedActionType::IsolateHost => {}
                HardenedActionType::CustomScript { path } => {
                    let _ = path;
                }
            }
            for condition in &rule.conditions {
                match condition {
                    HardenedResponseCondition::MinConfidence { threshold } => {
                        let _ = threshold;
                    }
                    HardenedResponseCondition::NotParentedBy { process_name } => {
                        let _ = process_name;
                    }
                    HardenedResponseCondition::MinSignalTypes { count } => {
                        let _ = count;
                    }
                    HardenedResponseCondition::RepeatCount { count, window_secs } => {
                        let _ = count;
                        let _ = window_secs;
                    }
                    HardenedResponseCondition::TimeWindow { start_hour, end_hour } => {
                        let _ = start_hour;
                        let _ = end_hour;
                    }
                    HardenedResponseCondition::Custom { params, .. } => {
                        let _ = params;
                    }
                }
            }
        }

        Ok(())
    }

    /// Convert the admitted hardened policy into the fixed-capacity runtime form.
    pub fn into_runtime(self) -> RuntimePolicy {
        RuntimePolicy::from_parts(
            self.scoring.alert_threshold,
            self.deception.suspicious_processes,
            self.deception.suspicious_patterns,
            self.registered_custom_conditions,
        )
    }
}

fn validate_absolute_path(path: &str, field: &str) -> Result<()> {
    if !path.starts_with('/') {
        return Err(AgentError::new(
            CFG_INVALID_VALUE,
            "Configuration contains an invalid value",
            "operation=validate_hardened_path; path must be absolute",
            field,
        ));
    }
    Ok(())
}
