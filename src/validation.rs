//! Configuration and policy diffing for change tracking.

use crate::timing::{TimingOperation, enforce_operation_min_timing};
use crate::{AgentError, Config, PolicyConfig, Result};
use core::fmt::Write as _;
use heapless::{String as HString, Vec as HVec};
use std::path::Path;
use std::time::Instant;

/// Validation strictness level.
#[derive(Debug, PartialEq, Eq)]
pub enum ValidationMode {
    /// Standard validation (format checks, no filesystem access)
    Standard,

    /// Strict validation (paths must exist, permissions verified)
    Strict,
}

impl Default for ValidationMode {
    fn default() -> Self {
        Self::Standard
    }
}

const CFG_VALIDATION_FAILED: u16 = 101;
const MAX_CONFIG_DIFF_CHANGES: usize = 32;
const MAX_POLICY_DIFF_CHANGES: usize = 32;
const HASH_PREFIX_HEX_LEN: usize = 16;

/// Fixed-capacity configuration diff report.
pub type ConfigDiff<'a> = HVec<ConfigChange<'a>, MAX_CONFIG_DIFF_CHANGES>;

/// Fixed-capacity policy diff report.
pub type PolicyDiff<'a> = HVec<PolicyChange<'a>, MAX_POLICY_DIFF_CHANGES>;

/// Configuration change detected during diff.
#[derive(Debug, PartialEq, Eq)]
pub enum ConfigChange<'a> {
    /// Root tag changed (shows hash, not secret)
    RootTagChanged {
        /// Prefix hash of the previous root tag.
        old_hash: HString<HASH_PREFIX_HEX_LEN>,
        /// Prefix hash of the replacement root tag.
        new_hash: HString<HASH_PREFIX_HEX_LEN>,
    },

    /// A decoy path was introduced in the candidate configuration.
    PathAdded {
        /// Path newly introduced in the candidate configuration.
        path: &'a Path,
    },

    /// A decoy path was removed from the previous configuration.
    PathRemoved {
        /// Path removed from the previous configuration.
        path: &'a Path,
    },

    /// Capability settings changed
    CapabilitiesChanged {
        /// Name of the capability field that changed.
        field: &'static str,
        /// Previous serialized value for the field.
        old: bool,
        /// New serialized value for the field.
        new: bool,
    },
}

/// Policy change detected during diff.
#[derive(Debug, PartialEq)]
pub enum PolicyChange<'a> {
    /// Threshold value changed
    ThresholdChanged {
        /// Name of the threshold field that changed.
        field: &'static str,
        /// Previous threshold value.
        old: f64,
        /// New threshold value.
        new: f64,
    },

    /// Response rules changed
    ResponseRulesChanged {
        /// Number of response rules before the change.
        old_count: usize,
        /// Number of response rules after the change.
        new_count: usize,
    },

    /// Suspicious process pattern introduced in the new policy.
    SuspiciousProcessAdded {
        /// Pattern introduced in the new policy.
        pattern: &'a str,
    },

    /// Suspicious process pattern removed from the previous policy.
    SuspiciousProcessRemoved {
        /// Pattern removed from the previous policy.
        pattern: &'a str,
    },
}

impl Config {
    /// Diff configuration against another configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if the fixed-capacity diff report cannot represent all
    /// detected changes.
    pub fn diff<'a>(&'a self, other: &'a Config) -> Result<ConfigDiff<'a>> {
        let started = Instant::now();
        let result = (|| {
            let mut changes = ConfigDiff::new();

            // Compare root tags via hash (secure, no exposure)
            if !self
                .deception
                .root_tag
                .hash_eq_ct(&other.deception.root_tag)
            {
                push_config_change(
                    &mut changes,
                    ConfigChange::RootTagChanged {
                        old_hash: hash_prefix_hex(&self.deception.root_tag.hash()[..8])?,
                        new_hash: hash_prefix_hex(&other.deception.root_tag.hash()[..8])?,
                    },
                )?;
            }

            for path in &other.deception.decoy_paths {
                if !self.deception.decoy_paths.iter().any(|current| current == path) {
                    push_config_change(
                        &mut changes,
                        ConfigChange::PathAdded {
                            path: path.as_path(),
                        },
                    )?;
                }
            }

            for path in &self.deception.decoy_paths {
                if !other.deception.decoy_paths.iter().any(|next| next == path) {
                    push_config_change(
                        &mut changes,
                        ConfigChange::PathRemoved {
                            path: path.as_path(),
                        },
                    )?;
                }
            }

            if self.telemetry.enable_syscall_monitor != other.telemetry.enable_syscall_monitor {
                push_config_change(
                    &mut changes,
                    ConfigChange::CapabilitiesChanged {
                        field: "enable_syscall_monitor",
                        old: self.telemetry.enable_syscall_monitor,
                        new: other.telemetry.enable_syscall_monitor,
                    },
                )?;
            }

            Ok(changes)
        })();

        enforce_operation_min_timing(started, TimingOperation::ConfigDiff);
        result
    }
}

impl PolicyConfig {
    /// Diff policy against another policy.
    ///
    /// # Errors
    ///
    /// Returns an error if the fixed-capacity diff report cannot represent all
    /// detected changes.
    pub fn diff<'a>(&'a self, other: &'a PolicyConfig) -> Result<PolicyDiff<'a>> {
        let started = Instant::now();
        let result = (|| {
            let mut changes = PolicyDiff::new();

            if (self.scoring.alert_threshold - other.scoring.alert_threshold).abs() > 0.01 {
                push_policy_change(
                    &mut changes,
                    PolicyChange::ThresholdChanged {
                        field: "alert_threshold",
                        old: self.scoring.alert_threshold,
                        new: other.scoring.alert_threshold,
                    },
                )?;
            }

            if self.response.rules.len() != other.response.rules.len() {
                push_policy_change(
                    &mut changes,
                    PolicyChange::ResponseRulesChanged {
                        old_count: self.response.rules.len(),
                        new_count: other.response.rules.len(),
                    },
                )?;
            }

            for pattern in &other.deception.suspicious_processes {
                if !self
                    .deception
                    .suspicious_processes
                    .iter()
                    .any(|current| current == pattern)
                {
                    push_policy_change(
                        &mut changes,
                        PolicyChange::SuspiciousProcessAdded {
                            pattern: pattern.as_str(),
                        },
                    )?;
                }
            }

            for pattern in &self.deception.suspicious_processes {
                if !other
                    .deception
                    .suspicious_processes
                    .iter()
                    .any(|next| next == pattern)
                {
                    push_policy_change(
                        &mut changes,
                        PolicyChange::SuspiciousProcessRemoved {
                            pattern: pattern.as_str(),
                        },
                    )?;
                }
            }

            Ok(changes)
        })();

        enforce_operation_min_timing(started, TimingOperation::PolicyDiff);
        result
    }
}

fn push_config_change<'a>(
    changes: &mut ConfigDiff<'a>,
    change: ConfigChange<'a>,
) -> Result<()> {
    changes.push(change).map_err(|_| {
        AgentError::new(
            CFG_VALIDATION_FAILED,
            "Configuration validation failed",
            "operation=diff_config; fixed-capacity diff buffer exhausted",
            "config.diff",
        )
    })
}

fn push_policy_change<'a>(
    changes: &mut PolicyDiff<'a>,
    change: PolicyChange<'a>,
) -> Result<()> {
    changes.push(change).map_err(|_| {
        AgentError::new(
            CFG_VALIDATION_FAILED,
            "Configuration validation failed",
            "operation=diff_policy; fixed-capacity diff buffer exhausted",
            "policy.diff",
        )
    })
}

fn hash_prefix_hex(bytes: &[u8]) -> Result<HString<HASH_PREFIX_HEX_LEN>> {
    let mut out = HString::<HASH_PREFIX_HEX_LEN>::new();
    for byte in bytes {
        write!(&mut out, "{byte:02x}").map_err(|_| {
            AgentError::new(
                CFG_VALIDATION_FAILED,
                "Configuration validation failed",
                "operation=diff_config; fixed-capacity root-tag hash buffer exhausted",
                "config.diff",
            )
        })?;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tags::RootTag;

    #[test]
    fn test_config_diff_detects_root_tag_change() {
        let config1 = Config::default();
        let mut config2 = Config::default();
        config2.deception.root_tag = RootTag::generate().expect("Failed to generate tag");

        let changes = config1.diff(&config2).expect("diff");
        assert!(!changes.is_empty());

        if let Some(ConfigChange::RootTagChanged { old_hash, new_hash }) = changes.first() {
            assert_eq!(old_hash.len(), 16);
            assert_eq!(new_hash.len(), 16);
            assert_ne!(old_hash, new_hash);
        } else {
            panic!("Expected RootTagChanged");
        }
    }

    #[test]
    fn test_policy_diff_detects_threshold_change() {
        let mut policy1 = PolicyConfig::default();
        let mut policy2 = PolicyConfig::default();

        policy1.scoring.alert_threshold = 50.0;
        policy2.scoring.alert_threshold = 75.0;

        let changes = policy1.diff(&policy2).expect("diff");
        assert!(!changes.is_empty());

        if let Some(PolicyChange::ThresholdChanged { field, old, new }) = changes.first() {
            assert_eq!(*field, "alert_threshold");
            assert_eq!(*old, 50.0);
            assert_eq!(*new, 75.0);
        } else {
            panic!("Expected ThresholdChanged");
        }
    }
}
