//! Configuration and policy diffing for change tracking.

use crate::{Config, PolicyConfig};
use std::collections::HashSet;
use std::path::PathBuf;

/// Validation strictness level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationMode {
    /// Standard validation (format checks, no filesystem access)
    Standard,

    /// Strict validation (paths must exist, permissions verified)
    Strict,
}

/// Configuration change detected during diff.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigChange {
    /// Root tag changed (shows hash, not secret)
    RootTagChanged { old_hash: String, new_hash: String },

    /// Decoy paths changed
    PathsChanged {
        added: Vec<PathBuf>,
        removed: Vec<PathBuf>,
    },

    /// Capability settings changed
    CapabilitiesChanged {
        field: String,
        old: String,
        new: String,
    },
}

/// Policy change detected during diff.
#[derive(Debug, Clone, PartialEq)]
pub enum PolicyChange {
    /// Threshold value changed
    ThresholdChanged {
        field: String,
        old: f64,
        new: f64,
    },

    /// Response rules changed
    ResponseRulesChanged {
        old_count: usize,
        new_count: usize,
    },

    /// Suspicious process patterns changed
    SuspiciousProcessesChanged {
        added: Vec<String>,
        removed: Vec<String>,
    },
}

impl Config {
    /// Diff configuration against another configuration.
    #[must_use]
    pub fn diff(&self, other: &Config) -> Vec<ConfigChange> {
        let mut changes = Vec::new();

        // Compare root tags via hash (secure, no exposure)
        if self.deception.root_tag.hash() != other.deception.root_tag.hash() {
            changes.push(ConfigChange::RootTagChanged {
                old_hash: hex::encode(&self.deception.root_tag.hash()[..8]),
                new_hash: hex::encode(&other.deception.root_tag.hash()[..8]),
            });
        }

        // Compare paths - use references to avoid cloning
        let old_paths: HashSet<&PathBuf> = self.deception.decoy_paths.iter().collect();
        let new_paths: HashSet<&PathBuf> = other.deception.decoy_paths.iter().collect();

        let added: Vec<PathBuf> = new_paths
            .difference(&old_paths)
            .map(|&p| p.clone())  // Only clone when building final diff result
            .collect();
        let removed: Vec<PathBuf> = old_paths
            .difference(&new_paths)
            .map(|&p| p.clone())  // Only clone when building final diff result
            .collect();

        if !added.is_empty() || !removed.is_empty() {
            changes.push(ConfigChange::PathsChanged { added, removed });
        }

        // Compare syscall monitoring capability
        if self.telemetry.enable_syscall_monitor != other.telemetry.enable_syscall_monitor {
            changes.push(ConfigChange::CapabilitiesChanged {
                field: "enable_syscall_monitor".to_string(),
                old: self.telemetry.enable_syscall_monitor.to_string(),
                new: other.telemetry.enable_syscall_monitor.to_string(),
            });
        }

        changes
    }
}

impl PolicyConfig {
    /// Diff policy against another policy.
    #[must_use]
    pub fn diff(&self, other: &PolicyConfig) -> Vec<PolicyChange> {
        let mut changes = Vec::new();

        // Threshold changes
        if (self.scoring.alert_threshold - other.scoring.alert_threshold).abs() > 0.01 {
            changes.push(PolicyChange::ThresholdChanged {
                field: "alert_threshold".to_string(),
                old: self.scoring.alert_threshold,
                new: other.scoring.alert_threshold,
            });
        }

        // Response rules
        if self.response.rules.len() != other.response.rules.len() {
            changes.push(PolicyChange::ResponseRulesChanged {
                old_count: self.response.rules.len(),
                new_count: other.response.rules.len(),
            });
        }

        // Suspicious processes - use references to avoid cloning
        let old: HashSet<&String> = self.deception.suspicious_processes.iter().collect();
        let new: HashSet<&String> = other.deception.suspicious_processes.iter().collect();

        let added: Vec<String> = new
            .difference(&old)
            .map(|&s| s.clone())  // Only clone when building final diff result
            .collect();
        let removed: Vec<String> = old
            .difference(&new)
            .map(|&s| s.clone())  // Only clone when building final diff result
            .collect();

        if !added.is_empty() || !removed.is_empty() {
            changes.push(PolicyChange::SuspiciousProcessesChanged { added, removed });
        }

        changes
    }
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

        let changes = config1.diff(&config2);
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

        let changes = policy1.diff(&policy2);
        assert!(!changes.is_empty());

        if let Some(PolicyChange::ThresholdChanged { field, old, new }) = changes.first() {
            assert_eq!(field, "alert_threshold");
            assert_eq!(*old, 50.0);
            assert_eq!(*new, 75.0);
        } else {
            panic!("Expected ThresholdChanged");
        }
    }
}