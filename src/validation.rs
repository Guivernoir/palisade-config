//! Configuration and policy diffing for change tracking.
//!
//! Enables auditable configuration management:
//! - Version control integration
//! - Change approval workflows
//! - Security-significant change detection
//! - Policy governance
//!
//! # Example
//!
//! ```rust
//! use palisade_config::{Config, PolicyConfig};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let old_config = Config::from_file("config.old.toml")?;
//! let new_config = Config::from_file("config.new.toml")?;
//!
//! // Detect security-significant changes
//! let changes = old_config.diff(&new_config);
//! for change in changes {
//!     println!("Change detected: {:?}", change);
//! }
//!
//! let old_policy = PolicyConfig::from_file("policy.old.toml")?;
//! let new_policy = PolicyConfig::from_file("policy.new.toml")?;
//!
//! // Detect policy changes
//! let policy_changes = old_policy.diff(&new_policy);
//! for change in policy_changes {
//!     println!("Policy change: {:?}", change);
//! }
//! # Ok(())
//! # }
//! ```

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
    ///
    /// Compares security-significant fields only:
    /// - Root tag (via hash, not secret)
    /// - Decoy paths
    /// - Capability flags
    ///
    /// Operational changes (logging, telemetry tuning) are excluded
    /// to reduce noise in change tracking.
    ///
    /// # Example
    ///
    /// ```rust
    /// use palisade_config::Config;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let old = Config::from_file("old.toml")?;
    /// let new = Config::from_file("new.toml")?;
    ///
    /// let changes = old.diff(&new);
    /// if !changes.is_empty() {
    ///     println!("Security-significant changes detected:");
    ///     for change in changes {
    ///         println!("  {:?}", change);
    ///     }
    /// }
    /// # Ok(())
    /// # }
    /// ```
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

        // Compare paths
        let old_paths: HashSet<_> = self.deception.decoy_paths.iter().collect();
        let new_paths: HashSet<_> = other.deception.decoy_paths.iter().collect();

        let added: Vec<_> = new_paths
            .difference(&old_paths)
            .map(|&p| p.clone())
            .collect();
        let removed: Vec<_> = old_paths
            .difference(&new_paths)
            .map(|&p| p.clone())
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
    ///
    /// Compares:
    /// - Alert thresholds
    /// - Response rule counts
    /// - Suspicious process patterns
    ///
    /// # Example
    ///
    /// ```rust
    /// use palisade_config::PolicyConfig;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let old = PolicyConfig::from_file("old-policy.toml")?;
    /// let new = PolicyConfig::from_file("new-policy.toml")?;
    ///
    /// let changes = old.diff(&new);
    /// if !changes.is_empty() {
    ///     println!("Policy changes detected:");
    ///     for change in changes {
    ///         println!("  {:?}", change);
    ///     }
    /// }
    /// # Ok(())
    /// # }
    /// ```
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

        // Suspicious processes
        let old: HashSet<_> = self.deception.suspicious_processes.iter().collect();
        let new: HashSet<_> = other.deception.suspicious_processes.iter().collect();

        let added: Vec<_> = new.difference(&old).map(|&s| s.clone()).collect();
        let removed: Vec<_> = old.difference(&new).map(|&s| s.clone()).collect();

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
        config2.deception.root_tag = RootTag::generate();

        let changes = config1.diff(&config2);
        assert!(!changes.is_empty());

        // Should show hash change, not raw secret
        if let Some(ConfigChange::RootTagChanged { old_hash, new_hash }) = changes.first() {
            assert_eq!(old_hash.len(), 16); // 8 bytes = 16 hex chars
            assert_eq!(new_hash.len(), 16);
            assert_ne!(old_hash, new_hash);
        } else {
            panic!("Expected RootTagChanged");
        }
    }

    #[test]
    fn test_config_diff_detects_path_changes() {
        let mut config1 = Config::default();
        let mut config2 = Config::default();

        config1.deception.decoy_paths = vec![PathBuf::from("/tmp/old")];
        config2.deception.decoy_paths = vec![PathBuf::from("/tmp/new")];

        let changes = config1.diff(&config2);
        assert!(!changes.is_empty());

        if let Some(ConfigChange::PathsChanged { added, removed }) = changes.first() {
            assert_eq!(added.len(), 1);
            assert_eq!(removed.len(), 1);
        } else {
            panic!("Expected PathsChanged");
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

    #[test]
    fn test_policy_diff_detects_suspicious_process_changes() {
        let mut policy1 = PolicyConfig::default();
        let mut policy2 = PolicyConfig::default();

        policy1.deception.suspicious_processes = vec!["mimikatz".to_string()];
        policy2.deception.suspicious_processes =
            vec!["mimikatz".to_string(), "procdump".to_string()];

        let changes = policy1.diff(&policy2);
        assert!(!changes.is_empty());

        if let Some(PolicyChange::SuspiciousProcessesChanged { added, removed }) = changes.first()
        {
            assert_eq!(added.len(), 1);
            assert_eq!(removed.len(), 0);
            assert_eq!(added[0], "procdump");
        } else {
            panic!("Expected SuspiciousProcessesChanged");
        }
    }

    #[test]
    fn test_config_diff_empty_when_identical() {
        let config1 = Config::default();
        let config2 = &config1;

        let changes = config1.diff(&config2);
        assert!(changes.is_empty());
    }

    #[test]
    fn test_policy_diff_empty_when_identical() {
        let policy1 = PolicyConfig::default();
        let policy2 = policy1.clone();

        let changes = policy1.diff(&policy2);
        assert!(changes.is_empty());
    }
}