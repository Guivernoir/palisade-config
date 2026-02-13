//! No-allocation runtime representations derived from deserialized configs.
//!
//! Deserialize/serialize can allocate. After conversion to these types, hot-path
//! operations can run without heap allocations.

use crate::errors;
use crate::timing::{enforce_operation_min_timing, TimingOperation};
use crate::{AgentError, Config, PolicyConfig, RootTag};
use heapless::{String as HString, Vec as HVec};
use std::time::Instant;

/// Maximum bytes for path-like fields.
pub const MAX_PATH_LEN: usize = 512;
/// Maximum bytes for generic labels.
pub const MAX_LABEL_LEN: usize = 64;
/// Maximum number of path entries retained in runtime config.
pub const MAX_PATH_ENTRIES: usize = 64;
/// Maximum number of credential types retained in runtime config.
pub const MAX_CREDENTIAL_TYPES: usize = 32;
/// Maximum number of suspicious process patterns retained in runtime policy.
pub const MAX_SUSPICIOUS_PROCESSES: usize = 128;
/// Maximum number of suspicious artifact patterns retained in runtime policy.
pub const MAX_SUSPICIOUS_PATTERNS: usize = 128;
/// Maximum number of registered custom conditions retained in runtime policy.
pub const MAX_CUSTOM_CONDITIONS: usize = 128;

/// Stack-only runtime configuration for no-allocation operation.
#[derive(Clone)]
pub struct RuntimeConfig {
    /// Effective agent hostname.
    pub hostname: HString<MAX_LABEL_LEN>,
    /// Root tag used for derivation.
    pub root_tag: RootTag,
    /// Decoy paths (UTF-8 only).
    pub decoy_paths: HVec<HString<MAX_PATH_LEN>, MAX_PATH_ENTRIES>,
    /// Watch paths (UTF-8 only).
    pub watch_paths: HVec<HString<MAX_PATH_LEN>, MAX_PATH_ENTRIES>,
    /// Credential types.
    pub credential_types: HVec<HString<MAX_LABEL_LEN>, MAX_CREDENTIAL_TYPES>,
    /// Honeytoken count.
    pub honeytoken_count: usize,
    /// Artifact permissions.
    pub artifact_permissions: u32,
}

/// Stack-only runtime policy for no-allocation operation.
#[derive(Clone)]
pub struct RuntimePolicy {
    /// Alert threshold.
    pub alert_threshold: f64,
    /// Suspicious process patterns.
    pub suspicious_processes: HVec<HString<MAX_LABEL_LEN>, MAX_SUSPICIOUS_PROCESSES>,
    /// Suspicious artifact patterns.
    pub suspicious_patterns: HVec<HString<MAX_LABEL_LEN>, MAX_SUSPICIOUS_PATTERNS>,
    /// Registered custom condition names.
    pub registered_custom_conditions: HVec<HString<MAX_LABEL_LEN>, MAX_CUSTOM_CONDITIONS>,
}

impl RuntimeConfig {
    /// Derive an artifact tag hex digest into a caller-provided fixed buffer.
    ///
    /// No heap allocation occurs.
    pub fn derive_artifact_tag_hex_into(&self, artifact_id: &str, out: &mut [u8; 128]) {
        self.root_tag
            .derive_artifact_tag_hex_into(self.hostname.as_str(), artifact_id, out);
    }
}

impl RuntimePolicy {
    /// Check for suspicious process name using ASCII case-insensitive substring matching.
    ///
    /// No heap allocation occurs.
    #[must_use]
    pub fn is_suspicious_process(&self, name: &str) -> bool {
        let started = Instant::now();
        let found = self
            .suspicious_processes
            .iter()
            .any(|pattern| contains_ascii_case_insensitive(name, pattern.as_str()));
        enforce_operation_min_timing(started, TimingOperation::PolicySuspiciousCheck);
        found
    }

    /// Check if a custom condition name is pre-registered.
    #[must_use]
    pub fn is_registered_custom_condition(&self, name: &str) -> bool {
        let started = Instant::now();
        let found = self
            .registered_custom_conditions
            .iter()
            .any(|registered| registered.as_str() == name);
        enforce_operation_min_timing(started, TimingOperation::PolicyCustomConditionCheck);
        found
    }
}

impl Config {
    /// Convert config to a stack-only runtime representation.
    ///
    /// # Errors
    ///
    /// Returns error if any field exceeds fixed runtime capacity or contains
    /// non-UTF8 paths.
    pub fn to_runtime(&self) -> Result<RuntimeConfig, AgentError> {
        let started = Instant::now();
        let result = (|| {
            let hostname = push_str::<MAX_LABEL_LEN>("agent.hostname", self.hostname().as_ref())?;

            let mut decoy_paths = HVec::<HString<MAX_PATH_LEN>, MAX_PATH_ENTRIES>::new();
            for path in &self.deception.decoy_paths {
                let path_str = path.to_str().ok_or_else(|| {
                    errors::invalid_value(
                        "to_runtime_config",
                        "deception.decoy_paths",
                        "path must be valid UTF-8 for runtime no-alloc mode",
                    )
                })?;
                push_vec_str("deception.decoy_paths", path_str, &mut decoy_paths)?;
            }

            let mut watch_paths = HVec::<HString<MAX_PATH_LEN>, MAX_PATH_ENTRIES>::new();
            for path in &self.telemetry.watch_paths {
                let path_str = path.to_str().ok_or_else(|| {
                    errors::invalid_value(
                        "to_runtime_config",
                        "telemetry.watch_paths",
                        "path must be valid UTF-8 for runtime no-alloc mode",
                    )
                })?;
                push_vec_str("telemetry.watch_paths", path_str, &mut watch_paths)?;
            }

            let mut credential_types = HVec::<HString<MAX_LABEL_LEN>, MAX_CREDENTIAL_TYPES>::new();
            for ctype in &self.deception.credential_types {
                push_vec_str("deception.credential_types", ctype, &mut credential_types)?;
            }

            Ok(RuntimeConfig {
                hostname,
                root_tag: self.deception.root_tag.clone(),
                decoy_paths,
                watch_paths,
                credential_types,
                honeytoken_count: self.deception.honeytoken_count,
                artifact_permissions: self.deception.artifact_permissions,
            })
        })();
        enforce_operation_min_timing(started, TimingOperation::RuntimeConfigBuild);
        result
    }
}

impl PolicyConfig {
    /// Convert policy to a stack-only runtime representation.
    ///
    /// # Errors
    ///
    /// Returns error if any field exceeds fixed runtime capacity.
    pub fn to_runtime(&self) -> Result<RuntimePolicy, AgentError> {
        let started = Instant::now();
        let result = (|| {
            let mut suspicious_processes =
                HVec::<HString<MAX_LABEL_LEN>, MAX_SUSPICIOUS_PROCESSES>::new();
            for p in &self.deception.suspicious_processes {
                push_vec_str("deception.suspicious_processes", p, &mut suspicious_processes)?;
            }

            let mut suspicious_patterns =
                HVec::<HString<MAX_LABEL_LEN>, MAX_SUSPICIOUS_PATTERNS>::new();
            for p in &self.deception.suspicious_patterns {
                push_vec_str("deception.suspicious_patterns", p, &mut suspicious_patterns)?;
            }

            let mut registered_custom_conditions =
                HVec::<HString<MAX_LABEL_LEN>, MAX_CUSTOM_CONDITIONS>::new();
            for c in &self.registered_custom_conditions {
                push_vec_str(
                    "registered_custom_conditions",
                    c,
                    &mut registered_custom_conditions,
                )?;
            }

            Ok(RuntimePolicy {
                alert_threshold: self.scoring.alert_threshold,
                suspicious_processes,
                suspicious_patterns,
                registered_custom_conditions,
            })
        })();
        enforce_operation_min_timing(started, TimingOperation::RuntimePolicyBuild);
        result
    }
}

fn push_str<const N: usize>(field: &str, value: &str) -> Result<HString<N>, AgentError> {
    let mut out = HString::<N>::new();
    out.push_str(value).map_err(|_| {
        errors::invalid_value(
            "to_runtime",
            field,
            format!("value exceeds fixed no-alloc capacity ({N} bytes)"),
        )
    })?;
    Ok(out)
}

fn push_vec_str<const N: usize, const M: usize>(
    field: &str,
    value: &str,
    out: &mut HVec<HString<N>, M>,
) -> Result<(), AgentError> {
    let item = push_str::<N>(field, value)?;
    out.push(item).map_err(|_| {
        errors::invalid_value(
            "to_runtime",
            field,
            format!("too many entries for fixed no-alloc capacity ({M})"),
        )
    })?;
    Ok(())
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
            if h[start + i].to_ascii_lowercase() != n[i].to_ascii_lowercase() {
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

#[cfg(test)]
mod tests {
    use crate::{Config, PolicyConfig};

    #[test]
    fn config_to_runtime_works() {
        let config = Config::default();
        let rt = config.to_runtime().expect("runtime conversion must succeed");
        let mut out = [0u8; 128];
        rt.derive_artifact_tag_hex_into("artifact", &mut out);
        assert!(out[0].is_ascii_hexdigit());
    }

    #[test]
    fn policy_to_runtime_works() {
        let policy = PolicyConfig::default();
        let rt = policy.to_runtime().expect("runtime conversion must succeed");
        assert!(rt.is_suspicious_process("MIMIKATZ.exe"));
        assert!(!rt.is_suspicious_process("notepad.exe"));
    }
}
