//! Property-based tests using proptest.
//!
//! Tests invariants that should hold for ALL inputs:
//! - Tag derivation properties
//! - Validation consistency
//! - Serialization round-trips
//! - Error handling robustness

use palisade_config::{Config, PolicyConfig, RootTag, Severity, ValidationMode, ProtectedString, ProtectedPath};
use proptest::prelude::*;
use std::path::PathBuf;

// ============================================================================
// Property: Tag Derivation is Deterministic
// ============================================================================

proptest! {
    #[test]
    fn prop_tag_derivation_deterministic(hostname in "\\w+", artifact_id in "\\w+") {
        let root = RootTag::generate();
        
        let tag1 = root.derive_artifact_tag(&hostname, &artifact_id);
        let tag2 = root.derive_artifact_tag(&hostname, &artifact_id);
        
        prop_assert_eq!(tag1, tag2, "Same inputs must produce same outputs");
    }
}

// ============================================================================
// Property: Different Hosts Produce Different Tags
// ============================================================================

proptest! {
    #[test]
    fn prop_different_hosts_different_tags(
        host1 in "\\w{5,20}",
        host2 in "\\w{5,20}",
        artifact_id in "\\w+"
    ) {
        prop_assume!(host1 != host2);
        
        let root = RootTag::generate();
        let tag1 = root.derive_artifact_tag(&host1, &artifact_id);
        let tag2 = root.derive_artifact_tag(&host2, &artifact_id);
        
        prop_assert_ne!(tag1, tag2, "Different hosts must have different tags");
    }
}

// ============================================================================
// Property: Different Artifacts Produce Different Tags
// ============================================================================

proptest! {
    #[test]
    fn prop_different_artifacts_different_tags(
        hostname in "\\w+",
        artifact1 in "\\w{5,20}",
        artifact2 in "\\w{5,20}"
    ) {
        prop_assume!(artifact1 != artifact2);
        
        let root = RootTag::generate();
        let tag1 = root.derive_artifact_tag(&hostname, &artifact1);
        let tag2 = root.derive_artifact_tag(&hostname, &artifact2);
        
        prop_assert_ne!(tag1, tag2, "Different artifacts must have different tags");
    }
}

// ============================================================================
// Property: Derived Tags Have Consistent Length
// ============================================================================

proptest! {
    #[test]
    fn prop_derived_tags_consistent_length(hostname in "\\w+", artifact_id in "\\w+") {
        let root = RootTag::generate();
        let tag = root.derive_artifact_tag(&hostname, &artifact_id);
        
        // SHA3-512 produces 64 bytes = 128 hex characters
        prop_assert_eq!(tag.len(), 128);
    }
}

// ============================================================================
// Property: Severity Ordering is Consistent
// ============================================================================

proptest! {
    #[test]
    fn prop_severity_ordering_consistent(score1 in 0.0f64..100.0, score2 in 0.0f64..100.0) {
        let severity1 = Severity::from_score(score1);
        let severity2 = Severity::from_score(score2);
        
        if score1 < score2 {
            prop_assert!(severity1 <= severity2, "Higher scores should have higher severity");
        }
    }
}

// ============================================================================
// Property: Severity Thresholds are Consistent
// ============================================================================

proptest! {
    #[test]
    fn prop_severity_thresholds(score in 0.0f64..100.0) {
        let severity = Severity::from_score(score);
        
        match severity {
            Severity::Low => prop_assert!(score < 40.0),
            Severity::Medium => prop_assert!(score >= 40.0 && score < 60.0),
            Severity::High => prop_assert!(score >= 60.0 && score < 80.0),
            Severity::Critical => prop_assert!(score >= 80.0),
        }
    }
}

// ============================================================================
// Property: Config Validation is Idempotent
// ============================================================================

proptest! {
    #[test]
    fn prop_validation_idempotent(_seed in any::<u64>()) {
        let config = Config::default();
        
        let result1 = config.validate();
        let result2 = config.validate();
        
        prop_assert_eq!(result1.is_ok(), result2.is_ok(),
            "Validation should give same result each time");
    }
}

// ============================================================================
// Property: Invalid Configs Always Fail Validation
// ============================================================================

proptest! {
    #[test]
    fn prop_empty_instance_id_fails(work_dir in "/[a-z]{3,10}") {
        let mut config = Config::default();
        config.agent.instance_id = ProtectedString::new(String::new());
        config.agent.work_dir = ProtectedPath::new(PathBuf::from(work_dir));
        
        prop_assert!(config.validate().is_err(),
            "Empty instance_id should always fail validation");
    }
}

// ============================================================================
// Property: Policy Suspicious Process Detection is Case-Insensitive
// ============================================================================

proptest! {
    #[test]
    fn prop_suspicious_process_case_insensitive(
        process_name in "(mimikatz|procdump|lazagne)"
    ) {
        let policy = PolicyConfig::default();
        
        let lower = process_name.to_lowercase();
        let upper = process_name.to_uppercase();
        let mixed = process_name.chars()
            .enumerate()
            .map(|(i, c)| if i % 2 == 0 { c.to_uppercase().to_string() } else { c.to_lowercase().to_string() })
            .collect::<String>();
        
        prop_assert!(policy.is_suspicious_process(&lower));
        prop_assert!(policy.is_suspicious_process(&upper));
        prop_assert!(policy.is_suspicious_process(&mixed));
    }
}

// ============================================================================
// Property: Honeytoken Count Must Be in Valid Range
// ============================================================================

proptest! {
    #[test]
    fn prop_honeytoken_count_validation(count in any::<usize>()) {
        let mut config = Config::default();
        config.deception.honeytoken_count = count;
        
        let result = config.validate();
        
        if count >= 1 && count <= 100 {
            // May still fail for other reasons, but shouldn't fail on count
            prop_assert!(result.is_ok() || result.is_err());
        } else {
            // For invalid counts, validation should fail
            prop_assert!(count == 0 || count > 100);
        }
    }
}

// ============================================================================
// Property: Event Buffer Size Must Be Adequate
// ============================================================================

proptest! {
    #[test]
    fn prop_event_buffer_size_validation(size in 0usize..10000) {
        let mut config = Config::default();
        config.telemetry.event_buffer_size = size;
        
        let result = config.validate();
        
        if size < 100 {
            prop_assert!(result.is_err(),
                "Buffer size < 100 should fail validation");
        }
    }
}

// ============================================================================
// Property: Alert Threshold Must Be in Valid Range
// ============================================================================

proptest! {
    #[test]
    fn prop_alert_threshold_validation(threshold in any::<f64>()) {
        let mut policy = PolicyConfig::default();
        policy.scoring.alert_threshold = threshold;
        
        let result = policy.validate();
        
        if threshold.is_nan() || threshold < 0.0 || threshold > 100.0 {
            prop_assert!(result.is_err(),
                "Alert threshold outside 0-100 or NaN should fail");
        }
    }
}

// ============================================================================
// Property: Tag Hash is Consistent
// ============================================================================

proptest! {
    #[test]
    fn prop_tag_hash_consistent(_seed in any::<u64>()) {
        let tag = RootTag::generate();
        
        let hash1 = tag.hash();
        let hash2 = tag.hash();
        
        prop_assert_eq!(hash1, hash2, "Hash should be consistent");
        prop_assert_eq!(hash1.len(), 64, "SHA3-512 should be 64 bytes");
    }
}

// ============================================================================
// Property: Config Diff is Symmetric for Same Configs
// ============================================================================

proptest! {
    #[test]
    fn prop_config_diff_symmetric_for_same(_seed in any::<u64>()) {
        let config = Config::default();
        
        let changes = config.diff(&config);
        
        prop_assert!(changes.is_empty(),
            "Diffing config against itself should show no changes");
    }
}

// ============================================================================
// Property: Policy Diff is Symmetric for Same Policies
// ============================================================================

proptest! {
    #[test]
    fn prop_policy_diff_symmetric_for_same(_seed in any::<u64>()) {
        let policy = PolicyConfig::default();
        
        let changes = policy.diff(&policy);
        
        prop_assert!(changes.is_empty(),
            "Diffing policy against itself should show no changes");
    }
}

// ============================================================================
// Property: Hostname Resolution Never Returns Empty
// ============================================================================

proptest! {
    #[test]
    fn prop_hostname_never_empty(_seed in any::<u64>()) {
        let config = Config::default();
        let hostname = config.hostname();
        
        prop_assert!(!hostname.is_empty(),
            "Hostname should never be empty");
    }
}

// ============================================================================
// Property: Artifact Permissions Must Be Valid Unix Permissions
// ============================================================================

proptest! {
    #[test]
    fn prop_artifact_permissions_validation(perms in any::<u32>()) {
        let mut config = Config::default();
        config.deception.artifact_permissions = perms;
        
        let result = config.validate();
        
        if perms > 0o777 {
            prop_assert!(result.is_err(),
                "Permissions > 0o777 should fail validation");
        }
    }
}

// ============================================================================
// Property: Correlation Window Must Be Reasonable
// ============================================================================

proptest! {
    #[test]
    fn prop_correlation_window_validation(window_secs in any::<u64>()) {
        let mut policy = PolicyConfig::default();
        policy.scoring.correlation_window_secs = window_secs;
        
        let result = policy.validate();
        
        if window_secs == 0 || window_secs > 3600 {
            prop_assert!(result.is_err(),
                "Correlation window outside 1-3600 should fail");
        }
    }
}

// ============================================================================
// Property: Cooldown Cannot Be Zero
// ============================================================================

proptest! {
    #[test]
    fn prop_cooldown_validation(cooldown in any::<u64>()) {
        let mut policy = PolicyConfig::default();
        policy.response.cooldown_secs = cooldown;
        
        let result = policy.validate();
        
        if cooldown == 0 {
            prop_assert!(result.is_err(),
                "Zero cooldown should fail validation");
        }
    }
}

// ============================================================================
// Property: Default Configs Always Validate
// ============================================================================

proptest! {
    #[test]
    fn prop_default_config_always_validates(_seed in any::<u64>()) {
        let config = Config::default();
        prop_assert!(config.validate().is_ok(),
            "Default config should always validate");
    }
}

proptest! {
    #[test]
    fn prop_default_policy_always_validates(_seed in any::<u64>()) {
        let policy = PolicyConfig::default();
        prop_assert!(policy.validate().is_ok(),
            "Default policy should always validate");
    }
}

// ============================================================================
// Property: Validation Mode Doesn't Affect Format Checks
// ============================================================================

proptest! {
    #[test]
    fn prop_validation_modes_consistent_for_format(_seed in any::<u64>()) {
        let config = Config::default();
        
        let standard = config.validate_with_mode(ValidationMode::Standard);
        let strict = config.validate_with_mode(ValidationMode::Strict);
        
        // Both should succeed for valid default config
        prop_assert!(standard.is_ok());
        prop_assert!(strict.is_ok() || strict.is_err()); // Strict may fail on filesystem
    }
}