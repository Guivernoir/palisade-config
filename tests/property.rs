//! Property-based tests for palisade-config
//!
//! Uses proptest to verify invariants across many random inputs.

use palisade_config::{RootTag, PolicyConfig, Config};
use proptest::prelude::*;

// ============================================================================
// ENTROPY VALIDATION PROPERTY TESTS
// ============================================================================

proptest! {
    /// Entropy validation should never panic, only return Result
    #[test]
    fn entropy_validation_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..256)) {
        // This should never panic - only succeed or return error
        let hex_str = hex::encode(&bytes);
        let _ = RootTag::new(hex_str);
    }

    /// Valid hex strings of sufficient length should parse
    #[test]
    fn valid_hex_strings_parse(bytes in prop::collection::vec(any::<u8>(), 32..33)) {
        // Generate random bytes, encode to hex, should parse if entropy is good
        let hex_str = hex::encode(&bytes);
        let result = RootTag::new(hex_str);
        
        // If it fails, it should be due to entropy, not parsing
        if result.is_err() {
            let err_str = result.unwrap_err().to_string();
            // Should fail for entropy reasons, not hex decoding
            prop_assert!(
                err_str.contains("entropy") || 
                err_str.contains("diversity") ||
                err_str.contains("sequential") ||
                err_str.contains("repeated")
            );
        }
    }

    /// All-zero sequences should always be rejected
    #[test]
    fn all_zeros_rejected(len in 32usize..256) {
        let zeros = vec![0u8; len];
        let hex_str = hex::encode(&zeros);
        let result = RootTag::new(hex_str);
        
        prop_assert!(result.is_err());
    }

    /// Sequential sequences should be rejected
    #[test]
    fn sequential_rejected(start in 0u8..200, len in 32usize..100) {
        let sequential: Vec<u8> = (0..len).map(|i| start.wrapping_add(i as u8)).collect();
        let hex_str = hex::encode(&sequential);
        let result = RootTag::new(hex_str);
        
        prop_assert!(result.is_err());
    }

    /// Low diversity sequences should be rejected
    #[test]
    fn low_diversity_rejected(byte in any::<u8>(), len in 32usize..128) {
        // Create sequence with only 2-3 unique bytes (low diversity)
        let mut bytes = vec![byte; len];
        bytes[0] = byte.wrapping_add(1);
        bytes[1] = byte.wrapping_add(2);
        
        let hex_str = hex::encode(&bytes);
        let result = RootTag::new(hex_str);
        
        prop_assert!(result.is_err());
    }
}

// ============================================================================
// TAG DERIVATION PROPERTY TESTS
// ============================================================================

proptest! {
    /// Tag derivation should be deterministic
    #[test]
    fn tag_derivation_is_deterministic(
        hostname in "[a-z]{3,20}",
        artifact_id in "[a-z0-9]{3,30}"
    ) {
        let root = RootTag::generate().unwrap();
        
        let tag1 = root.derive_artifact_tag(&hostname, &artifact_id);
        let tag2 = root.derive_artifact_tag(&hostname, &artifact_id);
        
        prop_assert_eq!(tag1, tag2);
    }

    /// Different hostnames should produce different tags
    #[test]
    fn different_hostnames_different_tags(
        hostname1 in "[a-z]{3,20}",
        hostname2 in "[a-z]{3,20}",
        artifact_id in "[a-z0-9]{3,30}"
    ) {
        prop_assume!(hostname1 != hostname2);
        
        let root = RootTag::generate().unwrap();
        
        let tag1 = root.derive_artifact_tag(&hostname1, &artifact_id);
        let tag2 = root.derive_artifact_tag(&hostname2, &artifact_id);
        
        prop_assert_ne!(tag1, tag2);
    }

    /// Different artifact IDs should produce different tags
    #[test]
    fn different_artifacts_different_tags(
        hostname in "[a-z]{3,20}",
        artifact1 in "[a-z0-9]{3,30}",
        artifact2 in "[a-z0-9]{3,30}"
    ) {
        prop_assume!(artifact1 != artifact2);
        
        let root = RootTag::generate().unwrap();
        
        let tag1 = root.derive_artifact_tag(&hostname, &artifact1);
        let tag2 = root.derive_artifact_tag(&hostname, &artifact2);
        
        prop_assert_ne!(tag1, tag2);
    }

    /// Derived tags should have consistent length (hex-encoded SHA3-512)
    #[test]
    fn derived_tags_have_consistent_length(
        hostname in "[a-z]{3,20}",
        artifact_id in "[a-z0-9]{3,30}"
    ) {
        let root = RootTag::generate().unwrap();
        let tag = root.derive_artifact_tag(&hostname, &artifact_id);
        
        // SHA3-512 produces 64 bytes = 128 hex characters
        prop_assert_eq!(tag.len(), 128);
    }
}

// ============================================================================
// POLICY VALIDATION PROPERTY TESTS
// ============================================================================

proptest! {
    /// Alert threshold must be in range [0, 100]
    #[test]
    fn alert_threshold_validation(threshold in any::<f64>()) {
        let mut policy = PolicyConfig::default();
        policy.scoring.alert_threshold = threshold;
        
        let result = policy.validate();
        
        if threshold >= 0.0 && threshold <= 100.0 {
            // Valid range - other validations might fail, but not threshold
            if result.is_err() {
                let err_str = result.unwrap_err().to_string();
                prop_assert!(!err_str.contains("alert_threshold"));
            }
        } else {
            // Invalid range - must fail
            prop_assert!(result.is_err());
        }
    }

    /// Correlation window must be in range [1, 3600]
    #[test]
    fn correlation_window_validation(window_secs in any::<u64>()) {
        let mut policy = PolicyConfig::default();
        policy.scoring.correlation_window_secs = window_secs;
        
        let result = policy.validate();
        
        if window_secs >= 1 && window_secs <= 3600 {
            if result.is_err() {
                let err_str = result.unwrap_err().to_string();
                prop_assert!(!err_str.contains("correlation_window"));
            }
        } else {
            prop_assert!(result.is_err());
        }
    }

    /// Max events must be in range [1, 100000]
    #[test]
    fn max_events_validation(max_events in any::<usize>()) {
        let mut policy = PolicyConfig::default();
        policy.scoring.max_events_in_memory = max_events;
        
        let result = policy.validate();
        
        if max_events >= 1 && max_events <= 100_000 {
            if result.is_err() {
                let err_str = result.unwrap_err().to_string();
                prop_assert!(!err_str.contains("max_events"));
            }
        } else {
            prop_assert!(result.is_err());
        }
    }

    /// Cooldown must be non-zero
    #[test]
    fn cooldown_validation(cooldown in any::<u64>()) {
        let mut policy = PolicyConfig::default();
        policy.response.cooldown_secs = cooldown;
        
        let result = policy.validate();
        
        if cooldown == 0 {
            prop_assert!(result.is_err());
        }
    }
}

// ============================================================================
// SUSPICIOUS PROCESS DETECTION PROPERTY TESTS
// ============================================================================

proptest! {
    /// Process detection should be case-insensitive
    #[test]
    fn process_detection_case_insensitive(
        process_name in "[a-zA-Z]{3,20}",
        use_upper in any::<bool>()
    ) {
        let mut policy = PolicyConfig::default();
        
        // Add lowercase version to suspicious processes
        policy.deception.suspicious_processes = vec![process_name.to_lowercase()]
            .into_boxed_slice();
        
        // Test with various cases
        let test_name = if use_upper {
            process_name.to_uppercase()
        } else {
            process_name.to_lowercase()
        };
        
        prop_assert!(policy.is_suspicious_process(&test_name));
    }

    /// Empty string should never match
    #[test]
    fn empty_string_never_suspicious(_patterns in prop::collection::vec("[a-z]{3,10}", 0..10)) {
        let mut policy = PolicyConfig::default();
        policy.deception.suspicious_processes = _patterns.into_boxed_slice();
        
        prop_assert!(!policy.is_suspicious_process(""));
    }

    /// Substring matching should work
    #[test]
    fn substring_matching(
        pattern in "[a-z]{3,10}",
        prefix in "[a-z]{0,5}",
        suffix in "[a-z]{0,5}"
    ) {
        let mut policy = PolicyConfig::default();
        policy.deception.suspicious_processes = vec![pattern.clone()]
            .into_boxed_slice();
        
        let full_name = format!("{}{}{}", prefix, pattern, suffix);
        
        prop_assert!(policy.is_suspicious_process(&full_name));
    }
}

// ============================================================================
// CONFIG VALIDATION PROPERTY TESTS
// ============================================================================

proptest! {
    /// Honeytoken count must be in range [1, 100]
    #[test]
    fn honeytoken_count_validation(count in any::<usize>()) {
        let mut config = Config::default();
        config.deception.honeytoken_count = count;
        
        let result = config.validate();
        
        if count >= 1 && count <= 100 {
            if result.is_err() {
                let err_str = result.unwrap_err().to_string();
                prop_assert!(!err_str.contains("honeytoken_count"));
            }
        } else {
            prop_assert!(result.is_err());
        }
    }

    /// Artifact permissions must be <= 0o777
    #[test]
    fn artifact_permissions_validation(perms in any::<u32>()) {
        let mut config = Config::default();
        config.deception.artifact_permissions = perms;
        
        let result = config.validate();
        
        if perms <= 0o777 {
            if result.is_err() {
                let err_str = result.unwrap_err().to_string();
                prop_assert!(!err_str.contains("artifact_permissions"));
            }
        } else {
            prop_assert!(result.is_err());
        }
    }

    /// Event buffer size must be >= 100
    #[test]
    fn event_buffer_size_validation(size in any::<usize>()) {
        let mut config = Config::default();
        config.telemetry.event_buffer_size = size;
        
        let result = config.validate();
        
        if size >= 100 {
            if result.is_err() {
                let err_str = result.unwrap_err().to_string();
                prop_assert!(!err_str.contains("event_buffer_size"));
            }
        } else {
            prop_assert!(result.is_err());
        }
    }

    /// Rotate size must be >= 1MB
    #[test]
    fn rotate_size_validation(size in any::<u64>()) {
        let mut config = Config::default();
        config.logging.rotate_size_bytes = size;
        
        let result = config.validate();
        
        if size >= 1024 * 1024 {
            if result.is_err() {
                let err_str = result.unwrap_err().to_string();
                prop_assert!(!err_str.contains("rotate_size"));
            }
        } else {
            prop_assert!(result.is_err());
        }
    }

    /// Max log files must be non-zero
    #[test]
    fn max_log_files_validation(count in any::<usize>()) {
        let mut config = Config::default();
        config.logging.max_log_files = count;
        
        let result = config.validate();
        
        if count == 0 {
            prop_assert!(result.is_err());
        }
    }
}

// ============================================================================
// SEVERITY MAPPING PROPERTY TESTS
// ============================================================================

proptest! {
    /// Severity from score should be monotonic
    #[test]
    fn severity_monotonic(score1 in 0.0f64..100.0, score2 in 0.0f64..100.0) {
        use palisade_config::Severity;
        
        let sev1 = Severity::from_score(score1);
        let sev2 = Severity::from_score(score2);
        
        if score1 < score2 {
            // Higher score should not result in lower severity
            prop_assert!(sev1 <= sev2);
        } else if score1 > score2 {
            prop_assert!(sev1 >= sev2);
        } else {
            prop_assert_eq!(sev1, sev2);
        }
    }

    /// Severity boundaries should be consistent
    #[test]
    fn severity_boundaries_consistent(score in 0.0f64..100.0) {
        use palisade_config::Severity;
        
        let severity = Severity::from_score(score);
        
        match severity {
            Severity::Critical => prop_assert!(score >= 80.0),
            Severity::High => prop_assert!(score >= 60.0 && score < 80.0),
            Severity::Medium => prop_assert!(score >= 40.0 && score < 60.0),
            Severity::Low => prop_assert!(score < 40.0),
        }
    }
}

// ============================================================================
// DIFF OPERATION PROPERTY TESTS
// ============================================================================

proptest! {
    /// Diff should be symmetric for paths
    #[test]
    fn diff_symmetric_for_no_changes(_seed in any::<u64>()) {
        let config1 = Config::default();
        let config2 = Config::default();
        
        let changes1 = config1.diff(&config2);
        let changes2 = config2.diff(&config1);
        
        // When configs are identical, diff should be empty both ways
        // (except for generated fields like root_tag)
        prop_assert_eq!(changes1.len(), changes2.len());
    }

    /// Diff should detect threshold changes
    #[test]
    fn diff_detects_threshold_change(old in 0.0f64..100.0, new in 0.0f64..100.0) {
        prop_assume!((old - new).abs() > 0.01);
        
        let mut policy1 = PolicyConfig::default();
        let mut policy2 = PolicyConfig::default();
        
        policy1.scoring.alert_threshold = old;
        policy2.scoring.alert_threshold = new;
        
        let changes = policy1.diff(&policy2);
        
        let has_threshold_change = changes.iter().any(|c| {
            matches!(c, palisade_config::PolicyChange::ThresholdChanged { .. })
        });
        
        prop_assert!(has_threshold_change);
    }
}
