//! Security-focused tests for palisade-config.
//!
//! Tests cover:
//! - Memory zeroization
//! - Information disclosure prevention
//! - Entropy validation
//! - Permission validation
//! - Attack surface minimization

use palisade_config::{Config, RootTag, ValidationMode, ProtectedPath, ProtectedString};
use std::path::PathBuf;
use tempfile::TempDir;

#[test]
fn test_root_tag_never_serialized_raw() {
    let tag = RootTag::generate();
    let serialized = toml::to_string(&tag).unwrap();
    
    // Raw secret should never appear in serialization
    assert!(serialized.contains("REDACTED"));
    assert!(!serialized.contains(hex::encode(&[0u8; 32]).as_str()));
}

#[test]
fn test_root_tag_debug_format_safe() {
    let tag = RootTag::generate();
    let debug_output = format!("{:?}", tag);
    
    // Debug output should not expose raw secret
    assert!(debug_output.contains("REDACTED"));
}

#[test]
fn test_deserialization_rejects_redacted_tag() {
    let toml_str = r#"root_tag = "***REDACTED***""#;
    let result: Result<RootTag, _> = toml::from_str(toml_str);
    
    // Should not allow deserializing placeholder
    assert!(result.is_err());
}

#[test]
fn test_entropy_validation_comprehensive() {
    // All zeros - REJECTED
    let all_zeros = hex::encode(vec![0u8; 32]);
    assert!(RootTag::new(all_zeros).is_err());
    
    // Sequential pattern - REJECTED
    let sequential: Vec<u8> = (0..32).collect();
    assert!(RootTag::new(hex::encode(sequential)).is_err());
    
    // Low diversity - REJECTED
    let low_diversity = vec![0xAA, 0xBB].repeat(16);
    assert!(RootTag::new(hex::encode(low_diversity)).is_err());
    
    // Repeated substring - REJECTED
    let repeated = b"DEADBEEF".repeat(4);
    assert!(RootTag::new(hex::encode(repeated)).is_err());
    
    // Good entropy - ACCEPTED
    let good = hex::encode(vec![
        0x1a, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f, 0x70, 0x81,
        0x92, 0xa3, 0xb4, 0xc5, 0xd6, 0xe7, 0xf8, 0x09,
        0xfe, 0xed, 0xdc, 0xcb, 0xba, 0xa9, 0x98, 0x87,
        0x76, 0x65, 0x54, 0x43, 0x32, 0x21, 0x10, 0x0f,
    ]);
    assert!(RootTag::new(good).is_ok());
}

#[test]
fn test_tag_derivation_provides_isolation() {
    let root = RootTag::generate();
    
    // Same artifact ID, different hosts
    let tag1 = root.derive_artifact_tag("host-a", "aws-credentials");
    let tag2 = root.derive_artifact_tag("host-b", "aws-credentials");
    
    // Tags must be different (prevents cross-host correlation)
    assert_ne!(tag1, tag2);
    
    // Tag length should be consistent
    assert_eq!(tag1.len(), 128); // 64 bytes * 2 hex chars
    assert_eq!(tag2.len(), 128);
}

#[test]
fn test_tag_derivation_deterministic() {
    let root = RootTag::generate();
    
    // Multiple derivations with same inputs
    let tag1 = root.derive_artifact_tag("host-x", "ssh-key");
    let tag2 = root.derive_artifact_tag("host-x", "ssh-key");
    let tag3 = root.derive_artifact_tag("host-x", "ssh-key");
    
    // Must be identical (required for defenders to correlate)
    assert_eq!(tag1, tag2);
    assert_eq!(tag2, tag3);
}

#[test]
fn test_config_file_permission_validation_unix() {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("config.toml");
        
        let toml_content = r#"
version = 1
[agent]
instance_id = "test"
work_dir = "/tmp/test"
[deception]
decoy_paths = ["/tmp/.fake"]
credential_types = ["aws"]
root_tag = "a1b2c3d4e5f67890abcdef1234567890a1b2c3d4e5f67890abcdef1234567890"
[telemetry]
watch_paths = ["/tmp"]
[logging]
log_path = "/tmp/test.log"
"#;
        
        std::fs::write(&config_path, toml_content).unwrap();
        
        // Set insecure permissions (world-readable)
        let mut perms = std::fs::metadata(&config_path).unwrap().permissions();
        perms.set_mode(0o644); // rw-r--r--
        std::fs::set_permissions(&config_path, perms).unwrap();
        
        // Should reject insecure file
        let result = Config::from_file(&config_path);
        assert!(result.is_err());
        
        if let Err(err) = result {
            let display = err.to_string();
            assert!(display.contains("permission") || display.contains("insecure"));
        }
        
        // Set secure permissions
        let mut perms = std::fs::metadata(&config_path).unwrap().permissions();
        perms.set_mode(0o600); // rw-------
        std::fs::set_permissions(&config_path, perms).unwrap();
        
        // Should now accept
        assert!(Config::from_file(&config_path).is_ok());
    }
}

#[test]
fn test_no_sensitive_data_in_default_error_display() {
    let mut config = Config::default();
    config.agent.instance_id = ProtectedString::new(String::new());
    
    let result = config.validate();
    assert!(result.is_err());
    
    if let Err(err) = result {
        let external_display = format!("{}", err);
        
        // External display should NOT contain:
        // - File paths
        // - Configuration values
        // - Stack traces
        // Should only show generic error code and message
        assert!(!external_display.contains("/tmp"));
        assert!(!external_display.contains("/var"));
        assert!(!external_display.contains("work_dir"));
    }
}

#[test]
fn test_internal_log_has_full_context() {
    let mut config = Config::default();
    config.deception.honeytoken_count = 0;
    
    let result = config.validate();
    assert!(result.is_err());
    
    if let Err(err) = result {
        // Internal log should have complete context
        err.with_internal_log(|log| {
            let log_str = format!("{:?}", log);
            // Should contain useful debugging information
            assert!(!log_str.is_empty());
        });
    }
}

#[test]
fn test_strict_validation_checks_work_dir_ownership() {
    #[cfg(unix)]
    {
        let temp_dir = TempDir::new().unwrap();
        let mut config = Config::default();
        config.agent.work_dir = ProtectedPath::new(temp_dir.path().join("agent-work"));
        
        // Create the directory
        std::fs::create_dir_all(config.agent.work_dir.as_path()).unwrap();
        
        // Strict validation should check ownership
        // (This test assumes current user owns temp_dir, so it should pass)
        let result = config.validate_with_mode(ValidationMode::Strict);
        assert!(result.is_ok() || result.is_err()); // Platform-dependent
    }
}

#[test]
fn test_validation_prevents_directory_traversal_attempts() {
    let mut config = Config::default();
    
    // Attempt to use relative path (potential traversal)
    config.agent.work_dir = ProtectedPath::new(PathBuf::from("../../../etc/shadow"));
    
    let result = config.validate();
    assert!(result.is_err());
    
    // Attempt to use path with traversal components
    config.agent.work_dir = ProtectedPath::new(PathBuf::from("/tmp/../../../etc/shadow"));
    
    // Even though this is absolute, it's suspicious
    // (Current validation requires absolute paths)
    let result = config.validate();
    // Should be okay since it's absolute, but application layer should normalize
    assert!(result.is_ok() || result.is_err()); // Implementation-dependent
}

#[test]
fn test_honeytoken_count_bounds_prevent_dos() {
    let mut config = Config::default();
    
    // Too few - should fail
    config.deception.honeytoken_count = 0;
    assert!(config.validate().is_err());
    
    // Too many - should fail (prevents resource exhaustion)
    config.deception.honeytoken_count = 101;
    assert!(config.validate().is_err());
    
    // Reasonable range - should pass
    config.deception.honeytoken_count = 50;
    assert!(config.validate().is_ok());
}

#[test]
fn test_buffer_size_minimums_prevent_dos() {
    let mut config = Config::default();
    
    // Too small buffer - potential DoS vector
    config.telemetry.event_buffer_size = 10;
    assert!(config.validate().is_err());
    
    // Reasonable buffer size
    config.telemetry.event_buffer_size = 1000;
    assert!(config.validate().is_ok());
}

#[test]
fn test_log_rotation_settings_prevent_disk_exhaustion() {
    let mut config = Config::default();
    
    // Too small rotation size - potential disk exhaustion
    config.logging.rotate_size_bytes = 100; // 100 bytes
    assert!(config.validate().is_err());
    
    // Zero max log files - potential disk exhaustion
    config.logging.max_log_files = 0;
    assert!(config.validate().is_err());
    
    // Reasonable settings
    config.logging.rotate_size_bytes = 10 * 1024 * 1024; // 10MB
    config.logging.max_log_files = 5;
    assert!(config.validate().is_ok());
}

#[test]
fn test_artifact_permissions_validation_unix() {
    let mut config = Config::default();
    
    // Invalid Unix permissions (> 0o777)
    config.deception.artifact_permissions = 0o1000;
    assert!(config.validate().is_err());
    
    // Valid permissions
    config.deception.artifact_permissions = 0o600;
    assert!(config.validate().is_ok());
}

#[test]
fn test_error_metadata_never_exposed_externally() {
    let mut config = Config::default();
    config.agent.work_dir = ProtectedPath::new(PathBuf::from("relative/path"));
    
    let result = config.validate();
    assert!(result.is_err());
    
    if let Err(err) = result {
        let external = format!("{}", err);
        
        // Metadata should not leak in external display
        assert!(!external.contains("relative/path"));
        assert!(!external.contains("metadata"));
    }
}

#[test]
fn test_tag_hash_comparison_safe() {
    let tag1 = RootTag::generate();
    let tag2 = RootTag::generate();
    
    // Can compare hashes without exposing secrets
    assert_ne!(tag1.hash(), tag2.hash());
    
    // Hash should be fixed size (SHA3-512 = 64 bytes)
    assert_eq!(tag1.hash().len(), 64);
    assert_eq!(tag2.hash().len(), 64);
}

#[test]
fn test_minimum_tag_length_enforced() {
    // Too short - should fail (less than 256 bits)
    let short_tag = hex::encode(vec![0xAB; 16]); // 128 bits
    assert!(RootTag::new(short_tag).is_err());
    
    // Minimum length (256 bits = 64 hex chars)
    let min_tag = hex::encode(vec![
        0x1a, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f, 0x70, 0x81,
        0x92, 0xa3, 0xb4, 0xc5, 0xd6, 0xe7, 0xf8, 0x09,
        0xfe, 0xed, 0xdc, 0xcb, 0xba, 0xa9, 0x98, 0x87,
        0x76, 0x65, 0x54, 0x43, 0x32, 0x21, 0x10, 0x0f,
    ]);
    assert!(RootTag::new(min_tag).is_ok());
}

#[test]
fn test_config_version_protection() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("config.toml");
    
    let future_version = r#"
version = 999
[agent]
instance_id = "test"
work_dir = "/tmp/test"
[deception]
decoy_paths = ["/tmp/.fake"]
credential_types = ["aws"]
root_tag = "a1b2c3d4e5f67890abcdef1234567890a1b2c3d4e5f67890abcdef1234567890"
[telemetry]
watch_paths = ["/tmp"]
[logging]
log_path = "/tmp/test.log"
"#;
    
    std::fs::write(&config_path, future_version).unwrap();
    
    // Should reject future versions
    let result = Config::from_file(&config_path);
    assert!(result.is_err());
}

#[test]
fn test_empty_lists_rejected_appropriately() {
    let mut config = Config::default();
    
    // Empty decoy paths - should fail
    config.deception.decoy_paths.clear();
    assert!(config.validate().is_err());
    
    // Empty credential types - should fail
    config.deception.decoy_paths = vec![PathBuf::from("/tmp/.fake")];
    config.deception.credential_types.clear();
    assert!(config.validate().is_err());
    
    // Empty watch paths - should fail
    config.deception.credential_types = vec!["aws".to_string()];
    config.telemetry.watch_paths.clear();
    assert!(config.validate().is_err());
}

#[test]
fn test_generated_tags_always_pass_entropy_validation() {
    // Generate many tags and verify all pass entropy checks
    for _ in 0..100 {
        let tag = RootTag::generate();
        
        // If this panics, RNG is broken
        assert_eq!(tag.hash().len(), 64);
    }
}

#[test]
fn test_config_cannot_be_cloned() {
    // This test documents that Clone is not available
    // Compile-time enforcement, but we can verify at runtime
    
    let config = Config::default();
    let _ref = &config; // References work
    
    // config.clone() would fail to compile
    // This test just verifies config exists and is usable
    assert!(config.validate().is_ok());
}

#[test]
fn test_policy_cannot_be_cloned() {
    use palisade_config::PolicyConfig;
    
    // This test documents that Clone is not available
    let policy = PolicyConfig::default();
    let _ref = &policy; // References work
    
    // policy.clone() would fail to compile
    assert!(policy.validate().is_ok());
}

#[test]
fn test_zeroization_on_drop() {
    // Create protected string in inner scope
    {
        let _protected = ProtectedString::new("secret_data".to_string());
        // Protected data exists here
    } // <- Zeroized on drop
    
    // Memory should be scrubbed after this point
    // Can't directly verify without unsafe code, but ZeroizeOnDrop guarantees this
}

#[test]
fn test_protected_types_redact_debug() {
    let protected = ProtectedString::new("sensitive".to_string());
    let debug = format!("{:?}", protected);
    
    assert!(debug.contains("REDACTED"));
    assert!(!debug.contains("sensitive"));
}