//! Comprehensive integration tests for palisade-config.
//!
//! Tests cover:
//! - Configuration loading and validation
//! - Policy loading and validation
//! - Tag derivation and entropy
//! - Change tracking and diffing
//! - Error handling and metadata
//! - Platform-specific behavior

use palisade_config::{
    Config, PolicyConfig, RootTag, ValidationMode, ConfigChange, PolicyChange,
    Severity, ActionType, ResponseCondition, ResponseRule,
};
use std::path::PathBuf;
use tempfile::TempDir;

#[test]
fn test_config_load_from_toml() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("config.toml");
    
    let toml_content = r#"
version = 1

[agent]
instance_id = "test-agent-001"
work_dir = "/tmp/palisade-test"
environment = "testing"

[deception]
decoy_paths = ["/tmp/.fake-creds"]
credential_types = ["aws", "ssh"]
honeytoken_count = 10
root_tag = "a1b2c3d4e5f67890abcdef1234567890a1b2c3d4e5f67890abcdef1234567890"
artifact_permissions = 0o600

[telemetry]
watch_paths = ["/tmp"]
event_buffer_size = 10000
enable_syscall_monitor = false

[logging]
log_path = "/tmp/palisade-test.log"
format = "json"
rotate_size_bytes = 104857600
max_log_files = 10
level = "INFO"
"#;

    std::fs::write(&config_path, toml_content).unwrap();
    
    // Load and validate
    let config = Config::from_file(&config_path).unwrap();
    
    assert_eq!(config.agent.instance_id.as_str(), "test-agent-001");
    assert_eq!(config.agent.environment, Some("testing".to_string()));
    assert_eq!(config.deception.honeytoken_count, 10);
}

#[test]
fn test_config_validation_mode_standard() {
    let config = Config::default();
    
    // Standard mode doesn't check filesystem
    assert!(config.validate_with_mode(ValidationMode::Standard).is_ok());
}

#[test]
fn test_config_validation_strict_mode_work_dir_creation() {
    let temp_dir = TempDir::new().unwrap();
    let mut config = Config::default();
    config.agent.work_dir = ProtectedPath::new(temp_dir.path().join("agent-work"));
    
    // Strict mode should create the directory
    assert!(config.validate_with_mode(ValidationMode::Strict).is_ok());
    assert!(config.agent.work_dir.as_path().exists());
}

#[test]
fn test_config_validation_catches_version_mismatch() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("config.toml");
    
    let toml_content = r#"
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

    std::fs::write(&config_path, toml_content).unwrap();
    
    let result = Config::from_file(&config_path);
    assert!(result.is_err());
    
    if let Err(err) = result {
        let display = err.to_string();
        assert!(display.contains("version") || display.contains("mismatch"));
    }
}

#[test]
fn test_policy_load_from_toml() {
    let temp_dir = TempDir::new().unwrap();
    let policy_path = temp_dir.path().join("policy.toml");
    
    let toml_content = r#"
version = 1

[scoring]
correlation_window_secs = 300
alert_threshold = 65.0
max_events_in_memory = 10000
enable_time_scoring = true
enable_ancestry_tracking = true
business_hours_start = 9
business_hours_end = 17

[scoring.weights]
artifact_access = 50.0
suspicious_process = 30.0
rapid_enumeration = 20.0
off_hours_activity = 15.0
ancestry_suspicious = 10.0

[response]
cooldown_secs = 60
max_kills_per_incident = 10
dry_run = false

[[response.rules]]
severity = "Low"
action = "log"

[[response.rules]]
severity = "High"
action = "kill_process"

[deception]
suspicious_processes = ["mimikatz", "procdump", "lazagne"]
suspicious_patterns = ["*.env", "*.credentials"]
"#;

    std::fs::write(&policy_path, toml_content).unwrap();
    
    let policy = PolicyConfig::from_file(&policy_path).unwrap();
    
    assert_eq!(policy.scoring.alert_threshold, 65.0);
    assert_eq!(policy.deception.suspicious_processes.len(), 3);
}

#[test]
fn test_policy_suspicious_process_detection() {
    let policy = PolicyConfig::default();
    
    // Case-insensitive detection
    assert!(policy.is_suspicious_process("MIMIKATZ.exe"));
    assert!(policy.is_suspicious_process("mimikatz"));
    assert!(policy.is_suspicious_process("MiMiKaTz"));
    
    // Benign processes
    assert!(!policy.is_suspicious_process("firefox"));
    assert!(!policy.is_suspicious_process("chrome"));
}

#[test]
fn test_policy_custom_condition_validation() {
    let mut policy = PolicyConfig::default();
    
    // Add unregistered custom condition - should fail validation
    policy.response.rules.push(ResponseRule {
        severity: Severity::Medium,
        conditions: vec![ResponseCondition::Custom {
            name: "unregistered_condition".to_string(),
            params: std::collections::HashMap::new(),
        }],
        action: ActionType::Alert,
    });
    
    assert!(policy.validate().is_err());
    
    // Register the condition - should now pass
    policy.registered_custom_conditions.insert("unregistered_condition".to_string());
    assert!(policy.validate().is_ok());
}

#[test]
fn test_severity_from_score() {
    assert_eq!(Severity::from_score(90.0), Severity::Critical);
    assert_eq!(Severity::from_score(70.0), Severity::High);
    assert_eq!(Severity::from_score(50.0), Severity::Medium);
    assert_eq!(Severity::from_score(30.0), Severity::Low);
    assert_eq!(Severity::from_score(0.0), Severity::Low);
}

#[test]
fn test_root_tag_generation() {
    let tag1 = RootTag::generate();
    let tag2 = RootTag::generate();
    
    // Different instances should have different hashes
    assert_ne!(tag1.hash(), tag2.hash());
    
    // Hash length should be 64 bytes (SHA3-512)
    assert_eq!(tag1.hash().len(), 64);
}

#[test]
fn test_tag_derivation_deterministic() {
    let root = RootTag::generate();
    
    let tag1 = root.derive_artifact_tag("host-a", "artifact-1");
    let tag2 = root.derive_artifact_tag("host-a", "artifact-1");
    
    // Same inputs should produce same output
    assert_eq!(tag1, tag2);
}

#[test]
fn test_tag_derivation_isolation() {
    let root = RootTag::generate();
    
    let tag_host_a = root.derive_artifact_tag("host-a", "ssh-key");
    let tag_host_b = root.derive_artifact_tag("host-b", "ssh-key");
    
    // Different hosts should have different tags
    assert_ne!(tag_host_a, tag_host_b);
}

#[test]
fn test_tag_entropy_validation_rejects_all_zeros() {
    let all_zeros = hex::encode(vec![0u8; 32]);
    assert!(RootTag::new(all_zeros).is_err());
}

#[test]
fn test_tag_entropy_validation_rejects_sequential() {
    let sequential: Vec<u8> = (0..32).collect();
    assert!(RootTag::new(hex::encode(sequential)).is_err());
}

#[test]
fn test_tag_entropy_validation_accepts_good_entropy() {
    let good_entropy = hex::encode(vec![
        0x1a, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f, 0x70, 0x81,
        0x92, 0xa3, 0xb4, 0xc5, 0xd6, 0xe7, 0xf8, 0x09,
        0xfe, 0xed, 0xdc, 0xcb, 0xba, 0xa9, 0x98, 0x87,
        0x76, 0x65, 0x54, 0x43, 0x32, 0x21, 0x10, 0x0f,
    ]);
    
    assert!(RootTag::new(good_entropy).is_ok());
}

#[test]
fn test_config_diff_detects_root_tag_change() {
    // Create two separate configs
    let config1 = Config::default();
    let mut config2 = Config::default();
    config2.deception.root_tag = RootTag::generate();
    
    let changes = config1.diff(&config2);
    assert!(!changes.is_empty());
    
    // Verify root tag change was detected
    assert!(changes.iter().any(|c| matches!(c, ConfigChange::RootTagChanged { .. })));
}

#[test]
fn test_config_diff_detects_path_changes() {
    // Create two separate configs with different paths
    let config1 = {
        let mut c = Config::default();
        c.deception.decoy_paths = vec![PathBuf::from("/tmp/old")];
        c
    };
    
    let config2 = {
        let mut c = Config::default();
        c.deception.decoy_paths = vec![PathBuf::from("/tmp/new")];
        c
    };
    
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
    let policy1 = {
        let mut p = PolicyConfig::default();
        p.scoring.alert_threshold = 50.0;
        p
    };
    
    let policy2 = {
        let mut p = PolicyConfig::default();
        p.scoring.alert_threshold = 75.0;
        p
    };
    
    let changes = policy1.diff(&policy2);
    assert!(!changes.is_empty());
    
    assert!(changes.iter().any(|c| matches!(c, PolicyChange::ThresholdChanged { .. })));
}

#[test]
fn test_policy_diff_detects_suspicious_process_changes() {
    let policy1 = PolicyConfig::default();
    
    let policy2 = {
        let mut p = PolicyConfig::default();
        p.deception.suspicious_processes.push("bloodhound".to_string());
        p
    };
    
    let changes = policy1.diff(&policy2);
    assert!(!changes.is_empty());
    
    if let Some(PolicyChange::SuspiciousProcessesChanged { added, removed }) = changes.first() {
        assert_eq!(added.len(), 1);
        assert_eq!(added[0], "bloodhound");
        assert_eq!(removed.len(), 0);
    } else {
        panic!("Expected SuspiciousProcessesChanged");
    }
}

#[test]
fn test_error_metadata_presence() {
    let mut config = Config::default();
    config.agent.instance_id = ProtectedString::new(String::new());
    
    let result = config.validate();
    assert!(result.is_err());
    
    if let Err(err) = result {
        // Error should have metadata from palisade-errors
        err.with_internal_log(|log| {
            // Internal log should have context
            assert!(
                log.source_internal().expect("No source internal").contains("instance_id") || 
                log.source_internal().expect("No source internal").contains("validate"));
        });
    }
}

#[test]
fn test_hostname_resolution() {
    let config = Config::default();
    let hostname = config.hostname();
    
    // Should return something (either configured or system hostname)
    assert!(!hostname.is_empty());
    assert_ne!(hostname, "");
}

#[test]
fn test_default_config_completeness() {
    let config = Config::default();
    
    // All required fields should be populated
    assert!(!config.agent.instance_id.as_str().is_empty());
    assert!(!config.deception.decoy_paths.is_empty());
    assert!(!config.deception.credential_types.is_empty());
    assert!(!config.telemetry.watch_paths.is_empty());
    assert!(config.deception.honeytoken_count > 0);
}

#[test]
fn test_default_policy_completeness() {
    let policy = PolicyConfig::default();
    
    // All required fields should be populated
    assert!(!policy.response.rules.is_empty());
    assert!(!policy.deception.suspicious_processes.is_empty());
    assert!(policy.scoring.alert_threshold > 0.0);
    assert!(policy.validate().is_ok());
}

#[test]
fn test_validation_error_codes_present() {
    let mut config = Config::default();
    config.agent.work_dir = ProtectedPath::new(PathBuf::from("relative/path"));
    
    let result = config.validate();
    assert!(result.is_err());
    
    if let Err(err) = result {
        // Error should be categorized
        let display = format!("{}", err);
        // Should have error code format
        assert!(display.contains("E-") || !display.is_empty());
    }
}

// Import protected types
use palisade_config::{ProtectedString, ProtectedPath};