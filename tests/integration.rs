//! Integration tests for palisade-config
//!
//! Tests full workflows: file loading, validation, serialization, diffing.

use palisade_config::{
    Config, PolicyConfig, RootTag, ValidationMode, ConfigChange, PolicyChange
};
use palisade_errors::definitions;
use std::path::PathBuf;
use tempfile::TempDir;
use tokio::fs;

const VALID_ROOT_TAG: &str = "8f2a7c91d4e6b3f0c5a19e274bd86370f1c49a2e6d8b35c7e902a4f1b6d3c8e5";

// ============================================================================
// CONFIG LOADING INTEGRATION TESTS
// ============================================================================

#[tokio::test]
async fn test_config_roundtrip_serialization() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("config.toml");

    // Create a config
    let mut original = Config::default();
    original.agent.environment = Some("production".to_string());

    // Serialize to TOML
    let toml_str = toml::to_string(&original).unwrap();
    fs::write(&config_path, &toml_str).await.unwrap();

    // Set proper permissions (Unix only)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&config_path).unwrap().permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(&config_path, perms).unwrap();
    }

    // Load it back
    let loaded = Config::from_file(&config_path).await.unwrap();

    // Verify key fields
    assert_eq!(loaded.version, original.version);
    assert_eq!(loaded.agent.environment, Some("production".to_string()));
    assert_eq!(loaded.deception.honeytoken_count, original.deception.honeytoken_count);
}

#[tokio::test]
async fn test_config_validates_on_load() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("invalid.toml");

    // Create invalid config (empty instance_id)
    let invalid_toml = format!(r#"
        version = 1

        [agent]
        instance_id = ""
        work_dir = "/var/lib/palisade"

        [deception]
        decoy_paths = ["/tmp/.creds"]
        credential_types = ["aws"]
        root_tag = "{VALID_ROOT_TAG}"

        [telemetry]
        watch_paths = ["/tmp"]

        [logging]
        log_path = "/var/log/palisade.log"
    "#);

    fs::write(&config_path, invalid_toml).await.unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&config_path).unwrap().permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(&config_path, perms).unwrap();
    }

    // Should fail validation
    let result = Config::from_file(&config_path).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_config_strict_validation_mode() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("config.toml");

    // Create config with non-existent paths
    let config_toml = format!(r#"
        version = 1

        [agent]
        instance_id = "test-agent"
        work_dir = "/var/lib/palisade"

        [deception]
        decoy_paths = ["/nonexistent/path"]
        credential_types = ["aws"]
        root_tag = "{VALID_ROOT_TAG}"

        [telemetry]
        watch_paths = ["/tmp"]

        [logging]
        log_path = "/var/log/palisade.log"
    "#);

    fs::write(&config_path, config_toml).await.unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&config_path).unwrap().permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(&config_path, perms).unwrap();
    }

    // Standard mode should pass
    let result_standard = Config::from_file(&config_path).await;
    assert!(result_standard.is_ok());

    // Strict mode should fail (path doesn't exist)
    let result_strict = Config::from_file_with_mode(&config_path, ValidationMode::Strict).await;
    assert!(result_strict.is_err());
}

#[cfg(unix)]
#[tokio::test]
async fn test_config_rejects_insecure_permissions() {
    use std::os::unix::fs::PermissionsExt;

    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("world_readable.toml");

    let config = Config::default();
    let toml_str = toml::to_string(&config).unwrap();
    fs::write(&config_path, &toml_str).await.unwrap();

    // Set world-readable permissions (INSECURE)
    let mut perms = std::fs::metadata(&config_path).unwrap().permissions();
    perms.set_mode(0o644);
    std::fs::set_permissions(&config_path, perms).unwrap();

    // Should fail security check
    let result = Config::from_file(&config_path).await;
    assert!(result.is_err());
    assert_eq!(*result.unwrap_err().code(), definitions::CFG_SECURITY_VIOLATION);
}

#[tokio::test]
async fn test_config_version_mismatch_detection() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("future_version.toml");

    // Create config with future version
    let future_toml = format!(r#"
        version = 999

        [agent]
        instance_id = "test"
        work_dir = "/var/lib/palisade"

        [deception]
        decoy_paths = ["/tmp"]
        credential_types = ["aws"]
        root_tag = "{VALID_ROOT_TAG}"

        [telemetry]
        watch_paths = ["/tmp"]

        [logging]
        log_path = "/var/log/palisade.log"
    "#);

    fs::write(&config_path, future_toml).await.unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&config_path).unwrap().permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(&config_path, perms).unwrap();
    }

    let result = Config::from_file(&config_path).await;
    assert!(result.is_err());
    assert_eq!(*result.unwrap_err().code(), definitions::CFG_VERSION_MISMATCH);
}

// ============================================================================
// POLICY LOADING INTEGRATION TESTS
// ============================================================================

#[tokio::test]
async fn test_policy_roundtrip_serialization() {
    let temp_dir = TempDir::new().unwrap();
    let policy_path = temp_dir.path().join("policy.toml");

    let original = PolicyConfig::default();

    let toml_str = toml::to_string(&original).unwrap();
    fs::write(&policy_path, &toml_str).await.unwrap();

    let loaded = PolicyConfig::from_file(&policy_path).await.unwrap();

    assert_eq!(loaded.version, original.version);
    assert_eq!(loaded.scoring.alert_threshold, original.scoring.alert_threshold);
    assert_eq!(loaded.response.rules.len(), original.response.rules.len());
}

#[tokio::test]
async fn test_policy_validates_custom_conditions() {
    let temp_dir = TempDir::new().unwrap();
    let policy_path = temp_dir.path().join("policy.toml");

    // Policy with unregistered custom condition
    let invalid_policy = r#"
        version = 1

        [scoring]
        alert_threshold = 50.0

        [deception]
        suspicious_processes = ["mimikatz"]

        [[response.rules]]
        severity = "High"
        action = "kill_process"

        [[response.rules.conditions]]
        type = "custom"
        name = "unregistered_condition"
        params = {}

        [response]
        cooldown_secs = 60
        max_kills_per_incident = 10
    "#;

    fs::write(&policy_path, invalid_policy).await.unwrap();

    // Should fail - custom condition not registered
    let result = PolicyConfig::from_file(&policy_path).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_policy_validates_registered_custom_conditions() {
    let temp_dir = TempDir::new().unwrap();
    let policy_path = temp_dir.path().join("policy.toml");

    let valid_policy = r#"
        version = 1
        registered_custom_conditions = ["my_custom_check"]

        [scoring]
        alert_threshold = 50.0

        [deception]
        suspicious_processes = ["mimikatz"]

        [[response.rules]]
        severity = "High"
        action = "kill_process"

        [[response.rules.conditions]]
        type = "custom"
        name = "my_custom_check"
        params = {}

        [response]
        cooldown_secs = 60
        max_kills_per_incident = 10
    "#;

    fs::write(&policy_path, valid_policy).await.unwrap();

    // Should pass - custom condition is registered
    let result = PolicyConfig::from_file(&policy_path).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_policy_max_events_validation() {
    let temp_dir = TempDir::new().unwrap();
    let policy_path = temp_dir.path().join("policy.toml");

    // Policy with excessive max_events_in_memory
    let invalid_policy = r#"
        version = 1

        [scoring]
        alert_threshold = 50.0
        max_events_in_memory = 200000

        [deception]
        suspicious_processes = []

        [[response.rules]]
        severity = "Low"
        action = "log"

        [response]
        cooldown_secs = 60
    "#;

    fs::write(&policy_path, invalid_policy).await.unwrap();

    let result = PolicyConfig::from_file(&policy_path).await;
    assert!(result.is_err());
}

// ============================================================================
// DIFF OPERATION INTEGRATION TESTS
// ============================================================================

#[test]
fn test_config_diff_detects_multiple_changes() {
    let config1 = Config::default();
    let mut config2 = Config::default();

    // Make multiple changes
    config2.deception.root_tag = RootTag::generate().unwrap();
    config2.deception.decoy_paths = vec![PathBuf::from("/new/path")].into_boxed_slice();
    config2.telemetry.enable_syscall_monitor = true;

    let changes = config1.diff(&config2);

    // Should detect root tag change, path change, and capability change
    assert!(changes.len() >= 2); // At least root tag and one other

    let has_root_tag_change = changes.iter().any(|c| matches!(c, ConfigChange::RootTagChanged { .. }));
    let has_path_change = changes.iter().any(|c| matches!(c, ConfigChange::PathsChanged { .. }));

    assert!(has_root_tag_change);
    assert!(has_path_change);
}

#[test]
fn test_policy_diff_detects_threshold_changes() {
    let policy1 = PolicyConfig::default();
    let mut policy2 = PolicyConfig::default();

    policy2.scoring.alert_threshold = 75.0;

    let changes = policy1.diff(&policy2);

    assert_eq!(changes.len(), 1);
    assert!(matches!(
        changes[0],
        PolicyChange::ThresholdChanged { field: _, old: 50.0, new: 75.0 }
    ));
}

#[test]
fn test_policy_diff_detects_process_changes() {
    let policy1 = PolicyConfig::default();
    let mut policy2 = PolicyConfig::default();

    // Add new suspicious process
    policy2.deception.suspicious_processes = vec![
        "mimikatz".to_string(),
        "procdump".to_string(),
        "lazagne".to_string(),
        "newmalware".to_string(),
    ].into_boxed_slice();

    let changes = policy1.diff(&policy2);

    let process_changes = changes.iter().find(|c| {
        matches!(c, PolicyChange::SuspiciousProcessesChanged { .. })
    });

    assert!(process_changes.is_some());
}

// ============================================================================
// CONCURRENT LOADING TESTS
// ============================================================================

#[tokio::test]
async fn test_concurrent_config_loading() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("config.toml");

    let config = Config::default();
    let toml_str = toml::to_string(&config).unwrap();
    fs::write(&config_path, &toml_str).await.unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&config_path).unwrap().permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(&config_path, perms).unwrap();
    }

    // Load config from multiple tasks concurrently
    let mut handles = vec![];
    for _ in 0..10 {
        let path = config_path.clone();
        let handle = tokio::spawn(async move {
            Config::from_file(&path).await
        });
        handles.push(handle);
    }

    // All should succeed
    for handle in handles {
        let result = handle.await.unwrap();
        assert!(result.is_ok());
    }
}

// ============================================================================
// HOSTNAME DERIVATION TESTS
// ============================================================================

#[test]
fn test_hostname_from_config_or_system() {
    let mut config = Config::default();
    
    // Test with explicitly set hostname
    config.agent.hostname = Some("test-host".to_string());
    let hostname = config.hostname();
    assert_eq!(hostname.as_ref(), "test-host");

    // Test with system hostname fallback
    config.agent.hostname = None;
    let hostname = config.hostname();
    assert!(!hostname.is_empty());
}

// ============================================================================
// TAG DERIVATION INTEGRATION TESTS
// ============================================================================

#[test]
fn test_tag_derivation_consistency() {
    let root = RootTag::generate().unwrap();
    
    // Same hostname and artifact should produce same tag
    let tag1 = root.derive_artifact_tag("host1", "artifact1");
    let tag2 = root.derive_artifact_tag("host1", "artifact1");
    assert_eq!(tag1, tag2);

    // Different hostname should produce different tag
    let tag3 = root.derive_artifact_tag("host2", "artifact1");
    assert_ne!(tag1, tag3);

    // Different artifact should produce different tag
    let tag4 = root.derive_artifact_tag("host1", "artifact2");
    assert_ne!(tag1, tag4);
}

#[test]
fn test_tag_derivation_hierarchy() {
    let root = RootTag::generate().unwrap();
    
    // Host tags should be deterministic
    let host_tag1 = root.derive_host_tag("production-server");
    let host_tag2 = root.derive_host_tag("production-server");
    assert_eq!(host_tag1, host_tag2);

    // Different roots should produce different host tags
    let root2 = RootTag::generate().unwrap();
    let host_tag3 = root2.derive_host_tag("production-server");
    assert_ne!(host_tag1, host_tag3);
}

// ============================================================================
// SUSPICIOUS PROCESS DETECTION TESTS
// ============================================================================

#[test]
fn test_suspicious_process_case_insensitivity() {
    let policy = PolicyConfig::default();

    // Should match regardless of case
    assert!(policy.is_suspicious_process("mimikatz"));
    assert!(policy.is_suspicious_process("MIMIKATZ"));
    assert!(policy.is_suspicious_process("MiMiKaTz"));
    assert!(policy.is_suspicious_process("mimikatz.exe"));
    
    // Should not match benign processes
    assert!(!policy.is_suspicious_process("firefox"));
    assert!(!policy.is_suspicious_process("chrome"));
}

#[test]
fn test_suspicious_process_substring_matching() {
    let policy = PolicyConfig::default();

    // Should match if pattern is substring
    assert!(policy.is_suspicious_process("my_mimikatz_variant.exe"));
    assert!(policy.is_suspicious_process("procdump64.exe"));
    
    // Should not match partial overlaps
    assert!(!policy.is_suspicious_process("procmon"));
}
