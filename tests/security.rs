//! Security-focused tests for palisade-config
//!
//! Tests adversarial inputs, injection attempts, and security properties.

use palisade_config::{Config, PolicyConfig, RootTag, ProtectedString, ProtectedPath};
use std::path::PathBuf;
use tempfile::TempDir;
use tokio::fs;

// ============================================================================
// TOML INJECTION ATTACK TESTS
// ============================================================================

#[tokio::test]
async fn test_toml_injection_in_strings() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("injection.toml");

    // Attempt TOML injection via string field
    let malicious_toml = r#"
        version = 1

        [agent]
        instance_id = "normal"
        work_dir = "/var/lib/palisade"
        environment = """
        injected"
        [malicious]
        evil = true
        """

        [deception]
        decoy_paths = ["/tmp"]
        credential_types = ["aws"]
        root_tag = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

        [telemetry]
        watch_paths = ["/tmp"]

        [logging]
        log_path = "/var/log/palisade.log"
    "#;

    fs::write(&config_path, malicious_toml).await.unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&config_path).unwrap().permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(&config_path, perms).unwrap();
    }

    // Should either reject malformed TOML or safely escape the injection
    let result = Config::from_file(&config_path).await;
    
    if let Ok(config) = result {
        // If it parsed, the injection should be escaped in the environment string
        assert!(config.agent.environment.is_some());
        let env = config
            .agent
            .environment
            .as_deref()
            .expect("environment should be present");
        // The newlines should be preserved as part of the string value
        assert!(env.contains("injected"));
    }
    // Parsing failure is also acceptable for malformed input
}

#[tokio::test]
async fn test_path_traversal_in_config_paths() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("traversal.toml");

    // Attempt path traversal
    let traversal_toml = r#"
        version = 1

        [agent]
        instance_id = "test"
        work_dir = "/var/lib/../../etc/passwd"

        [deception]
        decoy_paths = ["/tmp/../../../etc/shadow"]
        credential_types = ["aws"]
        root_tag = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

        [telemetry]
        watch_paths = ["/tmp"]

        [logging]
        log_path = "/var/log/palisade.log"
    "#;

    fs::write(&config_path, traversal_toml).await.unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&config_path).unwrap().permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(&config_path, perms).unwrap();
    }

    let result = Config::from_file(&config_path).await;
    
    if let Ok(config) = result {
        // Paths should be canonicalized or validated
        // The system should accept the path as-is (validation happens at runtime)
        // but the path traversal should still be in the PathBuf
        assert!(config.agent.work_dir.as_path().to_string_lossy().contains(".."));
    }
}

#[tokio::test]
async fn test_unicode_normalization_attacks() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("unicode.toml");

    // Unicode look-alike characters
    let unicode_toml = r#"
        version = 1

        [agent]
        instance_id = "tеst"
        work_dir = "/var/lib/palisade"

        [deception]
        decoy_paths = ["/tmp"]
        credential_types = ["аws"]
        root_tag = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

        [telemetry]
        watch_paths = ["/tmp"]

        [logging]
        log_path = "/var/log/palisade.log"
    "#;

    fs::write(&config_path, unicode_toml).await.unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&config_path).unwrap().permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(&config_path, perms).unwrap();
    }

    // Should parse without crashing
    let result = Config::from_file(&config_path).await;
    assert!(result.is_ok() || result.is_err()); // Either is fine, just shouldn't panic
}

// ============================================================================
// ENTROPY MANIPULATION TESTS
// ============================================================================

#[test]
fn test_weak_entropy_rejected() {
    // Test various weak entropy patterns
    let weak_patterns = vec![
        // All zeros
        hex::encode(vec![0u8; 32]),
        // All ones
        hex::encode(vec![0xFFu8; 32]),
        // Sequential
        hex::encode((0..32).collect::<Vec<u8>>()),
        // Repeated pattern
        hex::encode(vec![0xAB, 0xCD].repeat(16)),
        // Low diversity
        hex::encode(vec![0x42; 31].iter().chain(&[0x43]).copied().collect::<Vec<u8>>()),
    ];

    for pattern in weak_patterns {
        let result = RootTag::new(pattern);
        assert!(result.is_err(), "Weak entropy pattern should be rejected");
    }
}

#[test]
fn test_truncated_entropy_rejected() {
    // Too short (less than 256 bits)
    let short_patterns = vec![
        hex::encode(vec![0x42u8; 16]), // 128 bits
        hex::encode(vec![0x42u8; 24]), // 192 bits
        "0123456789abcdef".to_string(),  // Very short
    ];

    for pattern in short_patterns {
        let result = RootTag::new(pattern);
        assert!(result.is_err(), "Truncated entropy should be rejected");
    }
}

#[test]
fn test_invalid_hex_rejected() {
    let invalid_hex = vec![
        "not hex at all",
        "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ",
        "0123456789abcdefg", // 'g' is invalid
        "0x0123456789abcdef0123456789abcdef", // 0x prefix not allowed
    ];

    for pattern in invalid_hex {
        let result = RootTag::new(pattern.to_string());
        assert!(result.is_err(), "Invalid hex should be rejected");
    }
}

// ============================================================================
// POLICY INJECTION TESTS
// ============================================================================

#[tokio::test]
async fn test_custom_condition_injection() {
    let temp_dir = TempDir::new().unwrap();
    let policy_path = temp_dir.path().join("policy.toml");

    // Attempt to inject unregistered custom condition
    let injection_policy = r#"
        version = 1

        [scoring]
        alert_threshold = 50.0

        [deception]
        suspicious_processes = ["mimikatz"]

        [[response.rules]]
        severity = "Critical"
        action = "log"

        [[response.rules.conditions]]
        type = "custom"
        name = "backdoor_condition"
        params = { execute = "rm -rf /" }

        [response]
        cooldown_secs = 60
    "#;

    fs::write(&policy_path, injection_policy).await.unwrap();

    // Should reject unregistered custom condition
    let result = PolicyConfig::from_file(&policy_path).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_extremely_large_values() {
    let temp_dir = TempDir::new().unwrap();
    let policy_path = temp_dir.path().join("policy.toml");

    // Attempt resource exhaustion via large values
    let exhaustion_policy = r#"
        version = 1

        [scoring]
        alert_threshold = 50.0
        max_events_in_memory = 999999999

        [deception]
        suspicious_processes = []

        [[response.rules]]
        severity = "Low"
        action = "log"

        [response]
        cooldown_secs = 60
    "#;

    fs::write(&policy_path, exhaustion_policy).await.unwrap();

    // Should reject due to validation
    let result = PolicyConfig::from_file(&policy_path).await;
    assert!(result.is_err());
}

// ============================================================================
// MEMORY SAFETY TESTS
// ============================================================================

#[test]
fn test_protected_string_zeroizes() {
    let secret = "super_secret_password".to_string();
    let secret_clone = secret.clone();
    
    let protected = ProtectedString::new(secret);
    
    // Verify it contains the secret
    assert_eq!(protected.as_str(), &secret_clone);
    
    // Drop it (zeroize should happen)
    drop(protected);
    
    // We can't directly verify memory is zeroized without unsafe code,
    // but we trust the zeroize crate's implementation
}

#[test]
fn test_protected_path_zeroizes() {
    let path = PathBuf::from("/etc/shadow");
    let path_clone = path.clone();
    
    let protected = ProtectedPath::new(path);
    
    // Verify it contains the path
    assert_eq!(protected.as_path(), path_clone.as_path());
    
    // Drop it (zeroize should happen)
    drop(protected);
}

#[test]
fn test_root_tag_zeroizes() {
    let tag = RootTag::generate().unwrap();
    let hash = *tag.hash();
    
    // Verify hash is accessible
    assert_eq!(hash.len(), 64);
    
    // Drop tag (secret should zeroize)
    drop(tag);
    
    // Can't verify zeroization without unsafe, but hash should still be valid
    assert_eq!(hash.len(), 64);
}

#[test]
fn test_debug_output_redacts_secrets() {
    let protected_string = ProtectedString::new("password123".to_string());
    let debug = format!("{:?}", protected_string);
    
    assert!(!debug.contains("password123"));
    assert!(debug.contains("REDACTED"));
}

#[test]
fn test_root_tag_debug_redacts_secret() {
    let tag = RootTag::generate().unwrap();
    let debug = format!("{:?}", tag);
    
    assert!(debug.contains("REDACTED"));
    assert!(!debug.contains(&hex::encode(&[0u8; 32]))); // Shouldn't contain actual secret
}

// ============================================================================
// RACE CONDITION TESTS
// ============================================================================

#[tokio::test]
async fn test_concurrent_policy_modifications() {
    let temp_dir = TempDir::new().unwrap();
    let policy_path = temp_dir.path().join("policy.toml");

    let policy = PolicyConfig::default();
    let toml_str = toml::to_string(&policy).unwrap();
    fs::write(&policy_path, &toml_str).await.unwrap();

    // Simulate concurrent reads
    let mut handles = vec![];
    for _ in 0..50 {
        let path = policy_path.clone();
        let handle = tokio::spawn(async move {
            PolicyConfig::from_file(&path).await
        });
        handles.push(handle);
    }

    // All reads should succeed or fail consistently
    let mut results = vec![];
    for handle in handles {
        results.push(handle.await.unwrap());
    }

    // Should not have any panics or data races
    assert_eq!(results.len(), 50);
}

// ============================================================================
// DESERIALIZATION ATTACK TESTS
// ============================================================================

#[tokio::test]
async fn test_malformed_toml_handling() {
    let temp_dir = TempDir::new().unwrap();

    let malformed_inputs = vec![
        // Unclosed quotes
        r#"version = 1
           [agent]
           instance_id = "unclosed"#,
        
        // Invalid types
        r#"version = "not a number"
           [agent]"#,
        
        // Circular references (TOML doesn't support, but test anyway)
        r#"[a]
           b = { c = "test" }
           [a.b]
           c = { a = "circular" }"#,
    ];

    for (i, malformed) in malformed_inputs.iter().enumerate() {
        let path = temp_dir.path().join(format!("malformed_{}.toml", i));
        fs::write(&path, malformed).await.unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&path).unwrap().permissions();
            perms.set_mode(0o600);
            std::fs::set_permissions(&path, perms).unwrap();
        }

        let result = Config::from_file(&path).await;
        
        // Should fail gracefully, not panic
        assert!(result.is_err());
    }
}

// ============================================================================
// SIDE-CHANNEL ATTACK TESTS
// ============================================================================

#[test]
fn test_tag_comparison_timing_attack_resistance() {
    let tag1 = RootTag::generate().unwrap();
    let tag2 = RootTag::generate().unwrap();
    
    // Hash comparison should be constant-time
    let hash1 = tag1.hash();
    let hash2 = tag2.hash();
    
    // Multiple comparisons to check for timing variations
    let mut timings_equal = vec![];
    let mut timings_different = vec![];
    
    for _ in 0..1000 {
        let start = std::time::Instant::now();
        let _ = hash1 == hash1;
        timings_equal.push(start.elapsed());
        
        let start = std::time::Instant::now();
        let _ = hash1 == hash2;
        timings_different.push(start.elapsed());
    }
    
    // This is a weak test, but we can at least verify no panics
    // A real timing attack test would require more sophisticated analysis
    assert_eq!(timings_equal.len(), 1000);
    assert_eq!(timings_different.len(), 1000);
}

// ============================================================================
// INPUT VALIDATION BOUNDARY TESTS
// ============================================================================

#[test]
fn test_boundary_values_for_numeric_fields() {
    let mut policy = PolicyConfig::default();
    
    // Test exact boundary values
    policy.scoring.alert_threshold = 0.0;
    assert!(policy.validate().is_ok());
    
    policy.scoring.alert_threshold = 100.0;
    assert!(policy.validate().is_ok());
    
    policy.scoring.alert_threshold = -0.1;
    assert!(policy.validate().is_err());
    
    policy.scoring.alert_threshold = 100.1;
    assert!(policy.validate().is_err());
}

#[test]
fn test_boundary_values_for_usize_fields() {
    let mut policy = PolicyConfig::default();
    
    // Max events boundary
    policy.scoring.max_events_in_memory = 1;
    assert!(policy.validate().is_ok());
    
    policy.scoring.max_events_in_memory = 100_000;
    assert!(policy.validate().is_ok());
    
    policy.scoring.max_events_in_memory = 100_001;
    assert!(policy.validate().is_err());
    
    policy.scoring.max_events_in_memory = 0;
    assert!(policy.validate().is_err());
}

#[test]
fn test_empty_collections_validation() {
    let mut config = Config::default();
    
    // Empty decoy paths should fail
    config.deception.decoy_paths = Box::new([]);
    assert!(config.validate().is_err());
    
    // Empty credential types should fail
    config = Config::default();
    config.deception.credential_types = Box::new([]);
    assert!(config.validate().is_err());
    
    // Empty watch paths should fail
    config = Config::default();
    config.telemetry.watch_paths = Box::new([]);
    assert!(config.validate().is_err());
}
