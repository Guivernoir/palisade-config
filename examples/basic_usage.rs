/// Basic usage example for palisade-config.
use palisade_config::ProtectedString;
///
/// Demonstrates:
/// - Loading configuration and policy
/// - Validation modes
/// - Tag derivation
/// - Suspicious process checking
/// - Configuration diffing

use palisade_config::{
    ActionType, Config, PolicyConfig, ResponseCondition, ResponseRule, RootTag, Severity,
    ValidationMode,
};
use std::collections::HashMap;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Palisade Config Basic Usage ===\n");

    // ========================================================================
    // 1. Creating Configuration
    // ========================================================================
    println!("1. Creating default configuration...");
    let mut config = Config::default();
    config.agent.instance_id = ProtectedString::new("demo-agent-01".to_string());
    config.agent.environment = Some("development".to_string());

    println!("   Instance ID: {:?}", config.agent.instance_id);
    println!("   Environment: {:?}", config.agent.environment);
    println!("   Work dir: {}\n", config.agent.work_dir.as_path().display());

    // ========================================================================
    // 2. Validation
    // ========================================================================
    println!("2. Validating configuration...");
    match config.validate() {
        Ok(()) => println!("   ✓ Configuration valid (standard mode)\n"),
        Err(e) => {
            println!("   ✗ Configuration invalid: {}\n", e);
            return Ok(());
        }
    }

    // Strict validation (would check filesystem)
    println!("   Note: Strict validation would check:");
    println!("   - Directories exist");
    println!("   - Directories writable");
    println!("   - File permissions (Unix only)\n");

    // ========================================================================
    // 3. Cryptographic Tag Derivation
    // ========================================================================
    println!("3. Cryptographic tag derivation...");

    let hostname = config.hostname();
    println!("   Hostname: {}", hostname);

    // Generate root tag (in production, load from secure storage)
    let root_tag = RootTag::generate();
    println!("   Root tag: <secret, zeroized on drop>");
    println!("   Hash (safe to log): {:x?}\n", &root_tag.hash()[..8]);

    // Derive host-specific tag
    let host_tag = root_tag.derive_host_tag(&hostname);
    println!("   Host tag (64 bytes): {}...", hex::encode(&host_tag[..8]));

    // Derive artifact-specific tags
    let artifacts = ["fake-aws-credentials", "fake-ssh-key", "fake-db-backup"];

    println!("\n   Artifact tags:");
    for artifact_id in &artifacts {
        let tag = root_tag.derive_artifact_tag(&hostname, artifact_id);
        println!("   - {}: {}...", artifact_id, &tag[..32]);
    }
    println!();

    // Demonstrate tag isolation
    println!("   Tag isolation demonstration:");
    let tag_host_a = RootTag::generate();
    let tag_host_b = RootTag::generate();

    let artifact_a = tag_host_a.derive_artifact_tag("host-a", "ssh-key");
    let artifact_b = tag_host_b.derive_artifact_tag("host-b", "ssh-key");

    println!("   Host A: {}...", &artifact_a[..32]);
    println!("   Host B: {}...", &artifact_b[..32]);
    println!("   Different? {}\n", artifact_a != artifact_b);

    // ========================================================================
    // 4. Policy Configuration
    // ========================================================================
    println!("4. Policy configuration...");

    let mut policy = PolicyConfig::default();
    println!("   Alert threshold: {}", policy.scoring.alert_threshold);
    println!("   Correlation window: {}s", policy.scoring.correlation_window_secs);
    println!("   Response cooldown: {}s\n", policy.response.cooldown_secs);

    // Modify policy
    policy.scoring.alert_threshold = 60.0;
    println!("   ✓ Updated alert threshold to: {}\n", policy.scoring.alert_threshold);

    // ========================================================================
    // 5. Suspicious Process Detection
    // ========================================================================
    println!("5. Suspicious process detection (zero-allocation)...");

    let test_processes = [
        "firefox.exe",
        "chrome.exe",
        "mimikatz.exe",
        "MIMIKATZ.exe", // Case-insensitive
        "procdump.exe",
        "normal-app",
    ];

    println!("   Configured suspicious patterns: {:?}\n", policy.deception.suspicious_processes);

    for process in &test_processes {
        let is_suspicious = policy.is_suspicious_process(process);
        let marker = if is_suspicious { "⚠️  SUSPICIOUS" } else { "✓  Benign" };
        println!("   {} - {}", marker, process);
    }
    println!();

    // ========================================================================
    // 6. Response Rules
    // ========================================================================
    println!("6. Response rules configuration...");

    println!("   Default rules:");
    for rule in &policy.response.rules {
        println!("   - {:?}: {:?}", rule.severity, rule.action);
        if !rule.conditions.is_empty() {
            println!("     Conditions: {} required", rule.conditions.len());
        }
    }
    println!();

    // Add custom response rule
    policy.response.rules.push(ResponseRule {
        severity: Severity::Medium,
        conditions: vec![
            ResponseCondition::MinConfidence { threshold: 55.0 },
            ResponseCondition::TimeWindow {
                start_hour: 22,
                end_hour: 6,
            },
        ],
        action: ActionType::Alert,
    });

    println!("   ✓ Added custom rule for off-hours medium severity\n");

    // ========================================================================
    // 7. Configuration Diffing
    // ========================================================================
    println!("7. Configuration change tracking...");

    let old_config = Config::default();
    let mut new_config = Config::default();
    new_config.deception.root_tag = RootTag::generate();
    new_config.telemetry.enable_syscall_monitor = true;

    let changes = old_config.diff(&new_config);
    println!("   Detected {} changes:", changes.len());
    for change in changes {
        println!("   - {:?}", change);
    }
    println!();

    // Policy diffing
    let old_policy = PolicyConfig::default();
    let mut new_policy = PolicyConfig::default();
    new_policy.scoring.alert_threshold = 75.0;
    new_policy.deception.suspicious_processes.push("bloodhound".to_string());

    let policy_changes = old_policy.diff(&new_policy);
    println!("   Detected {} policy changes:", policy_changes.len());
    for change in policy_changes {
        println!("   - {:?}", change);
    }
    println!();

    // ========================================================================
    // 8. Scoring Weights
    // ========================================================================
    println!("8. Scoring weights configuration...");

    println!("   Weights:");
    println!("   - Artifact access: {}", policy.scoring.weights.artifact_access);
    println!("   - Suspicious process: {}", policy.scoring.weights.suspicious_process);
    println!("   - Rapid enumeration: {}", policy.scoring.weights.rapid_enumeration);
    println!("   - Off-hours activity: {}", policy.scoring.weights.off_hours_activity);
    println!("   - Ancestry suspicious: {}\n", policy.scoring.weights.ancestry_suspicious);

    // Calculate example score
    let mut score = 0.0;
    score += policy.scoring.weights.artifact_access; // Touched decoy
    score += policy.scoring.weights.suspicious_process; // mimikatz.exe
    score += policy.scoring.weights.off_hours_activity; // 3 AM

    let severity = Severity::from_score(score);
    println!("   Example incident:");
    println!("   - Scenario: mimikatz.exe accessed decoy at 3 AM");
    println!("   - Calculated score: {}", score);
    println!("   - Severity: {:?}\n", severity);

    // ========================================================================
    // 9. Custom Conditions (Security Feature)
    // ========================================================================
    println!("9. Custom conditions (policy injection prevention)...");

    // Register custom condition
    policy.registered_custom_conditions.insert("maintenance_window".to_string());

    // This would fail validation without registration
    let custom_rule = ResponseRule {
        severity: Severity::Low,
        conditions: vec![ResponseCondition::Custom {
            name: "maintenance_window".to_string(),
            params: HashMap::from([("window_id".to_string(), "weekly-patch".to_string())]),
        }],
        action: ActionType::Log,
    };

    println!("   ✓ Custom condition 'maintenance_window' registered");
    println!("   ✓ Rule with custom condition can be added\n");

    // This would fail validation
    let unregistered_rule = ResponseRule {
        severity: Severity::Low,
        conditions: vec![ResponseCondition::Custom {
            name: "unregistered_condition".to_string(),
            params: HashMap::new(),
        }],
        action: ActionType::Log,
    };

    policy.response.rules.push(unregistered_rule);
    match policy.validate() {
        Ok(()) => println!("   ✗ Should have failed validation!"),
        Err(e) => println!("   ✓ Correctly rejected unregistered condition: {}\n", e),
    }

    // ========================================================================
    // Summary
    // ========================================================================
    println!("=== Summary ===");
    println!("✓ Configuration validated");
    println!("✓ Cryptographic tags derived");
    println!("✓ Policy loaded and modified");
    println!("✓ Suspicious processes detected");
    println!("✓ Response rules configured");
    println!("✓ Change tracking demonstrated");
    println!("✓ Security features verified");
    println!("\nAll operations completed successfully!");

    Ok(())
}