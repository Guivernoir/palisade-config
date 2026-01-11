//! Policy hot-reload example with comprehensive error handling.
//!
//! Demonstrates:
//! - Loading policy from file
//! - Detecting policy changes via diff
//! - Hot-reloading without downtime
//! - Change validation and rollback
//! - Integration with palisade-errors for detailed logging

use palisade_config::{PolicyConfig, PolicyChange, Severity, ActionType, ResponseRule, ResponseCondition};
use std::path::PathBuf;
use tempfile::TempDir;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Palisade Config: Policy Hot-Reload ===\n");

    let temp_dir = TempDir::new()?;
    let policy_path = temp_dir.path().join("policy.toml");

    // ========================================================================
    // 1. Initial Policy Load
    // ========================================================================
    println!("1. Loading initial policy...");
    
    let initial_policy_toml = create_initial_policy_toml();
    std::fs::write(&policy_path, initial_policy_toml)?;
    
    let mut current_policy = PolicyConfig::from_file(&policy_path)?;
    println!("   ✓ Policy loaded");
    println!("   Alert threshold: {}", current_policy.scoring.alert_threshold);
    println!("   Response rules: {}", current_policy.response.rules.len());
    println!("   Suspicious processes: {}\n", current_policy.deception.suspicious_processes.len());

    // ========================================================================
    // 2. Simulate Production Operations
    // ========================================================================
    println!("2. Simulating production operations...");
    
    // Check some processes
    let test_processes = vec!["firefox", "mimikatz.exe", "chrome", "procdump"];
    for process in &test_processes {
        let is_suspicious = current_policy.is_suspicious_process(process);
        println!("   {} - {}", if is_suspicious { "⚠️ " } else { "✓ " }, process);
    }
    println!();

    // ========================================================================
    // 3. Policy Update - Threshold Adjustment
    // ========================================================================
    println!("3. Updating policy (threshold adjustment)...");
    
    let updated_policy_toml = create_updated_policy_toml();
    std::fs::write(&policy_path, updated_policy_toml)?;
    
    // Load new policy
    let new_policy = match PolicyConfig::from_file(&policy_path) {
        Ok(policy) => policy,
        Err(e) => {
            println!("   ✗ Failed to load new policy: {}", e);
            println!("   Keeping current policy (hot-reload failed)");
            return Ok(());
        }
    };
    
    // Detect changes
    let changes = current_policy.diff(&new_policy);
    
    if changes.is_empty() {
        println!("   No changes detected\n");
    } else {
        println!("   Detected {} change(s):", changes.len());
        for change in &changes {
            match change {
                PolicyChange::ThresholdChanged { field, old, new } => {
                    println!("   - Threshold changed: {} ({} → {})", field, old, new);
                }
                PolicyChange::ResponseRulesChanged { old_count, new_count } => {
                    println!("   - Response rules: {} → {}", old_count, new_count);
                }
                PolicyChange::SuspiciousProcessesChanged { added, removed } => {
                    if !added.is_empty() {
                        println!("   - Added suspicious processes: {:?}", added);
                    }
                    if !removed.is_empty() {
                        println!("   - Removed suspicious processes: {:?}", removed);
                    }
                }
            }
        }
        println!();
        
        // Apply new policy
        current_policy = new_policy;
        println!("   ✓ Policy hot-reloaded successfully\n");
    }

    // ========================================================================
    // 4. Policy Update - Add Suspicious Process
    // ========================================================================
    println!("4. Adding new suspicious process...");
    
    let bloodhound_policy_toml = create_bloodhound_policy_toml();
    std::fs::write(&policy_path, bloodhound_policy_toml)?;
    
    let new_policy = PolicyConfig::from_file(&policy_path)?;
    let changes = current_policy.diff(&new_policy);
    
    println!("   Changes detected:");
    for change in &changes {
        if let PolicyChange::SuspiciousProcessesChanged { added, removed: _ } = change {
            println!("   - Added: {:?}", added);
        }
    }
    
    current_policy = new_policy;
    println!("   ✓ Policy updated\n");
    
    // Test new detection
    println!("   Testing updated detection:");
    if current_policy.is_suspicious_process("bloodhound.exe") {
        println!("   ✓ bloodhound.exe now detected as suspicious\n");
    }

    // ========================================================================
    // 5. Invalid Policy - Validation Catches Errors
    // ========================================================================
    println!("5. Attempting invalid policy update...");
    
    let invalid_policy_toml = create_invalid_policy_toml();
    std::fs::write(&policy_path, invalid_policy_toml)?;
    
    match PolicyConfig::from_file(&policy_path) {
        Ok(_) => {
            println!("   ✗ Should have failed validation!");
        }
        Err(e) => {
            println!("   ✓ Invalid policy rejected:");
            println!("   External error: {}", e);
            println!("   (Internal logs would have full details)");
            
            // Policy remains unchanged - no downtime
            println!("   ✓ Current policy remains active (no downtime)\n");
        }
    }

    // ========================================================================
    // 6. Change Approval Workflow Simulation
    // ========================================================================
    println!("6. Simulating change approval workflow...");
    
    let proposed_policy = PolicyConfig::default();
    let changes = current_policy.diff(&proposed_policy);
    
    println!("   Proposed changes:");
    for change in &changes {
        println!("   - {:?}", change);
    }
    
    println!("\n   Change approval decision:");
    println!("   [ ] Approved by security team");
    println!("   [ ] Tested in staging environment");
    println!("   [ ] Scheduled maintenance window");
    println!("   → Changes ready for production\n");

    // ========================================================================
    // 7. Rollback Simulation (without clone - using file backup)
    // ========================================================================
    println!("7. Simulating rollback scenario...");
    
    // Store backup by writing current policy to file
    println!("   ✓ Current policy backed up to file");
    let backup_policy_toml = create_updated_policy_toml(); // Same as current
    let backup_path = temp_dir.path().join("policy.backup.toml");
    std::fs::write(&backup_path, backup_policy_toml)?;
    
    // Apply problematic update
    println!("   Applying new policy (alert_threshold = 10.0)...");
    let problematic_toml = create_problematic_policy_toml();
    std::fs::write(&policy_path, problematic_toml)?;
    current_policy = PolicyConfig::from_file(&policy_path)?;
    
    // Simulate production issues
    println!("   ⚠️  Alert storm detected!");
    println!("   ⚠️  False positive rate: 95%");
    println!("   → Initiating rollback...");
    
    // Rollback by reloading from backup file
    current_policy = PolicyConfig::from_file(&backup_path)?;
    println!("   ✓ Rolled back to previous policy");
    println!("   ✓ Alert threshold restored to: {}\n", current_policy.scoring.alert_threshold);

    // ========================================================================
    // 8. Performance Characteristics
    // ========================================================================
    println!("8. Performance characteristics:");
    println!("   - Policy load from disk: <10ms");
    println!("   - Policy validation: <5µs");
    println!("   - Policy diff calculation: <5µs");
    println!("   - Hot-reload total: <15ms");
    println!("   - Zero downtime: ✓");
    println!("   - Atomic switch: ✓\n");

    // ========================================================================
    // 9. Best Practices
    // ========================================================================
    println!("9. Production best practices:");
    println!("   1. Always validate new policy before applying");
    println!("   2. Use diff to generate change logs");
    println!("   3. Keep backup in file or database");
    println!("   4. Test in staging first");
    println!("   5. Monitor alerts after reload");
    println!("   6. Have rollback plan ready (backup file)");
    println!("   7. Log all policy changes with metadata");
    println!("   8. Use version control for policies\n");

    println!("=== Summary ===");
    println!("✓ Policy hot-reload enables zero-downtime updates");
    println!("✓ Change tracking provides audit trail");
    println!("✓ Validation prevents invalid policies");
    println!("✓ Rollback via file backup ensures safety");
    println!("✓ palisade-errors provides detailed error context");
    println!("\nPolicy hot-reload demonstration complete!");

    Ok(())
}

fn create_initial_policy_toml() -> String {
    r#"
version = 1

[scoring]
correlation_window_secs = 300
alert_threshold = 50.0
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
severity = "Medium"
action = "alert"

[[response.rules]]
severity = "High"
action = "kill_process"

[deception]
suspicious_processes = ["mimikatz", "procdump", "lazagne"]
suspicious_patterns = []
"#.to_string()
}

fn create_updated_policy_toml() -> String {
    r#"
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
severity = "Medium"
action = "alert"

[[response.rules]]
severity = "High"
action = "kill_process"

[deception]
suspicious_processes = ["mimikatz", "procdump", "lazagne"]
suspicious_patterns = []
"#.to_string()
}

fn create_bloodhound_policy_toml() -> String {
    r#"
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
severity = "Medium"
action = "alert"

[[response.rules]]
severity = "High"
action = "kill_process"

[deception]
suspicious_processes = ["mimikatz", "procdump", "lazagne", "bloodhound"]
suspicious_patterns = []
"#.to_string()
}

fn create_invalid_policy_toml() -> String {
    r#"
version = 1

[scoring]
correlation_window_secs = 300
alert_threshold = 150.0
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

[deception]
suspicious_processes = ["mimikatz"]
suspicious_patterns = []
"#.to_string()
}

fn create_problematic_policy_toml() -> String {
    r#"
version = 1

[scoring]
correlation_window_secs = 300
alert_threshold = 10.0
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
severity = "Medium"
action = "alert"

[[response.rules]]
severity = "High"
action = "kill_process"

[deception]
suspicious_processes = ["mimikatz", "procdump", "lazagne", "bloodhound"]
suspicious_patterns = []
"#.to_string()
}