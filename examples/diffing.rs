//! # Example 05 — Configuration & Policy Diffing
//!
//! Demonstrates the diff APIs for tracking changes between config and policy
//! revisions. Useful for:
//!   - Audit logs ("what changed between reload cycles?")
//!   - Hot-reload validation ("is this change safe to apply live?")
//!   - Rollback detection ("did someone modify the config on disk?")

use palisade_config::{
    Config, PolicyConfig, RootTag,
    ConfigChange, PolicyChange,
};
use std::path::PathBuf;

fn main() {
    // -------------------------------------------------------------------------
    // 1. Config diff — no changes
    // -------------------------------------------------------------------------
    println!("=== Config Diff: No Changes ===");
    let config_v1 = Config::default();
    let config_v2 = Config::default();

    // NOTE: Both have independently generated RootTags, so the root_tag will
    // always differ. In real usage you'd reload from the same file.
    // For this demo we'll focus on the other change types.
    let all_changes = config_v1.diff(&config_v2);
    println!("  changes detected: {}", all_changes.len());
    for change in &all_changes {
        println!("  - {:?}", change);
    }

    // -------------------------------------------------------------------------
    // 2. Config diff — detect decoy path changes
    // -------------------------------------------------------------------------
    println!("\n=== Config Diff: Path Changes ===");
    let config_v1 = Config::default();
    let mut config_v2 = Config::default();

    // Simulate a config reload that adds a path and removes another
    config_v2.deception.decoy_paths = vec![
        PathBuf::from("/tmp/.credentials"),   // kept
        PathBuf::from("/srv/.honeypot"),       // NEW
        // "/opt/.backup" — REMOVED
    ]
    .into_boxed_slice();

    // Force same root_tag so we isolate the path diff
    // (in production, root tags come from file — if unchanged the hash matches)
    config_v2.deception.decoy_paths = config_v1.deception.decoy_paths
        .iter()
        .cloned()
        .chain(std::iter::once(PathBuf::from("/srv/.honeypot-new")))
        .collect::<Vec<_>>()
        .into_boxed_slice();

    let changes = config_v1.diff(&config_v2);
    for change in &changes {
        match change {
            ConfigChange::PathsChanged { added, removed } => {
                println!("  PathsChanged:");
                for p in added   { println!("    + {:?}", p); }
                for p in removed { println!("    - {:?}", p); }
            }
            ConfigChange::RootTagChanged { old_hash, new_hash } => {
                println!("  RootTagChanged: {}...  →  {}...", old_hash, new_hash);
            }
            ConfigChange::CapabilitiesChanged { field, old, new } => {
                println!("  CapabilitiesChanged: {} = {} → {}", field, old, new);
            }
        }
    }

    // -------------------------------------------------------------------------
    // 3. Config diff — detect syscall monitor toggle
    // -------------------------------------------------------------------------
    println!("\n=== Config Diff: Syscall Monitor Toggle ===");
    let config_v1 = Config::default(); // enable_syscall_monitor = false
    let mut config_v2 = Config::default();
    config_v2.telemetry.enable_syscall_monitor = true;

    let changes = config_v1.diff(&config_v2);
    for change in &changes {
        if let ConfigChange::CapabilitiesChanged { field, old, new } = change {
            println!("  {field}: {old} → {new}");
        }
    }
    let has_cap_change = changes.iter().any(|c| {
        matches!(c, ConfigChange::CapabilitiesChanged { field, .. } if field == "enable_syscall_monitor")
    });
    assert!(has_cap_change, "Syscall monitor change must be detected");
    println!("  [OK] Capability change detected.");

    // -------------------------------------------------------------------------
    // 4. Config diff — detect root tag rotation
    // -------------------------------------------------------------------------
    println!("\n=== Config Diff: Root Tag Rotation ===");
    let config_v1 = Config::default();
    let mut config_v2 = Config::default();
    config_v2.deception.root_tag = RootTag::generate().expect("generate");

    let changes = config_v1.diff(&config_v2);
    let tag_change = changes.iter().find_map(|c| {
        if let ConfigChange::RootTagChanged { old_hash, new_hash } = c {
            Some((old_hash.clone(), new_hash.clone()))
        } else {
            None
        }
    });

    if let Some((old, new)) = tag_change {
        // Only first 8 bytes (16 hex chars) are exposed — rest is redacted
        println!("  old_hash prefix (8 bytes): {}", old);
        println!("  new_hash prefix (8 bytes): {}", new);
        assert_eq!(old.len(), 16, "Hash prefix must be 16 hex chars (8 bytes)");
        assert_ne!(old, new);
        println!("  [OK] Root tag rotation detected with minimal exposure.");
    } else {
        println!("  [NOTE] Same root tag in both (both generated same entropy — astronomically unlikely)");
    }

    // -------------------------------------------------------------------------
    // 5. Policy diff — scoring threshold change
    // -------------------------------------------------------------------------
    println!("\n=== Policy Diff: Threshold Change ===");
    let mut policy_v1 = PolicyConfig::default();
    let mut policy_v2 = PolicyConfig::default();
    policy_v1.scoring.alert_threshold = 50.0;
    policy_v2.scoring.alert_threshold = 70.0; // tightened

    let changes = policy_v1.diff(&policy_v2);
    for change in &changes {
        if let PolicyChange::ThresholdChanged { field, old, new } = change {
            println!("  {field}: {old:.1} → {new:.1}");
            let direction = if new > old { "tightened (higher bar for alerts)" }
                            else         { "relaxed (lower bar for alerts)" };
            println!("  interpretation: threshold {direction}");
        }
    }

    // -------------------------------------------------------------------------
    // 6. Policy diff — response rules count change
    // -------------------------------------------------------------------------
    println!("\n=== Policy Diff: Response Rules Change ===");
    let policy_v1 = PolicyConfig::default(); // 4 default rules
    let mut policy_v2 = PolicyConfig::default();
    policy_v2.response.rules.pop(); // remove Critical rule

    let changes = policy_v1.diff(&policy_v2);
    for change in &changes {
        if let PolicyChange::ResponseRulesChanged { old_count, new_count } = change {
            println!("  response rules: {old_count} → {new_count}");
            if new_count < old_count {
                println!("  WARNING: Response coverage reduced — verify intentional");
            }
        }
    }

    // -------------------------------------------------------------------------
    // 7. Policy diff — suspicious processes updated
    // -------------------------------------------------------------------------
    println!("\n=== Policy Diff: Suspicious Processes ===");
    let policy_v1 = PolicyConfig::default(); // mimikatz, procdump, lazagne
    let mut policy_v2 = PolicyConfig::default();
    policy_v2.deception.suspicious_processes = vec![
        "mimikatz".to_string(),
        "procdump".to_string(),
        // "lazagne" — REMOVED
        "bloodhound".to_string(), // ADDED
        "rubeus".to_string(),     // ADDED
    ]
    .into_boxed_slice();

    let changes = policy_v1.diff(&policy_v2);
    for change in &changes {
        if let PolicyChange::SuspiciousProcessesChanged { added, removed } = change {
            println!("  Added   : {:?}", added);
            println!("  Removed : {:?}", removed);
        }
    }

    // -------------------------------------------------------------------------
    // 8. Hot-reload pattern: apply diff only if safe
    // -------------------------------------------------------------------------
    println!("\n=== Hot-Reload Pattern ===");
    let running_policy = PolicyConfig::default();
    let new_policy     = PolicyConfig::default(); // in prod: loaded from disk

    let changes = running_policy.diff(&new_policy);

    let safe_to_apply = changes.iter().all(|c| {
        !matches!(c, PolicyChange::ResponseRulesChanged { new_count, .. } if *new_count == 0)
    });

    if safe_to_apply {
        println!("  Hot-reload: SAFE ({} changes, no critical degradation)", changes.len());
    } else {
        println!("  Hot-reload: BLOCKED — would remove all response rules");
    }

    println!("\nAll diff examples completed.");
}