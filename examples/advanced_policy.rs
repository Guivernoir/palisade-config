//! # Example 06 — Advanced Policy Configuration
//!
//! Demonstrates building a production-grade policy with:
//!   - Custom scoring weights tuned to environment
//!   - Conditional response rules (MinConfidence, TimeWindow, NotParentedBy, etc.)
//!   - Custom conditions with pre-registration (injection attack prevention)
//!   - Dry-run mode for safe rollout
//!   - Severity score mapping

use palisade_config::{
    ActionType, DeceptionPolicy, PolicyConfig, ResponseCondition, ResponsePolicy, ResponseRule,
    ScoringPolicy, ScoringWeights, Severity,
};
use std::collections::{HashMap, HashSet};

fn main() {
    // -------------------------------------------------------------------------
    // 1. Custom scoring weights
    //
    // Default weights are balanced for general-purpose deployments.
    // Here we tune for a financial-sector honeypot where off-hours access is
    // a much stronger signal than process ancestry.
    // -------------------------------------------------------------------------
    let financial_weights = ScoringWeights {
        artifact_access: 60.0,    // primary trigger — any access is suspicious
        suspicious_process: 35.0, // attacker tooling is definitive
        rapid_enumeration: 25.0,  // scanning behaviour
        off_hours_activity: 30.0, // ELEVATED: financial systems don't operate at 3am
        ancestry_suspicious: 5.0, // REDUCED: containerised environment, ancestry unreliable
    };

    println!("=== Custom Scoring Weights (Financial Sector) ===");
    println!(
        "  artifact_access     : {:.1}",
        financial_weights.artifact_access
    );
    println!(
        "  suspicious_process  : {:.1}",
        financial_weights.suspicious_process
    );
    println!(
        "  rapid_enumeration   : {:.1}",
        financial_weights.rapid_enumeration
    );
    println!(
        "  off_hours_activity  : {:.1}",
        financial_weights.off_hours_activity
    );
    println!(
        "  ancestry_suspicious : {:.1}",
        financial_weights.ancestry_suspicious
    );

    // Compute what a combined score might look like
    let simulated_score = financial_weights.artifact_access
        + financial_weights.off_hours_activity
        + financial_weights.suspicious_process;
    println!(
        "\n  Example: off-hours access by mimikatz = {:.1} points",
        simulated_score
    );
    println!("  Severity: {}", Severity::from_score(simulated_score));

    // -------------------------------------------------------------------------
    // 2. Response rules with all condition types
    // -------------------------------------------------------------------------
    println!("\n=== Response Rules with Conditions ===");

    // Register custom conditions BEFORE adding them to rules (prevents injection)
    let mut custom_conditions: HashSet<String> = HashSet::new();
    custom_conditions.insert("geo_block_non_corporate".to_string());
    custom_conditions.insert("asset_criticality_high".to_string());

    let rules = vec![
        // Low severity: always log
        ResponseRule {
            severity: Severity::Low,
            conditions: vec![],
            action: ActionType::Log,
        },
        // Medium: alert if confidence is reasonable
        ResponseRule {
            severity: Severity::Medium,
            conditions: vec![ResponseCondition::MinConfidence { threshold: 40.0 }],
            action: ActionType::Alert,
        },
        // High: kill process only if:
        //   - high confidence, AND
        //   - not parented by monitoring agent (prevent false kills), AND
        //   - at least 2 distinct signal types
        ResponseRule {
            severity: Severity::High,
            conditions: vec![
                ResponseCondition::MinConfidence { threshold: 65.0 },
                ResponseCondition::NotParentedBy {
                    process_name: "palisade-agent".to_string(),
                },
                ResponseCondition::MinSignalTypes { count: 2 },
            ],
            action: ActionType::KillProcess,
        },
        // Critical: isolate host only if:
        //   - very high confidence, AND
        //   - repeated incidents (not a one-off), AND
        //   - outside business hours (reduce false isolations during busy periods), AND
        //   - custom geo and criticality conditions are satisfied
        ResponseRule {
            severity: Severity::Critical,
            conditions: vec![
                ResponseCondition::MinConfidence { threshold: 85.0 },
                ResponseCondition::RepeatCount {
                    count: 3,
                    window_secs: 600,
                },
                ResponseCondition::TimeWindow {
                    start_hour: 18,
                    end_hour: 8,
                }, // 18:00–08:00
                ResponseCondition::Custom {
                    name: "geo_block_non_corporate".to_string(),
                    params: {
                        let mut p = HashMap::new();
                        p.insert("allowed_regions".to_string(), "EU,US-EAST".to_string());
                        p
                    },
                },
                ResponseCondition::Custom {
                    name: "asset_criticality_high".to_string(),
                    params: HashMap::new(),
                },
            ],
            action: ActionType::IsolateHost,
        },
    ];

    for rule in &rules {
        println!(
            "  severity={:?}  action={:?}  conditions={}",
            rule.severity,
            rule.action,
            rule.conditions.len()
        );
        for cond in &rule.conditions {
            match cond {
                ResponseCondition::MinConfidence { threshold } => {
                    println!("    - min_confidence >= {threshold:.1}")
                }
                ResponseCondition::NotParentedBy { process_name } => {
                    println!("    - not_parented_by '{process_name}'")
                }
                ResponseCondition::MinSignalTypes { count } => {
                    println!("    - min_signal_types >= {count}")
                }
                ResponseCondition::RepeatCount { count, window_secs } => {
                    println!("    - repeat_count >= {count} within {window_secs}s")
                }
                ResponseCondition::TimeWindow {
                    start_hour,
                    end_hour,
                } => println!("    - time_window {start_hour:02}:00–{end_hour:02}:00"),
                ResponseCondition::Custom { name, params } => {
                    println!("    - custom '{name}' params={:?}", params)
                }
            }
        }
    }

    // -------------------------------------------------------------------------
    // 3. Dry-run mode — all conditions evaluated, no actions executed
    // -------------------------------------------------------------------------
    println!("\n=== Dry-Run Mode ===");
    let mut policy = PolicyConfig {
        version: 1,
        scoring: ScoringPolicy {
            correlation_window_secs: 300,
            alert_threshold: 50.0,
            max_events_in_memory: 10_000,
            enable_time_scoring: true,
            enable_ancestry_tracking: true,
            weights: financial_weights,
            business_hours_start: 8,
            business_hours_end: 18,
        },
        response: ResponsePolicy {
            rules: rules,
            cooldown_secs: 120,        // 2 min cooldown in financial env
            max_kills_per_incident: 5, // conservative kill limit
            dry_run: true,             // SAFE ROLLOUT: log only
        },
        deception: DeceptionPolicy {
            suspicious_processes: vec![
                "mimikatz".to_string(),
                "procdump".to_string(),
                "lazagne".to_string(),
                "bloodhound".to_string(),
                "rubeus".to_string(),
                "sharpup".to_string(),
                "powersploit".to_string(),
                "cobalt strike".to_string(),
            ]
            .into_boxed_slice(),
            suspicious_patterns: vec![
                ".aws/credentials".to_string(),
                "id_rsa".to_string(),
                ".ssh/authorized_keys".to_string(),
                "shadow".to_string(),
                "ntds.dit".to_string(),
            ]
            .into_boxed_slice(),
        },
        registered_custom_conditions: custom_conditions,
    };

    println!(
        "  dry_run: {} (actions logged but NOT executed)",
        policy.response.dry_run
    );
    policy.validate().expect("Policy must be valid");
    println!("  validation: PASSED");

    // Flip off dry-run for production
    policy.response.dry_run = false;
    policy
        .validate()
        .expect("Policy still valid after disabling dry-run");
    println!("  dry_run disabled: still valid ✓");

    // -------------------------------------------------------------------------
    // 4. Custom condition injection prevention
    //
    // Unregistered custom conditions must fail validation.
    // This prevents an attacker who can write the policy file from introducing
    // arbitrary condition names that could be matched by custom handlers.
    // -------------------------------------------------------------------------
    println!("\n=== Custom Condition Security ===");

    let mut unsafe_policy = PolicyConfig::default();
    unsafe_policy
        .response
        .rules
        .retain(|r| r.severity != Severity::Low);
    unsafe_policy.response.rules.push(ResponseRule {
        severity: Severity::Low,
        conditions: vec![ResponseCondition::Custom {
            name: "injected_condition".to_string(), // NOT registered
            params: HashMap::new(),
        }],
        action: ActionType::Log,
    });

    match unsafe_policy.validate() {
        Err(e) => println!("  [OK] Unregistered condition rejected: {e}"),
        Ok(_) => println!("  [FAIL] Security check bypassed!"),
    }

    // Registering it makes it valid
    unsafe_policy
        .registered_custom_conditions
        .insert("injected_condition".to_string());
    match unsafe_policy.validate() {
        Ok(_) => println!("  [OK] Registered condition accepted ✓"),
        Err(e) => println!("  [FAIL] Registration not respected: {e}"),
    }

    // -------------------------------------------------------------------------
    // 5. Duplicate severity prevention
    //
    // Two rules at the same severity creates ambiguity — which fires first?
    // The validator catches this.
    // -------------------------------------------------------------------------
    println!("\n=== Duplicate Severity Prevention ===");

    let mut dup_policy = PolicyConfig::default();
    dup_policy.response.rules.push(ResponseRule {
        severity: Severity::Low, // already exists in default
        conditions: vec![],
        action: ActionType::Alert,
    });

    match dup_policy.validate() {
        Err(e) => println!("  [OK] Duplicate severity rejected: {e}"),
        Ok(_) => println!("  [FAIL] Duplicate severity accepted!"),
    }

    // -------------------------------------------------------------------------
    // 6. Severity scoring reference table
    // -------------------------------------------------------------------------
    println!("\n=== Severity Score Reference ===");
    println!("  {:>8}  {:>12}", "Score", "Severity");
    println!("  {:>8}  {:>12}", "-----", "--------");
    for score in [0.0_f64, 20.0, 39.9, 40.0, 59.9, 60.0, 79.9, 80.0, 100.0] {
        println!("  {:>8.1}  {:>12}", score, Severity::from_score(score));
    }

    println!("\nAdvanced policy examples completed.");
}
