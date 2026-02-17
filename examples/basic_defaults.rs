//! # Example 01 — Basic Defaults & Validation
//!
//! Demonstrates the out-of-the-box defaults for `Config` and `PolicyConfig`,
//! how to perform standard validation, and how to inspect configuration values.

use palisade_config::{Config, PolicyConfig, LogFormat, LogLevel, Severity};

fn main() {
    // -------------------------------------------------------------------------
    // 1. Build a Config from defaults (no file I/O required)
    // -------------------------------------------------------------------------
    let config = Config::default();

    println!("=== Agent Config ===");
    // instance_id and work_dir are ProtectedString/ProtectedPath — they redact in Debug.
    println!("  environment : {:?}", config.agent.environment);  // None
    println!("  hostname    : {}", config.hostname());            // system hostname or "unknown-host"

    println!("\n=== Deception Config ===");
    println!("  decoy_paths        : {:?}", &config.deception.decoy_paths);
    println!("  credential_types   : {:?}", &config.deception.credential_types);
    println!("  honeytoken_count   : {}", config.deception.honeytoken_count);
    println!("  artifact_perm (oct): {:o}", config.deception.artifact_permissions); // "600"
    // root_tag prints "[REDACTED]" — intentional.
    println!("  root_tag           : {:?}", config.deception.root_tag);

    println!("\n=== Telemetry Config ===");
    println!("  watch_paths        : {:?}", &config.telemetry.watch_paths);
    println!("  event_buffer_size  : {}", config.telemetry.event_buffer_size);
    println!("  syscall_monitor    : {}", config.telemetry.enable_syscall_monitor);

    println!("\n=== Logging Config ===");
    println!("  log_path           : {:?}", config.logging.log_path);
    println!("  format is JSON     : {}", config.logging.format == LogFormat::Json);
    println!("  rotate_size (MB)   : {}", config.logging.rotate_size_bytes / (1024 * 1024));
    println!("  max_log_files      : {}", config.logging.max_log_files);
    println!("  level >= INFO      : {}", config.logging.level >= LogLevel::Info);

    // -------------------------------------------------------------------------
    // 2. Validate the default config
    //
    // Standard mode: validates format, ranges, and field semantics.
    // Does NOT touch the filesystem (no path existence checks).
    // -------------------------------------------------------------------------
    config.validate().expect("Default config must always be valid");
    println!("\n[OK] Default Config passes standard validation.");

    // -------------------------------------------------------------------------
    // 3. Build a PolicyConfig from defaults
    // -------------------------------------------------------------------------
    let policy = PolicyConfig::default();

    println!("\n=== Scoring Policy ===");
    println!("  alert_threshold      : {}", policy.scoring.alert_threshold);
    println!("  correlation_window   : {}s", policy.scoring.correlation_window_secs);
    println!("  max_events_in_memory : {}", policy.scoring.max_events_in_memory);
    println!("  enable_time_scoring  : {}", policy.scoring.enable_time_scoring);
    println!("  business_hours       : {:02}:00–{:02}:00",
        policy.scoring.business_hours_start,
        policy.scoring.business_hours_end
    );

    println!("\n=== Scoring Weights ===");
    println!("  artifact_access     : {:.1}", policy.scoring.weights.artifact_access);
    println!("  suspicious_process  : {:.1}", policy.scoring.weights.suspicious_process);
    println!("  rapid_enumeration   : {:.1}", policy.scoring.weights.rapid_enumeration);
    println!("  off_hours_activity  : {:.1}", policy.scoring.weights.off_hours_activity);
    println!("  ancestry_suspicious : {:.1}", policy.scoring.weights.ancestry_suspicious);

    println!("\n=== Response Rules ===");
    for rule in &policy.response.rules {
        println!("  severity={:?}  action={:?}  conditions={}",
            rule.severity, rule.action, rule.conditions.len());
    }
    println!("  cooldown          : {}s", policy.response.cooldown_secs);
    println!("  max_kills         : {}", policy.response.max_kills_per_incident);
    println!("  dry_run           : {}", policy.response.dry_run);

    println!("\n=== Suspicious Processes ===");
    for proc in policy.deception.suspicious_processes.iter() {
        println!("  - {proc}");
    }

    // -------------------------------------------------------------------------
    // 4. Validate the default policy
    // -------------------------------------------------------------------------
    policy.validate().expect("Default policy must always be valid");
    println!("\n[OK] Default PolicyConfig passes validation.");

    // -------------------------------------------------------------------------
    // 5. Severity scoring thresholds
    // -------------------------------------------------------------------------
    println!("\n=== Severity from Score ===");
    for score in [25.0_f64, 45.0, 65.0, 85.0] {
        println!("  score={:4.1}  => severity={}", score, Severity::from_score(score));
    }

    // -------------------------------------------------------------------------
    // 6. Demonstrate what happens with an invalid config
    // -------------------------------------------------------------------------
    let mut broken = Config::default();
    broken.deception.honeytoken_count = 0; // violates 1..=100

    match broken.validate() {
        Err(e) => println!("\n[OK] Correctly rejected invalid honeytoken_count=0: {e}"),
        Ok(_)  => panic!("Should have failed validation"),
    }
}