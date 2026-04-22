//! # Example 02 — Loading Config & Policy from TOML Files
//!
//! Demonstrates the public operational APIs with embedded validation, strict
//! config validation, and robust error handling patterns.

use palisade_config::{ConfigApi, PolicyApi, ValidationMode};

const CONFIG_PATH: &str = "examples/config.toml";
const POLICY_PATH: &str = "examples/policy.toml";

#[tokio::main]
async fn main() {
    let config_api = ConfigApi::new();
    let strict_config_api = ConfigApi::new().with_validation_mode(ValidationMode::Strict);
    let policy_api = PolicyApi::new();

    // -------------------------------------------------------------------------
    // 1. Standard config load (embedded validation, no extra filesystem checks)
    // -------------------------------------------------------------------------
    println!("--- Loading config (Standard mode) ---");
    match config_api.load_file(CONFIG_PATH).await {
        Ok(config) => {
            println!("[OK] Config loaded successfully.");
            println!("     hostname  : {}", config.hostname());
            println!("     env       : {:?}", config.agent.environment);
            println!("     decoy cnt : {}", config.deception.decoy_paths.len());
            config_api
                .validate(&config)
                .expect("Loaded config must be valid");
            println!("     validation: passed");
        }
        Err(e) => {
            // In production you'd log internally and return a sanitised error.
            eprintln!("[FAIL] Could not load config: {e}");
            eprintln!("       Make sure '{CONFIG_PATH}' exists and is readable.");
            eprintln!("       See examples/config.toml for a valid template.");
            std::process::exit(1);
        }
    }

    // -------------------------------------------------------------------------
    // 2. Strict load — additionally checks that all paths exist on disk and
    //    that the log directory is writable. Use this on daemon startup.
    // -------------------------------------------------------------------------
    println!("\n--- Loading config (Strict mode) ---");
    match strict_config_api.load_file(CONFIG_PATH).await {
        Ok(_) => println!("[OK] Strict validation passed — all paths exist and are writable."),
        Err(e) => {
            // Expected in CI / sandboxed envs where paths don't exist.
            println!("[INFO] Strict validation failed (expected in some environments): {e}");
        }
    }

    // -------------------------------------------------------------------------
    // 3. Load a policy file
    // -------------------------------------------------------------------------
    println!("\n--- Loading policy ---");
    match policy_api.load_file(POLICY_PATH).await {
        Ok(policy) => {
            println!("[OK] Policy loaded successfully.");
            println!(
                "     alert_threshold   : {}",
                policy.scoring.alert_threshold
            );
            println!("     response rules    : {}", policy.response.rules.len());
            println!(
                "     suspicious procs  : {}",
                policy.deception.suspicious_processes.len()
            );
            println!(
                "     custom conditions : {}",
                policy.registered_custom_conditions.len()
            );

            policy_api
                .validate(&policy)
                .expect("Loaded policy must be valid");
            println!("     validation: passed");

            // Quick suspicious-process check after loading
            let test_names = [
                "MIMIKATZ.exe",
                "procdump64.exe",
                "svchost.exe",
                "LaZagne.py",
            ];
            println!("\n     Suspicious-process checks:");
            for name in test_names {
                println!(
                    "       {name:20} -> {}",
                    policy_api
                        .is_suspicious_process(&policy, name)
                        .expect("policy check")
                );
            }
        }
        Err(e) => {
            eprintln!("[FAIL] Could not load policy: {e}");
            eprintln!("       Make sure '{POLICY_PATH}' exists and is readable.");
            std::process::exit(1);
        }
    }

    // -------------------------------------------------------------------------
    // 4. Error-handling patterns
    //
    // AgentError exposes only a sanitized Display surface here. Avoid echoing
    // raw paths or validation specifics back to users.
    // -------------------------------------------------------------------------
    println!("\n--- Error handling pattern ---");
    match config_api.load_file("nonexistent/path/config.toml").await {
        Ok(_) => unreachable!(),
        Err(e) => {
            // Safe to show to users / API callers:
            println!("Public error  : {e}");
        }
    }
}
