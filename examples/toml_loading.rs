//! # Example 02 — Loading Config & Policy from TOML Files
//!
//! Demonstrates loading configuration from disk with both Standard and Strict
//! validation modes, plus robust error handling patterns.

use palisade_config::{Config, PolicyConfig, ValidationMode};

const CONFIG_PATH: &str = "examples/config.toml";
const POLICY_PATH: &str = "examples/policy.toml";

#[tokio::main]
async fn main() {
    // -------------------------------------------------------------------------
    // 1. Standard load (most common — validates fields but not filesystem paths)
    // -------------------------------------------------------------------------
    println!("--- Loading config (Standard mode) ---");
    match Config::from_file(CONFIG_PATH).await {
        Ok(config) => {
            println!("[OK] Config loaded successfully.");
            println!("     hostname  : {}", config.hostname());
            println!("     env       : {:?}", config.agent.environment);
            println!("     decoy cnt : {}", config.deception.decoy_paths.len());
            config.validate().expect("Loaded config must be valid");
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
    match Config::from_file_with_mode(CONFIG_PATH, ValidationMode::Strict).await {
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
    match PolicyConfig::from_file(POLICY_PATH).await {
        Ok(policy) => {
            println!("[OK] Policy loaded successfully.");
            println!("     alert_threshold   : {}", policy.scoring.alert_threshold);
            println!("     response rules    : {}", policy.response.rules.len());
            println!("     suspicious procs  : {}", policy.deception.suspicious_processes.len());
            println!("     custom conditions : {}", policy.registered_custom_conditions.len());

            policy.validate().expect("Loaded policy must be valid");
            println!("     validation: passed");

            // Quick suspicious-process check after loading
            let test_names = ["MIMIKATZ.exe", "procdump64.exe", "svchost.exe", "LaZagne.py"];
            println!("\n     Suspicious-process checks:");
            for name in test_names {
                println!("       {name:20} -> {}", policy.is_suspicious_process(name));
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
    // AgentError exposes a public display for users and an internal_log() for
    // your logging pipeline. Never forward internal_log to end-users.
    // -------------------------------------------------------------------------
    println!("\n--- Error handling pattern ---");
    match Config::from_file("nonexistent/path/config.toml").await {
        Ok(_) => unreachable!(),
        Err(e) => {
            // Safe to show to users / API callers:
            println!("Public error  : {e}");

            // Contains operation, metadata, path — keep internal:
            // println!("Internal log  : {:?}", e.internal_log()); // DO NOT forward externally
        }
    }
}