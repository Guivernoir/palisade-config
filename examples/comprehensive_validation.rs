//! Comprehensive validation example.
//!
//! Demonstrates all validation modes and error handling scenarios.

use palisade_config::{Config, ValidationMode};
use tempfile::TempDir;
use std::path::PathBuf;

use palisade_config::{ProtectedString, ProtectedPath};
fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Palisade Config: Comprehensive Validation ===\n");

    let temp_dir = TempDir::new()?;

    // ========================================================================
    // 1. Standard Validation Mode
    // ========================================================================
    println!("1. Standard validation (format checks only)...");
    
    let config = Config::default();
    match config.validate_with_mode(ValidationMode::Standard) {
        Ok(()) => println!("   ✓ Configuration valid\n"),
        Err(e) => {
            println!("   ✗ Validation failed: {}", e);
            e.with_internal_log(|log| {
                println!("   Internal: {:?}", log);
            });
        }
    }

    // ========================================================================
    // 2. Strict Validation Mode
    // ========================================================================
    println!("2. Strict validation (filesystem checks)...");
    
    let mut config = Config::default();
    config.agent.work_dir = ProtectedPath::new(temp_dir.path().join("agent-work"));
    
    match config.validate_with_mode(ValidationMode::Strict) {
        Ok(()) => {
            println!("   ✓ Configuration valid");
            println!("   ✓ Work directory created: {}", config.agent.work_dir.as_path().display());
            println!("   ✓ Permissions verified\n");
        }
        Err(e) => {
            println!("   ✗ Validation failed: {}", e);
        }
    }

    // ========================================================================
    // 3. Catching Empty Required Fields
    // ========================================================================
    println!("3. Validating required fields...");
    
    let mut config = Config::default();
    config.agent.instance_id = ProtectedString::new(String::new());
    
    match config.validate() {
        Ok(()) => println!("   ✗ Should have failed!"),
        Err(e) => {
            println!("   ✓ Correctly rejected empty instance_id");
            println!("   Error: {}\n", e);
        }
    }

    // ========================================================================
    // 4. Path Validation
    // ========================================================================
    println!("4. Path validation...");
    
    let mut config = Config::default();
    config.agent.work_dir = ProtectedPath::new(PathBuf::from("relative/path"));
    
    match config.validate() {
        Ok(()) => println!("   ✗ Should have failed!"),
        Err(e) => {
            println!("   ✓ Correctly rejected relative path");
            println!("   Error: {}\n", e);
        }
    }

    // ========================================================================
    // 5. Range Validation
    // ========================================================================
    println!("5. Range validation...");
    
    let mut config = Config::default();
    config.deception.honeytoken_count = 150;
    
    match config.validate() {
        Ok(()) => println!("   ✗ Should have failed!"),
        Err(e) => {
            println!("   ✓ Correctly rejected out-of-range value");
            println!("   Error: {}\n", e);
        }
    }

    println!("=== Validation demonstration complete! ===");
    Ok(())
}