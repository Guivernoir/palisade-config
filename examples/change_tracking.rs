//! Change tracking example - demonstrates config/policy diffing.
use palisade_config::{Config, PolicyConfig};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Change Tracking ===\n");
    
    let config1 = Config::default();
    let config2 = Config::default();
    
    let changes = config1.diff(&config2);
    println!("Config changes: {} (same config = no changes)", changes.len());
    
    let policy1 = PolicyConfig::default();
    let policy2 = PolicyConfig::default();
    
    let changes = policy1.diff(&policy2);
    println!("Policy changes: {} (same policy = no changes)", changes.len());
    
    Ok(())
}