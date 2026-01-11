//! Production deployment example with full error handling.
use palisade_config::{Config, PolicyConfig, ValidationMode};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Production Deployment ===\n");
    
    // Load and validate config
    let config = Config::default();
    config.validate_with_mode(ValidationMode::Strict)?;
    println!("✓ Configuration validated");
    
    // Load and validate policy
    let policy = PolicyConfig::default();
    policy.validate()?;
    println!("✓ Policy validated");
    
    println!("\n✓ Ready for production deployment");
    Ok(())
}