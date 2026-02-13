use palisade_config::Config;

#[tokio::main(flavor = "current_thread")]
async fn main() -> palisade_config::Result<()> {
    let config_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "./config.toml".to_string());

    let cfg = Config::from_file(&config_path).await?;
    cfg.validate()?;

    println!("Loaded config v{}", cfg.version);
    println!("Hostname: {}", cfg.hostname());
    println!("Decoy paths: {}", cfg.deception.decoy_paths.len());
    println!("Credential types: {}", cfg.deception.credential_types.len());

    Ok(())
}
