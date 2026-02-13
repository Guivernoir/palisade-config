use palisade_config::Config;

fn main() -> palisade_config::Result<()> {
    // Deserialize/load as usual, then convert once to runtime no-alloc shape.
    let runtime = Config::default().to_runtime()?;

    let mut out = [0u8; 128];
    runtime.derive_artifact_tag_hex_into("artifact-001", &mut out);

    let hex = std::str::from_utf8(&out).expect("hex output is valid UTF-8");
    println!("Artifact tag hex: {hex}");

    Ok(())
}
