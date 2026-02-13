use palisade_config::{
    get_timing_profile, set_timing_profile, Config, TimingProfile,
};

fn main() -> palisade_config::Result<()> {
    println!("Default timing profile: {:?}", get_timing_profile());

    // Switch to stronger smoothing.
    set_timing_profile(TimingProfile::Hardened);
    println!("Current timing profile: {:?}", get_timing_profile());

    // Operations automatically use centralized timing floors.
    let runtime = Config::default().to_runtime()?;
    let mut out = [0u8; 128];
    runtime.derive_artifact_tag_hex_into("artifact-ct", &mut out);

    // Restore default profile if desired.
    set_timing_profile(TimingProfile::Balanced);

    Ok(())
}
