//! # Example 08 — Full Integration: Daemon Startup Pattern
//!
//! Demonstrates the complete lifecycle of a honeypot agent:
//!
//!   1. Timing profile selection (before anything else)
//!   2. Config + policy load with strict validation
//!   3. Runtime conversion (heap → stack for hot paths)
//!   4. Artifact tag derivation (cryptographic binding)
//!   5. Simulated event processing loop
//!   6. Config hot-reload with diff-based decision
//!   7. Graceful shutdown (zeroization)
//!
//! This is the authoritative reference for integrating palisade-config into
//! an agent binary.

use palisade_config::{
    get_timing_profile, set_timing_profile, Config, PolicyConfig,
    RuntimeConfig, RuntimePolicy, Severity, TimingProfile,
};

// ─────────────────────────────────────────────────────────────────────────────
// Simulated event from the OS (inotify / eBPF / audit subsystem)
// ─────────────────────────────────────────────────────────────────────────────
#[derive(Debug)]
struct FileAccessEvent<'a> {
    artifact_id:  &'a str,
    process_name: &'a str,
    pid:          u32,
    is_off_hours: bool,
}

// ─────────────────────────────────────────────────────────────────────────────
// Simulated incident with scoring
// ─────────────────────────────────────────────────────────────────────────────
#[derive(Debug)]
struct Incident<'a> {
    event:    &'a FileAccessEvent<'a>,
    score:    f64,
    severity: Severity,
    tag:      [u8; 128], // stack-allocated artifact tag
}

// ─────────────────────────────────────────────────────────────────────────────
// Hot-path event processor — zero heap allocation per event
// ─────────────────────────────────────────────────────────────────────────────
fn process_event<'a>(
    event:     &'a FileAccessEvent<'a>,
    rt_config: &RuntimeConfig,
    rt_policy: &RuntimePolicy,
) -> Option<Incident<'a>> {
    // Step 1: derive artifact tag (no-alloc, stack buffer)
    let mut tag_buf = [0u8; 128];
    rt_config.derive_artifact_tag_hex_into(event.artifact_id, &mut tag_buf);

    // Step 2: compute confidence score
    let mut score = rt_policy.alert_threshold * 0.0; // start at zero
    score += 50.0; // base: artifact access

    if rt_policy.is_suspicious_process(event.process_name) {
        score += 30.0;
    }
    if event.is_off_hours {
        score += 15.0;
    }

    // Step 3: check threshold
    if score < rt_policy.alert_threshold {
        return None;
    }

    Some(Incident {
        event,
        score,
        severity: Severity::from_score(score),
        tag: tag_buf,
    })
}

#[tokio::main]
async fn main() {
    // =========================================================================
    // PHASE 1 — Timing profile (must be first — affects all subsequent calls)
    // =========================================================================
    let profile = if std::env::var("PALISADE_ENV").as_deref() == Ok("production") {
        TimingProfile::Hardened
    } else {
        TimingProfile::Balanced
    };
    set_timing_profile(profile);
    println!("[STARTUP] Timing profile: {:?}", get_timing_profile());

    // =========================================================================
    // PHASE 2 — Configuration load
    //
    // In a real daemon, these paths come from CLI args or /etc/palisade/.
    // We fall back to defaults here for the self-contained example.
    // =========================================================================
    println!("[STARTUP] Loading configuration...");

    let config = if std::path::Path::new("examples/config.toml").exists() {
        Config::from_file("examples/config.toml")
            .await
            .expect("Config load failed")
    } else {
        println!("  [WARN] examples/config.toml not found — using defaults");
        Config::default()
    };

    let policy = if std::path::Path::new("examples/policy.toml").exists() {
        PolicyConfig::from_file("examples/policy.toml")
            .await
            .expect("Policy load failed")
    } else {
        println!("  [WARN] examples/policy.toml not found — using defaults");
        PolicyConfig::default()
    };

    config.validate().expect("Config validation failed");
    policy.validate().expect("Policy validation failed");
    println!("[STARTUP] Config and policy loaded and validated.");

    // =========================================================================
    // PHASE 3 — Runtime conversion (heap → stack, one-time cost)
    // =========================================================================
    println!("[STARTUP] Converting to no-alloc runtime representations...");

    let rt_config = config.to_runtime()
        .expect("Config runtime conversion failed");
    let rt_policy = policy.to_runtime()
        .expect("Policy runtime conversion failed");

    println!("  hostname           : {}", rt_config.hostname);
    println!("  decoy_paths        : {}", rt_config.decoy_paths.len());
    println!("  watch_paths        : {}", rt_config.watch_paths.len());
    println!("  suspicious_procs   : {}", rt_policy.suspicious_processes.len());
    println!("  alert_threshold    : {}", rt_policy.alert_threshold);

    // =========================================================================
    // PHASE 4 — Pre-compute artifact tags for known decoys
    //
    // In production you'd persist these to a lookup table in shared memory.
    // Here we just print them to demonstrate the binding.
    // =========================================================================
    println!("\n[STARTUP] Binding artifact tags to decoy paths...");
    for path in rt_config.decoy_paths.iter() {
        let mut buf = [0u8; 128];
        rt_config.derive_artifact_tag_hex_into(path.as_str(), &mut buf);
        let tag = std::str::from_utf8(&buf).expect("hex is ASCII");
        println!("  {}  ->  {}...", path.as_str(), &tag[..24]);
    }

    // =========================================================================
    // PHASE 5 — Simulated event processing loop
    //
    // In a real agent this would be driven by inotify/fanotify/eBPF callbacks.
    // =========================================================================
    println!("\n[RUNTIME] Processing simulated events...");

    let events = vec![
        FileAccessEvent {
            artifact_id:  "/tmp/.credentials",
            process_name: "curl",
            pid:          1234,
            is_off_hours: false,
        },
        FileAccessEvent {
            artifact_id:  "/tmp/.credentials",
            process_name: "MIMIKATZ.exe",   // suspicious
            pid:          5678,
            is_off_hours: true,             // and off-hours
        },
        FileAccessEvent {
            artifact_id:  "/opt/.backup",
            process_name: "procdump64.exe", // suspicious
            pid:          9012,
            is_off_hours: false,
        },
        FileAccessEvent {
            artifact_id:  "/opt/.backup",
            process_name: "rsync",
            pid:          3456,
            is_off_hours: false,
        },
    ];

    let mut incident_count = 0;
    for event in &events {
        match process_event(event, &rt_config, &rt_policy) {
            Some(incident) => {
                incident_count += 1;
                let tag_str = std::str::from_utf8(&incident.tag).expect("hex");
                println!(
                    "  [INCIDENT] pid={:<6} proc={:<22} score={:.1}  severity={:?}  tag={}...",
                    incident.event.pid,
                    incident.event.process_name,
                    incident.score,
                    incident.severity,
                    &tag_str[..16],
                );
            }
            None => {
                println!(
                    "  [BENIGN ] pid={:<6} proc={:<22} (below threshold)",
                    event.pid, event.process_name
                );
            }
        }
    }

    println!("  Total incidents: {}/{}", incident_count, events.len());

    // =========================================================================
    // PHASE 6 — Config hot-reload pattern
    //
    // On SIGHUP (or a file-watcher callback), reload and diff before applying.
    // =========================================================================
    println!("\n[HOT-RELOAD] Simulating config reload...");

    let new_config  = Config::default();
    let new_policy  = PolicyConfig::default();

    new_config.validate().expect("Reloaded config invalid");
    new_policy.validate().expect("Reloaded policy invalid");

    let config_changes = config.diff(&new_config);
    let policy_changes = policy.diff(&new_policy);

    println!("  Config changes detected: {}", config_changes.len());
    for c in &config_changes {
        println!("    {:?}", c);
    }

    println!("  Policy changes detected: {}", policy_changes.len());
    for c in &policy_changes {
        println!("    {:?}", c);
    }

    // Safety gate: refuse reload if response rules would drop to zero
    let safe_to_reload = policy_changes.iter().all(|c| {
        !matches!(c, palisade_config::PolicyChange::ResponseRulesChanged {
            new_count, ..
        } if *new_count == 0)
    });

    if safe_to_reload {
        println!("  Hot-reload: APPLIED (safe diff)");
        // In production: atomically swap Arc<RuntimeConfig> / Arc<RuntimePolicy>
        let _new_rt_config = new_config.to_runtime().expect("runtime");
        let _new_rt_policy = new_policy.to_runtime().expect("runtime");
    } else {
        println!("  Hot-reload: BLOCKED (would eliminate all response rules — requires restart)");
    }

    // =========================================================================
    // PHASE 7 — Shutdown
    //
    // Config, PolicyConfig, and RootTag all implement ZeroizeOnDrop.
    // When these bindings go out of scope, the memory is securely wiped.
    // No explicit action required — Rust's drop mechanics handle it.
    // =========================================================================
    println!("\n[SHUTDOWN] Releasing resources...");
    println!("  Config and RootTag will be zeroized on drop (ZeroizeOnDrop).");
    println!("  No key material remains in heap after this scope exits.");
    println!("[SHUTDOWN] Done.");
}