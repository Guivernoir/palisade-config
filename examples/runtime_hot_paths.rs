//! # Example 03 — No-Allocation Runtime Hot Path
//!
//! Demonstrates converting heap-allocated config/policy into stack-only
//! `RuntimeConfig` and `RuntimePolicy` for hot-path operations.
//!
//! Key properties after conversion:
//! - All strings stored in `heapless::String<N>` (stack-allocated)
//! - All collections stored in `heapless::Vec<T, N>` (stack-allocated)
//! - Timing floors enforced on every suspicious-process check
//! - No allocations in the critical event-processing loop

use palisade_config::{Config, PolicyConfig};
use std::time::Instant;

fn main() {
    // -------------------------------------------------------------------------
    // 1. Build and convert Config to RuntimeConfig
    // -------------------------------------------------------------------------
    let config = Config::default();

    let rt_config = config.to_runtime()
        .expect("Default config must convert to runtime successfully");

    println!("=== RuntimeConfig (stack-only) ===");
    println!("  hostname             : {}", rt_config.hostname);
    println!("  decoy_paths count    : {}", rt_config.decoy_paths.len());
    println!("  watch_paths count    : {}", rt_config.watch_paths.len());
    println!("  credential_types     : {:?}",
        rt_config.credential_types.iter().map(|s| s.as_str()).collect::<Vec<_>>());
    println!("  honeytoken_count     : {}", rt_config.honeytoken_count);
    println!("  artifact_permissions : {:o}", rt_config.artifact_permissions);

    // -------------------------------------------------------------------------
    // 2. Derive artifact tags — zero heap allocation
    //
    // The buffer lives on the stack. No Vec, no String, no Box.
    // This is safe to call thousands of times per second in an event loop.
    // -------------------------------------------------------------------------
    println!("\n=== Artifact Tag Derivation (no-alloc) ===");
    let mut tag_buf = [0u8; 128]; // stack-allocated output buffer

    rt_config.derive_artifact_tag_hex_into("artifact-001", &mut tag_buf);
    let tag_str = std::str::from_utf8(&tag_buf).expect("hex is always valid UTF-8");
    println!("  artifact-001 tag: {}", tag_str);

    rt_config.derive_artifact_tag_hex_into("artifact-002", &mut tag_buf);
    let tag_str = std::str::from_utf8(&tag_buf).expect("hex is always valid UTF-8");
    println!("  artifact-002 tag: {}", tag_str);

    // Same inputs → same outputs (deterministic derivation)
    let mut buf_a = [0u8; 128];
    let mut buf_b = [0u8; 128];
    rt_config.derive_artifact_tag_hex_into("artifact-001", &mut buf_a);
    rt_config.derive_artifact_tag_hex_into("artifact-001", &mut buf_b);
    assert_eq!(buf_a, buf_b, "Tag derivation must be deterministic");
    println!("  determinism check: PASSED");

    // -------------------------------------------------------------------------
    // 3. Build and convert PolicyConfig to RuntimePolicy
    // -------------------------------------------------------------------------
    let policy = PolicyConfig::default();

    let rt_policy = policy.to_runtime()
        .expect("Default policy must convert to runtime successfully");

    println!("\n=== RuntimePolicy (stack-only) ===");
    println!("  alert_threshold           : {}", rt_policy.alert_threshold);
    println!("  suspicious_processes count: {}", rt_policy.suspicious_processes.len());
    println!("  suspicious_patterns count : {}", rt_policy.suspicious_patterns.len());
    println!("  custom_conditions count   : {}", rt_policy.registered_custom_conditions.len());

    // -------------------------------------------------------------------------
    // 4. Hot-path suspicious process check
    //
    // Uses ASCII case-insensitive substring matching.
    // Timing floor applied to prevent timing side-channels.
    // -------------------------------------------------------------------------
    println!("\n=== Hot-Path Suspicious Process Checks ===");
    let test_cases = [
        ("mimikatz.exe",   true),
        ("MIMIKATZ.EXE",   true),
        ("MiMiKaTz",       true),
        ("procdump64.exe", true),   // substring match on "procdump"
        ("LaZagne.py",     true),   // substring match on "lazagne" (stored lowercase)
        ("svchost.exe",    false),
        ("notepad.exe",    false),
        ("chrome.exe",     false),
    ];

    for (name, expected) in test_cases {
        let result = rt_policy.is_suspicious_process(name);
        let marker = if result == expected { "[OK]" } else { "[FAIL]" };
        println!("  {marker} is_suspicious({name:20}) = {result}  (expected {expected})");
    }

    // -------------------------------------------------------------------------
    // 5. Custom condition registration check
    // -------------------------------------------------------------------------
    println!("\n=== Custom Condition Checks ===");
    println!("  is_registered('never_registered') = {}",
        rt_policy.is_registered_custom_condition("never_registered"));

    // -------------------------------------------------------------------------
    // 6. Simulated high-frequency event loop (demonstrates no-alloc pattern)
    //
    // In a real agent, this loop would be driven by kernel events (inotify, eBPF).
    // We simulate 10,000 iterations to show the pattern is sound.
    // -------------------------------------------------------------------------
    println!("\n=== Simulated Event Loop (10,000 iterations) ===");
    let process_names = [
        "svchost.exe",
        "python3",
        "MIMIKATZ.EXE",
        "bash",
        "procdump64",
        "curl",
        "lazagne",
        "nginx",
    ];

    let start = Instant::now();
    let mut alert_count = 0usize;
    let mut tag_buf = [0u8; 128]; // reused on stack, no reallocation

    for i in 0..10_000usize {
        let process_name = process_names[i % process_names.len()];
        let artifact_id  = format!("artifact-{}", i % 16); // small heap alloc for demo ID only

        // Hot path: no allocation
        rt_config.derive_artifact_tag_hex_into(&artifact_id, &mut tag_buf);

        // Hot path: no allocation, timing floor enforced
        if rt_policy.is_suspicious_process(process_name) {
            alert_count += 1;
        }
    }

    let elapsed = start.elapsed();
    println!("  iterations : 10,000");
    println!("  alerts     : {alert_count}");
    println!("  elapsed    : {elapsed:?}");
    println!("  per-iter   : {:?}", elapsed / 10_000);
    println!("  Note: timing floors add deliberate latency to prevent side-channel analysis.");

    // -------------------------------------------------------------------------
    // 7. Capacity boundary — what happens if you exceed heapless limits?
    // -------------------------------------------------------------------------
    println!("\n=== Capacity Overflow Handling ===");
    let mut big_config = Config::default();
    // Inject 70 decoy paths (MAX_PATH_ENTRIES = 64)
    big_config.deception.decoy_paths = (0..70)
        .map(|i| std::path::PathBuf::from(format!("/tmp/decoy-{i:03}")))
        .collect::<Vec<_>>()
        .into_boxed_slice();

    match big_config.to_runtime() {
        Err(e) => println!("  [OK] Correctly rejected 70 decoy paths (max=64): {e}"),
        Ok(_)  => println!("  [UNEXPECTED] Accepted 70 paths — check MAX_PATH_ENTRIES"),
    }
}