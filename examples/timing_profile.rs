//! # Example 07 — Timing Floors
//!
//! Demonstrates the global timing-floor system used to enforce minimum
//! operation latencies, preventing coarse timing side-channel attacks.
//!
//! ## Why Timing Floors?
//!
//! Without them, an attacker can fingerprint your honeypot by observing that:
//!   - A "found" result returns faster than a "not found" result
//!   - Hash comparisons on short secrets terminate early
//!   - Config load times reveal whether validation succeeded or failed
//!
//! Timing floors normalise all these operations to a predictable minimum,
//! making timing correlation attacks statistically useless.
//!
use palisade_config::{
    Config, ConfigApi, DEFAULT_TIMING_FLOOR, PolicyApi, PolicyConfig, RootTag, get_timing_floor,
    set_timing_floor,
};
use std::time::Duration;
use std::time::Instant;

fn time_operation<F: Fn()>(label: &str, iterations: u32, f: F) -> std::time::Duration {
    let start = Instant::now();
    for _ in 0..iterations {
        f();
    }
    let elapsed = start.elapsed();
    let per_iter = elapsed / iterations;
    println!("  {label:40} : {per_iter:?}/iter ({iterations} iters)");
    per_iter
}

fn main() {
    println!("=== Timing Floor Fundamentals ===");
    println!("  Initial floor: {:?}", get_timing_floor());

    // -------------------------------------------------------------------------
    // 1. Start from the default floor
    // -------------------------------------------------------------------------
    set_timing_floor(DEFAULT_TIMING_FLOOR);
    assert_eq!(get_timing_floor(), DEFAULT_TIMING_FLOOR);
    println!("  Set to default: {:?}", get_timing_floor());

    // -------------------------------------------------------------------------
    // 2. Measure key operations under the default floor
    // -------------------------------------------------------------------------
    println!("\n=== Default Floor — Operation Timings ===");
    println!("  (floor applied crate-wide: {:?})", get_timing_floor());

    let root = RootTag::generate().expect("generate");
    let policy = PolicyConfig::default();
    let rt_policy = policy.to_runtime().expect("runtime");
    let config = Config::default();
    let rt_config = config.to_runtime().expect("runtime");

    // Each of these enforces its timing floor via spin-wait
    let balanced_tag_new = time_operation("RootTag::generate()", 5, || {
        let _ = RootTag::generate().expect("generate");
    });

    let balanced_hash_cmp = time_operation("RootTag::hash_eq_ct()", 50, || {
        let other = RootTag::generate().expect("generate");
        let _ = root.hash_eq_ct(&other);
    });

    let balanced_suspicious = time_operation("RuntimePolicy::is_suspicious_process()", 50, || {
        let _ = rt_policy.is_suspicious_process("MIMIKATZ.exe");
    });

    let balanced_tag_derive =
        time_operation("RuntimeConfig::derive_artifact_tag_hex_into()", 50, || {
            let mut buf = [0u8; 128];
            rt_config.derive_artifact_tag_hex_into("artifact-001", &mut buf);
        });

    // -------------------------------------------------------------------------
    // 3. Raise the floor and remeasure
    // -------------------------------------------------------------------------
    let hardened_floor = Duration::from_micros(250);
    set_timing_floor(hardened_floor);
    assert_eq!(get_timing_floor(), hardened_floor);

    println!("\n=== Raised Floor — Operation Timings ===");
    println!("  (floor applied crate-wide: {:?})", get_timing_floor());

    let hardened_tag_new = time_operation("RootTag::generate()", 5, || {
        let _ = RootTag::generate().expect("generate");
    });

    let hardened_hash_cmp = time_operation("RootTag::hash_eq_ct()", 50, || {
        let other = RootTag::generate().expect("generate");
        let _ = root.hash_eq_ct(&other);
    });

    let hardened_suspicious = time_operation("RuntimePolicy::is_suspicious_process()", 50, || {
        let _ = rt_policy.is_suspicious_process("MIMIKATZ.exe");
    });

    let hardened_tag_derive =
        time_operation("RuntimeConfig::derive_artifact_tag_hex_into()", 50, || {
            let mut buf = [0u8; 128];
            rt_config.derive_artifact_tag_hex_into("artifact-001", &mut buf);
        });

    // -------------------------------------------------------------------------
    // 4. Compare ratios — the higher floor should be consistently slower
    // -------------------------------------------------------------------------
    println!("\n=== Floor Comparison ===");
    println!(
        "  {:40}  {:>12}  {:>12}  {:>8}",
        "Operation", "Default", "Raised", "Ratio"
    );
    println!(
        "  {:40}  {:>12}  {:>12}  {:>8}",
        "---------", "--------", "--------", "-----"
    );

    fn ratio(h: std::time::Duration, b: std::time::Duration) -> f64 {
        if b.as_nanos() == 0 {
            return 0.0;
        }
        h.as_nanos() as f64 / b.as_nanos() as f64
    }

    println!(
        "  {:40}  {:>12?}  {:>12?}  {:>7.2}×",
        "RootTag::generate()",
        balanced_tag_new,
        hardened_tag_new,
        ratio(hardened_tag_new, balanced_tag_new)
    );

    println!(
        "  {:40}  {:>12?}  {:>12?}  {:>7.2}×",
        "hash_eq_ct()",
        balanced_hash_cmp,
        hardened_hash_cmp,
        ratio(hardened_hash_cmp, balanced_hash_cmp)
    );

    println!(
        "  {:40}  {:>12?}  {:>12?}  {:>7.2}×",
        "is_suspicious_process()",
        balanced_suspicious,
        hardened_suspicious,
        ratio(hardened_suspicious, balanced_suspicious)
    );

    println!(
        "  {:40}  {:>12?}  {:>12?}  {:>7.2}×",
        "derive_artifact_tag_hex_into()",
        balanced_tag_derive,
        hardened_tag_derive,
        ratio(hardened_tag_derive, balanced_tag_derive)
    );

    // -------------------------------------------------------------------------
    // 5. Timing floor semantics — floors are MINIMUMS, not exact targets
    //
    // A slow machine honours the contract trivially. A fast machine is held
    // to the floor via spin-wait. Both produce the same timing band from an
    // external observer's perspective.
    // -------------------------------------------------------------------------
    println!("\n=== Timing Floor Semantics ===");
    println!("  Floors are minimum durations, not exact timings.");
    println!("  On fast hardware: spin-wait enforces the floor.");
    println!("  On slow hardware: natural execution time ≥ floor already.");
    println!("  Either way: external observer sees a consistent lower bound.");

    // -------------------------------------------------------------------------
    // 6. Concurrent floor reads — atomic, lock-free, safe from multiple threads
    // -------------------------------------------------------------------------
    println!("\n=== Thread-Safety of Floor Reads ===");
    set_timing_floor(DEFAULT_TIMING_FLOOR);

    let handles: Vec<_> = (0..4)
        .map(|i| {
            std::thread::spawn(move || {
                let floor = get_timing_floor();
                println!("  Thread {i}: floor = {:?}", floor);
                floor
            })
        })
        .collect();

    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    assert!(
        results.iter().all(|&floor| floor == DEFAULT_TIMING_FLOOR),
        "All threads must read the same floor"
    );
    println!("  All threads consistent: ✓");

    // -------------------------------------------------------------------------
    // 7. API-level timing normalization on top of the global floor
    // -------------------------------------------------------------------------
    println!("\n=== API-Level Timing Normalization ===");
    let config_api = ConfigApi::new().with_timing_floor(Duration::from_millis(1));
    let policy_api = PolicyApi::new().with_timing_floor(Duration::from_millis(1));
    let cfg = Config::default();
    let policy = PolicyConfig::default();

    let config_timing = time_operation("ConfigApi::to_runtime()", 10, || {
        let _ = config_api.to_runtime(&cfg).expect("runtime");
    });
    let policy_timing = time_operation("PolicyApi::validate()", 10, || {
        policy_api.validate(&policy).expect("validate");
    });

    println!("  Config API floor observed : {:?}", config_timing);
    println!("  Policy API floor observed : {:?}", policy_timing);
    println!("\nTiming floor examples completed.");
}
