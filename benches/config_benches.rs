// CORRECTED BENCHMARK CODE FOR config_benches.rs
// Fixes the serialization round-trip benchmark failure

//! Configuration operation benchmarks.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use palisade_config::{Config, RootTag, ValidationMode};
use tempfile::TempDir;

fn bench_config_creation(c: &mut Criterion) {
    c.bench_function("config_default", |b| {
        b.iter(|| {
            let config = Config::default();
            black_box(config);
        });
    });
}

fn bench_config_validation(c: &mut Criterion) {
    let config = Config::default();
    
    c.bench_function("config_validate_standard", |b| {
        b.iter(|| {
            let result = config.validate_with_mode(ValidationMode::Standard);
            black_box(result);
        });
    });
}

fn bench_config_diff(c: &mut Criterion) {
    let config1 = Config::default();
    let config2 = Config::default();
    
    c.bench_function("config_diff_identical", |b| {
        b.iter(|| {
            let changes = config1.diff(&config2);
            black_box(changes);
        });
    });
}

// ============================================================================
// CORRECTED: Serialization benchmarks
// ============================================================================
//
// ISSUE: Config::default() creates a RootTag that serializes as "***REDACTED***"
// for security. This cannot be deserialized back, causing the round-trip to fail.
//
// SOLUTION: Use a valid TOML string with a real hex-encoded root tag for 
// deserialization benchmarking.

fn bench_config_serialization(c: &mut Criterion) {
    let config = Config::default();
    
    // Benchmark serialization (this works fine)
    c.bench_function("config_to_toml", |b| {
        b.iter(|| {
            let toml = toml::to_string(&config).unwrap();
            black_box(toml);
        });
    });
    
    // CORRECTED: Create valid TOML with actual hex-encoded root tag
    // Generate a valid root tag and get its hash for serialization
    let root_tag = RootTag::generate();
    let root_tag_hex = hex::encode(root_tag.hash());
    
    let valid_toml = format!(r#"
version = 1

[agent]
instance_id = "bench-agent"
work_dir = "/var/lib/palisade-agent"

[deception]
decoy_paths = ["/tmp/.credentials", "/opt/.backup"]
credential_types = ["aws", "ssh"]
honeytoken_count = 5
root_tag = "{}"
artifact_permissions = 384

[telemetry]
watch_paths = ["/tmp"]
event_buffer_size = 10000
enable_syscall_monitor = false

[logging]
log_path = "/var/log/palisade-agent.log"
format = "json"
rotate_size_bytes = 104857600
max_log_files = 10
level = "INFO"
"#, root_tag_hex);
    
    // Benchmark deserialization with valid TOML
    c.bench_function("config_from_toml", |b| {
        b.iter(|| {
            let config: Config = toml::from_str(&valid_toml).unwrap();
            black_box(config);
        });
    });
}

fn bench_hostname_resolution(c: &mut Criterion) {
    let config = Config::default();
    
    c.bench_function("hostname_resolution", |b| {
        b.iter(|| {
            let hostname = config.hostname();
            black_box(hostname);
        });
    });
}

// ============================================================================
// ADDITIONAL PERFORMANCE-CRITICAL BENCHMARKS
// ============================================================================
//
// Following your "SIMD & Vectorization" and "Allocation Minimization" preferences

fn bench_root_tag_operations(c: &mut Criterion) {
    c.bench_function("root_tag_generate", |b| {
        b.iter(|| {
            let tag = RootTag::generate();
            black_box(tag);
        });
    });
    
    let root_tag = RootTag::generate();
    
    c.bench_function("root_tag_hash", |b| {
        b.iter(|| {
            let hash = root_tag.hash();
            black_box(hash);
        });
    });
    
    c.bench_function("root_tag_derive", |b| {
        b.iter(|| {
            let derived = root_tag.derive_artifact_tag("host-bench", "artifact-bench");
            black_box(derived);
        });
    });
}

fn bench_config_file_operations(c: &mut Criterion) {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("bench_config.toml");
    
    // Create a valid config file
    let root_tag = RootTag::generate();
    let root_tag_hex = hex::encode(root_tag.hash());
    
    let config_content = format!(r#"
version = 1

[agent]
instance_id = "bench-agent"
work_dir = "/tmp/bench-work"

[deception]
decoy_paths = ["/tmp/.fake"]
credential_types = ["aws"]
honeytoken_count = 5
root_tag = "{}"
artifact_permissions = 384

[telemetry]
watch_paths = ["/tmp"]
event_buffer_size = 10000
enable_syscall_monitor = false

[logging]
log_path = "/tmp/bench.log"
format = "json"
rotate_size_bytes = 104857600
max_log_files = 10
level = "INFO"
"#, root_tag_hex);
    
    std::fs::write(&config_path, &config_content).unwrap();
    
    // Set secure permissions (required by validation)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(&config_path, perms).unwrap();
    }
    
    c.bench_function("config_load_from_file", |b| {
        b.iter(|| {
            let config = Config::from_file(&config_path).unwrap();
            black_box(config);
        });
    });
}

fn bench_validation_modes(c: &mut Criterion) {
    let config = Config::default();
    
    c.bench_function("validate_standard_mode", |b| {
        b.iter(|| {
            let result = config.validate_with_mode(ValidationMode::Standard);
            black_box(result);
        });
    });
    
    // Note: Strict validation benchmarking would require filesystem setup
    // and is highly environment-dependent, so we skip it here
}

// ============================================================================
// PERFORMANCE NOTES (Aligned with Hardened Rust preferences)
// ============================================================================
//
// 1. Memory Allocation Minimization:
//    - RootTag generation uses fixed-size arrays (no heap allocation)
//    - Tag derivation uses stack-based SHA3-512 (minimal allocations)
//    - Config validation borrows data (no clones)
//
// 2. Zero-Copy Semantics:
//    - hostname() returns &str (borrowed from config)
//    - validate() takes &self (immutable borrow)
//    - diff() takes &self (no ownership transfer)
//
// 3. Hot Path Optimization Opportunities:
//    - Tag derivation: Could use SIMD for SHA3 on x86_64
//    - Validation: Path existence checks could be batched
//    - Serialization: Could use unsafe zero-copy for large strings
//
// 4. Non-Blocking I/O (when applicable):
//    - File loading is synchronous (acceptable for config)
//    - For high-throughput scenarios, consider async config reloading
//
// 5. Error Handling Performance:
//    - Obfuscation adds minimal overhead (pointer indirection only)
//    - Error construction is lazy (metadata added on demand)

criterion_group!(
    benches,
    bench_config_creation,
    bench_config_validation,
    bench_config_diff,
    bench_config_serialization,
    bench_hostname_resolution,
    bench_root_tag_operations,
    bench_config_file_operations,
    bench_validation_modes,
);
criterion_main!(benches);