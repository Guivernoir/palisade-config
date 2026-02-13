// benches/palisade_performance.rs
//! Comprehensive benchmarks for palisade-config performance characteristics
//! 
//! Validates performance of key components including config loading, validation,
//! policy operations, tag derivation, and more.
//! Results are automatically saved to: palisade_benchmark_results.txt

use criterion::{criterion_group, criterion_main, Bencher, Criterion};
use palisade_config::*;
use palisade_errors::{definitions, AgentError};
use std::hint::black_box;
use std::path::PathBuf;
use std::time::Duration;

// ============================================================================
// Precise Allocation Tracking with stats_alloc
// ============================================================================

use stats_alloc::{Region, StatsAlloc, INSTRUMENTED_SYSTEM};
use std::alloc::System;
use std::fs::OpenOptions;
use std::io::Write;

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

/// Memory statistics for a single benchmark iteration
#[derive(Debug, Clone, Copy)]
struct MemStats {
    /// Total bytes allocated during operation
    allocated: usize,
    /// Total bytes deallocated during operation
    deallocated: usize,
    /// Net memory change (allocated - deallocated)
    net: isize,
    /// Number of allocation calls
    alloc_count: usize,
    /// Number of deallocation calls
    dealloc_count: usize,
}

impl MemStats {
    fn zero() -> Self {
        Self {
            allocated: 0,
            deallocated: 0,
            net: 0,
            alloc_count: 0,
            dealloc_count: 0,
        }
    }

    fn from_region(start: &stats_alloc::Stats, end: &stats_alloc::Stats) -> Self {
        let allocated = end.bytes_allocated.saturating_sub(start.bytes_allocated);
        let deallocated = end.bytes_deallocated.saturating_sub(start.bytes_deallocated);
        let alloc_count = end.allocations.saturating_sub(start.allocations);
        let dealloc_count = end.deallocations.saturating_sub(start.deallocations);
        
        Self {
            allocated,
            deallocated,
            net: allocated as isize - deallocated as isize,
            alloc_count,
            dealloc_count,
        }
    }

    fn median(stats: &[MemStats]) -> Self {
        if stats.is_empty() {
            return Self::zero();
        }

        let mut allocated: Vec<usize> = stats.iter().map(|s| s.allocated).collect();
        let mut deallocated: Vec<usize> = stats.iter().map(|s| s.deallocated).collect();
        let mut net: Vec<isize> = stats.iter().map(|s| s.net).collect();
        let mut alloc_count: Vec<usize> = stats.iter().map(|s| s.alloc_count).collect();
        let mut dealloc_count: Vec<usize> = stats.iter().map(|s| s.dealloc_count).collect();

        allocated.sort_unstable();
        deallocated.sort_unstable();
        net.sort_unstable();
        alloc_count.sort_unstable();
        dealloc_count.sort_unstable();

        let mid = stats.len() / 2;

        Self {
            allocated: allocated[mid],
            deallocated: deallocated[mid],
            net: net[mid],
            alloc_count: alloc_count[mid],
            dealloc_count: dealloc_count[mid],
        }
    }

    fn print_with_timing(&self, label: &str, time_ns: f64) {
        let output = format!(
            "\n┌─ Results: {} ─────────────────────────────────\n\
             │ Time:          {:>8.2} ns\n\
             │ Allocated:     {:>8} bytes  ({} allocs)\n\
             │ Deallocated:   {:>8} bytes  ({} deallocs)\n\
             │ Net Change:    {:>8} bytes\n\
             │ Avg per alloc: {:>8} bytes\n\
             └────────────────────────────────────────────────────────",
            label,
            time_ns,
            self.allocated, 
            self.alloc_count,
            self.deallocated, 
            self.dealloc_count,
            self.net.abs(),
            if self.alloc_count > 0 { self.allocated / self.alloc_count } else { 0 }
        );
        
        println!("{}", output);
        
        // Write to file with timing data
        Self::append_to_file(label, self, Some(time_ns));
    }

    fn append_to_file(label: &str, stats: &MemStats, time_ns: Option<f64>) {
        let filename = "palisade_benchmark_results.txt";
        
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(filename)
            .expect("Failed to open benchmark results file");
        
        // Write header with timestamp if file is empty/new
        let is_new_file = file.metadata()
            .map(|m| m.len() == 0)
            .unwrap_or(true);
            
        if is_new_file {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            
            writeln!(file, "════════════════════════════════════════════════════════════════════════════════════════════════").ok();
            writeln!(file, "Palisade Config Benchmark Results (Memory + Timing) - Unix timestamp: {}", now).ok();
            writeln!(file, "════════════════════════════════════════════════════════════════════════════════════════════════\n").ok();
        }
        
        // Format timing data
        let timing_str = if let Some(ns) = time_ns {
            if ns < 1_000.0 {
                format!("{:>8.2} ns", ns)
            } else if ns < 1_000_000.0 {
                format!("{:>8.2} µs", ns / 1_000.0)
            } else if ns < 1_000_000_000.0 {
                format!("{:>8.2} ms", ns / 1_000_000.0)
            } else {
                format!("{:>8.2} s", ns / 1_000_000_000.0)
            }
        } else {
            "  N/A      ".to_string()
        };
        
        writeln!(file, 
            "{:<50} │ Time: {} │ Alloc: {:>8} B ({:>3} calls) │ Dealloc: {:>8} B ({:>3} calls) │ Net: {:>8} B",
            label,
            timing_str,
            stats.allocated,
            stats.alloc_count,
            stats.deallocated,
            stats.dealloc_count,
            stats.net.abs()
        ).ok();
    }
}

// ============================================================================
// Benchmark Helper with Memory Tracking
// ============================================================================

fn bench_with_mem<F>(bencher: &mut Bencher, label: &str, mut f: F)
where
    F: FnMut(),
{
    let mut sampled_stats: Vec<MemStats> = Vec::with_capacity(256);
    let mut avg_time_ns = 0.0;

    bencher.iter_custom(|iters| {
        let mut total_time = Duration::ZERO;
        let sample_limit = 256usize;

        for i in 0..iters {
            let region = Region::new(GLOBAL);
            let start_time = std::time::Instant::now();
            black_box(f());
            let elapsed = start_time.elapsed();
            total_time += elapsed;

            if (i as usize) < sample_limit {
                let diff = region.change();
                sampled_stats.push(MemStats::from_region(&stats_alloc::Stats::default(), &diff));
            }
        }

        avg_time_ns = if iters > 0 {
            total_time.as_nanos() as f64 / iters as f64
        } else {
            0.0
        };

        total_time
    });

    let median_mem = MemStats::median(&sampled_stats);
    median_mem.print_with_timing(label, avg_time_ns);
}

// ============================================================================
// CONFIG BENCHMARKS
// ============================================================================

fn bench_config_creation(c: &mut Criterion) {
    c.bench_function("config_default", |b| {
        bench_with_mem(b, "Config Default Creation", || {
            black_box(Config::default());
        })
    });
}

fn bench_config_validation(c: &mut Criterion) {
    let config = Config::default();

    let mut group = c.benchmark_group("config_validation");

    group.bench_function("standard", |b| {
        bench_with_mem(b, "Config Validate Standard", || {
            let _ = black_box(config.validate());
        })
    });

    group.bench_function("strict", |b| {
        bench_with_mem(b, "Config Validate Strict", || {
            let _ = black_box(config.validate());
        })
    });

    group.finish();
}

fn bench_config_diff(c: &mut Criterion) {
    let config1 = Config::default();
    let mut config2 = Config::default();
    config2.deception.honeytoken_count += 1;

    c.bench_function("config_diff", |b| {
        bench_with_mem(b, "Config Diff", || {
            black_box(config1.diff(&config2));
        })
    });
}

fn bench_config_serialization(c: &mut Criterion) {
    let config = Config::default();

    c.bench_function("config_serialize_toml", |b| {
        bench_with_mem(b, "Config Serialize TOML", || {
            black_box(toml::to_string(&config).unwrap());
        })
    });
}

fn bench_config_deserialization(c: &mut Criterion) {
    let toml_str = toml::to_string(&Config::default()).unwrap();

    c.bench_function("config_deserialize_toml", |b| {
        bench_with_mem(b, "Config Deserialize TOML", || {
            black_box(toml::from_str::<Config>(&toml_str).unwrap());
        })
    });
}

// ============================================================================
// POLICY BENCHMARKS
// ============================================================================

fn bench_policy_creation(c: &mut Criterion) {
    c.bench_function("policy_default", |b| {
        bench_with_mem(b, "Policy Default Creation", || {
            black_box(PolicyConfig::default());
        })
    });
}

fn bench_policy_validation(c: &mut Criterion) {
    let policy = PolicyConfig::default();

    c.bench_function("policy_validate", |b| {
        bench_with_mem(b, "Policy Validate", || {
            let _ = black_box(policy.validate());
        })
    });
}

fn bench_policy_diff(c: &mut Criterion) {
    let policy1 = PolicyConfig::default();
    let mut policy2 = PolicyConfig::default();
    policy2.scoring.alert_threshold += 10.0;

    c.bench_function("policy_diff", |b| {
        bench_with_mem(b, "Policy Diff", || {
            black_box(policy1.diff(&policy2));
        })
    });
}

fn bench_policy_is_suspicious_process(c: &mut Criterion) {
    let policy = PolicyConfig::default();

    let mut group = c.benchmark_group("policy_suspicious_process");

    group.bench_function("match", |b| {
        bench_with_mem(b, "Is Suspicious Process Match", || {
            black_box(policy.is_suspicious_process("mimikatz.exe"));
        })
    });

    group.bench_function("no_match", |b| {
        bench_with_mem(b, "Is Suspicious Process No Match", || {
            black_box(policy.is_suspicious_process("notepad.exe"));
        })
    });

    group.finish();
}

// ============================================================================
// TAGS BENCHMARKS
// ============================================================================

fn bench_tag_generation(c: &mut Criterion) {
    c.bench_function("root_tag_generate", |b| {
        bench_with_mem(b, "Root Tag Generate", || {
            black_box(RootTag::generate().unwrap());
        })
    });
}

fn bench_tag_from_hex(c: &mut Criterion) {
    let hex = "8f2a7c91d4e6b3f0c5a19e274bd86370f1c49a2e6d8b35c7e902a4f1b6d3c8e5".to_string();

    c.bench_function("root_tag_from_hex", |b| {
        bench_with_mem(b, "Root Tag From Hex", || {
            black_box(RootTag::new(hex.clone()).unwrap());
        })
    });
}

fn bench_tag_derivation(c: &mut Criterion) {
    let tag = RootTag::generate().unwrap();

    let mut group = c.benchmark_group("tag_derivation");

    group.bench_function("host_tag", |b| {
        bench_with_mem(b, "Derive Host Tag", || {
            black_box(tag.derive_host_tag_bytes("localhost"));
        })
    });

    group.bench_function("artifact_tag", |b| {
        let mut out = [0u8; 128];
        bench_with_mem(b, "Derive Artifact Tag", || {
            tag.derive_artifact_tag_hex_into("localhost", "artifact1", &mut out);
            black_box(out);
        })
    });

    group.finish();
}

fn bench_entropy_validation(c: &mut Criterion) {
    let valid_hex = "8f2a7c91d4e6b3f0c5a19e274bd86370f1c49a2e6d8b35c7e902a4f1b6d3c8e5";
    let invalid_zeros_hex = "0000000000000000000000000000000000000000000000000000000000000000";

    let mut group = c.benchmark_group("entropy_validation");

    group.bench_function("valid", |b| {
        bench_with_mem(b, "Entropy Validate Valid", || {
            let _ = black_box(RootTag::new(valid_hex));
        })
    });

    group.bench_function("invalid_zeros", |b| {
        bench_with_mem(b, "Entropy Validate Invalid Zeros", || {
            let _ = black_box(RootTag::new(invalid_zeros_hex));
        })
    });

    group.finish();
}

// ============================================================================
// VALIDATION BENCHMARKS
// ============================================================================

fn bench_validation_modes(c: &mut Criterion) {
    let config = Config::default();

    let mut group = c.benchmark_group("validation_modes");

    group.bench_function("standard", |b| {
        bench_with_mem(b, "Validation Standard", || {
            let _ = black_box(config.validate());
        })
    });

    group.bench_function("strict", |b| {
        bench_with_mem(b, "Validation Strict", || {
            let _ = black_box(config.validate());
        })
    });

    group.finish();
}

fn bench_runtime_no_alloc(c: &mut Criterion) {
    let runtime_cfg = Config::default().to_runtime().unwrap();
    let runtime_policy = PolicyConfig::default().to_runtime().unwrap();

    let mut group = c.benchmark_group("runtime_no_alloc");

    group.bench_function("derive_artifact_tag_hex_into", |b| {
        let mut out = [0u8; 128];
        bench_with_mem(b, "Runtime Derive Artifact Tag Hex Into", || {
            runtime_cfg.derive_artifact_tag_hex_into("artifact1", &mut out);
            black_box(out);
        })
    });

    group.bench_function("is_suspicious_process", |b| {
        bench_with_mem(b, "Runtime Is Suspicious Process", || {
            black_box(runtime_policy.is_suspicious_process("MIMIKATZ.exe"));
        })
    });

    group.finish();
}

// ============================================================================
// ERROR BENCHMARKS 
// ============================================================================

fn bench_error_creation(c: &mut Criterion) {
    c.bench_function("error_creation_simple", |b| {
        bench_with_mem(b, "Error Creation Simple", || {
            let _ = black_box(AgentError::config(
                definitions::CFG_PARSE_FAILED,
                "operation",
                "details",
            ));
        })
    });
}

fn bench_error_with_metadata(c: &mut Criterion) {
    c.bench_function("error_with_metadata", |b| {
        bench_with_mem(b, "Error With Metadata", || {
            let _ = black_box(
                AgentError::config(definitions::CFG_PARSE_FAILED, "op", "details")
                    .with_metadata("key1", "value1")
                    .with_metadata("key2", "value2"),
            );
        })
    });
}

// ============================================================================
// PROTECTED TYPES BENCHMARKS
// ============================================================================

fn bench_protected_string(c: &mut Criterion) {
    c.bench_function("protected_string_new", |b| {
        bench_with_mem(b, "ProtectedString New", || {
            black_box(ProtectedString::new("secret".to_string()));
        })
    });
}

fn bench_protected_path(c: &mut Criterion) {
    c.bench_function("protected_path_new", |b| {
        bench_with_mem(b, "ProtectedPath New", || {
            black_box(ProtectedPath::new(PathBuf::from("/path")));
        })
    });
}

// ============================================================================
// ASYNC BENCHMARKS (Using block_on)
// ============================================================================

fn bench_config_from_file(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let temp_file = tempfile::NamedTempFile::new().unwrap();
    let path = temp_file.path().to_path_buf();
    let toml = toml::to_string(&Config::default()).unwrap();
    std::fs::write(&path, toml).unwrap();

    c.bench_function("config_from_file", |b| {
        bench_with_mem(b, "Config From File", || {
            rt.block_on(Config::from_file_with_mode(&path, ValidationMode::Standard)).unwrap();
        })
    });
}

// ============================================================================
// BENCHMARK GROUPS
// ============================================================================

criterion_group!(
    config_benches,
    bench_config_creation,
    bench_config_validation,
    bench_config_diff,
    bench_config_serialization,
    bench_config_deserialization,
    bench_config_from_file,
);

criterion_group!(
    policy_benches,
    bench_policy_creation,
    bench_policy_validation,
    bench_policy_diff,
    bench_policy_is_suspicious_process,
);

criterion_group!(
    tags_benches,
    bench_tag_generation,
    bench_tag_from_hex,
    bench_tag_derivation,
    bench_entropy_validation,
);

criterion_group!(
    validation_benches,
    bench_validation_modes,
    bench_runtime_no_alloc,
);

criterion_group!(
    error_benches,
    bench_error_creation,
    bench_error_with_metadata,
);

criterion_group!(
    protected_benches,
    bench_protected_string,
    bench_protected_path,
);

criterion_main!(
    config_benches,
    policy_benches,
    tags_benches,
    validation_benches,
    error_benches,
    protected_benches,
);
