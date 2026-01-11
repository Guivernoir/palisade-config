//! Configuration operation benchmarks.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use palisade_config::{Config, ValidationMode};
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

fn bench_config_serialization(c: &mut Criterion) {
    let config = Config::default();
    
    c.bench_function("config_to_toml", |b| {
        b.iter(|| {
            let toml = toml::to_string(&config).unwrap();
            black_box(toml);
        });
    });
    
    let toml = toml::to_string(&config).unwrap();
    
    c.bench_function("config_from_toml", |b| {
        b.iter(|| {
            let config: Config = toml::from_str(&toml).unwrap();
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

criterion_group!(
    benches,
    bench_config_creation,
    bench_config_validation,
    bench_config_diff,
    bench_config_serialization,
    bench_hostname_resolution
);
criterion_main!(benches);