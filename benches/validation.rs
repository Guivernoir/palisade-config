//! Validation operation benchmarks.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use palisade_config::{Config, ValidationMode};

fn bench_validation_modes(c: &mut Criterion) {
    let config = Config::default();
    
    c.bench_function("validate_standard", |b| {
        b.iter(|| {
            let result = config.validate_with_mode(ValidationMode::Standard);
            black_box(result);
        });
    });
}

fn bench_validation_components(c: &mut Criterion) {
    let config = Config::default();
    
    c.bench_function("validate_full", |b| {
        b.iter(|| {
            let result = config.validate();
            black_box(result);
        });
    });
}

criterion_group!(
    benches,
    bench_validation_modes,
    bench_validation_components
);
criterion_main!(benches);