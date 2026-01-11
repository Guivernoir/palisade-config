//! Policy operation benchmarks.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use palisade_config::{PolicyConfig, Severity};

fn bench_policy_creation(c: &mut Criterion) {
    c.bench_function("policy_default", |b| {
        b.iter(|| {
            let policy = PolicyConfig::default();
            black_box(policy);
        });
    });
}

fn bench_policy_validation(c: &mut Criterion) {
    let policy = PolicyConfig::default();
    
    c.bench_function("policy_validate", |b| {
        b.iter(|| {
            let result = policy.validate();
            black_box(result);
        });
    });
}

fn bench_suspicious_process_check(c: &mut Criterion) {
    let policy = PolicyConfig::default();
    
    c.bench_function("suspicious_process_benign", |b| {
        b.iter(|| {
            let result = policy.is_suspicious_process("firefox");
            black_box(result);
        });
    });
    
    c.bench_function("suspicious_process_malicious", |b| {
        b.iter(|| {
            let result = policy.is_suspicious_process("mimikatz.exe");
            black_box(result);
        });
    });
    
    c.bench_function("suspicious_process_mixed_case", |b| {
        b.iter(|| {
            let result = policy.is_suspicious_process("MiMiKaTz");
            black_box(result);
        });
    });
}

fn bench_severity_from_score(c: &mut Criterion) {
    c.bench_function("severity_low", |b| {
        b.iter(|| {
            let severity = Severity::from_score(30.0);
            black_box(severity);
        });
    });
    
    c.bench_function("severity_medium", |b| {
        b.iter(|| {
            let severity = Severity::from_score(50.0);
            black_box(severity);
        });
    });
    
    c.bench_function("severity_high", |b| {
        b.iter(|| {
            let severity = Severity::from_score(70.0);
            black_box(severity);
        });
    });
    
    c.bench_function("severity_critical", |b| {
        b.iter(|| {
            let severity = Severity::from_score(90.0);
            black_box(severity);
        });
    });
}

fn bench_policy_diff(c: &mut Criterion) {
    let policy1 = PolicyConfig::default();
    let policy2 = PolicyConfig::default();
    
    c.bench_function("policy_diff_identical", |b| {
        b.iter(|| {
            let changes = policy1.diff(&policy2);
            black_box(changes);
        });
    });
}

criterion_group!(
    benches,
    bench_policy_creation,
    bench_policy_validation,
    bench_suspicious_process_check,
    bench_severity_from_score,
    bench_policy_diff
);
criterion_main!(benches);