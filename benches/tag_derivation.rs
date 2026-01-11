//! Tag derivation benchmarks.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use palisade_config::RootTag;

fn bench_tag_generation(c: &mut Criterion) {
    c.bench_function("tag_generate", |b| {
        b.iter(|| {
            let tag = RootTag::generate();
            black_box(tag);
        });
    });
}

fn bench_host_tag_derivation(c: &mut Criterion) {
    let root = RootTag::generate();
    
    c.bench_function("tag_derive_host", |b| {
        b.iter(|| {
            let host_tag = root.derive_host_tag("prod-web-01");
            black_box(host_tag);
        });
    });
}

fn bench_artifact_tag_derivation(c: &mut Criterion) {
    let root = RootTag::generate();
    
    c.bench_function("tag_derive_artifact", |b| {
        b.iter(|| {
            let artifact_tag = root.derive_artifact_tag("prod-web-01", "aws-credentials");
            black_box(artifact_tag);
        });
    });
}

fn bench_tag_hash_access(c: &mut Criterion) {
    let tag = RootTag::generate();
    
    c.bench_function("tag_hash_access", |b| {
        b.iter(|| {
            let hash = tag.hash();
            black_box(hash);
        });
    });
}

fn bench_tag_comparison(c: &mut Criterion) {
    let tag1 = RootTag::generate();
    let tag2 = RootTag::generate();
    
    c.bench_function("tag_hash_comparison", |b| {
        b.iter(|| {
            let equal = tag1.hash() == tag2.hash();
            black_box(equal);
        });
    });
}

criterion_group!(
    benches,
    bench_tag_generation,
    bench_host_tag_derivation,
    bench_artifact_tag_derivation,
    bench_tag_hash_access,
    bench_tag_comparison
);
criterion_main!(benches);