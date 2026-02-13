# palisade-config

Security-focused configuration and policy crate for deception/honeypot systems.

## What this crate provides

- Typed `Config` and `PolicyConfig` models with validation
- Cryptographic tag derivation via `RootTag` (SHA3-512)
- Runtime no-allocation representations (`RuntimeConfig`, `RuntimePolicy`)
- Centralized timing-floor profiles (`TimingProfile::Balanced` / `Hardened`)
- Security-oriented error model via `palisade-errors`

## Version

Current crate version: `0.1.1`

## Installation

```toml
[dependencies]
palisade-config = "0.1.1"
```

## Quick start

### 1) Load and validate config/policy

```rust
use palisade_config::{Config, PolicyConfig};

#[tokio::main(flavor = "current_thread")]
async fn main() -> palisade_config::Result<()> {
    let cfg = Config::from_file("./config.toml").await?;
    cfg.validate()?;

    let policy = PolicyConfig::from_file("./policy.toml").await?;
    policy.validate()?;

    println!("Config v{} / Policy v{}", cfg.version, policy.version);
    Ok(())
}
```

### 2) Convert to runtime no-alloc mode

```rust
use palisade_config::Config;

fn main() -> palisade_config::Result<()> {
    let runtime = Config::default().to_runtime()?;

    let mut tag_hex = [0u8; 128];
    runtime.derive_artifact_tag_hex_into("artifact-001", &mut tag_hex);

    Ok(())
}
```

### 3) Set centralized timing profile

```rust
use palisade_config::{set_timing_profile, TimingProfile};

fn main() {
    set_timing_profile(TimingProfile::Hardened);
}
```

## Architecture

### Config vs policy

- `Config`: infrastructure/runtime mechanics (paths, logging, telemetry, root tag)
- `PolicyConfig`: detection/response logic (thresholds, rules, suspicious patterns)

### Runtime no-alloc layer

`to_runtime()` converts deserialized models into fixed-capacity runtime types backed by `heapless`:

- `RuntimeConfig`
- `RuntimePolicy`

This is the intended execution layer for strict no-allocation runtime behavior.

## Timing model

The crate uses centralized operation timing floors in `src/timing.rs`.

Profiles:

- `Balanced` (default): lower latency, moderate smoothing
- `Hardened`: higher floors, stronger timing smoothing

Applied across:

- tag creation/derivation/comparison
- config load/validate/diff
- policy load/validate/diff and suspicious-process checks
- runtime build and runtime policy checks

## Security notes

- Sensitive data types use zeroization (`ZeroizeOnDrop`).
- `RootTag` uses fixed-size secret storage (`[u8; 32]`).
- Runtime cryptographic APIs support no-allocation usage (`*_bytes`, `*_hex_into`).
- Constant-time compare is used for root tag hash equality.

## Important behavior changes

- `Config::from_file` and `PolicyConfig::from_file` are async.
- `RootTag::new(...)` expects exactly 64 hex chars (32 bytes).
- `RootTag` serialization currently outputs the root secret as hex for round-trip support.
  Treat serialized config files as sensitive secrets.

## Examples

See `examples/`:

- `basic_config.rs`
- `runtime_no_alloc.rs`
- `timing_profile.rs`

Run with:

```bash
cargo run --example basic_config -- ./config.toml
cargo run --example runtime_no_alloc
cargo run --example timing_profile
```

## Benchmark analysis utility

Script:

- `scripts/analyze_bench_results.py`

Usage docs:

- `scripts/ANALYZE_BENCH_RESULTS_USAGE.md`

## License

Apache-2.0
