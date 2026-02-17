# palisade-config

Security-focused configuration and policy crate for deception/honeypot systems.

[![Crates.io](https://img.shields.io/crates/v/palisade-config.svg)](https://crates.io/crates/palisade-config)
[![Documentation](https://docs.rs/palisade-config/badge.svg)](https://docs.rs/palisade-config)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

## What this crate provides

- Typed `Config` and `PolicyConfig` models with multi-layer validation
- Cryptographic tag derivation via `RootTag` (SHA3-512 hierarchy)
- Runtime no-allocation representations (`RuntimeConfig`, `RuntimePolicy`)
- Centralized timing-floor profiles (`TimingProfile::Balanced` / `Hardened`)
- Config/policy diffing for safe hot-reload workflows
- Security-oriented error model via `palisade-errors`

## Version

Current crate version: `1.0.2`

## Installation

```toml
[dependencies]
palisade-config = "1.0.2"
```

## Prerequisites: file permissions

`Config::from_file` and `PolicyConfig::from_file` enforce Unix file permissions
before reading. Config and policy files **must** be `0o600` (owner read/write only):

```bash
chmod 600 config.toml
chmod 600 policy.toml
```

Any other permission mode (e.g. default `0o644`) will return a security violation
error before any content is read. This is enforced, not optional.

## Quick start

### 1) Generate a root tag

The `root_tag` field in `config.toml` requires a 64-character hex-encoded 256-bit secret
with sufficient entropy (non-zero, non-sequential, ≥25% unique bytes):

```bash
openssl rand -hex 32
```

Paste the output into your `config.toml` as the `root_tag` value.

### 2) Load and validate config/policy

`from_file` runs standard validation automatically. Calling `validate()` again is
redundant — it is only needed when validating a config constructed in-process
(e.g. from `Config::default()` or after manual field mutation).

```rust
use palisade_config::{Config, PolicyConfig};

#[tokio::main(flavor = "current_thread")]
async fn main() -> palisade_config::Result<()> {
    // Loads, deserializes, and validates in one call.
    let cfg = Config::from_file("./config.toml").await?;
    let policy = PolicyConfig::from_file("./policy.toml").await?;

    println!("Config v{} / Policy v{}", cfg.version, policy.version);
    Ok(())
}
```

For strict validation (paths must exist, log directory must be writable):

```rust
use palisade_config::{Config, ValidationMode};

let cfg = Config::from_file_with_mode("./config.toml", ValidationMode::Strict).await?;
```

### 3) Convert to runtime no-alloc mode

```rust
use palisade_config::Config;

fn main() -> palisade_config::Result<()> {
    let cfg = Config::default();
    let runtime = cfg.to_runtime()?;

    let mut tag_hex = [0u8; 128];
    runtime.derive_artifact_tag_hex_into("artifact-001", &mut tag_hex);
    // tag_hex now contains the lowercase hex digest — no heap allocation

    Ok(())
}
```

### 4) Policy checks at runtime

```rust
use palisade_config::PolicyConfig;

fn main() -> palisade_config::Result<()> {
    let policy = PolicyConfig::default();
    let runtime = policy.to_runtime()?;

    // ASCII case-insensitive substring match, no heap allocation
    assert!(runtime.is_suspicious_process("MIMIKATZ.exe"));
    assert!(!runtime.is_suspicious_process("svchost.exe"));

    Ok(())
}
```

### 5) Hot-reload via diff

Diff exposes only what changed — safe to apply, log, or reject at your discretion:

```rust
use palisade_config::{Config, PolicyConfig};

fn hot_reload(
    current_cfg: &Config,
    new_cfg: &Config,
    current_policy: &PolicyConfig,
    new_policy: &PolicyConfig,
) {
    let cfg_changes = current_cfg.diff(new_cfg);
    let policy_changes = current_policy.diff(new_policy);

    for change in &cfg_changes {
        println!("{change:?}");
    }
    // Root tag changes surface as hash prefix only — secret never exposed in diff output
}
```

### 6) Set timing profile

```rust
use palisade_config::{set_timing_profile, TimingProfile};

fn main() {
    // Use Hardened in hostile environments; Balanced when latency budget is tight
    set_timing_profile(TimingProfile::Hardened);
}
```

## Architecture

### Config vs policy

| | `Config` | `PolicyConfig` |
|---|---|---|
| Purpose | Infrastructure mechanics | Detection/response logic |
| Contains | Paths, logging, telemetry, root tag | Thresholds, rules, suspicious patterns |
| Secret material | Yes (`RootTag`) | No |
| File sensitivity | High | Medium |

### Validation modes

`Standard` (default via `from_file`): format checks, range checks, entropy checks.
No filesystem access beyond reading the config file itself.

`Strict` (via `from_file_with_mode`): all Standard checks plus path existence,
parent directory existence, and log directory write-access verification.
Use in production; `Standard` is appropriate for CI environments where
monitored paths may not exist.

### Runtime no-alloc layer

`to_runtime()` converts deserialized models into fixed-capacity runtime types
backed by `heapless`. All hot-path operations on `RuntimeConfig` and `RuntimePolicy`
are designed for zero heap allocation.

Fixed capacities (see `runtime.rs`):

| Constant | Default |
|---|---|
| `MAX_PATH_LEN` | 512 bytes |
| `MAX_LABEL_LEN` | 64 bytes |
| `MAX_PATH_ENTRIES` | 64 |
| `MAX_CREDENTIAL_TYPES` | 32 |
| `MAX_SUSPICIOUS_PROCESSES` | 128 |
| `MAX_SUSPICIOUS_PATTERNS` | 128 |
| `MAX_CUSTOM_CONDITIONS` | 128 |

### Cryptographic tag hierarchy

```
root_tag (256-bit secret)
    └── host_tag  = SHA3-512(root_tag || hostname)
            └── artifact_tag = SHA3-512(host_tag || artifact_id)
```

Tags are deterministic — same inputs always produce the same tag. Rotating the
root tag breaks all artifact correlations simultaneously.

### Timing model

All security-sensitive operations have minimum execution floors applied via
`enforce_operation_min_timing`. This reduces coarse timing side-channel leakage;
it is not a full side-channel proof (see SECURITY.md).

| Profile | Use case |
|---|---|
| `Balanced` (default) | Lower latency, moderate smoothing |
| `Hardened` | Higher floors, stronger timing smoothing |

## Examples

See `examples/`:

- `toml_loading.rs` — load config and policy from TOML files, validate, run policy checks
- `full.rs` — full integration: startup, runtime conversion, tag binding, incident scoring, hot-reload, shutdown

Run with:

```bash
# Requires examples/config.toml and examples/policy.toml with chmod 600
cargo run --example basics
cargo run --example toml_loading
cargo run --example hot_paths
cargo run --example derivation
cargo run --example diffing
cargo run --example advanced_policy
cargo run --example timing
cargo run --example full
```

See `examples/config.toml` and `examples/policy.toml` for reference templates.

## Benchmark analysis utility

Script: `scripts/analyze_bench_results.py`

Usage: `scripts/ANALYZE_BENCH_RESULTS_USAGE.md`

## License

Apache-2.0