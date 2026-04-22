# palisade-config

Security-focused configuration and policy management for deception, honeypot, and high-scrutiny telemetry deployments.

[![Crates.io](https://img.shields.io/crates/v/palisade-config.svg)](https://crates.io/crates/palisade-config)
[![Documentation](https://docs.rs/palisade-config/badge.svg)](https://docs.rs/palisade-config)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

## Abstract

`palisade-config` is a deliberately narrow crate for loading, validating,
normalizing, and operationalizing sensitive configuration inputs in hostile or
high-observation environments. The design target is not generic application
configuration. It is the smaller and more demanding class of systems in which
configuration files themselves influence the attack surface: honeypots, decoy
infrastructure, deception agents, and tightly monitored detection pipelines.

The crate centers its public operational surface on two types:

- `ConfigApi` for infrastructure mechanics
- `PolicyApi` for detection and response policy

Those APIs embed validation into their load paths, support caller-selected
timing floors, and optionally route audit persistence through the encrypted log
path provided by `palisade-errors`.

## Positioning

This crate is a good fit when the following properties matter:

- configuration files contain security-sensitive material
- public-path timing behavior should be normalized to a minimum floor
- runtime hot paths should avoid heap allocation after startup conversion
- diffing and hot-reload review should expose structural changes without leaking
  secrets
- encrypted error and audit persistence should remain explicit and opt-in

It is a poor fit when the following priorities dominate:

- generic application settings with low security sensitivity
- derive-heavy integration with broad configuration ecosystems
- ergonomic error chaining across many third-party libraries
- unrestricted dynamic runtime structures with no fixed-capacity boundaries

## Public Interface

The preferred operational entry points are:

- `ConfigApi::new()`
- `PolicyApi::new()`
- `ConfigApi::load_runtime_file(...)` / `load_runtime_str(...)` for hardened,
  fixed-capacity admission directly into runtime config
- `PolicyApi::load_runtime_file(...)` / `load_runtime_str(...)` for hardened,
  fixed-capacity admission directly into runtime policy

The underlying typed models remain public for serialization, inspection, and
direct manipulation:

- `Config`
- `PolicyConfig`
- `RuntimeConfig`
- `RuntimePolicy`
- `RootTag`

The intended usage model is:

1. In high-risk production, load directly through the hardened runtime methods
2. Otherwise, load through `ConfigApi` / `PolicyApi`
3. Convert once to `RuntimeConfig` / `RuntimePolicy`
4. Operate on the runtime forms in hot paths

## Security Properties

### 1. Restricted Input Handling

On Unix platforms, configuration and policy files are opened through a
restricted loader that:

- rejects symlink inputs
- requires a regular file
- enforces owner-only permissions (`0o600` minimum policy)
- performs permission validation before content is admitted into the crate

On non-Unix platforms, the crate now fails closed for on-disk restricted file
admission. In a hardened deployment, `load_file(...)` is therefore a Unix-only
path unless the crate is redesigned around a platform-native trust model.

### 2. Embedded Validation

`ConfigApi` and `PolicyApi` embed validation into their load methods. In normal
use, a successful load already means parse plus validation succeeded.

Validation covers:

- schema/version compatibility
- required-field presence
- absolute-path requirements where applicable
- root-tag entropy heuristics
- range and capacity checks
- pre-registration of custom policy conditions

### 3. Runtime No-Allocation Path

`load_runtime_*()` and `to_runtime()` convert configuration into fixed-capacity
runtime types backed by `heapless`. After conversion, the hot-path primitives
are designed to avoid heap allocation and to avoid cloning long-lived secret
state.

The operational diff APIs also follow this model. `ConfigApi::diff(...)` and
`PolicyApi::diff(...)` now return borrowed, fixed-capacity reports instead of
allocating owned change sets.

For the compatibility loaders returning `Config` and `PolicyConfig`, this
guarantee does not apply to the load, deserialize, or validation stages because
those paths still materialize owned models.

For the hardened runtime loaders, the crate uses bounded file admission plus
fixed-capacity admitted types before moving directly into runtime structures.

### 4. Timing-Floor Normalization

Security-sensitive public operations use minimum execution floors to reduce
coarse timing discrimination.

The crate exposes:

- `DEFAULT_TIMING_FLOOR`
- `set_timing_floor(...)`
- `get_timing_floor()`
- `ConfigApi::with_timing_floor(...)`
- `PolicyApi::with_timing_floor(...)`

These floors reduce observable timing skew. They do not constitute a complete
side-channel proof.

### 5. Encrypted Log Persistence

When `feature = "log"` is enabled, this crate does not implement a separate log
encryption scheme of its own. Instead, it delegates persistence to
`palisade-errors::AgentError::log(...)`.

That matters operationally:

- persisted records are encrypted through the same hardened path used by
  `palisade-errors`
- the cryptographic implementation is inherited from that crate
- the underlying encrypted sink uses `crypto_bastion 0.4.0` through
  `palisade-errors`

In other words: yes, encrypted log persistence is applied, but it is applied by
delegation rather than by duplicating the encryption stack in this crate.

## Installation

```toml
[dependencies]
palisade-config = "2.0.0"
```

Enable encrypted log persistence and action logging:

```toml
[dependencies]
palisade-config = { version = "2.0.0", features = ["log"] }
```

## Quick Start

### 1. Provision a Root Tag

The `root_tag` field is a 64-character hex-encoded 256-bit secret.

```bash
openssl rand -hex 32
```

Treat the resulting value as high-sensitivity material.

### 2. Load Config and Policy

```rust
use palisade_config::{ConfigApi, PolicyApi, ValidationMode};

#[tokio::main(flavor = "current_thread")]
async fn main() -> palisade_config::Result<()> {
    let config_api = ConfigApi::new().with_validation_mode(ValidationMode::Strict);
    let policy_api = PolicyApi::new();

    let config = config_api.load_file("./config.toml").await?;
    let policy = policy_api.load_file("./policy.toml").await?;

    println!("config={} policy={}", config.version, policy.version);
    Ok(())
}
```

### 3. Hardened Production Load

```rust
use palisade_config::{ConfigApi, PolicyApi, ValidationMode};

#[tokio::main(flavor = "current_thread")]
async fn main() -> palisade_config::Result<()> {
    let config_api = ConfigApi::new().with_validation_mode(ValidationMode::Strict);
    let policy_api = PolicyApi::new();

    let runtime_config = config_api.load_runtime_file("./config.toml").await?;
    let runtime_policy = policy_api.load_runtime_file("./policy.toml").await?;

    let mut tag_hex = [0u8; 128];
    runtime_config.derive_artifact_tag_hex_into("artifact-001", &mut tag_hex);
    assert!(!runtime_policy.is_suspicious_process("svchost.exe"));
    Ok(())
}
```

### 4. Convert Once for Runtime Use

```rust
use palisade_config::{ConfigApi, PolicyApi};

fn prepare(
    config_api: &ConfigApi,
    policy_api: &PolicyApi,
    config: &palisade_config::Config,
    policy: &palisade_config::PolicyConfig,
) -> palisade_config::Result<()> {
    let runtime_config = config_api.to_runtime(config)?;
    let runtime_policy = policy_api.to_runtime(policy)?;

    let mut tag_hex = [0u8; 128];
    runtime_config.derive_artifact_tag_hex_into("artifact-001", &mut tag_hex);
    assert!(!runtime_policy.is_suspicious_process("svchost.exe"));
    Ok(())
}
```

### 5. Configure Timing Floors

```rust
use palisade_config::{DEFAULT_TIMING_FLOOR, set_timing_floor};
use std::time::Duration;

fn main() {
    set_timing_floor(DEFAULT_TIMING_FLOOR.max(Duration::from_micros(250)));
}
```

### 6. Enable Encrypted Audit Persistence

```rust
use palisade_config::{ConfigApi, PolicyApi};
use std::path::Path;

let config_api = ConfigApi::new()
    .with_log_path(Path::new("/var/log/palisade/config.audit.log"))
    .log_errors(true)
    .log_loads(true)
    .log_validations(true)
    .log_runtime_builds(true)
    .log_diffs(true);

let policy_api = PolicyApi::new()
    .with_log_path(Path::new("/var/log/palisade/policy.audit.log"))
    .log_errors(true)
    .log_loads(true)
    .log_validations(true)
    .log_runtime_builds(true)
    .log_diffs(true)
    .log_checks(true);
```

Notes:

- log paths should be absolute
- encrypted persistence is delegated to `AgentError::log(...)`
- enabled encrypted audit persistence fails closed across the operational API
  surface if the write cannot be completed
- action logging is opt-in per action category
- error logging is enabled automatically by `with_log_path(...)`
- the hardened runtime loaders are the recommended production path when you need
  bounded admission before runtime construction

## Validation Modes

`ValidationMode::Standard`

- parse and structural validation
- no extra filesystem assertions beyond loading the file itself
- suitable for CI, test harnesses, or incomplete staging layouts

`ValidationMode::Strict`

- all Standard checks
- existence checks for monitored filesystem targets
- parent-directory checks for writable logging destinations
- appropriate for production deployments with known-good filesystem layouts

## Architecture

### Config vs Policy

| Surface | Primary Concern | Example Contents |
|---|---|---|
| `Config` | infrastructure mechanics | working directories, watch paths, root tag, logging path |
| `PolicyConfig` | detection and response logic | thresholds, suspicious processes, response rules |

### Runtime Model

The crate distinguishes between admission-time and runtime-time structures:

- admission-time: flexible deserialized models
- runtime-time: fixed-capacity, no-allocation operational structures

This separation keeps the operational hot path narrow and bounded without
forcing the loading path to become artificially inflexible.

### Tag Derivation

```
root_tag (256-bit secret)
    -> host_tag = SHA3-512(root_tag || hostname)
    -> artifact_tag = SHA3-512(host_tag || artifact_id)
```

The design goal is stable per-host derivation with correlation resistance across
unrelated artifacts and straightforward invalidation through root-tag rotation.

## Operational Guidance

### Recommended Deployment Posture

For a high-risk honeypot deployment:

- use `ValidationMode::Strict`
- treat config and policy files as privileged assets
- keep files owner-only on Unix
- convert to runtime forms at startup, not lazily
- enable encrypted error and audit logging explicitly
- enable action logging only for the events you genuinely need to retain
- benchmark timing-floor choices against your real event volume

### Recommended Verification Workflow

```bash
cargo fmt --all
cargo test
cargo test --features log
cargo check --all-targets --all-features
cargo audit
cargo deny check
```

For higher assurance, add:

- reproducible CI builds
- scheduled dependency and supply-chain review
- fuzzing for parse and validation boundaries
- deployment-environment benchmarking for timing floors

Smoke-test fuzzing with:

```bash
cargo install cargo-fuzz --locked
cargo fuzz run config_from_toml -- -max_total_time=20
cargo fuzz run policy_from_toml -- -max_total_time=20
```

## Limitations

This crate should be adopted with the following limits in mind:

- timing floors reduce coarse timing leakage only
- hardened on-disk restricted loading is Unix-only and now fails closed on
  non-Unix platforms
- encrypted log persistence is delegated, not independently reimplemented here
- the crate does not protect against root-level host compromise
- plaintext config files still contain the serialized `root_tag`
- the compatibility loaders returning `Config` and `PolicyConfig` still use
  owned deserialized models
- the hardened runtime loaders close that boundary for production runtime
  admission, but they require the stricter fixed-capacity schema shape
- a strict no-trust posture still depends on operator controls, dependency
  review, and host hardening outside this crate

## Examples

Runnable examples are available under `examples/`:

- `basics`
- `toml_loading`
- `hot_paths`
- `derivation`
- `diffing`
- `advanced_policy`
- `timing`
- `full`

Run them with:

```bash
cargo run --example basics
cargo run --example toml_loading
cargo run --example hot_paths
cargo run --example derivation
cargo run --example diffing
cargo run --example advanced_policy
cargo run --example timing
cargo run --example full
```

## Related Documents

- [Security Policy](SECURITY.md)
- [Examples Guide](examples/README.md)
- [Benchmark Analysis Script Usage](scripts/ANALYZE_BENCH_RESULTS_USAGE.md)

## License

Apache-2.0
