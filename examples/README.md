# palisade-config — Examples

Comprehensive runnable examples covering every surface of the `palisade-config` crate.

## Prerequisites

```toml
# Cargo.toml
[dev-dependencies]
palisade-config = "1.0.1"
tokio = { version = "1", features = ["full"] }
hex = "0.4"
serde_json = "1"
```

## Running Examples

```bash
cargo run --example basics
cargo run --example toml_loading
cargo run --example runtime_hot_path
cargo run --example 04_tag_derivation
cargo run --example 05_diffing
cargo run --example 06_advanced_policy
cargo run --example 07_timing_profiles
cargo run --example 08_full_integration
```

To activate Hardened timing mode in examples 07 and 08:

```bash
PALISADE_ENV=production cargo run --example 07_timing_profiles
PALISADE_ENV=production cargo run --example 08_full_integration
```

---

## Example Overview

### `01_basic_defaults.rs` — Defaults & Validation

The starting point. Creates `Config` and `PolicyConfig` from defaults, inspects
every field, runs standard validation, and demonstrates what a validation failure
looks like. No filesystem access required.

**Covers:** `Config::default`, `PolicyConfig::default`, `Config::validate`,
`PolicyConfig::validate`, `Severity::from_score`, `ProtectedString`/`ProtectedPath`
debug redaction.

---

### `02_toml_loading.rs` — Loading from TOML

Loads `config.toml` and `policy.toml` from disk using both `Standard` and `Strict`
validation modes. Demonstrates the error-handling contract: public error vs.
internal log, and what to show to end-users vs. what to keep internal.

**Covers:** `Config::from_file`, `Config::from_file_with_mode`, `PolicyConfig::from_file`,
`ValidationMode::Standard`, `ValidationMode::Strict`, `AgentError` public/internal split.

**Requires:** `examples/config.toml` and `examples/policy.toml` to be present.

---

### `03_runtime_hotpath.rs` — No-Allocation Hot Path

The most performance-critical example. Shows the one-time conversion from
heap-allocated config/policy into stack-only `RuntimeConfig`/`RuntimePolicy`,
then drives a simulated 10,000-event loop with zero heap allocation per iteration.

**Covers:** `Config::to_runtime`, `PolicyConfig::to_runtime`, `RuntimeConfig`,
`RuntimePolicy`, `derive_artifact_tag_hex_into`, `is_suspicious_process`,
`is_registered_custom_condition`, capacity overflow handling.

---

### `04_tag_derivation.rs` — Cryptographic Tags

Deep-dive into the `RootTag` hierarchy. Covers generation, hex parsing, entropy
validation (all 4 rejection cases), the two-level derivation chain
(`root → host_tag → artifact_tag`), no-alloc hex output, constant-time comparison,
and serialise/deserialise round-trips including the `***REDACTED***` sentinel rejection.

**Covers:** `RootTag::generate`, `RootTag::new`, `RootTag::derive_host_tag`,
`RootTag::derive_artifact_tag`, `RootTag::derive_artifact_tag_hex_into`,
`RootTag::hash_eq_ct`, entropy validation errors, serde round-trip.

---

### `05_diffing.rs` — Change Tracking

Shows all diff variants: decoy path additions/removals, syscall monitor toggle,
root tag rotation, scoring threshold changes, response rule count changes, and
suspicious process list updates. Concludes with a practical hot-reload gate pattern.

**Covers:** `Config::diff`, `PolicyConfig::diff`, `ConfigChange`, `PolicyChange`,
hot-reload safety decision logic.

---

### `06_advanced_policy.rs` — Advanced Policy Configuration

Builds a production-grade financial-sector policy from scratch. Demonstrates all
five `ResponseCondition` variants with realistic parameters, custom condition
pre-registration security, duplicate severity rejection, and dry-run mode rollout.

**Covers:** `ScoringWeights`, `ResponseCondition` (all variants), `ResponseRule`,
`ActionType`, `PolicyConfig::validate`, custom condition injection prevention,
dry-run mode, severity reference table.

---

### `07_timing_profiles.rs` — Timing Side-Channel Mitigations

Benchmarks key operations under both `Balanced` and `Hardened` profiles and prints
a comparison table. Explains *why* timing floors exist and how the spin-wait
mechanism works on both fast and slow hardware. Includes a recommended profile
selection pattern based on `PALISADE_ENV`.

**Covers:** `set_timing_profile`, `get_timing_profile`, `TimingProfile`, timing
floor semantics, thread-safety of atomic profile reads.

---

### `08_full_integration.rs` — Daemon Startup Pattern

The authoritative end-to-end reference. Walks through all 7 lifecycle phases:
timing profile selection → config/policy load → runtime conversion →
artifact tag binding → event processing loop → hot-reload with diff-gating →
graceful shutdown with zeroization.

**Covers:** everything, in the order a real agent binary would use it.

---

## TOML Templates

### `config.toml`

Fully annotated configuration template. Every field documented with:
- Type and accepted values
- Default value
- Security implications
- When to change it

**Security note:** `root_tag` is a real-looking but intentionally invalid hex
string. Replace it with output from `RootTag::generate()` before use.

### `policy.toml`

Fully annotated policy template covering:
- All 5 `ResponseCondition` types with syntax examples
- All `ActionType` variants
- Comprehensive `suspicious_processes` list (14 common attacker tools)
- File pattern matching list
- Custom condition whitelist with commented examples

---

## Security Notes

### root_tag in config.toml

The `root_tag` field in `config.toml` is the master secret for your entire
artifact tag hierarchy. Treat it like a private key:

```
chmod 600 /etc/palisade/config.toml
chown palisade:palisade /etc/palisade/config.toml
```

Generate a new one per environment:

```rust
use palisade_config::RootTag;
let tag = RootTag::generate()?;
// Prints: a3f8c2...  (64 hex chars)
println!("{}", serde_json::to_string(&tag)?);
```

### ProtectedString / ProtectedPath

Fields wrapped in these types are automatically zeroized when dropped and
redact themselves in `Debug` output. Never unwrap them into plain `String`/`PathBuf`
and pass to logging — use the `.as_str()` / `.as_path()` accessors only where
needed, and let the wrappers go out of scope naturally.

### ValidationMode::Strict

Use `Strict` on daemon startup (paths must exist, log dir must be writable).
Use `Standard` for config validation in CI/testing environments where the
target paths don't exist.

### Error Handling Contract

```rust
match Config::from_file(path).await {
    Ok(config) => { /* proceed */ }
    Err(e) => {
        // SAFE to return to caller / log externally:
        return Err(e.to_string());

        // UNSAFE — contains internal paths, operation names, metadata:
        // log::error!("{:?}", e.internal_log());  // keep internal only
    }
}
```