# Examples Guide

## Abstract

The examples in this repository are intended to demonstrate operational usage of
`palisade-config`, not merely API syntax. Each example emphasizes a particular
deployment concern: admission-time validation, runtime conversion, diff-based
reload review, timing-floor selection, or encrypted audit persistence.

The examples should be read as executable notes for implementers evaluating the
crate in a realistic security context.

## Execution Prerequisites

```toml
[dev-dependencies]
palisade-config = "2.0.0"
tokio = { version = "1", features = ["full"] }
hex = "0.4"
serde_json = "1"
```

For examples that read on-disk configuration, ensure the sample files are
present and, on Unix, restricted appropriately:

```bash
chmod 600 examples/config.toml
chmod 600 examples/policy.toml
```

## Running the Suite

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

To exercise encrypted audit persistence:

```bash
cargo run --example toml_loading --features log
```

## Example Matrix

### `basic_defaults.rs`

Purpose:
Inspect the default config and policy models, validate them, and understand the
baseline shape of the crate without touching the filesystem.

Covers:
`Config::default`, `PolicyConfig::default`, `Config::validate`,
`PolicyConfig::validate`, `Severity::from_score`, protected debug redaction.

### `toml_loading.rs`

Purpose:
Demonstrate the intended operational entry points: `ConfigApi` and `PolicyApi`.

Covers:
embedded validation, strict config validation, error-surface handling,
suspicious-process checks through `PolicyApi`.

For high-risk runtime startup, prefer the hardened runtime-loading methods over
the compatibility loaders:

- `ConfigApi::load_runtime_file(...)`
- `PolicyApi::load_runtime_file(...)`

### `runtime_hot_paths.rs`

Purpose:
Show the transition from admission-time structures to fixed-capacity runtime
structures and highlight the post-conversion no-allocation operating model.

Covers:
`to_runtime`, artifact-tag derivation into caller buffers, suspicious-process
checks, registered custom-condition lookups.

### `tag_derivation.rs`

Purpose:
Explain the `RootTag` hierarchy and demonstrate deterministic derivation,
entropy rejection, and no-allocation hex output.

Covers:
`RootTag::generate`, `RootTag::new`, host/artifact derivation, constant-time
comparison, serde round-trip constraints.

### `diffing.rs`

Purpose:
Illustrate config/policy change review for hot reload and partial rollout.

Covers:
borrowed fixed-capacity diff reports, secret-preserving diffs, hot-reload
gating.

### `advanced_policy.rs`

Purpose:
Model realistic response logic with explicit condition semantics and
pre-registered custom-condition discipline.

Covers:
response conditions, action types, severity mapping, custom-condition policy.

### `timing_profile.rs`

Purpose:
Measure the timing-floor controls and explain how they interact with the
security-sensitive public surface.

Covers:
`DEFAULT_TIMING_FLOOR`, `set_timing_floor`, `get_timing_floor`,
`ConfigApi::with_timing_floor`, `PolicyApi::with_timing_floor`.

### `full_integration.rs`

Purpose:
Present a realistic startup-to-runtime lifecycle for a honeypot or deception
agent using the crate end to end.

Covers:
timing-floor selection, file admission, runtime conversion, artifact-tag
binding, event scoring, diff-based reload review, shutdown posture.

## Logging Note

When `feature = "log"` is enabled, example logging is not plain text. Audit
persistence is routed through `palisade-errors::AgentError::log(...)`, which
means the encrypted persistence path is inherited from that crate.

Operationally:

- `with_log_path(...)` enables the encrypted sink
- `log_errors(true)` persists error outcomes
- `log_loads(true)`, `log_validations(true)`, `log_runtime_builds(true)`,
  `log_diffs(true)`, and `log_checks(true)` opt into successful action records
- log paths should be absolute
- enabled encrypted persistence fails closed if the audit write cannot be
  completed

## High-Assurance Evaluation

For a production-style evaluation of the crate rather than just the examples,
run:

```bash
cargo test
cargo test --features log
cargo check --all-targets --all-features
cargo audit
cargo deny check
```

## Reading Order

For first-time evaluation, the most useful progression is:

1. `basic_defaults.rs`
2. `toml_loading.rs`
3. `runtime_hot_paths.rs`
4. `timing_profile.rs`
5. `full_integration.rs`

This order moves from model shape to admission path, then from runtime
operational behavior to end-to-end deployment framing.

## Limitations

The examples are pedagogical rather than exhaustive. They do not replace:

- environment-specific benchmarking
- platform hardening
- secrets-distribution design
- formal incident-response playbooks

For the crate's current guarantees and limits, consult the repository-level
security policy.
