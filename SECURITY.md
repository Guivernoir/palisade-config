# Security Policy

## Abstract

`palisade-config` is a security-sensitive crate intended for environments in
which configuration and policy inputs influence a live defensive surface. This
document describes the current guarantees, threat assumptions, operational
requirements, reporting channel, and known limitations for the latest supported
release.

## Supported Versions

Security fixes are applied to the latest released version only.

## Reporting Vulnerabilities

Do not report vulnerabilities through public issues.

Send reports to:

- `strukturaenterprise@gmail.com`

Include:

- affected version
- deployment context
- reproduction steps
- impact assessment
- suggested mitigation, if known

## Scope

This crate is responsible for:

- admission of configuration and policy files
- validation of sensitive configuration state
- hardened fixed-capacity admission directly into runtime structures
- derivation of runtime fixed-capacity structures
- root-tag handling and derivation support
- optional encrypted persistence of errors and selected audit actions

This crate is not responsible for:

- host hardening beyond the process boundary
- non-Unix ACL enforcement
- secret distribution infrastructure
- standardized secure-log interoperability formats
- containment after kernel- or root-level compromise

## Threat Model

The relevant attacker may:

- influence or replace configuration files on disk
- attempt symlink substitution or path redirection
- observe error messages and public-path timing
- obtain crash output or residual process memory after compromise
- access persisted log files without live process memory

The crate attempts to reduce information leakage and unsafe file admission at
the process boundary. It does not claim to secure a compromised host or to
eliminate all microarchitectural side channels.

## Current Guarantees

### 1. Restricted File Admission

On Unix platforms, configuration and policy files are loaded through a
restricted path that:

- opens with `O_NOFOLLOW`
- rejects symlink inputs
- requires the final target to be a regular file
- enforces owner-only permissions (`mode & 0o077 == 0`)

This guarantee applies to both `Config::from_file(...)` and
`PolicyConfig::from_file(...)`, and therefore also to `ConfigApi::load_file(...)`
and `PolicyApi::load_file(...)`.

On non-Unix platforms, the crate now fails closed for restricted on-disk
loading. Hardened file admission is therefore Unix-only in the current design.

### 2. Validation Discipline

Validation covers:

- schema version checks
- required-field presence
- path-shape validation
- range and size constraints
- custom-condition pre-registration
- root-tag entropy heuristics

`ValidationMode::Strict` adds environment-dependent filesystem assertions for
config workflows, including monitored-path existence and logging parent
directory checks.

### 3. Sensitive Data Handling

The crate uses zeroization and redacted debug behavior for selected sensitive
types:

- `RootTag`
- `ProtectedString`
- `ProtectedPath`

Diff outputs do not expose root-tag secrets directly. Tag changes are surfaced
through hash prefixes only.

### 4. Runtime Boundedness

`RuntimeConfig` and `RuntimePolicy` use fixed-capacity structures backed by
`heapless`. After conversion, hot-path runtime operations are designed to avoid
heap allocation.

The operational diff APIs follow the same principle: API-level config and policy
diffs return borrowed, fixed-capacity reports instead of owned heap-backed
change sets.

For the compatibility loaders returning `Config` and `PolicyConfig`, the load,
deserialize, and validation stages remain allocation-permitted.

For the hardened runtime loaders, the crate uses bounded input admission and
fixed-capacity admitted types before moving directly into runtime structures.

### 5. Timing Floors

Security-sensitive operations enforce minimum execution floors. The objective is
to reduce coarse timing discrimination across public paths.

Available controls:

- `DEFAULT_TIMING_FLOOR`
- `set_timing_floor(...)`
- `get_timing_floor()`
- `ConfigApi::with_timing_floor(...)`
- `PolicyApi::with_timing_floor(...)`

This is a mitigation, not a proof of side-channel resistance.

### 6. Encrypted Log Persistence

When `feature = "log"` is enabled, this crate persists encrypted records by
delegating to `palisade-errors::AgentError::log(...)`.

That implies:

- the encryption stack is inherited from `palisade-errors`
- the effective cryptographic backend includes `crypto_bastion 0.4.0` through
  that dependency
- this crate does not maintain an independent logging cipher implementation

Errors and selected successful actions can be persisted through this path.
Enabled encrypted audit writes now fail closed across the operational API
surface when the persistence step itself cannot complete.

## Operational Requirements

### Required Controls

Operators should treat the following as mandatory in high-risk deployments:

- owner-only file permissions on Unix for config and policy files
- `ValidationMode::Strict` for production config admission
- `load_runtime_file(...)` / `load_runtime_str(...)` for production runtime
  loading
- runtime conversion during controlled startup, not lazily in hot paths
- explicit review of log path placement and retention policy
- regular root-tag rotation procedures

### Strongly Recommended Controls

- external secret distribution through Vault, KMS, or equivalent
- immutable or tightly controlled configuration directories
- CI verification of dependency updates
- environment-specific benchmarking of timing floors
- incident-response procedures for root-tag rotation and artifact re-derivation

## Known Limitations

### 1. Timing Floors Are Not Side-Channel Proof

Timing floors reduce coarse observable differences but do not eliminate
microarchitectural leakage, scheduling effects, or pre-error-path work.

### 2. Serialized Root Tags Remain Sensitive at Rest

`RootTag` values serialize as hex so that TOML round-trips remain practical.
This means the secret exists in plaintext in the config file and must be treated
as private-key-class material.

### 3. Hardened Restricted Loading Is Unix-Only

The crate does not presently implement a trustworthy Windows ACL or other
portable restricted-file admission model. In hardened mode it therefore rejects
on-disk restricted loading on non-Unix targets instead of silently weakening the
trust boundary.

### 4. Host Compromise Remains Out of Scope

If the host or process is fully compromised, this crate should be considered
one control among many, not a containment boundary.

## Verification

Recommended verification commands:

```bash
cargo fmt --all
cargo test
cargo test --features log
cargo check --all-targets --all-features
cargo audit
cargo deny check
```

For deeper assurance, add:

- fuzzing of parse and validation boundaries
- platform-specific deployment tests
- operational benchmarking with realistic event rates

Recommended fuzz smoke commands:

```bash
cargo install cargo-fuzz --locked
cargo fuzz run config_from_toml -- -max_total_time=20
cargo fuzz run policy_from_toml -- -max_total_time=20
```

## Change-Sensitive Areas

Changes to the following files or modules deserve elevated review:

- `src/secure_fs.rs`
- `src/tags.rs`
- `src/timing.rs`
- `src/api.rs`
- any dependency or feature changes involving `palisade-errors`

## Disclosure Policy

Please allow time for triage and coordinated remediation before public
disclosure. Reports that include concrete reproductions and deployment context
are substantially easier to assess and prioritize.
