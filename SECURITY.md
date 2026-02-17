# Security Policy

## Scope

`palisade-config` is a security-sensitive crate that handles:

- Root cryptographic tag material
- Infrastructure and detection policy inputs
- Runtime decision-path checks

This document covers current guarantees, limitations, and reporting guidance.

## Supported versions

Security fixes are applied to the latest released version.

## Reporting vulnerabilities

Do not open public issues for vulnerabilities.

Send details to: `strukturaenterprise@gmail.com`

Include:

- Affected version
- Reproduction steps
- Impact assessment
- Suggested fix (if available)

## Current security model

### 1) File permission enforcement

On Unix systems, `Config::from_file` and `PolicyConfig::from_file` call
`validate_file_permissions` **before reading any content**. Files with
`mode & 0o077 != 0` (i.e. any group or world read/write/execute bits set) are
rejected with a security violation error. This means the minimum acceptable
permission is `0o600`. This is enforced in code, not advisory.

On non-Unix platforms, NTFS ACL validation is assumed to be handled externally.

### 2) Memory handling

- Sensitive fields use zeroization (`Zeroize`, `ZeroizeOnDrop`)
- `RootTag` secret storage is fixed-size (`[u8; 32]`), never heap-allocated
- `ProtectedString` and `ProtectedPath` wrap selected config fields with
  redacted `Debug` output and zeroization on drop
- `RootTag` secret is never exposed in `Debug` output or diff results
  (diff compares SHA3-512 hash prefix only)

### 3) Cryptographic derivation

SHA3-512 based derivation hierarchy:

```
root_tag (256-bit secret)
    └── host_tag  = SHA3-512(root_tag || hostname)
            └── artifact_tag = SHA3-512(host_tag || artifact_id)
```

- Tags are domain-separated by hostname and artifact ID
- Rotating the root tag invalidates all derived tags simultaneously
- `hash_eq_ct` uses constant-time comparison for root tag hash equality
- No-allocation derivation paths (`*_bytes`, `*_hex_into`) are available for
  hot-path use

### 4) Validation

`ValidationMode::Standard` (default via `from_file`):

- Format and type validation
- Entropy checks on `RootTag` (see below)
- Range and collection checks
- No filesystem access beyond reading the config file

`ValidationMode::Strict` (via `from_file_with_mode`):

- All Standard checks, plus:
- Existence checks for `deception.decoy_paths` parent directories
- Existence checks for `telemetry.watch_paths` entries
- Existence check and write-access test for `logging.log_path` parent directory
  (attempts to create and remove a temporary `.palisade-write-test` file)

Root tag entropy checks applied on both `RootTag::new` and `RootTag::generate`:

- All-zero rejection
- Unique byte threshold (≥ 25% of bytes must be distinct)
- Sequential pattern detection (> 50% sequential byte runs rejected)
- Repeated-substring detection (first quarter of bytes must not appear in the rest)

### 5) Runtime no-allocation path

`Config::to_runtime()` and `PolicyConfig::to_runtime()` convert loaded models
to fixed-capacity runtime forms backed by `heapless`. Runtime operations on
`RuntimeConfig` and `RuntimePolicy` are designed for zero heap allocation on
the hot path.

Allocation stages (load, deserialize, validation) remain allocation-permitted
by design; the no-allocation guarantee applies only to post-conversion runtime
operations.

### 6) Centralized timing floors

Timing normalization is centralized in `src/timing.rs`. Minimum execution floors
are applied to all security-sensitive operations via `enforce_operation_min_timing`
using spin-wait.

Profiles:

- `Balanced` (default): lower latency, moderate smoothing
- `Hardened`: higher floors, stronger timing smoothing

Operations covered: tag creation, derivation, comparison, config/policy
load/validate/diff, runtime build, suspicious-process checks, and custom
condition checks.

### 7) Custom condition registration

Policy `ResponseRule` entries using `ResponseCondition::Custom` must reference
a name present in `registered_custom_conditions`. Unregistered condition names
are rejected during policy validation to prevent condition injection via
externally-supplied policy files.

## Threats addressed

- Basic memory scraping risk reduction via zeroization
- Config disclosure risk reduction via file permission enforcement
- Cross-artifact correlation resistance through hierarchical tag derivation
- Misconfiguration detection via multi-layer validation
- Coarse timing signal reduction via operation floors
- Condition injection prevention via custom-condition pre-registration

## Known limitations

### 1) Timing floors are not side-channel proof

Floors reduce coarse timing leakage only. They do not eliminate microarchitectural
channels (CPU cache, branch predictor, SMT/hyperthreading effects). The spin-wait
implementation may also be affected by OS scheduling preemption.

### 2) Serialized root tag

`RootTag` serializes as hex to support round-trip TOML load/save. This means
the root secret is present in plaintext in config files on disk. Serialized
config files must be treated as high-sensitivity secrets equivalent to private
key material. See operational recommendations below.

### 3) No-allocation scope is post-conversion only

The no-allocation guarantee applies to `RuntimeConfig` and `RuntimePolicy`
operations. The load, deserialize, and `to_runtime()` conversion stages
allocate by design.

### 4) Entropy checks are heuristic

Checks catch common weak patterns (zeros, sequences, repeating blocks) but are
not a formal randomness proof. Use a CSPRNG (e.g. `openssl rand -hex 32`) for
tag generation. `RootTag::generate()` uses OS RNG (`OsRng`) and validates even
generated entropy as a sanity check.

### 5) OS / platform boundary

Filesystem and host-level hardening are external requirements. Root-level
compromise is out of scope. The crate enforces what it can observe at the
process boundary.

### 6) Non-Unix permission model

On non-Unix platforms, file permission enforcement is not implemented in-crate.
NTFS ACL validation must be handled externally.

## Operational recommendations

### File protection

- Config and policy files must be `chmod 600` (enforced on Unix).
- Do not commit config files containing `root_tag` values to version control.
- Prefer secret delivery via Vault, KMS, or a secrets manager; write the
  resolved config to a tempfile with `O_TMPFILE` or equivalent.

### Key hygiene

- Rotate root tags on incident response, agent lifecycle events, and on a
  regular schedule.
- After rotation, all previously derived artifact tags are invalidated —
  re-derive and re-deploy honeytokens.
- Store root tag backups with the same controls as private key material.

### Runtime mode

- Call `to_runtime()` at startup and operate exclusively on `RuntimeConfig` /
  `RuntimePolicy` in hot paths.
- Avoid using allocation-heavy deserialization APIs in latency-sensitive loops.

### Validation mode

- Use `ValidationMode::Strict` in production deployments where the filesystem
  is known-good.
- Use `ValidationMode::Standard` in CI/testing environments where monitored
  paths may not exist.
- Do not call `validate()` after `from_file()` — validation is already applied
  internally. Calling it again is redundant.

### Timing profile

- Use `TimingProfile::Hardened` in hostile network environments or where the
  crate is exposed to untrusted callers.
- Use `TimingProfile::Balanced` when latency budget is constrained and the
  threat model permits reduced floor margins.

### Build and dependency hygiene

- Use reproducible CI builds.
- Run `cargo audit` and supply-chain auditing on dependency updates.
- Review changes to `timing.rs`, `tags.rs`, and `errors.rs` with extra scrutiny
  — these are the highest-sensitivity modules.

## Hardening roadmap (planned)

- Optional encrypted-at-rest config integration patterns (Vault/KMS transit)
- Additional constant-time verification harnesses
- Expanded static analysis and fuzzing coverage (`cargo-fuzz` targets for
  entropy validation and TOML parsing paths)
- Non-Unix permission enforcement via platform ACL APIs