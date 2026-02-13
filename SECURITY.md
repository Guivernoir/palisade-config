# Security Policy

## Scope

`palisade-config` is a security-sensitive crate that handles:

- root cryptographic tag material
- infrastructure and detection policy inputs
- runtime decision-path checks

This document covers current guarantees, limitations, and reporting guidance.

## Supported versions

Security fixes are applied to the latest released version.

## Reporting vulnerabilities

Do not open public issues for vulnerabilities.

Send details to: `strukturaenterprise@gmail.com`

Include:

- affected version
- reproduction steps
- impact assessment
- suggested fix (if available)

## Current security model

### 1) Memory handling

- Sensitive fields use zeroization (`Zeroize`, `ZeroizeOnDrop`)
- `RootTag` secret storage is fixed-size (`[u8; 32]`)
- Protected wrappers are used for selected config fields

### 2) Cryptographic derivation

- SHA3-512 based derivation hierarchy:
  - host tag from root + hostname
  - artifact tag from host tag + artifact id
- Constant-time hash equality is used for root-tag hash comparison

### 3) Validation

- Config and policy are validated before runtime use
- Root tag entropy checks include:
  - all-zero rejection
  - uniqueness threshold
  - sequential-pattern detection
  - repeated-substring detection

### 4) Runtime no-allocation path

- `Config::to_runtime()` and `PolicyConfig::to_runtime()` convert loaded models to fixed-capacity runtime forms (`heapless`)
- Runtime operations on these types are designed for no heap allocation

### 5) Centralized timing floors

- Timing normalization is centralized in `src/timing.rs`
- Profiles:
  - `Balanced` (default)
  - `Hardened`
- Floors are applied across tag/config/policy/runtime operations

## Threats addressed

- Basic memory scraping risk reduction via zeroization
- Cross-artifact correlation resistance through derivation
- Misconfiguration detection via validation
- Coarse timing signal reduction via operation floors

## Known limitations

1. Timing floors are not a full side-channel proof
- They reduce coarse timing leakage only.
- They do not eliminate microarchitectural channels (cache, branch predictor, SMT effects).

2. Serialized root-tag secret
- `RootTag` currently serializes as hex to support round-trip load/save.
- Serialized config files must be treated as high-sensitivity secrets.

3. Runtime no-allocation scope
- No-allocation guarantees apply to runtime types and APIs.
- Load/deserialize stages may allocate by design.

4. Entropy checks are heuristic
- They catch common weak patterns but are not a formal randomness proof.

5. OS / platform boundary
- Filesystem and host-level hardening remain external requirements.
- Root-level compromise is out of scope.

## Operational recommendations

1. File protection
- Restrict config/policy files to least privilege.
- Avoid committing secrets in plaintext repos.

2. Key hygiene
- Rotate root tags on incident response and lifecycle events.
- Prefer secure secret delivery (Vault/KMS/SM).

3. Runtime mode
- Convert to runtime no-alloc types at startup.
- Avoid using allocation-heavy compatibility APIs in hot paths.

4. Timing profile
- Use `TimingProfile::Hardened` for hostile environments.
- Use `Balanced` when latency budget is tight and threat model permits.

5. Build and dependency hygiene
- Use reproducible CI checks.
- Run dependency and supply-chain auditing.

## Hardening roadmap (planned)

- Optional encrypted-at-rest config integration patterns
- Additional constant-time verification harnesses
- Expanded static analysis and fuzzing coverage
