# Security Policy

## Overview

Palisade Config is a **security-critical library** that handles cryptographic secrets, deception infrastructure configuration, and detection policy. This document describes:

1. The threat model
2. Security architecture and properties
3. Known limitations and caveats
4. Vulnerability disclosure procedures
5. Security best practices

**If you discover a security vulnerability, DO NOT open a public issue. See [Reporting Vulnerabilities](#reporting-vulnerabilities).**

---

## Threat Model

### In Scope

The library is designed to protect against:

#### 1. Memory Forensics Attacks

**Threat**: Attacker gains read access to process memory (core dump, swap, debugger)

**Mitigation**:

- All sensitive data wrapped in `ZeroizeOnDrop`
- Secrets zeroized immediately when no longer needed
- No secret data in Debug output

**Residual Risk**: Secrets may briefly exist on stack before zeroization

#### 2. Artifact Correlation Attacks

**Threat**: Attacker compromises multiple artifacts and attempts to correlate them to map infrastructure

**Mitigation**:

- Cryptographic tag derivation using SHA3-512
- Per-host, per-artifact unique tags
- Zero-knowledge property: tags reveal nothing about other artifacts

**Residual Risk**: None (cryptographically guaranteed)

#### 3. Configuration Disclosure

**Threat**: Configuration files leak system architecture, paths, capabilities

**Mitigation**:

- File permission validation (Unix 0600 required)
- No secrets in serialized output (redacted)
- Error messages obfuscated externally

**Residual Risk**: If attacker gains root access, mitigations are bypassed

#### 4. Timing Side-Channel Attacks

**Threat**: Timing variations reveal information about secret values

**Mitigation**:

- Timing normalization via palisade-errors
- No secret-dependent branching in hot paths
- Constant-time comparisons for sensitive operations

**Residual Risk**: CPU cache timing attacks (out of scope)

#### 5. Policy Injection Attacks

**Threat**: Malicious policy configuration enables privilege escalation or detection bypass

**Mitigation**:

- Custom conditions must be pre-registered (whitelist)
- Validation rejects unregistered condition names
- Parameter value constraints

**Residual Risk**: If attacker can write config files, they already have significant access

#### 6. Entropy-Related Failures

**Threat**: Weak root tags enable brute-force or correlation attacks

**Mitigation**:

- Comprehensive entropy validation (4 checks)
- Rejects sequential, repeated, or low-diversity patterns
- Even generated tags are validated (maintains invariant)

**Residual Risk**: Entropy checks are heuristic, not cryptographically provable

### Out of Scope

The library does **NOT** protect against:

#### 1. Root Privilege Escalation

If attacker gains root, they can:

- Read any file regardless of permissions
- Modify memory of running processes
- Bypass all OS-level protections

**Mitigation**: OS hardening, mandatory access control (SELinux/AppArmor)

#### 2. Supply Chain Attacks

Compromised dependencies or build toolchain

**Mitigation**:

- Minimal dependencies (only RustCrypto, serde, palisade-errors)
- Cargo audit checks
- Reproducible builds (future)

#### 3. Hardware Attacks

Physical memory access, DMA attacks, cold boot attacks

**Mitigation**: Hardware security modules (HSM), TPM, encrypted RAM (not implemented)

#### 4. Side-Channel Attacks on Cryptographic Operations

Power analysis, electromagnetic emanation, acoustic attacks

**Mitigation**: None (requires hardware countermeasures)

#### 5. Key Distribution

How root tags are securely distributed to agents

**Mitigation**: Out of scope—handled by deployment infrastructure (Vault, Secrets Manager, etc.)

---

## Security Architecture

### Defense-in-Depth Layers

```
┌──────────────────────────────────────────────────────────┐
│ Layer 1: Type System Enforcement                         │
│  ‣ No Clone on sensitive types (compile-time guarantee)  │
│  ‣ Explicit ownership transfer (borrow checker)          │
│  ‣ No implicit copies (no Copy trait)                    │
└──────────────────────────────────────────────────────────┘
                        ↓
┌──────────────────────────────────────────────────────────┐
│ Layer 2: Memory Protection                               │
│  ‣ ZeroizeOnDrop on RootTag, ProtectedString, etc.       │
│  ‣ Automatic cleanup on scope exit                       │
│  ‣ #[zeroize(skip)] on non-sensitive fields              │
└──────────────────────────────────────────────────────────┘
                        ↓
┌──────────────────────────────────────────────────────────┐
│ Layer 3: Cryptographic Isolation                         │
│  ‣ SHA3-512 tag derivation (NIST FIPS 202)               │
│  ‣ Hierarchical key derivation (no correlation)          │
│  ‣ One-way transformation (irreversible)                 │
└──────────────────────────────────────────────────────────┘
                        ↓
┌──────────────────────────────────────────────────────────┐
│ Layer 4: Input Validation                                │
│  ‣ Comprehensive entropy checks                          │
│  ‣ Format validation (paths, ranges)                     │
│  ‣ Platform-aware security (Unix permissions)            │
└──────────────────────────────────────────────────────────┘
                        ↓
┌──────────────────────────────────────────────────────────┐
│ Layer 5: Error Handling                                  │
│  ‣ Obfuscated external messages                          │
│  ‣ Detailed internal logging                             │
│  ‣ Timing normalization                                  │
└──────────────────────────────────────────────────────────┘
```

### Memory Safety Properties

#### Automatic Zeroization

```rust
{
    let root = RootTag::generate();
    let derived = root.derive_artifact_tag("host", "artifact");
    // Use derived...
} // ← All memory zeroized here
```

**Verification**: Manual inspection + ZeroizeOnDrop guarantees

#### No Cloning

```rust
let root = RootTag::generate();
let cloned = root.clone();  // ❌ Compile error: Clone not implemented
```

**Rationale**: Prevents accidental duplication of secrets

#### Explicit Ownership

```rust
fn takes_ownership(config: Config) { /* ... */ }
fn borrows_config(config: &Config) { /* ... */ }

let config = Config::from_file("config.toml")?;
takes_ownership(config);
// config no longer accessible—moved
```

**Benefit**: Rust compiler enforces single ownership

### Cryptographic Properties

#### Tag Non-Correlation

Given:

```
root_tag = R
artifact_tag_A = SHA3-512(SHA3-512(R || "host-a") || "artifact-1")
artifact_tag_B = SHA3-512(SHA3-512(R || "host-b") || "artifact-1")
```

An attacker with `artifact_tag_A` and `artifact_tag_B` **cannot**:

- Determine if they share the same root tag R
- Derive any other artifact tags
- Recover the root tag R

**Proof**: SHA3-512 is collision-resistant and preimage-resistant (NIST FIPS 202)

#### Forward Secrecy

Compromise of `artifact_tag_N` does **NOT** compromise:

- The root tag R
- Any other artifact tags
- Future artifact tags

**Limitation**: Compromising root tag R compromises all past and future artifacts

### Validation Security

#### Entropy Checks

Four independent checks:

1. **All-zeros**: Rejects `00000...`
2. **Diversity**: Requires ≥25% unique bytes
3. **Sequential**: Rejects `0x00, 0x01, 0x02...`
4. **Repetition**: Rejects repeated substrings

**Example: Weak inputs rejected**

```
❌ "0000000000000000000000000000000000000000000000000000000000000000"
❌ "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
❌ "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
✅ "a1b2c3d4e5f67890abcdef1234567890a1b2c3d4e5f67890abcdef1234567890"
```

**Caveat**: These are heuristics, not cryptographic proofs. They catch human mistakes and test fixtures, but cannot guarantee true randomness.

#### Platform-Aware Security

**On Unix:**

```rust
// Configuration file MUST be 0600 (owner read/write only)
// Group/other read = validation failure
Config::from_file("/etc/config.toml")?;  // Checks permissions
```

**On Windows:**

```rust
// Warning logged, but validation passes
// No standardized permission model
```

**On Other Platforms:**

```rust
// Warning logged, validation passes
// Best-effort security
```

---

## Known Limitations

### 1. Memory Zeroization Timing

**Issue**: Secrets briefly exist on the stack before zeroization occurs.

**Attack Scenario**: Memory corruption bug allows reading uninitialized stack memory.

**Mitigation**:

- Minimize secret lifetime
- Use stack guards (future)
- Encrypted RAM (hardware-dependent)

**Residual Risk**: Low (requires memory corruption exploit)

### 2. Debug Output

**Issue**: If `Debug` is accidentally used on sensitive types, secrets may leak to logs.

**Mitigation**:

- Custom `Debug` implementations that redact secrets
- Compile-time warnings if Debug is derived on protected types (future)

**Residual Risk**: Developer error

### 3. Serialization

**Issue**: Serialization could expose secrets if not carefully controlled.

**Current Protection**:

- `RootTag` serializes as `"***REDACTED***"`
- Protected types use `#[serde(skip)]` or custom serialization
- Manual testing verifies no secret leakage

**Residual Risk**: Refactoring could accidentally break serialization safety

### 4. Entropy Validation Bypasses

**Issue**: Determined attacker could craft input that passes validation but has predictable structure.

**Example**: `entropy_check_bypass_pattern` designed to fool specific heuristics

**Mitigation**:

- Multiple independent checks
- Conservative thresholds
- Regular review of validation logic

**Residual Risk**: Medium (heuristics are not proofs)

### 5. Policy Injection

**Issue**: If custom conditions aren't properly validated, malicious policies could execute arbitrary logic.

**Current Protection**:

- Custom conditions must be pre-registered
- Only registered names accepted
- Parameter validation (length limits, format checks)

**Caveat**: Assumes custom condition implementations themselves are safe

**Residual Risk**: Low (requires write access to policy files)

---

## Security Best Practices

### For Library Users

#### 1. Root Tag Management

**DO**:

- ✅ Generate with `RootTag::generate()` (cryptographically secure)
- ✅ Store in encrypted secrets management (Vault, AWS Secrets Manager)
- ✅ Rotate periodically (quarterly or after incidents)
- ✅ Use different root tags for different environments (dev/staging/prod)
- ✅ Audit all access to root tags

**DON'T**:

- ❌ Hard-code in source files
- ❌ Commit to version control
- ❌ Use sequential or patterned values
- ❌ Reuse across unrelated deployments
- ❌ Share via insecure channels (email, Slack)

#### 2. Configuration File Security

**DO**:

- ✅ Set permissions to 0600 on Unix (owner read/write only)
- ✅ Store in secure locations (`/etc`, not `/tmp`)
- ✅ Encrypt at rest (dm-crypt, LUKS)
- ✅ Audit access (auditd, osquery)
- ✅ Version control (Git) with secret redaction

**DON'T**:

- ❌ Make world-readable
- ❌ Store in user home directories
- ❌ Include in container images unencrypted
- ❌ Share via public file shares

#### 3. Validation

**DO**:

- ✅ Use `ValidationMode::Strict` in production
- ✅ Use `ValidationMode::Standard` in CI/CD
- ✅ Fail fast on validation errors (don't ignore)
- ✅ Log validation failures for audit

**DON'T**:

- ❌ Skip validation in production
- ❌ Silently ignore validation errors
- ❌ Downgrade from Strict to Standard in production

#### 4. Policy Management

**DO**:

- ✅ Version control policies (Git)
- ✅ Review policy changes (code review)
- ✅ Test policy changes in staging first
- ✅ Use configuration diffing to track changes
- ✅ Maintain audit log of policy updates

**DON'T**:

- ❌ Hot-reload policies without testing
- ❌ Allow arbitrary policy injection
- ❌ Register custom conditions without review

#### 5. Error Handling

**DO**:

- ✅ Log internal error details securely
- ✅ Show generic errors to external users
- ✅ Monitor error patterns (potential attacks)
- ✅ Use structured logging (JSON)

**DON'T**:

- ❌ Expose internal errors externally
- ❌ Log secrets in error messages
- ❌ Ignore error patterns

### For Library Developers

#### 1. Adding New Fields

When adding sensitive fields:

```rust
#[derive(ZeroizeOnDrop)]
pub struct NewSensitiveType {
    secret: Vec<u8>,

    #[zeroize(skip)]  // Only if truly non-sensitive
    public_data: String,
}
```

**Checklist**:

- [ ] Wrapped in `ZeroizeOnDrop`
- [ ] No `Clone` trait
- [ ] Custom `Debug` that redacts secrets
- [ ] Custom serialization that prevents leaks
- [ ] Tests verify zeroization
- [ ] Documentation explains sensitivity

#### 2. Validation Logic

When adding validation:

```rust
fn validate_new_field(&self) -> Result<()> {
    if self.field.is_invalid() {
        return Err(AgentError::config(
            definitions::CFG_INVALID_VALUE,
            "validate_new_field",
            "Generic error message",  // ← External
        )
        .with_metadata("field", "new_field")  // ← Internal
        .with_metadata("value", self.field.to_string())  // ← Internal
        .with_obfuscation());  // ← CRITICAL: Obfuscate external message
    }
    Ok(())
}
```

**Checklist**:

- [ ] External error message is generic
- [ ] Internal metadata has details
- [ ] `.with_obfuscation()` called
- [ ] No secrets in error messages
- [ ] Tests cover invalid inputs

#### 3. Cryptographic Operations

When adding crypto:

```rust
use sha3::{Digest, Sha3_512};

fn new_derivation(&self, input: &[u8]) -> Vec<u8> {
    let mut hasher = Sha3_512::new();
    hasher.update(&self.secret);  // ← Sensitive input
    hasher.update(input);
    hasher.finalize().to_vec()
}
```

**Checklist**:

- [ ] Use NIST-approved algorithms (SHA3, not SHA1)
- [ ] No custom crypto implementations
- [ ] Constant-time operations where applicable
- [ ] Zeroize intermediate buffers
- [ ] Tests verify security properties

---

## Vulnerability Disclosure

### Reporting Vulnerabilities

**DO NOT open public issues for security vulnerabilities.**

Instead:

1. **Email**: strukturaenterprise@gmail.com
2. **Include**:
   - Vulnerability description
   - Affected versions
   - Proof of concept (if possible)
   - Suggested mitigation

### What to Expect

- **24 hours**: Initial acknowledgment
- **7 days**: Initial assessment (severity, impact)
- **30 days**: Fix or mitigation plan
- **90 days**: Public disclosure (coordinated)

### Severity Guidelines

| Severity     | Impact                      | Examples                               |
| ------------ | --------------------------- | -------------------------------------- |
| **Critical** | Full system compromise      | RCE, authentication bypass             |
| **High**     | Significant security impact | Secret disclosure, correlation attacks |
| **Medium**   | Limited security impact     | DoS, timing side-channels              |
| **Low**      | Minimal security impact     | Information disclosure (non-secret)    |

### Security Advisories

Published at:

- [GitHub Security Advisories](https://github.com/palisade-project/palisade-config/security/advisories)
- [RustSec Advisory Database](https://rustsec.org/)

---

## Security Testing

### Automated Checks

```bash
# Dependency audit
cargo audit

# Linting (includes security checks)
cargo clippy -- -D warnings -D clippy::unwrap_used

# Tests
cargo test --all-features

# Memory sanitizer (requires nightly)
cargo +nightly test -Z build-std --target x86_64-unknown-linux-gnu
```

### Manual Security Review

Checklist:

- [ ] All sensitive fields have `ZeroizeOnDrop`
- [ ] No `Clone` on sensitive types
- [ ] Custom `Debug` implementations redact secrets
- [ ] Serialization doesn't leak secrets
- [ ] Validation uses `.with_obfuscation()`
- [ ] No secrets in error messages (external)
- [ ] Platform-specific security checks present
- [ ] Entropy validation covers all paths
- [ ] Tests verify security properties

### Fuzzing

```bash
# Install cargo-fuzz
cargo install cargo-fuzz

# Fuzz configuration parsing
cargo +nightly fuzz run config_parser

# Fuzz tag derivation
cargo +nightly fuzz run tag_derivation

# Fuzz validation
cargo +nightly fuzz run validation
```

---

## Audit History

| Date    | Auditor  | Scope                | Findings             | Status   |
| ------- | -------- | -------------------- | -------------------- | -------- |
| 2026-01 | Internal | Full codebase        | 0 critical, 2 medium | Resolved |
| TBD     | External | Cryptographic design | Pending              | -        |

**Note**: No external security audit has been performed yet. Community review is welcome.

---

## Security Updates

Subscribe to security notifications:

- GitHub: Watch repository → Custom → Security alerts
- Email: strukturaenterprise@gmail.com
- RSS: https://github.com/Guivernoir/palisade-config/security/advisories.atom

---

## References

### Standards and Specifications

- [NIST FIPS 202](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf) - SHA-3 Standard
- [RFC 5869](https://tools.ietf.org/html/rfc5869) - HMAC-based Key Derivation
- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)

### Rust Security

- [RustSec Advisory Database](https://rustsec.org/)
- [Rust Secure Code Working Group](https://www.rust-lang.org/governance/wgs/wg-secure-code)
- [Memory Safety in Rust](https://doc.rust-lang.org/nomicon/)

### Honeypot Security

- [The Honeynet Project](https://www.honeynet.org/)
- [SANS: Deploying and Using Honeypots](https://www.sans.org/reading-room/whitepapers/detection/deploying-honeypots-33729)

---

## License

This security policy is licensed under CC BY 4.0.

---

**Last Updated**: January 11th, 2026
**Document Version**: 0.1.0

---

**Questions?** Contact strukturaenterprise@gmail.com
