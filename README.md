# Palisade Config

**Security-hardened configuration management for honeypot and deception infrastructure.**

[![Crates.io](https://img.shields.io/crates/v/palisade-config.svg)](https://crates.io/crates/palisade-config)
[![Documentation](https://docs.rs/palisade-config/badge.svg)](https://docs.rs/palisade-config)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

---

## 🔒 Security Notice

**This library handles cryptographic secrets and security-critical configuration.**

Before using in production:

1. Read [`SECURITY.md`](./SECURITY.md) completely
2. Understand the threat model
3. Review your deployment's security posture
4. Establish key rotation procedures
5. Implement audit logging for configuration changes

**This is not a toy—misconfiguration creates attack vectors.**

---

## Overview

Palisade Config provides a battle-tested configuration system for deception infrastructure with a focus on:

- **Memory Safety**: Automatic zeroization of sensitive data
- **Cryptographic Isolation**: Zero-knowledge artifact correlation
- **Fail-Fast Validation**: Invalid configurations never run
- **Config/Policy Separation**: Infrastructure vs decision-making
- **Production-Ready**: Comprehensive error handling and logging

### Design Philosophy

In deception systems, configuration IS security:

| Configuration Issue | Attack Vector                |
| ------------------- | ---------------------------- |
| Config file leaks   | Reveals system architecture  |
| Weak entropy        | Enables artifact correlation |
| Path disclosure     | Information reconnaissance   |
| Threshold tuning    | False negatives/positives    |
| Memory persistence  | Forensic recovery            |

This library treats configuration as a **first-class security boundary**.

---

## Quick Start

### Installation

```toml
[dependencies]
palisade-config = "0.1.0"
palisade-errors = "0.1.0"  # Required for error handling
```

### Basic Usage

```rust
use palisade_config::{Config, PolicyConfig, ValidationMode};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load configuration (infrastructure)
    let config = Config::from_file("/etc/honeypot/config.toml")?;
    config.validate_with_mode(ValidationMode::Strict)?;

    // Load policy (detection logic)
    let policy = PolicyConfig::from_file("/etc/honeypot/policy.toml")?;
    policy.validate()?;

    // Derive cryptographically unique artifact tags
    let hostname = config.hostname();
    let artifact_tag = config.deception.root_tag
        .derive_artifact_tag(&hostname, "fake-aws-credentials");

    println!("Artifact tag: {}", artifact_tag);

    // Check for suspicious processes (zero-allocation hot path)
    if policy.is_suspicious_process("mimikatz.exe") {
        println!("THREAT DETECTED!");
    }

    Ok(())
}
```

### Example Configuration

**config.toml** (infrastructure):

```toml
version = 1

[agent]
instance_id = "honeypot-prod-web-01"
work_dir = "/var/lib/palisade-agent"
environment = "production"

[deception]
root_tag = "a1b2c3d4e5f67890abcdef1234567890a1b2c3d4e5f67890abcdef1234567890"
decoy_paths = [
    "/home/admin/.aws/credentials",
    "/opt/secrets/database.key"
]
credential_types = ["aws", "ssh", "gcp"]
honeytoken_count = 10
artifact_permissions = 0o600

[telemetry]
watch_paths = ["/home", "/opt"]
event_buffer_size = 50000
enable_syscall_monitor = false

[logging]
log_path = "/var/log/palisade-agent/agent.log"
format = "json"
level = "INFO"
```

**policy.toml** (detection logic):

```toml
version = 1

[scoring]
correlation_window_secs = 300
alert_threshold = 60.0
enable_time_scoring = true

[scoring.weights]
artifact_access = 50.0
suspicious_process = 35.0
rapid_enumeration = 25.0

[response]
cooldown_secs = 60
dry_run = false

[[response.rules]]
severity = "Critical"
action = "isolate_host"
conditions = [
    { type = "min_confidence", threshold = 85.0 },
    { type = "min_signal_types", count = 3 }
]

[deception]
suspicious_processes = ["mimikatz", "procdump", "lazagne"]
```

---

## Core Concepts

### 1. Configuration vs Policy

Palisade enforces a strict separation:

```
┌─────────────────────────────────────────┐
│         Configuration (Cold)             │
│  ‣ Infrastructure: paths, buffers       │
│  ‣ Capabilities: what can run           │
│  ‣ Requires deployment to change        │
│  ‣ Versioned with application           │
└─────────────────────────────────────────┘
              ↓
┌─────────────────────────────────────────┐
│            Policy (Hot)                  │
│  ‣ Decision logic: thresholds, rules    │
│  ‣ Detection patterns: signatures       │
│  ‣ Hot-reloadable without restart       │
│  ‣ Independently versioned              │
└─────────────────────────────────────────┘
```

**Why this matters:**

- Security teams can tune detection without DevOps involvement
- Policy mistakes don't require redeployment
- Different environments (dev/staging/prod) can share infrastructure config but have different policies

### 2. Cryptographic Tag Hierarchy

Artifacts are tagged using a secure derivation hierarchy:

```
root_tag (256-bit secret, never exposed)
    ↓ SHA3-512(root_tag || hostname)
host_tag (per-deployment, internal only)
    ↓ SHA3-512(host_tag || artifact_id)
artifact_tag (per-decoy, embedded in files)
```

**Security Properties:**

- ✅ Attackers **cannot** correlate artifacts across hosts
- ✅ Defenders **can** derive all tags from root
- ✅ Compromising one artifact ≠ compromising all
- ✅ Per-artifact revocation possible

**Example:**

```rust
let root = RootTag::generate();

// Different hosts get different tags for same artifact
let tag_host_a = root.derive_artifact_tag("host-a", "ssh-key");
let tag_host_b = root.derive_artifact_tag("host-b", "ssh-key");

assert_ne!(tag_host_a, tag_host_b);  // Zero correlation!
```

### 3. Memory Protection

All sensitive data is protected with `ZeroizeOnDrop`:

```rust
{
    let config = Config::from_file("config.toml")?;
    // Use config...
} // ← Memory zeroized here, forensically unrecoverable
```

**Protected Types:**

- `RootTag`: Cryptographic secrets
- `ProtectedString`: Instance IDs, tokens
- `ProtectedPath`: Work directories, artifact locations

### 4. Validation Modes

```rust
pub enum ValidationMode {
    Standard,  // Format checks, no filesystem I/O
    Strict,    // Paths must exist, permissions verified
}
```

**When to use:**

- **Standard**: CI/CD pipelines, Docker builds (paths don't exist yet)
- **Strict**: Production deployment (catch operational issues)

---

## Architecture

### Module Structure

```
palisade-config/
├── config.rs        # Infrastructure configuration
├── policy.rs        # Detection and response policy
├── tags.rs          # Cryptographic tag derivation
├── validation.rs    # Configuration diffing and validation
├── defaults.rs      # Centralized default values
└── lib.rs           # Public API exports
```

### Security Layers

```
Layer 1: Memory Protection
  ↓ ZeroizeOnDrop on all sensitive fields
  ↓ No Clone trait on secrets

Layer 2: Cryptographic Isolation
  ↓ SHA3-512 tag derivation
  ↓ Per-host, per-artifact uniqueness

Layer 3: Validation
  ↓ Comprehensive format checks
  ↓ Entropy validation
  ↓ Platform-aware security

Layer 4: Error Handling
  ↓ Obfuscated external messages
  ↓ Detailed internal logging
  ↓ Timing normalization
```

---

## Features

### Production-Ready Error Handling

Integration with `palisade-errors` provides:

- **Dual-layer error messages**: Generic externally, detailed internally
- **Structured logging**: JSON with contextual metadata
- **Ring buffer storage**: Last 1000 errors retained for debugging

```rust
// External: "Configuration validation failed"
// Internal: "deception.honeytoken_count must be 1-100, got 250"
```

### Configuration Diffing

Track security-significant changes for audit trails:

```rust
let old = Config::from_file("config.old.toml")?;
let new = Config::from_file("config.new.toml")?;

for change in old.diff(&new) {
    match change {
        ConfigChange::RootTagChanged { old_hash, new_hash } => {
            println!("WARNING: Root tag rotation detected");
        }
        ConfigChange::PathsChanged { added, removed } => {
            println!("Artifact paths modified");
        }
        _ => {}
    }
}
```

### Hot-Reloadable Policies

Tune detection without downtime:

```rust
let mut current_policy = PolicyConfig::from_file("policy.toml")?;

// ... later, reload policy ...
let new_policy = PolicyConfig::from_file("policy.toml")?;

if current_policy.diff(&new_policy).is_empty() {
    println!("No changes detected");
} else {
    current_policy = new_policy;  // Atomic update
    println!("Policy updated");
}
```

### Zero-Allocation Hot Paths

Performance-critical operations avoid heap usage:

```rust
// Single allocation (input conversion), then pure scanning
policy.is_suspicious_process("MIMIKATZ.exe");  // ~48-59ns
```

---

## Security Considerations

### File Permissions

**Configuration files MUST be 0600 (owner-only) on Unix systems.**

The library enforces this:

```rust
// Fails if config file is readable by group/others
Config::from_file("/etc/honeypot/config.toml")?;
```

### Root Tag Management

**The root_tag is the crown jewel of your deception infrastructure.**

Best practices:

1. Generate with `RootTag::generate()` (cryptographically secure RNG)
2. Store in encrypted storage (HashiCorp Vault, AWS Secrets Manager)
3. Never commit to version control
4. Rotate periodically (with artifact redeployment)
5. Audit all access

### Entropy Validation

All root tags undergo comprehensive validation:

1. Not all zeros
2. At least 25% unique bytes
3. No sequential patterns (0x00, 0x01, 0x02...)
4. No repeated substrings

This catches:

- Human mistakes ("00000..." placeholders)
- CI/CD test fixture leaks
- Weak RNG failures

### Platform Security

Unix-specific checks:

- ✅ File permissions (0600 required)
- ✅ Directory ownership validation
- ✅ Capabilities verification

Other platforms:

- ⚠️ Warnings logged (no standardized permission model)

---

## Performance

**Real benchmark results from `cargo bench` on 2010 hardware(Dell Latitude E6410):**

### Configuration Operations

| Operation               | Time      | Details                                  |
| ----------------------- | --------- | ---------------------------------------- |
| Config default creation | 4.18 µs   | Creating default config from scratch     |
| Config validation       | 13.88 ns  | Standard mode validation (format checks) |
| Config diff (identical) | 878.70 ns | Comparing two identical configurations   |
| Config to TOML          | 22.84 µs  | Serializing config to TOML format        |
| Config from TOML        | 34.04 µs  | Deserializing config from TOML           |
| Config load from file   | 49.31 µs  | Full file read + parse + validation      |
| Hostname resolution     | 506.32 ns | Resolving system hostname                |
| Validate standard mode  | 13.79 ns  | Standard validation (no filesystem I/O)  |

### Tag Derivation (Cryptographic Operations)

| Operation            | Time      | Details                                    |
| -------------------- | --------- | ------------------------------------------ |
| Root tag generation  | 2.37 µs   | Generating new 256-bit cryptographic tag   |
| Root tag hash access | 635.37 ps | Accessing cached hash value                |
| Root tag derivation  | 2.68 µs   | Deriving host tag from root tag (SHA3-512) |
| Tag generation       | 2.02 µs   | Full tag generation process                |
| Tag derive host      | 784.52 ns | Deriving host-specific tag                 |
| Tag derive artifact  | 2.68 µs   | Deriving artifact tag (SHA3-512 + hex)     |
| Tag hash access      | 636.76 ps | Accessing cached tag hash                  |
| Tag hash comparison  | 633.87 ps | Comparing two tag hashes (constant-time)   |

### Policy Operations

| Operation                      | Time      | Details                                       |
| ------------------------------ | --------- | --------------------------------------------- |
| Policy default creation        | 169.90 ns | Creating default policy configuration         |
| Policy validation              | 145.88 ns | Validating policy format and constraints      |
| Suspicious process (benign)    | 51.73 ns  | Checking non-malicious process name           |
| Suspicious process (malicious) | 59.69 ns  | Detecting known malicious process (hit)       |
| Suspicious process (mixed)     | 48.59 ns  | Case-insensitive pattern matching             |
| Severity classification (low)  | 633.85 ps | Low severity event classification             |
| Severity classification (med)  | 635.84 ps | Medium severity event classification          |
| Severity classification (high) | 639.57 ps | High severity event classification            |
| Severity classification (crit) | 666.62 ps | Critical severity event classification        |
| Policy diff (identical)        | 545.03 ns | Comparing two identical policy configurations |

### Validation Operations

| Operation         | Time     | Details                                |
| ----------------- | -------- | -------------------------------------- |
| Validate standard | 15.22 ns | Standard validation mode (format only) |
| Validate full     | 15.24 ns | Full validation (all checks enabled)   |

### Performance Notes

- **Cryptographic operations** (tag derivation): ~2-3 µs using SHA3-512
- **Hot path operations** (suspicious process checks): <60 ns with zero heap allocations
- **Memory usage**: Config ~2KB, Policy ~1KB (loaded once, hot-reloadable)
- **Benchmarks measured** on: Standard development hardware with criterion.rs
- **Overhead**: Sub-picosecond for cached hash access and severity classification
- **No regression**: Config diff improved by 3.8%, all other operations stable

**Key Performance Characteristics:**

1. **Configuration loading** is intentionally slower (~49µs) due to comprehensive validation
2. **Tag derivation** uses SHA3-512 (NIST FIPS 202) for security over speed
3. **Suspicious process detection** is highly optimized for runtime use (<60ns)
4. **Policy hot-reload** is extremely fast (<1µs for diff + update)
5. **Zero-allocation hot paths** prevent heap fragmentation in long-running agents

---

## Examples

See the [`examples/`](./examples/) directory:

- `basic_usage.rs` - Loading and validating configuration
- `tag_derivation.rs` - Cryptographic tag hierarchy
- `policy_hot_reload.rs` - Hot-reloading policies
- `comprehensive_validation.rs` - All validation modes
- `production_deployment.rs` - Production-ready setup
- `change_tracking.rs` - Configuration diffing

Run examples:

```bash
cargo run --example basic_usage
cargo run --example tag_derivation
```

---

## Testing

```bash
# Run all tests
cargo test

# Run with output
cargo test -- --nocapture

# Run specific test
cargo test test_root_tag_generation

# Run benchmarks
cargo bench

# Check formatting
cargo fmt --check

# Linting
cargo clippy -- -D warnings
```

---

## API Documentation

Full API documentation available at [docs.rs/palisade-config](https://docs.rs/palisade-config)

Quick links:

- [`Config`](https://docs.rs/palisade-config/latest/palisade_config/struct.Config.html) - Main configuration
- [`PolicyConfig`](https://docs.rs/palisade-config/latest/palisade_config/struct.PolicyConfig.html) - Detection policy
- [`RootTag`](https://docs.rs/palisade-config/latest/palisade_config/struct.RootTag.html) - Cryptographic tags
- [`ValidationMode`](https://docs.rs/palisade-config/latest/palisade_config/enum.ValidationMode.html) - Validation strictness

---

## Security Disclosures

**DO NOT open public issues for security vulnerabilities.**

See [`SECURITY.md`](./SECURITY.md) for responsible disclosure procedures.

---

## Contributing

Contributions welcome! Please ensure:

1. All tests pass (`cargo test`)
2. Code is formatted (`cargo fmt`)
3. No clippy warnings (`cargo clippy`)
4. New features have tests
5. Security implications documented
6. Benchmarks show no performance regressions (`cargo bench`)

---

## License

Licensed under:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))

---

## Acknowledgments

- **SHA3-512**: NIST FIPS 202 (Keccak)
- **Zeroization**: RustCrypto zeroize crate
- **Error handling**: palisade-errors framework
- **Benchmarking**: criterion.rs

---

## Related Projects

- **palisade-agent** - The main honeypot agent
- **palisade-errors** - Comprehensive error handling
- **palisade-telemetry** - Event collection and correlation

---

## Frequently Asked Questions

### Q: Can I use this for non-honeypot applications?

**A:** Yes! The security properties (memory zeroization, cryptographic isolation, comprehensive validation) are valuable for any security-critical configuration system.

### Q: Why SHA3-512 instead of BLAKE3?

**A:** SHA3-512 is NIST-approved (FIPS 202) and more conservative. BLAKE3 is faster but less widely audited. For key derivation (not a hot path at ~2.7µs), we choose conservatism over raw speed.

### Q: How do I rotate root tags?

**A:** Root tag rotation requires:

1. Generate new root tag
2. Re-derive all artifact tags
3. Redeploy all artifacts
4. Update agent configuration
5. Restart agents

This is intentionally manual to prevent accidental rotation.

### Q: Can policies be hot-reloaded?

**A:** Yes! Policies are designed for hot-reloading with <1µs diff operations. Configuration (infrastructure) requires restart.

### Q: What happens if entropy validation fails?

**A:** The library fails fast with an error. You must provide a new root tag with sufficient entropy. This prevents weak secrets from being used.

### Q: Is this library audited?

**A:** Not yet. Community security review welcome. See [`SECURITY.md`](./SECURITY.md).

### Q: Why is configuration loading "slow" at 49µs?

**A:** It's not slow—it's thorough. This includes file I/O, TOML parsing, entropy validation, permission checks, and format validation. For a security-critical operation performed once at startup, correctness trumps speed.

---

**Built with ❤️ and paranoia.**
