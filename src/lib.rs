//! # Palisade Config
//!
//! **Security-hardened configuration management for honeypot and deception infrastructure.**
//!
//! # ⚠️  SECURITY CRITICAL ⚠️
//!
//! This library handles:
//! - **Cryptographic secrets** (root tags, derived keys)
//! - **Sensitive infrastructure paths** (decoy locations, work directories)
//! - **Detection policy** (thresholds, response rules)
//! - **System identity** (instance IDs, hostnames)
//!
//! **Misconfiguration creates attack vectors. Read documentation carefully.**
//!
//! # Core Security Properties
//!
//! ## 1. Memory Protection
//!
//! All sensitive data is automatically zeroized on drop:
//!
//! ```rust
//! use palisade_config::Config;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! {
//!     let config = Config::from_file("/etc/honeypot/config.toml")?;
//!     // Use config...
//! } // ← Memory forensically unrecoverable after this point
//! # Ok(())
//! # }
//! ```
//!
//! **Protection against:**
//! - Memory dumps
//! - Core files
//! - Swap space recovery
//! - Debugger inspection (post-drop)
//!
//! **Does NOT protect against:**
//! - Active debugger (pre-drop)
//! - DMA attacks
//! - Hardware attacks
//!
//! ## 2. Cryptographic Isolation
//!
//! Tag derivation prevents artifact correlation:
//!
//! ```text
//! root_tag (256-bit secret)
//!    ↓ SHA3-512(root_tag || hostname)
//! host_tag (per-deployment)
//!    ↓ SHA3-512(host_tag || artifact_id)
//! artifact_tag (embedded in decoys)
//! ```
//!
//! **Security guarantees:**
//! - ✅ Attacker cannot correlate artifacts across hosts
//! - ✅ Compromising one artifact ≠ compromising all
//! - ✅ Defender can derive all tags from root
//! - ✅ Cryptographically provable (SHA3-512 preimage resistance)
//!
//! **Attack scenario this prevents:**
//! ```text
//! 1. Attacker compromises host-a, finds artifact_tag_a
//! 2. Attacker compromises host-b, finds artifact_tag_b
//! 3. Attacker attempts correlation
//! 4. RESULT: Tags appear completely random (no correlation possible)
//! ```
//!
//! ## 3. Validation Defense-in-Depth
//!
//! Multiple validation layers prevent misconfiguration:
//!
//! ```text
//! Layer 1: Format Validation
//!   ↓ Paths absolute, ranges valid, types correct
//!
//! Layer 2: Entropy Validation
//!   ↓ Root tags have sufficient randomness
//!
//! Layer 3: Platform Security
//!   ↓ Unix permissions, directory ownership
//!
//! Layer 4: Semantic Validation
//!   ↓ Business logic constraints, relationships
//! ```
//!
//! **Fail-fast philosophy:** Invalid configurations NEVER run.
//!
//! ## 4. Error Obfuscation
//!
//! Errors are dual-layer:
//!
//! ```rust
//! use palisade_config::Config;
//!
//! # fn main() {
//! let result = Config::from_file("/bad/path.toml");
//!
//! // External (shown to users/attackers):
//! // "Configuration validation failed"
//!
//! // Internal (logged securely):
//! // "deception.root_tag has insufficient entropy (only 8/32 unique bytes)"
//! # }
//! ```
//!
//! **Protection against:** Information disclosure via error messages
//!
//! # Architecture
//!
//! ## Config vs Policy Separation
//!
//! **Configuration (Infrastructure):**
//! - WHERE things run (paths, hosts, instances)
//! - HOW things connect (I/O, logging, telemetry)
//! - WHAT capabilities are enabled
//! - **Requires restart to change**
//! - Versioned with application
//!
//! **Policy (Decision Logic):**
//! - WHEN to alert (thresholds, scoring)
//! - HOW to respond (rules, actions)
//! - WHICH behaviors are suspicious
//! - **Hot-reloadable**
//! - Independently versioned
//!
//! ```text
//! ┌─────────────────────────────────┐
//! │      Config (Cold Path)          │
//! │                                  │
//! │  ‣ Root tag (cryptographic)      │
//! │  ‣ Decoy paths                   │
//! │  ‣ Work directories              │
//! │  ‣ Telemetry scope               │
//! │  ‣ Logging mechanics             │
//! └─────────────────────────────────┘
//!            ↓ Loaded at startup
//! ┌─────────────────────────────────┐
//! │       Policy (Hot Path)          │
//! │                                  │
//! │  ‣ Alert thresholds              │
//! │  ‣ Scoring weights               │
//! │  ‣ Response rules                │
//! │  ‣ Suspicious processes          │
//! └─────────────────────────────────┘
//!            ↓ Hot-reloadable
//! ```
//!
//! **Why this separation matters:**
//! - Security teams can tune detection without DevOps
//! - Policy mistakes don't require redeployment
//! - Different environments (dev/prod) can share infrastructure config
//!
//! # Quick Start
//!
//! ## Basic Usage
//!
//! ```rust,no_run
//! use palisade_config::{Config, PolicyConfig, ValidationMode};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // 1. Load and validate configuration (infrastructure)
//! let config = Config::from_file("/etc/honeypot/config.toml")?;
//! config.validate_with_mode(ValidationMode::Strict)?;
//!
//! // 2. Load and validate policy (detection logic)
//! let policy = PolicyConfig::from_file("/etc/honeypot/policy.toml")?;
//! policy.validate()?;
//!
//! // 3. Derive cryptographically unique artifact tags
//! let hostname = config.hostname();
//! let tag = config.deception.root_tag
//!     .derive_artifact_tag(&hostname, "fake-aws-credentials");
//!
//! // 4. Check for suspicious processes (zero-allocation hot path)
//! if policy.is_suspicious_process("mimikatz.exe") {
//!     println!("THREAT DETECTED!");
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ## Tag Derivation Example
//!
//! ```rust
//! use palisade_config::RootTag;
//!
//! // Generate cryptographically secure root tag
//! let root = RootTag::generate();
//!
//! // Derive per-host tag (internal only, never exposed)
//! let host_tag = root.derive_host_tag("prod-web-01");
//!
//! // Derive per-artifact tag (embedded in decoy files)
//! let artifact_tag = root.derive_artifact_tag("prod-web-01", "fake-aws-creds");
//!
//! // Different hosts = different tags (even for same artifact)
//! let tag_host_a = root.derive_artifact_tag("host-a", "ssh-key");
//! let tag_host_b = root.derive_artifact_tag("host-b", "ssh-key");
//! assert_ne!(tag_host_a, tag_host_b);
//! ```
//!
//! ## Configuration Diffing
//!
//! Track security-significant changes:
//!
//! ```rust,no_run
//! use palisade_config::Config;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let old = Config::from_file("config.old.toml")?;
//! let new = Config::from_file("config.new.toml")?;
//!
//! for change in old.diff(&new) {
//!     println!("Change detected: {:?}", change);
//!     // Log to audit trail, alert security team, etc.
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # Security Considerations
//!
//! ## File Permissions (CRITICAL)
//!
//! **Configuration files MUST be 0600 on Unix:**
//!
//! ```bash
//! # Correct
//! chmod 600 /etc/honeypot/config.toml
//! # -rw------- 1 root root ... config.toml
//!
//! # WRONG - library will reject this
//! chmod 644 /etc/honeypot/config.toml
//! # -rw-r--r-- 1 root root ... config.toml
//! ```
//!
//! **Why:** Group/other read permissions = information disclosure vulnerability.
//! Config files contain root tags, paths, and system architecture.
//!
//! ## Root Tag Management (CRITICAL)
//!
//! The root_tag is the **crown jewel** of your infrastructure:
//!
//! **DO:**
//! - ✅ Generate with `RootTag::generate()` (cryptographically secure RNG)
//! - ✅ Store in encrypted secrets management (Vault, AWS Secrets Manager)
//! - ✅ Rotate periodically (quarterly or after incidents)
//! - ✅ Use different root tags for different environments
//! - ✅ Audit all access
//!
//! **DON'T:**
//! - ❌ Hard-code in source files
//! - ❌ Commit to version control
//! - ❌ Use weak/sequential values ("00000...")
//! - ❌ Share via insecure channels
//! - ❌ Reuse across deployments
//!
//! ## Platform Security
//!
//! **Unix/Linux:**
//! - File permissions checked and enforced
//! - Directory ownership validated
//! - POSIX capabilities verified
//!
//! **Windows:**
//! - Warnings logged (no standardized permission model)
//! - Best-effort security
//! - Consider using ACLs manually
//!
//! **Other Platforms:**
//! - Warnings logged
//! - No enforcement (limitations documented)
//!
//! ## Performance Characteristics
//!
//! Designed for minimal overhead:
//!
//! | Operation | Time | Allocations |
//! |-----------|------|-------------|
//! | Config validation | <10µs | 0 (after load) |
//! | Policy hot-reload | <5µs | 0 |
//! | Tag derivation | <1µs | 1 (output buffer) |
//! | Suspicious process check | <50ns | 1 (lowercase) |
//!
//! Hot paths are zero-allocation after initial setup.
//!
//! # Threat Model
//!
//! ## In Scope
//!
//! The library protects against:
//! - **Memory forensics** (zeroization)
//! - **Artifact correlation** (cryptographic isolation)
//! - **Configuration disclosure** (file permissions, error obfuscation)
//! - **Timing attacks** (normalized via palisade-errors)
//! - **Policy injection** (validation, whitelisting)
//! - **Entropy failures** (comprehensive validation)
//!
//! ## Out of Scope
//!
//! The library does NOT protect against:
//! - **Root privilege escalation** (OS responsibility)
//! - **Supply chain attacks** (cargo audit, reproducible builds)
//! - **Hardware attacks** (DMA, cold boot, EM emanation)
//! - **Side-channel attacks** (power analysis, cache timing)
//! - **Key distribution** (deployment infrastructure responsibility)
//!
//! See [`SECURITY.md`](../SECURITY.md) for complete threat model.
//!
//! # Examples
//!
//! See `examples/` directory:
//! - `basic_usage.rs` - Loading and validating configuration
//! - `tag_derivation.rs` - Cryptographic tag hierarchy
//! - `policy_hot_reload.rs` - Hot-reloading and diffing policies
//! - `comprehensive_validation.rs` - All validation modes
//! - `production_deployment.rs` - Production-ready setup
//!
//! # Dependencies
//!
//! Minimal and carefully chosen:
//! - **sha3** (RustCrypto) - NIST-approved SHA3-512
//! - **zeroize** (RustCrypto) - Memory zeroization
//! - **serde** + **toml** - Configuration serialization
//! - **palisade-errors** - Error handling framework
//! - **rand** (only `OsRng` feature) - Cryptographic RNG
//!
//! **Security audit status:** All dependencies regularly audited via `cargo audit`.
//!
//! # FAQ
//!
//! ## Q: Can I use this for non-honeypot applications?
//!
//! **A:** Yes! The security properties (memory zeroization, cryptographic isolation,
//! comprehensive validation) are valuable for any security-critical configuration.
//!
//! ## Q: Why SHA3-512 instead of BLAKE3?
//!
//! **A:** SHA3-512 is NIST-approved (FIPS 202) and more conservative. BLAKE3 is
//! faster but less widely audited. For key derivation (not a hot path), we choose
//! cryptographic conservatism.
//!
//! ## Q: How do I rotate root tags?
//!
//! **A:** Root tag rotation requires:
//! 1. Generate new root tag
//! 2. Re-derive all artifact tags
//! 3. Redeploy all artifacts
//! 4. Update agent configuration
//! 5. Restart agents
//!
//! This is intentionally manual to prevent accidental rotation.
//!
//! ## Q: Are policies hot-reloadable?
//!
//! **A:** Yes! Policies are designed for hot-reloading. Configuration (infrastructure)
//! requires restart.
//!
//! # Stability Guarantees
//!
//! ## Semantic Versioning
//!
//! This library follows strict semantic versioning:
//! - **Patch** (0.1.x): Bug fixes, no breaking changes
//! - **Minor** (0.x.0): New features, backward compatible
//! - **Major** (x.0.0): Breaking changes, migration guide provided
//!
//! ## Compatibility
//!
//! - **Minimum Rust version:** 1.70.0
//! - **Configuration version:** Checked at load time
//! - **Policy version:** Independent versioning
//!
//! Version mismatches fail fast with clear upgrade instructions.
//!
//! # License
//!
//! Licensed under either of:
//! - Apache License, Version 2.0
//! - MIT License
//!
//! at your option.

#![warn(missing_docs)]
#![warn(clippy::all)]
#![warn(clippy::pedantic)]
#![warn(clippy::unwrap_used)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]

// Core modules
mod config;
mod defaults;
mod policy;
mod tags;
mod validation;

// Re-export core types for public API
pub use config::{
    AgentConfig, Config, DeceptionConfig, LogFormat, LogLevel, LoggingConfig, TelemetryConfig,
    ProtectedPath, ProtectedString,
};
pub use policy::{
    ActionType, DeceptionPolicy, PolicyConfig, ResponseCondition, ResponsePolicy, ResponseRule,
    ScoringPolicy, ScoringWeights, Severity,
};
pub use tags::RootTag;
pub use validation::{ConfigChange, PolicyChange, ValidationMode};

// Re-export from palisade-errors for convenience
pub use palisade_errors::{AgentError, Result};

/// Configuration schema version.
///
/// **CRITICAL: Increment when making breaking changes to configuration format.**
///
/// Agents will **reject** configurations with versions they don't understand,
/// preventing subtle misconfigurations that could create security vulnerabilities.
///
/// # Version History
///
/// - **v1**: Initial release
///   - Root tag derivation
///   - Config/policy separation
///   - Comprehensive validation
///
/// # Upgrade Process
///
/// When incrementing this version:
/// 1. Update this constant
/// 2. Add migration logic in `Config::from_file()`
/// 3. Update documentation
/// 4. Provide upgrade guide
/// 5. Add backward compatibility tests
///
/// **Never decrement this version.** Old agents should fail fast on new configs.
pub const CONFIG_VERSION: u32 = 1;

/// Policy schema version (separate from config).
///
/// **Policies evolve independently from configuration.**
///
/// This separation enables:
/// - Hot-reloading policies without infrastructure changes
/// - Different policy versions across environments
/// - A/B testing detection strategies
/// - Rollback of policy changes
///
/// # Version History
///
/// - **v1**: Initial release
///   - Scoring weights
///   - Response rules
///   - Suspicious process patterns
///
/// # Compatibility
///
/// Old policies CAN run on new agents (backward compatible).
/// New policies CANNOT run on old agents (forward incompatible).
///
/// This is intentional as new policy features should be opt-in.
pub const POLICY_VERSION: u32 = 1;

// SECURITY NOTE: This file deliberately avoids complex logic.
// Core security properties are enforced in individual modules:
//
// - config.rs: Memory protection, validation, file permissions
// - policy.rs: Hot-reloading, custom condition safety
// - tags.rs: Cryptographic derivation, entropy validation
// - validation.rs: Diffing, change tracking
// - defaults.rs: Security-conscious default values
//
// Keep this file minimal to reduce attack surface.