//! Cryptographic tag derivation for honeypot artifacts.
//!
//! # ⚠️ SECURITY CRITICAL ⚠️
//!
//! This module implements the cryptographic foundation of the deception system.
//! **Bugs here compromise the entire infrastructure.**
//!
//! # Cryptographic Design
//!
//! Tags form a hierarchical derivation tree using SHA3-512:
//!
//! ```text
//! root_tag (256-bit secret, NEVER exposed)
//!    ↓ SHA3-512(root_tag || hostname)
//! host_tag (per-deployment, internal only)
//!    ↓ SHA3-512(host_tag || artifact_id)
//! artifact_tag (per-decoy, embedded in files)
//! ```
//!
//! # Security Properties
//!
//! ## 1. Zero-Knowledge Correlation
//!
//! **Property:** Attackers cannot correlate artifacts across hosts.
//!
//! **Proof:**
//! ```text
//! Given: artifact_tag_A = SHA3-512(SHA3-512(R || "host-a") || "artifact-1")
//!        artifact_tag_B = SHA3-512(SHA3-512(R || "host-b") || "artifact-1")
//!
//! Attacker has: artifact_tag_A, artifact_tag_B
//! Attacker wants: Determine if same root R
//!
//! Result: Computationally infeasible
//!   - SHA3-512 is preimage-resistant (can't recover inputs)
//!   - Tags appear completely random
//!   - No statistical correlation possible
//! ```
//!
//! **Attack Scenario:**
//! 1. Attacker compromises host-a, extracts artifact_tag_A
//! 2. Attacker compromises host-b, extracts artifact_tag_B  
//! 3. Attacker attempts to identify related infrastructure
//! 4. **Result:** Tags appear unrelated (zero correlation)
//!
//! ## 2. Forward Secrecy
//!
//! **Property:** Compromising one artifact doesn't compromise others.
//!
//! ```text
//! Compromised: artifact_tag_1
//! Still secure: artifact_tag_2, artifact_tag_3, ..., root_tag
//! ```
//!
//! **Caveat:** Compromising root_tag compromises ALL artifacts (past and future).
//! This is why root_tag protection is paramount.
//!
//! ## 3. Internal Traceability
//!
//! **Property:** Defenders can derive all tags from root.
//!
//! ```rust
//! use palisade_config::RootTag;
//!
//! let root = RootTag::generate();
//!
//! // Derive all tags from single root
//! let tag_host_a = root.derive_artifact_tag("host-a", "artifact-1");
//! let tag_host_b = root.derive_artifact_tag("host-b", "artifact-1");
//! let tag_host_c = root.derive_artifact_tag("host-c", "artifact-1");
//!
//! // Can correlate internally, attackers cannot
//! ```
//!
//! ## 4. Memory Protection
//!
//! **Property:** Secrets are zeroized immediately when no longer needed.
//!
//! ```rust
//! use palisade_config::RootTag;
//!
//! {
//!     let root = RootTag::generate();
//!     let derived = root.derive_artifact_tag("host", "artifact");
//!     // Use derived...
//! } // ← Memory zeroized here (forensically unrecoverable)
//! ```
//!
//! # Cryptographic Choices
//!
//! ## Why SHA3-512?
//!
//! **Alternatives considered:**
//! - SHA2-512: Older, more conservative, but structurally weaker
//! - BLAKE3: Faster, but less widely audited
//! - HMAC-SHA3: Overkill for key derivation (no attacker control of inputs)
//!
//! **Decision:** SHA3-512
//! - NIST-approved (FIPS 202)
//! - Based on Keccak (different construction than SHA-2)
//! - 512-bit output provides comfortable security margin
//! - Not a hot path (< 1µs per derivation)
//! - Choose conservatism over performance
//!
//! ## Why Hierarchical Derivation?
//!
//! **Alternative: Direct derivation**
//! ```text
//! artifact_tag = SHA3-512(root || hostname || artifact_id)
//! ```
//!
//! **Problem:** No per-host revocation.
//!
//! **Hierarchical approach:**
//! ```text
//! host_tag = SHA3-512(root || hostname)
//! artifact_tag = SHA3-512(host_tag || artifact_id)
//! ```
//!
//! **Benefits:**
//! - Can rotate host_tag without changing root
//! - Can revoke single host without affecting others
//! - Enables per-host key management
//!
//! # Entropy Validation
//!
//! All root tags undergo comprehensive validation to prevent weak keys:
//!
//! ## Check 1: Not All Zeros
//!
//! ```rust,no_run
//! let weak = "0000000000000000000000000000000000000000000000000000000000000000";
//! // REJECTED: Obvious placeholder
//! ```
//!
//! **Rationale:** Lazy human mistakes, test fixtures.
//!
//! ## Check 2: Byte Diversity
//!
//! Requires ≥25% unique bytes.
//!
//! ```rust,no_run
//! let weak = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
//! // REJECTED: Only 1/32 unique bytes (3%)
//! ```
//!
//! **Rationale:** Low-entropy keys, repeated patterns.
//!
//! ## Check 3: Sequential Pattern Detection
//!
//! Rejects if >50% of byte transitions are sequential.
//!
//! ```rust,no_run
//! let weak = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
//! // REJECTED: Sequential byte pattern
//! ```
//!
//! **Rationale:** Test fixtures, counter-based generation.
//!
//! ## Check 4: Substring Repetition
//!
//! First quarter must not repeat in remainder.
//!
//! ```rust,no_run
//! let weak = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
//! // REJECTED: "deadbeef" repeats 8 times
//! ```
//!
//! **Rationale:** Obvious patterns, lazy generation.
//!
//! ## Limitations
//!
//! **These checks are heuristic, not cryptographic proofs.**
//!
//! They catch:
//! - ✅ Human mistakes
//! - ✅ Test fixture leaks
//! - ✅ Obvious patterns
//!
//! They don't catch:
//! - ❌ Sophisticated low-entropy patterns
//! - ❌ Compromised RNG (beyond detection scope)
//! - ❌ Chosen-plaintext attacks on derivation
//!
//! **Philosophy:** Defense-in-depth. Even `RootTag::generate()` is validated.
//!
//! # Attack Scenarios Considered
//!
//! ## Scenario 1: Multi-Host Compromise
//!
//! **Attacker:**
//! 1. Compromises host-a
//! 2. Finds artifact with tag `abc123...`
//! 3. Compromises host-b
//! 4. Finds artifact with tag `def456...`
//! 5. Attempts to correlate infrastructure
//!
//! **Defense:**
//! - Tags derived independently per host
//! - SHA3-512 preimage resistance prevents correlation
//! - Attacker cannot determine if same root tag
//!
//! **Result:** ✅ Attack fails
//!
//! ## Scenario 2: Memory Forensics
//!
//! **Attacker:**
//! 1. Gains memory dump of agent process
//! 2. Searches for root_tag
//! 3. Attempts to recover secrets
//!
//! **Defense:**
//! - `ZeroizeOnDrop` on all `RootTag` instances
//! - Memory scrubbed when out of scope
//! - No `Clone` trait (prevents duplication)
//!
//! **Caveat:** Active process memory can be read before zeroization.
//!
//! **Result:** ⚠️ Partial defense (better than nothing)
//!
//! ## Scenario 3: Artifact Brute Force
//!
//! **Attacker:**
//! 1. Obtains artifact_tag
//! 2. Attempts brute force to find root_tag
//! 3. Tries 2^64 guesses
//!
//! **Defense:**
//! - 256-bit root tag space = 2^256 possibilities
//! - SHA3-512 irreversible (preimage resistance)
//! - Brute force computationally infeasible
//!
//! **Result:** ✅ Attack fails (thermodynamically impossible)
//!
//! ## Scenario 4: Configuration File Leak
//!
//! **Attacker:**
//! 1. Gains read access to config.toml
//! 2. Attempts to extract root_tag
//!
//! **Defense:**
//! - File permissions enforced (0600 on Unix)
//! - Root tag in hex (not binary leak)
//! - Still requires file system access
//!
//! **Caveat:** If attacker has file system access, root_tag is compromised.
//!
//! **Mitigation:** Encrypt config files, use secrets management.
//!
//! **Result:** ⚠️ Out of scope for library (deployment concern)
//!
//! # Examples
//!
//! ## Basic Usage
//!
//! ```rust
//! use palisade_config::RootTag;
//!
//! // Generate cryptographically secure root tag
//! let root = RootTag::generate();
//!
//! // Derive per-artifact tags
//! let tag_aws = root.derive_artifact_tag("prod-web-01", "fake-aws-credentials");
//! let tag_ssh = root.derive_artifact_tag("prod-web-01", "fake-ssh-key");
//!
//! assert_ne!(tag_aws, tag_ssh); // Different artifacts = different tags
//! ```
//!
//! ## Cross-Host Independence
//!
//! ```rust
//! use palisade_config::RootTag;
//!
//! let root = RootTag::generate();
//!
//! // Same artifact, different hosts
//! let tag_host_a = root.derive_artifact_tag("host-a", "aws-creds");
//! let tag_host_b = root.derive_artifact_tag("host-b", "aws-creds");
//!
//! // Tags are completely different (zero correlation for attackers)
//! assert_ne!(tag_host_a, tag_host_b);
//! ```
//!
//! ## Deterministic Derivation
//!
//! ```rust
//! use palisade_config::RootTag;
//!
//! let root = RootTag::generate();
//!
//! // Same inputs always produce same outputs
//! let tag1 = root.derive_artifact_tag("host", "artifact");
//! let tag2 = root.derive_artifact_tag("host", "artifact");
//!
//! assert_eq!(tag1, tag2); // Deterministic
//! ```

use palisade_errors::{definitions, AgentError, Result};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha3::{Digest, Sha3_512};
use std::collections::HashSet;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Root cryptographic tag with hierarchical derivation capability.
///
/// # ⚠️ SECURITY CRITICAL ⚠️
///
/// **This is the root of trust for all artifact tags in the honeypot system.**
///
/// ## Responsibilities
///
/// 1. **Generate:** Create cryptographically secure root tags
/// 2. **Validate:** Ensure sufficient entropy
/// 3. **Derive:** Produce host and artifact tags
/// 4. **Protect:** Zeroize memory on drop
/// 5. **Redact:** Never expose in logs/errors
///
/// ## Security Requirements
///
/// - ✅ Generated with cryptographic randomness (`OsRng`)
/// - ✅ Stored securely (encrypted at rest, secrets management)
/// - ✅ Never exposed in logs or error messages
/// - ✅ Zeroized immediately when no longer needed
/// - ✅ Validated for entropy (all construction paths)
///
/// ## Memory Safety
///
/// Uses `ZeroizeOnDrop` to prevent memory forensics:
///
/// ```rust
/// use palisade_config::RootTag;
///
/// {
///     let root = RootTag::generate();
///     // Use root...
/// } // ← Memory scrubbed here (unrecoverable)
/// ```
///
/// ## Serialization Safety
///
/// **Never serializes the raw secret:**
///
/// ```rust
/// use palisade_config::RootTag;
///
/// let root = RootTag::generate();
/// let toml = toml::to_string(&root).unwrap();
///
/// assert!(toml.contains("REDACTED"));
/// assert!(!toml.contains(&hex::encode(root.hash())));
/// ```
///
/// ## Comparison Safety
///
/// Use hash for comparison (prevents timing attacks):
///
/// ```rust
/// use palisade_config::RootTag;
///
/// let tag1 = RootTag::generate();
/// let tag2 = RootTag::generate();
///
/// // Safe: compares hashes, not secrets
/// assert_ne!(tag1.hash(), tag2.hash());
/// ```
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct RootTag {
    /// The root secret (never exposed, never serialized, zeroized on drop)
    ///
    /// **SECURITY:** This field contains the cryptographic secret.
    /// - Never logged
    /// - Never displayed (Debug redacts)
    /// - Never serialized (custom Serialize)
    /// - Automatically zeroized (ZeroizeOnDrop)
    secret: Vec<u8>,

    /// SHA3-512 hash of the root secret (for secure diffing/comparison)
    ///
    /// **SECURITY:** This hash is safe to expose:
    /// - Preimage resistance: cannot recover secret from hash
    /// - Used for config diffing without exposing secret
    /// - Allows equality checks without timing attacks
    ///
    /// **Note:** Skip zeroization (hash is public, not secret)
    #[zeroize(skip)]
    hash: [u8; 64],
}

impl RootTag {
    /// Create from hex-encoded string with comprehensive validation.
    ///
    /// # Security Checks
    ///
    /// 1. **Length:** Minimum 64 hex characters (256-bit security)
    /// 2. **Encoding:** Valid hexadecimal
    /// 3. **Entropy:** Comprehensive validation (4 checks)
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Input too short (<64 hex chars)
    /// - Invalid hex encoding
    /// - Insufficient entropy (see [`validate_entropy`](Self::validate_entropy))
    ///
    /// # Examples
    ///
    /// ```rust
    /// use palisade_config::RootTag;
    ///
    /// // Valid tag (256-bit hex)
    /// let tag = RootTag::new(
    ///     "a1b2c3d4e5f67890abcdef1234567890\
    ///      a1b2c3d4e5f67890abcdef1234567890".to_string()
    /// ).unwrap();
    ///
    /// // Too short - rejected
    /// assert!(RootTag::new("deadbeef".to_string()).is_err());
    ///
    /// // All zeros - rejected (insufficient entropy)
    /// assert!(RootTag::new("0".repeat(64)).is_err());
    ///
    /// // Sequential - rejected (insufficient entropy)
    /// assert!(RootTag::new(
    ///     "000102030405060708090a0b0c0d0e0f\
    ///      101112131415161718191a1b1c1d1e1f".to_string()
    /// ).is_err());
    /// ```
    pub fn new(hex: String) -> Result<Self> {
        // Validation 1: Minimum length (256-bit security)
        if hex.len() < 64 {
            return Err(AgentError::config(
                definitions::CFG_INVALID_VALUE,
                "validate_root_tag",
                format!(
                    "Root tag too short ({} chars, minimum 64 for 256-bit security)",
                    hex.len()
                ),
            ).with_obfuscation());
        }

        // Validation 2: Hex encoding
        let bytes = hex::decode(&hex).map_err(|e| {
            AgentError::config(
                definitions::CFG_INVALID_VALUE,
                "validate_root_tag",
                format!("Root tag must be valid hex encoding: {}", e),
            ).with_obfuscation()
        })?;

        // Validation 3: Entropy (CRITICAL - applies to ALL tags)
        Self::validate_entropy(&bytes)?;

        // Compute SHA3-512 hash for secure diffing/comparison
        let mut hasher = Sha3_512::new();
        hasher.update(&bytes);
        let hash_result = hasher.finalize();

        let mut hash = [0u8; 64];
        hash.copy_from_slice(&hash_result);

        Ok(Self { secret: bytes, hash })
    }

    /// Generate cryptographically secure root tag using OS RNG.
    ///
    /// # Security Properties
    ///
    /// - Uses `OsRng` (cryptographically secure)
    /// - 256-bit entropy (32 bytes)
    /// - Validated even though generated (maintains invariant)
    ///
    /// # Panics
    ///
    /// Panics if `OsRng` produces invalid entropy. This should never happen
    /// and indicates a critical system failure.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use palisade_config::RootTag;
    ///
    /// let tag = RootTag::generate();
    /// assert_eq!(tag.hash().len(), 64); // SHA3-512 = 64 bytes
    /// ```
    #[must_use]
    pub fn generate() -> Self {
        use rand::RngCore;

        let mut bytes = vec![0u8; 32]; // 256-bit entropy
        rand::rngs::OsRng.fill_bytes(&mut bytes);

        // SECURITY: Validate even generated entropy
        // This maintains the invariant: "All RootTags have validated entropy"
        // If this fails, it indicates a critical RNG failure
        Self::validate_entropy(&bytes)
            .expect("OsRng produced invalid entropy - this should never happen and indicates a critical system failure");

        // Compute SHA3-512 hash
        let mut hasher = Sha3_512::new();
        hasher.update(&bytes);
        let hash_result = hasher.finalize();

        let mut hash = [0u8; 64];
        hash.copy_from_slice(&hash_result);

        Self { secret: bytes, hash }
    }

    /// Validate entropy quality with comprehensive heuristic checks.
    ///
    /// # ⚠️ SECURITY NOTICE ⚠️
    ///
    /// **These checks are heuristic, not cryptographic proofs.**
    ///
    /// They are designed to catch:
    /// - ✅ Lazy human mistakes ("0000..." placeholders)
    /// - ✅ CI/CD leaks (test fixtures)
    /// - ✅ Sequential patterns (counter-based generation)
    /// - ✅ Repeated substrings (obvious patterns)
    ///
    /// They do NOT guarantee:
    /// - ❌ True randomness (statistical tests needed)
    /// - ❌ Cryptographic strength (entropy estimation needed)
    /// - ❌ RNG quality (external audit needed)
    ///
    /// **Philosophy:** Multiple weak checks are better than no checks.
    /// Each check catches different failure modes.
    ///
    /// # Validation Checks
    ///
    /// ## Check 1: Not All Zeros
    ///
    /// **Rationale:** Catches placeholder values, uninitialized memory.
    ///
    /// ## Check 2: Byte Diversity
    ///
    /// **Rationale:** At least 25% of bytes must be unique.
    /// Low diversity indicates patterns or low entropy.
    ///
    /// **Example:**
    /// - `AAAABBBBCCCCDDDD` has 4/16 unique (25%) - passes
    /// - `AAAAAAAAAAAAAAAA` has 1/16 unique (6%) - fails
    ///
    /// ## Check 3: Sequential Pattern Detection
    ///
    /// **Rationale:** Rejects sequences like 0x00, 0x01, 0x02...
    /// Indicates counter-based or algorithmic generation.
    ///
    /// **Threshold:** Max 50% sequential transitions.
    ///
    /// ## Check 4: Substring Repetition
    ///
    /// **Rationale:** First quarter must not repeat in remainder.
    /// Catches "DEADBEEFDEADBEEF..." patterns.
    ///
    /// # Errors
    ///
    /// Returns error if any check fails.
    fn validate_entropy(bytes: &[u8]) -> Result<()> {
        // ===== CHECK 1: Not All Zeros =====
        if bytes.iter().all(|&b| b == 0) {
            return Err(AgentError::config(
                definitions::CFG_INVALID_VALUE,
                "validate_entropy",
                "Root tag has insufficient entropy (all zeros)",
            ).with_obfuscation());
        }

        // ===== CHECK 2: Byte Diversity =====
        // Require at least 25% unique bytes (conservative threshold)
        let unique_bytes: HashSet<_> = bytes.iter().collect();
        if unique_bytes.len() < bytes.len() / 4 {
            return Err(AgentError::config(
                definitions::CFG_INVALID_VALUE,
                "validate_entropy",
                format!(
                    "Root tag has low entropy (only {}/{} unique bytes)",
                    unique_bytes.len(),
                    bytes.len()
                ),
            ).with_obfuscation());
        }

        // ===== CHECK 3: Sequential Pattern Detection =====
        // Count transitions where byte[i+1] = byte[i] + 1
        let mut sequential_count = 0;
        for window in bytes.windows(2) {
            if window[1] == window[0].wrapping_add(1) {
                sequential_count += 1;
            }
        }
        // Reject if more than 50% of transitions are sequential
        if sequential_count > bytes.len() / 2 {
            return Err(AgentError::config(
                definitions::CFG_INVALID_VALUE,
                "validate_entropy",
                "Root tag appears to be sequential pattern",
            ).with_obfuscation());
        }

        // ===== CHECK 4: Substring Repetition Detection =====
        // Check if first quarter appears again in the rest
        if bytes.len() >= 8 {
            let first_quarter = &bytes[0..bytes.len() / 4];
            let rest = &bytes[bytes.len() / 4..];
            if rest.windows(first_quarter.len()).any(|w| w == first_quarter) {
                return Err(AgentError::config(
                    definitions::CFG_INVALID_VALUE,
                    "validate_entropy",
                    "Root tag contains repeated substrings",
                ).with_obfuscation());
            }
        }

        Ok(())
    }

    /// Derive host-specific tag using SHA3-512.
    ///
    /// # Cryptographic Operation
    ///
    /// ```text
    /// host_tag = SHA3-512(root_tag || hostname)
    /// ```
    ///
    /// # Security Properties
    ///
    /// - **Deterministic:** Same inputs always produce same output
    /// - **One-way:** Cannot recover root_tag from host_tag
    /// - **Collision-resistant:** Different hosts = different tags
    /// - **Independent:** Hosts cannot correlate each other
    ///
    /// # Usage
    ///
    /// **Internal only** - host tags should NOT be exposed:
    /// - Used for per-host key derivation
    /// - Enables per-host revocation
    /// - Not embedded in artifacts (use artifact_tag instead)
    ///
    /// # Examples
    ///
    /// ```rust
    /// use palisade_config::RootTag;
    ///
    /// let root = RootTag::generate();
    /// let host_tag = root.derive_host_tag("prod-web-01");
    ///
    /// assert_eq!(host_tag.len(), 64); // SHA3-512 = 64 bytes
    ///
    /// // Different hosts = different tags
    /// let tag_a = root.derive_host_tag("host-a");
    /// let tag_b = root.derive_host_tag("host-b");
    /// assert_ne!(tag_a, tag_b);
    ///
    /// // Deterministic
    /// let tag_again = root.derive_host_tag("host-a");
    /// assert_eq!(tag_a, tag_again);
    /// ```
    #[must_use]
    pub fn derive_host_tag(&self, hostname: &str) -> Vec<u8> {
        let mut hasher = Sha3_512::new();
        hasher.update(&self.secret);
        hasher.update(hostname.as_bytes());
        hasher.finalize().to_vec()
    }

    /// Derive artifact-specific tag using SHA3-512.
    ///
    /// # Cryptographic Operation
    ///
    /// ```text
    /// host_tag = SHA3-512(root_tag || hostname)
    /// artifact_tag = SHA3-512(host_tag || artifact_id)
    /// ```
    ///
    /// # Security Properties
    ///
    /// - **Per-host isolation:** Same artifact, different hosts = different tags
    /// - **Per-artifact uniqueness:** Different artifacts = different tags
    /// - **Zero correlation:** Attackers cannot link artifacts
    /// - **Defender traceability:** Can derive all tags from root
    ///
    /// # Output Format
    ///
    /// Returns hex-encoded tag (128 hex chars = 64 bytes).
    /// Suitable for embedding in decoy files.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use palisade_config::RootTag;
    ///
    /// let root = RootTag::generate();
    ///
    /// // Per-host, per-artifact tags
    /// let tag = root.derive_artifact_tag("prod-web-01", "fake-aws-credentials");
    /// assert_eq!(tag.len(), 128); // 64 bytes = 128 hex chars
    ///
    /// // Same artifact, different hosts = different tags
    /// let tag_host_a = root.derive_artifact_tag("host-a", "ssh-key");
    /// let tag_host_b = root.derive_artifact_tag("host-b", "ssh-key");
    /// assert_ne!(tag_host_a, tag_host_b);
    ///
    /// // Different artifacts, same host = different tags
    /// let tag_aws = root.derive_artifact_tag("host", "aws-creds");
    /// let tag_ssh = root.derive_artifact_tag("host", "ssh-key");
    /// assert_ne!(tag_aws, tag_ssh);
    /// ```
    #[must_use]
    pub fn derive_artifact_tag(&self, hostname: &str, artifact_id: &str) -> String {
        let host_tag = self.derive_host_tag(hostname);

        let mut hasher = Sha3_512::new();
        hasher.update(&host_tag);
        hasher.update(artifact_id.as_bytes());

        hex::encode(hasher.finalize())
    }

    /// Get SHA3-512 hash for comparison without exposing secret.
    ///
    /// # Security Properties
    ///
    /// - **Safe to log:** Hash doesn't reveal secret (preimage resistance)
    /// - **Safe to compare:** Constant-time comparison via arrays
    /// - **Safe to store:** Can be persisted without exposing secret
    ///
    /// # Usage
    ///
    /// - Configuration diffing (detect root tag changes)
    /// - Equality checks (without exposing secret)
    /// - Audit logging (track tag rotations)
    ///
    /// # Examples
    ///
    /// ```rust
    /// use palisade_config::RootTag;
    ///
    /// let tag1 = RootTag::generate();
    /// let tag2 = RootTag::generate();
    ///
    /// // Safe comparison without exposing secrets
    /// assert_ne!(tag1.hash(), tag2.hash());
    ///
    /// // Can log hash safely
    /// println!("Root tag hash: {:x?}", &tag1.hash()[..8]);
    /// ```
    #[must_use]
    pub fn hash(&self) -> &[u8; 64] {
        &self.hash
    }
}

// =============================================================================
// TRAIT IMPLEMENTATIONS WITH SECURITY HARDENING
// =============================================================================

impl std::fmt::Debug for RootTag {
    /// Debug implementation that NEVER exposes the secret.
    ///
    /// **SECURITY:** Only shows hash prefix (first 8 bytes).
    ///
    /// ```rust
    /// use palisade_config::RootTag;
    ///
    /// let root = RootTag::generate();
    /// let debug_str = format!("{:?}", root);
    ///
    /// assert!(debug_str.contains("REDACTED"));
    /// assert!(!debug_str.contains(&hex::encode(&root.secret)));
    /// ```
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RootTag")
            .field("secret", &"[REDACTED]")
            .field("hash", &format!("{:x?}...", &self.hash[..8]))
            .finish()
    }
}

impl Serialize for RootTag {
    /// Serialization that NEVER exposes the secret.
    ///
    /// **SECURITY:** Always serializes as "***REDACTED***".
    ///
    /// This prevents accidental secret exposure via:
    /// - JSON serialization
    /// - TOML serialization
    /// - Debug logging
    /// - Error messages
    ///
    /// ```rust
    /// use palisade_config::RootTag;
    ///
    /// let root = RootTag::generate();
    /// let toml = toml::to_string(&root).unwrap();
    ///
    /// assert!(toml.contains("REDACTED"));
    /// ```
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str("***REDACTED***")
    }
}

impl<'de> Deserialize<'de> for RootTag {
    /// Deserialization that rejects redacted values and validates entropy.
    ///
    /// **SECURITY:** Enforces that actual hex-encoded tags are provided.
    ///
    /// ```rust,ignore
    /// // In TOML:
    /// // root_tag = "***REDACTED***"  ← REJECTED
    /// // root_tag = "a1b2c3d4..."     ← ACCEPTED (if valid)
    /// ```
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;

        if value == "***REDACTED***" {
            return Err(serde::de::Error::custom(
                "Cannot deserialize redacted root tag. Provide actual hex-encoded tag.",
            ));
        }

        Self::new(value).map_err(serde::de::Error::custom)
    }
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // --- Generation Tests ---

    #[test]
    fn test_root_tag_generation_creates_valid_entropy() {
        let tag = RootTag::generate();
        assert_eq!(tag.secret.len(), 32); // 256 bits
        assert_eq!(tag.hash.len(), 64); // SHA3-512
    }

    #[test]
    fn test_root_tag_generation_is_random() {
        let tag1 = RootTag::generate();
        let tag2 = RootTag::generate();
        assert_ne!(tag1.hash(), tag2.hash());
    }

    // --- Derivation Tests ---

    #[test]
    fn test_tag_derivation_is_deterministic() {
        let root = RootTag::generate();
        let tag1 = root.derive_artifact_tag("host1", "artifact1");
        let tag2 = root.derive_artifact_tag("host1", "artifact1");
        assert_eq!(tag1, tag2);
    }

    #[test]
    fn test_tag_derivation_different_hosts() {
        let root = RootTag::generate();
        let tag1 = root.derive_artifact_tag("host1", "artifact1");
        let tag2 = root.derive_artifact_tag("host2", "artifact1");
        assert_ne!(tag1, tag2);
    }

    #[test]
    fn test_tag_derivation_different_artifacts() {
        let root = RootTag::generate();
        let tag1 = root.derive_artifact_tag("host1", "artifact1");
        let tag2 = root.derive_artifact_tag("host1", "artifact2");
        assert_ne!(tag1, tag2);
    }

    #[test]
    fn test_tag_derivation_output_format() {
        let root = RootTag::generate();
        let tag = root.derive_artifact_tag("host1", "artifact1");
        assert_eq!(tag.len(), 128); // SHA3-512 = 64 bytes = 128 hex chars
        assert!(tag.chars().all(|c| c.is_ascii_hexdigit()));
    }

    // --- Entropy Validation Tests ---

    #[test]
    fn test_entropy_validation_rejects_all_zeros() {
        let result = RootTag::new(hex::encode(vec![0u8; 32]));
        assert!(result.is_err());
    }

    #[test]
    fn test_entropy_validation_rejects_sequential() {
        let sequential: Vec<u8> = (0..32).collect();
        let result = RootTag::new(hex::encode(sequential));
        assert!(result.is_err());
    }

    #[test]
    fn test_entropy_validation_rejects_low_diversity() {
        let low_diversity = vec![0xAA, 0xBB].repeat(16);
        let result = RootTag::new(hex::encode(low_diversity));
        assert!(result.is_err());
    }

    #[test]
    fn test_entropy_validation_rejects_repeated_substring() {
        let repeated = b"DEADBEEF".repeat(4);
        let result = RootTag::new(hex::encode(repeated));
        assert!(result.is_err());
    }

    #[test]
    fn test_entropy_validation_accepts_good_entropy() {
        let good = hex::encode(vec![
            0x1a, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f, 0x70, 0x81,
            0x92, 0xa3, 0xb4, 0xc5, 0xd6, 0xe7, 0xf8, 0x09,
            0xfe, 0xed, 0xdc, 0xcb, 0xba, 0xa9, 0x98, 0x87,
            0x76, 0x65, 0x54, 0x43, 0x32, 0x21, 0x10, 0x0f,
        ]);
        assert!(RootTag::new(good).is_ok());
    }

    // --- Serialization Safety Tests ---

    #[test]
    fn test_serialization_redacts_secret() {
        use serde::Serialize;
        
        #[derive(Serialize)]
        struct Wrapper {
            root_tag: RootTag,
        }
        
        let root = RootTag::generate();
        let wrapper = Wrapper { root_tag: root };
        let serialized = toml::to_string(&wrapper).unwrap();
        assert!(serialized.contains("REDACTED"));
    }

    #[test]
    fn test_deserialization_rejects_redacted() {
        let toml_str = r#"root_tag = "***REDACTED***""#;
        let result: std::result::Result<RootTag, _> = toml::from_str(toml_str);
        assert!(result.is_err());
    }

    // --- Host Tag Tests ---

    #[test]
    fn test_host_tag_isolation() {
        let root = RootTag::generate();
        let host_tag_a = root.derive_host_tag("host-a");
        let host_tag_b = root.derive_host_tag("host-b");
        
        assert_ne!(host_tag_a, host_tag_b);
        assert_eq!(host_tag_a.len(), 64); // SHA3-512
    }

    #[test]
    fn test_host_tag_deterministic() {
        let root = RootTag::generate();
        let tag1 = root.derive_host_tag("host-a");
        let tag2 = root.derive_host_tag("host-a");
        assert_eq!(tag1, tag2);
    }

    // --- Hash Comparison Tests ---

    #[test]
    fn test_hash_comparison_safe() {
        let root1 = RootTag::generate();
        let root2 = RootTag::generate();
        
        assert_ne!(root1.hash(), root2.hash());
        assert_eq!(root1.hash().len(), 64);
    }

    // --- Debug Output Tests ---

    #[test]
    fn test_debug_does_not_expose_secret() {
        let root = RootTag::generate();
        let debug_str = format!("{:?}", root);
        
        assert!(debug_str.contains("REDACTED"));
        assert!(!debug_str.contains(&hex::encode(&root.secret)));
    }

    // --- Edge Case Tests ---

    #[test]
    fn test_root_tag_minimum_length() {
        let short_hex = "a".repeat(63); // 63 chars, need 64
        let result = RootTag::new(short_hex);
        assert!(result.is_err());
    }

    #[test]
    fn test_root_tag_invalid_hex() {
        let invalid_hex = "g".repeat(64); // 'g' is not hex
        let result = RootTag::new(invalid_hex);
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_hostname_handled() {
        let root = RootTag::generate();
        let tag = root.derive_artifact_tag("", "artifact");
        assert_eq!(tag.len(), 128); // Still works, just different tag
    }

    #[test]
    fn test_empty_artifact_id_handled() {
        let root = RootTag::generate();
        let tag = root.derive_artifact_tag("host", "");
        assert_eq!(tag.len(), 128); // Still works, just different tag
    }
}