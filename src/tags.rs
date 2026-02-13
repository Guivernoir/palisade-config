//! Cryptographic tag derivation for honeypot artifacts.

use crate::errors::EntropyValidationError;
use crate::timing::{enforce_operation_min_timing, TimingOperation};
use palisade_errors::Result;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha3::{Digest, Sha3_512};
use std::time::Instant;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Root cryptographic tag with hierarchical derivation capability.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct RootTag {
    /// The root secret (never exposed, never serialized, zeroized on drop)
    secret: [u8; 32],

    /// SHA3-512 hash of the root secret (for secure diffing/comparison)
    #[zeroize(skip)]
    hash: [u8; 64],
}

impl RootTag {
    /// Create from hex-encoded string with comprehensive validation.
    pub fn new(hex: impl AsRef<str>) -> Result<Self> {
        let started = Instant::now();
        let hex = hex.as_ref();

        let result = (|| {
            // Validation 1: Exact length (256-bit security)
            if hex.len() != 64 {
                return Err(EntropyValidationError::insufficient_length(hex.len(), 64));
            }

            // Validation 2: Hex encoding (decode into stack buffer, no heap allocation)
            let mut bytes = [0u8; 32];
            hex::decode_to_slice(hex, &mut bytes).map_err(EntropyValidationError::invalid_hex)?;

            // Validation 3: Entropy (CRITICAL - applies to ALL tags)
            Self::validate_entropy(&bytes)?;

            // Compute SHA3-512 hash for secure diffing/comparison
            let mut hasher = Sha3_512::new();
            hasher.update(bytes);
            let hash_result = hasher.finalize();

            let mut hash = [0u8; 64];
            hash.copy_from_slice(hash_result.as_slice());

            Ok(Self { secret: bytes, hash })
        })();

        enforce_operation_min_timing(started, TimingOperation::RootTagNew);
        result
    }

    /// Generate cryptographically secure root tag using OS RNG.
    /// 
    /// # Errors
    /// 
    /// Returns error if the OS RNG produces invalid entropy (catastrophic system failure).
    pub fn generate() -> Result<Self> {
        let started = Instant::now();
        use rand::RngCore;

        let mut bytes = [0u8; 32]; // 256-bit entropy
        rand::rngs::OsRng.fill_bytes(&mut bytes);

        // SECURITY: Validate even generated entropy
        // If OsRng produces invalid entropy, this is a critical system failure
        Self::validate_entropy(&bytes)?;

        // Compute SHA3-512 hash
        let mut hasher = Sha3_512::new();
        hasher.update(&bytes);
        let hash_result = hasher.finalize();

        let mut hash = [0u8; 64];
        hash.copy_from_slice(hash_result.as_slice());

        let out = Ok(Self {
            secret: bytes,
            hash,
        });

        enforce_operation_min_timing(started, TimingOperation::RootTagGenerate);
        out
    }

    /// Validate entropy quality with comprehensive heuristic checks.
    fn validate_entropy(bytes: &[u8]) -> Result<()> {
        if bytes.is_empty() {
            return Err(EntropyValidationError::insufficient_length(0, 32));
        }

        // Allocation-free entropy heuristics:
        // - track all-zero input
        // - track unique byte cardinality with a 256-bit bitmap
        // - detect sequential runs
        let mut all_zeros = true;
        let mut unique_bitmap = [0u64; 4];
        let mut unique_count = 0usize;
        let mut sequential_count = 0usize;

        let mut prev = bytes[0];
        for (i, &b) in bytes.iter().enumerate() {
            all_zeros &= b == 0;

            let idx = (b as usize) >> 6;
            let bit = 1u64 << ((b as usize) & 63);
            if (unique_bitmap[idx] & bit) == 0 {
                unique_bitmap[idx] |= bit;
                unique_count += 1;
            }

            if i > 0 && b == prev.wrapping_add(1) {
                sequential_count += 1;
            }
            prev = b;
        }

        if all_zeros {
            return Err(EntropyValidationError::all_zeros());
        }

        // Check 2: Byte Diversity (require at least 25% unique bytes)
        if unique_count < bytes.len() / 4 {
            return Err(EntropyValidationError::low_diversity(
                unique_count,
                bytes.len(),
            ));
        }

        // Check 3: Sequential Pattern Detection
        if sequential_count > bytes.len() / 2 {
            return Err(EntropyValidationError::sequential_pattern());
        }

        // Check 4: Substring Repetition Detection
        if bytes.len() >= 8 {
            let first_quarter = &bytes[0..bytes.len() / 4];
            let rest = &bytes[bytes.len() / 4..];
            if rest.windows(first_quarter.len()).any(|w| w == first_quarter) {
                return Err(EntropyValidationError::repeated_substring());
            }
        }

        Ok(())
    }

    /// Derive host-specific tag bytes using SHA3-512 (no heap allocation).
    #[must_use]
    pub fn derive_host_tag_bytes(&self, hostname: &str) -> [u8; 64] {
        let started = Instant::now();
        let mut hasher = Sha3_512::new();
        hasher.update(&self.secret);
        hasher.update(hostname.as_bytes());

        let digest = hasher.finalize();
        let mut out = [0u8; 64];
        out.copy_from_slice(&digest);
        enforce_operation_min_timing(started, TimingOperation::RootTagDeriveHost);
        out
    }

    /// Derive host-specific tag using SHA3-512.
    #[must_use]
    pub fn derive_host_tag(&self, hostname: &str) -> Vec<u8> {
        self.derive_host_tag_bytes(hostname).to_vec()
    }

    /// Derive artifact-specific tag bytes using SHA3-512 (no heap allocation).
    #[must_use]
    pub fn derive_artifact_tag_bytes(&self, hostname: &str, artifact_id: &str) -> [u8; 64] {
        let started = Instant::now();
        let host_tag = self.derive_host_tag_bytes(hostname);

        let mut hasher = Sha3_512::new();
        hasher.update(host_tag);
        hasher.update(artifact_id.as_bytes());

        let digest = hasher.finalize();
        let mut out = [0u8; 64];
        out.copy_from_slice(&digest);
        enforce_operation_min_timing(started, TimingOperation::RootTagDeriveArtifact);
        out
    }

    /// Derive artifact-specific tag as lowercase hex bytes into caller-provided buffer.
    ///
    /// This method performs no heap allocation.
    pub fn derive_artifact_tag_hex_into(
        &self,
        hostname: &str,
        artifact_id: &str,
        out: &mut [u8; 128],
    ) {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let digest = self.derive_artifact_tag_bytes(hostname, artifact_id);
        for (i, &b) in digest.iter().enumerate() {
            out[i * 2] = HEX[(b >> 4) as usize];
            out[i * 2 + 1] = HEX[(b & 0x0f) as usize];
        }
    }

    /// Derive artifact-specific tag using SHA3-512.
    #[must_use]
    pub fn derive_artifact_tag(&self, hostname: &str, artifact_id: &str) -> String {
        hex::encode(self.derive_artifact_tag_bytes(hostname, artifact_id))
    }

    /// Get SHA3-512 hash for comparison without exposing secret.
    #[must_use]
    pub fn hash(&self) -> &[u8; 64] {
        &self.hash
    }

    /// Constant-time comparison of root tag hashes.
    #[must_use]
    pub fn hash_eq_ct(&self, other: &Self) -> bool {
        let started = Instant::now();
        let eq = ct_eq(self.hash(), other.hash());
        enforce_operation_min_timing(started, TimingOperation::RootTagHashCompare);
        eq
    }
}

#[inline]
fn ct_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }

    let mut diff = 0u8;
    for (&l, &r) in left.iter().zip(right.iter()) {
        diff |= l ^ r;
    }
    diff == 0
}

impl std::fmt::Debug for RootTag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RootTag")
            .field("secret", &"[REDACTED]")
            .field("hash", &format!("{:x?}...", &self.hash[..8]))
            .finish()
    }
}

impl Serialize for RootTag {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(&self.secret))
    }
}

impl<'de> Deserialize<'de> for RootTag {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_root_tag_generation_creates_valid_entropy() {
        let tag = RootTag::generate().expect("Failed to generate tag");
        assert_eq!(tag.secret.len(), 32);
        assert_eq!(tag.hash.len(), 64);
    }

    #[test]
    fn test_root_tag_generation_is_random() {
        let tag1 = RootTag::generate().expect("Failed to generate tag1");
        let tag2 = RootTag::generate().expect("Failed to generate tag2");
        assert_ne!(tag1.hash(), tag2.hash());
    }

    #[test]
    fn test_tag_derivation_is_deterministic() {
        let root = RootTag::generate().expect("Failed to generate root");
        let tag1 = root.derive_artifact_tag("host1", "artifact1");
        let tag2 = root.derive_artifact_tag("host1", "artifact1");
        assert_eq!(tag1, tag2);
    }

    #[test]
    fn test_tag_derivation_different_hosts() {
        let root = RootTag::generate().expect("Failed to generate root");
        let tag1 = root.derive_artifact_tag("host1", "artifact1");
        let tag2 = root.derive_artifact_tag("host2", "artifact1");
        assert_ne!(tag1, tag2);
    }

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
    fn test_debug_does_not_expose_secret() {
        let root = RootTag::generate().expect("Failed to generate root");
        let debug_str = format!("{:?}", root);

        assert!(debug_str.contains("REDACTED"));
        assert!(!debug_str.contains(&hex::encode(&root.secret)));
    }
}
