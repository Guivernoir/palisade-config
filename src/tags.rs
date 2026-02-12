//! Cryptographic tag derivation for honeypot artifacts.

use crate::errors::EntropyValidationError;
use palisade_errors::Result;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha3::{Digest, Sha3_512};
use std::collections::HashSet;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Root cryptographic tag with hierarchical derivation capability.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct RootTag {
    /// The root secret (never exposed, never serialized, zeroized on drop)
    secret: Vec<u8>,

    /// SHA3-512 hash of the root secret (for secure diffing/comparison)
    #[zeroize(skip)]
    hash: [u8; 64],
}

impl RootTag {
    /// Create from hex-encoded string with comprehensive validation.
    pub fn new(hex: String) -> Result<Self> {
        // Validation 1: Minimum length (256-bit security)
        if hex.len() < 64 {
            return Err(EntropyValidationError::insufficient_length(hex.len(), 64));
        }

        // Validation 2: Hex encoding
        let bytes: Vec<u8> = hex::decode(&hex)
            .map_err(EntropyValidationError::invalid_hex)?;

        // Validation 3: Entropy (CRITICAL - applies to ALL tags)
        Self::validate_entropy(&bytes)?;

        // Compute SHA3-512 hash for secure diffing/comparison
        let mut hasher = Sha3_512::new();
        hasher.update(&bytes);
        let hash_result = hasher.finalize();

        let mut hash = [0u8; 64];
        hash.copy_from_slice(hash_result.as_slice());

        Ok(Self { secret: bytes, hash })
    }

    /// Generate cryptographically secure root tag using OS RNG.
    /// 
    /// # Errors
    /// 
    /// Returns error if the OS RNG produces invalid entropy (catastrophic system failure).
    pub fn generate() -> Result<Self> {
        use rand::RngCore;

        let mut bytes = vec![0u8; 32]; // 256-bit entropy
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

        Ok(Self { secret: bytes, hash })
    }

    /// Validate entropy quality with comprehensive heuristic checks.
    fn validate_entropy(bytes: &[u8]) -> Result<()> {
        // Check 1: Not All Zeros
        if bytes.iter().all(|&b| b == 0) {
            return Err(EntropyValidationError::all_zeros());
        }

        // Check 2: Byte Diversity (require at least 25% unique bytes)
        let unique_bytes: HashSet<_> = bytes.iter().collect();
        if unique_bytes.len() < bytes.len() / 4 {
            return Err(EntropyValidationError::low_diversity(
                unique_bytes.len(),
                bytes.len(),
            ));
        }

        // Check 3: Sequential Pattern Detection
        let mut sequential_count = 0;
        for window in bytes.windows(2) {
            if window[1] == window[0].wrapping_add(1) {
                sequential_count += 1;
            }
        }
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

    /// Derive host-specific tag using SHA3-512.
    #[must_use]
    pub fn derive_host_tag(&self, hostname: &str) -> Vec<u8> {
        let mut hasher = Sha3_512::new();
        hasher.update(&self.secret);
        hasher.update(hostname.as_bytes());
        hasher.finalize().to_vec()
    }

    /// Derive artifact-specific tag using SHA3-512.
    #[must_use]
    pub fn derive_artifact_tag(&self, hostname: &str, artifact_id: &str) -> String {
        let host_tag = self.derive_host_tag(hostname);

        let mut hasher = Sha3_512::new();
        hasher.update(&host_tag);
        hasher.update(artifact_id.as_bytes());

        hex::encode(hasher.finalize())
    }

    /// Get SHA3-512 hash for comparison without exposing secret.
    #[must_use]
    pub fn hash(&self) -> &[u8; 64] {
        &self.hash
    }
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
        serializer.serialize_str("***REDACTED***")
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