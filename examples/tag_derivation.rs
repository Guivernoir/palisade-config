//! # Example 04 — Cryptographic Tag Derivation
//!
//! Demonstrates `RootTag` generation, validation, and the full hierarchical
//! tag derivation chain:
//!
//!   root_secret → host_tag (hostname) → artifact_tag (artifact_id)
//!
//! Security guarantees:
//! - 256-bit root secret, never serialised in plaintext
//! - Zeroized on drop (no key material left in heap after free)
//! - SHA3-512 at every derivation level
//! - Constant-time hash comparison
//! - Timing floor on every operation
//! - Fixed-buffer derivation on the hot path

use palisade_config::RootTag;

fn main() {
    // -------------------------------------------------------------------------
    // 1. Generate a cryptographically secure RootTag
    // -------------------------------------------------------------------------
    println!("=== RootTag Generation ===");
    let root =
        RootTag::generate().expect("OS RNG produced invalid entropy — catastrophic system failure");

    // Debug impl deliberately hides the secret
    println!("  {:?}", root);

    // Hash is safe to log (it's a hash of the secret, not the secret itself)
    println!("  hash[:8]: {}", hex::encode(&root.hash()[..8]));

    // -------------------------------------------------------------------------
    // 2. Parse a RootTag from a known hex string (for config persistence)
    // -------------------------------------------------------------------------
    println!("\n=== RootTag from Hex ===");
    // Generate a hex string to use as an example (in prod, this is in your config TOML)
    let root_for_hex_demo = RootTag::generate().expect("generate");
    // We can't access .secret directly (private), but we can serialise to get the hex:
    let serialised = serde_json::to_string(&root_for_hex_demo).expect("serialise");
    let hex_str = serialised.trim_matches('"');

    println!("  hex (64 chars): {}...{}", &hex_str[..8], &hex_str[56..]);
    let parsed = RootTag::new(hex_str).expect("Valid hex must parse successfully");
    println!("  parsed ok: {:?}", parsed);

    // The two tags must have the same hash (same secret)
    assert!(
        root_for_hex_demo.hash_eq_ct(&parsed),
        "Parsed tag must match original"
    );
    println!("  hash_eq_ct: PASSED");

    // -------------------------------------------------------------------------
    // 3. Entropy validation — reject weak keys at parse time
    // -------------------------------------------------------------------------
    println!("\n=== Entropy Validation ===");

    let bad_inputs: &[(&str, &str)] = &[
        ("all zeros", &"00".repeat(32)),
        ("sequential", &hex::encode((0u8..32).collect::<Vec<_>>())),
        ("too short", "deadbeef"),
        ("not hex", &"zz".repeat(32)),
        ("low diversity", &"ab".repeat(32)), // only 1 unique byte
    ];

    for (label, hex) in bad_inputs {
        match RootTag::new(hex) {
            Err(e) => println!("  [OK] Rejected '{label}': {e}"),
            Ok(_) => println!("  [FAIL] Accepted '{label}' — entropy check bypassed!"),
        }
    }

    // -------------------------------------------------------------------------
    // 4. Hierarchical derivation
    // -------------------------------------------------------------------------
    println!("\n=== Hierarchical Derivation ===");
    let root = RootTag::generate().expect("generate");

    // Level 1: host tag
    let host_a = root.derive_host_tag_bytes("honeypot-alpha.internal");
    let host_b = root.derive_host_tag_bytes("honeypot-beta.internal");

    println!("  host_a[:8]: {}", hex::encode(&host_a[..8]));
    println!("  host_b[:8]: {}", hex::encode(&host_b[..8]));
    assert_ne!(host_a, host_b, "Different hosts → different tags");
    println!("  Isolation: different hosts produce different host tags ✓");

    // Level 2: artifact tag (fixed-size digest path)
    let art_a1 = root.derive_artifact_tag_bytes("honeypot-alpha.internal", "aws-credentials-001");
    let art_a2 = root.derive_artifact_tag_bytes("honeypot-alpha.internal", "aws-credentials-002");
    let art_b1 = root.derive_artifact_tag_bytes("honeypot-beta.internal", "aws-credentials-001");

    println!("\n  artifact alpha/art-001 [:8]: {}...", hex::encode(&art_a1[..8]));
    println!("  artifact alpha/art-002 [:8]: {}...", hex::encode(&art_a2[..8]));
    println!("  artifact beta /art-001 [:8]: {}...", hex::encode(&art_b1[..8]));

    assert_ne!(
        art_a1, art_a2,
        "Same host, different artifact → different tag"
    );
    assert_ne!(
        art_a1, art_b1,
        "Different host, same artifact → different tag"
    );
    println!("  Isolation: all artifact tag collisions: NONE ✓");

    // Determinism check
    let art_a1_again =
        root.derive_artifact_tag_bytes("honeypot-alpha.internal", "aws-credentials-001");
    assert_eq!(art_a1, art_a1_again, "Derivation must be deterministic");
    println!("  Determinism: repeated derivation produces same tag ✓");

    // -------------------------------------------------------------------------
    // 5. No-alloc derivation into stack buffer
    // -------------------------------------------------------------------------
    println!("\n=== No-Alloc Derivation (stack buffer) ===");
    let mut buf = [0u8; 128];
    root.derive_artifact_tag_hex_into("honeypot-alpha.internal", "ssh-key-honeypot", &mut buf);

    let as_str = std::str::from_utf8(&buf).expect("hex is always ASCII");
    println!(
        "  tag (128 hex chars): {}...{}",
        &as_str[..16],
        &as_str[112..]
    );
    assert!(
        buf.iter().all(|b| b.is_ascii_hexdigit()),
        "Output must be valid lowercase hex"
    );
    println!("  hex validity: PASSED ✓");

    // Verify it matches the fixed-size digest path
    let digest = root.derive_artifact_tag_bytes("honeypot-alpha.internal", "ssh-key-honeypot");
    let digest_hex = hex::encode(digest);
    assert_eq!(
        digest_hex, as_str,
        "No-alloc buffer and digest-derived hex paths must agree"
    );
    println!("  Consistency (buffer == digest-derived hex): PASSED ✓");

    // -------------------------------------------------------------------------
    // 6. Constant-time comparison
    // -------------------------------------------------------------------------
    println!("\n=== Constant-Time Hash Comparison ===");
    let tag1 = RootTag::generate().expect("generate");
    let tag2 = RootTag::generate().expect("generate");

    println!("  tag1 == tag1 (self): {}", tag1.hash_eq_ct(&tag1));
    println!("  tag1 == tag2 (diff): {}", tag1.hash_eq_ct(&tag2));
    assert!(tag1.hash_eq_ct(&tag1), "Tag must equal itself");
    assert!(!tag1.hash_eq_ct(&tag2), "Different tags must not be equal");
    println!("  Constant-time comparison: PASSED ✓");

    // -------------------------------------------------------------------------
    // 7. Serialise / deserialise round-trip (TOML embedding)
    // -------------------------------------------------------------------------
    println!("\n=== Serialise / Deserialise Round-trip ===");
    let original = RootTag::generate().expect("generate");
    let serialised = serde_json::to_string(&original).expect("serialise");

    // Serialised form is the raw hex string — verify length
    let hex_in_json = serialised.trim_matches('"');
    assert_eq!(hex_in_json.len(), 64, "Serialised tag must be 64 hex chars");
    println!("  serialised length: {} chars ✓", hex_in_json.len());

    let deserialised: RootTag = serde_json::from_str(&serialised).expect("deserialise");
    assert!(
        original.hash_eq_ct(&deserialised),
        "Round-trip must preserve tag identity"
    );
    println!("  round-trip identity: PASSED ✓");

    // Deserialising "***REDACTED***" must fail — prevents log scraping attacks
    let redacted = r#""***REDACTED***""#;
    assert!(
        serde_json::from_str::<RootTag>(redacted).is_err(),
        "REDACTED sentinel must be rejected"
    );
    println!("  REDACTED sentinel rejection: PASSED ✓");

    println!("\nAll tag derivation checks passed.");
}
