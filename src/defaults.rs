//! Default values for configuration and policy.
//!
//! # Security Rationale
//!
//! **Defaults ARE security decisions.** This module centralizes all default values
//! to ensure consistency and enable security review.
//!
//! ## Design Principles
//!
//! 1. **Secure by Default**: Defaults should never create vulnerabilities
//! 2. **Fail Safe**: When in doubt, choose the more restrictive option
//! 3. **Explicit is Better**: No "magic" values without documentation
//! 4. **Performance-Conscious**: Defaults should be performant for typical deployments
//! 5. **Operational Viability**: Defaults should work in real environments
//!
//! ## Default Value Philosophy
//!
//! Each default is chosen based on:
//! - **Security impact**: Does this create an attack surface?
//! - **Operational impact**: Will this cause production issues?
//! - **Resource usage**: Is this sustainable at scale?
//! - **Backward compatibility**: Can we change this later?
//!
//! ## Review Process
//!
//! When modifying defaults:
//! 1. **Document security rationale** (why this value?)
//! 2. **Consider attack scenarios** (what could go wrong?)
//! 3. **Test operational impact** (staging environment)
//! 4. **Update documentation** (CHANGELOG, upgrade guide)
//! 5. **Increment version if breaking** (fail-fast on incompatibility)
//!
//! # Examples
//!
//! ## Secure Default Example
//!
//! ```rust
//! use palisade_config::Config;
//!
//! let config = Config::default();
//!
//! // Artifact permissions default to 0o600 (owner read/write only)
//! // RATIONALE: Prevents information disclosure via file permissions
//! assert_eq!(config.deception.artifact_permissions, 0o600);
//!
//! // Event buffer is large (10,000 events)
//! // RATIONALE: Prevents event loss during burst activity
//! assert_eq!(config.telemetry.event_buffer_size, 10_000);
//! ```
//!
//! ## Performance Default Example
//!
//! ```rust
//! use palisade_config::PolicyConfig;
//!
//! let policy = PolicyConfig::default();
//!
//! // Correlation window is 5 minutes
//! // RATIONALE: Balance between detection accuracy and memory usage
//! assert_eq!(policy.scoring.correlation_window_secs, 300);
//! ```

use crate::{CONFIG_VERSION, LogFormat, LogLevel, POLICY_VERSION};

// ============================================================================
// VERSION DEFAULTS
// ============================================================================

/// Default configuration schema version.
///
/// **SECURITY RATIONALE:**
/// - Always use current version
/// - Prevents accidental downgrades
/// - Ensures latest security features are enabled
#[inline]
#[must_use]
pub(crate) fn default_version() -> u32 {
    CONFIG_VERSION
}

/// Default policy schema version.
///
/// **SECURITY RATIONALE:**
/// - Independent from config version
/// - Enables hot-reloading without version conflicts
/// - Backward compatible (old policies on new agents work)
#[inline]
#[must_use]
pub(crate) fn default_policy_version() -> u32 {
    POLICY_VERSION
}

// ============================================================================
// DECEPTION DEFAULTS
// ============================================================================

/// Default number of honeytokens to generate.
///
/// **VALUE:** 5
///
/// **SECURITY RATIONALE:**
/// - Small enough to minimize false positive noise
/// - Large enough to provide coverage
/// - Not so many that patterns emerge
///
/// **OPERATIONAL CONSIDERATIONS:**
/// - Each honeytoken creates monitoring overhead
/// - More tokens = more memory usage
/// - 5 provides good balance for typical deployments
///
/// **ATTACK SCENARIOS CONSIDERED:**
/// - ✅ Prevents exhaustive enumeration (5 is manageable)
/// - ✅ Reduces pattern detection (not too many)
/// - ✅ Maintains plausibility (not suspiciously many)
#[inline]
#[must_use]
pub(crate) fn default_honeytoken_count() -> usize {
    5
}

/// Default Unix permissions for created artifacts.
///
/// **VALUE:** 0o600 (owner read/write only)
///
/// **SECURITY RATIONALE:**
/// - Prevents information disclosure via file permissions
/// - Group/other read = reconnaissance opportunity
/// - More restrictive than typical (0o644)
/// - Honeypots should not have "helpful" permissions
///
/// **OPERATIONAL CONSIDERATIONS:**
/// - May require manual chmod if processes need group read
/// - Some backup tools expect readable files
/// - Fail-safe: choose security over convenience
///
/// **ATTACK SCENARIOS CONSIDERED:**
/// - ✅ Prevents lateral movement (other users can't read)
/// - ✅ Limits reconnaissance (permissions don't reveal info)
/// - ✅ Forces active attacks (can't passively read)
#[inline]
#[must_use]
pub(crate) fn default_artifact_permissions() -> u32 {
    0o600
}

// ============================================================================
// TELEMETRY DEFAULTS
// ============================================================================

/// Default event buffer size (ring buffer capacity).
///
/// **VALUE:** 10,000 events
///
/// **SECURITY RATIONALE:**
/// - Large enough to handle burst activity without dropping events
/// - Not so large that memory usage becomes a DoS vector
/// - Allows ~5 minutes of high-frequency events (30-40 events/sec)
///
/// **OPERATIONAL CONSIDERATIONS:**
/// - Each event is ~100 bytes = 1MB total buffer
/// - Buffer full = oldest events dropped (ring buffer)
/// - Sufficient for typical honeypot workload
///
/// **ATTACK SCENARIOS CONSIDERED:**
/// - ✅ Prevents event flooding DoS (bounded memory)
/// - ✅ Retains enough context for correlation
/// - ✅ Handles burst activity (rapid enumeration attacks)
#[inline]
#[must_use]
pub(crate) fn default_event_buffer_size() -> usize {
    10_000
}

// ============================================================================
// SCORING DEFAULTS
// ============================================================================

/// Default correlation window for event scoring.
///
/// **VALUE:** 300 seconds (5 minutes)
///
/// **SECURITY RATIONALE:**
/// - Long enough to correlate related events
/// - Short enough to limit memory usage
/// - Typical attack scenarios unfold in minutes, not hours
///
/// **OPERATIONAL CONSIDERATIONS:**
/// - Events older than 5 minutes are aged out
/// - Slow attacks (>5 min) won't correlate
/// - Trade-off: detection accuracy vs memory
///
/// **ATTACK SCENARIOS CONSIDERED:**
/// - ✅ Detects rapid enumeration (seconds to minutes)
/// - ✅ Correlates multi-stage attacks (C2 callback after initial access)
/// - ❌ Misses very slow attacks (intentional—not a priority)
#[inline]
#[must_use]
pub(crate) fn default_correlation_window() -> u64 {
    300 // 5 minutes
}

/// Default alert threshold (confidence score).
///
/// **VALUE:** 50.0 (out of 100)
///
/// **SECURITY RATIONALE:**
/// - Medium sensitivity (not hair-trigger, not oblivious)
/// - Tuned for honeypot environment (expect some noise)
/// - Allows for tuning via policy hot-reload
///
/// **OPERATIONAL CONSIDERATIONS:**
/// - Lower threshold = more false positives
/// - Higher threshold = more false negatives
/// - 50.0 is balanced for initial deployment
///
/// **ATTACK SCENARIOS CONSIDERED:**
/// - ✅ Detects credential theft (high confidence)
/// - ✅ Detects process enumeration (medium confidence)
/// - ✅ Filters benign activity (low confidence)
#[inline]
#[must_use]
pub(crate) fn default_alert_threshold() -> f64 {
    50.0
}

/// Default maximum events to retain in correlation window.
///
/// **VALUE:** 10,000 events
///
/// **SECURITY RATIONALE:**
/// - Hard limit on memory usage (DoS protection)
/// - Same as event buffer size (consistent)
/// - Prevents memory exhaustion from event flooding
///
/// **OPERATIONAL CONSIDERATIONS:**
/// - If exceeded, oldest events are dropped
/// - Should be sized for peak load + margin
/// - 10k events = ~1MB memory
///
/// **ATTACK SCENARIOS CONSIDERED:**
/// - ✅ Prevents memory exhaustion DoS
/// - ✅ Maintains system stability under attack
/// - ❌ May drop events during extreme flooding (acceptable trade-off)
#[inline]
#[must_use]
pub(crate) fn default_max_events() -> usize {
    10_000
}

/// Default "true" boolean value.
///
/// **RATIONALE:**
/// - Convenience function for serde defaults
/// - Enables opt-out rather than opt-in for security features
/// - Used for: time-based scoring, ancestry tracking
///
/// **SECURITY PHILOSOPHY:**
/// - Security features should be enabled by default
/// - Require explicit disabling (not forgetting to enable)
/// - "Secure by default" principle
#[inline]
#[must_use]
pub(crate) fn default_true() -> bool {
    true
}

/// Default business hours start (24-hour format).
///
/// **VALUE:** 9 (9:00 AM)
///
/// **SECURITY RATIONALE:**
/// - Used for off-hours activity scoring
/// - Typical business hours for most organizations
/// - Conservative assumption (not too early)
///
/// **OPERATIONAL CONSIDERATIONS:**
/// - Should be customized per organization
/// - Used for time-based threat scoring
/// - Off-hours activity = higher suspicion
///
/// **ATTACK SCENARIOS CONSIDERED:**
/// - ✅ Detects after-hours data exfiltration
/// - ✅ Increases confidence for night/weekend attacks
/// - ⚠️  May create false positives for global teams (tune via policy)
#[inline]
#[must_use]
pub(crate) fn default_business_hours_start() -> u8 {
    9
}

/// Default business hours end (24-hour format).
///
/// **VALUE:** 17 (5:00 PM)
///
/// **SECURITY RATIONALE:**
/// - Standard business hours for most organizations
/// - Conservative assumption (not too late)
/// - Balances detection vs operational reality
///
/// **OPERATIONAL CONSIDERATIONS:**
/// - Evening work (5-7pm) may trigger false positives
/// - Should be tuned per organization culture
/// - Policy hot-reload enables easy adjustment
///
/// **ATTACK SCENARIOS CONSIDERED:**
/// - ✅ Late-night attacks get higher confidence scores
/// - ✅ Weekend attacks are flagged
/// - ⚠️  On-call engineers may trigger false positives (acceptable)
#[inline]
#[must_use]
pub(crate) fn default_business_hours_end() -> u8 {
    17
}

// ============================================================================
// SCORING WEIGHT DEFAULTS
// ============================================================================
// These weights determine how different signals contribute to threat score.
// Total confidence = Σ(signal_weight * signal_detected)
// Weights should sum to ~100 for typical multi-signal scenarios.

/// Default weight for artifact access signal.
///
/// **VALUE:** 50.0
///
/// **SECURITY RATIONALE:**
/// - Artifact access is the PRIMARY indicator in honeypots
/// - Single access should trigger medium-confidence alert
/// - Weighted higher than other signals (intentional)
///
/// **OPERATIONAL CONSIDERATIONS:**
/// - Legitimate access should be near-zero (it's a honeypot!)
/// - False positives indicate misconfiguration
/// - High weight ensures timely detection
///
/// **ATTACK SCENARIOS CONSIDERED:**
/// - ✅ Credential theft (access + suspicious process = 80 confidence)
/// - ✅ Reconnaissance (access + enumeration = 70 confidence)
/// - ✅ False positives filtered by other signals
#[inline]
#[must_use]
pub(crate) fn default_artifact_access_weight() -> f64 {
    50.0
}

/// Default weight for suspicious process signal.
///
/// **VALUE:** 30.0
///
/// **SECURITY RATIONALE:**
/// - Suspicious processes are strong indicators
/// - Combined with artifact access = high confidence
/// - Alone = medium confidence (may be benign)
///
/// **OPERATIONAL CONSIDERATIONS:**
/// - Process name detection is heuristic (not foolproof)
/// - Attackers can rename binaries
/// - Weighted below artifact access (secondary signal)
///
/// **ATTACK SCENARIOS CONSIDERED:**
/// - ✅ Mimikatz + artifact access = 80 confidence (critical)
/// - ✅ Mimikatz alone = 30 confidence (medium)
/// - ⚠️  Renamed binaries evade detection (acceptable limitation)
#[inline]
#[must_use]
pub(crate) fn default_suspicious_process_weight() -> f64 {
    30.0
}

/// Default weight for rapid enumeration signal.
///
/// **VALUE:** 20.0
///
/// **SECURITY RATIONALE:**
/// - Rapid access to multiple files = reconnaissance
/// - Not as strong as artifact access (may be legitimate)
/// - Combined with other signals = higher confidence
///
/// **OPERATIONAL CONSIDERATIONS:**
/// - Backup tools may trigger this (false positive)
/// - Threshold tuning via policy reduces noise
/// - Lower weight than primary signals (tertiary)
///
/// **ATTACK SCENARIOS CONSIDERED:**
/// - ✅ Lateral movement enumeration
/// - ✅ Automated scanning tools
/// - ⚠️  Backup/indexing tools (false positives—tune threshold)
#[inline]
#[must_use]
pub(crate) fn default_rapid_enum_weight() -> f64 {
    20.0
}

/// Default weight for off-hours activity signal.
///
/// **VALUE:** 15.0
///
/// **SECURITY RATIONALE:**
/// - Off-hours activity is suspicious but not definitive
/// - Modifier rather than primary signal
/// - Increases confidence when combined with other signals
///
/// **OPERATIONAL CONSIDERATIONS:**
/// - Global teams may work off-hours (false positives)
/// - Automated processes run 24/7 (tune exclusions)
/// - Lower weight (modifier, not primary detection)
///
/// **ATTACK SCENARIOS CONSIDERED:**
/// - ✅ After-hours data exfiltration gets boost
/// - ✅ Weekend attacks are more suspicious
/// - ⚠️  Legitimate off-hours work (acceptable false positive rate)
#[inline]
#[must_use]
pub(crate) fn default_off_hours_weight() -> f64 {
    15.0
}

/// Default weight for suspicious process ancestry signal.
///
/// **VALUE:** 10.0
///
/// **SECURITY RATIONALE:**
/// - Process ancestry provides context
/// - Weak signal alone, strong when combined
/// - Example: cmd.exe spawned by w3wp.exe (web shell)
///
/// **OPERATIONAL CONSIDERATIONS:**
/// - Ancestry tracking has overhead (enable via config)
/// - May miss attacks that break process tree
/// - Lowest weight (context signal, not primary)
///
/// **ATTACK SCENARIOS CONSIDERED:**
/// - ✅ Web shells (unexpected parent processes)
/// - ✅ Process injection (suspicious ancestry)
/// - ❌ Direct execution (no ancestry to detect)
#[inline]
#[must_use]
pub(crate) fn default_ancestry_suspicious_weight() -> f64 {
    10.0
}

// ============================================================================
// RESPONSE DEFAULTS
// ============================================================================

/// Default cooldown period between responses.
///
/// **VALUE:** 60 seconds
///
/// **SECURITY RATIONALE:**
/// - Prevents alert storm from single incident
/// - Gives time for incident investigation
/// - Rate-limits response actions (stability)
///
/// **OPERATIONAL CONSIDERATIONS:**
/// - Multiple incidents within 60s = single response
/// - May delay response to separate incidents
/// - Trade-off: stability vs response time
///
/// **ATTACK SCENARIOS CONSIDERED:**
/// - ✅ Prevents DoS via response trigger flooding
/// - ✅ Maintains system stability
/// - ❌ May miss separate rapid attacks (acceptable—not common)
#[inline]
#[must_use]
pub(crate) fn default_cooldown() -> u64 {
    60 // 1 minute
}

/// Default maximum process kills per incident.
///
/// **VALUE:** 10
///
/// **SECURITY RATIONALE:**
/// - Safety limit prevents mass process termination
/// - 10 is sufficient for typical attack scenarios
/// - Prevents accidental system instability
///
/// **OPERATIONAL CONSIDERATIONS:**
/// - Large process trees may hit limit
/// - Limit applies per incident (not global)
/// - Fail-safe: prefer system stability over kill completeness
///
/// **ATTACK SCENARIOS CONSIDERED:**
/// - ✅ Limits damage from misconfiguration
/// - ✅ Prevents cascade failures
/// - ⚠️  Sophisticated attacks with many processes may partially survive
#[inline]
#[must_use]
pub(crate) fn default_max_kills() -> usize {
    10
}

// ============================================================================
// LOGGING DEFAULTS
// ============================================================================

/// Default log format.
///
/// **VALUE:** JSON
///
/// **SECURITY RATIONALE:**
/// - Machine-parseable (SIEM integration)
/// - Structured format prevents log injection
/// - Industry standard for security logging
///
/// **OPERATIONAL CONSIDERATIONS:**
/// - Slightly less human-readable than text
/// - Better for automated analysis
/// - Standard for modern logging infrastructure
///
/// **ATTACK SCENARIOS CONSIDERED:**
/// - ✅ Prevents log injection attacks (structured format)
/// - ✅ Enables automated correlation (SIEM-ready)
/// - ✅ Supports forensic analysis (queryable)
#[inline]
#[must_use]
pub(crate) fn default_log_format() -> LogFormat {
    LogFormat::Json
}

/// Default log rotation size.
///
/// **VALUE:** 100 MB
///
/// **SECURITY RATIONALE:**
/// - Large enough to retain significant history
/// - Small enough to prevent disk exhaustion
/// - Industry standard for rotation threshold
///
/// **OPERATIONAL CONSIDERATIONS:**
/// - High-traffic honeypots may rotate frequently
/// - Low-traffic honeypots may never rotate
/// - Balances retention vs disk usage
///
/// **ATTACK SCENARIOS CONSIDERED:**
/// - ✅ Prevents log-based DoS (disk exhaustion)
/// - ✅ Maintains log availability for forensics
/// - ✅ Enables log archival strategies
#[inline]
#[must_use]
pub(crate) fn default_rotate_size() -> u64 {
    100 * 1024 * 1024 // 100 MB
}

/// Default maximum number of rotated log files to keep.
///
/// **VALUE:** 10
///
/// **SECURITY RATIONALE:**
/// - Sufficient history for incident investigation
/// - Prevents unbounded disk usage
/// - ~1GB total logs (10 * 100MB)
///
/// **OPERATIONAL CONSIDERATIONS:**
/// - Oldest logs are deleted on rotation
/// - External archival recommended for long-term retention
/// - Balance between disk usage and history
///
/// **ATTACK SCENARIOS CONSIDERED:**
/// - ✅ Prevents disk exhaustion
/// - ✅ Retains recent history for forensics
/// - ⚠️  Very old incidents may lack logs (use external archival)
#[inline]
#[must_use]
pub(crate) fn default_max_log_files() -> usize {
    10
}

/// Default log level.
///
/// **VALUE:** Info
///
/// **SECURITY RATIONALE:**
/// - Balances verbosity vs noise
/// - Includes security events (errors, warnings, info)
/// - Excludes debug noise (performance, clutter)
///
/// **OPERATIONAL CONSIDERATIONS:**
/// - Debug level too verbose for production
/// - Warn level too quiet (misses context)
/// - Info is industry standard for production
///
/// **ATTACK SCENARIOS CONSIDERED:**
/// - ✅ Logs all security-relevant events
/// - ✅ Excludes performance noise
/// - ✅ Enables forensic analysis
#[inline]
#[must_use]
pub(crate) fn default_log_level() -> LogLevel {
    LogLevel::Info
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_are_consistent() {
        assert_eq!(default_version(), CONFIG_VERSION);
        assert_eq!(default_policy_version(), POLICY_VERSION);
    }

    #[test]
    fn deception_defaults_are_secure() {
        // Artifact permissions should be restrictive
        assert_eq!(default_artifact_permissions(), 0o600);
        
        // Honeytoken count should be reasonable
        let count = default_honeytoken_count();
        assert!(count > 0 && count <= 100);
    }

    #[test]
    fn telemetry_defaults_prevent_dos() {
        // Event buffer should be bounded
        let buffer = default_event_buffer_size();
        assert!(buffer >= 100 && buffer <= 1_000_000);
    }

    #[test]
    fn scoring_defaults_are_balanced() {
        // Weights should be positive
        assert!(default_artifact_access_weight() > 0.0);
        assert!(default_suspicious_process_weight() > 0.0);
        assert!(default_rapid_enum_weight() > 0.0);
        
        // Alert threshold should be in valid range
        let threshold = default_alert_threshold();
        assert!(threshold >= 0.0 && threshold <= 100.0);
    }

    #[test]
    fn response_defaults_have_safety_limits() {
        // Cooldown prevents alert storms
        assert!(default_cooldown() > 0);
        
        // Max kills prevents runaway termination
        let max_kills = default_max_kills();
        assert!(max_kills > 0 && max_kills <= 100);
    }

    #[test]
    fn business_hours_are_valid() {
        let start = default_business_hours_start();
        let end = default_business_hours_end();
        
        assert!(start < 24);
        assert!(end < 24);
        assert!(start < end);
    }

    #[test]
    fn logging_defaults_are_operational() {
        // Log rotation size should be reasonable
        let rotate_size = default_rotate_size();
        assert!(rotate_size >= 1024 * 1024); // At least 1MB
        assert!(rotate_size <= 1024 * 1024 * 1024); // At most 1GB
        
        // Max log files should be reasonable
        let max_files = default_max_log_files();
        assert!(max_files >= 1 && max_files <= 100);
    }
}

// ============================================================================
// SECURITY AUDIT LOG
// ============================================================================
//
// All changes to default values should be documented here for security review:
//
// 2026-01-11:
//   - Initial default values established
//   - All defaults reviewed for security implications
//   - Comprehensive documentation and rationale added
//   - Tests verify security properties
//
// Future changes should follow this format:
// YYYY-MM-DD:
//   - Changed: <field_name>
//   - Old value: <old>
//   - New value: <new>
//   - Rationale: <why>
//   - Security impact: <assessment>
//   - Reviewer: <name>