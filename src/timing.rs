//! Centralized timing-profile controls for constant-time floor normalization.

use std::sync::atomic::{AtomicU8, Ordering};
use std::time::{Duration, Instant};

/// Runtime timing profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TimingProfile {
    /// Lower latency with moderate timing smoothing.
    Balanced = 0,
    /// Higher latency with stronger timing smoothing.
    Hardened = 1,
}

/// Internal operation kinds with dedicated timing floors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TimingOperation {
    ConfigLoad,
    ConfigValidateStandard,
    ConfigValidateStrict,
    ConfigHostname,
    ConfigDiff,
    PolicyLoad,
    PolicyValidate,
    PolicyDiff,
    PolicySuspiciousCheckLegacy,
    RuntimeConfigBuild,
    RuntimePolicyBuild,
    RootTagNew,
    RootTagGenerate,
    RootTagDeriveHost,
    RootTagDeriveArtifact,
    RootTagHashCompare,
    PolicySuspiciousCheck,
    PolicyCustomConditionCheck,
}

static TIMING_PROFILE: AtomicU8 = AtomicU8::new(TimingProfile::Balanced as u8);

/// Set global timing profile for constant-time floor normalization.
pub fn set_timing_profile(profile: TimingProfile) {
    TIMING_PROFILE.store(profile as u8, Ordering::Relaxed);
}

/// Get current global timing profile.
#[must_use]
pub fn get_timing_profile() -> TimingProfile {
    match TIMING_PROFILE.load(Ordering::Relaxed) {
        1 => TimingProfile::Hardened,
        _ => TimingProfile::Balanced,
    }
}

#[inline]
const fn timing_floor(profile: TimingProfile, op: TimingOperation) -> Duration {
    match profile {
        TimingProfile::Balanced => match op {
            TimingOperation::ConfigLoad => Duration::from_micros(30),
            TimingOperation::ConfigValidateStandard => Duration::from_micros(12),
            TimingOperation::ConfigValidateStrict => Duration::from_micros(16),
            TimingOperation::ConfigHostname => Duration::from_micros(2),
            TimingOperation::ConfigDiff => Duration::from_micros(8),
            TimingOperation::PolicyLoad => Duration::from_micros(30),
            TimingOperation::PolicyValidate => Duration::from_micros(12),
            TimingOperation::PolicyDiff => Duration::from_micros(8),
            TimingOperation::PolicySuspiciousCheckLegacy => Duration::from_micros(8),
            TimingOperation::RuntimeConfigBuild => Duration::from_micros(10),
            TimingOperation::RuntimePolicyBuild => Duration::from_micros(10),
            TimingOperation::RootTagNew => Duration::from_micros(18),
            TimingOperation::RootTagGenerate => Duration::from_micros(18),
            TimingOperation::RootTagDeriveHost => Duration::from_micros(8),
            TimingOperation::RootTagDeriveArtifact => Duration::from_micros(12),
            TimingOperation::RootTagHashCompare => Duration::from_micros(1),
            TimingOperation::PolicySuspiciousCheck => Duration::from_micros(8),
            TimingOperation::PolicyCustomConditionCheck => Duration::from_micros(4),
        },
        TimingProfile::Hardened => match op {
            TimingOperation::ConfigLoad => Duration::from_micros(45),
            TimingOperation::ConfigValidateStandard => Duration::from_micros(18),
            TimingOperation::ConfigValidateStrict => Duration::from_micros(24),
            TimingOperation::ConfigHostname => Duration::from_micros(4),
            TimingOperation::ConfigDiff => Duration::from_micros(12),
            TimingOperation::PolicyLoad => Duration::from_micros(45),
            TimingOperation::PolicyValidate => Duration::from_micros(18),
            TimingOperation::PolicyDiff => Duration::from_micros(12),
            TimingOperation::PolicySuspiciousCheckLegacy => Duration::from_micros(12),
            TimingOperation::RuntimeConfigBuild => Duration::from_micros(16),
            TimingOperation::RuntimePolicyBuild => Duration::from_micros(16),
            TimingOperation::RootTagNew => Duration::from_micros(28),
            TimingOperation::RootTagGenerate => Duration::from_micros(28),
            TimingOperation::RootTagDeriveHost => Duration::from_micros(12),
            TimingOperation::RootTagDeriveArtifact => Duration::from_micros(18),
            TimingOperation::RootTagHashCompare => Duration::from_micros(2),
            TimingOperation::PolicySuspiciousCheck => Duration::from_micros(12),
            TimingOperation::PolicyCustomConditionCheck => Duration::from_micros(6),
        },
    }
}

#[inline]
pub(crate) fn enforce_operation_min_timing(started: Instant, op: TimingOperation) {
    let target = started + timing_floor(get_timing_profile(), op);
    while Instant::now() < target {
        std::hint::spin_loop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_roundtrip() {
        set_timing_profile(TimingProfile::Balanced);
        assert_eq!(get_timing_profile(), TimingProfile::Balanced);
        set_timing_profile(TimingProfile::Hardened);
        assert_eq!(get_timing_profile(), TimingProfile::Hardened);
    }
}
