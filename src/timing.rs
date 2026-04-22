//! Centralized timing-floor controls for public-path normalization.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Default minimum duration applied to public operations.
pub const DEFAULT_TIMING_FLOOR: Duration = Duration::from_micros(50);

/// Internal operation kinds that participate in timing-floor enforcement.
#[derive(Debug, PartialEq, Eq)]
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

static TIMING_FLOOR_NANOS: AtomicU64 = AtomicU64::new(DEFAULT_TIMING_FLOOR.as_nanos() as u64);

/// Set the global minimum duration for public operations in this crate.
pub fn set_timing_floor(floor: Duration) {
    let nanos = floor.as_nanos().min(u128::from(u64::MAX)) as u64;
    TIMING_FLOOR_NANOS.store(nanos, Ordering::Relaxed);
}

/// Get the current global minimum duration for public operations.
#[must_use]
pub fn get_timing_floor() -> Duration {
    Duration::from_nanos(TIMING_FLOOR_NANOS.load(Ordering::Relaxed))
}

#[inline]
pub(crate) fn enforce_operation_min_timing(started: Instant, _op: TimingOperation) {
    let target = started + get_timing_floor();
    while Instant::now() < target {
        std::hint::spin_loop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timing_floor_roundtrip() {
        set_timing_floor(Duration::from_micros(25));
        assert_eq!(get_timing_floor(), Duration::from_micros(25));
        set_timing_floor(DEFAULT_TIMING_FLOOR);
        assert_eq!(get_timing_floor(), DEFAULT_TIMING_FLOOR);
    }
}
