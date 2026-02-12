//! Default values for configuration and policy.

use crate::{CONFIG_VERSION, LogFormat, LogLevel, POLICY_VERSION};

#[inline]
#[must_use]
pub(crate) fn default_version() -> u32 {
    CONFIG_VERSION
}

#[inline]
#[must_use]
pub(crate) fn default_policy_version() -> u32 {
    POLICY_VERSION
}

#[inline]
#[must_use]
pub(crate) fn default_honeytoken_count() -> usize {
    5
}

#[inline]
#[must_use]
pub(crate) fn default_artifact_permissions() -> u32 {
    0o600
}

#[inline]
#[must_use]
pub(crate) fn default_event_buffer_size() -> usize {
    10_000
}

#[inline]
#[must_use]
pub(crate) fn default_correlation_window() -> u64 {
    300
}

#[inline]
#[must_use]
pub(crate) fn default_alert_threshold() -> f64 {
    50.0
}

#[inline]
#[must_use]
pub(crate) fn default_max_events() -> usize {
    10_000
}

#[inline]
#[must_use]
pub(crate) fn default_true() -> bool {
    true
}

#[inline]
#[must_use]
pub(crate) fn default_business_hours_start() -> u8 {
    9
}

#[inline]
#[must_use]
pub(crate) fn default_business_hours_end() -> u8 {
    17
}

#[inline]
#[must_use]
pub(crate) fn default_artifact_access_weight() -> f64 {
    50.0
}

#[inline]
#[must_use]
pub(crate) fn default_suspicious_process_weight() -> f64 {
    30.0
}

#[inline]
#[must_use]
pub(crate) fn default_rapid_enum_weight() -> f64 {
    20.0
}

#[inline]
#[must_use]
pub(crate) fn default_off_hours_weight() -> f64 {
    15.0
}

#[inline]
#[must_use]
pub(crate) fn default_ancestry_suspicious_weight() -> f64 {
    10.0
}

#[inline]
#[must_use]
pub(crate) fn default_cooldown() -> u64 {
    60
}

#[inline]
#[must_use]
pub(crate) fn default_max_kills() -> usize {
    10
}

#[inline]
#[must_use]
pub(crate) fn default_log_format() -> LogFormat {
    LogFormat::Json
}

#[inline]
#[must_use]
pub(crate) fn default_rotate_size() -> u64 {
    100 * 1024 * 1024
}

#[inline]
#[must_use]
pub(crate) fn default_max_log_files() -> usize {
    10
}

#[inline]
#[must_use]
pub(crate) fn default_log_level() -> LogLevel {
    LogLevel::Info
}