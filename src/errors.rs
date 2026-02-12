//! Centralized error definitions and helpers for palisade-config.
//!
//! This module provides:
//! - Type-safe error construction
//! - Consistent error metadata
//! - Automatic obfuscation
//! - Semantic error categories
//!
//! # Philosophy
//!
//! Well, that was quite the strategic decision, wasn't it? Rather than scattering
//! error construction logic across the codebase like confetti at a wedding,
//! we've consolidated everything here. Military precision meets error handling.

use palisade_errors::{definitions, AgentError};
use std::path::Path;

// ============================================================================
// ERROR CONSTRUCTION HELPERS
// ============================================================================

/// Configuration file parsing failed.
///
/// Use when TOML syntax is invalid or file cannot be read.
#[inline]
pub(crate) fn parse_error(operation: &str, details: impl Into<String>) -> AgentError {
    AgentError::config(
        definitions::CFG_PARSE_FAILED,
        operation.to_owned(),
        details.into(),
    )
}

/// Configuration version mismatch.
///
/// Use when config/policy version doesn't match expected version.
#[inline]
pub(crate) fn version_error(
    operation: &str,
    file_version: u32,
    expected_version: u32,
    message: impl Into<String>,
) -> AgentError {
    AgentError::config(
        definitions::CFG_VERSION_MISMATCH,
        operation.to_owned(),
        message.into(),
    )
        .with_metadata("file_version", file_version.to_string())
        .with_metadata("expected_version", expected_version.to_string())
}

/// Required configuration field is missing or empty.
///
/// Use when mandatory fields are absent or contain no data.
#[inline]
pub(crate) fn missing_required(
    operation: &str,
    field: &str,
    impact: &str,
) -> AgentError {
    AgentError::config(
        definitions::CFG_MISSING_REQUIRED,
        operation.to_owned(),
        format!("{} cannot be empty", field),
    )
    .with_metadata("field", field.to_owned())
    .with_metadata("impact", impact.to_owned())
}

/// Configuration field has invalid value.
///
/// Use when value is out of range, wrong format, or semantically incorrect.
#[inline]
pub(crate) fn invalid_value(
    operation: &str,
    field: &str,
    reason: impl Into<String>,
) -> AgentError {
    AgentError::config(
        definitions::CFG_INVALID_VALUE,
        operation.to_owned(),
        reason.into(),
    )
        .with_metadata("field", field.to_owned())
}

/// Configuration field has invalid value with expected/actual context.
///
/// Tactical breakdown: shows what you sent vs what was expected.
#[inline]
pub(crate) fn invalid_value_with_range(
    operation: &str,
    field: &str,
    actual: impl Into<String>,
    expected: impl Into<String>,
    reason: impl Into<String>,
) -> AgentError {
    AgentError::config(
        definitions::CFG_INVALID_VALUE,
        operation.to_owned(),
        reason.into(),
    )
        .with_metadata("field", field.to_owned())
        .with_metadata("actual_value", actual.into())
        .with_metadata("expected_range", expected.into())
}

/// Security violation in configuration.
///
/// Use when configuration creates a security vulnerability.
#[inline]
pub(crate) fn security_violation(
    operation: &str,
    reason: impl Into<String>,
    impact: &str,
) -> AgentError {
    AgentError::config(
        definitions::CFG_SECURITY_VIOLATION,
        operation.to_owned(),
        reason.into(),
    )
        .with_metadata("security_impact", impact.to_owned())
}

/// General validation failure.
///
/// Use when validation fails but doesn't fit other categories.
#[inline]
pub(crate) fn validation_failed(
    operation: &str,
    details: impl Into<String>,
) -> AgentError {
    AgentError::config(
        definitions::CFG_VALIDATION_FAILED,
        operation.to_owned(),
        details.into(),
    )
}

/// File I/O read operation failed.
///
/// Never exposes file paths externally - only in internal logs.
#[inline]
pub(crate) fn io_read_error<P: AsRef<Path>>(
    operation: &str,
    path: P,
    error: std::io::Error,
) -> AgentError {
    AgentError::from_io_path(
        definitions::IO_READ_FAILED,
        operation.to_owned(),
        path.as_ref().display().to_string(),
        error,
    )
}

/// File I/O write operation failed.
///
/// Never exposes file paths externally - only in internal logs.
#[inline]
pub(crate) fn io_write_error<P: AsRef<Path>>(
    operation: &str,
    path: P,
    error: std::io::Error,
) -> AgentError {
    AgentError::from_io_path(
        definitions::IO_WRITE_FAILED,
        operation.to_owned(),
        path.as_ref().display().to_string(),
        error,
    )
}

/// File metadata operation failed.
///
/// Use when stat/chmod/chown operations fail.
#[inline]
pub(crate) fn io_metadata_error<P: AsRef<Path>>(
    operation: &str,
    path: P,
    error: std::io::Error,
) -> AgentError {
    AgentError::from_io_path(
        definitions::IO_METADATA_FAILED,
        operation.to_owned(),
        path.as_ref().display().to_string(),
        error,
    )
}

// ============================================================================
// VALIDATION ERROR BUILDERS
// ============================================================================

/// Builder for path validation errors.
///
/// Provides consistent error messages for path-related validation failures.
pub(crate) struct PathValidationError;

impl PathValidationError {
    /// Path is not absolute.
    #[inline]
    pub fn not_absolute(field: &str, operation: &str) -> AgentError {
        invalid_value(
            operation,
            field,
            format!("{} must be an absolute path", field),
        )
    }

    /// Path parent directory doesn't exist.
    #[inline]
    pub fn parent_missing(field: &str, index: Option<usize>, operation: &str) -> AgentError {
        let mut err = validation_failed(
            operation,
            format!("{} parent directory does not exist", field),
        )
        .with_metadata("field", field.to_owned());

        if let Some(idx) = index {
            err = err.with_metadata("path_index", idx.to_string());
        }

        err
    }

    /// Path doesn't exist.
    #[inline]
    pub fn not_found(field: &str, index: Option<usize>, operation: &str) -> AgentError {
        let mut err = validation_failed(
            operation,
            format!("{} does not exist", field),
        )
        .with_metadata("field", field.to_owned());

        if let Some(idx) = index {
            err = err.with_metadata("path_index", idx.to_string());
        }

        err
    }
}

/// Builder for range validation errors.
///
/// British precision for numerical boundaries.
pub(crate) struct RangeValidationError;

impl RangeValidationError {
    /// Value is below minimum.
    #[inline]
    pub fn below_minimum<T: ToString>(
        field: &str,
        actual: T,
        minimum: T,
        operation: &str,
    ) -> AgentError {
        invalid_value_with_range(
            operation,
            field,
            actual.to_string(),
            format!("minimum: {}", minimum.to_string()),
            format!("{} below minimum threshold", field),
        )
    }

    /// Value is above maximum.
    #[inline]
    pub fn above_maximum<T: ToString>(
        field: &str,
        actual: T,
        maximum: T,
        operation: &str,
    ) -> AgentError {
        invalid_value_with_range(
            operation,
            field,
            actual.to_string(),
            format!("maximum: {}", maximum.to_string()),
            format!("{} exceeds maximum threshold", field),
        )
    }

    /// Value is outside valid range.
    #[inline]
    pub fn out_of_range<T: ToString>(
        field: &str,
        actual: T,
        min: T,
        max: T,
        operation: &str,
    ) -> AgentError {
        invalid_value_with_range(
            operation,
            field,
            actual.to_string(),
            format!("{}-{}", min.to_string(), max.to_string()),
            format!("{} must be within valid range", field),
        )
    }
}

/// Builder for collection validation errors.
///
/// For when your arrays have made questionable life choices.
pub(crate) struct CollectionValidationError;

impl CollectionValidationError {
    /// Collection is empty but shouldn't be.
    #[inline]
    pub fn empty(field: &str, impact: &str, operation: &str) -> AgentError {
        missing_required(operation, field, impact)
    }

    /// Collection has duplicate entries.
    #[allow(dead_code)]
    #[inline]
    pub fn duplicate<T: ToString>(
        field: &str,
        value: T,
        operation: &str,
    ) -> AgentError {
        validation_failed(
            operation,
            format!("Duplicate entry in {}: {:?}", field, value.to_string()),
        )
        .with_metadata("field", field.to_owned())
    }
}

// ============================================================================
// PLATFORM-SPECIFIC ERROR HELPERS
// ============================================================================

/// Unix permission validation errors.
#[cfg(unix)]
pub(crate) struct UnixPermissionError;

#[cfg(unix)]
impl UnixPermissionError {
    /// File has insecure permissions.
    #[inline]
    pub fn insecure_permissions(actual_mode: u32, expected_mode: &str) -> AgentError {
        security_violation(
            "validate_file_permissions",
            "Configuration file has insecure permissions",
            "config_disclosure",
        )
        .with_metadata("file_mode", format!("{:o}", actual_mode & 0o777))
        .with_metadata("expected_mode", expected_mode.to_owned())
    }

    /// Directory owned by different user.
    #[allow(dead_code)]
    #[inline]
    pub fn wrong_ownership(dir_uid: u32, current_uid: u32) -> AgentError {
        security_violation(
            "validate_directory_ownership",
            "Work directory owned by different user",
            "privilege_escalation_risk",
        )
        .with_metadata("dir_uid", dir_uid.to_string())
        .with_metadata("current_uid", current_uid.to_string())
    }
}

// ============================================================================
// ENTROPY VALIDATION ERROR HELPERS
// ============================================================================

/// Entropy validation errors for cryptographic tags.
pub(crate) struct EntropyValidationError;

impl EntropyValidationError {
    /// All bytes are zero.
    #[inline]
    pub fn all_zeros() -> AgentError {
        invalid_value(
            "validate_entropy",
            "root_tag",
            "Root tag has insufficient entropy (all zeros)",
        )
    }

    /// Low byte diversity.
    #[inline]
    pub fn low_diversity(unique_count: usize, total_count: usize) -> AgentError {
        invalid_value(
            "validate_entropy",
            "root_tag",
            format!(
                "Root tag has low entropy (only {}/{} unique bytes)",
                unique_count, total_count
            ),
        )
    }

    /// Sequential pattern detected.
    #[inline]
    pub fn sequential_pattern() -> AgentError {
        invalid_value(
            "validate_entropy",
            "root_tag",
            "Root tag appears to be sequential pattern",
        )
    }

    /// Repeated substring detected.
    #[inline]
    pub fn repeated_substring() -> AgentError {
        invalid_value(
            "validate_entropy",
            "root_tag",
            "Root tag contains repeated substrings",
        )
    }

    /// Tag too short.
    #[inline]
    pub fn insufficient_length(actual: usize, minimum: usize) -> AgentError {
        invalid_value_with_range(
            "validate_root_tag",
            "root_tag",
            format!("{} characters", actual),
            format!("minimum {} for 256-bit security", minimum),
            "Root tag too short",
        )
    }

    /// Invalid hex encoding.
    #[inline]
    pub fn invalid_hex(error: hex::FromHexError) -> AgentError {
        invalid_value(
            "validate_root_tag",
            "root_tag",
            format!("Root tag must be valid hex encoding: {}", error),
        )
    }
}

// ============================================================================
// POLICY VALIDATION ERROR HELPERS
// ============================================================================

/// Policy-specific validation errors.
pub(crate) struct PolicyValidationError;

impl PolicyValidationError {
    /// Custom condition not registered.
    #[inline]
    pub fn unregistered_condition(condition_name: &str) -> AgentError {
        validation_failed(
            "validate_policy",
            format!(
                "Custom condition '{}' not in registered_custom_conditions. \
                 Register it to prevent policy injection attacks.",
                condition_name
            ),
        )
    }

    /// Duplicate severity in response rules.
    #[inline]
    pub fn duplicate_severity(severity: &str) -> AgentError {
        validation_failed(
            "validate_policy",
            format!("Duplicate response rule for severity: {}", severity),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_error_is_obfuscated() {
        let err = parse_error("test_op", "test details");
        assert_eq!(*err.code(), definitions::CFG_PARSE_FAILED);
    }

    #[test]
    fn test_version_error_includes_metadata() {
        let err = version_error("test_op", 2, 1, "version mismatch");
        let log = err.internal_log();
        
        let metadata: Vec<_> = log.metadata().iter().map(|(k, _)| *k).collect();
        assert!(metadata.contains(&"file_version"));
        assert!(metadata.contains(&"expected_version"));
    }

    #[test]
    fn test_invalid_value_with_range_includes_context() {
        let err = invalid_value_with_range(
            "test_op",
            "test_field",
            "100",
            "1-10",
            "value out of range",
        );
        
        let log = err.internal_log();
        let metadata: Vec<_> = log.metadata().iter().map(|(k, _)| *k).collect();
        
        assert!(metadata.contains(&"field"));
        assert!(metadata.contains(&"actual_value"));
        assert!(metadata.contains(&"expected_range"));
    }

    #[test]
    fn test_range_validation_helpers() {
        let err = RangeValidationError::below_minimum("count", 5, 10, "test_op");
        assert_eq!(*err.code(), definitions::CFG_INVALID_VALUE);

        let err = RangeValidationError::above_maximum("count", 100, 50, "test_op");
        assert_eq!(*err.code(), definitions::CFG_INVALID_VALUE);

        let err = RangeValidationError::out_of_range("count", 200, 1, 100, "test_op");
        assert_eq!(*err.code(), definitions::CFG_INVALID_VALUE);
    }

    #[test]
    fn test_entropy_validation_helpers() {
        let err = EntropyValidationError::all_zeros();
        assert_eq!(*err.code(), definitions::CFG_INVALID_VALUE);

        let err = EntropyValidationError::low_diversity(5, 32);
        assert_eq!(*err.code(), definitions::CFG_INVALID_VALUE);
    }

    #[test]
    fn test_path_validation_helpers() {
        let err = PathValidationError::not_absolute("test_path", "test_op");
        assert_eq!(*err.code(), definitions::CFG_INVALID_VALUE);

        let err = PathValidationError::parent_missing("test_path", Some(0), "test_op");
        assert_eq!(*err.code(), definitions::CFG_VALIDATION_FAILED);
    }

    #[test]
    fn test_collection_validation_helpers() {
        let err = CollectionValidationError::empty("items", "no_data", "test_op");
        assert_eq!(*err.code(), definitions::CFG_MISSING_REQUIRED);

        let err = CollectionValidationError::duplicate("items", "duplicate_value", "test_op");
        assert_eq!(*err.code(), definitions::CFG_VALIDATION_FAILED);
    }
}
