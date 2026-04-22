//! # Palisade Config
//!
//! **Security-hardened configuration management for honeypot and deception infrastructure.**
//!
//! ## Public Interface
//!
//! The operational public surface is centered on two types:
//!
//! - [`ConfigApi`] for configuration loading, validation, runtime conversion,
//!   diffing, and optional action logging
//! - [`PolicyApi`] for policy loading, validation, runtime conversion, runtime
//!   checks, diffing, and optional action logging
//!
//! The underlying typed models remain public for direct data access and
//! serialization, but the API types are the preferred entry points for normal
//! operational use.
//!
//! # Core Security Properties
//!
//! - **Memory Protection**: All sensitive data automatically zeroized on drop
//! - **Cryptographic Isolation**: Tag derivation prevents artifact correlation
//! - **Validation Defense-in-Depth**: Multiple validation layers
//! - **Error Obfuscation**: Dual-layer error handling

#![warn(missing_docs)]
#![warn(clippy::all)]
#![warn(clippy::pedantic)]
#![warn(clippy::unwrap_used)]
#![deny(unsafe_code)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]

// Core modules
mod api;
mod config;
mod defaults;
mod hardened;
mod policy;
mod runtime;
mod secure_fs;
mod tags;
mod timing;
mod validation;

// Re-export core types for public API
pub use api::{ConfigApi, PolicyApi};
pub use config::{
    AgentConfig, Config, DeceptionConfig, LogFormat, LogLevel, LoggingConfig, ProtectedPath,
    ProtectedString, TelemetryConfig,
};
pub use hardened::{HardenedConfig, HardenedPolicy};
pub use policy::{
    ActionType, DeceptionPolicy, PolicyConfig, ResponseCondition, ResponsePolicy, ResponseRule,
    ScoringPolicy, ScoringWeights, Severity,
};
pub use runtime::{RuntimeConfig, RuntimePolicy};
pub use tags::RootTag;
pub use timing::{DEFAULT_TIMING_FLOOR, get_timing_floor, set_timing_floor};
pub use validation::{ConfigChange, ConfigDiff, PolicyChange, PolicyDiff, ValidationMode};

// Re-export from palisade-errors for convenience
pub use palisade_errors::AgentError;

/// Standard result type used throughout this crate.
pub type Result<T> = std::result::Result<T, AgentError>;

/// Configuration schema version.
pub const CONFIG_VERSION: u32 = 1;

/// Policy schema version (separate from config).
pub const POLICY_VERSION: u32 = 1;
