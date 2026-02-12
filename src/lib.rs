//! # Palisade Config
//!
//! **Security-hardened configuration management for honeypot and deception infrastructure.**
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
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]

// Core modules
mod config;
mod defaults;
mod errors;
mod policy;
mod tags;
mod validation;

// Re-export core types for public API
pub use config::{
    AgentConfig, Config, DeceptionConfig, LogFormat, LogLevel, LoggingConfig, TelemetryConfig,
    ProtectedPath, ProtectedString,
};
pub use policy::{
    ActionType, DeceptionPolicy, PolicyConfig, ResponseCondition, ResponsePolicy, ResponseRule,
    ScoringPolicy, ScoringWeights, Severity,
};
pub use tags::RootTag;
pub use validation::{ConfigChange, PolicyChange, ValidationMode};

// Re-export from palisade-errors for convenience
pub use palisade_errors::{AgentError, Result};

/// Configuration schema version.
pub const CONFIG_VERSION: u32 = 1;

/// Policy schema version (separate from config).
pub const POLICY_VERSION: u32 = 1;