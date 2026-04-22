//! Narrow operational APIs for configuration and policy workflows.
//!
//! The public operational surface of this crate is centered on two types:
//! [`ConfigApi`] for configuration workflows and [`PolicyApi`] for policy
//! workflows. Their inherent methods are the supported entry points for loading,
//! validating, converting, diffing, and optionally logging operational actions.
//!
//! Both APIs embed validation into their load methods and can apply caller-
//! selected timing floors to normalize their public-path behavior.

use crate::validation::ValidationMode;
use crate::{
    AgentError, Config, ConfigDiff, HardenedConfig, HardenedPolicy, PolicyDiff, PolicyConfig,
    RuntimeConfig, RuntimePolicy,
};
use crate::hardened::{MAX_HARDENED_CONFIG_BYTES, MAX_HARDENED_POLICY_BYTES};
use crate::secure_fs::{RestrictedInputKind, read_restricted_file_bounded};
#[cfg(feature = "log")]
use core::fmt::Write as _;
#[cfg(feature = "log")]
use heapless::String as HString;
#[cfg(feature = "log")]
use std::io;
use std::path::Path;
use std::time::{Duration, Instant};

#[cfg(feature = "log")]
const CFG_VALIDATION_EVENT: u16 = 101;
#[cfg(feature = "log")]
const CFG_LOAD_EVENT: u16 = 108;
#[cfg(feature = "log")]
const CFG_CONVERSION_EVENT: u16 = 121;
#[cfg(feature = "log")]
const CFG_DIFF_EVENT: u16 = 125;
#[cfg(feature = "log")]
const AUDIT_INTERNAL_CAP: usize = 256;
#[cfg(feature = "log")]
const AUDIT_SENSITIVE_CAP: usize = 512;

/// Operational API for configuration workflows.
#[derive(Debug, Default)]
pub struct ConfigApi<'a> {
    validation_mode: ValidationMode,
    timing_floor: Option<Duration>,
    marker: core::marker::PhantomData<&'a Path>,
    #[cfg(feature = "log")]
    logging: ConfigLogging<'a>,
}

impl<'a> ConfigApi<'a> {
    /// Create a configuration API with embedded validation enabled.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Select the validation mode used by this API.
    #[must_use]
    pub fn with_validation_mode(mut self, mode: ValidationMode) -> Self {
        self.validation_mode = mode;
        self
    }

    /// Apply a minimum total duration to this API's operations.
    #[must_use]
    pub fn with_timing_floor(mut self, floor: Duration) -> Self {
        self.timing_floor = Some(floor);
        self
    }

    /// Load, parse, and validate a configuration file.
    pub async fn load_file<P: AsRef<std::path::Path>>(
        &self,
        path: P,
    ) -> std::result::Result<Config, AgentError> {
        let started = Instant::now();
        let path = path.as_ref();
        let result = Config::from_file_with_mode(path, &self.validation_mode).await;
        self.finish_result(
            started,
            result,
            #[cfg(feature = "log")]
            Some(("config.load_file.success", path)),
        )
    }

    /// Load, parse, and validate configuration from TOML text.
    pub fn load_str(&self, contents: &str) -> std::result::Result<Config, AgentError> {
        let started = Instant::now();
        let result = Config::from_toml_str_with_mode(contents, &self.validation_mode);
        self.finish_result(
            started,
            result,
            #[cfg(feature = "log")]
            Some(("config.load_str.success", Path::new("<inline-config>"))),
        )
    }

    /// Validate an already-constructed configuration with this API's mode.
    pub fn validate(&self, config: &Config) -> std::result::Result<(), AgentError> {
        let started = Instant::now();
        let result = config.validate_with_mode(&self.validation_mode);
        self.finish_result(
            started,
            result,
            #[cfg(feature = "log")]
            Some(("config.validate.success", Path::new("<in-memory-config>"))),
        )
    }

    /// Convert a configuration to its runtime representation.
    pub fn to_runtime(&self, config: &Config) -> std::result::Result<RuntimeConfig, AgentError> {
        let started = Instant::now();
        let result = config.to_runtime();
        self.finish_result(
            started,
            result,
            #[cfg(feature = "log")]
            Some(("config.runtime.success", Path::new("<runtime-config>"))),
        )
    }

    /// Load, parse, validate, and convert configuration directly into the
    /// fixed-capacity runtime representation.
    pub async fn load_runtime_file<P: AsRef<std::path::Path>>(
        &self,
        path: P,
    ) -> std::result::Result<RuntimeConfig, AgentError> {
        let started = Instant::now();
        let path = path.as_ref();
        let result = async {
            let bytes =
                read_restricted_file_bounded::<MAX_HARDENED_CONFIG_BYTES>(path, RestrictedInputKind::Config)
                    .await?;
            let contents = std::str::from_utf8(bytes.as_slice()).map_err(|_| {
                AgentError::new(
                    100,
                    "Configuration input could not be parsed",
                    "operation=parse_hardened_config_toml; input is not valid UTF-8",
                    "",
                )
            })?;
            let hardened = HardenedConfig::from_str_with_mode(contents, &self.validation_mode)?;
            Ok(hardened.into_runtime())
        }
        .await;
        self.finish_result(
            started,
            result,
            #[cfg(feature = "log")]
            Some(("config.load_runtime_file.success", path)),
        )
    }

    /// Load, parse, validate, and convert configuration text directly into the
    /// fixed-capacity runtime representation.
    pub fn load_runtime_str(&self, contents: &str) -> std::result::Result<RuntimeConfig, AgentError> {
        let started = Instant::now();
        let result = HardenedConfig::from_str_with_mode(contents, &self.validation_mode)
            .map(HardenedConfig::into_runtime);
        self.finish_result(
            started,
            result,
            #[cfg(feature = "log")]
            Some(("config.load_runtime_str.success", Path::new("<inline-runtime-config>"))),
        )
    }

    /// Diff two configurations.
    pub fn diff<'b>(
        &self,
        current: &'b Config,
        next: &'b Config,
    ) -> std::result::Result<ConfigDiff<'b>, AgentError> {
        let started = Instant::now();
        let changes = current.diff(next)?;
        #[cfg(feature = "log")]
        if self.logging.log_diffs {
            self.log_diff_action("config.diff.success", changes.len())?;
        }
        self.finish_success(started);
        Ok(changes)
    }

    /// Enable hardened audit persistence to `path`.
    #[cfg(feature = "log")]
    #[cfg_attr(docsrs, doc(cfg(feature = "log")))]
    #[must_use]
    pub fn with_log_path(mut self, path: &'a Path) -> Self {
        self.logging.path = Some(path);
        self.logging.log_errors = true;
        self
    }

    /// Configure whether operation errors are persisted.
    #[cfg(feature = "log")]
    #[cfg_attr(docsrs, doc(cfg(feature = "log")))]
    #[must_use]
    pub fn log_errors(mut self, enabled: bool) -> Self {
        self.logging.log_errors = enabled;
        self
    }

    /// Configure whether successful load actions are persisted.
    #[cfg(feature = "log")]
    #[cfg_attr(docsrs, doc(cfg(feature = "log")))]
    #[must_use]
    pub fn log_loads(mut self, enabled: bool) -> Self {
        self.logging.log_loads = enabled;
        self
    }

    /// Configure whether successful validation actions are persisted.
    #[cfg(feature = "log")]
    #[cfg_attr(docsrs, doc(cfg(feature = "log")))]
    #[must_use]
    pub fn log_validations(mut self, enabled: bool) -> Self {
        self.logging.log_validations = enabled;
        self
    }

    /// Configure whether successful runtime-conversion actions are persisted.
    #[cfg(feature = "log")]
    #[cfg_attr(docsrs, doc(cfg(feature = "log")))]
    #[must_use]
    pub fn log_runtime_builds(mut self, enabled: bool) -> Self {
        self.logging.log_runtime_builds = enabled;
        self
    }

    /// Configure whether diff actions are persisted.
    #[cfg(feature = "log")]
    #[cfg_attr(docsrs, doc(cfg(feature = "log")))]
    #[must_use]
    pub fn log_diffs(mut self, enabled: bool) -> Self {
        self.logging.log_diffs = enabled;
        self
    }

    fn finish_result<T>(
        &self,
        started: Instant,
        result: std::result::Result<T, AgentError>,
        #[cfg(feature = "log")] success_action: Option<(&str, &Path)>,
    ) -> std::result::Result<T, AgentError> {
        match result {
            Ok(value) => {
                #[cfg(feature = "log")]
                if let Some((action, sensitive)) = success_action {
                    self.log_success_for_action(action, sensitive)?;
                }
                self.finish_success(started);
                Ok(value)
            }
            Err(error) => {
                #[cfg(feature = "log")]
                if let Err(log_failure) = self.logging.log_error(&error) {
                    return Err(self.normalize_error(log_failure, started));
                }
                Err(self.normalize_error(error, started))
            }
        }
    }

    fn finish_success(&self, started: Instant) {
        if let Some(floor) = self.timing_floor {
            let target = started + floor;
            while Instant::now() < target {
                std::hint::spin_loop();
            }
        }
    }

    fn normalize_error(&self, error: AgentError, _started: Instant) -> AgentError {
        if let Some(floor) = self.timing_floor {
            error.with_timing_normalization(floor)
        } else {
            error
        }
    }

    #[cfg(feature = "log")]
    fn log_success_for_action(
        &self,
        action: &str,
        sensitive: &Path,
    ) -> std::result::Result<(), AgentError> {
        let should_log = match action {
            "config.load_file.success" | "config.load_str.success" => self.logging.log_loads,
            "config.load_runtime_file.success" | "config.load_runtime_str.success" => {
                self.logging.log_loads
            }
            "config.validate.success" => self.logging.log_validations,
            "config.runtime.success" => self.logging.log_runtime_builds,
            _ => false,
        };

        if should_log {
            let mut internal = new_audit_buffer("config.log_success_for_action")?;
            write!(&mut internal, "action={action}; validation_mode={:?}", self.validation_mode)
                .map_err(|_| audit_buffer_overflow("config.log_success_for_action"))?;

            let sensitive = path_to_audit_text(sensitive, "config.log_success_for_action")?;
            self.log_action(
                match action {
                    "config.runtime.success" => CFG_CONVERSION_EVENT,
                    "config.validate.success" => CFG_VALIDATION_EVENT,
                    _ => CFG_LOAD_EVENT,
                },
                "Configuration API action recorded",
                internal,
                sensitive,
            )?;
        }

        Ok(())
    }

    #[cfg(feature = "log")]
    fn log_diff_action(
        &self,
        action: &str,
        change_count: usize,
    ) -> std::result::Result<(), AgentError> {
        let mut internal = new_audit_buffer("config.log_diff_action")?;
        write!(&mut internal, "action={action}; change_count={change_count}")
            .map_err(|_| audit_buffer_overflow("config.log_diff_action"))?;
        self.log_action(
            CFG_DIFF_EVENT,
            "Configuration API action recorded",
            internal,
            "<config-diff>",
        )
    }

    #[cfg(feature = "log")]
    fn log_action<I: AsRef<str>, S: AsRef<str>>(
        &self,
        code: u16,
        external: &str,
        internal: I,
        sensitive: S,
    ) -> std::result::Result<(), AgentError> {
        self.logging
            .log_record(code, external, internal.as_ref(), sensitive.as_ref())
    }
}

/// Operational API for policy workflows.
#[derive(Debug, Default)]
pub struct PolicyApi<'a> {
    timing_floor: Option<Duration>,
    marker: core::marker::PhantomData<&'a Path>,
    #[cfg(feature = "log")]
    logging: PolicyLogging<'a>,
}

impl<'a> PolicyApi<'a> {
    /// Create a policy API with embedded validation enabled.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Apply a minimum total duration to this API's operations.
    #[must_use]
    pub fn with_timing_floor(mut self, floor: Duration) -> Self {
        self.timing_floor = Some(floor);
        self
    }

    /// Load, parse, and validate a policy file.
    pub async fn load_file<P: AsRef<std::path::Path>>(
        &self,
        path: P,
    ) -> std::result::Result<PolicyConfig, AgentError> {
        let started = Instant::now();
        let path = path.as_ref();
        let result = PolicyConfig::from_file(path).await;
        self.finish_result(
            started,
            result,
            #[cfg(feature = "log")]
            Some(("policy.load_file.success", path)),
        )
    }

    /// Load, parse, and validate policy from TOML text.
    pub fn load_str(&self, contents: &str) -> std::result::Result<PolicyConfig, AgentError> {
        let started = Instant::now();
        let result = PolicyConfig::from_toml_str(contents);
        self.finish_result(
            started,
            result,
            #[cfg(feature = "log")]
            Some(("policy.load_str.success", Path::new("<inline-policy>"))),
        )
    }

    /// Validate an already-constructed policy.
    pub fn validate(&self, policy: &PolicyConfig) -> std::result::Result<(), AgentError> {
        let started = Instant::now();
        let result = policy.validate();
        self.finish_result(
            started,
            result,
            #[cfg(feature = "log")]
            Some(("policy.validate.success", Path::new("<in-memory-policy>"))),
        )
    }

    /// Convert a policy to its runtime representation.
    pub fn to_runtime(
        &self,
        policy: &PolicyConfig,
    ) -> std::result::Result<RuntimePolicy, AgentError> {
        let started = Instant::now();
        let result = policy.to_runtime();
        self.finish_result(
            started,
            result,
            #[cfg(feature = "log")]
            Some(("policy.runtime.success", Path::new("<runtime-policy>"))),
        )
    }

    /// Load, parse, validate, and convert policy directly into the fixed-capacity
    /// runtime representation.
    pub async fn load_runtime_file<P: AsRef<std::path::Path>>(
        &self,
        path: P,
    ) -> std::result::Result<RuntimePolicy, AgentError> {
        let started = Instant::now();
        let path = path.as_ref();
        let result = async {
            let bytes =
                read_restricted_file_bounded::<MAX_HARDENED_POLICY_BYTES>(path, RestrictedInputKind::Policy)
                    .await?;
            let contents = std::str::from_utf8(bytes.as_slice()).map_err(|_| {
                AgentError::new(
                    100,
                    "Configuration input could not be parsed",
                    "operation=parse_hardened_policy_toml; input is not valid UTF-8",
                    "",
                )
            })?;
            let hardened = HardenedPolicy::from_str(contents)?;
            Ok(hardened.into_runtime())
        }
        .await;
        self.finish_result(
            started,
            result,
            #[cfg(feature = "log")]
            Some(("policy.load_runtime_file.success", path)),
        )
    }

    /// Load, parse, validate, and convert policy text directly into the fixed-capacity
    /// runtime representation.
    pub fn load_runtime_str(&self, contents: &str) -> std::result::Result<RuntimePolicy, AgentError> {
        let started = Instant::now();
        let result = HardenedPolicy::from_str(contents).map(HardenedPolicy::into_runtime);
        self.finish_result(
            started,
            result,
            #[cfg(feature = "log")]
            Some(("policy.load_runtime_str.success", Path::new("<inline-runtime-policy>"))),
        )
    }

    /// Diff two policies.
    pub fn diff<'b>(
        &self,
        current: &'b PolicyConfig,
        next: &'b PolicyConfig,
    ) -> std::result::Result<PolicyDiff<'b>, AgentError> {
        let started = Instant::now();
        let changes = current.diff(next)?;
        #[cfg(feature = "log")]
        if self.logging.log_diffs {
            self.log_diff_action("policy.diff.success", changes.len())?;
        }
        self.finish_success(started);
        Ok(changes)
    }

    /// Run the suspicious-process check through the policy API.
    pub fn is_suspicious_process(
        &self,
        policy: &PolicyConfig,
        name: &str,
    ) -> std::result::Result<bool, AgentError> {
        let started = Instant::now();
        let found = policy.is_suspicious_process(name);
        #[cfg(feature = "log")]
        if self.logging.log_checks {
            self.log_check_action("policy.is_suspicious_process", found, name)?;
        }
        self.finish_success(started);
        Ok(found)
    }

    /// Enable hardened error persistence to `path`.
    #[cfg(feature = "log")]
    #[cfg_attr(docsrs, doc(cfg(feature = "log")))]
    #[must_use]
    pub fn with_log_path(mut self, path: &'a Path) -> Self {
        self.logging.path = Some(path);
        self.logging.log_errors = true;
        self
    }

    /// Configure whether operation errors are persisted.
    #[cfg(feature = "log")]
    #[cfg_attr(docsrs, doc(cfg(feature = "log")))]
    #[must_use]
    pub fn log_errors(mut self, enabled: bool) -> Self {
        self.logging.log_errors = enabled;
        self
    }

    /// Configure whether successful load actions are persisted.
    #[cfg(feature = "log")]
    #[cfg_attr(docsrs, doc(cfg(feature = "log")))]
    #[must_use]
    pub fn log_loads(mut self, enabled: bool) -> Self {
        self.logging.log_loads = enabled;
        self
    }

    /// Configure whether successful validation actions are persisted.
    #[cfg(feature = "log")]
    #[cfg_attr(docsrs, doc(cfg(feature = "log")))]
    #[must_use]
    pub fn log_validations(mut self, enabled: bool) -> Self {
        self.logging.log_validations = enabled;
        self
    }

    /// Configure whether successful runtime-conversion actions are persisted.
    #[cfg(feature = "log")]
    #[cfg_attr(docsrs, doc(cfg(feature = "log")))]
    #[must_use]
    pub fn log_runtime_builds(mut self, enabled: bool) -> Self {
        self.logging.log_runtime_builds = enabled;
        self
    }

    /// Configure whether diff actions are persisted.
    #[cfg(feature = "log")]
    #[cfg_attr(docsrs, doc(cfg(feature = "log")))]
    #[must_use]
    pub fn log_diffs(mut self, enabled: bool) -> Self {
        self.logging.log_diffs = enabled;
        self
    }

    /// Configure whether suspicious-process checks are persisted.
    #[cfg(feature = "log")]
    #[cfg_attr(docsrs, doc(cfg(feature = "log")))]
    #[must_use]
    pub fn log_checks(mut self, enabled: bool) -> Self {
        self.logging.log_checks = enabled;
        self
    }

    fn finish_result<T>(
        &self,
        started: Instant,
        result: std::result::Result<T, AgentError>,
        #[cfg(feature = "log")] success_action: Option<(&str, &Path)>,
    ) -> std::result::Result<T, AgentError> {
        match result {
            Ok(value) => {
                #[cfg(feature = "log")]
                if let Some((action, sensitive)) = success_action {
                    self.log_success_for_action(action, sensitive)?;
                }
                self.finish_success(started);
                Ok(value)
            }
            Err(error) => {
                #[cfg(feature = "log")]
                if let Err(log_failure) = self.logging.log_error(&error) {
                    return Err(self.normalize_error(log_failure, started));
                }
                Err(self.normalize_error(error, started))
            }
        }
    }

    fn finish_success(&self, started: Instant) {
        if let Some(floor) = self.timing_floor {
            let target = started + floor;
            while Instant::now() < target {
                std::hint::spin_loop();
            }
        }
    }

    fn normalize_error(&self, error: AgentError, _started: Instant) -> AgentError {
        if let Some(floor) = self.timing_floor {
            error.with_timing_normalization(floor)
        } else {
            error
        }
    }

    #[cfg(feature = "log")]
    fn log_success_for_action(
        &self,
        action: &str,
        sensitive: &Path,
    ) -> std::result::Result<(), AgentError> {
        let should_log = match action {
            "policy.load_file.success" | "policy.load_str.success" => self.logging.log_loads,
            "policy.load_runtime_file.success" | "policy.load_runtime_str.success" => {
                self.logging.log_loads
            }
            "policy.validate.success" => self.logging.log_validations,
            "policy.runtime.success" => self.logging.log_runtime_builds,
            _ => false,
        };

        if should_log {
            let mut internal = new_audit_buffer("policy.log_success_for_action")?;
            write!(&mut internal, "action={action}")
                .map_err(|_| audit_buffer_overflow("policy.log_success_for_action"))?;
            let sensitive = path_to_audit_text(sensitive, "policy.log_success_for_action")?;
            self.log_action(
                match action {
                    "policy.runtime.success" => CFG_CONVERSION_EVENT,
                    "policy.validate.success" => CFG_VALIDATION_EVENT,
                    _ => CFG_LOAD_EVENT,
                },
                "Policy API action recorded",
                internal,
                sensitive,
            )?;
        }

        Ok(())
    }

    #[cfg(feature = "log")]
    fn log_diff_action(
        &self,
        action: &str,
        change_count: usize,
    ) -> std::result::Result<(), AgentError> {
        let mut internal = new_audit_buffer("policy.log_diff_action")?;
        write!(&mut internal, "action={action}; change_count={change_count}")
            .map_err(|_| audit_buffer_overflow("policy.log_diff_action"))?;
        self.log_action(
            CFG_DIFF_EVENT,
            "Policy API action recorded",
            internal,
            "<policy-diff>",
        )
    }

    #[cfg(feature = "log")]
    fn log_check_action(
        &self,
        action: &str,
        found: bool,
        name: &str,
    ) -> std::result::Result<(), AgentError> {
        let mut internal = new_audit_buffer("policy.log_check_action")?;
        write!(&mut internal, "action={action}; found={found}")
            .map_err(|_| audit_buffer_overflow("policy.log_check_action"))?;
        self.log_action(
            CFG_VALIDATION_EVENT,
            "Policy API action recorded",
            internal,
            name,
        )
    }

    #[cfg(feature = "log")]
    fn log_action<I: AsRef<str>, S: AsRef<str>>(
        &self,
        code: u16,
        external: &str,
        internal: I,
        sensitive: S,
    ) -> std::result::Result<(), AgentError> {
        self.logging
            .log_record(code, external, internal.as_ref(), sensitive.as_ref())
    }
}

#[cfg(feature = "log")]
fn log_write_failure(context: &str, path: &Path, error: &io::Error) -> AgentError {
    let mut internal = HString::<AUDIT_INTERNAL_CAP>::new();
    let _ = write!(
        &mut internal,
        "operation={context}; io_kind={}; encrypted audit persistence failed",
        error.kind()
    );
    let sensitive = path_to_audit_text(path, context)
        .unwrap_or_else(|_| {
            let mut fallback = HString::<AUDIT_SENSITIVE_CAP>::new();
            let _ = fallback.push_str("<audit-path-overflow>");
            fallback
        });
    AgentError::new(
        611,
        "Audit operation failed",
        internal,
        sensitive,
    )
}

#[cfg(feature = "log")]
#[derive(Debug, Default)]
struct ConfigLogging<'a> {
    path: Option<&'a Path>,
    log_errors: bool,
    log_loads: bool,
    log_validations: bool,
    log_runtime_builds: bool,
    log_diffs: bool,
}

#[cfg(feature = "log")]
impl<'a> ConfigLogging<'a> {
    fn log_error(&self, error: &AgentError) -> std::result::Result<(), AgentError> {
        if self.log_errors
            && let Some(path) = self.path.as_deref()
        {
            error
                .log(path)
                .map_err(|log_error| log_write_failure("config.log_error", path, &log_error))?;
        }

        Ok(())
    }

    fn log_record(
        &self,
        code: u16,
        external: &str,
        internal: &str,
        sensitive: &str,
    ) -> std::result::Result<(), AgentError> {
        if let Some(path) = self.path.as_deref() {
            let record = AgentError::new(code, external, internal, sensitive);
            record
                .log(path)
                .map_err(|log_error| log_write_failure("config.log_record", path, &log_error))?;
        }

        Ok(())
    }
}

#[cfg(feature = "log")]
#[derive(Debug, Default)]
struct PolicyLogging<'a> {
    path: Option<&'a Path>,
    log_errors: bool,
    log_loads: bool,
    log_validations: bool,
    log_runtime_builds: bool,
    log_diffs: bool,
    log_checks: bool,
}

#[cfg(feature = "log")]
impl<'a> PolicyLogging<'a> {
    fn log_error(&self, error: &AgentError) -> std::result::Result<(), AgentError> {
        if self.log_errors
            && let Some(path) = self.path.as_deref()
        {
            error
                .log(path)
                .map_err(|log_error| log_write_failure("policy.log_error", path, &log_error))?;
        }

        Ok(())
    }

    fn log_record(
        &self,
        code: u16,
        external: &str,
        internal: &str,
        sensitive: &str,
    ) -> std::result::Result<(), AgentError> {
        if let Some(path) = self.path.as_deref() {
            let record = AgentError::new(code, external, internal, sensitive);
            record
                .log(path)
                .map_err(|log_error| log_write_failure("policy.log_record", path, &log_error))?;
        }

        Ok(())
    }
}

#[cfg(feature = "log")]
fn new_audit_buffer(context: &str) -> std::result::Result<HString<AUDIT_INTERNAL_CAP>, AgentError> {
    let _ = context;
    Ok(HString::new())
}

#[cfg(feature = "log")]
fn audit_buffer_overflow(context: &str) -> AgentError {
    let mut internal = HString::<AUDIT_INTERNAL_CAP>::new();
    let _ = write!(
        &mut internal,
        "operation={context}; fixed-capacity audit buffer overflow"
    );
    AgentError::new(611, "Audit operation failed", internal, context)
}

#[cfg(feature = "log")]
fn path_to_audit_text(
    path: &Path,
    context: &str,
) -> std::result::Result<HString<AUDIT_SENSITIVE_CAP>, AgentError> {
    let mut sensitive = HString::<AUDIT_SENSITIVE_CAP>::new();
    write!(&mut sensitive, "{}", path.display()).map_err(|_| audit_buffer_overflow(context))?;
    Ok(sensitive)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::get_timing_floor;

    #[cfg(feature = "log")]
    const VALID_ROOT_TAG: &str = "8f2a7c91d4e6b3f0c5a19e274bd86370f1c49a2e6d8b35c7e902a4f1b6d3c8e5";

    #[test]
    fn config_api_load_str_embeds_validation() {
        let api = ConfigApi::new();
        let invalid = r#"
            version = 1

            [agent]
            instance_id = ""
            work_dir = "/var/lib/palisade"

            [deception]
            decoy_paths = ["/tmp/.creds"]
            credential_types = ["aws"]
            root_tag = "8f2a7c91d4e6b3f0c5a19e274bd86370f1c49a2e6d8b35c7e902a4f1b6d3c8e5"

            [telemetry]
            watch_paths = ["/tmp"]

            [logging]
            log_path = "/var/log/palisade.log"
        "#;

        let err = api.load_str(invalid).unwrap_err();
        assert_eq!(err.to_string(), "Required configuration is missing");
    }

    #[test]
    fn policy_api_load_str_embeds_validation() {
        let api = PolicyApi::new();
        let invalid = r#"
            version = 1

            [scoring]
            alert_threshold = 101.0
            correlation_window_secs = 300
            max_events_in_memory = 1000
            enable_time_scoring = true
            enable_ancestry_tracking = true
            business_hours_start = 9
            business_hours_end = 17

            [response]
            cooldown_secs = 60
            max_kills_per_incident = 10
            dry_run = false

            [[response.rules]]
            severity = "Low"
            action = "log"

            [deception]
            suspicious_processes = ["mimikatz"]
            suspicious_patterns = ["/tmp/.creds"]
        "#;

        let err = api.load_str(invalid).unwrap_err();
        assert_eq!(err.to_string(), "Configuration contains an invalid value");
    }

    #[test]
    fn config_api_timing_floor_normalizes_error_path() {
        let api = ConfigApi::new().with_timing_floor(Duration::from_millis(5));
        let started = Instant::now();
        let _ = api.load_str("not valid toml = [");
        assert!(started.elapsed() >= Duration::from_millis(5));
    }

    #[test]
    fn global_timing_floor_is_available_alongside_apis() {
        assert!(get_timing_floor() >= Duration::ZERO);
    }

    #[test]
    fn config_api_can_load_runtime_directly_from_text() {
        let api = ConfigApi::new();
        let valid = r#"
            version = 1

            [agent]
            instance_id = "demo-agent"
            hostname = "demo-host"
            work_dir = "/var/lib/palisade"

            [deception]
            decoy_paths = ["/tmp/.creds"]
            credential_types = ["aws"]
            root_tag = "8f2a7c91d4e6b3f0c5a19e274bd86370f1c49a2e6d8b35c7e902a4f1b6d3c8e5"

            [telemetry]
            watch_paths = ["/tmp"]

            [logging]
            log_path = "/var/log/palisade.log"
        "#;

        let runtime = api.load_runtime_str(valid).expect("runtime config");
        assert_eq!(runtime.hostname.as_str(), "demo-host");
        assert_eq!(runtime.decoy_paths.len(), 1);
    }

    #[test]
    fn policy_api_can_load_runtime_directly_from_text() {
        let api = PolicyApi::new();
        let valid = r#"
            version = 1

            [scoring]
            alert_threshold = 50.0

            [response]
            cooldown_secs = 60

            [[response.rules]]
            severity = "Low"
            action = "log"

            registered_custom_conditions = []

            [deception]
            suspicious_processes = ["mimikatz"]
            suspicious_patterns = [".aws/credentials"]
        "#;

        let runtime = api.load_runtime_str(valid).expect("runtime policy");
        assert_eq!(runtime.alert_threshold, 50.0);
        assert!(runtime.is_suspicious_process("mimikatz.exe"));
    }

    #[cfg(feature = "log")]
    #[test]
    fn config_api_can_log_success_actions() {
        let dir = tempfile::tempdir().expect("tempdir");
        let log_path = dir.path().join("config-audit.log");
        let api = ConfigApi::new().with_log_path(&log_path).log_loads(true);

        let valid = format!(
            r#"
            version = 1

            [agent]
            instance_id = "demo-agent"
            work_dir = "/var/lib/palisade"

            [deception]
            decoy_paths = ["/tmp/.creds"]
            credential_types = ["aws"]
            root_tag = "{VALID_ROOT_TAG}"

            [telemetry]
            watch_paths = ["/tmp"]

            [logging]
            log_path = "/var/log/palisade.log"
        "#
        );

        let _ = api.load_str(&valid).expect("load config");
        assert!(log_path.exists());
    }

    #[cfg(feature = "log")]
    #[test]
    fn policy_api_can_log_errors() {
        let dir = tempfile::tempdir().expect("tempdir");
        let log_path = dir.path().join("policy-errors.log");
        let api = PolicyApi::new().with_log_path(&log_path).log_errors(true);

        let invalid = "not valid toml";
        let _ = api.load_str(invalid);
        assert!(log_path.exists());
    }

    #[cfg(feature = "log")]
    #[test]
    fn config_api_fails_closed_when_success_logging_cannot_persist() {
        let api = ConfigApi::new()
            .with_log_path(Path::new("relative-config-audit.log"))
            .log_loads(true);

        let valid = format!(
            r#"
            version = 1

            [agent]
            instance_id = "demo-agent"
            work_dir = "/var/lib/palisade"

            [deception]
            decoy_paths = ["/tmp/.creds"]
            credential_types = ["aws"]
            root_tag = "{VALID_ROOT_TAG}"

            [telemetry]
            watch_paths = ["/tmp"]

            [logging]
            log_path = "/var/log/palisade.log"
        "#
        );

        let err = api
            .load_str(&valid)
            .expect_err("relative log path should fail closed");
        assert_eq!(err.to_string(), "Audit operation failed");
    }

    #[cfg(feature = "log")]
    #[test]
    fn config_api_diff_fails_closed_when_audit_logging_cannot_persist() {
        let api = ConfigApi::new()
            .with_log_path(Path::new("relative-config-diff-audit.log"))
            .log_diffs(true);

        let current = Config::default();
        let mut next = Config::default();
        next.telemetry.enable_syscall_monitor = !current.telemetry.enable_syscall_monitor;

        let err = api
            .diff(&current, &next)
            .expect_err("relative log path should fail closed");
        assert_eq!(err.to_string(), "Audit operation failed");
    }

    #[cfg(feature = "log")]
    #[test]
    fn policy_api_fails_closed_when_error_logging_cannot_persist() {
        let api = PolicyApi::new()
            .with_log_path(Path::new("relative-policy-audit.log"))
            .log_errors(true);

        let err = api
            .load_str("not valid toml")
            .expect_err("relative log path should fail closed");
        assert_eq!(err.to_string(), "Audit operation failed");
    }

    #[cfg(feature = "log")]
    #[test]
    fn policy_api_check_fails_closed_when_audit_logging_cannot_persist() {
        let api = PolicyApi::new()
            .with_log_path(Path::new("relative-policy-check-audit.log"))
            .log_checks(true);

        let err = api
            .is_suspicious_process(&PolicyConfig::default(), "mimikatz")
            .expect_err("relative log path should fail closed");
        assert_eq!(err.to_string(), "Audit operation failed");
    }
}
