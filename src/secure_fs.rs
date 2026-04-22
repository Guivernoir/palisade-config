//! Restricted file-loading helpers for security-sensitive configuration input.

use crate::{AgentError, Result};
use heapless::Vec as HVec;
use std::path::Path;

const CFG_SECURITY_VIOLATION: u16 = 107;
const IO_READ_FAILED: u16 = 800;
const IO_METADATA_FAILED: u16 = 802;

/// The class of restricted input being loaded.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum RestrictedInputKind {
    /// Primary agent configuration.
    Config,
    /// Detection and response policy.
    Policy,
}

impl RestrictedInputKind {
    fn metadata_external(&self) -> &'static str {
        match self {
            Self::Config => "Configuration file metadata could not be read",
            Self::Policy => "Policy file metadata could not be read",
        }
    }

    fn read_external(&self) -> &'static str {
        "Configuration input could not be read"
    }

    fn validate_operation(&self) -> &'static str {
        match self {
            Self::Config => "validate_config_file",
            Self::Policy => "validate_policy_file",
        }
    }

    fn load_operation(&self) -> &'static str {
        match self {
            Self::Config => "load_config",
            Self::Policy => "load_policy",
        }
    }
}

/// Read a restricted configuration or policy file with platform-aware safety checks.
pub(crate) async fn read_restricted_file(path: &Path, kind: RestrictedInputKind) -> Result<String> {
    #[cfg(unix)]
    {
        read_restricted_file_unix(path, kind).await
    }

    #[cfg(not(unix))]
    {
        read_restricted_file_portable(path, kind).await
    }
}

/// Read a restricted configuration or policy file into a fixed-capacity byte buffer.
pub(crate) async fn read_restricted_file_bounded<const N: usize>(
    path: &Path,
    kind: RestrictedInputKind,
) -> Result<HVec<u8, N>> {
    #[cfg(unix)]
    {
        read_restricted_file_bounded_unix(path, kind).await
    }

    #[cfg(not(unix))]
    {
        let _ = path;
        let _ = kind;
        Err(AgentError::new(
            CFG_SECURITY_VIOLATION,
            "Configuration was rejected for security reasons",
            "operation=validate_restricted_file; portable file admission is unsupported in hardened no-trust mode; supported_platform=unix",
            "",
        ))
    }
}

#[cfg(unix)]
async fn read_restricted_file_unix(path: &Path, kind: RestrictedInputKind) -> Result<String> {
    use std::fs::OpenOptions;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    use tokio::io::AsyncReadExt;

    let std_file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| {
            if error.raw_os_error() == Some(libc::ELOOP) {
                AgentError::new(
                    CFG_SECURITY_VIOLATION,
                    "Configuration was rejected for security reasons",
                    format!(
                        "operation={}; restricted input must not be a symlink; security_impact=symlink_substitution",
                        kind.validate_operation()
                    ),
                    path.display().to_string(),
                )
            } else {
                AgentError::new(
                    IO_READ_FAILED,
                    kind.read_external(),
                    format!(
                        "operation={}; io_kind={}; open failed",
                        kind.load_operation(),
                        error.kind()
                    ),
                    path.display().to_string(),
                )
            }
        })?;

    let metadata = std_file.metadata().map_err(|error| {
        AgentError::new(
            IO_METADATA_FAILED,
            kind.metadata_external(),
            format!(
                "operation={}; io_kind={}; metadata failed",
                kind.validate_operation(),
                error.kind()
            ),
            path.display().to_string(),
        )
    })?;

    if !metadata.is_file() {
        return Err(AgentError::new(
            CFG_SECURITY_VIOLATION,
            "Configuration was rejected for security reasons",
            format!(
                "operation={}; restricted input must be a regular file; security_impact=unexpected_input_surface",
                kind.validate_operation()
            ),
            path.display().to_string(),
        ));
    }

    let mode = metadata.permissions().mode();
    if (mode & 0o077) != 0 {
        return Err(AgentError::new(
            CFG_SECURITY_VIOLATION,
            "Configuration was rejected for security reasons",
            format!(
                "operation={}; restricted input has insecure permissions; file_mode={:o}; expected_mode=0o600; security_impact=config_disclosure",
                kind.validate_operation(),
                mode & 0o777
            ),
            "",
        ));
    }

    let mut contents = String::new();
    let mut file = tokio::fs::File::from_std(std_file);
    file.read_to_string(&mut contents).await.map_err(|error| {
        AgentError::new(
            IO_READ_FAILED,
            kind.read_external(),
            format!(
                "operation={}; io_kind={}; read failed",
                kind.load_operation(),
                error.kind()
            ),
            path.display().to_string(),
        )
    })?;

    Ok(contents)
}

#[cfg(not(unix))]
async fn read_restricted_file_portable(path: &Path, kind: RestrictedInputKind) -> Result<String> {
    let _ = kind;
    let _ = path;
    Err(AgentError::new(
        CFG_SECURITY_VIOLATION,
        "Configuration was rejected for security reasons",
        "operation=validate_restricted_file; portable file admission is unsupported in hardened no-trust mode; supported_platform=unix",
        "",
    ))
}

#[cfg(unix)]
async fn read_restricted_file_bounded_unix<const N: usize>(
    path: &Path,
    kind: RestrictedInputKind,
) -> Result<HVec<u8, N>> {
    use std::fs::OpenOptions;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    use tokio::io::AsyncReadExt;

    let std_file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| {
            if error.raw_os_error() == Some(libc::ELOOP) {
                AgentError::new(
                    CFG_SECURITY_VIOLATION,
                    "Configuration was rejected for security reasons",
                    format!(
                        "operation={}; restricted input must not be a symlink; security_impact=symlink_substitution",
                        kind.validate_operation()
                    ),
                    path.display().to_string(),
                )
            } else {
                AgentError::new(
                    IO_READ_FAILED,
                    kind.read_external(),
                    format!(
                        "operation={}; io_kind={}; open failed",
                        kind.load_operation(),
                        error.kind()
                    ),
                    path.display().to_string(),
                )
            }
        })?;

    let metadata = std_file.metadata().map_err(|error| {
        AgentError::new(
            IO_METADATA_FAILED,
            kind.metadata_external(),
            format!(
                "operation={}; io_kind={}; metadata failed",
                kind.validate_operation(),
                error.kind()
            ),
            path.display().to_string(),
        )
    })?;

    if !metadata.is_file() {
        return Err(AgentError::new(
            CFG_SECURITY_VIOLATION,
            "Configuration was rejected for security reasons",
            format!(
                "operation={}; restricted input must be a regular file; security_impact=unexpected_input_surface",
                kind.validate_operation()
            ),
            path.display().to_string(),
        ));
    }

    let mode = metadata.permissions().mode();
    if (mode & 0o077) != 0 {
        return Err(AgentError::new(
            CFG_SECURITY_VIOLATION,
            "Configuration was rejected for security reasons",
            format!(
                "operation={}; restricted input has insecure permissions; file_mode={:o}; expected_mode=0o600; security_impact=config_disclosure",
                kind.validate_operation(),
                mode & 0o777
            ),
            "",
        ));
    }

    let mut file = tokio::fs::File::from_std(std_file);
    let mut out = HVec::<u8, N>::new();
    let mut chunk = [0u8; 1024];

    loop {
        let read = file.read(&mut chunk).await.map_err(|error| {
            AgentError::new(
                IO_READ_FAILED,
                kind.read_external(),
                format!(
                    "operation={}; io_kind={}; read failed",
                    kind.load_operation(),
                    error.kind()
                ),
                path.display().to_string(),
            )
        })?;

        if read == 0 {
            break;
        }

        out.extend_from_slice(&chunk[..read]).map_err(|_| {
            AgentError::new(
                IO_READ_FAILED,
                kind.read_external(),
                "operation=read_restricted_file_bounded; file exceeds hardened fixed-capacity limit",
                path.display().to_string(),
            )
        })?;
    }

    Ok(out)
}
