use std::path::PathBuf;

use thiserror::Error;

/// Typed errors for the stalwart016 provisioner.
///
/// Each variant maps to a distinct exit code so systemd and operators can
/// distinguish transient failures (worth retrying) from fatal ones (need
/// manual intervention).
#[allow(dead_code)]
#[derive(Error, Debug)]
pub enum ProvisionError {
    #[error("recovery admin password file is missing or empty: {0}")]
    MissingRecoveryPassword(PathBuf),

    #[error("backup sentinel file is missing or empty: {0}")]
    MissingBackupSentinel(PathBuf),

    #[error("port 8080 is already in use — another service is occupying the recovery port")]
    PortConflict,

    #[error(
        "recovery server did not become ready after {attempts} attempts ({interval_secs}s apart)"
    )]
    RecoveryTimeout { attempts: u32, interval_secs: f64 },

    #[error(
        "apply input not readable inside the service sandbox: {path}\n\
             hint: the unit runs with PrivateTmp + ProtectHome + ProtectSystem=strict,\n\
             so host /tmp, /var/tmp and /home are NOT visible. Stage migration inputs\n\
             under a sandbox-visible directory (e.g. /var/lib/stalwart016-migration);\n\
             the module binds migration/apply file parent dirs read-only, but the dir\n\
             must exist at activation."
    )]
    ApplyInputUnreadable { path: PathBuf },

    #[error("stalwart-cli apply failed on {file}: {detail}")]
    ApplyFailed { file: String, detail: String },

    #[error("store health check failed: probe table '{table}' unreachable in {database}")]
    StoreHealthCheck { table: String, database: String },

    #[error("stalwart-cli query failed for {object}: {detail}")]
    QueryFailed { object: String, detail: String },
}

/// Exit codes mapped to failure modes.
///
/// - 0: success
/// - 1: generic failure
/// - 2: transient (recovery timeout, apply failure — systemd should retry)
/// - 3: fatal (missing backup sentinel, port conflict — operator must intervene)
/// - 4: configuration error (unreadable files, etc.)
impl ProvisionError {
    /// Exit codes mapped to failure modes.
    ///
    /// - 0: success
    /// - 1: generic failure
    /// - 2: transient (recovery timeout, apply failure — systemd should retry)
    /// - 3: fatal (missing backup sentinel, port conflict — operator must intervene)
    /// - 4: configuration error (unreadable files, etc.)
    #[allow(dead_code)]
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::RecoveryTimeout { .. } | Self::ApplyFailed { .. } => 2,
            Self::MissingBackupSentinel(_) | Self::PortConflict => 3,
            Self::MissingRecoveryPassword(_)
            | Self::ApplyInputUnreadable { .. }
            | Self::StoreHealthCheck { .. }
            | Self::QueryFailed { .. } => 4,
        }
    }
}
