use std::path::PathBuf;

use thiserror::Error;

/// Typed errors for the stalwart016 provisioner.
///
/// Each variant maps to a distinct exit code so systemd and operators can
/// distinguish transient failures (worth retrying) from fatal ones (need
/// manual intervention).
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

    #[error("stalwart-cli query failed for {object}: {detail}")]
    QueryFailed { object: String, detail: String },
}
