//! PostgreSQL store health check.
//!
//! Probes a core Stalwart table (default `f`) to verify the PostgreSQL
//! datastore is reachable and the schema exists. Used as a safety net when
//! both marker files claim "current" — catches a silently-wiped PostgreSQL
//! data directory (e.g., after a NixOS switch that reinitialised PG).

use std::path::Path;
use std::process::{Command, Stdio};

use anyhow::{Context, Result};

/// Result of the store health check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreHealth {
    /// Store is reachable and the probe table exists.
    Ok,
    /// The probe failed — table missing or connection refused.
    Unreachable,
    /// The PG password credential file is unreadable or empty.
    CredentialUnreadable,
}

/// Probe a PostgreSQL table to verify the Stalwart store is healthy.
///
/// Runs `psql -t -c "SELECT 1 FROM <probe_table> LIMIT 1"` against the
/// configured PostgreSQL instance. Returns `StoreHealth::Unreachable` on
/// any failure (table missing, connection refused, auth failure).
pub fn probe_store(
    psql_binary: &Path,
    host: &str,
    port: u16,
    user: &str,
    database: &str,
    password_file: &Path,
    probe_table: &str,
) -> Result<StoreHealth> {
    let password = match std::fs::read_to_string(password_file) {
        Ok(p) => p,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(StoreHealth::CredentialUnreadable);
        }
        Err(e) => {
            return Err(e).context(format!(
                "reading PG password from {}",
                password_file.display()
            ));
        }
    };

    let password = password.trim();
    if password.is_empty() {
        return Ok(StoreHealth::CredentialUnreadable);
    }

    let query = format!("SELECT 1 FROM {probe_table} LIMIT 1");
    let status = Command::new(psql_binary)
        .arg("-h")
        .arg(host)
        .arg("-p")
        .arg(port.to_string())
        .arg("-U")
        .arg(user)
        .arg("-d")
        .arg(database)
        .arg("-t")
        .arg("-c")
        .arg(&query)
        .env("PGPASSWORD", password)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .context(format!("running psql probe: {query}"))?;

    if status.success() {
        Ok(StoreHealth::Ok)
    } else {
        Ok(StoreHealth::Unreachable)
    }
}
