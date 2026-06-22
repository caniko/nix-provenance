//! PostgreSQL store health check.
//!
//! Probes a core Stalwart table (default `f`) to verify the PostgreSQL
//! datastore is reachable and the schema exists. Used as a safety net when
//! both marker files claim "current" — catches a silently-wiped PostgreSQL
//! data directory (e.g., after a NixOS switch that reinitialised PG).
//!
//! The probe is two-phase: first a bare `SELECT 1` to establish PG is
//! reachable, then `SELECT 1 FROM <table> LIMIT 1` to verify the schema.
//! A connection failure in phase 1 is treated as transient (PG may be
//! restarting); only a phase-2 miss triggers recovery mode.

use std::path::Path;
use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail};

/// Result of the store health check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreHealth {
    /// Store is reachable and the probe table exists.
    Ok,
    /// PostgreSQL is unreachable (connection refused, auth failure,
    /// timeout).  The caller should skip the health check — this is
    /// likely transient and does not mean the schema is gone.
    Unreachable,
    /// PostgreSQL is reachable but the probe table is missing from the
    /// database.  The schema needs to be re-created in recovery mode.
    TableMissing,
    /// The PG password credential file is unreadable or empty.
    CredentialUnreadable,
}

/// Probe a PostgreSQL table to verify the Stalwart store is healthy.
///
/// Phase 1: run `SELECT 1` (bare, no table reference).  If this
/// fails, PostgreSQL is unreachable — return `Unreachable` so the
/// caller can skip.
///
/// Phase 2: run `SELECT 1 FROM <probe_table> LIMIT 1`.  If this
/// fails (PG was reachable in phase 1 so the connection works), the
/// probe table is missing — return `TableMissing`.
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

    // Phase 1: bare connectivity probe (no table reference).
    let connect_ok = Command::new(psql_binary)
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
        .arg("SELECT 1")
        .env("PGPASSWORD", password)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .context("running psql connectivity probe")?
        .success();

    if !connect_ok {
        return Ok(StoreHealth::Unreachable);
    }

    // Phase 2: table probe.
    if !probe_table
        .chars()
        .all(|c| c.is_alphanumeric() || c == '_' || c == '.')
    {
        bail!(
            "probe_table contains invalid characters; use only alphanumeric, underscore, and dot"
        );
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
        .context(format!("running psql table probe: {query}"))?;

    if status.success() {
        Ok(StoreHealth::Ok)
    } else {
        Ok(StoreHealth::TableMissing)
    }
}
