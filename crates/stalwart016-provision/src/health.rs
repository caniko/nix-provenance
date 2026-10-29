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
    password_file: Option<&Path>,
    probe_table: &str,
) -> Result<StoreHealth> {
    // None = peer/trust auth (e.g. Unix socket): no PGPASSWORD.
    let password = match password_file {
        None => None,
        Some(password_file) => {
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
            let password = password.trim().to_owned();
            if password.is_empty() {
                return Ok(StoreHealth::CredentialUnreadable);
            }
            Some(password)
        }
    };
    let psql = |query: &str| {
        let mut cmd = Command::new(psql_binary);
        cmd.args([
            "-h",
            host,
            "-p",
            &port.to_string(),
            "-U",
            user,
            "-d",
            database,
            "-t",
            "-c",
            query,
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null());
        if let Some(pw) = &password {
            cmd.env("PGPASSWORD", pw);
        }
        cmd.status()
    };

    // Phase 1: bare connectivity probe (no table reference).
    let connect_ok = psql("SELECT 1")
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
    let status = psql(&query).context(format!("running psql table probe: {query}"))?;

    if status.success() {
        Ok(StoreHealth::Ok)
    } else {
        Ok(StoreHealth::TableMissing)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// Fake psql: succeeds only if PGPASSWORD is unset and host is a socket dir.
    #[test]
    fn peer_auth_probe_sets_no_password() {
        let dir = std::env::temp_dir().join(format!("pg-peer-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let bin = dir.join("psql");
        std::fs::write(
            &bin,
            "#!/bin/sh\n[ -z \"${PGPASSWORD+x}\" ] && [ \"$2\" = /run/postgresql ] && [ \"$4\" = 5432 ]\n",
        )
        .unwrap();
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        let r = probe_store(
            &bin,
            "/run/postgresql",
            5432,
            "stalwart",
            "stalwart",
            None,
            "t",
        )
        .unwrap();
        assert!(matches!(r, StoreHealth::Ok));
        // With a password file, PGPASSWORD is set so the fake fails -> Unreachable.
        let pw = dir.join("pw");
        std::fs::write(&pw, "x\n").unwrap();
        let r = probe_store(
            &bin,
            "/run/postgresql",
            5432,
            "stalwart",
            "stalwart",
            Some(&pw),
            "t",
        )
        .unwrap();
        assert!(matches!(r, StoreHealth::Unreachable));
        std::fs::remove_dir_all(&dir).ok();
    }
}
