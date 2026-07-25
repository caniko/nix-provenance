//! Runtime password-file and rotation-marker helpers.
//!
//! Password values are read from runtime files and are never serialized into
//! Nix-rendered state. Markers store only a SHA-256 digest of the secret after a
//! platform confirms the password was set.

use std::fs;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::{Error, Result};

/// Read a password from `path`, trimming surrounding whitespace and rejecting
/// empty files.
pub fn read_password_file(path: impl AsRef<Path>) -> Result<String> {
    let path = path.as_ref();
    let value = fs::read_to_string(path)
        .map_err(|source| Error::io(format!("reading password file {}", path.display()), source))?
        .trim()
        .to_owned();
    if value.is_empty() {
        return Err(Error::invalid(format!(
            "password file {} is empty",
            path.display()
        )));
    }
    Ok(value)
}

/// Return a lowercase hex SHA-256 digest for `secret`.
pub fn secret_digest(secret: &str) -> String {
    let digest = Sha256::digest(secret.as_bytes());
    digest
        .iter()
        .fold(String::with_capacity(digest.len() * 2), |mut out, byte| {
            use std::fmt::Write as _;
            write!(out, "{byte:02x}").expect("write to String is infallible");
            out
        })
}

/// Persistent password marker store.
#[derive(Debug, Clone)]
pub struct PasswordMarkerStore {
    dir: PathBuf,
}

impl PasswordMarkerStore {
    /// Create a marker store rooted at `dir`.
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    /// Return true when the marker for `id` is missing or differs from
    /// `secret`'s digest.
    pub fn needs_update(&self, id: &str, secret: &str) -> Result<bool> {
        let desired = secret_digest(secret);
        match fs::read_to_string(self.marker_path(id)) {
            Ok(current) => Ok(current.trim() != desired),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(true),
            Err(err) => Err(Error::io(format!("reading password marker for {id}"), err)),
        }
    }

    /// Return the stored marker digest for `id`, or `None` when no marker has
    /// been recorded.
    pub fn current_digest(&self, id: &str) -> Result<Option<String>> {
        match fs::read_to_string(self.marker_path(id)) {
            Ok(current) => Ok(Some(current.trim().to_owned())),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(Error::io(format!("reading password marker for {id}"), err)),
        }
    }

    /// Record that `secret` was successfully applied for `id`.
    pub fn commit(&self, id: &str, secret: &str) -> Result<()> {
        fs::create_dir_all(&self.dir).map_err(|source| {
            Error::io(
                format!("creating password marker directory {}", self.dir.display()),
                source,
            )
        })?;
        fs::write(self.marker_path(id), format!("{}\n", secret_digest(secret)))
            .map_err(|source| Error::io(format!("writing password marker for {id}"), source))
    }

    /// Mark that an initial password must still be applied for `id`.
    pub fn mark_pending(&self, id: &str) -> Result<()> {
        fs::create_dir_all(&self.dir).map_err(|source| {
            Error::io(
                format!("creating password marker directory {}", self.dir.display()),
                source,
            )
        })?;
        fs::write(self.pending_path(id), b"pending\n").map_err(|source| {
            Error::io(format!("writing pending password marker for {id}"), source)
        })
    }

    /// Clear a pending initial-password marker for `id`, if one exists.
    pub fn clear_pending(&self, id: &str) -> Result<()> {
        match fs::remove_file(self.pending_path(id)) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(Error::io(
                format!("removing pending password marker for {id}"),
                err,
            )),
        }
    }

    /// Return true when an initial password is marked pending for `id`.
    pub fn is_pending(&self, id: &str) -> Result<bool> {
        match fs::metadata(self.pending_path(id)) {
            Ok(meta) => Ok(meta.is_file()),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(err) => Err(Error::io(
                format!("reading pending password marker for {id}"),
                err,
            )),
        }
    }

    fn marker_path(&self, id: &str) -> PathBuf {
        self.dir.join(format!("{}.sha256", marker_filename(id)))
    }

    fn pending_path(&self, id: &str) -> PathBuf {
        self.dir.join(format!("{}.pending", marker_filename(id)))
    }
}

fn marker_filename(id: &str) -> String {
    secret_digest(id)
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    fn temp_path(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before Unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("nix-provenance-{name}-{nanos}"))
    }

    #[test]
    fn password_file_is_trimmed_and_empty_is_rejected() {
        let path = temp_path("password");
        fs::write(&path, " secret \n").unwrap();
        assert_eq!(read_password_file(&path).unwrap(), "secret");
        fs::write(&path, "\n").unwrap();
        assert!(read_password_file(&path).is_err());
        let _ = fs::remove_file(path);
    }

    #[test]
    fn unchanged_marker_skips_and_changed_secret_updates() {
        let dir = temp_path("markers");
        let store = PasswordMarkerStore::new(&dir);
        assert!(
            store
                .needs_update("rauthy:user@example.com", "one")
                .unwrap()
        );
        store.commit("rauthy:user@example.com", "one").unwrap();
        assert!(
            !store
                .needs_update("rauthy:user@example.com", "one")
                .unwrap()
        );
        assert!(
            store
                .needs_update("rauthy:user@example.com", "two")
                .unwrap()
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn pending_marker_round_trips_and_clear_is_idempotent() {
        let dir = temp_path("pending-markers");
        let store = PasswordMarkerStore::new(&dir);
        assert!(!store.is_pending("rauthy:user@example.com").unwrap());
        store.mark_pending("rauthy:user@example.com").unwrap();
        assert!(store.is_pending("rauthy:user@example.com").unwrap());
        store.clear_pending("rauthy:user@example.com").unwrap();
        assert!(!store.is_pending("rauthy:user@example.com").unwrap());
        store.clear_pending("rauthy:user@example.com").unwrap();
        let _ = fs::remove_dir_all(dir);
    }
}
