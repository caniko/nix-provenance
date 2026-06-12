//! Runtime password-file and rotation-marker helpers.
//!
//! Password values are read from runtime files and are never serialized into
//! Nix-rendered state. Markers store only a SHA-256 digest of the secret after a
//! platform confirms the password was set.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};

/// Read a password from `path`, trimming surrounding whitespace and rejecting
/// empty files.
pub fn read_password_file(path: impl AsRef<Path>) -> Result<String> {
    let path = path.as_ref();
    let value = fs::read_to_string(path)
        .with_context(|| format!("reading password file {}", path.display()))?
        .trim()
        .to_owned();
    if value.is_empty() {
        bail!("password file {} is empty", path.display());
    }
    Ok(value)
}

/// Return a lowercase hex SHA-256 digest for `secret`.
pub fn secret_digest(secret: &str) -> String {
    let digest = Sha256::digest(secret.as_bytes());
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    out
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
            Err(err) => Err(err).with_context(|| format!("reading password marker for {id}")),
        }
    }

    /// Record that `secret` was successfully applied for `id`.
    pub fn commit(&self, id: &str, secret: &str) -> Result<()> {
        fs::create_dir_all(&self.dir).with_context(|| {
            format!("creating password marker directory {}", self.dir.display())
        })?;
        fs::write(self.marker_path(id), format!("{}\n", secret_digest(secret)))
            .with_context(|| format!("writing password marker for {id}"))
    }

    fn marker_path(&self, id: &str) -> PathBuf {
        self.dir.join(format!("{}.sha256", marker_filename(id)))
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
        assert!(store
            .needs_update("rauthy:user@example.com", "one")
            .unwrap());
        store.commit("rauthy:user@example.com", "one").unwrap();
        assert!(!store
            .needs_update("rauthy:user@example.com", "one")
            .unwrap());
        assert!(store
            .needs_update("rauthy:user@example.com", "two")
            .unwrap());
        let _ = fs::remove_dir_all(dir);
    }
}
