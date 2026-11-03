//! Digest stamps that tell a real secret rotation from a path-only event
//! (for example an agenix generation switch that leaves the content alone).

use std::fs;
use std::path::Path;

use crate::Result;
use crate::generated_secret::atomic_write_secret;
use crate::password::{read_password_file, secret_digest};

/// Record the digest of `secret` at `stamp` (written 0600).
///
/// # Errors
///
/// Returns an error when the stamp cannot be written.
pub fn record(stamp: &Path, secret: &str) -> Result<()> {
    if let Some(dir) = stamp.parent() {
        fs::create_dir_all(dir)
            .map_err(|s| crate::Error::io(format!("creating {}", dir.display()), s))?;
    }
    atomic_write_secret(stamp, &secret_digest(secret))
}

/// True when the secret in `secret_file` matches the digest recorded at
/// `stamp`. A missing or unreadable stamp counts as changed.
///
/// # Errors
///
/// Returns an error when the secret file cannot be read.
pub fn secret_unchanged(secret_file: &Path, stamp: &Path) -> Result<bool> {
    let secret = read_password_file(secret_file)?;
    Ok(fs::read_to_string(stamp).is_ok_and(|s| s.trim() == secret_digest(&secret)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unchanged_until_the_secret_changes() {
        let dir = tempfile::tempdir().unwrap();
        let secret = dir.path().join("s");
        let stamp = dir.path().join("run/stamp");
        fs::write(&secret, "one\n").unwrap();
        assert!(!secret_unchanged(&secret, &stamp).unwrap());
        record(&stamp, "one").unwrap();
        assert!(secret_unchanged(&secret, &stamp).unwrap());
        fs::write(&secret, "two\n").unwrap();
        assert!(!secret_unchanged(&secret, &stamp).unwrap());
    }
}
