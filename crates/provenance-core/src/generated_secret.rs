//! Persistent generated-secret storage.

use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use rand::distr::{Alphanumeric, SampleString};
use zeroize::Zeroize;

use crate::{Error, Result};

const GENERATED_SECRET_LENGTH: usize = 64;
const SECRET_FILE_MODE: u32 = 0o600;
const SECRET_DIRECTORY_MODE: u32 = 0o700;

/// A secret value whose debug and display representations are redacted.
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct SecretValue(String);

impl SecretValue {
    /// Construct a secret from non-empty text, trimming file-style surrounding
    /// whitespace.
    pub fn from_text(value: &str) -> Result<Self> {
        Ok(Self::new(normalized(value)?))
    }

    fn new(value: String) -> Self {
        Self(value)
    }

    /// Borrow the secret for the one operation that needs its value.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted>")
    }
}

impl fmt::Display for SecretValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted>")
    }
}

/// How a generated secret file was obtained during an ensure operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretSource {
    /// The existing persistent artifact was kept.
    Existing,
    /// The first artifact was adopted from a caller-supplied source file.
    Adopted,
    /// A fresh value was generated from the operating system CSPRNG.
    Generated,
}

/// Result of ensuring a generated secret artifact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnsureSecretResult {
    /// Persistent artifact path.
    pub path: PathBuf,
    /// Source of the value now stored at [`Self::path`].
    pub source: SecretSource,
}

/// Read-only state of a generated secret artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretFileStatus {
    /// The artifact does not exist yet.
    Missing,
    /// The artifact exists, is non-empty, and has mode `0600`.
    Ready,
}

/// Persistent, file-backed generated secret storage.
///
/// The store deliberately owns only one file below the caller-provided state
/// directory. It never returns a secret in status or ensure results, and all
/// writes use a same-directory temporary file followed by an atomic rename.
#[derive(Debug, Clone)]
pub struct GeneratedSecretStore {
    state_dir: PathBuf,
    name: String,
}

impl GeneratedSecretStore {
    /// Construct a store for `name` below `state_dir`.
    ///
    /// `name` must be a single path component so callers cannot escape the
    /// persistent state directory.
    pub fn new(state_dir: impl Into<PathBuf>, name: impl Into<String>) -> Result<Self> {
        let name = name.into();
        if name.is_empty() || name == "." || name == ".." || name.contains(['/', '\\', '\0']) {
            return Err(Error::invalid(
                "generated secret file name must be one non-empty path component",
            ));
        }
        Ok(Self {
            state_dir: state_dir.into(),
            name,
        })
    }

    /// Construct a store from its complete persistent artifact path.
    pub fn at(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let state_dir = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| {
                Error::invalid(format!(
                    "generated secret path {} has no valid file name",
                    path.display()
                ))
            })?;
        Self::new(state_dir, name)
    }

    /// Return the persistent artifact path.
    pub fn path(&self) -> PathBuf {
        self.state_dir.join(&self.name)
    }

    /// Ensure the artifact exists, adopting `adopt_from` once when supplied or
    /// generating a fresh value when no source exists.
    pub fn ensure(&self, adopt_from: Option<&Path>) -> Result<EnsureSecretResult> {
        self.prepare_directory()?;
        match self.status()? {
            SecretFileStatus::Ready => Ok(EnsureSecretResult {
                path: self.path(),
                source: SecretSource::Existing,
            }),
            SecretFileStatus::Missing => {
                let (secret, source) = match adopt_from {
                    Some(path) => (read_file(path)?, SecretSource::Adopted),
                    None => (generate(), SecretSource::Generated),
                };
                self.replace(&secret)?;
                Ok(EnsureSecretResult {
                    path: self.path(),
                    source,
                })
            }
        }
    }

    /// Check the artifact without returning its value.
    pub fn status(&self) -> Result<SecretFileStatus> {
        let path = self.path();
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(SecretFileStatus::Missing);
            }
            Err(error) => {
                return Err(Error::io(
                    format!("checking generated secret file {}", path.display()),
                    error,
                ));
            }
        };
        ensure_regular_private_file(&path, &metadata)?;
        let _ = read_file(&path)?;
        Ok(SecretFileStatus::Ready)
    }

    /// Read the existing secret after validating its file type and mode.
    pub fn read(&self) -> Result<SecretValue> {
        let path = self.path();
        let metadata = fs::symlink_metadata(&path).map_err(|source| {
            Error::io(
                format!("reading generated secret file {}", path.display()),
                source,
            )
        })?;
        ensure_regular_private_file(&path, &metadata)?;
        read_file(&path)
    }

    /// Recover a missing artifact from a provider-returned value.
    ///
    /// Existing artifacts are never overwritten by recovery. Use [`Self::replace`]
    /// for an intentional rotation.
    pub fn recover(&self, secret: &str) -> Result<bool> {
        self.prepare_directory()?;
        if self.status()? == SecretFileStatus::Ready {
            return Ok(false);
        }
        let secret = normalized(secret)?;
        let secret = SecretValue::new(secret);
        self.replace(&secret)?;
        Ok(true)
    }

    /// Generate and atomically install a new secret, replacing the old value.
    pub fn rotate(&self) -> Result<SecretValue> {
        self.prepare_directory()?;
        let secret = generate();
        self.replace(&secret)?;
        Ok(secret)
    }

    /// Atomically replace the artifact with `secret`.
    pub fn replace(&self, secret: &SecretValue) -> Result<()> {
        self.prepare_directory()?;
        atomic_write_secret(&self.path(), secret.expose())
    }

    /// Atomically replace the artifact with non-empty secret text.
    pub fn replace_text(&self, secret: &str) -> Result<()> {
        self.prepare_directory()?;
        atomic_write_secret(&self.path(), secret)
    }

    fn prepare_directory(&self) -> Result<()> {
        match fs::symlink_metadata(&self.state_dir) {
            Ok(metadata) if metadata.file_type().is_dir() => {}
            Ok(_) => {
                return Err(Error::invalid(format!(
                    "generated secret state path {} is not a directory",
                    self.state_dir.display()
                )));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir_all(&self.state_dir).map_err(|source| {
                    Error::io(
                        format!(
                            "creating generated secret state directory {}",
                            self.state_dir.display()
                        ),
                        source,
                    )
                })?;
            }
            Err(error) => {
                return Err(Error::io(
                    format!(
                        "checking generated secret state directory {}",
                        self.state_dir.display()
                    ),
                    error,
                ));
            }
        }
        fs::set_permissions(
            &self.state_dir,
            fs::Permissions::from_mode(SECRET_DIRECTORY_MODE),
        )
        .map_err(|source| {
            Error::io(
                format!(
                    "restricting generated secret state directory {}",
                    self.state_dir.display()
                ),
                source,
            )
        })
    }
}

/// Write a secret atomically with mode `0600`.
pub fn atomic_write_secret(path: &Path, secret: &str) -> Result<()> {
    let mut secret = normalized(secret)?;
    let parent = match path.parent() {
        Some(parent) => parent,
        None => {
            secret.zeroize();
            return Err(Error::invalid(format!(
                "secret path {} has no parent directory",
                path.display()
            )));
        }
    };
    let name = match path.file_name().and_then(|name| name.to_str()) {
        Some(name) => name,
        None => {
            secret.zeroize();
            return Err(Error::invalid(format!(
                "secret path {} has no valid file name",
                path.display()
            )));
        }
    };

    for attempt in 0..100_u32 {
        let temporary = parent.join(format!(".{name}.{}.{}.tmp", std::process::id(), attempt));
        let mut file = match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(SECRET_FILE_MODE)
            .open(&temporary)
        {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                secret.zeroize();
                return Err(Error::io(
                    format!("creating temporary secret file {}", temporary.display()),
                    error,
                ));
            }
        };

        let result = (|| {
            file.set_permissions(fs::Permissions::from_mode(SECRET_FILE_MODE))
                .map_err(|source| {
                    Error::io(
                        format!("setting permissions on {}", temporary.display()),
                        source,
                    )
                })?;
            file.write_all(secret.as_bytes()).map_err(|source| {
                Error::io(
                    format!("writing temporary secret file {}", temporary.display()),
                    source,
                )
            })?;
            file.sync_all().map_err(|source| {
                Error::io(
                    format!("syncing temporary secret file {}", temporary.display()),
                    source,
                )
            })?;
            drop(file);
            fs::rename(&temporary, path).map_err(|source| {
                Error::io(format!("installing secret file {}", path.display()), source)
            })?;
            File::open(parent)
                .and_then(|directory| directory.sync_all())
                .map_err(|source| {
                    Error::io(
                        format!("syncing secret directory {}", parent.display()),
                        source,
                    )
                })?;
            let metadata = fs::symlink_metadata(path).map_err(|source| {
                Error::io(
                    format!("checking installed secret file {}", path.display()),
                    source,
                )
            })?;
            ensure_regular_private_file(path, &metadata)
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        secret.zeroize();
        return result;
    }

    secret.zeroize();
    Err(Error::invalid(format!(
        "could not allocate a temporary path for secret file {}",
        path.display()
    )))
}

fn ensure_regular_private_file(path: &Path, metadata: &std::fs::Metadata) -> Result<()> {
    if !metadata.file_type().is_file() {
        return Err(Error::invalid(format!(
            "generated secret path {} is not a regular file",
            path.display()
        )));
    }
    if metadata.mode() & 0o777 != SECRET_FILE_MODE {
        return Err(Error::invalid(format!(
            "generated secret file {} must have mode 0600",
            path.display()
        )));
    }
    Ok(())
}

fn read_file(path: &Path) -> Result<SecretValue> {
    let mut raw = fs::read_to_string(path)
        .map_err(|source| Error::io(format!("reading secret file {}", path.display()), source))?;
    let result = SecretValue::from_text(&raw);
    raw.zeroize();
    result
}

fn normalized(value: &str) -> Result<String> {
    let value = value.trim();
    if value.is_empty() {
        return Err(Error::invalid("secret value must not be empty"));
    }
    Ok(value.to_owned())
}

fn generate() -> SecretValue {
    SecretValue::new(Alphanumeric.sample_string(&mut rand::rng(), GENERATED_SECRET_LENGTH))
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before Unix epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("nix-provenance-generated-{name}-{nanos}"));
        fs::create_dir(&path).expect("create secret test directory");
        path
    }

    #[test]
    fn generated_secret_is_idempotent_and_private() {
        let dir = temp_dir("idempotent");
        let store = GeneratedSecretStore::new(&dir, "forgejo.secret").unwrap();
        let first = store.ensure(None).unwrap();
        let value = store.read().unwrap();
        let second = store.ensure(None).unwrap();

        assert_eq!(first.source, SecretSource::Generated);
        assert_eq!(second.source, SecretSource::Existing);
        assert_eq!(store.read().unwrap().expose(), value.expose());
        assert_eq!(
            fs::metadata(store.path()).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 1);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn existing_secret_is_adopted_once() {
        let dir = temp_dir("adopt");
        let source = dir.join("legacy");
        fs::write(&source, "legacy-secret\n").unwrap();
        let store = GeneratedSecretStore::new(&dir, "forgejo.secret").unwrap();

        assert_eq!(
            store.ensure(Some(&source)).unwrap().source,
            SecretSource::Adopted
        );
        assert_eq!(store.read().unwrap().expose(), "legacy-secret");
        fs::write(&source, "different\n").unwrap();
        assert_eq!(
            store.ensure(Some(&source)).unwrap().source,
            SecretSource::Existing
        );
        assert_eq!(store.read().unwrap().expose(), "legacy-secret");
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn rotation_and_recovery_replace_only_when_requested() {
        let dir = temp_dir("rotate");
        let store = GeneratedSecretStore::new(&dir, "forgejo.secret").unwrap();
        store.ensure(None).unwrap();
        let old = store.read().unwrap();
        let rotated = store.rotate().unwrap();
        assert_ne!(old.expose(), rotated.expose());
        fs::remove_file(store.path()).unwrap();
        assert!(store.recover(rotated.expose()).unwrap());
        assert_eq!(store.read().unwrap().expose(), rotated.expose());
        assert!(!store.recover("must-not-replace").unwrap());
        assert_eq!(store.read().unwrap().expose(), rotated.expose());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn secret_debug_and_display_do_not_leak() {
        let secret = SecretValue::new("do-not-leak".to_owned());
        assert!(!format!("{secret:?}").contains("do-not-leak"));
        assert!(!format!("{secret}").contains("do-not-leak"));
    }
}
