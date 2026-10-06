//! Interactive document creation; the consuming secret manager owns encryption.
use super::{Account, Failure, Result};
use clap::Args;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

#[derive(Args)]
pub(super) struct EnrollArgs {
    /// New JSON file under the current user's private XDG_RUNTIME_DIR.
    #[arg(long)]
    pub out: PathBuf,
    /// Explicitly enroll an account without TOTP; the default requires its existing seed.
    #[arg(long)]
    pub password_only: bool,
}

pub(super) fn disable_core_dumps() -> Result<()> {
    let limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: setrlimit reads a valid stack-allocated rlimit; it retains no pointer.
    if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &limit) } != 0 {
        return Err(Failure::permanent(
            "Cannot disable credential-process core dumps",
        ));
    }
    Ok(())
}

fn private_directory(path: &Path) -> Result<PathBuf> {
    let path = fs::canonicalize(path).map_err(|_| {
        Failure::permanent("Credential output requires an existing private runtime directory")
    })?;
    let metadata = fs::metadata(&path)
        .map_err(|_| Failure::permanent("Cannot inspect credential runtime directory"))?;
    // SAFETY: geteuid takes no arguments and has no preconditions.
    let uid = unsafe { libc::geteuid() };
    if !metadata.is_dir() || metadata.uid() != uid || metadata.permissions().mode() & 0o077 != 0 {
        return Err(Failure::permanent(
            "Credential runtime directory must be user-owned and mode 0700",
        ));
    }
    Ok(path)
}

fn output_path(path: &Path) -> Result<PathBuf> {
    let runtime = std::env::var_os("XDG_RUNTIME_DIR")
        .ok_or_else(|| Failure::permanent("Credential enrollment requires XDG_RUNTIME_DIR"))?;
    let runtime = private_directory(Path::new(&runtime))?;
    if !path.is_absolute() {
        return Err(Failure::permanent(
            "Credential output must be an absolute runtime path",
        ));
    }
    let parent = private_directory(
        path.parent()
            .ok_or_else(|| Failure::permanent("Credential output has no parent directory"))?,
    )?;
    if !parent.starts_with(runtime) {
        return Err(Failure::permanent(
            "Credential output must stay under XDG_RUNTIME_DIR",
        ));
    }
    let path = parent.join(
        path.file_name()
            .ok_or_else(|| Failure::permanent("Credential output has no file name"))?,
    );
    if path.symlink_metadata().is_ok() {
        return Err(Failure::permanent(
            "Credential output already exists; choose a new runtime file",
        ));
    }
    Ok(path)
}

fn prompt(label: &str) -> Result<Zeroizing<String>> {
    rpassword::prompt_password(label)
        .map(Zeroizing::new)
        .map_err(|_| {
            Failure::permanent("Credential enrollment requires an interactive controlling terminal")
        })
}

fn write_document(path: &Path, account: &Account) -> Result<()> {
    account.validate()?;
    let bytes = Zeroizing::new(
        serde_json::to_vec(account)
            .map_err(|_| Failure::permanent("Cannot encode Proton credential document"))?,
    );
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|_| Failure::permanent("Cannot create a new private credential document"))?;
    if file
        .write_all(&bytes)
        .and_then(|()| file.sync_all())
        .is_err()
    {
        let _ = fs::remove_file(path);
        return Err(Failure::permanent(
            "Cannot persist Proton credential document",
        ));
    }
    Ok(())
}

pub(super) fn run(args: &EnrollArgs) -> Result<()> {
    // Validate the destination before requesting any credentials.
    let path = output_path(&args.out)?;
    let username = prompt("Proton account username: ")?;
    let password = prompt("Proton account password: ")?;
    let confirmation = prompt("Repeat password: ")?;
    if password != confirmation {
        return Err(Failure::permanent(
            "Password confirmation did not match; no document was created",
        ));
    }
    let seed = if args.password_only {
        None
    } else {
        let seed = prompt("Existing Proton authenticator seed (base32, not the six-digit code): ")?;
        let confirmation = prompt("Repeat authenticator seed: ")?;
        if seed != confirmation {
            return Err(Failure::permanent(
                "Authenticator seed confirmation did not match; no document was created",
            ));
        }
        Some(seed)
    };
    let account = Account {
        username: username.to_string(),
        password: password.to_string(),
        totp_secret: seed.as_ref().map(|value| value.to_string()),
    };
    write_document(&path, &account)?;
    eprintln!(
        "Private Proton credential document created; encrypt it through your secret manager and remove the runtime file"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn document_creation_is_private_and_never_replaces_existing_material() {
        let directory = tempdir().expect("private fixture directory");
        let path = directory.path().join("account.json");
        let account = Account {
            username: "fixture".into(),
            password: "private fixture".into(),
            totp_secret: None,
        };
        assert!(write_document(&path, &account).is_ok());
        assert_eq!(
            fs::metadata(&path).expect("metadata").permissions().mode() & 0o777,
            0o600
        );
        let before = fs::read(&path).expect("document");
        assert!(write_document(&path, &account).is_err());
        assert_eq!(fs::read(&path).expect("preserved document"), before);
        assert!(super::super::read_account(&path).is_ok());
    }

    #[test]
    fn invalid_credentials_create_no_file() {
        let directory = tempdir().expect("private fixture directory");
        let path = directory.path().join("account.json");
        let account = Account {
            username: "fixture".into(),
            password: "private fixture".into(),
            totp_secret: Some("invalid!".into()),
        };
        assert!(write_document(&path, &account).is_err());
        assert!(!path.exists());
    }
}
