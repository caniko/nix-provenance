//! Interactive document creation; the consuming secret manager owns encryption.
use super::{Account, Failure, MAX_BYTES, Result, decode_seed};
use clap::Args;
use data_encoding::BASE32_NOPAD;
use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::{IsTerminal, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

#[derive(Args)]
pub(super) struct EnrollArgs {
    /// New JSON file under the current user's private XDG_RUNTIME_DIR.
    #[arg(long, required_unless_present = "stdout", conflicts_with = "stdout")]
    pub out: Option<PathBuf>,
    /// Read a bounded credential JSON document from a private stdin pipe.
    #[arg(long, requires = "stdout")]
    pub stdin: bool,
    /// Write the validated canonical document to a private stdout pipe.
    #[arg(long, requires = "stdin", conflicts_with = "out")]
    pub stdout: bool,
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

fn decode_parameter(input: &str) -> Result<Zeroizing<String>> {
    let invalid = || Failure::permanent("Invalid Proton authenticator URI encoding");
    let mut bytes = Zeroizing::new(Vec::with_capacity(input.len()));
    let mut source = input.bytes();
    while let Some(byte) = source.next() {
        bytes.push(match byte {
            b'%' => {
                let high = char::from(source.next().ok_or_else(invalid)?).to_digit(16);
                let low = char::from(source.next().ok_or_else(invalid)?).to_digit(16);
                ((high.ok_or_else(invalid)? << 4) | low.ok_or_else(invalid)?) as u8
            }
            b'+' => b' ',
            byte => byte,
        });
    }
    let value = std::str::from_utf8(&bytes).map_err(|_| invalid())?;
    Ok(Zeroizing::new(value.to_owned()))
}

fn normalize_seed(input: &str) -> Result<String> {
    let invalid = || Failure::permanent("Invalid or unsupported Proton authenticator URI");
    let mut uri_seed = None;
    if input.starts_with("otpauth:") {
        if input.contains('#') || input.chars().any(char::is_control) {
            return Err(invalid());
        }
        let (label, query) = input
            .strip_prefix("otpauth://totp/")
            .and_then(|path| path.split_once('?'))
            .ok_or_else(invalid)?;
        let label = decode_parameter(label)?;
        if label.trim().is_empty() || label.chars().any(char::is_control) {
            return Err(invalid());
        }
        let mut seen = BTreeSet::new();
        for parameter in query.split('&') {
            let (key, value) = parameter.split_once('=').ok_or_else(invalid)?;
            let key = decode_parameter(key)?;
            let value = decode_parameter(value)?;
            let key = match key.as_str() {
                "secret" => "secret",
                "issuer" => "issuer",
                "algorithm" if value.eq_ignore_ascii_case("SHA1") => "algorithm",
                "digits" if value.as_str() == "6" => "digits",
                "period" if value.as_str() == "30" => "period",
                _ => return Err(invalid()),
            };
            if !seen.insert(key) {
                return Err(invalid());
            }
            if key == "secret" {
                uri_seed = Some(value);
            }
        }
        if uri_seed.is_none() {
            return Err(invalid());
        }
    }
    let seed = uri_seed.as_deref().map_or(input, String::as_str);
    let canonical = Zeroizing::new(BASE32_NOPAD.encode(&decode_seed(seed)?));
    if matches!(canonical.len(), 6 | 8) && canonical.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(Failure::permanent(
            "Enroll the authenticator seed, not a one-time code",
        ));
    }
    Ok(canonical.to_string())
}

fn prepare_account(mut account: Account, password_only: bool) -> Result<Account> {
    match (account.totp_secret.take(), password_only) {
        (Some(seed), false) => {
            let seed = Zeroizing::new(seed);
            account.totp_secret = Some(normalize_seed(&seed)?);
        }
        (None, true) => {}
        (seed, _) => {
            let _seed = seed.map(Zeroizing::new);
            return Err(Failure::permanent(
                "Enrollment requires a TOTP seed, or explicit --password-only without a seed",
            ));
        }
    }
    account.validate()?;
    Ok(account)
}

fn pipe_document(password_only: bool) -> Result<()> {
    if std::io::stdin().is_terminal() || std::io::stdout().is_terminal() {
        return Err(Failure::permanent(
            "Credential document mode requires private stdin/stdout pipes",
        ));
    }
    let mut input = Zeroizing::new(Vec::with_capacity(MAX_BYTES + 1));
    std::io::stdin()
        .take((MAX_BYTES + 1) as u64)
        .read_to_end(&mut input)
        .map_err(|_| Failure::permanent("Cannot read Proton credential input"))?;
    if input.len() > MAX_BYTES {
        return Err(Failure::permanent("Proton credential input is too large"));
    }
    let account: Account = serde_json::from_slice(&input).map_err(|_| {
        Failure::permanent(
            "Invalid Proton credential JSON; expected username, password, and optional totpSecret",
        )
    })?;
    let account = prepare_account(account, password_only)?;
    let document = Zeroizing::new(
        serde_json::to_vec(&account)
            .map_err(|_| Failure::permanent("Cannot encode Proton credential document"))?,
    );
    std::io::stdout()
        .write_all(&document)
        .map_err(|_| Failure::permanent("Cannot write Proton credential output"))
}

pub(super) fn run(args: &EnrollArgs) -> Result<()> {
    if args.stdin && args.stdout {
        return pipe_document(args.password_only);
    }
    // Validate the destination before requesting any credentials.
    let path = output_path(
        args.out
            .as_deref()
            .ok_or_else(|| Failure::permanent("Enrollment requires an output destination"))?,
    )?;
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
    let account = prepare_account(
        Account {
            username: username.to_string(),
            password: password.to_string(),
            totp_secret: seed.as_ref().map(|value| value.to_string()),
        },
        args.password_only,
    )?;
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
