use anyhow::{Context, Result, ensure};
use clap::{
    Parser, Subcommand,
    builder::{PathBufValueParser, TypedValueParser},
};
use provenance_oauth::{
    Config, Enrollment, OAuthClient, Secret, Target,
    budget::AccessBudget,
    google::{Google, write_agy_token},
    now,
    openai::OpenAi,
    opencode,
    state::{Store, atomic_write, read_json},
};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::{IsTerminal, Read, Write},
    os::unix::fs::{FileTypeExt, OpenOptionsExt},
    path::{Path, PathBuf},
    process::{Command, ExitCode, Stdio},
};
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(
    version,
    about = "Host-scoped OAuth authorization and access credentials"
)]
struct Cli {
    /// Public manifest emitted by services.provenance.oauth.
    #[arg(long)]
    config: PathBuf,
    #[command(subcommand)]
    command: Action,
}

#[derive(Subcommand)]
enum Action {
    /// Authorize a declared host/user and encrypt the enrollment through agenix.
    Authorize {
        host: String,
        provider: String,
        #[arg(long)]
        user: String,
        #[arg(long, default_value = "chatgpt")]
        profile: String,
        #[arg(long, default_value = "default")]
        account: String,
        /// The existing agenix-rekey declaration's encrypted source path.
        #[arg(long)]
        secret: PathBuf,
        /// Google OAuth client JSON downloaded from Cloud Console.
        #[arg(long)]
        client_file: Option<PathBuf>,
        /// agy's acp_token.json, rclone's token JSON, or `-` for OpenCode auth export on stdin.
        #[arg(long, value_parser = PathBufValueParser::new().map(Box::new))]
        token_file: Option<Box<PathBuf>>,
        /// Private operator-side transaction directory. Retries reuse enrollment.
        #[arg(long)]
        pending_directory: PathBuf,
        /// Start a fresh authorization rather than resuming this transaction.
        #[arg(long)]
        reauth: bool,
        #[arg(long, default_value = "agenix")]
        agenix: PathBuf,
        /// Rekey after encryption. Deployment remains the fleet operator's job.
        #[arg(long)]
        rekey: bool,
    },
    /// Discard pending plaintext after the fleet operator verifies this generation on target.
    Finalize {
        #[arg(long)]
        pending_directory: PathBuf,
        #[arg(long)]
        generation: u64,
    },
    /// Import a runtime enrollment without replaying older token generations.
    Apply {
        #[arg(long)]
        enrollment: PathBuf,
        /// Explicit first enrollment only; never set this on boot services.
        #[arg(long)]
        initialize: bool,
    },
    /// Emit access-only JSON to a pipe, refreshing under the shared state lock.
    Access {
        /// Emit only the access token for a stock command-based consumer.
        #[arg(long)]
        raw: bool,
    },
    /// Emit an rclone Drive remote to a pipe without refreshing it.
    RcloneConfig {
        #[arg(long)]
        remote: String,
    },
    /// Emit agy's Antigravity token JSON to a pipe.
    AgyToken,
    /// Emit agy's interactive CLI keyring entry JSON to a pipe.
    AgyKeyringEntry,
    /// Checkpoint a rotated ChatGPT credential from the local OpenCode store.
    OpencodeSync {
        #[arg(long, default_value = "opencode")]
        opencode: PathBuf,
    },
    /// Restore a missing ChatGPT credential to the local OpenCode store.
    OpencodeInstall {
        #[arg(long, default_value = "opencode")]
        opencode: PathBuf,
        #[arg(long)]
        activate: bool,
    },
    /// Inspect enrollment metadata; never prints token values.
    Status,
    /// Revoke local consumption while retaining the generation tombstone.
    Remove,
    /// Restore an explicitly decrypted current checkpoint into missing state.
    Restore {
        #[arg(long)]
        checkpoint: PathBuf,
    },
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("provenance-oauth: {error:#}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<()> {
    let budget = AccessBudget::default();
    let config: Config = read_json(&cli.config, false)?;
    config.validate()?;
    if let Action::Finalize {
        pending_directory,
        generation,
    } = &cli.command
    {
        let pending_config = Config {
            state_directory: pending_directory.clone(),
            ..config.clone()
        };
        let _lock = Store::lock(&pending_config)?;
        let receipt = read_receipt(&pending_config)?;
        let pending = pending_directory.join("enrollment.json");
        if pending.try_exists()? {
            let enrollment: Enrollment = read_json(&pending, true)?;
            enrollment.validate(&config.target)?;
            ensure!(
                enrollment.generation == *generation
                    && receipt.as_ref().is_none_or(|r| r.generation <= *generation),
                "pending generation does not match the verified target generation"
            );
            atomic_write(
                &pending_directory.join("receipt.json"),
                &serde_json::to_vec(&Receipt {
                    version: 1,
                    target: config.target.clone(),
                    generation: *generation,
                })?,
            )?;
            discard_pending(&pending_config)?;
        } else {
            ensure!(
                receipt.is_some_and(|r| r.generation == *generation),
                "no matching enrollment transaction to finalize"
            );
        }
        print_stage(&config.target, *generation, "finalized");
        return Ok(());
    }
    if let Action::Authorize {
        host,
        provider,
        user,
        profile,
        account,
        secret,
        client_file,
        token_file,
        pending_directory,
        reauth,
        agenix,
        rekey,
    } = cli.command
    {
        ensure!(
            config.target
                == Target {
                    host,
                    user,
                    provider,
                    profile,
                    account,
                    enrollment: config.target.enrollment.clone(),
                },
            "requested target does not match the evaluated manifest"
        );
        let import_token = matches!(
            config.target.profile.as_str(),
            "antigravity" | "drive" | "opencode"
        );
        let import_client =
            config.target.provider == "google" && config.target.profile != "antigravity";
        for (flag, provided, required) in [
            ("--token-file", token_file.is_some(), import_token),
            ("--client-file", client_file.is_some(), import_client),
        ] {
            ensure!(
                !provided || required,
                "{flag} is rejected for this OAuth profile"
            );
        }
        ensure!(
            token_file.is_some() || !import_token,
            "--token-file is required for this OAuth profile"
        );
        ensure!(
            config.target.profile != "opencode"
                || token_file
                    .as_deref()
                    .is_some_and(|path| path.as_path() == Path::new("-")),
            "openai/opencode requires --token-file -; pipe OpenCode auth export to stdin"
        );
        ensure!(
            client_file.is_some() || !import_client,
            "--client-file is required for this OAuth profile"
        );
        let pending_config = Config {
            state_directory: pending_directory,
            ..config.clone()
        };
        let _lock = Store::lock(&pending_config)?;
        let pending = pending_config.state_directory.join("enrollment.json");
        let previous: Option<Enrollment> = if pending.try_exists()? {
            Some(read_json(&pending, true)?)
        } else {
            None
        };
        if let Some(previous) = &previous {
            previous.validate(&config.target)?;
        }
        let receipt = read_receipt(&pending_config)?;
        if !reauth
            && let Some(receipt) = &receipt
            && previous
                .as_ref()
                .is_none_or(|p| p.generation <= receipt.generation)
        {
            // Also finishes a crash between publishing the receipt and unlinking
            // the original grant. A retry never re-encrypts that consumed grant.
            discard_pending(&pending_config)?;
            print_stage(&config.target, receipt.generation, "finalized");
            return Ok(());
        }
        let enrollment = if !reauth && previous.is_some() {
            previous.context("pending enrollment disappeared")?
        } else {
            let last = previous
                .as_ref()
                .map_or(0, |p| p.generation)
                .max(receipt.as_ref().map_or(0, |r| r.generation));
            let generation = now()?.max(
                last.checked_add(1)
                    .context("enrollment generation overflow")?,
            );
            let prompt = |url: &str, code: &str| {
                eprintln!(
                    "Authorize {} for {}@{}: {url}\nDevice code: {code}",
                    config.target.profile, config.target.user, config.target.host
                );
            };
            let grant = match config.target.provider.as_str() {
                "openai" if config.target.profile == "opencode" => {
                    opencode::authorize(&config.target)?
                }
                "openai" => OpenAi::new()?.authorize(prompt)?,
                "google" if config.target.profile == "antigravity" => {
                    let bytes = read_google_file(
                        token_file.as_deref().context("missing --token-file")?,
                        "Antigravity token",
                    )?;
                    Google::new()?.authorize_antigravity(&bytes, &config.target)?
                }
                "google" => {
                    let full_drive = config.target.profile == "drive";
                    let credentials = read_client_file(
                        client_file.as_deref().context("missing --client-file")?,
                        full_drive,
                    )?;
                    let google = Google::new()?;
                    if full_drive {
                        let bytes = read_google_file(
                            token_file.as_deref().context("missing --token-file")?,
                            "rclone token",
                        )?;
                        google.authorize_drive(credentials, &bytes)?
                    } else {
                        google.authorize(credentials, prompt)?
                    }
                }
                _ => unreachable!(),
            };
            let enrollment = Enrollment {
                version: 1,
                target: config.target.clone(),
                generation,
                grant,
            };
            enrollment.validate(&config.target)?;
            atomic_write(&pending, &Zeroizing::new(serde_json::to_vec(&enrollment)?))?;
            enrollment
        };
        // agenix owns recipient selection and encrypted source formatting. Its
        // import interface takes a private file path, never a token in argv/env.
        // --input refuses an existing output, even with --force. Encrypt into a
        // fresh private directory, then publish atomically; a failed retry must
        // leave the previous encrypted source intact.
        let staging = tempfile::tempdir_in(&pending_config.state_directory)?;
        let ciphertext = staging.path().join("enrollment.age");
        let status = Command::new(&agenix)
            .arg("edit")
            .arg("-i")
            .arg(&pending)
            .arg(&ciphertext)
            .stdin(Stdio::null())
            .status()
            .context("start agenix enrollment encryption")?;
        ensure!(
            status.success(),
            "agenix encryption failed; retry authorize with the same pending directory"
        );
        let mut encrypted = Vec::new();
        fs::File::open(&ciphertext)
            .context("agenix did not produce an encrypted enrollment")?
            .take(512 * 1024 + 1)
            .read_to_end(&mut encrypted)?;
        ensure!(
            encrypted.len() <= 512 * 1024,
            "encrypted enrollment exceeds size limit"
        );
        age::Decryptor::new(encrypted.as_slice())
            .map_err(|_| anyhow::anyhow!("agenix did not produce a valid age enrollment"))?;
        atomic_write(&secret, &encrypted)?;
        if rekey {
            let status = Command::new(&agenix).args(["rekey", "-a"]).status()?;
            ensure!(
                status.success(),
                "enrollment encrypted but rekey failed; retry the same transaction"
            );
        }
        print_stage(
            &config.target,
            enrollment.generation,
            if rekey { "rekeyed" } else { "encrypted" },
        );
        return Ok(());
    }
    verify_local_target(&config.target)?;
    // Refuse requests for another refresh owner before opening state.
    if matches!(cli.command, Action::Access { .. }) {
        config.target.require_access()?;
    }
    ensure!(
        !matches!(
            cli.command,
            Action::OpencodeSync { .. } | Action::OpencodeInstall { .. }
        ) || config.target.profile == "opencode",
        "command requires openai/opencode"
    );
    ensure!(
        !matches!(cli.command, Action::AgyToken)
            || (config.target.provider == "google" && config.target.profile == "antigravity"),
        "agy-token requires google/antigravity"
    );
    ensure!(
        !matches!(cli.command, Action::RcloneConfig { .. })
            || matches!(config.target.profile.as_str(), "drive-file" | "drive"),
        "rclone config requires google/drive-file or google/drive"
    );
    if matches!(cli.command, Action::AgyKeyringEntry) {
        ensure!(
            config.target.provider == "google" && config.target.profile == "antigravity",
            "agy-keyring-entry requires google/antigravity"
        );
        ensure!(
            fs::metadata("/proc/self/fd/1")
                .context("cannot inspect keyring output")?
                .file_type()
                .is_fifo(),
            "Antigravity keyring credentials must be consumed through a pipe"
        );
    }
    let store = if matches!(cli.command, Action::Access { .. }) {
        Store::lock_with_budget(&config, &budget)?
    } else {
        Store::lock(&config)?
    };
    match cli.command {
        Action::Apply {
            enrollment,
            initialize,
        } => {
            store.apply(&read_json(&enrollment, true)?, initialize)?;
            println!("{}", store.status()?);
        }
        Action::Access { raw } => {
            ensure!(
                !std::io::stdout().is_terminal(),
                "access credentials must be consumed through a pipe"
            );
            // Construct the client before access can persist refresh intent.
            let provider = OpenAi::new()?;
            let access = store.access_with_budget(now, &budget, |previous, timeout| {
                provider.refresh_with_timeout(previous, timeout)
            })?;
            let mut stdout = std::io::stdout().lock();
            if raw {
                writeln!(stdout, "{}", access.access_token.0)?;
            } else {
                serde_json::to_writer(&mut stdout, &access)?;
                writeln!(stdout)?;
            }
        }
        Action::RcloneConfig { remote } => {
            ensure!(
                !std::io::stdout().is_terminal(),
                "rclone credentials must be consumed through a pipe"
            );
            let grant = store.grant()?;
            let scope = if config.target.profile == "drive" {
                "drive"
            } else {
                "drive.file"
            };
            let output = Zeroizing::new(rclone_config(&remote, scope, &grant)?);
            std::io::stdout().lock().write_all(output.as_bytes())?;
        }
        Action::AgyToken => {
            ensure!(
                !std::io::stdout().is_terminal(),
                "Antigravity credentials must be consumed through a pipe"
            );
            let mut stdout = std::io::stdout().lock();
            write_agy_token(store.grant()?, &mut stdout)?;
            writeln!(stdout)?;
        }
        Action::AgyKeyringEntry => {
            let grant = store.grant()?;
            let mut stdout = std::io::stdout().lock();
            Google::new()?.write_agy_keyring_entry(&grant, &mut stdout)?;
            writeln!(stdout)?;
        }
        Action::OpencodeSync { opencode } => opencode::sync(&store, &opencode)?,
        Action::OpencodeInstall { opencode, activate } => {
            opencode::install(&store, &opencode, activate)?
        }
        Action::Status => println!("{}", store.status()?),
        Action::Remove => {
            store.remove()?;
            println!("{}", store.status()?);
        }
        Action::Restore { checkpoint } => {
            store.restore(&checkpoint)?;
            println!("{}", store.status()?);
        }
        Action::Authorize { .. } | Action::Finalize { .. } => unreachable!(),
    }
    Ok(())
}

fn read_google_file(path: &Path, kind: &str) -> Result<Zeroizing<Vec<u8>>> {
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)
        .with_context(|| format!("cannot open {kind} file"))?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file() && metadata.len() <= 64 * 1024,
        "{kind} file must be a bounded regular file"
    );
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(64 * 1024 + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= 64 * 1024, "{kind} file exceeds size limit");
    Ok(bytes)
}

fn read_client_file(path: &Path, desktop: bool) -> Result<OAuthClient> {
    let bytes = read_google_file(path, "Google client")?;
    let document: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|_| anyhow::anyhow!("invalid Google client JSON"))?;
    let root = document.as_object().context("invalid Google client JSON")?;
    let fields = if desktop {
        root.get("installed")
            .and_then(serde_json::Value::as_object)
            .context("google/drive requires a Desktop app (installed) client JSON")?
    } else if root.contains_key("client_id") || root.contains_key("client_secret") {
        root
    } else {
        let mut objects = root.values().filter_map(serde_json::Value::as_object);
        let object = objects.next().context("invalid Google client JSON")?;
        ensure!(objects.next().is_none(), "invalid Google client JSON");
        object
    };
    let client = OAuthClient {
        client_id: fields
            .get("client_id")
            .and_then(serde_json::Value::as_str)
            .context("invalid Google client credentials")?
            .to_owned(),
        client_secret: Secret(
            fields
                .get("client_secret")
                .and_then(serde_json::Value::as_str)
                .context("invalid Google client credentials")?
                .to_owned(),
        ),
    };
    client.validate()?;
    Ok(client)
}

fn rclone_config(remote: &str, scope: &str, grant: &provenance_oauth::Grant) -> Result<String> {
    ensure!(
        !remote.is_empty()
            && remote
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b)),
        "invalid rclone remote name"
    );
    let client = grant
        .client
        .as_ref()
        .context("Google grant is missing client credentials")?;
    let millis = i64::try_from(grant.expires_at).context("invalid token expiry")?;
    let expiry = chrono::DateTime::from_timestamp_millis(millis)
        .context("invalid token expiry")?
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let token = Zeroizing::new(serde_json::to_string(
        &serde_json::json!({"access_token": grant.access_token.0, "token_type": "Bearer", "refresh_token": grant.refresh_token.0, "expiry": expiry}),
    )?);
    let token = Zeroizing::new(token.replace('%', "\\u0025"));
    Ok(format!(
        "[{remote}]\ntype = drive\nclient_id = {}\nclient_secret = {}\nscope = {scope}\ntoken = {}\n",
        client.client_id, client.client_secret.0, *token
    ))
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    version: u32,
    target: Target,
    generation: u64,
}

fn read_receipt(config: &Config) -> Result<Option<Receipt>> {
    let path = config.state_directory.join("receipt.json");
    if !path.try_exists()? {
        return Ok(None);
    }
    let receipt: Receipt = read_json(&path, true)?;
    ensure!(
        receipt.version == 1 && receipt.target == config.target && receipt.generation > 0,
        "invalid enrollment receipt target or version"
    );
    Ok(Some(receipt))
}

fn discard_pending(config: &Config) -> Result<()> {
    match fs::remove_file(config.state_directory.join("enrollment.json")) {
        Ok(()) => fs::File::open(&config.state_directory)?.sync_all()?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

fn print_stage(target: &Target, generation: u64, stage: &str) {
    println!(
        "{}",
        serde_json::json!({ "target": target, "generation": generation, "stage": stage })
    );
}

fn verify_local_target(target: &Target) -> Result<()> {
    let hostname = fs::read_to_string("/proc/sys/kernel/hostname")?;
    ensure!(
        hostname.trim() == target.host,
        "this OAuth profile belongs to another host"
    );
    // Resolve the effective account from the operating system, not $USER.
    let user = Command::new("id")
        .arg("-un")
        .output()
        .context("resolve current local user")?;
    ensure!(
        user.status.success() && String::from_utf8(user.stdout)?.trim() == target.user,
        "this OAuth profile belongs to another local user"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn google_client_files_are_bounded_and_validated() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("client.json");
        for json in [
            r#"{"client_id":"id","client_secret":"secret"}"#,
            r#"{"installed":{"client_id":"id","client_secret":"secret","redirect_uris":[]}}"#,
        ] {
            fs::write(&path, json).unwrap();
            let client = read_client_file(&path, false).unwrap();
            assert_eq!(client.client_id, "id");
            assert_eq!(client.client_secret.0, "secret");
            assert_eq!(
                read_client_file(&path, true).is_ok(),
                json.contains("\"installed\"")
            );
        }
        for json in [
            r#"{"client_id":"id"}"#,
            r#"{"client_id":"id","client_secret":"unsafe%"}"#,
            r#"{"a":{"client_id":"id","client_secret":"secret"},"b":{}}"#,
        ] {
            fs::write(&path, json).unwrap();
            assert!(read_client_file(&path, false).is_err());
        }
        fs::write(&path, vec![b' '; 64 * 1024 + 1]).unwrap();
        assert!(read_client_file(&path, false).is_err());
    }

    #[test]
    fn renders_rclone_config_and_rejects_bad_remote() {
        let grant = provenance_oauth::Grant {
            access_token: Secret("access".into()),
            refresh_token: Secret("refresh".into()),
            expires_at: 1_700_000_000_000,
            account_id: "id".into(),
            client: Some(OAuthClient {
                client_id: "id".into(),
                client_secret: Secret("secret".into()),
            }),
            project_id: None,
            scopes: None,
            opencode: None,
        };
        assert_eq!(
            rclone_config("gdrive", "drive.file", &grant).unwrap(),
            "[gdrive]\ntype = drive\nclient_id = id\nclient_secret = secret\nscope = drive.file\ntoken = {\"access_token\":\"access\",\"expiry\":\"2023-11-14T22:13:20.000Z\",\"refresh_token\":\"refresh\",\"token_type\":\"Bearer\"}\n"
        );
        assert!(rclone_config("bad\n[other]", "drive", &grant).is_err());
        let mut grant = grant;
        grant.access_token.0 = "%(type)s".into();
        let output = rclone_config("gdrive", "drive", &grant).unwrap();
        assert!(output.contains("\nscope = drive\n"));
        let token = output
            .lines()
            .find_map(|line| line.strip_prefix("token = "))
            .unwrap();
        assert!(!token.contains('%'));
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(token).unwrap()["access_token"],
            "%(type)s"
        );
    }
}
