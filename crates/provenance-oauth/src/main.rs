use anyhow::{Context, Result, ensure};
use clap::{Parser, Subcommand};
use provenance_oauth::{
    Config, Enrollment, Target, now,
    openai::OpenAi,
    state::{Store, atomic_write, read_json},
};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::{IsTerminal, Read, Write},
    path::PathBuf,
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
                    account
                },
            "requested target does not match the evaluated manifest"
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
            let grant = OpenAi::new()?.authorize(|url, code| {
                eprintln!(
                    "Authorize {} for {}@{}: {url}\nDevice code: {code}",
                    config.target.profile, config.target.user, config.target.host
                );
            })?;
            let enrollment = Enrollment {
                version: 1,
                target: config.target.clone(),
                generation,
                grant,
            };
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
    let store = Store::lock(&config)?;
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
            let provider = OpenAi::new()?;
            let access = store.access(now, |previous| provider.refresh(previous))?;
            let mut stdout = std::io::stdout().lock();
            if raw {
                writeln!(stdout, "{}", access.access_token.0)?;
            } else {
                serde_json::to_writer(&mut stdout, &access)?;
                writeln!(stdout)?;
            }
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
