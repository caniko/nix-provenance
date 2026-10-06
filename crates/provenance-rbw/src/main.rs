use std::ffi::OsString;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use provenance_rbw::{Config, prepare, profile_name, status};

#[derive(Parser)]
#[command(about = "Durable rbw client state", version)]
struct Cli {
    #[arg(long)]
    config: PathBuf,
    #[command(subcommand)]
    command: Operation,
}

#[derive(Subcommand)]
enum Operation {
    /// Stop the legacy agent and migrate state once, without authenticating.
    Prepare,
    /// Report state-file metadata without exposing vault contents or tokens.
    Status,
    /// Prepare durable state, then replace this process with the packaged client.
    Exec {
        #[arg(long, value_enum)]
        program: Program,
        #[arg(last = true)]
        args: Vec<OsString>,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum Program {
    Rbw,
    Agent,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let config: Config =
        serde_json::from_slice(&std::fs::read(&cli.config).context("reading public rbw manifest")?)
            .context("parsing public rbw manifest")?;
    let profile = profile_name(std::env::var("RBW_PROFILE").ok().as_deref())?;
    match cli.command {
        Operation::Prepare => prepare(&config, &profile),
        Operation::Status => {
            println!(
                "{}",
                serde_json::to_string_pretty(&status(&config, &profile)?)?
            );
            Ok(())
        }
        Operation::Exec { program, args } => {
            prepare(&config, &profile)?;
            // Restrictive permissions also apply to later files written by rbw.
            // SAFETY: umask only changes this process's file-creation mask.
            unsafe {
                libc::umask(0o077);
            }
            Err(config
                .command(matches!(program, Program::Agent))
                .args(args)
                .exec())
            .context("executing packaged rbw client")
        }
    }
}
