//! Declarative GitHub account keys, collaborator invitations, and invitation acceptance.

mod client;
mod reconcile;
mod state;

use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, Result, bail};
use clap::Parser;

use client::GithubClient;
use state::State;

/// Exit status for configuration errors that a retry cannot fix.
const PERMANENT_FAILURE: u8 = 2;

#[derive(Debug, Parser)]
#[command(
    name = "github-provision",
    version,
    about = "Declaratively provision GitHub account keys and repository collaborators"
)]
struct Cli {
    /// Path to the JSON state file rendered by Home Manager.
    #[arg(long)]
    state: PathBuf,

    /// Runtime file containing the account's personal access token.
    #[arg(long)]
    token_file: PathBuf,

    /// GitHub REST API root.
    #[arg(long, default_value = "https://api.github.com")]
    api_url: String,

    /// Permit deletion of keys declared with present = false.
    #[arg(long)]
    allow_delete: bool,
}

fn load(cli: &Cli) -> Result<(State, GithubClient)> {
    let raw = fs::read_to_string(&cli.state)
        .with_context(|| format!("reading state file {}", cli.state.display()))?;
    let state: State = serde_json::from_str(&raw)
        .with_context(|| format!("parsing state file {}", cli.state.display()))?;
    state.validate()?;
    let token = provenance_core::secret::resolve(
        Some(&cli.token_file),
        None,
        "GitHub token",
        "--token-file",
        "GITHUB_TOKEN",
    )?;
    Ok((state, GithubClient::new(&cli.api_url, &token)?))
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let (state, client) = match load(&cli) {
        Ok(loaded) => loaded,
        Err(error) => {
            eprintln!("[github-provision] {error:#}");
            return ExitCode::from(PERMANENT_FAILURE);
        }
    };
    let run = || -> Result<_> {
        let login = client.login()?;
        if !login.eq_ignore_ascii_case(&state.login) {
            bail!(
                "token authenticates as {login}, not the declared {}",
                state.login
            );
        }
        reconcile::reconcile(&client, &state, cli.allow_delete)
    };
    match run() {
        Ok(summary) => {
            eprintln!(
                "[github-provision] {}: created={}, accepted={}, deleted={}, unchanged={}",
                state.login, summary.created, summary.updated, summary.deleted, summary.unchanged
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("[github-provision] {}: {error:#}", state.login);
            ExitCode::FAILURE
        }
    }
}
