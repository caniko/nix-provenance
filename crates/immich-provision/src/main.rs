mod client;
mod reconcile;
mod state;

use std::fs;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;

use client::ImmichClient;
use reconcile::reconcile;
use state::State;

#[derive(Parser, Debug)]
#[command(
    name = "immich-provision",
    version,
    about = "Declaratively provision Immich users with a short-lived local provisioning token"
)]
struct Cli {
    /// Immich base URL. Both http://host:2283 and http://host:2283/api are accepted.
    #[arg(long)]
    url: String,

    /// Path to the JSON state file rendered by NixOS or written by hand.
    #[arg(long)]
    state: PathBuf,

    /// File containing a short-lived Immich provisioning/session token.
    #[arg(long)]
    token_file: Option<PathBuf>,

    /// Short-lived Immich provisioning/session token.
    #[arg(long, env = "IMMICH_PROVISION_TOKEN", hide_env_values = true)]
    token: Option<String>,

    /// Accept invalid TLS certificates when talking to Immich.
    #[arg(long)]
    accept_invalid_certs: bool,

    /// Allow user deletion when the state also sets users.<name>.delete.force = true.
    #[arg(long)]
    allow_user_delete: bool,

    /// Seconds to wait for Immich to answer before reconciling.
    #[arg(long, default_value_t = 60)]
    ready_timeout: u64,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let token = provenance_core::secret::resolve(
        cli.token_file.as_deref(),
        cli.token.as_deref(),
        "provisioning token",
        "--token-file",
        "IMMICH_PROVISION_TOKEN",
    )?;
    let raw = fs::read_to_string(&cli.state)
        .with_context(|| format!("reading state file {}", cli.state.display()))?;
    let state: State = serde_json::from_str(&raw)
        .with_context(|| format!("parsing state file {}", cli.state.display()))?;

    let client = ImmichClient::new(&cli.url, &token, cli.accept_invalid_certs)?;
    client
        .wait_ready(Duration::from_secs(cli.ready_timeout))
        .context("waiting for Immich to become ready")?;

    let summary = reconcile(&client, &state, cli.allow_user_delete)?;
    eprintln!(
        "[immich-provision] done: created={}, updated={}, deleted={}, unchanged={}",
        summary.created, summary.updated, summary.deleted, summary.unchanged
    );
    Ok(())
}
