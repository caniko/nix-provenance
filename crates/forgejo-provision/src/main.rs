//! Declarative Forgejo SSH public-key provisioning.

mod client;
mod reconcile;
mod state;

use std::fs;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;

use client::ForgejoClient;
use reconcile::reconcile;
use state::State;

#[derive(Debug, Parser)]
#[command(
    name = "forgejo-provision",
    version,
    about = "Declaratively provision Forgejo SSH public keys"
)]
struct Cli {
    /// Forgejo base URL, for example http://127.0.0.1:3000.
    #[arg(long)]
    url: String,

    /// Path to the JSON state file rendered by NixOS.
    #[arg(long)]
    state: PathBuf,

    /// Forgejo administrator used for the API's Basic-auth requests.
    #[arg(long)]
    admin_user: String,

    /// Runtime file containing the administrator password.
    #[arg(long)]
    admin_password_file: PathBuf,

    /// Seconds to wait for Forgejo's API before failing.
    #[arg(long, default_value_t = 30)]
    ready_timeout: u64,

    /// Accept invalid TLS certificates for an explicitly configured HTTPS URL.
    #[arg(long)]
    accept_invalid_certs: bool,

    /// Permit deletion of keys declared with present = false.
    #[arg(long)]
    allow_ssh_key_delete: bool,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let password = provenance_core::secret::resolve(
        Some(&cli.admin_password_file),
        None,
        "Forgejo admin password",
        "--admin-password-file",
        "FORGEJO_ADMIN_PASSWORD",
    )?;
    let raw = fs::read_to_string(&cli.state)
        .with_context(|| format!("reading state file {}", cli.state.display()))?;
    let state: State = serde_json::from_str(&raw)
        .with_context(|| format!("parsing state file {}", cli.state.display()))?;
    state.validate()?;

    let client = ForgejoClient::new(
        &cli.url,
        &cli.admin_user,
        &password,
        cli.accept_invalid_certs,
    )?;
    client
        .wait_ready(Duration::from_secs(cli.ready_timeout))
        .context("waiting for Forgejo to become ready")?;
    let summary = reconcile(&client, &state, cli.allow_ssh_key_delete)?;
    eprintln!(
        "[forgejo-provision] done: created={}, deleted={}, unchanged={}",
        summary.created, summary.deleted, summary.unchanged
    );
    Ok(())
}
