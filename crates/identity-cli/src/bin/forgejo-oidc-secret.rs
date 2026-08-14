//! Reconcile the Kanidm OAuth2 secret consumed by Forgejo.

use std::path::PathBuf;

use anyhow::Result;
use clap::Parser;

use identity_cli::kanidm::{ClientConfig, reconcile_oauth2_basic_secret};

#[derive(Debug, Parser)]
#[command(
    name = "forgejo-oidc-secret",
    about = "Reconcile a Kanidm OAuth2 secret into a private runtime file",
    version
)]
struct Cli {
    /// Kanidm base URL.
    #[arg(long, env = "KANIDM_URL")]
    url: String,

    /// File containing the idm_admin password.
    #[arg(long, env = "KANIDM_IDM_ADMIN_PASSWORD_FILE")]
    idm_admin_password_file: PathBuf,

    /// Kanidm OAuth2 client name.
    #[arg(long)]
    name: String,

    /// Private runtime path for the local secret artifact.
    #[arg(long)]
    state_file: PathBuf,

    /// Optional legacy secret file used only when the state artifact is missing.
    #[arg(long)]
    adopt_from: Option<PathBuf>,

    /// Reset the provider secret before writing the local artifact.
    #[arg(long)]
    rotate: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let config = ClientConfig::new(cli.url, cli.idm_admin_password_file.display().to_string());
    let action = reconcile_oauth2_basic_secret(
        &config,
        &cli.name,
        &cli.state_file,
        cli.adopt_from.as_deref(),
        cli.rotate,
    )
    .await?;
    println!("oauth2_secret_action={}", action.as_str());
    Ok(())
}
