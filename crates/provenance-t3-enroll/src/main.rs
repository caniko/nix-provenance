use std::path::PathBuf;
use std::time::Duration;

use anyhow::Result;
use clap::Parser;
use provenance_t3_enroll::{Config, Summary, load_manifest, run};

#[derive(Parser)]
#[command(
    about = "Enroll native T3 Code environments for one existing Unix user",
    version
)]
struct Cli {
    /// Public, non-secret enrollment manifest.
    #[arg(long)]
    manifest: PathBuf,
    /// Attempts per native operation. Retries repeat the same declared capability.
    #[arg(long, default_value_t = 1, value_parser = clap::value_parser!(u32).range(1..=10))]
    attempts: u32,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let manifest = load_manifest(&cli.manifest)?;
    let summary = run(
        &manifest,
        &Config {
            attempts: cli.attempts,
            retry_delay: Duration::from_secs(2),
            desktop_timeout: Duration::from_secs(120),
            owner_timeout: Duration::from_secs(30),
            command_timeout: Duration::from_secs(30),
            ssh: PathBuf::from("ssh"),
        },
    )?;
    print_summary(&summary);
    Ok(())
}

fn print_summary(summary: &Summary) {
    for peer in &summary.peers {
        println!(
            "{} {} ({})",
            if peer.linked { "linked" } else { "kept" },
            peer.label,
            peer.environment_id
        );
    }
    if let Some(imported) = &summary.imported {
        println!(
            "imported desktop connections: {} targets, {} profiles, {} credentials",
            imported.targets, imported.profiles, imported.credentials
        );
    }
}
