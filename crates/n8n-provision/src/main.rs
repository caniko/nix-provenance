mod client;
mod state;

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context as _, Result};
use clap::{Parser, Subcommand};
use provenance_core::generated_secret::atomic_write_secret;
use provenance_core::password::{PasswordMarkerStore, read_password_file, secret_digest};
use serde_json::{Value, json};

use client::N8n;
use state::State;

#[derive(Parser, Debug)]
#[command(
    name = "n8n-provision",
    about = "Declarative n8n owner and credential bootstrap",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Render N8N_INSTANCE_OWNER_* (bcrypt hash) into an EnvironmentFile (ExecStartPre=+).
    OwnerEnv {
        #[arg(long)]
        state: PathBuf,
        #[arg(long)]
        credential_dir: PathBuf,
        /// Directory persisting the last bcrypt hash so restarts do not churn it.
        #[arg(long)]
        hash_dir: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
    /// Upsert declared credentials by name through the owner session.
    Reconcile {
        #[arg(long)]
        state: PathBuf,
        #[arg(long)]
        credential_dir: PathBuf,
        #[arg(long)]
        marker_dir: PathBuf,
        #[arg(long, default_value_t = 120)]
        ready_timeout: u64,
    },
}

fn load_state(path: &Path) -> Result<State> {
    let raw = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let state: State = serde_json::from_str(&raw).context("parsing state")?;
    state.validate()?;
    Ok(state)
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::OwnerEnv {
            state,
            credential_dir,
            hash_dir,
            out,
        } => owner_env(&load_state(&state)?, &credential_dir, &hash_dir, &out),
        Command::Reconcile {
            state,
            credential_dir,
            marker_dir,
            ready_timeout,
        } => reconcile(
            &load_state(&state)?,
            &credential_dir,
            &marker_dir,
            ready_timeout,
        ),
    }
}

fn quote(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}

/// Reuse the stored hash while it still verifies the current password;
/// otherwise hash anew and persist.
fn owner_hash(password: &str, hash_file: &Path) -> Result<String> {
    // bcrypt silently truncates beyond 72 bytes, which would accept any
    // password sharing that prefix.
    anyhow::ensure!(
        password.len() <= 72,
        "owner password exceeds bcrypt's 72-byte limit"
    );
    if let Ok(existing) = fs::read_to_string(hash_file) {
        let existing = existing.trim();
        if bcrypt::verify(password, existing).unwrap_or(false) {
            return Ok(existing.to_owned());
        }
    }
    let hash = bcrypt::hash(password, 10)?;
    if let Some(dir) = hash_file.parent() {
        fs::create_dir_all(dir)?;
    }
    atomic_write_secret(hash_file, &hash)?;
    Ok(hash)
}

fn owner_env_body(state: &State, hash: &str) -> String {
    let o = &state.owner;
    format!(
        "N8N_INSTANCE_OWNER_MANAGED_BY_ENV=true\nN8N_INSTANCE_OWNER_EMAIL={}\nN8N_INSTANCE_OWNER_FIRST_NAME={}\nN8N_INSTANCE_OWNER_LAST_NAME={}\nN8N_INSTANCE_OWNER_PASSWORD_HASH={}\n",
        quote(&o.email),
        quote(&o.first_name),
        quote(&o.last_name),
        quote(hash)
    )
}

fn owner_env(state: &State, credential_dir: &Path, hash_dir: &Path, out: &Path) -> Result<()> {
    let password = read_password_file(credential_dir.join(&state.owner.credential_name))?;
    let hash = owner_hash(&password, &hash_dir.join("owner.bcrypt"))?;
    if let Some(dir) = out.parent() {
        fs::create_dir_all(dir)?;
    }
    atomic_write_secret(out, &owner_env_body(state, &hash))?;
    Ok(())
}

/// Credential field value: the file verbatim minus one terminal line ending, so
/// significant leading/trailing whitespace survives (unlike the trimmed password reader).
fn read_secret_value(path: &Path) -> Result<String> {
    let raw = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let value = raw
        .strip_suffix("\n")
        .map(|v| v.strip_suffix("\r").unwrap_or(v))
        .unwrap_or(&raw);
    anyhow::ensure!(
        !value.is_empty(),
        "credential file {} is empty",
        path.display()
    );
    Ok(value.to_owned())
}

/// Resolved credential payload; secrets are read from systemd credentials.
fn resolve_data(cred: &state::Credential, credential_dir: &Path) -> Result<Value> {
    let mut data: BTreeMap<String, Value> = cred.data.clone();
    for (field, file) in &cred.data_files {
        data.insert(
            field.clone(),
            json!(read_secret_value(&credential_dir.join(file))?),
        );
    }
    Ok(serde_json::to_value(data)?)
}

fn reconcile(
    state: &State,
    credential_dir: &Path,
    marker_dir: &Path,
    ready_timeout: u64,
) -> Result<()> {
    let n8n = N8n::new(&state.url)?;
    n8n.wait_ready(Duration::from_secs(ready_timeout))?;
    let password = read_password_file(credential_dir.join(&state.owner.credential_name))?;
    n8n.login(&state.owner.email, &password)?;
    let existing = n8n.list_credentials()?;
    let markers = PasswordMarkerStore::new(marker_dir);

    for (name, cred) in &state.credentials {
        let data = resolve_data(cred, credential_dir)?;
        // Digest over type + resolved data: the marker says "n8n holds exactly this".
        let fingerprint = secret_digest(&format!("{}\n{data}", cred.kind));
        let id = format!("n8n-credential:{name}");
        let found = existing
            .iter()
            .find(|(_, n)| n == name)
            .map(|(i, _)| i.as_str());
        match found {
            Some(_) if !markers.needs_update(&id, &fingerprint)? => {}
            Some(cred_id) => {
                n8n.update_credential(cred_id, name, &cred.kind, &data)?;
                markers.commit(&id, &fingerprint)?;
                eprintln!("credential {name}: updated");
            }
            None => {
                n8n.create_credential(name, &cred.kind, &data)?;
                markers.commit(&id, &fingerprint)?;
                eprintln!("credential {name}: created");
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_value_keeps_inner_whitespace_and_drops_one_newline() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("v");
        fs::write(&f, " pw \n").unwrap();
        assert_eq!(read_secret_value(&f).unwrap(), " pw ");
        fs::write(&f, "\n").unwrap();
        assert!(read_secret_value(&f).is_err());
    }

    #[test]
    fn overlong_password_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        assert!(owner_hash(&"a".repeat(73), &dir.path().join("h")).is_err());
    }

    #[test]
    fn hash_is_reused_until_password_changes() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("owner.bcrypt");
        let first = owner_hash("pw-one", &file).unwrap();
        assert_eq!(owner_hash("pw-one", &file).unwrap(), first);
        let second = owner_hash("pw-two", &file).unwrap();
        assert_ne!(second, first);
        assert!(bcrypt::verify("pw-two", &second).unwrap());
        assert!(first.starts_with("$2b$"));
    }
}
