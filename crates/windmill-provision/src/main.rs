mod client;
mod db;
mod state;

use std::fs;
use std::os::unix::fs::{PermissionsExt, chown};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context as _, Result, bail};
use clap::{Parser, Subcommand};
use provenance_core::generated_secret::atomic_write_secret;
use provenance_core::password::{PasswordMarkerStore, read_password_file};

use client::Windmill;
use state::State;

#[derive(Parser, Debug)]
#[command(
    name = "windmill-provision",
    about = "Declarative Windmill bootstrap: superadmin env file, operator logins, workspaces, tokens",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Render SUPERADMIN_SECRET into a systemd EnvironmentFile (ExecStartPre=+).
    Env {
        /// File holding the superadmin secret (systemd credential).
        #[arg(long)]
        secret_file: PathBuf,
        /// EnvironmentFile to write (mode 0600).
        #[arg(long)]
        out: PathBuf,
    },
    /// Reconcile users, workspaces, memberships and tokens.
    Reconcile {
        /// Nix-rendered state JSON.
        #[arg(long)]
        state: PathBuf,
        /// systemd credentials directory (%d).
        #[arg(long)]
        credential_dir: PathBuf,
        #[arg(long)]
        marker_dir: PathBuf,
        #[arg(long, default_value = "runuser")]
        runuser: PathBuf,
        #[arg(long, default_value = "psql")]
        psql: PathBuf,
        #[arg(long, default_value_t = 120)]
        ready_timeout: u64,
    },
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Env { secret_file, out } => write_env(&secret_file, &out),
        Command::Reconcile {
            state,
            credential_dir,
            marker_dir,
            runuser,
            psql,
            ready_timeout,
        } => {
            let raw = fs::read_to_string(&state)
                .with_context(|| format!("reading {}", state.display()))?;
            let state: State = serde_json::from_str(&raw).context("parsing state")?;
            state.validate()?;
            let db = db::Psql {
                runuser,
                psql,
                database: state.database.clone(),
            };
            reconcile(&state, &credential_dir, &marker_dir, &db, ready_timeout)
        }
    }
}

/// systemd EnvironmentFile value: double-quoted, `\` and `"` escaped.
fn env_line(secret: &str) -> Result<String> {
    if secret.chars().any(char::is_control) {
        bail!("superadmin secret contains control characters");
    }
    let escaped = secret.replace('\\', "\\\\").replace('"', "\\\"");
    Ok(format!("SUPERADMIN_SECRET=\"{escaped}\"\n"))
}

fn write_env(secret_file: &Path, out: &Path) -> Result<()> {
    let secret = read_password_file(secret_file)?;
    if let Some(dir) = out.parent() {
        fs::create_dir_all(dir)?;
    }
    atomic_write_secret(out, &env_line(&secret)?)?;
    Ok(())
}

/// Look up the numeric id of `name` in passwd/group style `content`
/// (`name:x:id:...`).
fn lookup_id(content: &str, name: &str) -> Option<u32> {
    content.lines().find_map(|line| {
        let mut f = line.split(':');
        (f.next()? == name).then(|| f.nth(1)?.parse().ok())?
    })
}

fn resolve_id(file: &str, name: &str) -> Result<u32> {
    if let Ok(id) = name.parse() {
        return Ok(id);
    }
    lookup_id(&fs::read_to_string(file)?, name).with_context(|| format!("{name} not in {file}"))
}

/// Create the token directory if missing; an existing directory keeps its mode.
fn ensure_dir(dir: &Path) -> Result<()> {
    if !dir.exists() {
        fs::create_dir_all(dir)?;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o755))?;
    }
    Ok(())
}

fn install_token(token: &state::Token, value: &str) -> Result<()> {
    if let Some(dir) = token.path.parent() {
        ensure_dir(dir)?;
    }
    // atomic_write_secret installs 0600 root first; widen only afterwards.
    atomic_write_secret(&token.path, value)?;
    chown(
        &token.path,
        Some(resolve_id("/etc/passwd", &token.owner)?),
        Some(resolve_id("/etc/group", &token.group)?),
    )?;
    fs::set_permissions(&token.path, fs::Permissions::from_mode(token.mode_bits()?))?;
    Ok(())
}

fn reconcile(
    state: &State,
    credential_dir: &Path,
    marker_dir: &Path,
    db: &db::Psql,
    ready_timeout: u64,
) -> Result<()> {
    let superadmin = read_password_file(credential_dir.join(&state.superadmin_credential))?;
    let wm = Windmill::new(&state.url)?;
    wm.wait_ready(Duration::from_secs(ready_timeout))?;
    let markers = PasswordMarkerStore::new(marker_dir);

    // Users first: workspace membership and token minting need the rows.
    for (name, user) in &state.users {
        let password = read_password_file(credential_dir.join(&user.credential_name))?;
        let id = format!("windmill:{}", user.email);
        // The marker covers the instance-admin flag too, so flipping `admin`
        // re-applies the row even when the password file is unchanged.
        let fingerprint = format!("admin={}\n{password}", user.admin);
        if markers.needs_update(&id, &fingerprint)? || !db.user_has_argon2_hash(&user.email)? {
            let hash = db::hash_password(&password)?;
            db.run(&db::upsert_user_sql(&user.email, name, &hash, user.admin))?;
            markers.commit(&id, &fingerprint)?;
            eprintln!("user {name}: password applied");
        }
    }
    if state.disable_default_admin {
        db.run(&db::lock_default_admin_sql())?;
    }

    for (id, ws) in &state.workspaces {
        if !wm.workspace_exists(&superadmin, id)? {
            wm.create_workspace(&superadmin, id, &ws.name)?;
            eprintln!("workspace {id}: created");
        }
    }
    for (name, user) in &state.users {
        for ws in &user.workspaces {
            if wm.add_user(&superadmin, ws, name, &user.email, user.admin)? {
                eprintln!("user {name}: added to {ws}");
            }
        }
    }

    for (label, token) in &state.tokens {
        // A kept token must still match the declared user/workspace/scopes.
        let spec_id = format!("windmill-token:{label}");
        let spec = format!("{}\n{:?}\n{:?}", token.user, token.workspace, token.scopes);
        let valid = !markers.needs_update(&spec_id, &spec)?
            && match fs::read_to_string(&token.path) {
                Ok(existing) if !existing.trim().is_empty() => {
                    wm.token_is_valid(existing.trim(), token.workspace.as_deref())?
                }
                _ => false,
            };
        if valid {
            // Re-assert ownership/mode so declared drift heals without a re-mint.
            let existing = fs::read_to_string(&token.path)?;
            install_token(token, existing.trim())?;
            continue;
        }
        let user = &state.users[&token.user];
        let old_token = fs::read_to_string(&token.path).ok();
        let password = read_password_file(credential_dir.join(&user.credential_name))?;
        let session = wm.login(&user.email, &password)?;
        let value = wm.create_token(&session, label, token.workspace.as_deref(), &token.scopes)?;
        install_token(token, &value)?;
        // Exactly one live token per label: revoke the previous one(s). Done
        // after the new file is installed so a failure never leaves no token.
        if let Some(new_prefix) = db::token_prefix(&value) {
            let old_prefix = old_token
                .as_deref()
                .and_then(|t| db::token_prefix(t.trim()));
            let column = db.token_prefix_column()?;
            db.run(&db::revoke_old_tokens_sql(
                label,
                &user.email,
                new_prefix,
                old_prefix,
                column,
            ))?;
        }
        markers.commit(&spec_id, &spec)?;
        eprintln!("token {label}: minted");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_line_quotes_and_rejects_control_chars() {
        assert_eq!(
            env_line("a b\"c\\d").unwrap(),
            "SUPERADMIN_SECRET=\"a b\\\"c\\\\d\"\n"
        );
        assert!(env_line("a\nb").is_err());
    }

    #[test]
    fn id_lookup_reads_third_field() {
        let passwd = "root:x:0:0::/root:/bin/sh\nstudio:x:994:993::/x:/bin/false\n";
        assert_eq!(lookup_id(passwd, "studio"), Some(994));
        assert_eq!(lookup_id(passwd, "ghost"), None);
    }
}
