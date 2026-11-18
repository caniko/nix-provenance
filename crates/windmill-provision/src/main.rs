mod client;
mod db;
mod state;

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::os::unix::fs::PermissionsExt;
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
    about = "Declarative Windmill bootstrap: superadmin env file, operator logins, workspaces, scripts, variables, tokens",
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
        /// Where to record the secret digest, so `changed` can tell a real rotation.
        #[arg(long)]
        stamp: PathBuf,
    },
    /// Exit 0 only when the secret differs from the digest recorded at the last
    /// start (ExecCondition of the rotation restart; exit 1 skips it).
    Changed {
        #[arg(long)]
        secret_file: PathBuf,
        #[arg(long)]
        stamp: PathBuf,
    },
    /// Lock the stock admin@windmill.dev account. Runs in its own unit so a
    /// missing user password file cannot keep it from running.
    LockDefaultAdmin {
        /// Nix-rendered state JSON.
        #[arg(long)]
        state: PathBuf,
        #[arg(long, default_value = "runuser")]
        runuser: PathBuf,
        #[arg(long, default_value = "psql")]
        psql: PathBuf,
        #[arg(long, default_value_t = 120)]
        ready_timeout: u64,
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
        /// Bound on waiting for a deployed version's lock generation job.
        #[arg(long, default_value_t = 300)]
        deploy_timeout: u64,
    },
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Env {
            secret_file,
            out,
            stamp,
        } => write_env(&secret_file, &out, &stamp),
        Command::Changed { secret_file, stamp } => {
            if provenance_core::stamp::secret_unchanged(&secret_file, &stamp)? {
                std::process::exit(1);
            }
            Ok(())
        }
        Command::LockDefaultAdmin {
            state,
            runuser,
            psql,
            ready_timeout,
        } => {
            let state = read_state(&state)?;
            if !state.disable_default_admin {
                return Ok(());
            }
            let db = db::Psql {
                runuser,
                psql,
                database: state.database,
            };
            lock_default_admin(&db, Duration::from_secs(ready_timeout))
        }
        Command::Reconcile {
            state,
            credential_dir,
            marker_dir,
            runuser,
            psql,
            ready_timeout,
            deploy_timeout,
        } => {
            let state = read_state(&state)?;
            let db = db::Psql {
                runuser,
                psql,
                database: state.database.clone(),
            };
            // Fail closed: a rejected declaration must not leave the stock login open.
            // The dedicated unit is the load-order-safe path; this stays because
            // the lock is idempotent and reconcile may run outside systemd.
            if state.disable_default_admin {
                lock_default_admin(&db, Duration::from_secs(ready_timeout))?;
            }
            state.validate()?;
            reconcile(
                &state,
                &credential_dir,
                &marker_dir,
                &db,
                ready_timeout,
                deploy_timeout,
            )
        }
    }
}

fn read_state(path: &Path) -> Result<State> {
    let raw = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    serde_json::from_str(&raw).context("parsing state")
}

/// systemd EnvironmentFile value: double-quoted, `\` and `"` escaped.
fn env_line(secret: &str) -> Result<String> {
    if secret.chars().any(char::is_control) {
        bail!("superadmin secret contains control characters");
    }
    let escaped = secret.replace('\\', "\\\\").replace('"', "\\\"");
    Ok(format!("SUPERADMIN_SECRET=\"{escaped}\"\n"))
}

fn write_env(secret_file: &Path, out: &Path, stamp: &Path) -> Result<()> {
    let secret = read_password_file(secret_file)?;
    provenance_core::stamp::record(stamp, &secret)?;
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

/// Create the token directory and any missing ancestors at an explicit 0755
/// (the unit's UMask would otherwise leave new ancestors at 0700 and lock the
/// declared group out). Existing directories keep their mode.
fn ensure_dir(dir: &Path) -> Result<()> {
    let mut missing: Vec<&Path> = dir.ancestors().take_while(|p| !p.exists()).collect();
    missing.reverse();
    for path in missing {
        fs::create_dir(path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o755))?;
    }
    Ok(())
}

/// Read an existing token file without following a symlink planted by its
/// consumer: only a regular, singly-linked file counts; anything else is
/// treated as absent (so the token is re-minted).
fn read_token_file(path: &Path) -> Option<String> {
    use std::io::Read as _;
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .ok()?;
    let meta = file.metadata().ok()?;
    if !meta.is_file() || meta.nlink() != 1 {
        return None;
    }
    let mut value = String::new();
    // A token is a few dozen bytes; a larger file (consumer-writable) is invalid.
    file.take(4096).read_to_string(&mut value).ok()?;
    (value.len() < 4096).then_some(value)
}

/// Install `value` at the token path atomically. Owner and mode are applied to
/// the temporary file through its descriptor before the rename, so no
/// path-based `chown`/`chmod` can follow a symlink planted by the consumer.
fn install_token(token: &state::Token, value: &str) -> Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;

    let parent = token.path.parent().context("token path has no parent")?;
    ensure_dir(parent)?;
    let name = token
        .path
        .file_name()
        .and_then(|n| n.to_str())
        .context("token path has no file name")?;
    let uid = resolve_id("/etc/passwd", &token.owner)?;
    let gid = resolve_id("/etc/group", &token.group)?;
    let tmp = parent.join(format!(".{name}.{}.tmp", std::process::id()));
    let _ = fs::remove_file(&tmp);
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        // create_new (O_CREAT|O_EXCL) never follows a symlink at `tmp`.
        .open(&tmp)
        .with_context(|| format!("creating {}", tmp.display()))?;
    let result = (|| -> Result<()> {
        std::os::unix::fs::fchown(&file, Some(uid), Some(gid))?;
        file.set_permissions(fs::Permissions::from_mode(token.mode_bits()?))?;
        file.write_all(value.as_bytes())?;
        file.sync_all()?;
        fs::rename(&tmp, &token.path)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

fn lock_default_admin(db: &db::Psql, timeout: Duration) -> Result<()> {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        match db.run(&db::lock_default_admin_sql()) {
            Ok(_) => return Ok(()),
            Err(e) if std::time::Instant::now() >= deadline => {
                return Err(e).context("locking the stock admin");
            }
            Err(_) => std::thread::sleep(Duration::from_secs(1)),
        }
    }
}

fn reconcile(
    state: &State,
    credential_dir: &Path,
    marker_dir: &Path,
    db: &db::Psql,
    ready_timeout: u64,
    deploy_timeout: u64,
) -> Result<()> {
    let wm = Windmill::new(&state.url)?;
    wm.wait_ready(Duration::from_secs(ready_timeout))?;
    // Revocation first: it needs no secret file, membership or token step, so
    // a bad password file or a failed upsert cannot keep removed access live.
    prune(state, marker_dir, db)?;
    let superadmin = read_password_file(credential_dir.join(&state.superadmin_credential))?;
    let markers = PasswordMarkerStore::new(marker_dir);

    // Users first: workspace membership and token minting need the rows.
    for (name, user) in &state.users {
        let password = read_password_file(credential_dir.join(&user.credential_name))?;
        let id = format!("windmill:{}", user.email);
        // The marker covers the instance-admin flag too, so flipping `admin`
        // re-applies the row even when the password file is unchanged.
        let fingerprint = format!("admin={}\n{password}", user.admin);
        if markers.needs_update(&id, &fingerprint)?
            || !db.account_in_sync(&user.email, &password, user.admin)?
        {
            let hash = db::hash_password(&password)?;
            db.run(&db::upsert_user_sql(&user.email, name, &hash, user.admin))?;
            markers.commit(&id, &fingerprint)?;
            eprintln!("user {name}: password applied");
        }
    }
    for (id, ws) in &state.workspaces {
        if !wm.workspace_exists(&superadmin, id)? {
            wm.create_workspace(&superadmin, id, &ws.name)?;
            eprintln!("workspace {id}: created");
        } else {
            wm.rename_workspace(&superadmin, id, &ws.name)?;
        }
    }
    for (name, user) in &state.users {
        for ws in &user.workspaces {
            if wm.add_user(&superadmin, ws, &user.email, user.admin)? {
                eprintln!("user {name}: added to {ws}");
            } else {
                // Already a member: converge the role on the member's actual
                // username, which need not equal the declared key.
                let username = db.workspace_username(ws, &user.email)?.with_context(|| {
                    format!("{} is a member of {ws} but has no usr row", user.email)
                })?;
                wm.set_workspace_admin(&superadmin, ws, &username, user.admin)?;
            }
        }
    }

    // Code and configuration next: a script is redeployed only when its
    // content, language or tag differs from the latest deployed version, and a
    // variable only when its value, secrecy or description differs. The
    // variable value comes from its runtime credential file, never the state.
    for (ws, spec) in &state.workspaces {
        for (path, script) in &spec.scripts {
            let content = fs::read_to_string(&script.content_file)
                .with_context(|| format!("reading {}", script.content_file.display()))?;
            let deployed = wm.script(&superadmin, ws, path)?;
            // A new version does not inherit its parent's tag: a declaration
            // that says nothing about it must send the deployed one back.
            let deployed_tag = deployed.as_ref().and_then(|d| d.tag.as_deref());
            let tag = script
                .tag
                .as_deref()
                .or(deployed_tag)
                .filter(|tag| !tag.is_empty());
            // Windmill 1.839.0 applies a `// tag <name>` badge from the source
            // over the tag sent with the deploy, so a source that disagrees with
            // the declaration would deploy a version the declaration does not
            // describe. Refuse it before deploying.
            if let Some(source) = source_tag(&content) {
                anyhow::ensure!(
                    Some(source) == tag,
                    "script {ws}/{path}: the source declares `// tag {source}`, not the declared tag {}: remove the annotation or declare the same tag",
                    tag.unwrap_or("")
                );
            }
            if script_unchanged(deployed.as_ref(), &script.language, &content, tag) {
                // The version is deployed but not necessarily runnable: its
                // dependency job may still be queued, or may have failed.
                let hash = deployed
                    .as_ref()
                    .map(|d| d.hash.as_str())
                    .context("deployed script without a hash")?;
                wm.wait_runnable(&superadmin, ws, hash, Duration::from_secs(deploy_timeout))?;
                continue;
            }
            let hash = wm.create_script(
                &superadmin,
                ws,
                &client::ScriptDeploy {
                    path,
                    language: &script.language,
                    summary: &script.summary,
                    content: &content,
                    tag,
                    parent: deployed.as_ref().map(|d| d.hash.as_str()),
                },
            )?;
            wm.wait_runnable(&superadmin, ws, &hash, Duration::from_secs(deploy_timeout))?;
            // Read the stored tag back: a version with the wrong tag is unrunnable
            // (no worker pool serves it) while the deploy itself succeeded, so a
            // mismatch is a failed declaration, not a cosmetic difference.
            let stored = wm
                .script(&superadmin, ws, path)?
                .with_context(|| format!("script {ws}/{path}: vanished after deploying {hash}"))?;
            anyhow::ensure!(
                stored.tag.as_deref().filter(|tag| !tag.is_empty()) == tag,
                "script {ws}/{path}: Windmill stored tag {:?}, not the declared {:?}",
                stored.tag.as_deref().unwrap_or(""),
                tag.unwrap_or("")
            );
            eprintln!("script {ws}/{path}: deployed");
        }
        for (path, variable) in &spec.variables {
            let value = read_password_file(credential_dir.join(&variable.credential_name))?;
            let deployed = wm.variable(&superadmin, ws, path)?;
            if variable_unchanged(deployed.as_ref(), variable, &value) {
                continue;
            }
            if deployed.is_some() {
                wm.update_variable(
                    &superadmin,
                    ws,
                    path,
                    &value,
                    variable.is_secret,
                    &variable.description,
                )?;
                eprintln!("variable {ws}/{path}: updated");
            } else {
                wm.create_variable(
                    &superadmin,
                    ws,
                    path,
                    &value,
                    variable.is_secret,
                    &variable.description,
                )?;
                eprintln!("variable {ws}/{path}: created");
            }
        }
    }

    for (label, token) in &state.tokens {
        // A kept token must still match the declared user/workspace/scopes.
        let spec_id = format!("windmill-token:{label}");
        // Windmill copies the owner's super_admin into the token at mint time,
        // so the spec covers the owner's email and admin flag too.
        let owner = &state.users[&token.user];
        let spec = format!(
            "{}\n{}\n{}\n{:?}\n{:?}",
            token.user, owner.email, owner.admin, token.workspace, token.scopes
        );
        let valid = !markers.needs_update(&spec_id, &spec)?
            && match read_token_file(&token.path) {
                Some(existing) if !existing.trim().is_empty() => wm.token_is_valid(
                    existing.trim(),
                    token.workspace.as_deref(),
                    &state.users[&token.user].email,
                )?,
                _ => false,
            };
        if valid {
            // Re-assert ownership/mode so declared drift heals without a re-mint.
            let existing = read_token_file(&token.path).context("re-reading kept token")?;
            install_token(token, existing.trim())?;
            // Finish a revocation an earlier re-mint left undone: the marker
            // still matches, so nothing else would retry it.
            if let Some(keep) = db::token_prefix(existing.trim()) {
                let column = db.token_prefix_column()?;
                db.run(&db::revoke_old_tokens_sql(
                    label,
                    &owner.email,
                    keep,
                    None,
                    column,
                ))?;
            }
            continue;
        }
        let user = &state.users[&token.user];
        let old_token = read_token_file(&token.path);
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

/// The tag a script's source declares with Windmill's `// tag <name>` badge.
///
/// Windmill 1.839.0 parses the leading comment block of a version's source and
/// applies the `tag` badge over the tag sent with the deploy (its
/// `parse_pipeline_annotations` sets `ns.tag`). `//`, `#` and `--` open a
/// comment depending on the language; the badge is `tag` followed by its value.
fn source_tag(content: &str) -> Option<&str> {
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        // The annotation lives in the leading comment block: stop at the first
        // line that is not a comment.
        let Some(body) = ["//", "#", "--"]
            .iter()
            .find_map(|marker| line.strip_prefix(marker))
        else {
            break;
        };
        let Some(rest) = body.trim_start().strip_prefix("tag") else {
            continue;
        };
        // A keyword must be followed by whitespace: `tags` is a plain comment.
        if !rest.starts_with(char::is_whitespace) {
            continue;
        }
        let tag = rest.trim();
        if !tag.is_empty() {
            return Some(tag);
        }
    }
    None
}

/// True when the latest deployed version already holds exactly this code and
/// tag: Windmill keeps a version per deploy, so a no-op must not call create.
fn script_unchanged(
    deployed: Option<&client::DeployedScript>,
    language: &str,
    content: &str,
    tag: Option<&str>,
) -> bool {
    deployed.is_some_and(|d| {
        d.language == language
            && d.content == content
            && d.tag.as_deref().filter(|tag| !tag.is_empty()) == tag
    })
}

/// True when the deployed variable already holds exactly this declaration
/// (value, secrecy and description). A secret Windmill refuses to decrypt
/// (`value: null`) never matches, so it is written again.
fn variable_unchanged(
    deployed: Option<&client::DeployedVariable>,
    declared: &state::Variable,
    value: &str,
) -> bool {
    deployed.is_some_and(|d| {
        d.is_secret == declared.is_secret
            && d.description.as_deref().unwrap_or("") == declared.description
            && d.value.as_deref() == Some(value)
    })
}

const TOKEN_REGISTRY: &str = "tokens.json";
/// Previous-run registry: only a missing file is an empty first run; an
/// unreadable or corrupt one aborts so removals are never silently forgotten.
fn read_registry<T: serde::de::DeserializeOwned + Default>(path: &Path) -> Result<T> {
    match fs::read_to_string(path) {
        Ok(raw) => {
            serde_json::from_str(&raw).with_context(|| format!("parsing {}", path.display()))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(T::default()),
        Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
    }
}

/// What an earlier run recorded about a token it manages.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
struct Recorded {
    path: PathBuf,
    email: String,
}

fn declared_tokens(state: &State) -> BTreeMap<String, Recorded> {
    state
        .tokens
        .iter()
        .map(|(label, t)| {
            (
                label.clone(),
                Recorded {
                    path: t.path.clone(),
                    email: state.users[&t.user].email.clone(),
                },
            )
        })
        .collect()
}

/// Recorded tokens whose label is no longer declared, or whose owner or path
/// changed: the recorded token is stale and is revoked by its old identity.
fn removed_tokens(
    previous: &BTreeMap<String, Recorded>,
    declared: &BTreeMap<String, Recorded>,
) -> Vec<(String, Recorded)> {
    previous
        .iter()
        .filter(|(label, rec)| declared.get(*label) != Some(*rec))
        .map(|(label, rec)| (label.clone(), rec.clone()))
        .collect()
}

/// Provisioned logins (from the DB marker `company = 'provisioned'`) whose
/// email is no longer declared.
fn undeclared_emails(provisioned: Vec<String>, state: &State) -> Vec<String> {
    let declared: BTreeSet<&str> = state.users.values().map(|u| u.email.as_str()).collect();
    provisioned
        .into_iter()
        .filter(|email| !declared.contains(email.as_str()))
        .collect()
}

/// Revoke what the declaration no longer names: tokens first, then logins.
/// Tokens are revoked by the recorded label plus owner email, so adopted
/// (unmarked) accounts are covered too; the file is deleted only afterwards.
/// ponytail: the registry is written once per successful prune, so a label
/// removed again before any run completes is not remembered; keep a journal
/// if that window matters.
fn prune(state: &State, marker_dir: &Path, db: &db::Psql) -> Result<()> {
    let registry = marker_dir.join(TOKEN_REGISTRY);
    let previous: BTreeMap<String, Recorded> = read_registry(&registry)?;
    let declared = declared_tokens(state);
    for (label, rec) in removed_tokens(&previous, &declared) {
        anyhow::ensure!(state::is_safe_ident(&label), "unsafe recorded token label");
        anyhow::ensure!(
            state::is_safe_ident(&rec.email),
            "unsafe recorded token email"
        );
        let old_prefix = read_token_file(&rec.path);
        let old_prefix = old_prefix
            .as_deref()
            .and_then(|t| db::token_prefix(t.trim()));
        let column = db.token_prefix_column()?;
        db.run(&db::revoke_label_sql(
            &label, &rec.email, old_prefix, column,
        ))?;
        // Always drop the file: a declaration reusing this path then sees no
        // token and mints a fresh one, never trusting the just-revoked value.
        match fs::remove_file(&rec.path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e).with_context(|| format!("removing {}", rec.path.display())),
        }
        eprintln!("token {label}: revoked (no longer declared)");
    }
    for email in undeclared_emails(db.provisioned_emails()?, state) {
        anyhow::ensure!(state::is_safe_ident(&email), "unsafe provisioned email");
        db.run(&db::lock_user_sql(&email))?;
        eprintln!("user {email}: locked (no longer declared)");
    }
    fs::create_dir_all(marker_dir)?;
    atomic_write_secret(&registry, &serde_json::to_string(&declared)?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::MetadataExt as _;

    use super::*;

    #[test]
    fn corrupt_registry_aborts_and_missing_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("r.json");
        let empty: BTreeSet<String> = read_registry(&f).unwrap();
        assert!(empty.is_empty());
        fs::write(&f, "{not json").unwrap();
        assert!(read_registry::<BTreeSet<String>>(&f).is_err());
    }

    #[test]
    fn env_line_quotes_and_rejects_control_chars() {
        assert_eq!(
            env_line("a b\"c\\d").unwrap(),
            "SUPERADMIN_SECRET=\"a b\\\"c\\\\d\"\n"
        );
        assert!(env_line("a\nb").is_err());
    }

    fn sample_state() -> State {
        serde_json::from_str(
            r#"{"url":"http://127.0.0.1:1","database":"d","superadmin_credential":"s",
            "disable_default_admin":true,
            "users":{"can":{"email":"can@example.com","credential_name":"p","workspaces":[],"admin":true}},
            "tokens":{"keep":{"user":"can","path":"/x/keep","owner":"root","group":"root","mode":"0600"}}}"#,
        )
        .unwrap()
    }

    #[test]
    fn removed_tokens_are_the_recorded_but_undeclared_ones() {
        let state = sample_state();
        let rec = |p: &str| Recorded {
            path: PathBuf::from(p),
            email: "can@example.com".into(),
        };
        let previous = BTreeMap::from([
            ("keep".to_owned(), rec("/x/keep")),
            ("gone".to_owned(), rec("/x/gone")),
        ]);
        assert_eq!(
            removed_tokens(&previous, &declared_tokens(&state)),
            vec![("gone".to_owned(), rec("/x/gone"))]
        );
        // A changed owner retires the old recorded token too.
        let moved = BTreeMap::from([("t".to_owned(), rec("/x/t"))]);
        let other = Recorded {
            path: "/x/t".into(),
            email: "other@example.com".into(),
        };
        assert_eq!(
            removed_tokens(&moved, &BTreeMap::from([("t".to_owned(), other)])).len(),
            1
        );
    }

    #[test]
    fn undeclared_emails_are_provisioned_logins_no_longer_declared() {
        let state = sample_state();
        let provisioned = vec!["can@example.com".to_owned(), "old@example.com".to_owned()];
        assert_eq!(
            undeclared_emails(provisioned, &state),
            vec!["old@example.com".to_owned()]
        );
    }

    #[test]
    fn token_reads_refuse_symlinks_and_hardlinks() {
        let root = tempfile::tempdir().unwrap();
        let secret = root.path().join("secret");
        fs::write(&secret, "other-secret").unwrap();
        let link = root.path().join("link");
        std::os::unix::fs::symlink(&secret, &link).unwrap();
        assert_eq!(read_token_file(&link), None);
        let hard = root.path().join("hard");
        fs::hard_link(&secret, &hard).unwrap();
        assert_eq!(read_token_file(&hard), None);
        let plain = root.path().join("plain");
        fs::write(&plain, "tok").unwrap();
        assert_eq!(read_token_file(&plain).as_deref(), Some("tok"));
    }

    #[test]
    fn install_token_sets_mode_without_following_a_planted_symlink() {
        let root = tempfile::tempdir().unwrap();
        let victim = root.path().join("victim");
        fs::write(&victim, "keep").unwrap();
        fs::set_permissions(&victim, fs::Permissions::from_mode(0o644)).unwrap();
        let path = root.path().join("tok");
        let token = state::Token {
            user: "can".into(),
            workspace: None,
            scopes: vec![],
            path: path.clone(),
            owner: fs::metadata(root.path()).unwrap().uid().to_string(),
            group: fs::metadata(root.path()).unwrap().gid().to_string(),
            mode: "0640".into(),
        };
        // A symlink planted at the final path is replaced, never followed.
        std::os::unix::fs::symlink(&victim, &path).unwrap();
        install_token(&token, "secret").unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "secret");
        assert!(
            !fs::symlink_metadata(&path)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o640
        );
        assert_eq!(fs::read_to_string(&victim).unwrap(), "keep");
        assert_eq!(
            fs::metadata(&victim).unwrap().permissions().mode() & 0o777,
            0o644
        );
    }

    #[test]
    fn ensure_dir_makes_every_new_ancestor_0755_and_keeps_existing_modes() {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let leaf = root.path().join("a/b/c");
        ensure_dir(&leaf).unwrap();
        for dir in ["a", "a/b", "a/b/c"] {
            let mode = fs::metadata(root.path().join(dir))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o755, "{dir}");
        }
        assert_eq!(
            fs::metadata(root.path()).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }

    #[test]
    fn a_source_tag_badge_is_read_from_the_leading_comment_block() {
        assert_eq!(source_tag("// tag hub\ncode"), Some("hub"));
        assert_eq!(source_tag("\n// summary\n// tag hub\ncode"), Some("hub"));
        assert_eq!(source_tag("# tag  hub \ncode"), Some("hub"));
        assert_eq!(source_tag("-- tag hub\nselect 1"), Some("hub"));
        // The badge does not apply past the comment block, and unrelated
        // comments are not tags.
        assert_eq!(source_tag("code\n// tag hub"), None);
        assert_eq!(source_tag("// taga hub"), None);
        assert_eq!(source_tag("// tags are useful"), None);
        assert_eq!(source_tag("// tag"), None);
        assert_eq!(source_tag("let x = 1;"), None);
    }

    #[test]
    fn a_deploy_is_skipped_only_for_identical_code_and_tag() {
        let deployed = client::DeployedScript {
            content: "export function main() {}".into(),
            language: "bun".into(),
            hash: "4376b64b1b94b9b9".into(),
            tag: Some("hub".into()),
        };
        assert!(script_unchanged(
            Some(&deployed),
            "bun",
            "export function main() {}",
            Some("hub")
        ));
        assert!(!script_unchanged(
            Some(&deployed),
            "bun",
            "export function main() { 1 }",
            Some("hub")
        ));
        assert!(!script_unchanged(
            Some(&deployed),
            "deno",
            &deployed.content,
            Some("hub")
        ));
        // A changed tag is a new version; an undeclared one keeps the deployed.
        assert!(!script_unchanged(
            Some(&deployed),
            "bun",
            &deployed.content,
            Some("other")
        ));
        assert!(!script_unchanged(
            Some(&deployed),
            "bun",
            &deployed.content,
            None
        ));
        assert!(!script_unchanged(
            None,
            "bun",
            &deployed.content,
            Some("hub")
        ));
        // Windmill reports an untagged version as `""` or null; both mean no tag.
        let untagged = client::DeployedScript {
            tag: Some(String::new()),
            ..deployed.clone()
        };
        assert!(script_unchanged(
            Some(&untagged),
            "bun",
            &deployed.content,
            None
        ));
        assert!(script_unchanged(
            Some(&client::DeployedScript {
                tag: None,
                ..deployed.clone()
            }),
            "bun",
            &deployed.content,
            None
        ));
    }

    #[test]
    fn a_variable_is_written_unless_value_secrecy_and_description_match() {
        let declared = state::Variable {
            credential_name: "password-hub".into(),
            is_secret: true,
            description: String::new(),
        };
        let live = |value: Option<&str>, is_secret: bool, description: Option<&str>| {
            client::DeployedVariable {
                value: value.map(str::to_owned),
                is_secret,
                description: description.map(str::to_owned),
            }
        };
        assert!(variable_unchanged(
            Some(&live(Some("tok"), true, None)),
            &declared,
            "tok"
        ));
        assert!(variable_unchanged(
            Some(&live(Some("tok"), true, Some(""))),
            &declared,
            "tok"
        ));
        assert!(!variable_unchanged(
            Some(&live(Some("tok"), true, None)),
            &declared,
            "rotated"
        ));
        // A secret Windmill did not decrypt cannot be compared: rewrite it.
        assert!(!variable_unchanged(
            Some(&live(None, true, None)),
            &declared,
            "tok"
        ));
        assert!(!variable_unchanged(
            Some(&live(Some("tok"), false, None)),
            &declared,
            "tok"
        ));
        assert!(!variable_unchanged(None, &declared, "tok"));
    }

    #[test]
    fn id_lookup_reads_third_field() {
        let passwd = "root:x:0:0::/root:/bin/sh\nstudio:x:994:993::/x:/bin/false\n";
        assert_eq!(lookup_id(passwd, "studio"), Some(994));
        assert_eq!(lookup_id(passwd, "ghost"), None);
    }
}
