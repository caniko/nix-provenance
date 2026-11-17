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
    about = "Declarative n8n owner, credential and workflow bootstrap",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Render N8N_INSTANCE_OWNER_* (bcrypt hash) into an EnvironmentFile (run by the n8n-owner-env oneshot).
    OwnerEnv {
        #[arg(long)]
        state: PathBuf,
        /// Owner password file, read as root here so n8n itself never gets it.
        #[arg(long)]
        password_file: PathBuf,
        /// Directory persisting the last bcrypt hash so restarts do not churn it.
        #[arg(long)]
        hash_dir: PathBuf,
        #[arg(long)]
        out: PathBuf,
        /// Where to record the password digest for `changed`.
        #[arg(long)]
        stamp: PathBuf,
    },
    /// Exit 0 only when the owner password differs from the digest recorded at
    /// the last render (ExecCondition of the rotation restart; exit 1 skips it).
    Changed {
        #[arg(long)]
        password_file: PathBuf,
        #[arg(long)]
        stamp: PathBuf,
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
            password_file,
            hash_dir,
            out,
            stamp,
        } => owner_env(
            &load_state(&state)?,
            &password_file,
            &hash_dir,
            &out,
            &stamp,
        ),
        Command::Changed {
            password_file,
            stamp,
        } => {
            if provenance_core::stamp::secret_unchanged(&password_file, &stamp)? {
                std::process::exit(1);
            }
            Ok(())
        }
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
/// Stored hash: regular file, no symlink, at most 128 bytes (a bcrypt hash is 60).
fn read_hash(path: &Path) -> Option<String> {
    use std::io::Read as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .ok()?;
    if !file.metadata().ok()?.is_file() {
        return None;
    }
    let mut buf = String::new();
    file.take(128).read_to_string(&mut buf).ok()?;
    Some(buf)
}

fn owner_hash(password: &str, hash_file: &Path) -> Result<String> {
    // bcrypt silently truncates beyond 72 bytes, which would accept any
    // password sharing that prefix.
    anyhow::ensure!(
        password.len() <= 72,
        "owner password exceeds bcrypt's 72-byte limit"
    );
    if let Some(existing) = read_hash(hash_file) {
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

fn owner_env(
    state: &State,
    password_file: &Path,
    hash_dir: &Path,
    out: &Path,
    stamp: &Path,
) -> Result<()> {
    let password = read_password_file(password_file)?;
    provenance_core::stamp::record(stamp, &password)?;
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
        let prefix = cred
            .data_file_prefixes
            .get(field)
            .map(String::as_str)
            .unwrap_or("");
        data.insert(
            field.clone(),
            json!(format!(
                "{prefix}{}",
                read_secret_value(&credential_dir.join(file))?
            )),
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
    let registry = marker_dir.join(CREDENTIAL_REGISTRY);
    let previous: BTreeMap<String, String> = read_registry(&registry)?;
    // name -> id of credentials this tool created (never adopted ones).
    let mut owned = previous.clone();
    // name -> what n8n holds after this run, for the workflow credential ids.
    let mut provisioned: BTreeMap<String, ProvisionedCredential> = BTreeMap::new();

    for (name, cred) in &state.credentials {
        let data = resolve_data(cred, credential_dir)?;
        // Digest over type + resolved data: the marker says "n8n holds exactly this".
        let id = format!("n8n-credential:{name}");
        let found = pick_target(&existing, &previous, name)?;
        // A credential we created, renamed in n8n and in the declaration
        // alike, stays ours under its new name (and is not pruned below).
        if let Some(cred_id) = found
            && previous.values().any(|i| i == cred_id)
        {
            owned.insert(name.clone(), cred_id.to_owned());
        }
        // The target id is part of the fingerprint: a different n8n credential
        // under this name (recreated, or a UI one) must always be written.
        let fingerprint = |target: &str| secret_digest(&format!("{target}\n{}\n{data}", cred.kind));
        let target = match found {
            Some(cred_id) if !markers.needs_update(&id, &fingerprint(cred_id))? => {
                cred_id.to_owned()
            }
            Some(cred_id) => {
                n8n.update_credential(cred_id, name, &cred.kind, &data)?;
                markers.commit(&id, &fingerprint(cred_id))?;
                eprintln!("credential {name}: updated");
                cred_id.to_owned()
            }
            None => {
                let new_id = n8n.create_credential(name, &cred.kind, &data)?;
                owned.insert(name.clone(), new_id.clone());
                // Persist at once: a later failure must not forget this ownership.
                save_registry(&registry, &owned, marker_dir)?;
                markers.commit(&id, &fingerprint(&new_id))?;
                eprintln!("credential {name}: created");
                new_id
            }
        };
        provisioned.insert(
            name.clone(),
            ProvisionedCredential {
                id: target,
                kind: cred.kind.clone(),
            },
        );
    }

    // Delete credentials this tool created that are no longer declared, by
    // recorded id only: same-named UI or adopted credentials are never touched.
    for (name, id) in removed_credentials(&previous, state) {
        owned.remove(&name);
        if owned.values().any(|i| *i == id) {
            continue;
        }
        // Already gone (deleted by hand): the desired state holds, nothing to do.
        if existing.iter().any(|(i, _)| *i == id) {
            n8n.delete_credential(&id)?;
            eprintln!("credential {name}: deleted (no longer declared)");
        }
    }
    fs::create_dir_all(marker_dir)?;
    save_registry(&registry, &owned, marker_dir)?;
    reconcile_workflows(&n8n, state, &provisioned)?;
    Ok(())
}

fn save_registry(
    registry: &Path,
    owned: &BTreeMap<String, String>,
    marker_dir: &Path,
) -> Result<()> {
    fs::create_dir_all(marker_dir)?;
    atomic_write_secret(registry, &serde_json::to_string(owned)?)?;
    Ok(())
}

/// A declared credential as n8n holds it after this run.
struct ProvisionedCredential {
    id: String,
    kind: String,
}

/// Import or update every declared workflow by name, bind its credential
/// references to the provisioned credential ids, and converge its activation.
///
/// Workflows are compared against the live copy (n8n's read-back), not a
/// marker: a UI edit is reverted and an unchanged declaration writes nothing.
fn reconcile_workflows(
    n8n: &N8n,
    state: &State,
    provisioned: &BTreeMap<String, ProvisionedCredential>,
) -> Result<()> {
    if state.workflows.is_empty() {
        return Ok(());
    }
    let existing = n8n.list_workflows()?;
    for (name, workflow) in &state.workflows {
        let raw = fs::read_to_string(&workflow.file)
            .with_context(|| format!("reading {}", workflow.file.display()))?;
        let file: Value = serde_json::from_str(&raw)
            .with_context(|| format!("parsing workflow file {}", workflow.file.display()))?;
        let mut payload = workflow_payload(name, &file)?;
        bind_credentials(&mut payload["nodes"], &workflow.credentials, provisioned)
            .with_context(|| format!("workflow {name}"))?;

        let mut created = false;
        let (id, version, was_active, active_version) =
            match existing.iter().find(|(_, known)| known == name) {
                None => {
                    let state = n8n.create_workflow(&payload)?;
                    created = true;
                    eprintln!("workflow {name}: created");
                    (state.id, state.version, false, None)
                }
                Some((id, _)) => {
                    let live = n8n.workflow(id)?;
                    let version = live["versionId"].as_str().map(str::to_owned);
                    let was_active = live["active"].as_bool().unwrap_or(false);
                    let active_version = live["activeVersionId"].as_str().map(str::to_owned);
                    if covers(&payload, &live) {
                        (id.clone(), version, was_active, active_version)
                    } else {
                        let state = n8n.update_workflow(id, &payload)?;
                        eprintln!("workflow {name}: updated");
                        (state.id, state.version, was_active, active_version)
                    }
                }
            };

        // Published means: active on exactly the version this run wrote. An
        // update to an active workflow bumps versionId, so it is republished.
        let published = was_active && version.is_some() && active_version == version;
        if workflow.active && !published {
            let version = version.with_context(|| {
                format!("workflow {name}: n8n returned no versionId to activate")
            })?;
            n8n.activate_workflow(&id, &version)?;
            eprintln!(
                "workflow {name}: {}",
                if created { "activated" } else { "republished" }
            );
        } else if !workflow.active && was_active {
            n8n.deactivate_workflow(&id)?;
            eprintln!("workflow {name}: deactivated");
        }
    }
    Ok(())
}

/// The import payload: the managed fields of a workflow export, renamed to the
/// declared name. `active`, `id` and `pinData` are never taken from the file.
fn workflow_payload(name: &str, file: &Value) -> Result<Value> {
    let nodes = file
        .get("nodes")
        .filter(|nodes| nodes.is_array())
        .context("workflow file has no nodes array")?;
    let connections = file
        .get("connections")
        .filter(|connections| connections.is_object())
        .context("workflow file has no connections object")?;
    let mut payload = json!({"name": name, "nodes": nodes, "connections": connections});
    for key in ["settings", "meta"] {
        if let Some(value) = file.get(key)
            && !value.is_null()
        {
            payload[key] = value.clone();
        }
    }
    Ok(payload)
}

/// Rewrite every node credential reference to `{id, name}` of the declared
/// credential it maps to, failing when the reference is not provisioned with
/// the type the node expects.
fn bind_credentials(
    nodes: &mut Value,
    mapping: &BTreeMap<String, String>,
    provisioned: &BTreeMap<String, ProvisionedCredential>,
) -> Result<()> {
    let nodes = nodes.as_array_mut().context("nodes must be an array")?;
    for node in nodes {
        let node_name = node
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("<unnamed>")
            .to_owned();
        let Some(credentials) = node.get_mut("credentials") else {
            continue;
        };
        let credentials = credentials
            .as_object_mut()
            .context("node credentials must be an object")?;
        for (kind, reference) in credentials.iter_mut() {
            let current = reference["name"]
                .as_str()
                .or_else(|| reference.as_str())
                .with_context(|| format!("node {node_name}: credential {kind} has no name"))?;
            let declared = mapping.get(current).map(String::as_str).unwrap_or(current);
            let credential = provisioned.get(declared).with_context(|| {
                format!(
                    "node {node_name}: credential {kind} references {declared:?}, which services.n8n.provision.credentials does not declare"
                )
            })?;
            anyhow::ensure!(
                credential.kind == *kind,
                "node {node_name}: {declared:?} is a {} credential but the node needs {kind}",
                credential.kind
            );
            *reference = json!({"id": credential.id, "name": declared});
        }
    }
    Ok(())
}

/// True when every field the tenant manages in `desired` is present unchanged
/// in `live`. Extra fields are ignored (n8n adds node ids and `webhookId`s),
/// while a changed managed field forces a write.
fn covers(desired: &Value, live: &Value) -> bool {
    match desired {
        Value::Object(desired) => live.as_object().is_some_and(|live| {
            desired
                .iter()
                .all(|(key, value)| live.get(key).is_some_and(|other| covers(value, other)))
        }),
        Value::Array(desired) => live.as_array().is_some_and(|live| {
            desired.len() == live.len()
                && desired
                    .iter()
                    .zip(live)
                    .all(|(value, other)| covers(value, other))
        }),
        _ => desired == live,
    }
}
/// The n8n credential to update: the recorded one when it still exists, else a
/// single same-named one (adopted); several candidates are ambiguous, so refuse.
fn pick_target<'a>(
    existing: &'a [(String, String)],
    previous: &BTreeMap<String, String>,
    name: &str,
) -> Result<Option<&'a str>> {
    if let Some(id) = previous.get(name)
        && let Some((i, _)) = existing.iter().find(|(i, _)| i == id)
    {
        return Ok(Some(i));
    }
    let mut named = existing.iter().filter(|(_, n)| n == name);
    let first = named.next().map(|(i, _)| i.as_str());
    anyhow::ensure!(
        named.next().is_none(),
        "credential {name}: several n8n credentials share this name and none is recorded as ours"
    );
    Ok(first)
}

const CREDENTIAL_REGISTRY: &str = "credentials.json";

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

/// Credentials (name, id) recorded by earlier runs that are no longer declared.
fn removed_credentials(
    previous: &BTreeMap<String, String>,
    state: &State,
) -> Vec<(String, String)> {
    previous
        .iter()
        .filter(|(name, _)| !state.credentials.contains_key(*name))
        .map(|(n, i)| (n.clone(), i.clone()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn workflow_payload_takes_the_managed_fields_and_the_declared_name() {
        let file = json!({
            "name": "exported-name",
            "nodes": [{"name": "Webhook", "type": "n8n-nodes-base.webhook"}],
            "connections": {"Webhook": {}},
            "settings": {"executionOrder": "v1"},
            "meta": {"contract": "fleetix-hub/v1"},
            "active": true,
            "id": "not-ours",
        });
        let payload = workflow_payload("fleetix-hub-claim", &file).unwrap();
        assert_eq!(payload["name"], "fleetix-hub-claim");
        assert_eq!(payload["nodes"], file["nodes"]);
        assert_eq!(payload["connections"], file["connections"]);
        assert_eq!(payload["settings"], file["settings"]);
        assert_eq!(payload["meta"], file["meta"]);
        // The file's activation state and id never decide n8n's.
        assert!(payload.get("active").is_none());
        assert!(payload.get("id").is_none());
        assert!(workflow_payload("x", &json!({"connections": {}})).is_err());
        assert!(workflow_payload("x", &json!({"nodes": []})).is_err());
    }

    fn provisioned() -> BTreeMap<String, ProvisionedCredential> {
        BTreeMap::from([
            (
                "hub-webhook".to_owned(),
                ProvisionedCredential {
                    id: "c1".into(),
                    kind: "httpHeaderAuth".into(),
                },
            ),
            (
                "hub-db".to_owned(),
                ProvisionedCredential {
                    id: "c2".into(),
                    kind: "postgres".into(),
                },
            ),
        ])
    }

    #[test]
    fn node_credentials_are_rewritten_to_the_provisioned_ids() {
        let mut nodes = json!([
            {"name": "Webhook", "credentials": {"httpHeaderAuth": {"name": "Fleetix Hub webhook token"}}},
            {"name": "Record", "credentials": {"postgres": {"id": "stale", "name": "Fleetix Hub publications"}}},
            {"name": "Plain", "parameters": {}},
        ]);
        let mapping = BTreeMap::from([
            (
                "Fleetix Hub webhook token".to_owned(),
                "hub-webhook".to_owned(),
            ),
            ("Fleetix Hub publications".to_owned(), "hub-db".to_owned()),
        ]);
        bind_credentials(&mut nodes, &mapping, &provisioned()).unwrap();
        assert_eq!(
            nodes[0]["credentials"]["httpHeaderAuth"],
            json!({"id": "c1", "name": "hub-webhook"})
        );
        assert_eq!(
            nodes[1]["credentials"]["postgres"],
            json!({"id": "c2", "name": "hub-db"})
        );
        assert!(nodes[2].get("credentials").is_none());
    }

    #[test]
    fn an_unmapped_reference_must_be_a_declared_credential_name() {
        // Identity mapping: the reference name is the declared credential name.
        let mut nodes = json!([
            {"name": "Webhook", "credentials": {"httpHeaderAuth": {"name": "hub-webhook"}}},
        ]);
        bind_credentials(&mut nodes, &BTreeMap::new(), &provisioned()).unwrap();
        assert_eq!(
            nodes[0]["credentials"]["httpHeaderAuth"],
            json!({"id": "c1", "name": "hub-webhook"})
        );
        // An undeclared reference and a type mismatch both fail closed.
        let mut ghost = json!([
            {"name": "Webhook", "credentials": {"httpHeaderAuth": {"name": "ghost"}}},
        ]);
        let err = bind_credentials(&mut ghost, &BTreeMap::new(), &provisioned()).unwrap_err();
        assert!(err.to_string().contains("ghost"), "{err}");
        let mut wrong_type = json!([
            {"name": "Record", "credentials": {"httpHeaderAuth": {"name": "hub-db"}}},
        ]);
        assert!(bind_credentials(&mut wrong_type, &BTreeMap::new(), &provisioned()).is_err());
    }

    #[test]
    fn covers_ignores_fields_n8n_adds_but_sees_managed_changes() {
        let desired = json!({
            "name": "w",
            "nodes": [{"name": "Webhook", "type": "webhook", "position": [0, 0]}],
            "settings": {"executionOrder": "v1"},
        });
        // n8n adds node ids, webhookId, active, versionId, checksum...
        let live = json!({
            "name": "w",
            "active": false,
            "versionId": "v1",
            "checksum": "abc",
            "nodes": [{
                "id": "n1", "name": "Webhook", "type": "webhook",
                "position": [0, 0], "webhookId": "hook-1",
            }],
            "settings": {"executionOrder": "v1", "timezone": "UTC"},
        });
        assert!(covers(&desired, &live));
        // A managed change (position, node count, settings) is not covered.
        let moved = json!({
            "nodes": [{"name": "Webhook", "type": "webhook", "position": [10, 0]}],
            "settings": {"executionOrder": "v1"},
        });
        assert!(!covers(&moved, &live));
        let extra_node = json!({
            "nodes": [
                {"name": "Webhook", "type": "webhook", "position": [0, 0]},
                {"name": "Extra", "type": "noop", "position": [0, 0]},
            ],
        });
        assert!(!covers(&extra_node, &live));
        let other_order = json!({"settings": {"executionOrder": "v0"}});
        assert!(!covers(&other_order, &live));
    }

    #[test]
    fn credential_prefix_is_applied_while_the_file_stays_the_secret() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("token"), "abc123\n").unwrap();
        let cred: state::Credential = serde_json::from_str(
            r#"{"type":"httpHeaderAuth",
                "data":{"name":"Authorization"},
                "data_files":{"value":"token"},
                "data_file_prefixes":{"value":"Bearer "}}"#,
        )
        .unwrap();
        let data = resolve_data(&cred, dir.path()).unwrap();
        assert_eq!(data["name"], "Authorization");
        assert_eq!(data["value"], "Bearer abc123");
    }

    #[test]
    fn target_prefers_recorded_id_and_refuses_ambiguity() {
        let existing = vec![
            ("a".to_owned(), "c".to_owned()),
            ("b".to_owned(), "c".to_owned()),
        ];
        let mut previous = BTreeMap::new();
        assert!(pick_target(&existing, &previous, "c").is_err());
        previous.insert("c".to_owned(), "b".to_owned());
        assert_eq!(pick_target(&existing, &previous, "c").unwrap(), Some("b"));
        assert_eq!(pick_target(&existing, &previous, "zz").unwrap(), None);
    }

    #[test]
    fn corrupt_registry_aborts_and_missing_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("r.json");
        let empty: BTreeMap<String, String> = read_registry(&f).unwrap();
        assert!(empty.is_empty());
        fs::write(&f, "{not json").unwrap();
        assert!(read_registry::<BTreeMap<String, String>>(&f).is_err());
    }

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
    fn removed_credentials_are_recorded_but_undeclared_names() {
        let state: State = serde_json::from_str(
            r#"{"url":"http://127.0.0.1:5678",
            "owner":{"email":"a@b.c","first_name":"A","last_name":"B","credential_name":"p"},
            "credentials":{"keep":{"type":"httpHeaderAuth"}}}"#,
        )
        .unwrap();
        let previous = BTreeMap::from([
            ("keep".to_owned(), "1".to_owned()),
            ("gone".to_owned(), "2".to_owned()),
        ]);
        assert_eq!(
            removed_credentials(&previous, &state),
            vec![("gone".to_owned(), "2".to_owned())]
        );
    }

    #[test]
    fn stored_hash_ignores_symlinks_and_oversize_files() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real");
        fs::write(&real, "x".repeat(1000)).unwrap();
        assert_eq!(read_hash(&real).unwrap().len(), 128);
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert!(read_hash(&link).is_none());
    }

    #[test]
    fn credential_target_change_changes_fingerprint() {
        let fp = |t: &str| secret_digest(&format!("{t}\nk\n{{}}"));
        assert_ne!(fp("1"), fp("2"));
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
