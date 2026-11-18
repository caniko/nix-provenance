mod client;
mod state;

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context as _, Result, bail};
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

    // Deactivation comes before every step that can fail: a bad replacement
    // export or a credential write must not leave the old webhook serving.
    if state.workflows.values().any(|workflow| !workflow.active) {
        deactivate_declared(&n8n, state, &n8n.list_workflows()?)?;
    }

    // Resolve every target before writing anything: two declarations can
    // resolve to one n8n credential (a rename recorded under its old name plus
    // its live name), and the second write would overwrite the first's secret.
    let targets = resolve_targets(&existing, &previous, state)?;

    for (name, cred) in &state.credentials {
        let data = resolve_data(cred, credential_dir)?;
        // Digest over type + resolved data: the marker says "n8n holds exactly this".
        let id = format!("n8n-credential:{name}");
        let found = targets.get(name.as_str()).copied();
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

/// Deactivate every existing workflow declared `active = false`, before any
/// other step: publishing state is the only thing a later failure must not
/// strand, because a live webhook outlives a failed provision run.
fn deactivate_declared(n8n: &N8n, state: &State, existing: &[(String, String)]) -> Result<()> {
    for (name, workflow) in &state.workflows {
        if workflow.active {
            continue;
        }
        let Some((id, _)) = existing.iter().find(|(_, known)| known == name) else {
            continue;
        };
        if !n8n.workflow(id)?["active"].as_bool().unwrap_or(false) {
            continue;
        }
        n8n.deactivate_workflow(id)?;
        eprintln!("workflow {name}: deactivated");
    }
    Ok(())
}

/// Import or update every declared workflow by name, bind its credential
/// references to the provisioned credential ids, and converge its activation.
///
/// Workflows are compared against the live copy (n8n's read-back), not a
/// marker: a UI edit is reverted and an unchanged declaration writes nothing.
///
/// A workflow that executes another one is imported after it: n8n generates
/// the ids and validates an `executeWorkflow` reference by id when the caller
/// is published, so the reference is rewritten to the live id first.
fn reconcile_workflows(
    n8n: &N8n,
    state: &State,
    provisioned: &BTreeMap<String, ProvisionedCredential>,
) -> Result<()> {
    if state.workflows.is_empty() {
        return Ok(());
    }
    let existing = n8n.list_workflows()?;
    let mut index = WorkflowIndex::new(&existing);
    let mut declared = read_declared(state)?;
    for position in import_order(&declared)? {
        let declared = &mut declared[position];
        let name = declared.name.clone();
        let workflow = &state.workflows[&name];
        let mut payload = declared.payload.clone();
        bind_executed_workflows(&mut payload, &name, &index)?;
        bind_credentials(&mut payload["nodes"], &workflow.credentials, provisioned)
            .with_context(|| format!("workflow {name}"))?;
        let id = converge_workflow(n8n, &name, workflow.active, &payload, &existing)?;
        index.insert(&id, &name);
    }
    Ok(())
}

/// Import (or update) one workflow and converge its activation. Returns its id.
fn converge_workflow(
    n8n: &N8n,
    name: &str,
    active: bool,
    payload: &Value,
    existing: &[(String, String)],
) -> Result<String> {
    let mut created = false;
    let (id, version, was_active, active_version) =
        match existing.iter().find(|(_, known)| known == name) {
            None => {
                let state = n8n.create_workflow(payload)?;
                created = true;
                eprintln!("workflow {name}: created");
                (state.id, state.version, false, None)
            }
            Some((id, _)) => {
                let live = n8n.workflow(id)?;
                let version = live["versionId"].as_str().map(str::to_owned);
                let was_active = live["active"].as_bool().unwrap_or(false);
                let active_version = live["activeVersionId"].as_str().map(str::to_owned);
                if matches_declaration(payload, &live) {
                    (id.to_owned(), version, was_active, active_version)
                } else {
                    let state = n8n.update_workflow(id, payload)?;
                    eprintln!("workflow {name}: updated");
                    (state.id, state.version, was_active, active_version)
                }
            }
        };

    // Published means: active on exactly the version this run wrote. An
    // update to an active workflow bumps versionId, so it is republished.
    let published = was_active && version.is_some() && active_version == version;
    if active && !published {
        let version = version
            .with_context(|| format!("workflow {name}: n8n returned no versionId to activate"))?;
        n8n.activate_workflow(&id, &version)?;
        eprintln!(
            "workflow {name}: {}",
            if created { "activated" } else { "republished" }
        );
    } else if !active && was_active {
        n8n.deactivate_workflow(&id)?;
        eprintln!("workflow {name}: deactivated");
    }
    Ok(id)
}

/// A declared workflow read from its export, before references are resolved.
struct DeclaredWorkflow {
    name: String,
    payload: Value,
}

fn read_declared(state: &State) -> Result<Vec<DeclaredWorkflow>> {
    state
        .workflows
        .iter()
        .map(|(name, workflow)| {
            let raw = fs::read_to_string(&workflow.file)
                .with_context(|| format!("reading {}", workflow.file.display()))?;
            let file: Value = serde_json::from_str(&raw)
                .with_context(|| format!("parsing workflow file {}", workflow.file.display()))?;
            Ok(DeclaredWorkflow {
                name: name.clone(),
                payload: workflow_payload(name, &file)?,
            })
        })
        .collect()
}

/// Declared positions ordered so every workflow follows the declared ones it
/// executes. A cycle cannot be imported, because no member can be published
/// before another.
fn import_order(declared: &[DeclaredWorkflow]) -> Result<Vec<usize>> {
    let position: BTreeMap<&str, usize> = declared
        .iter()
        .enumerate()
        .map(|(i, workflow)| (workflow.name.as_str(), i))
        .collect();
    let dependencies: Vec<Vec<usize>> = declared
        .iter()
        .map(|workflow| {
            executed_references(&workflow.payload)
                .iter()
                .filter_map(|reference| position.get(reference.as_str()).copied())
                .collect()
        })
        .collect();
    let mut imported = vec![false; declared.len()];
    let mut order = Vec::with_capacity(declared.len());
    while order.len() < declared.len() {
        let ready: Vec<usize> = (0..declared.len())
            .filter(|i| !imported[*i] && dependencies[*i].iter().all(|d| imported[*d]))
            .collect();
        if ready.is_empty() {
            let cyclic: Vec<&str> = (0..declared.len())
                .filter(|i| !imported[*i])
                .map(|i| declared[i].name.as_str())
                .collect();
            bail!(
                "declared workflows execute each other in a cycle: {}",
                cyclic.join(", ")
            );
        }
        for i in ready {
            imported[i] = true;
            order.push(i);
        }
    }
    Ok(order)
}

/// Workflow identity by name and by id, kept current as this run imports.
struct WorkflowIndex {
    id_by_name: BTreeMap<String, String>,
    name_by_id: BTreeMap<String, String>,
}

impl WorkflowIndex {
    fn new(existing: &[(String, String)]) -> Self {
        let mut index = Self {
            id_by_name: BTreeMap::new(),
            name_by_id: BTreeMap::new(),
        };
        for (id, name) in existing {
            index.insert(id, name);
        }
        index
    }

    fn insert(&mut self, id: &str, name: &str) {
        self.id_by_name.insert(name.to_owned(), id.to_owned());
        self.name_by_id.insert(id.to_owned(), name.to_owned());
    }

    /// The live `(id, name)` a reference names: an id already, a declared name,
    /// or the name of a workflow that existed in n8n before this run.
    fn resolve(&self, reference: &str) -> Option<(String, String)> {
        if let Some(name) = self.name_by_id.get(reference) {
            return Some((reference.to_owned(), name.clone()));
        }
        self.id_by_name
            .get(reference)
            .map(|id| (id.clone(), reference.to_owned()))
    }
}

/// The workflows a declared payload executes, as written in its
/// `executeWorkflow` nodes.
fn executed_references(payload: &Value) -> Vec<String> {
    payload["nodes"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(executed_reference)
        .map(str::to_owned)
        .collect()
}

/// The workflow reference an `executeWorkflow` node carries, when it resolves
/// one from a name or id rather than at run time.
fn executed_reference(node: &Value) -> Option<&str> {
    if node.get("type").and_then(Value::as_str) != Some(EXECUTE_WORKFLOW) {
        return None;
    }
    let parameters = node.get("parameters")?;
    // `source = parameter` means the id comes from an expression.
    if parameters.get("source").and_then(Value::as_str) == Some("parameter") {
        return None;
    }
    let value = match parameters.get("workflowId")? {
        // "By URL" names another instance's workflow, never one here.
        Value::Object(object) => {
            if object.get("mode").and_then(Value::as_str) == Some("url") {
                return None;
            }
            object.get("value")?.as_str()?
        }
        Value::String(value) => value.as_str(),
        _ => return None,
    };
    (!value.contains("{{")).then_some(value)
}

/// Rewrite every `executeWorkflow` reference of `payload` to the live id of the
/// workflow it names. n8n generates the ids and validates the reference by id
/// when the caller is published, so a name (or a stale id) never survives.
fn bind_executed_workflows(payload: &mut Value, caller: &str, index: &WorkflowIndex) -> Result<()> {
    let nodes = payload["nodes"]
        .as_array_mut()
        .context("nodes must be an array")?;
    for node in nodes {
        let Some(reference) = executed_reference(node).map(str::to_owned) else {
            continue;
        };
        let node_name = node
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("<unnamed>")
            .to_owned();
        let Some((id, name)) = index.resolve(&reference) else {
            bail!(
                "workflow {caller}, node {node_name}: executes {reference:?}, which is neither declared nor present in n8n"
            )
        };
        if id == reference {
            continue;
        }
        let Some(locator) = node
            .get_mut("parameters")
            .and_then(|parameters| parameters.get_mut("workflowId"))
        else {
            continue;
        };
        match locator {
            Value::String(value) => *value = id,
            Value::Object(object) => {
                object.insert("value".into(), json!(id));
                object.insert("cachedResultName".into(), json!(name));
            }
            _ => {}
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

/// True when the live copy is exactly the declaration: the same name, the same
/// nodes (field for field, after dropping the ids n8n generates and mints), the
/// same connections, settings and metadata. Anything extra in the live copy is
/// drift too — a `disabled` a UI edit added to a node, an edited connection —
/// while a workflow n8n left alone matches.
fn matches_declaration(desired: &Value, live: &Value) -> bool {
    let (Some(desired), Some(live)) = (desired.as_object(), live.as_object()) else {
        return false;
    };
    desired.iter().all(|(key, value)| {
        let live = live.get(key);
        match key.as_str() {
            "nodes" => live.is_some_and(|live| nodes(value) == nodes(live)),
            _ => live == Some(value),
        }
    })
}

/// Node fields n8n owns: the id it assigns and the `webhookId` it mints for
/// trigger nodes. The tenant declares neither, so they never count as drift.
const NODE_GENERATED: [&str; 2] = ["id", "webhookId"];

/// The nodes with their n8n-generated fields removed, for an exact comparison.
fn nodes(value: &Value) -> Vec<BTreeMap<&str, &Value>> {
    value
        .as_array()
        .into_iter()
        .flatten()
        .map(|node| match node.as_object() {
            Some(node) => node
                .iter()
                .filter(|(key, _)| !NODE_GENERATED.contains(&key.as_str()))
                .map(|(key, value)| (key.as_str(), value))
                .collect(),
            None => BTreeMap::from([("", node)]),
        })
        .collect()
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
/// The n8n node type that calls another workflow, by name or id.
const EXECUTE_WORKFLOW: &str = "n8n-nodes-base.executeWorkflow";

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

/// Resolve every declared credential's n8n target before any write. Two
/// declarations that resolve to one credential (a recorded id plus a live name
/// match after a rename) would overwrite each other's secret, so refuse.
fn resolve_targets<'a>(
    existing: &'a [(String, String)],
    previous: &BTreeMap<String, String>,
    state: &'a State,
) -> Result<BTreeMap<&'a str, &'a str>> {
    let mut targets = BTreeMap::new();
    let mut claimed: BTreeMap<&str, &str> = BTreeMap::new();
    for name in state.credentials.keys() {
        let Some(cred_id) = pick_target(existing, previous, name)? else {
            continue;
        };
        if let Some(other) = claimed.insert(cred_id, name) {
            bail!(
                "credentials {other} and {name} both resolve to n8n credential {cred_id}: rename or delete one in n8n"
            );
        }
        targets.insert(name.as_str(), cred_id);
    }
    Ok(targets)
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
    fn a_declaration_matches_only_an_identical_live_copy() {
        let desired = json!({
            "name": "w",
            "nodes": [{"name": "Webhook", "type": "webhook", "position": [0, 0]}],
            "connections": {"Webhook": {"main": [[]]}},
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
            "connections": {"Webhook": {"main": [[]]}},
            "settings": {"executionOrder": "v1"},
        });
        assert!(matches_declaration(&desired, &live));
        // A managed change (position, node count, settings, connections) is drift.
        let moved = json!({
            "nodes": [{"name": "Webhook", "type": "webhook", "position": [10, 0]}],
        });
        assert!(!matches_declaration(&moved, &live));
        let extra_node = json!({
            "nodes": [
                {"name": "Webhook", "type": "webhook", "position": [0, 0]},
                {"name": "Extra", "type": "noop", "position": [0, 0]},
            ],
        });
        assert!(!matches_declaration(&extra_node, &live));
        let other_order = json!({"settings": {"executionOrder": "v0"}});
        assert!(!matches_declaration(&other_order, &live));
        let dropped_connection = json!({"connections": {}});
        assert!(!matches_declaration(&dropped_connection, &live));
        // A field a UI edit added to a node is drift, not an extra to ignore.
        let disabled = json!({
            "nodes": [{
                "id": "n1", "name": "Webhook", "type": "webhook",
                "position": [0, 0], "webhookId": "hook-1", "disabled": true,
            }],
        });
        assert!(!matches_declaration(&live, &disabled));
        // An extra settings key is drift too.
        let extra_setting = json!({"settings": {"executionOrder": "v1", "timezone": "UTC"}});
        assert!(!matches_declaration(&extra_setting, &live));
    }

    #[test]
    fn executed_workflows_are_references_only_when_they_name_one() {
        let payload = json!({"nodes": [
            {"name": "Claim", "type": EXECUTE_WORKFLOW, "parameters": {
                "workflowId": {"__rl": true, "value": "fleetix-hub-claim", "mode": "list"},
            }},
            {"name": "Plain", "type": EXECUTE_WORKFLOW, "parameters": {
                "workflowId": "by-id",
            }},
            {"name": "Expression", "type": EXECUTE_WORKFLOW, "parameters": {
                "workflowId": {"__rl": true, "value": "={{ $json.id }}", "mode": "list"},
            }},
            {"name": "Parameter", "type": EXECUTE_WORKFLOW, "parameters": {
                "source": "parameter", "workflowId": {"value": "from-args"},
            }},
            {"name": "Url", "type": EXECUTE_WORKFLOW, "parameters": {
                "workflowId": {"__rl": true, "value": "https://x/y", "mode": "url"},
            }},
            {"name": "Other", "type": "n8n-nodes-base.code", "parameters": {}},
        ]});
        assert_eq!(
            executed_references(&payload),
            vec!["fleetix-hub-claim".to_owned(), "by-id".to_owned()]
        );
    }

    #[test]
    fn callers_are_imported_after_the_workflows_they_execute() {
        let declared = |name: &str, executes: Option<&str>| DeclaredWorkflow {
            name: name.to_owned(),
            payload: json!({"name": name, "nodes": match executes {
                Some(target) => json!([{"name": "Call", "type": EXECUTE_WORKFLOW, "parameters": {
                    "workflowId": {"__rl": true, "value": target, "mode": "list"},
                }}]),
                None => json!([]),
            }}),
        };
        // Declared order is alphabetical; the caller comes last in the import.
        let order = import_order(&[
            declared("fleetix-hub-bluesky", Some("fleetix-hub-claim")),
            declared("fleetix-hub-claim", None),
            declared("fleetix-hub-lookup", None),
        ])
        .unwrap();
        let names: Vec<&str> = order
            .iter()
            .map(|i| {
                [
                    "fleetix-hub-bluesky",
                    "fleetix-hub-claim",
                    "fleetix-hub-lookup",
                ][*i]
            })
            .collect();
        assert_eq!(
            names,
            vec![
                "fleetix-hub-claim",
                "fleetix-hub-lookup",
                "fleetix-hub-bluesky"
            ]
        );
        // A cycle has no valid order.
        let err = import_order(&[declared("a", Some("b")), declared("b", Some("a"))]).unwrap_err();
        assert!(err.to_string().contains("cycle"), "{err}");
        // A reference outside the declaration is not a dependency.
        assert_eq!(
            import_order(&[declared("a", Some("elsewhere"))])
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn execute_workflow_references_are_rewritten_to_live_ids() {
        let mut index = WorkflowIndex::new(&[("w0".to_owned(), "fleetix-hub-claim".to_owned())]);
        let mut payload = json!({"name": "caller", "nodes": [
            {"name": "Claim", "type": EXECUTE_WORKFLOW, "parameters": {
                "workflowId": {"__rl": true, "value": "fleetix-hub-claim", "mode": "list",
                               "cachedResultName": "fleetix-hub-claim"},
            }},
            {"name": "Webhook", "type": "n8n-nodes-base.webhook", "parameters": {}},
        ]});
        bind_executed_workflows(&mut payload, "caller", &index).unwrap();
        assert_eq!(
            payload["nodes"][0]["parameters"]["workflowId"],
            json!({"__rl": true, "value": "w0", "mode": "list",
                   "cachedResultName": "fleetix-hub-claim"})
        );
        // An id already live is left alone, and an unknown reference fails.
        let mut by_id = json!({"nodes": [{"name": "Claim", "type": EXECUTE_WORKFLOW,
            "parameters": {"workflowId": {"value": "w0", "mode": "list"}}}]});
        bind_executed_workflows(&mut by_id, "caller", &index).unwrap();
        assert_eq!(by_id["nodes"][0]["parameters"]["workflowId"]["value"], "w0");
        let mut ghost = json!({"nodes": [{"name": "Claim", "type": EXECUTE_WORKFLOW,
            "parameters": {"workflowId": {"value": "ghost", "mode": "list"}}}]});
        let err = bind_executed_workflows(&mut ghost, "caller", &index).unwrap_err();
        assert!(err.to_string().contains("ghost"), "{err}");
        // The next import in the run resolves the id it just created.
        index.insert("w1", "fleetix-hub-bluesky");
        assert_eq!(
            index.resolve("fleetix-hub-bluesky"),
            Some(("w1".to_owned(), "fleetix-hub-bluesky".to_owned()))
        );
        assert_eq!(index.resolve("ghost"), None);
    }

    #[test]
    fn two_declarations_cannot_share_one_n8n_credential() {
        let state: State = serde_json::from_str(
            r#"{"url":"http://127.0.0.1:5678",
            "owner":{"email":"a@b.c","first_name":"A","last_name":"B","credential_name":"p"},
            "credentials":{
              "A":{"type":"httpHeaderAuth"},
              "B":{"type":"httpHeaderAuth"}}}"#,
        )
        .unwrap();
        // A was recorded under id 1; the credential it names is now called B,
        // which is also declared, so both declarations resolve to id 1.
        let existing = vec![("1".to_owned(), "B".to_owned())];
        let previous = BTreeMap::from([("A".to_owned(), "1".to_owned())]);
        let err = resolve_targets(&existing, &previous, &state).unwrap_err();
        assert!(err.to_string().contains("both resolve"), "{err}");
        // Distinct targets resolve without a claim.
        let existing = vec![
            ("1".to_owned(), "A".to_owned()),
            ("2".to_owned(), "B".to_owned()),
        ];
        let targets = resolve_targets(&existing, &BTreeMap::new(), &state).unwrap();
        assert_eq!(targets["A"], "1");
        assert_eq!(targets["B"], "2");
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
