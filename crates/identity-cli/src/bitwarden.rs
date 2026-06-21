//! Bitwarden CLI-backed login item upsert support.

use std::env;
use std::ffi::OsStr;
use std::io::{self, Read};
use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result, anyhow, bail};
use base64::Engine;
use serde::Deserialize;
use serde_json::{Value, json};

const VAULT_LOCKED_MESSAGE: &str =
    "Bitwarden vault locked or session missing: run `bw unlock` and export `BW_SESSION`";

/// A Bitwarden login item to create or update.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BwLoginItem {
    pub name: String,
    pub username: String,
    pub password: String,
    pub totp: Option<String>,
    pub folder: Option<String>,
    pub session: Option<String>,
}

/// Inputs accepted by the `bitwarden upsert` CLI command.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct UpsertInput {
    pub name: Option<String>,
    pub username: Option<String>,
    pub password_from: Option<String>,
    pub totp: Option<String>,
    pub folder: Option<String>,
    pub session: Option<String>,
    pub from_json: Option<String>,
    pub use_primary: bool,
}

/// Create or update a Bitwarden login item idempotently using the `bw` CLI.
pub fn upsert_login(item: BwLoginItem) -> Result<()> {
    let session = require_unlocked_session(item.session.as_deref())?;
    let folder_id = match item.folder.as_deref() {
        Some(folder) => Some(resolve_folder_id(folder, &session)?),
        None => None,
    };
    let existing = find_existing_item(&item.name, folder_id.as_deref(), &session)?;
    let encoded = encode_item_json(&item, folder_id.as_deref(), existing.as_ref(), &session)?;

    if let Some(existing) = existing {
        run_bw([
            OsStr::new("edit"),
            OsStr::new("item"),
            OsStr::new(&existing.id),
            OsStr::new(&encoded),
            OsStr::new("--session"),
            OsStr::new(&session),
            OsStr::new("--nointeraction"),
        ])
        .context("editing Bitwarden item")?;
    } else {
        run_bw([
            OsStr::new("create"),
            OsStr::new("item"),
            OsStr::new(&encoded),
            OsStr::new("--session"),
            OsStr::new(&session),
            OsStr::new("--nointeraction"),
        ])
        .context("creating Bitwarden item")?;
    }

    Ok(())
}

/// Resolve mixed explicit/JSON CLI input into a concrete Bitwarden login item.
pub fn resolve_input(input: UpsertInput) -> Result<BwLoginItem> {
    let provision = match input.from_json.as_deref() {
        Some("-") => Some(read_provision_json_from_stdin()?),
        Some(path) => Some(read_provision_json_from_file(path)?),
        None => None,
    };

    resolve_input_with_provision(input, provision.as_ref())
}

/// Validate an explicit password source before doing vault preflight.
pub fn validate_password_source(path: &str) -> Result<()> {
    if path == "-" || Path::new(path).is_file() {
        Ok(())
    } else {
        bail!("password file does not exist: {path}")
    }
}

#[derive(Debug, Deserialize)]
struct Status {
    status: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BwItemRef {
    id: String,
    name: String,
    folder_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct BwFolder {
    id: String,
    name: String,
}

fn resolve_input_with_provision(
    input: UpsertInput,
    provision: Option<&Value>,
) -> Result<BwLoginItem> {
    let password = match input.password_from.as_deref() {
        Some("-") if input.from_json.as_deref() == Some("-") => {
            bail!("--password-from - cannot be combined with --from-json -")
        }
        Some("-") => read_stdin_to_string("password from stdin")?,
        Some(path) => std::fs::read_to_string(path)
            .with_context(|| format!("reading password file {path}"))?
            .trim_end_matches(['\r', '\n'])
            .to_owned(),
        None => {
            let provision =
                provision.ok_or_else(|| anyhow!("missing --password-from or --from-json"))?;
            if input.use_primary {
                string_field(provision, "primary_password")?
            } else {
                string_field(provision, "posix_password")?
            }
        }
    };

    let name = input
        .name
        .or_else(|| provision.and_then(|value| optional_string_field(value, "name")))
        .ok_or_else(|| anyhow!("missing --name"))?;
    let username = input
        .username
        .or_else(|| provision.and_then(|value| optional_string_field(value, "username")))
        .or_else(|| provision.and_then(|value| optional_string_field(value, "spn")))
        .or_else(|| provision.and_then(|value| optional_string_field(value, "account")))
        .ok_or_else(|| anyhow!("missing --username"))?;
    let totp = input
        .totp
        .or_else(|| provision.and_then(|value| optional_string_field(value, "totp_uri")));

    Ok(BwLoginItem {
        name,
        username,
        password,
        totp,
        folder: input.folder,
        session: input.session,
    })
}

fn require_unlocked_session(explicit: Option<&str>) -> Result<String> {
    ensure_bw_available()?;

    let session = explicit
        .map(str::to_owned)
        .or_else(|| env::var("BW_SESSION").ok())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow!(VAULT_LOCKED_MESSAGE))?;

    let status_output = run_bw([
        OsStr::new("status"),
        OsStr::new("--session"),
        OsStr::new(&session),
        OsStr::new("--nointeraction"),
    ])
    .map_err(|_| anyhow!(VAULT_LOCKED_MESSAGE))?;
    let status: Status =
        serde_json::from_slice(&status_output).context("parsing `bw status` output")?;
    if status.status != "unlocked" {
        bail!(VAULT_LOCKED_MESSAGE);
    }

    Ok(session)
}

fn ensure_bw_available() -> Result<()> {
    run_bw([OsStr::new("--version")])
        .map(|_| ())
        .context("`bw` CLI not found on PATH")
}

fn resolve_folder_id(folder_name: &str, session: &str) -> Result<String> {
    let output = run_bw([
        OsStr::new("list"),
        OsStr::new("folders"),
        OsStr::new("--session"),
        OsStr::new(session),
        OsStr::new("--nointeraction"),
    ])
    .context("listing Bitwarden folders")?;
    let folders: Vec<BwFolder> =
        serde_json::from_slice(&output).context("parsing Bitwarden folder list")?;
    let matches = folders
        .into_iter()
        .filter(|folder| folder.name == folder_name)
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [folder] => Ok(folder.id.clone()),
        [] => bail!("Bitwarden folder not found: {folder_name}"),
        _ => bail!("multiple Bitwarden folders named {folder_name}; cannot choose safely"),
    }
}

fn find_existing_item(
    name: &str,
    folder_id: Option<&str>,
    session: &str,
) -> Result<Option<BwItemRef>> {
    let output = run_bw([
        OsStr::new("list"),
        OsStr::new("items"),
        OsStr::new("--search"),
        OsStr::new(name),
        OsStr::new("--session"),
        OsStr::new(session),
        OsStr::new("--nointeraction"),
    ])
    .context("listing Bitwarden items")?;
    let items: Vec<BwItemRef> =
        serde_json::from_slice(&output).context("parsing Bitwarden item list")?;
    let matches = items
        .into_iter()
        .filter(|item| item.name == name)
        .filter(|item| match folder_id {
            Some(folder_id) => item.folder_id.as_deref() == Some(folder_id),
            None => true,
        })
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [] => Ok(None),
        [item] => Ok(Some(item.clone())),
        _ => bail!("multiple Bitwarden items named {name}; cannot update safely"),
    }
}

fn encode_item_json(
    item: &BwLoginItem,
    folder_id: Option<&str>,
    existing: Option<&BwItemRef>,
    session: &str,
) -> Result<String> {
    let mut value: Value = if let Some(existing) = existing {
        let output = run_bw([
            OsStr::new("get"),
            OsStr::new("item"),
            OsStr::new(&existing.id),
            OsStr::new("--session"),
            OsStr::new(session),
            OsStr::new("--nointeraction"),
        ])
        .context("getting existing Bitwarden item")?;
        serde_json::from_slice(&output).context("parsing existing Bitwarden item")?
    } else {
        let output = run_bw([
            OsStr::new("get"),
            OsStr::new("template"),
            OsStr::new("item"),
            OsStr::new("--session"),
            OsStr::new(session),
            OsStr::new("--nointeraction"),
        ])
        .context("getting Bitwarden item template")?;
        serde_json::from_slice(&output).context("parsing Bitwarden item template")?
    };

    value["type"] = json!(1);
    value["name"] = json!(item.name);
    value["folderId"] = folder_id.map_or(Value::Null, |id| json!(id));
    if !value.get("login").is_some_and(Value::is_object) {
        value["login"] = json!({});
    }
    value["login"]["username"] = json!(item.username);
    value["login"]["password"] = json!(item.password);
    value["login"]["totp"] = item.totp.as_deref().map_or(Value::Null, |totp| json!(totp));

    let raw = serde_json::to_vec(&value).context("serializing Bitwarden item JSON")?;
    Ok(base64::engine::general_purpose::STANDARD.encode(raw))
}

fn run_bw<I, S>(args: I) -> Result<Vec<u8>>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let output = Command::new("bw")
        .args(args)
        .output()
        .context("running `bw`")?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let message = stderr.trim();
        if message.is_empty() {
            bail!("`bw` exited with status {}", output.status);
        }
        bail!("`bw` exited with status {}: {message}", output.status);
    }
    Ok(output.stdout)
}

fn read_provision_json_from_stdin() -> Result<Value> {
    let raw = read_stdin_to_string("provision JSON from stdin")?;
    serde_json::from_str(&raw).context("parsing provision JSON from stdin")
}

fn read_provision_json_from_file(path: &str) -> Result<Value> {
    let raw = std::fs::read_to_string(path).with_context(|| format!("reading JSON file {path}"))?;
    serde_json::from_str(&raw).with_context(|| format!("parsing JSON file {path}"))
}

fn read_stdin_to_string(label: &str) -> Result<String> {
    let mut raw = String::new();
    io::stdin()
        .read_to_string(&mut raw)
        .with_context(|| format!("reading {label}"))?;
    Ok(raw.trim_end_matches(['\r', '\n']).to_owned())
}

fn string_field(value: &Value, field: &str) -> Result<String> {
    optional_string_field(value, field).ok_or_else(|| anyhow!("provision JSON missing `{field}`"))
}

fn optional_string_field(value: &Value, field: &str) -> Option<String> {
    value
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::{BwLoginItem, UpsertInput, resolve_input_with_provision, validate_password_source};

    #[test]
    fn explicit_fields_win_over_json() {
        let json = serde_json::json!({
            "name": "json-name",
            "username": "json-user",
            "posix_password": "json-posix",
            "primary_password": "json-primary",
            "totp_uri": "otpauth://totp/json"
        });

        let item = resolve_input_with_provision(
            UpsertInput {
                name: Some("flag-name".to_owned()),
                username: Some("flag-user".to_owned()),
                password_from: None,
                totp: Some("otpauth://totp/flag".to_owned()),
                folder: Some("Ops".to_owned()),
                session: Some("session".to_owned()),
                from_json: None,
                use_primary: false,
            },
            Some(&json),
        )
        .unwrap();

        assert_eq!(
            item,
            BwLoginItem {
                name: "flag-name".to_owned(),
                username: "flag-user".to_owned(),
                password: "json-posix".to_owned(),
                totp: Some("otpauth://totp/flag".to_owned()),
                folder: Some("Ops".to_owned()),
                session: Some("session".to_owned()),
            }
        );
    }

    #[test]
    fn use_primary_selects_primary_password() {
        let json = serde_json::json!({
            "name": "json-name",
            "spn": "alice",
            "posix_password": "json-posix",
            "primary_password": "json-primary"
        });

        let item = resolve_input_with_provision(
            UpsertInput {
                use_primary: true,
                ..UpsertInput::default()
            },
            Some(&json),
        )
        .unwrap();

        assert_eq!(item.password, "json-primary");
        assert_eq!(item.username, "alice");
    }

    #[test]
    fn missing_json_or_password_source_is_an_error() {
        let err = resolve_input_with_provision(
            UpsertInput {
                name: Some("item".to_owned()),
                username: Some("user".to_owned()),
                ..UpsertInput::default()
            },
            None,
        )
        .unwrap_err();

        assert!(err.to_string().contains("missing --password-from"));
    }

    #[test]
    fn password_source_validation_accepts_stdin_and_existing_files() {
        let path = std::env::temp_dir().join(format!(
            "identity-cli-password-source-{}",
            std::process::id()
        ));
        std::fs::write(&path, "secret").unwrap();

        assert!(validate_password_source("-").is_ok());
        assert!(validate_password_source(path.to_str().unwrap()).is_ok());

        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn password_source_validation_rejects_missing_files() {
        let path = std::env::temp_dir().join(format!(
            "identity-cli-password-source-missing-{}",
            std::process::id()
        ));

        let err = validate_password_source(path.to_str().unwrap()).unwrap_err();

        assert!(err.to_string().contains("password file does not exist"));
        assert!(err.to_string().contains(path.to_str().unwrap()));
    }
}
