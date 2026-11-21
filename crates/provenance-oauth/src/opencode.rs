//! OpenCode owns the rotating grant. These commands only copy its local state.
use crate::{Grant, Secret, Target, state::Store};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, value::RawValue};
use std::{
    fmt,
    io::{self, IsTerminal, Read, Write},
    path::Path,
    process::{Command, Stdio},
};
use zeroize::Zeroizing;

const MAX_EXPORT: u64 = 4 * 1024 * 1024;

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Details {
    #[serde(rename = "methodID")]
    method_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    metadata: Option<Map<String, Value>>,
}

impl fmt::Debug for Details {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED OpenCode credential details]")
    }
}

pub(crate) fn valid_label(label: &str) -> bool {
    !label.trim().is_empty()
        && label.len() <= 256
        && !label.starts_with('-')
        && !label.chars().any(char::is_control)
}

pub(crate) fn validate(grant: &Grant) -> Result<()> {
    let details = grant
        .opencode
        .as_ref()
        .context("missing OpenCode OAuth method")?;
    ensure!(
        !details.method_id.is_empty()
            && details.method_id.len() <= 128
            && details.method_id.bytes().all(|b| b.is_ascii_graphic())
            && grant.expires_at < (1_u64 << 53)
            && [&grant.access_token.0, &grant.refresh_token.0]
                .into_iter()
                .all(|s| s.len() <= 16 * 1024 && s.bytes().all(|b| b.is_ascii_graphic())),
        "invalid OpenCode OAuth value"
    );
    Ok(())
}

#[derive(Deserialize, Serialize)]
struct Entry<T> {
    id: String,
    #[serde(rename = "integrationID")]
    integration: String,
    label: String,
    active: bool,
    value: T,
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
enum Credential {
    Oauth {
        access: Secret,
        refresh: Secret,
        expires: u64,
        #[serde(flatten)]
        details: Details,
    },
}

fn select(bytes: &[u8], target: &Target, expected_id: Option<&str>) -> Result<Option<Grant>> {
    let entries: Vec<Entry<&RawValue>> = serde_json::from_slice(bytes)
        .map_err(|_| anyhow::anyhow!("invalid OpenCode auth export array"))?;
    let mut selected = None;
    let folded_label = target.account.to_lowercase();
    for entry in entries
        .into_iter()
        .filter(|entry| entry.integration == "openai")
    {
        if entry.label != target.account {
            // Native switch matches labels case-insensitively and prefers IDs.
            ensure!(
                entry.label.to_lowercase() != folded_label && entry.id != target.account,
                "OpenCode credential label is ambiguous"
            );
            continue;
        }
        ensure!(selected.is_none(), "OpenCode credential label is ambiguous");
        selected = Some(entry);
    }
    let Some(entry) = selected else {
        return Ok(None);
    };
    ensure!(
        expected_id.is_none_or(|id| id == entry.id),
        "OpenCode label belongs to a different credential ID; re-enroll the intended login"
    );
    ensure!(
        entry.value.get().len() <= 48 * 1024,
        "OpenCode credential exceeds size limit"
    );
    // The other entries' values were borrowed as raw JSON, never deserialized.
    let Credential::Oauth {
        access,
        refresh,
        expires,
        details,
    } = serde_json::from_str(entry.value.get())
        .map_err(|_| anyhow::anyhow!("selected OpenCode credential is not a valid OAuth value"))?;
    let grant = Grant {
        access_token: access,
        refresh_token: refresh,
        expires_at: expires,
        account_id: entry.id,
        client: None,
        project_id: None,
        scopes: None,
        opencode: Some(details),
    };
    grant.validate_for(target)?;
    Ok(Some(grant))
}

fn read_export(input: impl Read) -> Result<Zeroizing<Vec<u8>>> {
    let mut bytes = Zeroizing::new(Vec::new());
    input.take(MAX_EXPORT + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= MAX_EXPORT,
        "OpenCode auth export exceeds size limit"
    );
    Ok(bytes)
}

pub fn authorize(target: &Target) -> Result<Grant> {
    let stdin = io::stdin();
    ensure!(!stdin.is_terminal(), "pipe OpenCode auth export to stdin");
    let bytes = read_export(stdin.lock())?;
    select(&bytes, target, None)?
        .context("OpenCode auth export is missing the requested OpenAI label")
}

fn auth(opencode: &Path) -> Command {
    let mut cmd = Command::new(opencode);
    cmd.arg("auth")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    cmd
}

fn export(opencode: &Path, target: &Target, expected_id: &str) -> Result<Option<Grant>> {
    let mut child = auth(opencode)
        .args(["export", "openai"])
        .stdout(Stdio::piped())
        .spawn()
        .context("start OpenCode auth export")?;
    let result = read_export(
        child
            .stdout
            .take()
            .context("missing OpenCode export pipe")?,
    );
    if result.is_err() {
        let _ = child.kill();
    }
    let status = child.wait()?;
    let bytes = result?;
    ensure!(status.success(), "OpenCode auth export failed");
    select(&bytes, target, Some(expected_id))
}

pub fn sync(store: &Store<'_>, opencode: &Path) -> Result<()> {
    store.sync_opencode(|id| export(opencode, store.target(), id))
}

pub fn install(store: &Store<'_>, opencode: &Path, activate: bool) -> Result<()> {
    let grant = store.opencode_grant()?;
    let target = store.target();
    let id = &grant.account_id;
    if export(opencode, target, id)?.is_none() {
        let details = grant.opencode.context("missing OpenCode OAuth method")?;
        // Native import is create-only and preserves any existing selection.
        // OpenCode may auto-select its first credential; only switch explicitly
        // when requested.
        let bytes = Zeroizing::new(serde_json::to_vec(&[Entry {
            id: id.clone(),
            integration: "openai".into(),
            label: target.account.clone(),
            active: false,
            value: Credential::Oauth {
                access: grant.access_token,
                refresh: grant.refresh_token,
                expires: grant.expires_at,
                details,
            },
        }])?);
        let mut child = auth(opencode)
            .arg("import")
            .stdin(Stdio::piped())
            .spawn()
            .context("start OpenCode auth import")?;
        let write = child
            .stdin
            .take()
            .context("missing OpenCode import pipe")?
            .write_all(&bytes);
        let status = child.wait()?;
        write.context("write OpenCode credential to import pipe")?;
        ensure!(status.success(), "OpenCode auth import failed");
        ensure!(
            export(opencode, target, id)?.is_some(),
            "OpenCode did not import the requested credential"
        );
    }
    if activate {
        ensure!(
            auth(opencode)
                .args(["switch", "openai", "--", id])
                .status()?
                .success(),
            "OpenCode auth switch failed"
        );
    }
    Ok(())
}
