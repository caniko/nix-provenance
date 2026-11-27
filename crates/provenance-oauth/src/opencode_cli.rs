//! Standalone operator subcommands for OpenCode (`opencode-capture`, `opencode-check`).

use crate::{CliError, antigravity_cli::run_attended, opencode::valid_label, state::atomic_write};
use anyhow::{Context, Result, ensure};
use clap::Args;
use serde::{Deserialize, Serialize};
use serde_json::{Value, value::RawValue};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{IsTerminal, Read, Write},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};
use zeroize::Zeroizing;

const MAX_EXPORT_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Args, Debug)]
pub struct OpencodeCaptureArgs {
    /// OpenCode credential label to capture.
    #[arg(long)]
    pub account: String,
    /// Skip interactive `opencode auth login` and export the already-present label.
    #[arg(long)]
    pub skip_login: bool,
    /// Path to the `opencode` executable.
    #[arg(long, default_value = "opencode")]
    pub opencode_bin: PathBuf,
    /// Destination path (`-` for non-TTY stdout, or a file path written atomically with mode 0600).
    #[arg(long, default_value = "-")]
    pub output: PathBuf,
}

#[derive(Args, Debug)]
pub struct OpencodeCheckArgs {
    /// Optional OpenCode credential label to verify.
    #[arg(long)]
    pub account: Option<String>,
    /// Path to the `opencode` executable.
    #[arg(long, default_value = "opencode")]
    pub opencode_bin: PathBuf,
    /// Inspect an export JSON file (or `-` for stdin) instead of running `opencode`.
    #[arg(long, value_name = "PATH")]
    pub export_file: Option<PathBuf>,
    /// Also run `opencode auth export openai` (bounded to 4 MiB) and verify grant metadata without outputting tokens.
    #[arg(long)]
    pub verify_export: bool,
    /// Emit structured JSON output.
    #[arg(long)]
    pub json: bool,
}

#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
pub struct CredentialInfo {
    pub id: String,
    pub label: String,
    pub provider: String,
}

#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
pub struct ExportMetadata {
    pub has_refresh_token: bool,
    pub has_access_token: bool,
    pub expires_at: Option<u64>,
}

#[derive(Serialize, Debug)]
pub struct OpencodeCheckReport {
    pub ok: bool,
    pub account: Option<String>,
    pub matched: bool,
    pub unique: bool,
    pub credentials: Vec<CredentialInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<ExportMetadata>,
    pub error: Option<String>,
}

pub fn run_capture(args: OpencodeCaptureArgs) -> std::result::Result<(), CliError> {
    if !valid_label(&args.account) {
        return Err(CliError::validation("invalid OpenCode credential label"));
    }
    if args.output == Path::new("-") && std::io::stdout().is_terminal() {
        return Err(CliError::validation(
            "refusing to write OpenCode credentials to a terminal; redirect stdout or pass --output <PATH>",
        ));
    }

    if !args.skip_login {
        let before = list_openai_labels(&args.opencode_bin)
            .map_err(|e| CliError::runtime(format!("{e:#}")))?;
        eprintln!(
            "Sign in to OpenAI account {:?} in OpenCode. Follow the browser or callback prompt.",
            args.account
        );
        let status = run_attended(Command::new(&args.opencode_bin).args([
            "auth",
            "login",
            "openai",
            "--method",
            "chatgpt-browser",
        ]))?;
        if !status.success() {
            return Err(CliError::runtime("OpenCode login failed"));
        }
        let after = list_openai_labels(&args.opencode_bin)
            .map_err(|e| CliError::runtime(format!("{e:#}")))?;
        let mut created = after.iter().filter(|(id, _)| !before.contains_key(*id));
        let Some((id, label)) = created.next() else {
            return Err(CliError::runtime("OpenCode did not store a new login"));
        };
        if created.next().is_some() {
            return Err(CliError::runtime(
                "multiple new OpenAI credentials appeared; label the intended login before capturing",
            ));
        }
        if !is_unique_label(&after, id, &args.account) {
            eprintln!(
                "In OpenCode, open /connect -> OpenAI. Rename the new credential {label:?} to {:?}, moving any conflicting old label out of the way first, then exit OpenCode.",
                args.account
            );
            let rename_status = run_attended(&mut Command::new(&args.opencode_bin))?;
            if !rename_status.success() {
                return Err(CliError::runtime(
                    "OpenCode account label was not confirmed",
                ));
            }
        }
        let refreshed = list_openai_labels(&args.opencode_bin)
            .map_err(|e| CliError::runtime(format!("{e:#}")))?;
        if !is_unique_label(&refreshed, id, &args.account) {
            return Err(CliError::runtime(format!(
                "the newly signed-in OpenAI credential does not have the unique label {:?}",
                args.account
            )));
        }
    }

    let exported =
        export_openai(&args.opencode_bin).map_err(|e| CliError::runtime(format!("{e:#}")))?;

    let (creds, _) = inspect_export_bytes(&exported, Some(&args.account))
        .map_err(|e| CliError::runtime(format!("{e:#}")))?;
    let (matched, unique) = check_label_uniqueness(&creds, Some(&args.account));
    if !matched {
        return Err(CliError::runtime(format!(
            "no OpenAI credential labelled {:?} found in OpenCode export",
            args.account
        )));
    }
    if !unique {
        return Err(CliError::runtime(format!(
            "OpenAI credential label {:?} is ambiguous in OpenCode export",
            args.account
        )));
    }

    if args.output == Path::new("-") {
        let mut stdout = std::io::stdout().lock();
        stdout
            .write_all(&exported)
            .map_err(|e| CliError::runtime(format!("could not write export to stdout: {e}")))?;
    } else {
        atomic_write(&args.output, &exported).map_err(|e| {
            CliError::runtime(format!(
                "could not write export to {}: {e:#}",
                args.output.display()
            ))
        })?;
    }
    Ok(())
}

pub fn run_check(args: OpencodeCheckArgs) -> std::result::Result<(), CliError> {
    let report = build_check_report(&args);
    let ok = report.ok;

    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).unwrap_or_else(|_| "{}".into())
        );
        return if ok { Ok(()) } else { Err(CliError::silent(1)) };
    }

    println!(
        "OpenCode OpenAI credentials: {} found (matched: {}, unique: {})",
        report.credentials.len(),
        report.matched,
        report.unique
    );
    for cred in &report.credentials {
        println!(
            "  - {} (id: {}, provider: {})",
            cred.label, cred.id, cred.provider
        );
    }
    if let Some(meta) = &report.metadata {
        println!(
            "Export metadata: refresh_token={}, access_token={}, expires_at={:?}",
            meta.has_refresh_token, meta.has_access_token, meta.expires_at
        );
    }
    if ok {
        Ok(())
    } else {
        Err(CliError::runtime(
            report
                .error
                .unwrap_or_else(|| "OpenCode check failed".into()),
        ))
    }
}

fn build_check_report(args: &OpencodeCheckArgs) -> OpencodeCheckReport {
    let account = args.account.clone();
    let result = if let Some(export_file) = &args.export_file {
        read_export_file(export_file)
            .and_then(|bytes| inspect_export_bytes(&bytes, account.as_deref()))
    } else {
        list_openai_credentials(&args.opencode_bin).and_then(|creds| {
            let meta = if args.verify_export {
                let exported = export_openai(&args.opencode_bin)?;
                let (exported_credentials, meta) =
                    inspect_export_bytes(&exported, account.as_deref())?;
                let (matched, unique) =
                    check_label_uniqueness(&exported_credentials, account.as_deref());
                ensure!(
                    matched && unique,
                    "OpenCode export has no matching unique OpenAI credentials"
                );
                if account.is_none() {
                    fn identities(credentials: &[CredentialInfo]) -> BTreeSet<(&str, &str)> {
                        credentials
                            .iter()
                            .map(|cred| (cred.id.as_str(), cred.label.as_str()))
                            .collect()
                    }
                    ensure!(
                        identities(&creds) == identities(&exported_credentials),
                        "OpenCode auth list and export contain different OpenAI credentials"
                    );
                }
                meta
            } else {
                None
            };
            Ok((creds, meta))
        })
    };

    match result {
        Ok((credentials, metadata)) => {
            let (matched, unique) = check_label_uniqueness(&credentials, account.as_deref());
            let mut error = None;
            let ok = if let Some(acc) = &account {
                if !matched {
                    error = Some(format!("no OpenAI credential labelled {acc:?} found"));
                    false
                } else if !unique {
                    error = Some(format!("OpenAI credential label {acc:?} is ambiguous"));
                    false
                } else if (args.export_file.is_some() || args.verify_export) && metadata.is_none() {
                    error = Some(format!(
                        "no OpenAI credential labelled {acc:?} found in export"
                    ));
                    false
                } else {
                    true
                }
            } else if credentials.is_empty() {
                error = Some("no OpenAI credentials found".into());
                false
            } else if !unique {
                error = Some("duplicate case-insensitive OpenAI credential labels found".into());
                false
            } else {
                true
            };
            OpencodeCheckReport {
                ok,
                account,
                matched,
                unique,
                credentials,
                metadata,
                error,
            }
        }
        Err(err) => OpencodeCheckReport {
            ok: false,
            account,
            matched: false,
            unique: false,
            credentials: Vec::new(),
            metadata: None,
            error: Some(format!("{err:#}")),
        },
    }
}

fn list_openai_labels(opencode_bin: &Path) -> Result<BTreeMap<String, String>> {
    let creds = list_openai_credentials(opencode_bin)?;
    Ok(creds.into_iter().map(|c| (c.id, c.label)).collect())
}

fn list_openai_credentials(opencode_bin: &Path) -> Result<Vec<CredentialInfo>> {
    let output = Command::new(opencode_bin)
        .args(["auth", "list", "--format", "json"])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .context("run opencode auth list")?;
    ensure!(output.status.success(), "opencode auth list failed");
    parse_auth_list(&output.stdout)
}

pub fn parse_auth_list(bytes: &[u8]) -> Result<Vec<CredentialInfo>> {
    let integrations: Vec<Value> = serde_json::from_slice(bytes)
        .map_err(|_| anyhow::anyhow!("invalid public OpenCode auth list"))?;
    let mut credentials = Vec::new();
    for openai in integrations.iter().filter(|entry| entry["id"] == "openai") {
        for connection in openai["connections"]
            .as_array()
            .context("invalid OpenAI connections list")?
        {
            if connection["type"] == "credential" {
                let id = connection["id"]
                    .as_str()
                    .context("missing OpenAI credential ID")?;
                let label = connection["label"]
                    .as_str()
                    .context("missing OpenAI credential label")?;
                credentials.push(CredentialInfo {
                    id: id.to_owned(),
                    label: label.to_owned(),
                    provider: "openai".to_owned(),
                });
            }
        }
    }
    Ok(credentials)
}

fn is_unique_label(labels: &BTreeMap<String, String>, id: &str, account: &str) -> bool {
    let folded = account.to_lowercase();
    labels.get(id).is_some_and(|label| label == account)
        && !labels.iter().any(|(other_id, label)| {
            other_id != id && (label.to_lowercase() == folded || other_id == account)
        })
}

fn check_label_uniqueness(credentials: &[CredentialInfo], account: Option<&str>) -> (bool, bool) {
    let openai: Vec<&CredentialInfo> = credentials
        .iter()
        .filter(|c| c.provider == "openai")
        .collect();
    if let Some(account) = account {
        let folded = account.to_lowercase();
        let exact_matches: Vec<_> = openai.iter().filter(|c| c.label == account).collect();
        let folded_or_id_matches: Vec<_> = openai
            .iter()
            .filter(|c| c.label.to_lowercase() == folded || c.id == account)
            .collect();
        let matched = !exact_matches.is_empty();
        let unique = exact_matches.len() == 1 && folded_or_id_matches.len() == 1;
        (matched, unique)
    } else {
        let mut seen = std::collections::BTreeSet::new();
        let mut unique = true;
        for c in &openai {
            if !seen.insert(c.label.to_lowercase()) {
                unique = false;
            }
        }
        (!openai.is_empty(), unique)
    }
}

fn read_bounded_export(reader: impl Read) -> Result<Zeroizing<Vec<u8>>> {
    let mut bytes = Zeroizing::new(Vec::new());
    reader.take(MAX_EXPORT_BYTES + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= MAX_EXPORT_BYTES,
        "OpenCode auth export exceeds 4 MiB size limit"
    );
    Ok(bytes)
}

fn read_export_file(path: &Path) -> Result<Zeroizing<Vec<u8>>> {
    if path == Path::new("-") {
        read_bounded_export(std::io::stdin().lock())
    } else {
        let file = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(path)
            .context("cannot open OpenCode export file")?;
        let meta = file.metadata()?;
        ensure!(
            meta.is_file() && meta.len() <= MAX_EXPORT_BYTES,
            "OpenCode export file must be a bounded regular file"
        );
        read_bounded_export(file)
    }
}

fn export_openai(opencode_bin: &Path) -> Result<Zeroizing<Vec<u8>>> {
    let mut child = Command::new(opencode_bin)
        .args(["auth", "export", "openai"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .context("start OpenCode auth export")?;
    let read = read_bounded_export(
        child
            .stdout
            .take()
            .context("missing OpenCode export pipe")?,
    );
    if read.is_err() {
        let _ = child.kill();
    }
    let status = child.wait()?;
    let bytes = read?;
    ensure!(status.success(), "OpenCode auth export failed");
    Ok(bytes)
}

fn inspect_export_bytes(
    bytes: &[u8],
    account: Option<&str>,
) -> Result<(Vec<CredentialInfo>, Option<ExportMetadata>)> {
    #[derive(Deserialize)]
    struct ExportEntry<'a> {
        id: String,
        #[serde(rename = "integrationID")]
        integration: String,
        label: String,
        #[serde(borrow)]
        value: &'a RawValue,
    }

    let entries: Vec<ExportEntry<'_>> = serde_json::from_slice(bytes)
        .map_err(|_| anyhow::anyhow!("invalid OpenCode auth export JSON"))?;

    let mut credentials = Vec::new();
    let mut metadata = None;

    for entry in &entries {
        if entry.integration != "openai" {
            continue;
        }
        credentials.push(CredentialInfo {
            id: entry.id.clone(),
            label: entry.label.clone(),
            provider: entry.integration.clone(),
        });
        if account.is_none_or(|acc| entry.label == acc) {
            let entry_metadata = extract_export_metadata(entry.value)?;
            metadata.get_or_insert(entry_metadata);
        }
    }

    Ok((credentials, metadata))
}

fn extract_export_metadata(raw: &RawValue) -> Result<ExportMetadata> {
    ensure!(
        raw.get().starts_with('{'),
        "OpenCode credential value must be a JSON object"
    );
    #[derive(Deserialize)]
    struct OAuthValue {
        #[serde(rename = "type")]
        kind: String,
        #[serde(default)]
        access: Option<crate::Secret>,
        #[serde(default)]
        refresh: Option<crate::Secret>,
        #[serde(default)]
        expires: Option<u64>,
    }

    let parsed: OAuthValue = serde_json::from_str(raw.get())
        .map_err(|_| anyhow::anyhow!("OpenCode credential value is not valid OAuth JSON"))?;
    ensure!(
        parsed.kind == "oauth",
        "OpenCode export entry is not an OAuth credential"
    );
    ensure!(
        parsed
            .refresh
            .as_ref()
            .is_some_and(|s| !s.0.trim().is_empty()),
        "OpenCode OAuth export entry is missing a refresh token"
    );
    Ok(ExportMetadata {
        has_refresh_token: true,
        has_access_token: parsed.access.as_ref().is_some_and(|s| !s.0.is_empty()),
        expires_at: parsed.expires.filter(|&e| e > 0),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_auth_list_collects_all_openai_integrations() {
        let credentials = parse_auth_list(
            br#"[
                {"id":"openai","connections":[{"type":"credential","id":"id-1","label":"Work"}]},
                {"id":"other"},
                {"id":"openai","connections":[{"type":"credential","id":"id-2","label":"work"}]}
            ]"#,
        )
        .unwrap();
        assert_eq!(credentials.len(), 2);
        assert_eq!(credentials[1].id, "id-2");
        assert_eq!(
            check_label_uniqueness(&credentials, Some("Work")),
            (true, false)
        );
    }

    #[test]
    fn detects_unique_and_duplicate_labels() {
        let creds = vec![
            CredentialInfo {
                id: "id-1".into(),
                label: "Work".into(),
                provider: "openai".into(),
            },
            CredentialInfo {
                id: "id-2".into(),
                label: "work".into(),
                provider: "openai".into(),
            },
        ];
        assert_eq!(check_label_uniqueness(&creds, Some("Work")), (true, false));
        assert_eq!(check_label_uniqueness(&creds, None), (true, false));

        let unique = vec![CredentialInfo {
            id: "id-1".into(),
            label: "Work".into(),
            provider: "openai".into(),
        }];
        assert_eq!(check_label_uniqueness(&unique, Some("Work")), (true, true));
        assert_eq!(
            check_label_uniqueness(&unique, Some("Other")),
            (false, false)
        );
    }

    #[test]
    fn inspects_export_metadata_without_exposing_tokens() {
        let export = serde_json::json!([{
            "id": "cred-1",
            "integrationID": "openai",
            "label": "work",
            "active": true,
            "value": {
                "type": "oauth",
                "access": "super-secret-access",
                "refresh": "super-secret-refresh",
                "expires": 1_800_000_000_000_u64,
                "methodID": "chatgpt-browser"
            }
        }]);
        let bytes = serde_json::to_vec(&export).unwrap();
        let (creds, meta) = inspect_export_bytes(&bytes, Some("work")).unwrap();
        assert_eq!(creds.len(), 1);
        let meta = meta.unwrap();
        assert!(meta.has_access_token && meta.has_refresh_token);
        assert_eq!(meta.expires_at, Some(1_800_000_000_000));
        let serialized = serde_json::to_string(&meta).unwrap();
        assert!(!serialized.contains("super-secret"));
    }
}
