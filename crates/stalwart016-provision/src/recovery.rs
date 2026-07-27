//! Stalwart recovery server lifecycle management.
//!
//! Starts stalwart in recovery mode (background), waits for the recovery
//! listener to become ready by polling `stalwart-cli query`, and provides
//! `apply_document` / `query_object` helpers that shell out to `stalwart-cli`
//! with the correct environment variables.

use std::fs;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::Duration;

use anyhow::{bail, Context, Result};

use crate::error::ProvisionError;

/// A running stalwart recovery server.
///
/// On drop, the child process is killed (SIGTERM via `kill`, then SIGKILL as
/// fallback) and reaped. This mirrors the shell script's `trap cleanup EXIT`.
pub struct RecoveryServer {
    child: Child,
}

impl RecoveryServer {
    /// Start stalwart in recovery mode.
    ///
    /// Sets `STALWART_RECOVERY_MODE=1`, `STALWART_RECOVERY_ADMIN`, and
    /// `STALWART_HOSTNAME`, then launches the stalwart binary in the
    /// background.
    pub fn start(
        stalwart_binary: &Path,
        config_path: &Path,
        recovery_admin: &str, // "admin:password"
        hostname: &str,
    ) -> Result<Self> {
        let mut cmd = Command::new(stalwart_binary);
        cmd.arg("--config").arg(config_path);
        cmd.env("STALWART_RECOVERY_MODE", "1");
        cmd.env("STALWART_RECOVERY_ADMIN", recovery_admin);
        cmd.env("STALWART_HOSTNAME", hostname);
        // Pass stderr through so recovery server logs show up in the
        // systemd journal alongside the provisioner's diagnostics.
        cmd.stdout(Stdio::null());
        cmd.stderr(Stdio::inherit());

        let child = cmd
            .spawn()
            .context("failed to start stalwart in recovery mode")?;

        Ok(Self { child })
    }

    /// Wait for the recovery listener to be ready.
    ///
    /// Polls `stalwart-cli query <probe_object> --json` against the recovery
    /// URL. Returns `Ok(())` when the query succeeds, or
    /// `Err(ProvisionError::RecoveryTimeout)` after `max_attempts`.
    pub fn wait_ready(
        cli_binary: &Path,
        url: &str,
        username: &str,
        password: &str,
        probe_object: &str,
        max_attempts: u32,
        interval: Duration,
    ) -> Result<()> {
        for attempt in 1..=max_attempts {
            let result = Command::new(cli_binary)
                .arg("query")
                .arg(probe_object)
                .arg("--json")
                .arg("--url")
                .arg(url)
                .arg("--user")
                .arg(username)
                .arg("--password")
                .arg(password)
                .stderr(Stdio::piped())
                .stdout(Stdio::null())
                .output();

            match result {
                Ok(out) if out.status.success() => return Ok(()),
                Ok(out) => {
                    let stderr = String::from_utf8_lossy(&out.stderr);
                    // Sanitize: log only the diagnostic, not the full password.
                    let diagnostic = stderr
                        .lines()
                        .find(|l| !l.contains("assword"))
                        .unwrap_or(stderr.trim());
                    if attempt % 10 == 0 || !stderr.is_empty() {
                        eprintln!(
                            "stalwart016-provision: query probe attempt {attempt}/{max_attempts}: {diagnostic}"
                        );
                    }
                }
                Err(e) => {
                    if attempt % 10 == 0 {
                        eprintln!(
                            "stalwart016-provision: query probe attempt {attempt}/{max_attempts} \
                             failed to spawn: {e}"
                        );
                    }
                }
            }

            if attempt < max_attempts {
                thread::sleep(interval);
            }
        }

        Err(ProvisionError::RecoveryTimeout {
            attempts: max_attempts,
            interval_secs: interval.as_secs_f64(),
        }
        .into())
    }
}

impl Drop for RecoveryServer {
    fn drop(&mut self) {
        // Send SIGTERM (same as shell script's `kill $pid`).
        let pid = self.child.id();
        let _ = Command::new("kill")
            .arg(pid.to_string())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        // Wait for the process to exit.
        let _ = self.child.wait();
    }
}

/// Result of a `stalwart-cli apply` invocation.
#[derive(Debug)]
pub struct ApplyResult {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

/// Run `stalwart-cli apply` on a document file.
///
/// Sets `STALWART_URL`, `STALWART_USER`, `STALWART_PASSWORD` environment
/// variables. Returns the apply output even on failure.
pub fn apply_document(
    cli_binary: &Path,
    url: &str,
    username: &str,
    password: &str,
    file: &Path,
    continue_on_error: bool,
) -> Result<ApplyResult> {
    if !file.exists() {
        return Err(ProvisionError::ApplyInputUnreadable {
            path: file.to_path_buf(),
        }
        .into());
    }

    let mut cmd = Command::new(cli_binary);
    cmd.arg("apply").arg("--no-color").arg("--file").arg(file);
    if continue_on_error {
        cmd.arg("--continue-on-error");
    }
    cmd.arg("--url")
        .arg(url)
        .arg("--user")
        .arg(username)
        .arg("--password")
        .arg(password);

    let output = cmd
        .output()
        .context(format!("running stalwart-cli apply on {}", file.display()))?;

    Ok(ApplyResult {
        exit_code: output.status.code().unwrap_or(1),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    })
}

/// Run `stalwart-cli query` and capture JSON output.
pub fn query_object(
    cli_binary: &Path,
    url: &str,
    username: &str,
    password: &str,
    object_type: &str,
) -> Result<serde_json::Value> {
    let fields = query_fields(object_type);
    let output = Command::new(cli_binary)
        .arg("query")
        .arg(object_type)
        .arg("--fields")
        .arg(fields)
        .arg("--json")
        .arg("--url")
        .arg(url)
        .arg("--user")
        .arg(username)
        .arg("--password")
        .arg(password)
        .output()
        .context(format!("running stalwart-cli query {object_type}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!(
            "{}",
            ProvisionError::QueryFailed {
                object: object_type.to_string(),
                detail: stderr.to_string(),
            }
        );
    }

    parse_query_output(object_type, &output.stdout)
}

/// Return the stable identifier field for a registry object.
///
/// Most Stalwart registry objects expose `name`; OAuth clients are keyed by
/// `clientId` instead. Keeping this mapping here lets the evidence capture
/// remain enabled for every declaratively managed object without asking the
/// CLI to select a field that does not exist.
fn query_fields(object_type: &str) -> &'static str {
    match object_type {
        "OAuthClient" => "clientId",
        _ => "name",
    }
}

fn parse_query_output(object_type: &str, stdout: &[u8]) -> Result<serde_json::Value> {
    if let Ok(value) = serde_json::from_slice(stdout) {
        return Ok(value);
    }

    let text = std::str::from_utf8(stdout).context(format!(
        "parsing UTF-8 from stalwart-cli query {object_type}"
    ))?;
    let mut rows = Vec::new();
    for (idx, line) in text.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let value = serde_json::from_str(trimmed).context(format!(
            "parsing NDJSON line {} from stalwart-cli query {object_type}",
            idx + 1
        ))?;
        rows.push(value);
    }

    Ok(serde_json::Value::Array(rows))
}

/// Write query output to a file for operational evidence.
pub fn write_query_output(
    output_dir: &Path,
    object_type: &str,
    data: &serde_json::Value,
) -> Result<()> {
    let path = output_dir.join(format!("query-{object_type}.json"));
    fs::write(&path, serde_json::to_string_pretty(data)?)
        .context(format!("writing query output to {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{parse_query_output, query_fields};

    #[test]
    fn oauth_clients_use_client_id_field() {
        assert_eq!(query_fields("OAuthClient"), "clientId");
        assert_eq!(query_fields("NetworkListener"), "name");
    }

    #[test]
    fn parses_single_json_document() {
        let data = parse_query_output("Domain", br#"{"name":"example.test"}"#).unwrap();
        assert_eq!(data["name"], "example.test");
    }

    #[test]
    fn parses_query_ndjson_as_array() {
        let data = parse_query_output(
            "NetworkListener",
            br#""smtp"
{"name":"submission"}
"#,
        )
        .unwrap();

        let rows = data.as_array().unwrap();
        assert_eq!(rows[0], "smtp");
        assert_eq!(rows[1]["name"], "submission");
    }
}
