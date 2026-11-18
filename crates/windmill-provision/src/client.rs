//! Windmill HTTP API (loopback, plain HTTP).

use std::thread::sleep;
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, bail};
use reqwest::StatusCode;
use reqwest::blocking::Client;
use serde_json::json;

/// The deployed fields the reconciler compares before deploying a new version.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
pub struct DeployedScript {
    pub content: String,
    pub language: String,
    /// Hex version hash, the parent a new version must supersede.
    pub hash: String,
    /// Worker-pool tag; a new version does not inherit its parent's, so a
    /// redeploy that leaves it undeclared must send the deployed one back.
    #[serde(default)]
    pub tag: Option<String>,
}

/// A version's lock generation, which Windmill runs as its own job: `lock` is
/// null until that job writes it (an empty lock means "no dependencies"), and
/// `lock_error_logs` is set when the job failed and the version will never run.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Deserialize)]
pub struct DeploymentStatus {
    #[serde(default)]
    pub lock: Option<String>,
    #[serde(default)]
    pub lock_error_logs: Option<String>,
    #[serde(default)]
    pub job_id: Option<String>,
}

/// The deployed fields of a variable. Windmill returns `value` as null for a
/// secret it will not decrypt, and `description` may be absent.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
pub struct DeployedVariable {
    #[serde(default)]
    pub value: Option<String>,
    pub is_secret: bool,
    #[serde(default)]
    pub description: Option<String>,
}

/// Request body of `POST /scripts/create` (`NewScript`). Only the fields the
/// tenant manages are set; Windmill keeps the previous version's settings for
/// the rest (its serde defaults are applied field by field). Windmill refuses a
/// deploy at a path that already holds a version unless `parent` names it.
fn script_body(deploy: &ScriptDeploy<'_>) -> serde_json::Value {
    json!({
        "path": deploy.path,
        "content": deploy.content,
        "language": deploy.language,
        "summary": deploy.summary,
        "description": "",
        "kind": "script",
        "tag": deploy.tag,
        "parent_hash": deploy.parent,
    })
}

/// One script version to deploy.
pub struct ScriptDeploy<'a> {
    pub path: &'a str,
    pub language: &'a str,
    pub summary: &'a str,
    pub content: &'a str,
    /// Worker-pool tag (`hub` routes the runs and the lock job there). `None`
    /// on a redeploy keeps the deployed tag.
    pub tag: Option<&'a str>,
    /// Hash of the version this supersedes; `None` only for a new path.
    pub parent: Option<&'a str>,
}

pub struct Windmill {
    base: String,
    http: Client,
}

impl Windmill {
    pub fn new(base: &str) -> Result<Self> {
        Ok(Self {
            base: base.trim_end_matches('/').to_owned(),
            // Credentials travel over this client: never via an environment proxy.
            http: Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .user_agent("windmill-provision")
                .timeout(Duration::from_secs(30))
                .no_proxy()
                .build()?,
        })
    }

    pub fn wait_ready(&self, timeout: Duration) -> Result<()> {
        let deadline = Instant::now() + timeout;
        loop {
            let ready = self
                .http
                .get(format!("{}/api/version", self.base))
                .send()
                .map(|r| r.status().is_success())
                .unwrap_or(false);
            if ready {
                return Ok(());
            }
            if Instant::now() >= deadline {
                bail!("Windmill not ready after {timeout:?}");
            }
            sleep(Duration::from_secs(1));
        }
    }

    pub fn workspace_exists(&self, bearer: &str, id: &str) -> Result<bool> {
        let resp = self
            .http
            .post(format!("{}/api/workspaces/exists", self.base))
            .bearer_auth(bearer)
            .json(&json!({ "id": id }))
            .send()?;
        Ok(provenance_core::http::ensure_success(resp)?.json()?)
    }

    pub fn create_workspace(&self, bearer: &str, id: &str, name: &str) -> Result<()> {
        let resp = self
            .http
            .post(format!("{}/api/workspaces/create", self.base))
            .bearer_auth(bearer)
            .json(&json!({ "id": id, "name": name }))
            .send()?;
        provenance_core::http::ensure_success(resp)
            .with_context(|| format!("creating workspace {id}"))?;
        Ok(())
    }

    /// Set the display name of an existing workspace (idempotent).
    pub fn rename_workspace(&self, bearer: &str, id: &str, name: &str) -> Result<()> {
        let resp = self
            .http
            .post(format!(
                "{}/api/w/{id}/workspaces/change_workspace_name",
                self.base
            ))
            .bearer_auth(bearer)
            .json(&json!({ "new_name": name }))
            .send()?;
        provenance_core::http::ensure_success(resp)
            .with_context(|| format!("renaming workspace {id}"))?;
        Ok(())
    }

    /// Add an existing instance user to a workspace. Returns `false` when the
    /// email is already a member; any other failure (including a username
    /// conflict) is an error.
    pub fn add_user(&self, bearer: &str, ws: &str, email: &str, admin: bool) -> Result<bool> {
        let resp = self
            .http
            .post(format!("{}/api/w/{ws}/workspaces/add_user", self.base))
            .bearer_auth(bearer)
            .json(
                &json!({ "email": email, "username": null, "is_admin": admin, "operator": false }),
            )
            .send()?;
        if resp.status().is_success() {
            return Ok(true);
        }
        let status = resp.status();
        let body = resp.text().unwrap_or_default();
        if status == StatusCode::BAD_REQUEST && is_email_already_member(&body) {
            return Ok(false);
        }
        // Body is an error message from Windmill, never a credential.
        bail!("adding {email} to {ws}: HTTP {status}: {body}");
    }

    /// Converge the workspace role of an existing member (`username` is the
    /// member's actual workspace username).
    pub fn set_workspace_admin(
        &self,
        bearer: &str,
        ws: &str,
        username: &str,
        admin: bool,
    ) -> Result<()> {
        let resp = self
            .http
            .post(format!("{}/api/w/{ws}/users/update/{username}", self.base))
            .bearer_auth(bearer)
            .json(&json!({ "is_admin": admin }))
            .send()?;
        provenance_core::http::ensure_success(resp)
            .with_context(|| format!("updating {username} role in {ws}"))?;
        Ok(())
    }

    /// The latest deployed version of the script at `path`, or `None` when the
    /// path holds none.
    pub fn script(&self, bearer: &str, ws: &str, path: &str) -> Result<Option<DeployedScript>> {
        let resp = self
            .http
            .get(format!("{}/api/w/{ws}/scripts/get/p/{path}", self.base))
            .bearer_auth(bearer)
            .send()?;
        if resp.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let body: serde_json::Value = provenance_core::http::json_ok(resp, "script")
            .with_context(|| format!("reading {path}"))?;
        serde_json::from_value(body)
            .map(Some)
            .with_context(|| format!("decoding script {path}"))
    }

    /// Deploy one version at its path, superseding `deploy.parent` (the hash
    /// Windmill reported for the current version). Windmill keeps the version
    /// history; the caller decides whether the content changed. Returns the new
    /// version's hash, whose lock generation is still running.
    pub fn create_script(
        &self,
        bearer: &str,
        ws: &str,
        deploy: &ScriptDeploy<'_>,
    ) -> Result<String> {
        let resp = self
            .http
            .post(format!("{}/api/w/{ws}/scripts/create", self.base))
            .bearer_auth(bearer)
            .json(&script_body(deploy))
            .send()?;
        let status = resp.status();
        if status.is_success() {
            return Ok(resp.text()?.trim().to_owned());
        }
        // Windmill's body here is a deploy error (bad language, path conflict),
        // never a credential: the script content is caller-supplied code.
        let body = resp.text().unwrap_or_default();
        bail!("deploying script {}: HTTP {status}: {body}", deploy.path);
    }

    /// The deployment status of one version by hash.
    pub fn deployment_status(
        &self,
        bearer: &str,
        ws: &str,
        hash: &str,
    ) -> Result<DeploymentStatus> {
        let resp = self
            .http
            .get(format!(
                "{}/api/w/{ws}/scripts/deployment_status/h/{hash}",
                self.base
            ))
            .bearer_auth(bearer)
            .send()?;
        let body = provenance_core::http::json_ok(resp, "script deployment status")
            .with_context(|| format!("reading deployment status of {hash}"))?;
        serde_json::from_value(body)
            .with_context(|| format!("decoding deployment status of {hash}"))
    }

    /// Wait (bounded) until the version's dependency job has written its lock,
    /// and fail when that job failed or never ran. Only a version with a lock is
    /// runnable, so a queued or failed job is a failed declaration, not a
    /// no-op: the source already matches on the next run, and would otherwise
    /// be skipped while the path keeps executing the previous version.
    ///
    /// The job's logs are not copied here: journald would keep a dependency
    /// installer's output (and anything it echoes) forever, so the error names
    /// the job id instead.
    pub fn wait_runnable(
        &self,
        bearer: &str,
        ws: &str,
        hash: &str,
        timeout: Duration,
    ) -> Result<()> {
        let deadline = Instant::now() + timeout;
        loop {
            let status = self.deployment_status(bearer, ws, hash)?;
            if status
                .lock_error_logs
                .as_deref()
                .is_some_and(|logs| !logs.trim().is_empty())
            {
                bail!(
                    "lock generation failed for script version {hash}; the dependency job {} has its logs",
                    status.job_id.as_deref().unwrap_or("<unknown>")
                );
            }
            if status.lock.is_some() {
                return Ok(());
            }
            if Instant::now() >= deadline {
                bail!(
                    "script version {hash} still has no lock after {timeout:?} (dependency job {:?})",
                    status.job_id
                );
            }
            sleep(Duration::from_secs(1));
        }
    }

    /// The variable at `path` with its value decrypted (Windmill's `get` does
    /// that for secret variables unless asked not to), or `None` when absent.
    pub fn variable(&self, bearer: &str, ws: &str, path: &str) -> Result<Option<DeployedVariable>> {
        let resp = self
            .http
            .get(format!("{}/api/w/{ws}/variables/get/{path}", self.base))
            .bearer_auth(bearer)
            .send()?;
        if resp.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let body: serde_json::Value = provenance_core::http::json_ok(resp, "variable")
            .with_context(|| format!("reading {path}"))?;
        serde_json::from_value(body)
            .map(Some)
            .with_context(|| format!("decoding variable {path}"))
    }

    pub fn create_variable(
        &self,
        bearer: &str,
        ws: &str,
        path: &str,
        value: &str,
        is_secret: bool,
        description: &str,
    ) -> Result<()> {
        let body = json!({
            "path": path,
            "value": value,
            "is_secret": is_secret,
            "description": description,
        });
        let resp = self
            .http
            .post(format!("{}/api/w/{ws}/variables/create", self.base))
            .bearer_auth(bearer)
            .json(&body)
            .send()?;
        // No body in the error: it carries the variable's plaintext value on
        // some Windmill errors, and the value is the whole point of the file.
        provenance_core::http::ensure_success(resp)
            .with_context(|| format!("creating variable {path}"))?;
        Ok(())
    }

    pub fn update_variable(
        &self,
        bearer: &str,
        ws: &str,
        path: &str,
        value: &str,
        is_secret: bool,
        description: &str,
    ) -> Result<()> {
        let body = json!({
            "value": value,
            "is_secret": is_secret,
            "description": description,
        });
        let resp = self
            .http
            .post(format!("{}/api/w/{ws}/variables/update/{path}", self.base))
            .bearer_auth(bearer)
            .json(&body)
            .send()?;
        provenance_core::http::ensure_success(resp)
            .with_context(|| format!("updating variable {path}"))?;
        Ok(())
    }

    pub fn login(&self, email: &str, password: &str) -> Result<String> {
        let resp = self
            .http
            .post(format!("{}/api/auth/login", self.base))
            .json(&json!({ "email": email, "password": password }))
            .send()?;
        let body = provenance_core::http::ensure_success(resp)
            .with_context(|| format!("logging in as {email}"))?
            .text()?;
        Ok(body.trim().trim_matches('"').to_owned())
    }

    pub fn create_token(
        &self,
        session: &str,
        label: &str,
        workspace: Option<&str>,
        scopes: &[String],
    ) -> Result<String> {
        let scopes = (!scopes.is_empty()).then_some(scopes);
        let resp = self
            .http
            .post(format!("{}/api/users/tokens/create", self.base))
            .bearer_auth(session)
            .json(&json!({ "label": label, "workspace_id": workspace, "scopes": scopes, "expiration": null }))
            .send()?;
        let body = provenance_core::http::ensure_success(resp)
            .with_context(|| format!("minting token {label}"))?
            .text()?;
        Ok(body.trim().trim_matches('"').to_owned())
    }

    /// False only for 401; 403 (scoped token) is valid, other statuses error.
    /// Workspace-bound tokens are checked on the workspace route, which is the
    /// one they are issued for.
    pub fn token_is_valid(
        &self,
        token: &str,
        workspace: Option<&str>,
        email: &str,
    ) -> Result<bool> {
        let path = match workspace {
            Some(ws) => format!("/api/w/{ws}/users/whoami"),
            None => "/api/users/whoami".to_owned(),
        };
        let resp = self
            .http
            .get(format!("{}{path}", self.base))
            .bearer_auth(token)
            .send()?;
        let status = resp.status();
        if !token_status_valid(status)? {
            return Ok(false);
        }
        // A readable identity must be the declared user: a foreign (still valid)
        // bearer dropped at this path is not ours. 403 (scoped) cannot say.
        if status.is_success() {
            let who: serde_json::Value = resp.json()?;
            return Ok(who["email"]
                .as_str()
                .is_some_and(|e| e.eq_ignore_ascii_case(email)));
        }
        Ok(true)
    }
}

/// Windmill's duplicate-membership error is "user with email X already exists
/// in workspace Y"; a username clash reads "user with username ..." and must
/// not be mistaken for it.
fn is_email_already_member(body: &str) -> bool {
    body.contains("user with email") && body.contains("already exists")
}

/// 401 means the token is dead; 403 is a scoped token that may not call
/// whoami. Anything else (5xx, 404) is an unusable answer, not a verdict.
fn token_status_valid(status: StatusCode) -> Result<bool> {
    match status {
        StatusCode::UNAUTHORIZED => Ok(false),
        s if s.is_success() || s == StatusCode::FORBIDDEN => Ok(true),
        s => bail!("unexpected token check status {s}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_email_conflict_counts_as_already_a_member() {
        assert!(is_email_already_member(
            "Bad request: user with email a@b.c already exists in workspace studio"
        ));
        assert!(!is_email_already_member(
            "Bad request: user with username can already exists in workspace studio"
        ));
    }

    #[test]
    fn only_401_invalidates_and_odd_statuses_error() {
        assert!(!token_status_valid(StatusCode::UNAUTHORIZED).unwrap());
        assert!(token_status_valid(StatusCode::OK).unwrap());
        assert!(token_status_valid(StatusCode::FORBIDDEN).unwrap());
        assert!(token_status_valid(StatusCode::BAD_GATEWAY).is_err());
    }

    #[test]
    fn script_create_body_supersedes_the_deployed_version() {
        let creating = script_body(&ScriptDeploy {
            path: "f/a/b",
            language: "bun",
            summary: "sum",
            content: "code",
            tag: Some("hub"),
            parent: None,
        });
        assert_eq!(creating["path"], "f/a/b");
        assert_eq!(creating["language"], "bun");
        assert_eq!(creating["summary"], "sum");
        assert_eq!(creating["content"], "code");
        assert_eq!(creating["kind"], "script");
        // A new version does not inherit its parent's worker tag.
        assert_eq!(creating["tag"], "hub");
        assert!(creating["parent_hash"].is_null());
        // Redeploying over an existing path must name the version it supersedes,
        // or Windmill answers "Path conflict for <path> with non-archived hash".
        let redeploying = script_body(&ScriptDeploy {
            path: "f/a/b",
            language: "bun",
            summary: "sum",
            content: "code2",
            tag: None,
            parent: Some("4376b64b1b94b9b9"),
        });
        assert_eq!(redeploying["parent_hash"], "4376b64b1b94b9b9");
        assert!(redeploying["tag"].is_null());
    }

    #[test]
    fn deployed_scripts_carry_their_version_hash() {
        // 1.601 nests the script, 1.839 flattens it: both expose the fields.
        for body in [
            json!({"hash": "4376b64b1b94b9b9", "content": "c", "language": "bun", "starred": null, "tag": "hub"}),
            json!({"hash": "4376b64b1b94b9b9", "content": "c", "language": "bun", "is_draft": false, "tag": "hub"}),
        ] {
            let script: DeployedScript = serde_json::from_value(body).unwrap();
            assert_eq!(script.hash, "4376b64b1b94b9b9");
            assert_eq!(script.language, "bun");
            assert_eq!(script.tag.as_deref(), Some("hub"));
        }
        // An untagged script answers null (or an empty string); never a tag.
        let untagged: DeployedScript =
            serde_json::from_value(json!({"hash": "h", "content": "c", "language": "bash"}))
                .unwrap();
        assert_eq!(untagged.tag, None);
    }

    #[test]
    fn deployment_status_distinguishes_ready_pending_and_failed() {
        // A language without dependencies gets an empty lock at create time.
        let ready: DeploymentStatus =
            serde_json::from_value(json!({"lock": "", "lock_error_logs": null, "job_id": "1"}))
                .unwrap();
        assert_eq!(ready.lock.as_deref(), Some(""));
        assert!(ready.lock_error_logs.is_none());
        // A dependency job that has not written the lock yet.
        let pending: DeploymentStatus =
            serde_json::from_value(json!({"lock": null, "job_id": "1"})).unwrap();
        assert!(pending.lock.is_none());
        assert_eq!(pending.job_id.as_deref(), Some("1"));
        // A dependency job that failed stamps the error and never a lock.
        let failed: DeploymentStatus = serde_json::from_value(json!(
            {"lock": null, "lock_error_logs": "bun install failed"}
        ))
        .unwrap();
        assert!(failed.lock.is_none());
        assert!(
            failed
                .lock_error_logs
                .as_deref()
                .is_some_and(|logs| !logs.trim().is_empty())
        );
        // An older Windmill that elides null fields answers pending, not ready.
        assert!(
            serde_json::from_value::<DeploymentStatus>(json!({}))
                .unwrap()
                .lock
                .is_none()
        );
    }
}
