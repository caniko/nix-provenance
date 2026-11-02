//! Windmill HTTP API (loopback, plain HTTP).

use std::thread::sleep;
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, bail};
use reqwest::StatusCode;
use reqwest::blocking::Client;
use serde_json::json;

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
    pub fn token_is_valid(&self, token: &str, workspace: Option<&str>) -> Result<bool> {
        let path = match workspace {
            Some(ws) => format!("/api/w/{ws}/users/whoami"),
            None => "/api/users/whoami".to_owned(),
        };
        let resp = self
            .http
            .get(format!("{}{path}", self.base))
            .bearer_auth(token)
            .send()?;
        token_status_valid(resp.status())
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
}
