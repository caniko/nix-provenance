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
            http: provenance_core::http::build_blocking_client(
                "windmill-provision",
                false,
                Some(Duration::from_secs(30)),
            )?,
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

    /// Add an existing instance user to a workspace. "Already a member" is
    /// success so reruns are no-ops.
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
        if status == StatusCode::BAD_REQUEST && body.contains("already exists") {
            return Ok(false);
        }
        // Body is an error message from Windmill, never a credential.
        bail!("adding {email} to {ws}: HTTP {status}: {body}");
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

    /// False only for 401: scoped tokens may legitimately get 403 on whoami.
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
        Ok(resp.status() != StatusCode::UNAUTHORIZED)
    }
}
