//! Thin blocking HTTP client over Vikunja's `/api/v1` team and webhook API.
//!
//! Authentication is a long-lived scoped API token sent as
//! `Authorization: Bearer <token>`. The token must cover the deployed
//! instance's `teams`, `teams_members`, and `webhooks` route scopes. Derive
//! exact scope strings from `GET /api/v1/routes` when minting the token;
//! Vikunja scopes pin methods and paths.

use std::fmt;
use std::thread::sleep;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use provenance_core::http::ensure_success as ok;
use reqwest::blocking::{Client, RequestBuilder, Response};
use reqwest::{Method, StatusCode};
use serde::{Deserialize, Serialize};

pub struct VikunjaClient {
    http: Client,
    /// Base API URL including the `/api/v1` suffix.
    api: String,
    /// Pre-rendered `Bearer <token>` header value.
    auth: String,
}

impl fmt::Debug for VikunjaClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VikunjaClient")
            .field("api", &self.api)
            .field("auth", &"<redacted>")
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Deserialize)]
pub struct TeamSummary {
    pub id: i64,
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct TeamDetail {
    #[serde(default)]
    pub members: Vec<TeamMember>,
}

#[derive(Debug, Deserialize)]
pub struct TeamMember {
    pub username: String,
}

#[derive(Debug, Serialize)]
pub struct TeamRequest<'a> {
    pub name: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<&'a str>,
}

#[derive(Debug, Serialize)]
struct MemberRequest<'a> {
    username: &'a str,
    admin: bool,
}

#[derive(Debug, Deserialize)]
struct VikunjaError {
    code: i64,
    #[serde(default)]
    message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddMemberOutcome {
    Added,
    AlreadyMember,
    UserMissing,
}

impl VikunjaClient {
    pub fn new(base_url: &str, token: &str, accept_invalid_certs: bool) -> Result<Self> {
        let base = base_url.trim_end_matches('/');
        let api = format!("{base}/api/v1");
        let http = provenance_core::http::build_blocking_client(
            concat!("vikunja-provision/", env!("CARGO_PKG_VERSION")),
            accept_invalid_certs,
            Some(Duration::from_secs(30)),
        )?;
        Ok(Self {
            http,
            api,
            auth: format!("Bearer {token}"),
        })
    }

    fn req(&self, method: Method, path: &str) -> RequestBuilder {
        self.http
            .request(method, format!("{}{path}", self.api))
            .header(reqwest::header::AUTHORIZATION, &self.auth)
    }

    fn send_ok(&self, req: RequestBuilder, context: impl Into<String>) -> Result<Response> {
        let context = context.into();
        let resp = req.send().with_context(|| context.clone())?;
        ok(resp).with_context(|| context)
    }

    fn send_write_ok(&self, req: RequestBuilder, operation: &str) -> Result<Response> {
        let resp = req.send().with_context(|| operation.to_string())?;
        let status = resp.status();
        if status == StatusCode::FORBIDDEN {
            let body = resp.text().unwrap_or_default();
            bail!(
                "{operation} failed with HTTP 403; this is a hard token-scope drift error. \
                 Re-mint the Vikunja API token with current teams/teams_members scopes from \
                 GET /api/v1/routes: {body}"
            );
        }
        ok(resp).with_context(|| operation.to_string())
    }

    /// Poll the public info endpoint until the server is up, then validate the
    /// token with one authenticated team-list call.
    pub fn wait_ready(&self, attempts: u32, delay: Duration) -> Result<()> {
        let mut last_err = None;
        for attempt in 1..=attempts {
            match self.http.get(format!("{}/info", self.api)).send() {
                Ok(resp) if resp.status().is_success() => return self.check_token(),
                Ok(resp) => last_err = Some(anyhow!("readiness probe returned {}", resp.status())),
                Err(e) => last_err = Some(anyhow!("readiness probe failed: {e}")),
            }
            if attempt < attempts {
                sleep(delay);
            }
        }
        Err(last_err.unwrap_or_else(|| anyhow!("server not ready")))
            .context("vikunja did not become ready in time")
    }

    fn check_token(&self) -> Result<()> {
        let resp = self
            .req(Method::GET, "/teams")
            .send()
            .context("validating API token against /teams")?;
        let status = resp.status();
        if status.is_success() {
            return Ok(());
        }
        let body = resp.text().unwrap_or_default();
        match status {
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => bail!(
                "API token rejected ({status}) -- check the token value and its teams read scope: {body}"
            ),
            _ => bail!("unexpected status {status} validating API token: {body}"),
        }
    }

    pub fn list_teams(&self) -> Result<Vec<TeamSummary>> {
        let resp = self.send_ok(self.req(Method::GET, "/teams"), "requesting Vikunja teams")?;
        resp.json().context("decoding teams list")
    }

    pub fn get_team(&self, id: i64) -> Result<TeamDetail> {
        let resp = self.send_ok(
            self.req(Method::GET, &format!("/teams/{id}")),
            format!("requesting Vikunja team {id}"),
        )?;
        resp.json().context("decoding team")
    }

    pub fn create_team(&self, name: &str, description: Option<&str>) -> Result<()> {
        self.send_write_ok(
            self.req(Method::PUT, "/teams")
                .json(&TeamRequest { name, description }),
            &format!("creating Vikunja team {name}"),
        )?;
        Ok(())
    }

    pub fn update_team(&self, id: i64, name: &str, description: Option<&str>) -> Result<()> {
        self.send_write_ok(
            self.req(Method::POST, &format!("/teams/{id}"))
                .json(&TeamRequest { name, description }),
            &format!("updating Vikunja team {id} ({name})"),
        )?;
        Ok(())
    }

    pub fn delete_team(&self, id: i64, name: &str) -> Result<()> {
        self.send_write_ok(
            self.req(Method::DELETE, &format!("/teams/{id}")),
            &format!("deleting Vikunja team {id} ({name})"),
        )?;
        Ok(())
    }

    pub fn add_member(
        &self,
        team_id: i64,
        username: &str,
        admin: bool,
    ) -> Result<AddMemberOutcome> {
        let operation = format!("adding Vikunja team member {username} to team {team_id}");
        let resp = self
            .req(Method::PUT, &format!("/teams/{team_id}/members"))
            .json(&MemberRequest { username, admin })
            .send()
            .with_context(|| operation.clone())?;
        let status = resp.status();
        if status == StatusCode::FORBIDDEN {
            let body = resp.text().unwrap_or_default();
            bail!(
                "{operation} failed with HTTP 403; this is a hard token-scope drift error. \
                 Re-mint the Vikunja API token with current teams/teams_members scopes from \
                 GET /api/v1/routes: {body}"
            );
        }
        if status.is_success() {
            return Ok(AddMemberOutcome::Added);
        }

        let body = resp.text().unwrap_or_default();
        if let Ok(err) = serde_json::from_str::<VikunjaError>(&body) {
            match err.code {
                6005 => return Ok(AddMemberOutcome::AlreadyMember),
                1005 => return Ok(AddMemberOutcome::UserMissing),
                _ => {}
            }
            bail!(
                "{operation} failed with Vikunja business code {}: {}",
                err.code,
                err.message
            );
        }
        bail!("{operation} failed with HTTP {status}: {body}");
    }

    pub fn remove_member(&self, team_id: i64, username: &str) -> Result<()> {
        self.send_write_ok(
            self.req(
                Method::DELETE,
                &format!("/teams/{team_id}/members/{username}"),
            ),
            &format!("removing Vikunja team member {username} from team {team_id}"),
        )?;
        Ok(())
    }

    // ------------------------------------------------------------------
    // Webhook API
    // ------------------------------------------------------------------

    /// List all webhooks for a project.
    pub fn list_webhooks(&self, project_id: i64) -> Result<Vec<WebhookSummary>> {
        let resp = self.send_ok(
            self.req(Method::GET, &format!("/projects/{project_id}/webhooks")),
            format!("requesting Vikunja webhooks for project {project_id}"),
        )?;
        resp.json().context("decoding webhooks list")
    }

    /// Create a webhook for a project.
    pub fn create_webhook(
        &self,
        project_id: i64,
        url: &str,
        events: &[String],
        secret: Option<&str>,
    ) -> Result<()> {
        self.req(Method::PUT, &format!("/projects/{project_id}/webhooks"))
            .json(&WebhookRequest { url, events, secret })
            .send()
            .with_context(|| format!("creating Vikunja webhook for project {project_id}"))
            .and_then(|resp| {
                let status = resp.status();
                if status.is_success() {
                    Ok(())
                } else {
                    let body = resp.text().unwrap_or_default();
                    bail!("creating Vikunja webhook for project {project_id} returned {status}: {body}")
                }
            })
    }

    /// Update a webhook for a project.
    pub fn update_webhook(
        &self,
        project_id: i64,
        webhook_id: i64,
        url: &str,
        events: &[String],
        secret: Option<&str>,
    ) -> Result<()> {
        self.req(
            Method::POST,
            &format!("/projects/{project_id}/webhooks/{webhook_id}"),
        )
        .json(&WebhookRequest { url, events, secret })
        .send()
        .with_context(|| format!("updating Vikunja webhook {webhook_id} for project {project_id}"))
        .and_then(|resp| {
            let status = resp.status();
            if status.is_success() {
                Ok(())
            } else {
                let body = resp.text().unwrap_or_default();
                bail!("updating Vikunja webhook {webhook_id} for project {project_id} returned {status}: {body}")
            }
        })
    }

    /// Delete a webhook.
    pub fn delete_webhook(&self, project_id: i64, webhook_id: i64) -> Result<()> {
        self.send_write_ok(
            self.req(
                Method::DELETE,
                &format!("/projects/{project_id}/webhooks/{webhook_id}"),
            ),
            &format!(
                "deleting Vikunja webhook {webhook_id} from project {project_id}"
            ),
        )?;
        Ok(())
    }
}

/// A webhook as returned by the Vikunja API.
#[derive(Debug, Deserialize)]
pub struct WebhookSummary {
    pub id: i64,
    pub url: String,
    #[serde(default)]
    pub events: Vec<String>,
}

#[derive(Debug, Serialize)]
struct WebhookRequest<'a> {
    url: &'a str,
    events: &'a [String],
    #[serde(skip_serializing_if = "Option::is_none")]
    secret: Option<&'a str>,
}
