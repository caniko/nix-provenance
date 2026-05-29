//! Thin blocking HTTP client over Rauthy's `/auth/v1` admin API.
//!
//! Authentication is a long-lived Rauthy **API key**, sent as
//! `Authorization: API-Key <name>$<secret>` (verified against rauthy 0.35.1
//! `src/middlewares/src/principal.rs`). The key must carry these access
//! groups/rights: Users(read,create,update,delete), Groups(…), Roles(…),
//! Clients(…). Secrets(read,update) is only needed if you later manage client
//! secrets (this tool currently does not).

use std::thread::sleep;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use reqwest::blocking::{Client, RequestBuilder, Response};
use reqwest::{Method, StatusCode};
use serde::{Deserialize, Serialize};

pub struct RauthyClient {
    http: Client,
    /// Base API URL including the `/auth/v1` suffix.
    api: String,
    /// Pre-rendered `API-Key <name>$<secret>` header value.
    auth: String,
}

// ---------------------------------------------------------------------------
// Wire types (subset of rauthy 0.35.1 api_types we read or send)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct GroupResponse {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Deserialize)]
pub struct RoleResponse {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Deserialize)]
pub struct UserResponse {
    pub id: String,
    pub email: String,
    #[serde(default)]
    pub given_name: Option<String>,
    #[serde(default)]
    pub family_name: Option<String>,
    #[serde(default)]
    pub language: Option<String>,
    #[serde(default)]
    pub roles: Vec<String>,
    #[serde(default)]
    pub groups: Option<Vec<String>>,
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub email_verified: bool,
}

#[derive(Debug, Deserialize)]
pub struct ClientResponse {
    #[serde(default)]
    pub redirect_uris: Vec<String>,
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default)]
    pub flows_enabled: Vec<String>,
    #[serde(default)]
    pub enabled: bool,
}

#[derive(Debug, Serialize)]
struct GroupRequest<'a> {
    group: &'a str,
}

#[derive(Debug, Serialize)]
struct RoleRequest<'a> {
    role: &'a str,
}

#[derive(Debug, Serialize)]
pub struct NewUserRequest {
    pub email: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub given_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub family_name: Option<String>,
    pub language: String,
    pub roles: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub groups: Option<Vec<String>>,
}

#[derive(Debug, Serialize)]
pub struct UpdateUserRequest {
    pub email: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub given_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub family_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,
    pub roles: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub groups: Option<Vec<String>>,
    pub enabled: bool,
    pub email_verified: bool,
}

#[derive(Debug, Serialize)]
pub struct NewClientRequest {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub confidential: bool,
    pub redirect_uris: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub post_logout_redirect_uris: Option<Vec<String>>,
}

/// Full client config (`PUT /clients/{id}`). Rauthy requires every non-Option
/// field on each update — this is a full replace, not a patch.
#[derive(Debug, Serialize)]
pub struct UpdateClientRequest {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub confidential: bool,
    pub redirect_uris: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub post_logout_redirect_uris: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_origins: Option<Vec<String>>,
    pub enabled: bool,
    pub flows_enabled: Vec<String>,
    pub access_token_alg: String,
    pub id_token_alg: String,
    pub auth_code_lifetime: i32,
    pub access_token_lifetime: i32,
    pub scopes: Vec<String>,
    pub default_scopes: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub challenges: Option<Vec<String>>,
    pub force_mfa: bool,
}

impl RauthyClient {
    pub fn new(base_url: &str, api_key: &str, accept_invalid_certs: bool) -> Result<Self> {
        let base = base_url.trim_end_matches('/');
        let api = format!("{base}/auth/v1");
        let http = Client::builder()
            .danger_accept_invalid_certs(accept_invalid_certs)
            .timeout(Duration::from_secs(30))
            .user_agent(concat!("rauthy-provision/", env!("CARGO_PKG_VERSION")))
            .build()
            .context("building HTTP client")?;
        Ok(Self {
            http,
            api,
            auth: format!("API-Key {api_key}"),
        })
    }

    fn req(&self, method: Method, path: &str) -> RequestBuilder {
        self.http
            .request(method, format!("{}{path}", self.api))
            .header(reqwest::header::AUTHORIZATION, &self.auth)
    }

    /// Poll the unauthenticated health endpoint until the server is up, then
    /// validate the API key with a single authenticated call.
    ///
    /// Readiness and auth are deliberately separate. Rauthy answers
    /// `/auth/v1/health` (no auth) with 200 as soon as it is up, whereas the
    /// authenticated admin endpoints return **400** for a *malformed* key
    /// (not in `<name>$<secret>` form) and **401/403** for a *rejected* one.
    /// Probing an admin endpoint for readiness — as this used to — misreads a
    /// bad key's 400 as "still starting" and burns the entire timeout before
    /// failing with a misleading "did not become ready in time".
    pub fn wait_ready(&self, attempts: u32, delay: Duration) -> Result<()> {
        let mut last_err = None;
        for attempt in 1..=attempts {
            match self.http.get(format!("{}/health", self.api)).send() {
                Ok(resp) if resp.status().is_success() => return self.check_api_key(),
                Ok(resp) => last_err = Some(anyhow!("readiness probe returned {}", resp.status())),
                Err(e) => last_err = Some(anyhow!("readiness probe failed: {e}")),
            }
            if attempt < attempts {
                sleep(delay);
            }
        }
        Err(last_err.unwrap_or_else(|| anyhow!("server not ready")))
            .context("rauthy did not become ready in time")
    }

    /// Validate the configured API key against `/groups` once the server is up,
    /// turning the auth status into an actionable error.
    fn check_api_key(&self) -> Result<()> {
        let resp = self
            .req(Method::GET, "/groups")
            .send()
            .context("validating API key against /groups")?;
        let status = resp.status();
        if status.is_success() {
            return Ok(());
        }
        let body = resp.text().unwrap_or_default();
        match status {
            StatusCode::BAD_REQUEST => bail!(
                "API key malformed ({status}) — the value must be a full Rauthy API key in \
                 `<name>$<secret>` form, minted by Rauthy's bootstrap API-key flow or the \
                 Admin UI (API Keys). A 400 here means rauthy could not even parse it \
                 (e.g. the `$` separator is missing): {body}"
            ),
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => bail!(
                "API key rejected ({status}) — check the key value and its access rights \
                 (needs Users/Groups/Roles/Clients read+write): {body}"
            ),
            _ => bail!("unexpected status {status} validating API key: {body}"),
        }
    }

    // ----- groups -----

    pub fn list_groups(&self) -> Result<Vec<GroupResponse>> {
        let resp = ok(self.req(Method::GET, "/groups").send()?)?;
        resp.json().context("decoding groups list")
    }

    pub fn create_group(&self, name: &str) -> Result<()> {
        ok(self
            .req(Method::POST, "/groups")
            .json(&GroupRequest { group: name })
            .send()?)?;
        Ok(())
    }

    pub fn delete_group(&self, id: &str) -> Result<()> {
        ok(self.req(Method::DELETE, &format!("/groups/{id}")).send()?)?;
        Ok(())
    }

    // ----- roles -----

    pub fn list_roles(&self) -> Result<Vec<RoleResponse>> {
        let resp = ok(self.req(Method::GET, "/roles").send()?)?;
        resp.json().context("decoding roles list")
    }

    pub fn create_role(&self, name: &str) -> Result<()> {
        ok(self
            .req(Method::POST, "/roles")
            .json(&RoleRequest { role: name })
            .send()?)?;
        Ok(())
    }

    pub fn delete_role(&self, id: &str) -> Result<()> {
        ok(self.req(Method::DELETE, &format!("/roles/{id}")).send()?)?;
        Ok(())
    }

    // ----- users -----

    pub fn get_user_by_email(&self, email: &str) -> Result<Option<UserResponse>> {
        let resp = self
            .req(Method::GET, &format!("/users/email/{email}"))
            .send()?;
        if resp.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let resp = ok(resp)?;
        Ok(Some(resp.json().context("decoding user")?))
    }

    pub fn create_user(&self, body: &NewUserRequest) -> Result<()> {
        ok(self.req(Method::POST, "/users").json(body).send()?)?;
        Ok(())
    }

    pub fn update_user(&self, id: &str, body: &UpdateUserRequest) -> Result<()> {
        ok(self
            .req(Method::PUT, &format!("/users/{id}"))
            .json(body)
            .send()?)?;
        Ok(())
    }

    pub fn delete_user(&self, id: &str) -> Result<()> {
        ok(self.req(Method::DELETE, &format!("/users/{id}")).send()?)?;
        Ok(())
    }

    // ----- clients -----

    pub fn get_client(&self, id: &str) -> Result<Option<ClientResponse>> {
        let resp = self.req(Method::GET, &format!("/clients/{id}")).send()?;
        if resp.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let resp = ok(resp)?;
        Ok(Some(resp.json().context("decoding client")?))
    }

    pub fn create_client(&self, body: &NewClientRequest) -> Result<()> {
        ok(self.req(Method::POST, "/clients").json(body).send()?)?;
        Ok(())
    }

    pub fn update_client(&self, id: &str, body: &UpdateClientRequest) -> Result<()> {
        ok(self
            .req(Method::PUT, &format!("/clients/{id}"))
            .json(body)
            .send()?)?;
        Ok(())
    }

    pub fn delete_client(&self, id: &str) -> Result<()> {
        ok(self.req(Method::DELETE, &format!("/clients/{id}")).send()?)?;
        Ok(())
    }
}

/// Turn a non-2xx response into an error carrying the response body.
fn ok(resp: Response) -> Result<Response> {
    let status = resp.status();
    if status.is_success() {
        Ok(resp)
    } else {
        let body = resp.text().unwrap_or_default();
        bail!("rauthy API returned {status}: {body}");
    }
}
