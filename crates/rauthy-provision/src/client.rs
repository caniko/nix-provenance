//! Thin blocking HTTP client over Rauthy's `/auth/v1` admin API.
//!
//! Authentication is a long-lived Rauthy **API key**, sent as
//! `Authorization: API-Key <name>$<secret>` (verified against rauthy 0.35.1
//! `src/middlewares/src/principal.rs`). The key must carry these access
//! groups/rights: Users(read,create,update,delete), Groups(…), Roles(…),
//! Clients(…). Scopes and UserAttributes are needed for custom OIDC claim
//! provisioning. Secrets(update) is needed for generated confidential client
//! secrets. Providers(read,create,update,delete) is needed when upstream auth
//! providers are declared. ApiKeys(read,create,update,delete) is needed only
//! for transient provisioning-key management.

use std::fmt;
use std::thread::sleep;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use provenance_core::http::ensure_success as ok;
use reqwest::blocking::{Client, RequestBuilder, Response};
use reqwest::{Method, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub struct RauthyClient {
    http: Client,
    /// Base API URL including the `/auth/v1` suffix.
    api: String,
    /// Pre-rendered `API-Key <name>$<secret>` header value.
    auth: String,
}

impl fmt::Debug for RauthyClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RauthyClient")
            .field("api", &self.api)
            .field("auth", &"<redacted>")
            .finish_non_exhaustive()
    }
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
pub struct ScopeResponse {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub attr_include_access: Option<Vec<String>>,
    #[serde(default)]
    pub attr_include_id: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
pub struct UserAttributeConfigResponse {
    pub name: String,
    #[serde(default)]
    pub desc: Option<String>,
    #[serde(default)]
    pub default_value: Option<Value>,
    #[serde(default)]
    pub user_editable: bool,
}

#[derive(Debug, Deserialize)]
pub struct UserAttributeConfigsResponse {
    #[serde(default)]
    pub values: Vec<UserAttributeConfigResponse>,
}

#[derive(Debug, Deserialize)]
pub struct UserAttributeValueResponse {
    pub key: String,
    pub value: Value,
}

#[derive(Debug, Deserialize)]
pub struct UserAttributeValuesResponse {
    #[serde(default)]
    pub values: Vec<UserAttributeValueResponse>,
}

#[derive(Debug, Default, Deserialize)]
pub struct UserValuesResponse {
    #[serde(default)]
    pub preferred_username: Option<String>,
    #[serde(default)]
    pub birthdate: Option<String>,
    #[serde(default)]
    pub phone: Option<String>,
    #[serde(default)]
    pub street: Option<String>,
    #[serde(default)]
    pub zip: Option<String>,
    #[serde(default)]
    pub city: Option<String>,
    #[serde(default)]
    pub country: Option<String>,
    #[serde(default)]
    pub tz: Option<String>,
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
    #[serde(default)]
    pub user_expires: Option<i64>,
    #[serde(default)]
    pub user_values: UserValuesResponse,
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
    pub challenges: Option<Vec<String>>,
    #[serde(default)]
    pub enabled: bool,
}

#[derive(Debug, Deserialize)]
pub struct ProviderResponse {
    pub id: String,
    pub name: String,
    pub typ: String,
    pub enabled: bool,
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub userinfo_endpoint: String,
    #[serde(default)]
    pub jwks_endpoint: Option<String>,
    pub client_id: String,
    #[serde(default)]
    pub client_secret: Option<String>,
    pub scope: String,
    #[serde(default)]
    pub admin_claim_path: Option<String>,
    #[serde(default)]
    pub admin_claim_value: Option<String>,
    #[serde(default)]
    pub mfa_claim_path: Option<String>,
    #[serde(default)]
    pub mfa_claim_value: Option<String>,
    pub use_pkce: bool,
    pub client_secret_basic: bool,
    pub client_secret_post: bool,
    pub auto_onboarding: bool,
    pub auto_link: bool,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct ProviderLinkedUserResponse {
    pub id: String,
    pub email: String,
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
pub struct ScopeRequest {
    pub scope: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attr_include_access: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attr_include_id: Option<Vec<String>>,
}

#[derive(Debug, Serialize)]
pub struct UserAttributeConfigRequest {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub desc: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_value: Option<Value>,
    pub user_editable: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct UserAttributeValueRequest {
    pub key: String,
    pub value: Value,
}

#[derive(Debug, Serialize)]
pub struct UserAttributeValuesUpdateRequest {
    pub values: Vec<UserAttributeValueRequest>,
}

#[derive(Debug, Serialize)]
struct PreferredUsernameRequest<'a> {
    preferred_username: Option<&'a str>,
    force_overwrite: Option<bool>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_expires: Option<i64>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_expires: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct UserPatchValue {
    pub key: &'static str,
    pub value: Value,
}

#[derive(Debug, Default, Serialize)]
pub struct UserPatchRequest {
    pub put: Vec<UserPatchValue>,
    pub del: Vec<String>,
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
    pub challenges: Option<Vec<String>>,
    pub force_mfa: bool,
}

#[derive(Debug, Serialize)]
pub struct ProviderRequest {
    pub name: String,
    pub typ: String,
    pub enabled: bool,
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub userinfo_endpoint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwks_endpoint: Option<String>,
    pub use_pkce: bool,
    pub client_secret_basic: bool,
    pub client_secret_post: bool,
    pub auto_onboarding: bool,
    pub auto_link: bool,
    pub client_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,
    pub scope: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub admin_claim_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub admin_claim_value: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mfa_claim_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mfa_claim_value: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ApiKeyRequest {
    pub name: String,
    pub exp: Option<i64>,
    pub access: Vec<ApiKeyAccessRequest>,
}

#[derive(Debug, Serialize)]
pub struct ApiKeyAccessRequest {
    pub group: &'static str,
    pub access_rights: Vec<&'static str>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum ClientSecretResponse {
    String(String),
    Object {
        #[serde(default)]
        secret: Option<String>,
        #[serde(default)]
        client_secret: Option<String>,
        #[serde(default)]
        value: Option<String>,
    },
}

impl ClientSecretResponse {
    fn into_secret(self) -> Option<String> {
        match self {
            Self::String(s) => Some(s),
            Self::Object {
                secret,
                client_secret,
                value,
            } => secret.or(client_secret).or(value),
        }
    }
}

impl RauthyClient {
    pub fn new(base_url: &str, api_key: &str, accept_invalid_certs: bool) -> Result<Self> {
        let base = base_url.trim_end_matches('/');
        let api = format!("{base}/auth/v1");
        let http = provenance_core::http::build_blocking_client(
            concat!("rauthy-provision/", env!("CARGO_PKG_VERSION")),
            accept_invalid_certs,
            Some(Duration::from_secs(30)),
        )?;
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

    fn send_ok(&self, req: RequestBuilder, context: impl Into<String>) -> Result<Response> {
        let context = context.into();
        let resp = req.send().with_context(|| context.clone())?;
        ok(resp).with_context(|| context)
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
        self.wait_healthy(attempts, delay)?;
        self.check_api_key()
    }

    /// Poll the unauthenticated health endpoint until the server is up.
    pub fn wait_healthy(&self, attempts: u32, delay: Duration) -> Result<()> {
        let mut last_err = None;
        for attempt in 1..=attempts {
            match self.http.get(format!("{}/health", self.api)).send() {
                Ok(resp) if resp.status().is_success() => return Ok(()),
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
                 (needs Users/Groups/Roles/Clients read+write, plus Scopes/UserAttributes \
                 read+write when custom OIDC claims are declared, Secrets update/read for \
                 generated client secrets, and Providers read/write when upstream auth providers \
                 are declared): {body}"
            ),
            _ => bail!("unexpected status {status} validating API key: {body}"),
        }
    }

    fn send_ok_or_permission_hint(
        &self,
        req: RequestBuilder,
        context: impl Into<String>,
        missing_rights: &str,
    ) -> Result<Response> {
        let context = context.into();
        let resp = req.send().with_context(|| context.clone())?;
        if matches!(
            resp.status(),
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN
        ) {
            let status = resp.status();
            let body = resp.text().unwrap_or_default();
            bail!(
                "{context} failed ({status}). Grant {missing_rights} to the Rauthy \
                 provisioning API key, then rerun: {body}"
            );
        }
        ok(resp).with_context(|| context)
    }

    // ----- API keys -----

    pub fn create_or_update_api_key(&self, body: &ApiKeyRequest) -> Result<()> {
        let resp = self
            .req(Method::POST, "/api_keys")
            .json(body)
            .send()
            .with_context(|| format!("creating transient Rauthy API key {}", body.name))?;
        match resp.status() {
            status if status.is_success() => Ok(()),
            StatusCode::BAD_REQUEST => {
                let resp = self
                    .req(Method::PUT, &format!("/api_keys/{}", body.name))
                    .json(body)
                    .send()
                    .with_context(|| format!("updating transient Rauthy API key {}", body.name))?;
                if matches!(
                    resp.status(),
                    StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN
                ) {
                    let status = resp.status();
                    let body = resp.text().unwrap_or_default();
                    bail!(
                        "Rauthy API key manager lacks permission to update API keys ({status}). \
                         Grant ApiKeys update rights to the manager key, then rerun: {body}"
                    );
                }
                ok(resp)
                    .with_context(|| format!("updating transient Rauthy API key {}", body.name))?;
                Ok(())
            }
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => {
                let status = resp.status();
                let body = resp.text().unwrap_or_default();
                bail!(
                    "Rauthy API key manager lacks permission to create API keys ({status}). \
                     Grant ApiKeys create/update/delete rights to the manager key, then rerun: {body}"
                );
            }
            _ => {
                ok(resp)
                    .with_context(|| format!("creating transient Rauthy API key {}", body.name))?;
                Ok(())
            }
        }
    }

    pub fn rotate_api_key_secret(&self, name: &str) -> Result<String> {
        let resp = self
            .req(Method::PUT, &format!("/api_keys/{name}/secret"))
            .send()
            .with_context(|| format!("rotating transient Rauthy API key {name}"))?;
        if matches!(
            resp.status(),
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN
        ) {
            let status = resp.status();
            let body = resp.text().unwrap_or_default();
            bail!(
                "Rauthy API key manager lacks permission to rotate API-key secrets ({status}). \
                 Grant ApiKeys update rights to the manager key, then rerun: {body}"
            );
        }
        let resp = ok(resp).with_context(|| format!("rotating transient Rauthy API key {name}"))?;
        let secret = resp
            .text()
            .context("decoding transient Rauthy API-key secret response")?;
        if secret.trim().is_empty() {
            bail!("Rauthy returned an empty secret for transient API key {name}");
        }
        Ok(secret)
    }

    pub fn delete_api_key(&self, name: &str) -> Result<()> {
        let resp = self
            .req(Method::DELETE, &format!("/api_keys/{name}"))
            .send()
            .with_context(|| format!("deleting transient Rauthy API key {name}"))?;
        if matches!(
            resp.status(),
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN
        ) {
            let status = resp.status();
            let body = resp.text().unwrap_or_default();
            bail!(
                "Rauthy API key manager lacks permission to delete API keys ({status}). \
                 Grant ApiKeys delete rights to the manager key, then rerun: {body}"
            );
        }
        ok(resp).with_context(|| format!("deleting transient Rauthy API key {name}"))?;
        Ok(())
    }

    // ----- groups -----

    pub fn list_groups(&self) -> Result<Vec<GroupResponse>> {
        let resp = self.send_ok(self.req(Method::GET, "/groups"), "requesting Rauthy groups")?;
        resp.json().context("decoding groups list")
    }

    pub fn create_group(&self, name: &str) -> Result<()> {
        self.send_ok(
            self.req(Method::POST, "/groups")
                .json(&GroupRequest { group: name }),
            format!("creating Rauthy group {name}"),
        )?;
        Ok(())
    }

    pub fn delete_group(&self, id: &str) -> Result<()> {
        self.send_ok(
            self.req(Method::DELETE, &format!("/groups/{id}")),
            format!("deleting Rauthy group {id}"),
        )?;
        Ok(())
    }

    // ----- roles -----

    pub fn list_roles(&self) -> Result<Vec<RoleResponse>> {
        let resp = self.send_ok(self.req(Method::GET, "/roles"), "requesting Rauthy roles")?;
        resp.json().context("decoding roles list")
    }

    pub fn create_role(&self, name: &str) -> Result<()> {
        self.send_ok(
            self.req(Method::POST, "/roles")
                .json(&RoleRequest { role: name }),
            format!("creating Rauthy role {name}"),
        )?;
        Ok(())
    }

    pub fn delete_role(&self, id: &str) -> Result<()> {
        self.send_ok(
            self.req(Method::DELETE, &format!("/roles/{id}")),
            format!("deleting Rauthy role {id}"),
        )?;
        Ok(())
    }

    // ----- scopes -----

    pub fn list_scopes(&self) -> Result<Vec<ScopeResponse>> {
        let resp = self.send_ok_or_permission_hint(
            self.req(Method::GET, "/scopes"),
            "requesting Rauthy scopes",
            "Scopes read/create/update/delete rights",
        )?;
        resp.json().context("decoding scopes list")
    }

    pub fn create_scope(&self, body: &ScopeRequest) -> Result<()> {
        self.send_ok_or_permission_hint(
            self.req(Method::POST, "/scopes").json(body),
            format!("creating Rauthy scope {}", body.scope),
            "Scopes read/create/update/delete rights",
        )?;
        Ok(())
    }

    pub fn update_scope(&self, id: &str, body: &ScopeRequest) -> Result<()> {
        self.send_ok_or_permission_hint(
            self.req(Method::PUT, &format!("/scopes/{id}")).json(body),
            format!("updating Rauthy scope {}", body.scope),
            "Scopes read/create/update/delete rights",
        )?;
        Ok(())
    }

    pub fn delete_scope(&self, id: &str) -> Result<()> {
        self.send_ok_or_permission_hint(
            self.req(Method::DELETE, &format!("/scopes/{id}")),
            format!("deleting Rauthy scope {id}"),
            "Scopes read/create/update/delete rights",
        )?;
        Ok(())
    }

    // ----- custom user attributes -----

    pub fn list_user_attributes(&self) -> Result<Vec<UserAttributeConfigResponse>> {
        let resp = self.send_ok_or_permission_hint(
            self.req(Method::GET, "/users/attr"),
            "requesting Rauthy user attribute configs",
            "UserAttributes read/create/update/delete rights",
        )?;
        let decoded: UserAttributeConfigsResponse =
            resp.json().context("decoding user attribute config list")?;
        Ok(decoded.values)
    }

    pub fn create_user_attribute(&self, body: &UserAttributeConfigRequest) -> Result<()> {
        self.send_ok_or_permission_hint(
            self.req(Method::POST, "/users/attr").json(body),
            format!("creating Rauthy user attribute {}", body.name),
            "UserAttributes read/create/update/delete rights",
        )?;
        Ok(())
    }

    pub fn update_user_attribute(
        &self,
        name: &str,
        body: &UserAttributeConfigRequest,
    ) -> Result<()> {
        self.send_ok_or_permission_hint(
            self.req(Method::PUT, &format!("/users/attr/{name}"))
                .json(body),
            format!("updating Rauthy user attribute {}", body.name),
            "UserAttributes read/create/update/delete rights",
        )?;
        Ok(())
    }

    pub fn delete_user_attribute(&self, name: &str) -> Result<()> {
        self.send_ok_or_permission_hint(
            self.req(Method::DELETE, &format!("/users/attr/{name}")),
            format!("deleting Rauthy user attribute {name}"),
            "UserAttributes read/create/update/delete rights",
        )?;
        Ok(())
    }

    // ----- users -----

    pub fn get_user_by_email(&self, email: &str) -> Result<Option<UserResponse>> {
        let resp = self
            .req(Method::GET, &format!("/users/email/{email}"))
            .send()
            .with_context(|| format!("looking up Rauthy user {email}"))?;
        if resp.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let resp = ok(resp).with_context(|| format!("looking up Rauthy user {email}"))?;
        Ok(Some(resp.json().context("decoding user")?))
    }

    pub fn create_user(&self, body: &NewUserRequest) -> Result<()> {
        self.send_ok(
            self.req(Method::POST, "/users").json(body),
            format!("creating Rauthy user {}", body.email),
        )?;
        Ok(())
    }

    pub fn update_user(&self, id: &str, body: &UpdateUserRequest) -> Result<()> {
        self.send_ok(
            self.req(Method::PUT, &format!("/users/{id}")).json(body),
            format!("updating Rauthy user {id}"),
        )?;
        Ok(())
    }

    pub fn patch_user(&self, id: &str, body: &UserPatchRequest) -> Result<()> {
        self.send_ok_or_permission_hint(
            self.req(Method::PATCH, &format!("/users/{id}")).json(body),
            format!("patching Rauthy user {id}"),
            "Users update rights",
        )?;
        Ok(())
    }

    pub fn delete_user(&self, id: &str) -> Result<()> {
        self.send_ok(
            self.req(Method::DELETE, &format!("/users/{id}")),
            format!("deleting Rauthy user {id}"),
        )?;
        Ok(())
    }

    pub fn get_user_attributes(&self, id: &str) -> Result<Vec<UserAttributeValueResponse>> {
        let resp = self.send_ok_or_permission_hint(
            self.req(Method::GET, &format!("/users/{id}/attr")),
            format!("requesting Rauthy user attributes for {id}"),
            "UserAttributes read/create/update/delete rights",
        )?;
        let decoded: UserAttributeValuesResponse =
            resp.json().context("decoding user attribute values")?;
        Ok(decoded.values)
    }

    pub fn update_user_attributes(
        &self,
        id: &str,
        values: Vec<UserAttributeValueRequest>,
    ) -> Result<()> {
        self.send_ok_or_permission_hint(
            self.req(Method::PUT, &format!("/users/{id}/attr"))
                .json(&UserAttributeValuesUpdateRequest { values }),
            format!("updating Rauthy user attributes for {id}"),
            "UserAttributes read/create/update/delete rights",
        )?;
        Ok(())
    }

    pub fn update_preferred_username(&self, id: &str, username: Option<&str>) -> Result<()> {
        self.send_ok_or_permission_hint(
            self.req(Method::PUT, &format!("/users/{id}/self/preferred_username"))
                .json(&PreferredUsernameRequest {
                    preferred_username: username,
                    force_overwrite: Some(true),
                }),
            format!("updating Rauthy preferred_username for {id}"),
            "Users update rights",
        )?;
        Ok(())
    }

    // ----- clients -----

    pub fn get_client(&self, id: &str) -> Result<Option<ClientResponse>> {
        let resp = self
            .req(Method::GET, &format!("/clients/{id}"))
            .send()
            .with_context(|| format!("looking up Rauthy client {id}"))?;
        if resp.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let resp = ok(resp).with_context(|| format!("looking up Rauthy client {id}"))?;
        Ok(Some(resp.json().context("decoding client")?))
    }

    pub fn create_client(&self, body: &NewClientRequest) -> Result<()> {
        self.send_ok(
            self.req(Method::POST, "/clients").json(body),
            format!("creating Rauthy client {}", body.id),
        )?;
        Ok(())
    }

    pub fn update_client(&self, id: &str, body: &UpdateClientRequest) -> Result<()> {
        self.send_ok(
            self.req(Method::PUT, &format!("/clients/{id}")).json(body),
            format!("updating Rauthy client {id}"),
        )?;
        Ok(())
    }

    pub fn delete_client(&self, id: &str) -> Result<()> {
        self.send_ok(
            self.req(Method::DELETE, &format!("/clients/{id}")),
            format!("deleting Rauthy client {id}"),
        )?;
        Ok(())
    }

    pub fn rotate_client_secret(&self, id: &str) -> Result<String> {
        let resp = self
            .req(Method::PUT, &format!("/clients/{id}/secret"))
            .send()
            .with_context(|| format!("rotating Rauthy client secret for {id}"))?;
        let status = resp.status();
        if matches!(status, StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN) {
            let body = resp.text().unwrap_or_default();
            bail!(
                "Rauthy API key lacks permission to rotate secret for client {id} ({status}). \
                 Grant Secrets update/read rights to the provisioning key, then rerun: {body}"
            );
        }
        let resp = ok(resp).with_context(|| format!("rotating Rauthy client secret for {id}"))?;
        let secret = resp
            .json::<ClientSecretResponse>()
            .context("decoding Rauthy client-secret response")?
            .into_secret()
            .ok_or_else(|| anyhow!("Rauthy client-secret response did not contain a secret"))?;
        if secret.trim().is_empty() {
            bail!("Rauthy returned an empty client secret for {id}");
        }
        Ok(secret)
    }

    // ----- upstream auth providers -----

    pub fn list_providers(&self) -> Result<Vec<ProviderResponse>> {
        let resp = self.send_ok_or_permission_hint(
            self.req(Method::POST, "/providers"),
            "requesting Rauthy upstream auth providers",
            "Providers read/create/update/delete rights",
        )?;
        resp.json().context("decoding provider list")
    }

    pub fn create_provider(&self, body: &ProviderRequest) -> Result<()> {
        self.send_ok_or_permission_hint(
            self.req(Method::POST, "/providers/create").json(body),
            format!("creating Rauthy upstream auth provider {}", body.name),
            "Providers read/create/update/delete rights",
        )?;
        Ok(())
    }

    pub fn update_provider(&self, id: &str, body: &ProviderRequest) -> Result<()> {
        self.send_ok_or_permission_hint(
            self.req(Method::PUT, &format!("/providers/{id}"))
                .json(body),
            format!("updating Rauthy upstream auth provider {id}"),
            "Providers read/create/update/delete rights",
        )?;
        Ok(())
    }

    pub fn delete_provider(&self, id: &str) -> Result<()> {
        self.send_ok_or_permission_hint(
            self.req(Method::DELETE, &format!("/providers/{id}")),
            format!("deleting Rauthy upstream auth provider {id}"),
            "Providers read/create/update/delete rights",
        )?;
        Ok(())
    }

    pub fn provider_linked_users(&self, id: &str) -> Result<Vec<ProviderLinkedUserResponse>> {
        let context = format!("checking linked users for Rauthy upstream auth provider {id}");
        let resp = self
            .req(Method::GET, &format!("/providers/{id}/delete_safe"))
            .send()
            .with_context(|| context.clone())?;
        if matches!(
            resp.status(),
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN
        ) {
            let status = resp.status();
            let body = resp.text().unwrap_or_default();
            bail!(
                "{context} failed ({status}). Grant Providers read/create/update/delete rights \
                 to the Rauthy provisioning API key, then rerun: {body}"
            );
        }
        let status = resp.status();
        if status != StatusCode::NOT_ACCEPTABLE {
            let resp = ok(resp).with_context(|| context.clone())?;
            return resp.json().context("decoding provider linked-user list");
        }
        resp.json().context("decoding provider linked-user list")
    }

    // ----- password-reset email (set-password link for new users) -----

    /// Ask Rauthy to email `email` a set-password / registration link, landing
    /// the user at `redirect_uri` once they finish. Drives Rauthy's
    /// `request_reset` flow, which is **unauthenticated** (no API key) and gated
    /// by a Proof-of-Work: fetch a challenge from `/pow`, solve it with spow,
    /// then POST it alongside the email.
    ///
    /// For a credential-less user (just created via [`Self::create_user`])
    /// Rauthy sends a "new user" set-password mail. The endpoint always returns
    /// 200 for username-enumeration safety, so success here does not prove
    /// delivery — confirm via the Rauthy/stalwart journals.
    pub fn request_password_reset(&self, email: &str, redirect_uri: &str) -> Result<()> {
        // 1. Fetch a PoW challenge (plain-text body, unauthenticated).
        let challenge = ok(self
            .http
            .post(format!("{}/pow", self.api))
            .send()
            .context("requesting PoW challenge")?)?
        .text()
        .context("reading PoW challenge body")?;

        // 2. Solve it locally. spow parses the difficulty out of the challenge;
        //    the solved value is the challenge with the winning counter appended.
        let pow = spow::pow::Pow::work(&challenge)
            .map_err(|e| anyhow!("solving PoW challenge failed: {e}"))?;

        // 3. POST request_reset (no auth header; email + redirect + solved PoW).
        ok(self
            .http
            .post(format!("{}/users/request_reset", self.api))
            .json(&RequestResetRequest {
                email,
                redirect_uri,
                pow: &pow,
            })
            .send()
            .context("posting request_reset")?)?;
        Ok(())
    }
}

#[derive(Debug, Serialize)]
struct RequestResetRequest<'a> {
    email: &'a str,
    redirect_uri: &'a str,
    pow: &'a str,
}
