use std::fmt;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use reqwest::blocking::{Client, RequestBuilder};
use serde::Deserialize;
use serde_json::{Map, Value, json};

#[derive(Clone)]
pub struct ImmichClient {
    api_base: String,
    token: String,
    client: Client,
}

impl fmt::Debug for ImmichClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ImmichClient")
            .field("api_base", &self.api_base)
            .field("token", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl ImmichClient {
    pub fn new(base_url: &str, token: &str, accept_invalid_certs: bool) -> Result<Self> {
        let base = base_url.trim().trim_end_matches('/');
        if base.is_empty() {
            bail!("Immich URL must not be empty");
        }
        let api_base = if base.ends_with("/api") {
            base.to_owned()
        } else {
            format!("{base}/api")
        };
        let client = provenance_core::http::build_blocking_client(
            concat!("immich-provision/", env!("CARGO_PKG_VERSION")),
            accept_invalid_certs,
            None,
        )?;
        Ok(Self {
            api_base,
            token: token.trim().to_owned(),
            client,
        })
    }

    pub fn wait_ready(&self, timeout: Duration) -> Result<()> {
        let deadline = Instant::now() + timeout;
        loop {
            let error = match self.client.get(self.url("/server/ping")).send() {
                Ok(resp) if resp.status().is_success() => return Ok(()),
                Ok(resp) => format!("HTTP {}", resp.status()),
                Err(err) => err.to_string(),
            };

            if Instant::now() >= deadline {
                bail!("Immich did not become ready before timeout: {error}");
            }
            thread::sleep(Duration::from_secs(2));
        }
    }

    pub fn system_config(&self) -> Result<SystemConfig> {
        let resp = self
            .auth(self.client.get(self.url("/system-config")))
            .send()
            .context("requesting Immich system config")?;
        Ok(provenance_core::http::json_ok(
            resp,
            "Immich system config",
        )?)
    }

    pub fn list_users(&self) -> Result<Vec<ImmichUser>> {
        let resp = self
            .auth(
                self.client
                    .get(self.url("/admin/users"))
                    .query(&[("withDeleted", "false")]),
            )
            .send()
            .context("requesting Immich users")?;
        Ok(provenance_core::http::json_ok(resp, "Immich users")?)
    }

    pub fn create_user(&self, body: &Map<String, Value>) -> Result<ImmichUser> {
        let resp = self
            .auth(self.client.post(self.url("/admin/users")).json(body))
            .send()
            .context("creating Immich user")?;
        Ok(provenance_core::http::json_ok(resp, "created Immich user")?)
    }

    pub fn update_user(&self, id: &str, body: &Map<String, Value>) -> Result<ImmichUser> {
        let resp = self
            .auth(
                self.client
                    .put(self.url(&format!("/admin/users/{id}")))
                    .json(body),
            )
            .send()
            .with_context(|| format!("updating Immich user {id}"))?;
        Ok(provenance_core::http::json_ok(resp, "updated Immich user")?)
    }

    pub fn delete_user(&self, id: &str, force: bool) -> Result<ImmichUser> {
        let resp = self
            .auth(
                self.client
                    .delete(self.url(&format!("/admin/users/{id}")))
                    .json(&json!({ "force": force })),
            )
            .send()
            .with_context(|| format!("deleting Immich user {id}"))?;
        Ok(provenance_core::http::json_ok(resp, "deleted Immich user")?)
    }

    pub fn list_api_keys(&self) -> Result<Vec<ImmichApiKey>> {
        let resp = self
            .auth(self.client.get(self.url("/api-keys")))
            .send()
            .context("requesting Immich API keys")?;
        Ok(provenance_core::http::json_ok(resp, "Immich API keys")?)
    }

    /// Create an API key; Immich returns its secret only in this response.
    pub fn create_api_key(&self, name: &str, permissions: &[String]) -> Result<CreatedApiKey> {
        let resp = self
            .auth(
                self.client
                    .post(self.url("/api-keys"))
                    .json(&json!({ "name": name, "permissions": permissions })),
            )
            .send()
            .with_context(|| format!("creating Immich API key {name}"))?;
        Ok(provenance_core::http::json_ok(
            resp,
            "created Immich API key",
        )?)
    }

    pub fn update_api_key_permissions(&self, id: &str, permissions: &[String]) -> Result<()> {
        let resp = self
            .auth(
                self.client
                    .put(self.url(&format!("/api-keys/{id}")))
                    .json(&json!({ "permissions": permissions })),
            )
            .send()
            .with_context(|| format!("updating Immich API key {id}"))?;
        let _: Value = provenance_core::http::json_ok(resp, "updated Immich API key")?;
        Ok(())
    }

    pub fn delete_api_key(&self, id: &str) -> Result<()> {
        let resp = self
            .auth(self.client.delete(self.url(&format!("/api-keys/{id}"))))
            .send()
            .with_context(|| format!("deleting Immich API key {id}"))?;
        if !resp.status().is_success() {
            bail!("deleting Immich API key {id}: HTTP {}", resp.status());
        }
        Ok(())
    }

    /// The id of the API key `secret` authenticates as, or `None` when Immich
    /// rejects it (revoked, deleted, or never valid).
    pub fn api_key_id_for(&self, secret: &str) -> Result<Option<String>> {
        let resp = self
            .client
            .get(self.url("/api-keys/me"))
            .header("x-api-key", secret)
            .send()
            .context("checking a stored Immich API key")?;
        if resp.status() == reqwest::StatusCode::UNAUTHORIZED {
            return Ok(None);
        }
        let key: ImmichApiKey = provenance_core::http::json_ok(resp, "current Immich API key")?;
        Ok(Some(key.id))
    }

    fn auth(&self, req: RequestBuilder) -> RequestBuilder {
        req.bearer_auth(&self.token)
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.api_base, path)
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct SystemConfig {
    pub oauth: OAuthConfig,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct OAuthConfig {
    pub enabled: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImmichUser {
    pub id: String,
    pub email: String,
    pub name: String,
    #[serde(default)]
    pub is_admin: bool,
    #[serde(default)]
    pub storage_label: Option<String>,
    #[serde(default)]
    pub quota_size_in_bytes: Option<u64>,
    #[serde(default)]
    pub avatar_color: Option<String>,
    #[serde(default)]
    pub should_change_password: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ImmichApiKey {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub permissions: Vec<String>,
}

#[derive(Deserialize)]
pub struct CreatedApiKey {
    pub id: String,
    pub secret: String,
}
