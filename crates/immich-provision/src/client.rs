use std::thread;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use reqwest::blocking::{Client, RequestBuilder};
use reqwest::StatusCode;
use serde::Deserialize;
use serde_json::{json, Map, Value};

#[derive(Clone)]
pub struct ImmichClient {
    api_base: String,
    token: String,
    client: Client,
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
        let client = Client::builder()
            .danger_accept_invalid_certs(accept_invalid_certs)
            .user_agent(concat!("immich-provision/", env!("CARGO_PKG_VERSION")))
            .build()
            .context("building HTTP client")?;
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
        self.auth(self.client.get(self.url("/system-config")))
            .send()
            .context("requesting Immich system config")?
            .json_ok("Immich system config")
    }

    pub fn list_users(&self) -> Result<Vec<ImmichUser>> {
        self.auth(
            self.client
                .get(self.url("/admin/users"))
                .query(&[("withDeleted", "false")]),
        )
        .send()
        .context("requesting Immich users")?
        .json_ok("Immich users")
    }

    pub fn create_user(&self, body: &Map<String, Value>) -> Result<ImmichUser> {
        self.auth(self.client.post(self.url("/admin/users")).json(body))
            .send()
            .context("creating Immich user")?
            .json_ok("created Immich user")
    }

    pub fn update_user(&self, id: &str, body: &Map<String, Value>) -> Result<ImmichUser> {
        self.auth(
            self.client
                .put(self.url(&format!("/admin/users/{id}")))
                .json(body),
        )
        .send()
        .with_context(|| format!("updating Immich user {id}"))?
        .json_ok("updated Immich user")
    }

    pub fn delete_user(&self, id: &str, force: bool) -> Result<ImmichUser> {
        self.auth(
            self.client
                .delete(self.url(&format!("/admin/users/{id}")))
                .json(&json!({ "force": force })),
        )
        .send()
        .with_context(|| format!("deleting Immich user {id}"))?
        .json_ok("deleted Immich user")
    }

    fn auth(&self, req: RequestBuilder) -> RequestBuilder {
        req.bearer_auth(&self.token)
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.api_base, path)
    }
}

trait ResponseExt {
    fn json_ok<T: serde::de::DeserializeOwned>(self, context: &str) -> Result<T>;
}

impl ResponseExt for reqwest::blocking::Response {
    fn json_ok<T: serde::de::DeserializeOwned>(self, context: &str) -> Result<T> {
        let status = self.status();
        if status.is_success() {
            return self
                .json()
                .with_context(|| format!("decoding {context} response"));
        }

        let body = self.text().unwrap_or_default();
        if status == StatusCode::UNAUTHORIZED {
            bail!("{context} request was unauthorized; provisioning token was rejected");
        }
        bail!("{context} request failed with HTTP {status}: {body}");
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
    pub should_change_password: bool,
}
