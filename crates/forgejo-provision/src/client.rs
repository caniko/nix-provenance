//! Small blocking client for Forgejo's administrative SSH-key API.

use std::fmt;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use provenance_core::http::{ensure_success, json_ok};
use reqwest::Url;
use reqwest::blocking::{Client, RequestBuilder};
use serde::{Deserialize, Serialize};

const PAGE_SIZE: u32 = 100;

/// Forgejo administrative client authenticated with HTTP Basic auth.
pub struct ForgejoClient {
    http: Client,
    api: Url,
    admin_user: String,
    admin_password: String,
}

impl fmt::Debug for ForgejoClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ForgejoClient")
            .field("api", &self.api)
            .field("admin_user", &self.admin_user)
            .field("admin_password", &"<redacted>")
            .finish_non_exhaustive()
    }
}

/// A public key returned by Forgejo.
#[derive(Debug, Clone, Deserialize)]
pub struct PublicKey {
    /// Forgejo's stable key id, used for deletion.
    pub id: i64,
    /// User-chosen key title.
    pub title: String,
    /// OpenSSH public-key text.
    pub key: String,
    /// Whether Forgejo restricts this key to read-only access.
    #[serde(default)]
    pub read_only: bool,
}

#[derive(Debug, Serialize)]
struct CreateKey<'a> {
    title: &'a str,
    key: &'a str,
    read_only: bool,
}

impl ForgejoClient {
    /// Build a client for a Forgejo base URL (for example, http://127.0.0.1:3000).
    pub fn new(
        base_url: &str,
        admin_user: &str,
        admin_password: &str,
        accept_invalid_certs: bool,
    ) -> Result<Self> {
        let base_url = base_url.trim();
        if base_url.is_empty() {
            bail!("Forgejo URL must not be empty");
        }
        if admin_user.trim().is_empty() {
            bail!("Forgejo admin username must not be empty");
        }
        if admin_password.trim().is_empty() {
            bail!("Forgejo admin password must not be empty");
        }

        let mut api = Url::parse(base_url).with_context(|| "parsing Forgejo URL")?;
        if !matches!(api.scheme(), "http" | "https") || api.host_str().is_none() {
            bail!("Forgejo URL must use http or https and include a host");
        }
        let path = api.path().trim_end_matches('/');
        let api_path = if path.ends_with("/api/v1") {
            format!("{path}/")
        } else {
            format!("{path}/api/v1/")
        };
        api.set_path(&api_path);

        let http = provenance_core::http::build_blocking_client(
            concat!("forgejo-provision/", env!("CARGO_PKG_VERSION")),
            accept_invalid_certs,
            None,
        )?;
        Ok(Self {
            http,
            api,
            admin_user: admin_user.trim().to_owned(),
            admin_password: admin_password.trim().to_owned(),
        })
    }

    /// Wait for Forgejo's API to answer before making mutating requests.
    pub fn wait_ready(&self, timeout: Duration) -> Result<()> {
        let deadline = Instant::now() + timeout;
        loop {
            let error = match self.http.get(self.url(&["version"])?).send() {
                Ok(response) if response.status().is_success() => return Ok(()),
                Ok(response) => format!("HTTP {}", response.status()),
                Err(error) => error.to_string(),
            };
            if Instant::now() >= deadline {
                bail!("Forgejo did not become ready before timeout: {error}");
            }
            thread::sleep(Duration::from_secs(1));
        }
    }

    /// List all public keys attached to one Forgejo user.
    pub fn list_keys(&self, username: &str) -> Result<Vec<PublicKey>> {
        let mut page = 1_u32;
        let mut keys = Vec::new();
        loop {
            let response = self
                .auth(self.http.get(self.url(&["users", username, "keys"])?))
                .query(&[("page", page), ("limit", PAGE_SIZE)])
                .send()
                .with_context(|| format!("listing Forgejo SSH keys for user {username}"))?;
            let page_keys: Vec<PublicKey> = json_ok(response, "Forgejo SSH-key list")?;
            let count = page_keys.len();
            keys.extend(page_keys);
            if count < PAGE_SIZE as usize {
                return Ok(keys);
            }
            page = page.saturating_add(1);
        }
    }

    /// Add one public key to a Forgejo user.
    pub fn create_key(
        &self,
        username: &str,
        title: &str,
        key: &str,
        read_only: bool,
    ) -> Result<()> {
        let response = self
            .auth(
                self.http
                    .post(self.url(&["admin", "users", username, "keys"])?),
            )
            .json(&CreateKey {
                title,
                key,
                read_only,
            })
            .send()
            .with_context(|| format!("creating Forgejo SSH key {username}/{title}"))?;
        ensure_success(response)?;
        Ok(())
    }

    /// Delete one public key by Forgejo id.
    pub fn delete_key(&self, username: &str, title: &str, id: i64) -> Result<()> {
        let id = id.to_string();
        let url = self.url(&["admin", "users", username, "keys", &id])?;
        let response = self
            .auth(self.http.delete(url))
            .send()
            .with_context(|| format!("deleting Forgejo SSH key {username}/{title}"))?;
        ensure_success(response)?;
        Ok(())
    }

    fn auth(&self, request: RequestBuilder) -> RequestBuilder {
        request.basic_auth(&self.admin_user, Some(&self.admin_password))
    }

    fn url(&self, segments: &[&str]) -> Result<Url> {
        let mut url = self.api.clone();
        {
            let mut path = url
                .path_segments_mut()
                .map_err(|_| anyhow::anyhow!("Forgejo URL cannot accept path segments"))?;
            path.extend(segments.iter().copied());
        }
        Ok(url)
    }
}
