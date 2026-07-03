use std::fmt;
use std::thread::sleep;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use reqwest::blocking::{Client, RequestBuilder};
use reqwest::{Method, StatusCode};
use serde::Deserialize;

pub struct TuwunelClient {
    http: Client,
    base: String,
    auth: Option<String>,
}

impl fmt::Debug for TuwunelClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TuwunelClient")
            .field("base", &self.base)
            .field("auth", &self.auth.as_deref().map(|_| "<redacted>"))
            .finish()
    }
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct RegisterResponse {
    access_token: String,
    #[serde(default)]
    user_id: Option<String>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct ErrorResponse {
    errcode: Option<String>,
    error: Option<String>,
    session: Option<String>,
}

impl TuwunelClient {
    pub fn new(base_url: &str, token: &str) -> Result<Self> {
        let http = build_client(concat!("tuwunel-provision/", env!("CARGO_PKG_VERSION")))?;
        Ok(Self {
            http,
            base: base_url.trim_end_matches('/').to_owned(),
            auth: Some(format!("Bearer {token}")),
        })
    }

    pub fn new_without_auth(base_url: &str) -> Result<Self> {
        let http = build_client(concat!("tuwunel-provision/", env!("CARGO_PKG_VERSION")))?;
        Ok(Self {
            http,
            base: base_url.trim_end_matches('/').to_owned(),
            auth: None,
        })
    }

    fn req_auth(&self, method: Method, path: &str) -> RequestBuilder {
        let mut req = self.http.request(method, format!("{}{path}", self.base));
        if let Some(ref token) = self.auth {
            req = req.header(reqwest::header::AUTHORIZATION, token);
        }
        req
    }

    pub fn wait_ready(&self, attempts: u32, delay: Duration) -> Result<()> {
        let mut last_err = None;
        for attempt in 1..=attempts {
            match self
                .http
                .get(format!("{}/_matrix/client/versions", self.base))
                .send()
            {
                Ok(resp) if resp.status().is_success() => return Ok(()),
                Ok(resp) => {
                    last_err = Some(anyhow!("readiness probe returned {}", resp.status()))
                }
                Err(e) => last_err = Some(anyhow!("readiness probe failed: {e}")),
            }
            if attempt < attempts {
                sleep(delay);
            }
        }
        Err(last_err.unwrap_or_else(|| anyhow!("server not ready")))
            .context("tuwunel did not become ready in time")
    }

    pub fn register_admin(&self, username: &str, password: &str) -> Result<String> {
        let localpart = username.trim_start_matches('@');
        let localpart = localpart.split(':').next().unwrap_or(localpart);

        match self.try_register(localpart, password, true, None) {
            Ok(token) => return Ok(token),
            Err(e) => {
                if let Some(session) = extract_session_id(&e) {
                    eprintln!(
                        "tuwunel-provision: register flow requires session {}; completing m.login.dummy",
                        session
                    );
                    return self.try_register(localpart, password, true, Some(&session));
                }
                return Err(e);
            }
        }
    }

    fn try_register(
        &self,
        localpart: &str,
        password: &str,
        admin: bool,
        session: Option<&str>,
    ) -> Result<String> {
        let mut body = serde_json::json!({
            "username": localpart,
            "password": password,
            "admin": admin,
        });
        if let Some(s) = session {
            body["auth"] = serde_json::json!({
                "session": s,
                "type": "m.login.dummy"
            });
        }

        let resp = self
            .req_auth(Method::POST, "/_matrix/client/v3/register")
            .json(&body)
            .send()
            .context("register request failed")?;

        let status = resp.status();
        if status.is_success() {
            let data: RegisterResponse = resp
                .json()
                .context("decoding register response")?;
            return Ok(data.access_token);
        }

        let body_text = resp.text().unwrap_or_default();
        if status == StatusCode::UNAUTHORIZED {
            if let Ok(err) = serde_json::from_str::<ErrorResponse>(&body_text) {
                if let Some(session) = err.session {
                    return Err(anyhow!("need_session:{session}"));
                }
            }
            if session.is_none() {
                bail!("register returned 401 without a session — registration may be disabled: {body_text}");
            }
            bail!("register returned 401 during session completion: {body_text}");
        }

        bail!("register returned HTTP {status}: {body_text}");
    }

    pub fn create_or_update_user(
        &self,
        user_id: &str,
        password: &str,
        admin: bool,
        display_name: Option<&str>,
    ) -> Result<()> {
        let path = format!("/_synapse/admin/v2/users/{user_id}");
        let mut body = serde_json::json!({
            "password": password,
            "admin": admin,
        });
        if let Some(dn) = display_name {
            body["displayname"] = serde_json::json!(dn);
        }

        let resp = self
            .req_auth(Method::POST, &path)
            .json(&body)
            .send()
            .with_context(|| format!("admin API request for {user_id}"))?;

        let status = resp.status();
        if status.is_success() {
            return Ok(());
        }

        if status == StatusCode::NOT_FOUND || status == StatusCode::METHOD_NOT_ALLOWED {
            eprintln!(
                "tuwunel-provision: admin API returned {status} for {user_id} — \
                 falling back to register endpoint"
            );
            return self.register_fallback(user_id, password, admin, display_name);
        }

        let body_text = resp.text().unwrap_or_default();
        if status == StatusCode::UNAUTHORIZED {
            bail!(
                "admin API returned 401 for {user_id} — the admin token has been rejected"
            );
        }
        bail!("admin API returned {status} for {user_id}: {body_text}");
    }

    fn register_fallback(
        &self,
        user_id: &str,
        password: &str,
        admin: bool,
        display_name: Option<&str>,
    ) -> Result<()> {
        let localpart = user_id.trim_start_matches('@');
        let localpart = localpart.split(':').next().unwrap_or(localpart);

        match self.try_register(localpart, password, admin, None) {
            Ok(_token) => {
                if let Some(dn) = display_name {
                    if let Err(e) = self.set_display_name(user_id, dn) {
                        eprintln!(
                            "tuwunel-provision: warning — failed to set display name \
                             for {user_id} via fallback: {e}"
                        );
                    }
                }
                Ok(())
            }
            Err(e) => {
                if let Some(session) = extract_session_id(&e) {
                    self.try_register(localpart, password, admin, Some(&session))?;
                    if let Some(dn) = display_name {
                        if let Err(e) = self.set_display_name(user_id, dn) {
                            eprintln!(
                                "tuwunel-provision: warning — failed to set display name \
                                 for {user_id} via fallback: {e}"
                            );
                        }
                    }
                    return Ok(());
                }
                Err(e)
            }
        }
    }

    pub fn set_display_name(&self, user_id: &str, display_name: &str) -> Result<()> {
        let path = format!("/_matrix/client/v3/profile/{user_id}/displayname");
        let body = serde_json::json!({ "displayname": display_name });

        let resp = self
            .req_auth(Method::PUT, &path)
            .json(&body)
            .send()
            .with_context(|| format!("setting display name for {user_id}"))?;

        let status = resp.status();
        if status.is_success() {
            return Ok(());
        }
        let body_text = resp.text().unwrap_or_default();
        bail!("display name API returned {status} for {user_id}: {body_text}");
    }
}

fn build_client(user_agent: &str) -> Result<Client> {
    Client::builder()
        .user_agent(user_agent)
        .build()
        .context("building HTTP client")
}

fn extract_session_id(err: &anyhow::Error) -> Option<String> {
    let msg = format!("{err:#}");
    if let Some(session) = msg.strip_prefix("need_session:") {
        return Some(session.to_owned());
    }
    for cause in err.chain() {
        let msg = format!("{cause}");
        if let Some(session) = msg.strip_prefix("need_session:") {
            return Some(session.to_owned());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn register_response_deserializes_access_token() {
        let resp: RegisterResponse = serde_json::from_value(json!({
            "access_token": "syt_YWNjZXNz...",
            "user_id": "@can:example.com",
            "home_server": "example.com",
            "device_id": "DEVICE"
        }))
        .unwrap();
        assert_eq!(resp.access_token, "syt_YWNjZXNz...");
        assert_eq!(resp.user_id.as_deref(), Some("@can:example.com"));
    }

    #[test]
    fn error_response_parses_session() {
        let err: ErrorResponse = serde_json::from_value(json!({
            "errcode": "M_USER_IN_USE",
            "error": "User ID already taken.",
            "session": "abc123"
        }))
        .unwrap();
        assert_eq!(err.session.as_deref(), Some("abc123"));
    }

    #[test]
    fn extract_session_id_from_need_session_error() {
        let err = anyhow!("need_session:abc123");
        assert_eq!(extract_session_id(&err), Some("abc123".to_owned()));
    }

    #[test]
    fn extract_session_id_returns_none_for_unrelated_error() {
        let err = anyhow!("something else went wrong");
        assert_eq!(extract_session_id(&err), None);
    }
}
