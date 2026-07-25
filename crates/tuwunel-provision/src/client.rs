use std::fmt;
use std::thread::sleep;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use reqwest::blocking::{Client, RequestBuilder};
use reqwest::{Method, StatusCode};
use serde::{Deserialize, Serialize};

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
struct RegisterResponse {
    access_token: String,
}

#[derive(Debug, Deserialize)]
struct ErrorResponse {
    errcode: Option<String>,
    error: Option<String>,
    session: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CreateRoomResponse {
    room_id: String,
}

#[derive(Debug, Serialize)]
struct CreateRoomRequest<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    room_alias_name: Option<&'a str>,
    visibility: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    topic: Option<&'a str>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    invite: Vec<&'a str>,
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
                Ok(resp) => last_err = Some(anyhow!("readiness probe returned {}", resp.status())),
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
            Ok(token) => Ok(token),
            Err(e) => {
                if let Some(session) = extract_session_id(&e) {
                    eprintln!(
                        "tuwunel-provision: register flow requires interactive authentication; completing m.login.dummy"
                    );
                    return self.try_register(localpart, password, true, Some(&session));
                }
                Err(e)
            }
        }
    }

    pub fn login_password(&self, localpart: &str, password: &str) -> Result<String> {
        let body = serde_json::json!({
            "type": "m.login.password",
            "identifier": {
                "type": "m.id.user",
                "user": localpart,
            },
            "password": password,
        });

        let resp = self
            .req_auth(Method::POST, "/_matrix/client/v3/login")
            .json(&body)
            .send()
            .context("password login request failed")?;

        let status = resp.status();
        if status.is_success() {
            let data: RegisterResponse = resp.json().context("decoding login response")?;
            return Ok(data.access_token);
        }

        bail!("password login returned HTTP {status}");
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
            let data: RegisterResponse = resp.json().context("decoding register response")?;
            return Ok(data.access_token);
        }

        let body_text = resp.text().unwrap_or_default();
        if status == StatusCode::BAD_REQUEST
            && let Ok(err) = serde_json::from_str::<ErrorResponse>(&body_text)
            && err.errcode.as_deref() == Some("M_USER_IN_USE")
        {
            return Err(anyhow!("user_in_use:{localpart}"));
        }
        if status == StatusCode::FORBIDDEN
            && let Ok(err) = serde_json::from_str::<ErrorResponse>(&body_text)
            && err.errcode.as_deref() == Some("M_FORBIDDEN")
            && err
                .error
                .as_deref()
                .is_some_and(|msg| msg.contains("Registration has been disabled"))
        {
            return Err(anyhow!("registration_disabled"));
        }
        if status == StatusCode::UNAUTHORIZED
            && let Ok(err) = serde_json::from_str::<ErrorResponse>(&body_text)
            && let Some(session) = err.session
        {
            return Err(anyhow!("need_session:{session}"));
        }
        if status == StatusCode::UNAUTHORIZED {
            if session.is_none() {
                bail!("register returned 401 without a session — registration may be disabled");
            }
            bail!("register returned 401 during session completion");
        }

        bail!("register returned HTTP {status}");
    }

    pub fn create_or_update_user(
        &self,
        user_id: &str,
        password: &str,
        admin: bool,
        display_name: Option<&str>,
        public_registration_enabled: bool,
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
            if public_registration_enabled {
                eprintln!(
                    "tuwunel-provision: admin API returned {status} for {user_id} — \
                     falling back to public registration inside bootstrap window"
                );
                return self.register_fallback(user_id, password, admin, display_name);
            }

            bail!(
                "registration_required:{user_id}:admin API returned {status}; public registration \
                 bootstrap is not enabled"
            );
        }

        if status == StatusCode::UNAUTHORIZED {
            bail!("admin API returned 401 for {user_id} — the admin token has been rejected");
        }
        bail!("admin API returned {status} for {user_id}");
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
                if let Some(dn) = display_name
                    && let Err(e) = self.set_display_name(user_id, dn)
                {
                    eprintln!(
                        "tuwunel-provision: warning — failed to set display name \
                         for {user_id} via fallback: {e}"
                    );
                }
                Ok(())
            }
            Err(e) => {
                if let Some(session) = extract_session_id(&e) {
                    self.try_register(localpart, password, admin, Some(&session))?;
                    if let Some(dn) = display_name
                        && let Err(e) = self.set_display_name(user_id, dn)
                    {
                        eprintln!(
                            "tuwunel-provision: warning — failed to set display name \
                             for {user_id} via fallback: {e}"
                        );
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
        bail!("display name API returned {status} for {user_id}");
    }

    pub fn resolve_room_alias(&self, alias: &str) -> Result<Option<String>> {
        let path = format!(
            "/_matrix/client/v3/directory/room/{}",
            percent_encode(alias)
        );
        let resp = self
            .req_auth(Method::GET, &path)
            .send()
            .with_context(|| format!("resolving room alias {alias}"))?;

        let status = resp.status();
        if status.is_success() {
            let body: serde_json::Value = resp.json().context("decoding room alias response")?;
            let room_id = body
                .get("room_id")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| {
                    anyhow!("room alias response for {alias} did not include room_id")
                })?;
            return Ok(Some(room_id.to_owned()));
        }
        if status == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        bail!("room alias lookup returned {status} for {alias}");
    }

    pub fn create_room(
        &self,
        alias: &str,
        name: Option<&str>,
        topic: Option<&str>,
        invite: &[String],
    ) -> Result<String> {
        let alias_localpart = alias_localpart(alias)?;
        let body = CreateRoomRequest {
            room_alias_name: Some(alias_localpart),
            visibility: "private",
            name,
            topic,
            invite: invite.iter().map(String::as_str).collect(),
        };

        let resp = self
            .req_auth(Method::POST, "/_matrix/client/v3/createRoom")
            .json(&body)
            .send()
            .with_context(|| format!("creating room {alias}"))?;
        let status = resp.status();
        if status.is_success() {
            let data: CreateRoomResponse = resp.json().context("decoding createRoom response")?;
            return Ok(data.room_id);
        }
        bail!("createRoom returned {status} for {alias}");
    }

    pub fn invite_user_to_room(&self, room_id: &str, user_id: &str) -> Result<()> {
        let path = format!(
            "/_matrix/client/v3/rooms/{}/invite",
            percent_encode(room_id)
        );
        let body = serde_json::json!({ "user_id": user_id });
        let resp = self
            .req_auth(Method::POST, &path)
            .json(&body)
            .send()
            .with_context(|| format!("inviting {user_id} to {room_id}"))?;
        let status = resp.status();
        if status.is_success() {
            return Ok(());
        }
        let body_text = resp.text().unwrap_or_default();
        if status == StatusCode::FORBIDDEN && body_text.contains("already") {
            return Ok(());
        }
        bail!("room invite returned {status} for {user_id} in {room_id}");
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
fn is_user_in_use(err: &anyhow::Error) -> bool {
    err.chain()
        .map(|cause| format!("{cause}"))
        .any(|msg| msg.starts_with("user_in_use:"))
}

fn alias_localpart(alias: &str) -> Result<&str> {
    let Some(rest) = alias.strip_prefix('#') else {
        bail!("Matrix room alias must start with '#': {alias}");
    };
    let Some((localpart, _server)) = rest.split_once(':') else {
        bail!("Matrix room alias must include a server name: {alias}");
    };
    if localpart.is_empty() {
        bail!("Matrix room alias localpart is empty: {alias}");
    }
    Ok(localpart)
}

fn percent_encode(value: &str) -> String {
    let mut out = String::new();
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(byte as char);
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

pub fn registration_required(err: &anyhow::Error) -> bool {
    err.chain()
        .map(|cause| format!("{cause}"))
        .any(|msg| msg.starts_with("registration_required:") || msg == "registration_disabled")
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

    #[test]
    fn parses_alias_localpart() {
        assert_eq!(
            alias_localpart("#canix-alerts:matrix.tartanoglu.com").unwrap(),
            "canix-alerts"
        );
    }

    #[test]
    fn percent_encodes_matrix_identifiers() {
        assert_eq!(
            percent_encode("#canix-alerts:matrix.tartanoglu.com"),
            "%23canix-alerts%3Amatrix.tartanoglu.com"
        );
        assert_eq!(percent_encode("!room:id"), "%21room%3Aid");
    }

    #[test]
    fn is_user_in_use_detects_sentinel_error() {
        let err = anyhow!("user_in_use:can");
        assert!(is_user_in_use(&err));
    }

    #[test]
    fn registration_required_detects_disabled_registration() {
        let err = anyhow!("registration_disabled");
        assert!(registration_required(&err));
    }

    #[test]
    fn registration_required_detects_missing_bootstrap_window() {
        let err = anyhow!(
            "registration_required:@alice:example.com:admin API returned 404; public registration bootstrap is not enabled"
        );
        assert!(registration_required(&err));
    }
}
