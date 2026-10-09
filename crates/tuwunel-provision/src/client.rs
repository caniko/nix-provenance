use std::collections::{BTreeMap, BTreeSet};
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
    preset: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    topic: Option<&'a str>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    invite: Vec<&'a str>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    initial_state: Vec<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    power_level_content_override: Option<serde_json::Value>,
}

impl<'a> CreateRoomRequest<'a> {
    fn new(
        alias_localpart: &'a str,
        name: Option<&'a str>,
        topic: Option<&'a str>,
        invite: &'a [String],
        encrypted: bool,
    ) -> Self {
        Self {
            room_alias_name: Some(alias_localpart),
            visibility: "private",
            preset: encrypted.then_some("private_chat"),
            name,
            topic,
            invite: invite.iter().map(String::as_str).collect(),
            power_level_content_override: encrypted
                .then(|| serde_json::json!({"invite":100,"events":{"m.room.redaction":100}})),
            initial_state: if encrypted {
                vec![
                    serde_json::json!({"type": "m.room.join_rules", "state_key": "", "content": {"join_rule": "invite"}}),
                    serde_json::json!({"type": "m.room.guest_access", "state_key": "", "content": {"guest_access": "forbidden"}}),
                    serde_json::json!({"type": "m.room.encryption", "state_key": "", "content": {"algorithm": "m.megolm.v1.aes-sha2"}}),
                    serde_json::json!({"type": "m.room.history_visibility", "state_key": "", "content": {"history_visibility": "joined"}}),
                ]
            } else {
                Vec::new()
            },
        }
    }
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

    /// Attach a login token without rebuilding the HTTP transport. In particular,
    /// room provisioning must not introduce a fallible constructor after login
    /// but before its reconciliation/logout path.
    pub fn with_token(&self, token: &str) -> Self {
        Self {
            http: self.http.clone(),
            base: self.base.clone(),
            auth: Some(format!("Bearer {token}")),
        }
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
            Err(e) if is_user_in_use(&e) => self
                .login_password(localpart, password)
                .with_context(|| format!("logging into existing admin user {localpart}")),
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
        self.login_password_with_device(localpart, password, None)
    }

    /// Reuse one bounded provisioning device per service account rather than
    /// creating another Matrix device on every declarative reconciliation.
    pub fn login_password_with_device(
        &self,
        localpart: &str,
        password: &str,
        device_id: Option<&str>,
    ) -> Result<String> {
        let mut body = serde_json::json!({
            "type": "m.login.password",
            "identifier": {
                "type": "m.id.user",
                "user": localpart,
            },
            "password": password,
        });
        if let Some(device_id) = device_id {
            body["device_id"] = device_id.into();
            body["initial_device_display_name"] = "Tuwunel room provisioning".into();
        }

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

        // Preserve the HTTP status in the error chain so callers distinguish
        // definitive authentication refusals from potentially committed logins.
        resp.error_for_status()
            .with_context(|| format!("password login returned HTTP {status}"))?;
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
                if is_user_in_use(&e) {
                    self.login_password(localpart, password)
                        .with_context(|| format!("verifying existing user {user_id}"))?;
                    if let Some(dn) = display_name
                        && let Err(e) = self.set_display_name(user_id, dn)
                    {
                        eprintln!(
                            "tuwunel-provision: warning — failed to set display name \
                             for {user_id} after existing-user reconciliation: {e}"
                        );
                    }
                    return Ok(());
                }
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
        encrypted: bool,
    ) -> Result<String> {
        let (alias_localpart, _) = parse_room_alias(alias)?;
        let body = CreateRoomRequest::new(alias_localpart, name, topic, invite, encrypted);

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

    /// Read live state as the declared room creator. An admin alias lookup
    /// alone does not establish encryption, join rules, or who can read it.
    pub fn private_room_members(
        &self,
        room_id: &str,
        creator: &str,
        invite: &[String],
        encrypted: bool,
    ) -> Result<BTreeSet<String>> {
        let path = format!("/_matrix/client/v3/rooms/{}/state", percent_encode(room_id));
        let response = self
            .req_auth(Method::GET, &path)
            .send()
            .with_context(|| format!("reading state of room {room_id}"))?;
        let status = response.status();
        if !status.is_success() {
            bail!(
                "room state returned {status} for {room_id}; the declared creator must be joined"
            );
        }
        let events: Vec<serde_json::Value> =
            response.json().context("decoding Matrix room state")?;
        verify_private_room_state(&events, creator, invite, encrypted)
    }

    pub fn logout(&self) -> Result<()> {
        let response = self
            .req_auth(Method::POST, "/_matrix/client/v3/logout")
            .send()
            .context("logging out room provisioning device")?;
        if !response.status().is_success() {
            bail!(
                "room provisioning device logout returned {}",
                response.status()
            );
        }
        Ok(())
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

fn verify_private_room_state(
    events: &[serde_json::Value],
    creator: &str,
    invite: &[String],
    encrypted: bool,
) -> Result<BTreeSet<String>> {
    let mut join_rule = None;
    let mut guest_access = None;
    let mut algorithm = None;
    let mut history_visibility = None;
    let mut creation = None;
    let mut power_levels = None;
    let mut members = BTreeMap::new();
    for event in events {
        match event.get("type").and_then(serde_json::Value::as_str) {
            Some("m.room.join_rules") if event["state_key"].as_str() == Some("") => {
                join_rule = event["content"]["join_rule"].as_str();
            }
            Some("m.room.guest_access") if event["state_key"].as_str() == Some("") => {
                guest_access = event["content"]["guest_access"].as_str();
            }
            Some("m.room.encryption") if event["state_key"].as_str() == Some("") => {
                algorithm = event["content"]["algorithm"].as_str();
            }
            Some("m.room.history_visibility") if event["state_key"].as_str() == Some("") => {
                history_visibility = event["content"]["history_visibility"].as_str();
            }
            Some("m.room.create") if event["state_key"].as_str() == Some("") => {
                creation = Some(event);
            }
            Some("m.room.power_levels") if event["state_key"].as_str() == Some("") => {
                power_levels = Some(&event["content"]);
            }
            Some("m.room.third_party_invite") => {
                if !event["content"]
                    .as_object()
                    .is_some_and(serde_json::Map::is_empty)
                {
                    bail!("room contains an undeclared third-party invitation");
                }
            }
            Some("m.room.member") => {
                if let (Some(user), Some(membership)) = (
                    event["state_key"].as_str(),
                    event["content"]["membership"].as_str(),
                ) {
                    members.insert(user.to_owned(), membership.to_owned());
                }
            }
            _ => {}
        }
    }
    if join_rule != Some("invite") || guest_access != Some("forbidden") {
        bail!("room is not invite-only with guest access forbidden");
    }
    if encrypted && algorithm != Some("m.megolm.v1.aes-sha2") {
        bail!(
            "room is missing the required Matrix encryption state; refusing to retrofit encryption"
        );
    }
    if !matches!(history_visibility, Some("joined" | "invited" | "shared")) {
        bail!("room history is not restricted to members");
    }
    let creation = creation.context("room is missing its canonical creation event")?;
    if creation["sender"].as_str() != Some(creator) {
        bail!("room was not created by the declared owner");
    }
    if let Some(additional) = creation["content"].get("additional_creators") {
        // ponytail: private rooms have one controlling owner; co-owners need an
        // explicit ownership policy before adopting their rooms.
        if !additional.as_array().is_some_and(Vec::is_empty) {
            bail!("room has additional creators outside its single-owner policy");
        }
    }
    let version = match creation["content"].get("room_version") {
        Some(version) => version.as_str().context("invalid room version")?,
        None => "1",
    };
    // Room version IDs are opaque strings, not numbers to normalize.
    let version = [
        "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12",
    ]
    .iter()
    .position(|&supported| supported == version)
    .with_context(|| format!("unsupported Matrix room version: {version}"))?
        + 1;
    // Order exact integers first, then any legacy float overflow beyond i64.
    // This preserves integer precision without saturating distinct finite legacy
    // powers or rounding their comparisons through f64 in modern rooms.
    let level = |value: Option<&serde_json::Value>, default: i64| -> Result<(i64, f64)> {
        match value {
            Some(serde_json::Value::String(value)) if version < 10 => value
                .trim()
                .parse()
                .map(|n| (n, 0.0))
                .context("invalid Matrix power level"),
            Some(value) if version < 6 && value.is_f64() => {
                let n = value
                    .as_f64()
                    .filter(|n| n.is_finite())
                    .context("invalid Matrix power level")?
                    .trunc();
                let overflow = if n >= i64::MAX as f64 || n < i64::MIN as f64 {
                    n
                } else {
                    0.0
                };
                Ok((n as i64, overflow))
            }
            Some(value) => value
                .as_i64()
                .map(|n| (n, 0.0))
                .context("invalid Matrix power level"),
            None => Ok((default, 0.0)),
        }
    };
    let empty = serde_json::Map::new();
    let powers = match power_levels {
        Some(value) => value.as_object().context("invalid room power levels")?,
        None => &empty,
    };
    let users = match powers.get("users") {
        Some(value) => value
            .as_object()
            .context("invalid room user power levels")?,
        None => &empty,
    };
    let default_user = level(powers.get("users_default"), 0)?;
    // Matrix v12 creators have infinite power; older rooms without a power
    // event give the creation sender 100. These are protocol defaults, not
    // inferred ownership or fabricated state.
    let owner_power = if version >= 12 {
        (i64::MAX, f64::INFINITY)
    } else if power_levels.is_none() {
        (100, 0.0)
    } else {
        users
            .get(creator)
            .map_or(Ok(default_user), |value| level(Some(value), 0))?
    };
    if owner_power <= default_user {
        bail!("declared owner does not control room power levels");
    }
    let mut nonowner_power = default_user;
    for (user, value) in users {
        if user != creator {
            let power = level(Some(value), 0)?;
            if power > nonowner_power {
                nonowner_power = power;
            }
        }
    }
    if nonowner_power >= owner_power {
        bail!("room has another controlling account");
    }
    for (key, default) in [
        ("state_default", 50),
        ("invite", 0),
        ("kick", 50),
        ("ban", 50),
        ("redact", 50),
    ] {
        if key == "redact" && version >= 12 {
            // v12 redaction sending is controlled by the event threshold below.
            continue;
        }
        let required = level(powers.get(key), default)?;
        if owner_power < required {
            bail!("declared owner lacks room control for {key}");
        }
        if nonowner_power >= required {
            bail!("nonowner can change room policy through {key}");
        }
    }
    let events = match powers.get("events") {
        Some(value) => value.as_object().context("invalid event power levels")?,
        None => &empty,
    };
    // Every supported version checks the redaction event's sending threshold;
    // `redact` alone cannot stop redaction of another local user's event.
    let required = match events.get("m.room.redaction") {
        Some(value) => level(Some(value), 0)?,
        None => level(powers.get("events_default"), 0)?,
    };
    if owner_power < required {
        bail!("declared owner lacks room control for m.room.redaction");
    }
    if nonowner_power >= required {
        bail!("nonowner can change room policy through m.room.redaction");
    }
    for (kind, value) in events {
        let required = level(Some(value), 0)?;
        if owner_power < required {
            bail!("declared owner cannot control all room event types");
        }
        // Only known timeline messages may bypass owner-only state control.
        if !matches!(
            kind.as_str(),
            "m.room.message"
                | "m.room.encrypted"
                | "m.reaction"
                | "m.sticker"
                | "m.poll.start"
                | "m.poll.response"
                | "m.poll.end"
                | "org.matrix.msc3381.poll.start"
                | "org.matrix.msc3381.poll.response"
                | "org.matrix.msc3381.poll.end"
        ) && nonowner_power >= required
        {
            bail!("nonowner can change room policy through {kind}");
        }
    }
    if members.get(creator).map(String::as_str) != Some("join") {
        bail!("declared room creator is not joined");
    }
    let allowed: BTreeSet<&str> = std::iter::once(creator)
        .chain(invite.iter().map(String::as_str))
        .collect();
    let mut present = BTreeSet::new();
    for (user, membership) in members {
        if matches!(membership.as_str(), "join" | "invite" | "knock") {
            if !allowed.contains(user.as_str()) || membership == "knock" {
                bail!("room contains an undeclared active member or invitation: {user}");
            }
            present.insert(user);
        }
    }
    Ok(present)
}

#[cfg(test)]
mod private_room_tests {
    use super::*;

    fn state() -> Vec<serde_json::Value> {
        vec![
            serde_json::json!({"type":"m.room.join_rules", "state_key":"", "content":{"join_rule":"invite"}}),
            serde_json::json!({"type":"m.room.guest_access", "state_key":"", "content":{"guest_access":"forbidden"}}),
            serde_json::json!({"type":"m.room.encryption", "state_key":"", "content":{"algorithm":"m.megolm.v1.aes-sha2"}}),
            serde_json::json!({"type":"m.room.history_visibility", "state_key":"", "content":{"history_visibility":"joined"}}),
            serde_json::json!({"type":"m.room.create", "state_key":"", "sender":"@iris:example.test", "content":{}}),
            serde_json::json!({"type":"m.room.power_levels", "state_key":"", "content":{"users":{"@iris:example.test":100},"invite":100,"events":{"m.room.redaction":100}}}),
            serde_json::json!({"type":"m.room.member", "state_key":"@iris:example.test", "content":{"membership":"join"}}),
            serde_json::json!({"type":"m.room.member", "state_key":"@can:example.test", "content":{"membership":"invite"}}),
        ]
    }

    #[test]
    fn encrypted_room_is_private_before_the_first_invitation() {
        let invited = vec!["@can:example.test".to_owned()];
        let request =
            CreateRoomRequest::new("hermes-iris", Some("hermes-iris"), None, &invited, true);
        let body = serde_json::to_value(request).unwrap();
        assert_eq!(body["visibility"], "private");
        assert_eq!(body["preset"], "private_chat");
        assert_eq!(body["invite"], serde_json::json!(["@can:example.test"]));
        assert_eq!(body["power_level_content_override"]["invite"], 100);
        assert_eq!(
            body["power_level_content_override"]["events"]["m.room.redaction"],
            100
        );
        assert_eq!(body["initial_state"][0]["content"]["join_rule"], "invite");
        assert_eq!(
            body["initial_state"][1]["content"]["guest_access"],
            "forbidden"
        );
        assert_eq!(
            body["initial_state"][2]["content"]["algorithm"],
            "m.megolm.v1.aes-sha2"
        );
    }

    fn verify(events: &[serde_json::Value]) -> Result<BTreeSet<String>> {
        verify_private_room_state(
            events,
            "@iris:example.test",
            &["@can:example.test".into()],
            true,
        )
    }

    #[test]
    fn only_creator_and_invited_human_may_be_present() {
        let members = verify(&state()).unwrap();
        assert_eq!(
            members,
            BTreeSet::from(["@iris:example.test".into(), "@can:example.test".into()])
        );
        let mut events = state();
        events.push(serde_json::json!({"type":"m.room.member", "state_key":"@matrix-admin:example.test", "content":{"membership":"join"}}));
        assert!(verify(&events).is_err());
        events.pop();
        events.push(serde_json::json!({"type":"m.room.member", "state_key":"@other:example.test", "content":{"membership":"invite"}}));
        assert!(verify(&events).is_err());
    }

    #[test]
    fn refuses_unencrypted_or_public_existing_room() {
        let mut events = state();
        events.retain(|event| event["type"] != "m.room.encryption");
        assert!(verify(&events).is_err());
        events = state();
        events[0]["content"]["join_rule"] = "public".into();
        assert!(verify(&events).is_err());
        events = state();
        events[1]["content"]["guest_access"] = "can_join".into();
        assert!(verify(&events).is_err());
    }

    #[test]
    fn nonempty_state_keys_cannot_prove_private_room_policy() {
        for index in 0..5 {
            let mut events = state();
            events[index]["state_key"] = "unrelated".into();
            assert!(verify(&events).is_err());
        }
    }

    #[test]
    fn accepts_missing_invitation_to_reconcile_and_departed_members() {
        let mut events = state();
        events.pop();
        events.push(serde_json::json!({"type":"m.room.member", "state_key":"@old:example.test", "content":{"membership":"leave"}}));
        assert_eq!(
            verify(&events).unwrap(),
            BTreeSet::from(["@iris:example.test".into()])
        );
    }

    #[test]
    fn rejects_public_history_foreign_creator_and_lost_controlling_power() {
        let mut events = state();
        events[3]["content"]["history_visibility"] = "world_readable".into();
        assert!(verify(&events).is_err());
        events = state();
        events[4]["sender"] = "@other:example.test".into();
        assert!(verify(&events).is_err());
        for levels in [
            serde_json::json!({"users":{"@iris:example.test":0}}),
            serde_json::json!({"users":{"@iris:example.test":100,"@other:example.test":100}}),
            serde_json::json!({"users":{"@iris:example.test":100},"state_default":101}),
            serde_json::json!({"users":{"@iris:example.test":100},"invite":101}),
            serde_json::json!({"users":{"@iris:example.test":100},"users_default":100}),
            serde_json::json!({"users":{"@iris:example.test":100},"events":{"m.room.power_levels":101}}),
        ] {
            events = state();
            events[5]["content"] = levels;
            assert!(verify(&events).is_err());
        }
    }

    #[test]
    fn rejects_permissive_protocol_defaults_and_supports_v12_single_creator() {
        let mut events = state();
        events.retain(|event| event["type"] != "m.room.power_levels");
        assert!(verify(&events).is_err());
        events = state();
        events[4]["content"]["room_version"] = "12".into();
        events[5]["content"] = serde_json::json!({"users":{},"invite":100,"events":{"m.room.tombstone":150,"m.room.redaction":100}});
        assert!(verify(&events).is_ok());
        events[4]["content"]["additional_creators"] = serde_json::json!(["@other:example.test"]);
        assert!(verify(&events).is_err());
    }

    #[test]
    fn unsupported_room_version_identifiers_do_not_inherit_standard_authority() {
        for version in [
            "012",
            "01",
            "+12",
            "+1",
            "001",
            "0",
            "13",
            "org.example.room",
            " 12",
            "12 ",
            "1.0",
        ] {
            let mut events = state();
            events[4]["content"]["room_version"] = version.into();
            assert!(verify(&events).is_err(), "unsupported identifier {version}");
            // Unsupported v12-like identifiers must not grant creator infinity.
            events[5]["content"]["users"] = serde_json::json!({});
            assert!(
                verify(&events).is_err(),
                "unsupported creator authority {version}"
            );
        }
    }

    #[test]
    fn rejects_every_nonowner_privacy_or_membership_threshold() {
        for key in ["state_default", "invite", "kick", "ban", "redact"] {
            for explicit_user in [false, true] {
                let mut events = state();
                if explicit_user {
                    events[5]["content"]["users"]["@can:example.test"] = 10.into();
                } else {
                    events[5]["content"]["users_default"] = 10.into();
                }
                events[5]["content"][key] = 10.into();
                assert!(
                    verify(&events).is_err(),
                    "accepted {key} with nonowner power 10"
                );
            }
        }
        for kind in [
            "m.room.power_levels",
            "m.room.join_rules",
            "m.room.guest_access",
            "m.room.history_visibility",
            "m.room.encryption",
            "m.room.member",
            "m.room.third_party_invite",
            "m.room.server_acl",
            "m.room.tombstone",
        ] {
            let mut events = state();
            events[5]["content"]["events"][kind] = 0.into();
            assert!(
                verify(&events).is_err(),
                "accepted nonowner control of {kind}"
            );
        }
        let mut events = state();
        events[5]["content"]["events"]["m.room.encrypted"] = 0.into();
        assert!(
            verify(&events).is_ok(),
            "ordinary encrypted messages remain allowed"
        );
    }

    #[test]
    fn every_supported_version_requires_owner_only_effective_redaction_power() {
        for version in 1..=12 {
            for (mut levels, safe) in [
                (serde_json::json!({"invite":100}), false),
                (serde_json::json!({"invite":100,"events_default":0}), false),
                (
                    serde_json::json!({"invite":100,"events_default":100,"events":{"m.room.redaction":0}}),
                    false,
                ),
                (
                    serde_json::json!({"invite":100,"users_default":10,"events_default":10}),
                    false,
                ),
                (
                    serde_json::json!({"invite":100,"users":{"@can:example.test":10},"events_default":10}),
                    false,
                ),
                (serde_json::json!({"invite":100,"events_default":50}), true),
                (
                    serde_json::json!({"invite":100,"events_default":0,"events":{"m.room.redaction":100}}),
                    true,
                ),
            ] {
                if version < 12 {
                    levels["users"]["@iris:example.test"] = 100.into();
                }
                let mut events = state();
                events[4]["content"]["room_version"] = version.to_string().into();
                events[5]["content"] = levels;
                assert_eq!(verify(&events).is_ok(), safe, "room version {version}");
            }
        }
        let mut events = state();
        events[4]["content"]["room_version"] = "11".into();
        events[5]["content"]["events"] = serde_json::json!({});
        events[5]["content"]["events_default"] = 101.into();
        assert!(verify(&events).is_err(), "owner cannot send redactions");
        events[5]["content"]["events"]["m.room.redaction"] = 100.into();
        assert!(
            verify(&events).is_ok(),
            "explicit threshold overrides default"
        );
    }

    #[test]
    fn legacy_string_power_levels_follow_room_version_rules() {
        for version in 1..=12 {
            let mut events = state();
            events[4]["content"]["room_version"] = version.to_string().into();
            events[5]["content"] = serde_json::json!({
                "users":{"@iris:example.test":" +00100 ","@can:example.test":" -01 "},
                "users_default":"-01", "events_default":"000", "state_default":"+050",
                "invite":" 100 ", "kick":"50", "ban":"50", "redact":"50",
                "events":{"m.room.redaction":"\t+100\n","m.room.encrypted":"0","m.room.power_levels":"100"}
            });
            assert_eq!(
                verify(&events).is_ok(),
                version < 10,
                "room version {version}"
            );
        }
    }

    #[test]
    fn legacy_power_parsing_rejects_malformed_values_and_preserves_policy() {
        for version in 1..=9 {
            for invalid in [
                serde_json::json!(""),
                serde_json::json!("+"),
                serde_json::json!("-"),
                serde_json::json!("1.0"),
                serde_json::json!("1e2"),
                serde_json::json!("0x64"),
                serde_json::json!("1 00"),
                serde_json::json!("100abc"),
                serde_json::json!("9223372036854775808"),
                serde_json::json!(true),
                serde_json::json!(null),
                serde_json::json!({}),
            ] {
                let mut events = state();
                events[4]["content"]["room_version"] = version.to_string().into();
                events[5]["content"]["events"]["m.room.redaction"] = invalid;
                assert!(verify(&events).is_err(), "room version {version}");
            }
            for levels in [
                serde_json::json!({"users":{"@iris:example.test":"100"},"invite":"100","events":{"m.room.redaction":"0"}}),
                serde_json::json!({"users":{"@iris:example.test":"100","@can:example.test":"100"},"invite":"100","events":{"m.room.redaction":"100"}}),
            ] {
                let mut events = state();
                events[4]["content"]["room_version"] = version.to_string().into();
                events[5]["content"] = levels;
                let error = verify(&events).unwrap_err().to_string();
                assert!(!error.contains("invalid Matrix power level"), "{error}");
            }
        }
    }

    #[test]
    fn legacy_float_powers_follow_version_rules_and_truncate_towards_zero() {
        for version in 1..=12 {
            let mut events = state();
            events[4]["content"]["room_version"] = version.to_string().into();
            events[5]["content"] = serde_json::json!({
                "users":{"@iris:example.test":100.9}, "users_default":-0.9,
                "state_default":50.9, "invite":100.5, "kick":50.9, "ban":50.9, "redact":50.9,
                "events":{"m.room.redaction":100.5}
            });
            assert_eq!(
                verify(&events).is_ok(),
                version < 6,
                "room version {version}"
            );
            events[5]["content"]["events"]["m.room.redaction"] = 0.9.into();
            assert!(
                verify(&events).is_err(),
                "nonowner can send redactions after truncation"
            );
        }
        for version in 1..=5 {
            let mut events = state();
            events[4]["content"]["room_version"] = version.to_string().into();
            events[5]["content"]["users"]["@iris:example.test"] = 1e100.into();
            events[5]["content"]["events"]["m.room.redaction"] = 5e99.into();
            assert!(
                verify(&events).is_ok(),
                "finite powers beyond i64 remain comparable"
            );
            events[5]["content"]["users"]["@can:example.test"] = 1e100.into();
            assert!(
                verify(&events).is_err(),
                "equal legacy controller power is refused"
            );
        }
    }

    #[test]
    fn integer_power_comparisons_remain_exact_above_f64_precision() {
        for version in 1..=11 {
            for strings in [false, true] {
                let power = |n: i64| {
                    if strings {
                        serde_json::json!(n.to_string())
                    } else {
                        serde_json::json!(n)
                    }
                };
                let mut events = state();
                events[4]["content"]["room_version"] = version.to_string().into();
                let owner = power(9_007_199_254_740_993);
                events[5]["content"] = serde_json::json!({
                    "users":{"@iris:example.test":owner,"@can:example.test":power(9_007_199_254_740_992)},
                    "users_default":-1, "state_default":owner, "invite":owner,
                    "kick":owner, "ban":owner, "redact":owner,
                    "events":{"m.room.redaction":owner}
                });
                assert_eq!(verify(&events).is_ok(), !strings || version < 10);
                events[5]["content"]["events"]["m.room.redaction"] = power(9_007_199_254_740_994);
                assert!(
                    verify(&events).is_err(),
                    "owner cannot meet a strictly greater threshold"
                );
            }
        }
    }

    #[test]
    fn v12_ignores_redact_but_requires_owner_only_redaction_events() {
        for version in 1..=12 {
            let mut events = state();
            events[4]["content"]["room_version"] = version.to_string().into();
            events[5]["content"]["redact"] = 0.into();
            assert_eq!(
                verify(&events).is_ok(),
                version == 12,
                "room version {version}"
            );
            events[5]["content"]["events"]["m.room.redaction"] = 0.into();
            assert!(
                verify(&events).is_err(),
                "redaction sending power must still exclude nonowners"
            );
        }
    }

    #[test]
    fn ordinary_poll_events_do_not_grant_room_policy_control() {
        for kind in [
            "m.poll.start",
            "m.poll.response",
            "m.poll.end",
            "org.matrix.msc3381.poll.start",
            "org.matrix.msc3381.poll.response",
            "org.matrix.msc3381.poll.end",
        ] {
            let mut events = state();
            events[5]["content"]["events"][kind] = 0.into();
            assert!(verify(&events).is_ok(), "rejected timeline event {kind}");
        }
    }

    #[test]
    fn rejects_active_third_party_invitations_but_accepts_revoked_empty_state() {
        let mut events = state();
        events.push(serde_json::json!({"type":"m.room.third_party_invite", "state_key":"token", "content":{"display_name":"outsider","public_key":"key"}}));
        assert!(verify(&events).is_err());
        events.last_mut().unwrap()["content"] = serde_json::json!({});
        assert!(verify(&events).is_ok());
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

fn is_user_in_use(err: &anyhow::Error) -> bool {
    err.chain()
        .map(|cause| format!("{cause}"))
        .any(|msg| msg.starts_with("user_in_use:"))
}

pub(crate) fn parse_room_alias(alias: &str) -> Result<(&str, &str)> {
    let Some(rest) = alias.strip_prefix('#') else {
        bail!("Matrix room alias must start with '#': {alias}");
    };
    let Some((localpart, server)) = rest.split_once(':') else {
        bail!("Matrix room alias must include a server name: {alias}");
    };
    if localpart.is_empty() {
        bail!("Matrix room alias localpart is empty: {alias}");
    }
    if server.is_empty() {
        bail!("Matrix room alias server name is empty: {alias}");
    }
    Ok((localpart, server))
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
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpListener;

    #[test]
    fn existing_accounts_require_successful_password_login() {
        for admin in [true, false] {
            for accepted in [true, false] {
                let listener = TcpListener::bind("127.0.0.1:0").unwrap();
                let url = format!("http://{}", listener.local_addr().unwrap());
                let server = std::thread::spawn(move || {
                    for step in 0..2 {
                        let (mut stream, _) = listener.accept().unwrap();
                        stream
                            .set_read_timeout(Some(Duration::from_secs(5)))
                            .unwrap();
                        let mut reader = BufReader::new(&stream);
                        let mut line = String::new();
                        reader.read_line(&mut line).unwrap();
                        assert_eq!(
                            line.trim(),
                            if step == 0 {
                                "POST /_matrix/client/v3/register HTTP/1.1"
                            } else {
                                "POST /_matrix/client/v3/login HTTP/1.1"
                            }
                        );
                        let mut length = 0;
                        loop {
                            line.clear();
                            reader.read_line(&mut line).unwrap();
                            if line == "\r\n" {
                                break;
                            }
                            if let Some(value) =
                                line.to_ascii_lowercase().strip_prefix("content-length:")
                            {
                                length = value.trim().parse::<usize>().unwrap();
                            }
                        }
                        let mut body = vec![0; length];
                        reader.read_exact(&mut body).unwrap();
                        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
                        if step == 1 {
                            assert_eq!(body["identifier"]["user"], "alice");
                            assert_eq!(body["password"], "fixture-password");
                        }
                        let (status, response) = if step == 0 {
                            (
                                400,
                                json!({"errcode":"M_USER_IN_USE", "error":"already exists"}),
                            )
                        } else if accepted {
                            (200, json!({"access_token":"fixture-access"}))
                        } else {
                            (
                                403,
                                json!({"errcode":"M_FORBIDDEN", "error":"wrong password"}),
                            )
                        };
                        let response = response.to_string();
                        write!(stream, "HTTP/1.1 {status} Fixture\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response}", response.len()).unwrap();
                    }
                });
                let client = TuwunelClient::new_without_auth(&url).unwrap();
                let result = if admin {
                    client
                        .register_admin("@alice:example.test", "fixture-password")
                        .map(|_| ())
                } else {
                    client.register_fallback("@alice:example.test", "fixture-password", false, None)
                };
                assert_eq!(result.is_ok(), accepted);
                server.join().unwrap();
            }
        }
    }

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
    fn parses_room_alias_without_dropping_the_server() {
        assert_eq!(
            parse_room_alias("#canix-alerts:matrix.tartanoglu.com").unwrap(),
            ("canix-alerts", "matrix.tartanoglu.com")
        );
        for server in ["example.test:8448", "[::1]:8448"] {
            let alias = format!("#room:{server}");
            assert_eq!(parse_room_alias(&alias).unwrap(), ("room", server));
        }
        assert!(parse_room_alias("#room:").is_err());
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
