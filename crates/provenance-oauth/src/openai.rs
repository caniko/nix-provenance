//! ChatGPT device authorization, as implemented by upstream Codex/OpenCode/OMP.
//! URLs and client identity are fixed: an input config cannot redirect tokens.
use crate::{Grant, Secret, now};
use anyhow::{Context, Result, bail, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use reqwest::blocking::{Client, Response};
use serde::Deserialize;
use std::{
    thread,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

const ISSUER: &str = "https://auth.openai.com";
const CLIENT: &str = "app_EMoamEEZ73f0CkXaXp7hrann";

pub struct OpenAi {
    client: Client,
}

fn document<T: serde::de::DeserializeOwned>(response: Response) -> Result<T> {
    let status = response.status();
    ensure!(
        status.is_success(),
        "OpenAI authorization request failed (HTTP {})",
        status.as_u16()
    );
    ensure!(
        response.content_length().unwrap_or(0) <= 128 * 1024,
        "OpenAI response exceeds size limit"
    );
    let mut bytes = Zeroizing::new(Vec::new());
    use std::io::Read;
    response
        .take(128 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| anyhow::anyhow!("could not read OpenAI response"))?;
    ensure!(
        bytes.len() <= 128 * 1024,
        "OpenAI response exceeds size limit"
    );
    serde_json::from_slice(&bytes)
        .map_err(|_| anyhow::anyhow!("invalid OpenAI authorization response"))
}

#[derive(Deserialize)]
struct Tokens {
    access_token: Secret,
    refresh_token: Option<Secret>,
    expires_in: u64,
    id_token: Option<Secret>,
}

impl OpenAi {
    pub fn new() -> Result<Self> {
        Ok(Self {
            client: Client::builder()
                .https_only(true)
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(5))
                .user_agent(concat!("nix-provenance-oauth/", env!("CARGO_PKG_VERSION")))
                .build()?,
        })
    }

    /// The callback displays a device URL/code to the human authorizing the
    /// target. No refresh or access token is emitted through this interface.
    pub fn authorize(&self, prompt: impl FnOnce(&str, &str)) -> Result<Grant> {
        #[derive(Deserialize)]
        struct Device {
            device_auth_id: Secret,
            user_code: String,
            interval: serde_json::Value,
        }
        let device: Device = document(
            self.client
                .post(format!("{ISSUER}/api/accounts/deviceauth/usercode"))
                .json(&serde_json::json!({ "client_id": CLIENT }))
                .send()
                .map_err(|_| anyhow::anyhow!("OpenAI device authorization unavailable"))?,
        )?;
        ensure!(
            !device.device_auth_id.0.is_empty()
                && !device.user_code.is_empty()
                && device.user_code.len() <= 64
                && device
                    .user_code
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-'),
            "invalid OpenAI device authorization code"
        );
        let seconds = match device.interval {
            serde_json::Value::String(value) => value.parse::<u64>().ok(),
            serde_json::Value::Number(value) => value.as_u64(),
            _ => None,
        }
        .context("OpenAI device response is missing a polling interval")?;
        ensure!(
            (1..=60).contains(&seconds),
            "invalid OpenAI polling interval"
        );
        prompt("https://auth.openai.com/codex/device", &device.user_code);
        let deadline = Instant::now() + Duration::from_secs(15 * 60);
        while Instant::now() + Duration::from_secs(seconds + 3) < deadline {
            thread::sleep(Duration::from_secs(seconds + 3));
            let response = self.client.post(format!("{ISSUER}/api/accounts/deviceauth/token"))
                .json(&serde_json::json!({ "device_auth_id": device.device_auth_id.0, "user_code": device.user_code }))
                .send().map_err(|_| anyhow::anyhow!("OpenAI device polling unavailable"))?;
            if matches!(response.status().as_u16(), 403 | 404) {
                continue;
            }
            #[derive(Deserialize)]
            struct Code {
                authorization_code: Secret,
                code_verifier: Secret,
            }
            let code: Code = document(response)?;
            ensure!(
                !code.authorization_code.0.is_empty() && !code.code_verifier.0.is_empty(),
                "OpenAI device response is missing the authorization code"
            );
            return self.exchange(
                &[
                    ("grant_type", "authorization_code"),
                    ("client_id", CLIENT),
                    ("code", &code.authorization_code.0),
                    ("code_verifier", &code.code_verifier.0),
                    (
                        "redirect_uri",
                        "https://auth.openai.com/deviceauth/callback",
                    ),
                ],
                None,
            );
        }
        bail!("OpenAI device authorization timed out")
    }

    pub fn refresh(&self, previous: &Grant) -> Result<Grant> {
        self.exchange(
            &[
                ("grant_type", "refresh_token"),
                ("client_id", CLIENT),
                ("refresh_token", &previous.refresh_token.0),
            ],
            Some(previous),
        )
    }

    fn exchange(&self, fields: &[(&str, &str)], previous: Option<&Grant>) -> Result<Grant> {
        let tokens: Tokens = document(
            self.client
                .post(format!("{ISSUER}/oauth/token"))
                .form(fields)
                .send()
                .map_err(|_| {
                    anyhow::anyhow!("OpenAI token exchange failed; its outcome may be uncertain")
                })?,
        )?;
        into_grant(tokens, previous, now()?)
    }
}

fn into_grant(tokens: Tokens, previous: Option<&Grant>, now: u64) -> Result<Grant> {
    // These claims are metadata from a token received over authenticated TLS,
    // not a JWT signature-verification or user-authentication boundary.
    let account_id = account(&tokens.access_token.0)
        .or_else(|| tokens.id_token.as_ref().and_then(|token| account(&token.0)))
        .or_else(|| previous.map(|grant| grant.account_id.clone()))
        .context("OpenAI token is missing its ChatGPT account ID")?;
    let refresh_token = tokens
        .refresh_token
        .or_else(|| previous.map(|grant| grant.refresh_token.clone()))
        .context("OpenAI enrollment is missing a refresh token")?;
    let expires_at = tokens
        .expires_in
        .checked_mul(1000)
        .and_then(|ttl| now.checked_add(ttl))
        .context("invalid OpenAI token expiry")?;
    ensure!(
        tokens.expires_in > 60,
        "OpenAI access token expires too soon"
    );
    let grant = Grant {
        access_token: tokens.access_token,
        refresh_token,
        expires_at,
        account_id,
    };
    grant.validate()?;
    Ok(grant)
}

fn account(token: &str) -> Option<String> {
    let payload = token.split('.').nth(1)?;
    let bytes = Zeroizing::new(URL_SAFE_NO_PAD.decode(payload).ok()?);
    let claims: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    claims
        .get("https://api.openai.com/auth")?
        .get("chatgpt_account_id")?
        .as_str()
        .map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_response_never_exposes_token_material() {
        let previous = Grant {
            access_token: Secret("access-secret".into()),
            refresh_token: Secret("refresh-secret".into()),
            expires_at: 123,
            account_id: "account".into(),
        };
        let tokens = Tokens {
            access_token: Secret("next-access-secret".into()),
            refresh_token: None,
            expires_in: u64::MAX,
            id_token: None,
        };
        let error = into_grant(tokens, Some(&previous), 100)
            .unwrap_err()
            .to_string();
        assert_eq!(error, "invalid OpenAI token expiry");
        assert!(!format!("{previous:?}").contains("refresh-secret"));
    }

    #[test]
    fn refresh_may_retain_refresh_token_but_enrollment_cannot_invent_one() {
        let previous = Grant {
            access_token: Secret("old".into()),
            refresh_token: Secret("refresh".into()),
            expires_at: 123,
            account_id: "account".into(),
        };
        let tokens = || Tokens {
            access_token: Secret("next".into()),
            refresh_token: None,
            expires_in: 3600,
            id_token: None,
        };
        let next = into_grant(tokens(), Some(&previous), 100).unwrap();
        assert_eq!(next.refresh_token.0, "refresh");
        assert_eq!(next.expires_at, 3_600_100);
        assert!(into_grant(tokens(), None, 100).is_err());
    }
}
