//! Google Drive device authorization. Endpoints are fixed to avoid credential redirection.
use crate::{Grant, OAuthClient, Secret, now};
use anyhow::{Context, Result, bail, ensure};
use reqwest::blocking::{Client, Response};
use serde::Deserialize;
use std::{
    io::Read,
    thread,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

const TOKEN: &str = "https://oauth2.googleapis.com/token";
const DEVICE: &str = "https://oauth2.googleapis.com/device/code";
const ABOUT: &str = "https://www.googleapis.com/drive/v3/about?fields=user(permissionId)";

#[derive(Deserialize)]
struct Tokens {
    access_token: Secret,
    refresh_token: Option<Secret>,
    expires_in: u64,
}

fn document<T: serde::de::DeserializeOwned>(response: Response) -> Result<T> {
    ensure!(
        response.content_length().unwrap_or(0) <= 128 * 1024,
        "Google response exceeds size limit"
    );
    let mut bytes = Zeroizing::new(Vec::new());
    response
        .take(128 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| anyhow::anyhow!("could not read Google response"))?;
    ensure!(
        bytes.len() <= 128 * 1024,
        "Google response exceeds size limit"
    );
    serde_json::from_slice(&bytes)
        .map_err(|_| anyhow::anyhow!("invalid Google authorization response"))
}

fn poll_response(response: Response, interval: &mut u64) -> Result<Option<Tokens>> {
    if response.status().is_success() {
        return Ok(Some(document(response)?));
    }
    #[derive(Deserialize)]
    struct Error {
        error: String,
    }
    let error: Error = document(response)?;
    match error.error.as_str() {
        "authorization_pending" => Ok(None),
        "slow_down" => {
            *interval = interval
                .checked_add(5)
                .context("Google polling interval overflow")?;
            Ok(None)
        }
        "access_denied" => bail!("Google authorization was denied"),
        "expired_token" => bail!("Google device authorization expired"),
        _ => bail!("Google device authorization failed"),
    }
}

pub struct Google {
    client: Client,
}

impl Google {
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

    pub fn authorize(
        &self,
        credentials: OAuthClient,
        prompt: impl FnOnce(&str, &str),
    ) -> Result<Grant> {
        #[derive(Deserialize)]
        struct Device {
            device_code: Secret,
            user_code: String,
            verification_url: String,
            interval: u64,
            expires_in: u64,
        }
        credentials.validate()?;
        let response = self
            .client
            .post(DEVICE)
            .form(&[
                ("client_id", credentials.client_id.as_str()),
                ("scope", "https://www.googleapis.com/auth/drive.file"),
            ])
            .send()
            .map_err(|_| anyhow::anyhow!("Google device authorization unavailable"))?;
        ensure!(
            response.status().is_success(),
            "Google device authorization failed (HTTP {})",
            response.status().as_u16()
        );
        let device: Device = document(response)?;
        let url = valid_verification_url(&device.verification_url)
            .context("invalid Google device authorization response")?;
        ensure!(
            !device.device_code.0.is_empty()
                && valid_user_code(&device.user_code)
                && (1..=60).contains(&device.interval)
                && (1..=3600).contains(&device.expires_in),
            "invalid Google device authorization response"
        );
        prompt(url.as_str(), &device.user_code);
        let deadline = Instant::now() + Duration::from_secs(device.expires_in);
        let mut interval = device.interval;
        loop {
            ensure!(
                Instant::now() + Duration::from_secs(interval) < deadline,
                "Google device authorization expired"
            );
            thread::sleep(Duration::from_secs(interval));
            let response = self
                .client
                .post(TOKEN)
                .form(&[
                    ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
                    ("client_id", &credentials.client_id),
                    ("client_secret", &credentials.client_secret.0),
                    ("device_code", &device.device_code.0),
                ])
                .send()
                .map_err(|_| anyhow::anyhow!("Google device polling unavailable"))?;
            let Some(tokens) = poll_response(response, &mut interval)? else {
                continue;
            };
            #[derive(Deserialize)]
            struct About {
                user: User,
            }
            #[derive(Deserialize)]
            struct User {
                #[serde(rename = "permissionId")]
                permission_id: String,
            }
            let response = self
                .client
                .get(ABOUT)
                .bearer_auth(&tokens.access_token.0)
                .send()
                .map_err(|_| anyhow::anyhow!("Google Drive account lookup unavailable"))?;
            ensure!(
                response.status().is_success(),
                "Google Drive account lookup failed (HTTP {})",
                response.status().as_u16()
            );
            let about: About = document(response)?;
            return into_grant(tokens, credentials, about.user.permission_id);
        }
    }
}

fn valid_user_code(value: &str) -> bool {
    !value.is_empty() && value.len() <= 64 && value.bytes().all(|b| (b' '..=b'~').contains(&b))
}

fn valid_verification_url(value: &str) -> Option<reqwest::Url> {
    if !value.bytes().all(|b| (b' '..=b'~').contains(&b)) {
        return None;
    }
    let (_, authority) = value.split_once("://")?;
    if authority.split(['/', '?', '#']).next()?.contains('@') {
        return None;
    }
    let url = reqwest::Url::parse(value).ok()?;
    (url.scheme() == "https"
        && url.username().is_empty()
        && url.password().is_none()
        && url
            .host_str()
            .is_some_and(|host| host == "google.com" || host.ends_with(".google.com")))
    .then_some(url)
}

fn into_grant(tokens: Tokens, credentials: OAuthClient, account_id: String) -> Result<Grant> {
    ensure!(
        tokens.expires_in > 60,
        "Google access token expires too soon"
    );
    let expires_at = tokens
        .expires_in
        .checked_mul(1000)
        .and_then(|ttl| now().ok()?.checked_add(ttl))
        .context("invalid Google token expiry")?;
    let grant = Grant {
        access_token: tokens.access_token,
        refresh_token: tokens
            .refresh_token
            .context("Google enrollment is missing a refresh token")?,
        expires_at,
        account_id,
        client: Some(credentials),
    };
    grant.validate()?;
    Ok(grant)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn polling_responses() {
        use std::{
            io::{Read, Write},
            net::TcpListener,
        };
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            for (status, body) in [
                ("400 Bad Request", r#"{"error":"authorization_pending"}"#),
                ("400 Bad Request", r#"{"error":"slow_down"}"#),
                (
                    "200 OK",
                    r#"{"access_token":"a","refresh_token":"r","expires_in":3600}"#,
                ),
                ("400 Bad Request", r#"{"error":"access_denied"}"#),
                ("400 Bad Request", r#"{"error":"expired_token"}"#),
            ] {
                let (mut socket, _) = listener.accept().unwrap();
                let mut request = [0; 2048];
                assert!(socket.read(&mut request).unwrap() > 0);
                write!(
                    socket,
                    "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
                .unwrap();
            }
        });
        let client = Client::new();
        let mut interval = 3;
        let mut response = || {
            poll_response(
                client
                    .post(format!("http://{address}/token"))
                    .send()
                    .unwrap(),
                &mut interval,
            )
        };
        assert!(response().unwrap().is_none());
        assert!(response().unwrap().is_none());
        assert!(response().unwrap().is_some());
        assert!(response().err().unwrap().to_string().contains("denied"));
        assert!(response().err().unwrap().to_string().contains("expired"));
        assert_eq!(interval, 8);
        server.join().unwrap();
    }

    #[test]
    fn verification_urls_and_codes() {
        for url in [
            "https://google.com/device",
            "https://accounts.google.com/new?x=1",
        ] {
            assert!(valid_verification_url(url).is_some());
        }
        assert!(valid_user_code("AB CD+12"));
        for code in ["", "a\nb", "é", &"a".repeat(65)] {
            assert!(!valid_user_code(code));
        }
        for url in [
            "http://google.com",
            "https://evilgoogle.com",
            "https://google.com.evil.test",
            "https://@google.com",
            "https://user@google.com",
            "https://user:pass@google.com",
            "https://google.com/\r\ndevice",
        ] {
            assert!(valid_verification_url(url).is_none());
        }
    }
}
