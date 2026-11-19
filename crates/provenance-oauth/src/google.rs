//! Google authorization. Endpoints are fixed to avoid credential redirection.
use crate::{Grant, OAuthClient, Secret, Target, now};
use anyhow::{Context, Result, bail, ensure};
use reqwest::blocking::{Client, Response};
use serde::{Deserialize, Serialize};
use std::{
    io::{Read, Write},
    thread,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

const TOKEN: &str = "https://oauth2.googleapis.com/token";
const DEVICE: &str = "https://oauth2.googleapis.com/device/code";
const ABOUT: &str = "https://www.googleapis.com/drive/v3/about?fields=user(permissionId)";
const USERINFO: &str = "https://openidconnect.googleapis.com/v1/userinfo";

#[derive(Deserialize, Serialize)]
struct AgyToken {
    client_id: String,
    client_secret: Secret,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    project_id: Option<String>,
    refresh_token: Secret,
    scopes: Vec<String>,
    #[serde(default = "google_token_uri")]
    token_uri: String,
}

fn google_token_uri() -> String {
    TOKEN.into()
}

fn parse_agy_token(bytes: &[u8]) -> Result<Grant> {
    let token: AgyToken = serde_json::from_slice(bytes)
        .map_err(|_| anyhow::anyhow!("invalid Antigravity token JSON"))?;
    ensure!(token.token_uri == TOKEN, "invalid Antigravity token_uri");
    let grant = Grant {
        access_token: Secret::default(),
        refresh_token: token.refresh_token,
        expires_at: 0,
        account_id: String::new(),
        client: Some(OAuthClient {
            client_id: token.client_id,
            client_secret: token.client_secret,
        }),
        project_id: token.project_id,
        scopes: Some(token.scopes),
    };
    grant.validate_antigravity_credentials()?;
    Ok(grant)
}

pub fn write_agy_token(grant: Grant, output: impl Write) -> Result<()> {
    let client = grant
        .client
        .context("Google grant is missing client credentials")?;
    let token = AgyToken {
        client_id: client.client_id,
        client_secret: client.client_secret,
        project_id: grant.project_id,
        refresh_token: grant.refresh_token,
        scopes: grant
            .scopes
            .context("Antigravity grant is missing scopes")?,
        token_uri: google_token_uri(),
    };
    serde_json::to_writer(output, &token)?;
    Ok(())
}

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

    pub fn authorize_antigravity(&self, bytes: &[u8], target: &Target) -> Result<Grant> {
        self.import_antigravity(bytes, target, TOKEN, USERINFO)
    }

    fn import_antigravity(
        &self,
        bytes: &[u8],
        target: &Target,
        token_endpoint: &str,
        userinfo_endpoint: &str,
    ) -> Result<Grant> {
        ensure!(
            target.provider == "google" && target.profile == "antigravity",
            "token import requires google/antigravity"
        );
        let mut grant = parse_agy_token(bytes)?;
        let client = grant
            .client
            .as_ref()
            .context("Google grant is missing client credentials")?;
        let response = self
            .client
            .post(token_endpoint)
            .form(&[
                ("grant_type", "refresh_token"),
                ("client_id", client.client_id.as_str()),
                ("client_secret", &client.client_secret.0),
                ("refresh_token", &grant.refresh_token.0),
            ])
            .send()
            .map_err(|_| anyhow::anyhow!("Antigravity Google token exchange unavailable"))?;
        ensure!(
            response.status().is_success(),
            "Antigravity Google token exchange failed (HTTP {})",
            response.status().as_u16()
        );
        #[derive(Deserialize)]
        struct Refreshed {
            access_token: Secret,
            #[serde(default)]
            scope: String,
        }
        let tokens: Refreshed = document(response)?;
        ensure!(
            !tokens.access_token.is_empty(),
            "Google token exchange did not return an access token"
        );
        // The file's scopes are a claim; the exchange reports what Google granted.
        ensure!(
            tokens
                .scope
                .split(' ')
                .any(|scope| scope == "https://www.googleapis.com/auth/cloud-platform"),
            "Antigravity Google grant lacks the cloud-platform scope"
        );
        let response = self
            .client
            .get(userinfo_endpoint)
            .bearer_auth(&tokens.access_token.0)
            .send()
            .map_err(|_| anyhow::anyhow!("Antigravity Google account lookup unavailable"))?;
        ensure!(
            response.status().is_success(),
            "Antigravity Google account lookup failed (HTTP {})",
            response.status().as_u16()
        );
        #[derive(Deserialize)]
        struct UserInfo {
            sub: String,
        }
        grant.account_id = document::<UserInfo>(response)?.sub;
        grant.scopes = Some(tokens.scope.split_whitespace().map(str::to_owned).collect());
        grant.validate_for(target)?;
        Ok(grant)
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
        project_id: None,
        scopes: None,
    };
    grant.validate()?;
    Ok(grant)
}

#[cfg(test)]
mod tests {
    use super::*;

    const AGY: &str = r#"{
        "client_id":"123.apps.googleusercontent.com",
        "client_secret":"fixture-secret",
        "project_id":"fixture-project",
        "refresh_token":"1//fixture-refresh",
        "scopes":["https://www.googleapis.com/auth/cloud-platform","https://www.googleapis.com/auth/userinfo.email","https://www.googleapis.com/auth/aicode"]
    }"#;

    #[test]
    fn validates_agy_token_fields() {
        let fixture: serde_json::Value = serde_json::from_str(AGY).unwrap();
        assert!(parse_agy_token(AGY.as_bytes()).is_ok());
        for (key, value) in [
            ("refresh_token", serde_json::Value::Null),
            ("refresh_token", "".into()),
            ("refresh_token", "1//bad\n".into()),
            ("refresh_token", "a".repeat(513).into()),
            ("client_id", "bad.example.com".into()),
            ("client_secret", "%unsafe".into()),
            ("token_uri", "https://example.com/token".into()),
            (
                "scopes",
                serde_json::json!(["https://www.googleapis.com/auth/userinfo.email"]),
            ),
        ] {
            let mut invalid = fixture.clone();
            if value.is_null() {
                invalid.as_object_mut().unwrap().remove(key);
            } else {
                invalid[key] = value;
            }
            assert!(
                parse_agy_token(&serde_json::to_vec(&invalid).unwrap()).is_err(),
                "accepted invalid {key}"
            );
        }
    }

    #[test]
    fn agy_import_verifies_subject_without_storing_access() {
        use std::{
            io::{BufRead, BufReader},
            net::TcpListener,
        };

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let granted = r#"{"access_token":"fixture-access","scope":"https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/cloud-platform"}"#;
            let userinfo = ("GET /userinfo", r#"{"sub":"1234"}"#);
            {
                for (path, body) in [
                    ("POST /token", granted),
                    userinfo,
                    ("POST /token", granted),
                    userinfo,
                    // The file claims cloud-platform; Google granted less.
                    (
                        "POST /token",
                        r#"{"access_token":"fixture-access","scope":"https://www.googleapis.com/auth/userinfo.email"}"#,
                    ),
                ] {
                    let (mut socket, _) = listener.accept().unwrap();
                    socket
                        .set_read_timeout(Some(Duration::from_secs(5)))
                        .unwrap();
                    let mut request = BufReader::new(&mut socket);
                    let mut line = String::new();
                    request.read_line(&mut line).unwrap();
                    assert!(line.starts_with(path));
                    let mut length = 0;
                    let mut authorized = false;
                    loop {
                        line.clear();
                        assert_ne!(request.read_line(&mut line).unwrap(), 0);
                        if line == "\r\n" {
                            break;
                        }
                        if let Some((name, value)) = line.trim_end().split_once(": ") {
                            if name.eq_ignore_ascii_case("content-length") {
                                length = value.parse().unwrap();
                            }
                            if name.eq_ignore_ascii_case("authorization") {
                                authorized = value == "Bearer fixture-access";
                            }
                        }
                    }
                    if path == "POST /token" {
                        let mut bytes = vec![0; length];
                        request.read_exact(&mut bytes).unwrap();
                        let form = String::from_utf8(bytes).unwrap();
                        assert_eq!(
                            form,
                            "grant_type=refresh_token&client_id=123.apps.googleusercontent.com&client_secret=fixture-secret&refresh_token=1%2F%2Ffixture-refresh"
                        );
                    } else {
                        assert!(authorized);
                    }
                    write!(
                        socket,
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    )
                    .unwrap();
                }
            }
        });
        let google = Google {
            client: Client::builder()
                .no_proxy()
                .timeout(Duration::from_secs(5))
                .build()
                .unwrap(),
        };
        let mut target = Target {
            host: "host".into(),
            user: "user".into(),
            provider: "google".into(),
            profile: "antigravity".into(),
            account: "1234".into(),
        };
        let import = |target: &Target| {
            google.import_antigravity(
                AGY.as_bytes(),
                target,
                &format!("http://{address}/token"),
                &format!("http://{address}/userinfo"),
            )
        };
        let grant = import(&target).unwrap();
        assert_eq!(grant.account_id, "1234");
        assert!(
            serde_json::to_value(&grant)
                .unwrap()
                .get("accessToken")
                .is_none()
        );
        let mut output = Vec::new();
        write_agy_token(grant, &mut output).unwrap();
        let mut expected: serde_json::Value = serde_json::from_str(AGY).unwrap();
        expected["token_uri"] = TOKEN.into();
        // The scopes Google granted, not the file's claim.
        expected["scopes"] = serde_json::json!([
            "https://www.googleapis.com/auth/userinfo.email",
            "https://www.googleapis.com/auth/cloud-platform"
        ]);
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&output).unwrap(),
            expected
        );
        target.account = "different-subject".into();
        assert!(
            import(&target)
                .unwrap_err()
                .to_string()
                .contains("does not match the manifest account")
        );
        target.account = "1234".into();
        assert!(
            import(&target)
                .unwrap_err()
                .to_string()
                .contains("lacks the cloud-platform scope")
        );
        server.join().unwrap();
    }

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
