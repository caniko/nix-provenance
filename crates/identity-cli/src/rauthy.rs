//! Rauthy email-credential helpers for the identity CLI.
//!
//! The third-party adapter (`services.provenance.externalApps`) and
//! `services.rauthy.provision` provision some users with an emailed set-password
//! link (`passwordInitByEmail` / `sendPasswordEmail = true`). That email is sent
//! exactly once, on user creation — so there is no declarative way to *resend*
//! it to a user who already exists (e.g. their link expired, or never arrived).
//!
//! These helpers close that gap: list every email-derived user as defined in a
//! rauthy-provision state file, and (re)send any of them a fresh set-password
//! link via Rauthy's unauthenticated `request_reset` flow (the same flow the
//! reconciler drives on creation), so the operation is ergonomic and repeatable.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, Result, anyhow, bail};
use serde::Deserialize;

/// Subset of the rauthy-provision state schema we need: the users map (keyed by
/// email) with just the email-credential fields. Unknown fields are ignored so
/// this stays forward-compatible with the full schema in `rauthy-provision`.
#[derive(Debug, Deserialize)]
struct State {
    #[serde(default)]
    users: BTreeMap<String, UserSpec>,
}

#[derive(Debug, Deserialize)]
struct UserSpec {
    #[serde(default)]
    given_name: Option<String>,
    #[serde(default)]
    family_name: Option<String>,
    #[serde(default)]
    send_password_email: bool,
    #[serde(default)]
    password_email_redirect_uri: Option<String>,
}

/// An email-derived user: one provisioned with `send_password_email = true`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmailUser {
    /// Primary email — the Rauthy user key and where the link is sent.
    pub email: String,
    /// Human display name (`given [family]`), if the spec carried one.
    pub name: Option<String>,
    /// Where Rauthy lands the user after they set their password.
    pub redirect_uri: Option<String>,
}

impl UserSpec {
    fn display_name(&self) -> Option<String> {
        match (&self.given_name, &self.family_name) {
            (Some(g), Some(f)) => Some(format!("{g} {f}")),
            (Some(g), None) => Some(g.clone()),
            _ => None,
        }
    }
}

fn read_state(path: &Path) -> Result<State> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("reading rauthy provision state {}", path.display()))?;
    serde_json::from_str(&raw)
        .with_context(|| format!("parsing rauthy provision state {}", path.display()))
}

/// Every user provisioned with an emailed set-password link, sorted by email.
pub fn email_users(path: &Path) -> Result<Vec<EmailUser>> {
    let state = read_state(path)?;
    Ok(state
        .users
        .into_iter()
        .filter(|(_, u)| u.send_password_email)
        .map(|(email, u)| EmailUser {
            name: u.display_name(),
            redirect_uri: u.password_email_redirect_uri,
            email,
        })
        .collect())
}

/// Whether `id` identifies `user`: exact email, the email local-part, or the
/// (case-insensitive) display name or its first (given-name) word.
fn matches(user: &EmailUser, id: &str) -> bool {
    let id = id.trim();
    if user.email.eq_ignore_ascii_case(id) {
        return true;
    }
    if user
        .email
        .split('@')
        .next()
        .is_some_and(|local| local.eq_ignore_ascii_case(id))
    {
        return true;
    }
    if let Some(name) = &user.name {
        if name.eq_ignore_ascii_case(id) {
            return true;
        }
        if name
            .split_whitespace()
            .next()
            .is_some_and(|given| given.eq_ignore_ascii_case(id))
        {
            return true;
        }
    }
    false
}

/// Resolve a free-form identifier to exactly one email-derived user, erroring
/// helpfully when there is no match or the identifier is ambiguous.
pub fn find_user(path: &Path, identifier: &str) -> Result<EmailUser> {
    let mut matched: Vec<EmailUser> = email_users(path)?
        .into_iter()
        .filter(|u| matches(u, identifier))
        .collect();
    match matched.len() {
        0 => bail!(
            "no email-derived user matches '{identifier}' in {}. \
             Run `identity-cli rauthy list-email-users` to see candidates.",
            path.display()
        ),
        1 => Ok(matched.remove(0)),
        _ => {
            let emails: Vec<&str> = matched.iter().map(|u| u.email.as_str()).collect();
            bail!(
                "'{identifier}' is ambiguous between {}; use the full email address.",
                emails.join(", ")
            )
        }
    }
}

/// (Re)send `user` a set-password / reset link via Rauthy's `request_reset`
/// flow. This endpoint is unauthenticated and Proof-of-Work gated: fetch a
/// challenge from `/pow`, solve it locally, then POST it with the email and
/// redirect. Rauthy always answers 200 (username-enumeration safety), so a
/// success here does not prove delivery — confirm via the Rauthy / mail-server
/// logs. Mirrors `rauthy-provision`'s `request_password_reset`.
pub async fn reset_password(base_url: &str, user: &EmailUser) -> Result<()> {
    let redirect = user.redirect_uri.as_deref().ok_or_else(|| {
        anyhow!(
            "user {} has send_password_email but no password_email_redirect_uri in the state",
            user.email
        )
    })?;
    let api = format!("{}/auth/v1", base_url.trim_end_matches('/'));
    let http = reqwest::Client::builder()
        .user_agent(concat!("identity-cli/", env!("CARGO_PKG_VERSION")))
        .build()
        .context("building HTTP client")?;

    // 1. Fetch a PoW challenge (unauthenticated, plain-text body).
    let challenge = http
        .post(format!("{api}/pow"))
        .send()
        .await
        .context("requesting PoW challenge")?
        .error_for_status()
        .context("PoW challenge request failed")?
        .text()
        .await
        .context("reading PoW challenge body")?;

    // 2. Solve it locally (CPU-bound; spow parses the difficulty from the body).
    let pow = tokio::task::spawn_blocking(move || {
        spow::pow::Pow::work(&challenge).map_err(|e| anyhow!("solving PoW challenge: {e}"))
    })
    .await
    .context("joining PoW solver task")??;

    // 3. POST request_reset (no auth header; email + redirect + solved PoW).
    #[derive(serde::Serialize)]
    struct RequestReset<'a> {
        email: &'a str,
        redirect_uri: &'a str,
        pow: &'a str,
    }
    http.post(format!("{api}/users/request_reset"))
        .json(&RequestReset {
            email: &user.email,
            redirect_uri: redirect,
            pow: &pow,
        })
        .send()
        .await
        .context("posting request_reset")?
        .error_for_status()
        .context("request_reset failed")?;
    Ok(())
}

pub fn api_key_from_file(path: &Path) -> Result<String> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("reading Rauthy API key file {}", path.display()))?;
    let key = raw.trim().to_owned();
    if key.is_empty() {
        bail!("Rauthy API key file {} is empty", path.display());
    }
    Ok(key)
}

pub(crate) fn require_confirmed_email(user: &EmailUser, confirm: &str) -> Result<()> {
    if confirm.trim().eq_ignore_ascii_case(&user.email) {
        return Ok(());
    }
    bail!(
        "confirmation email does not match {}; pass --confirm with that exact address",
        user.email
    )
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

fn api_base(base_url: &str) -> String {
    format!("{}/auth/v1", base_url.trim_end_matches('/'))
}

fn http_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .user_agent(concat!("identity-cli/", env!("CARGO_PKG_VERSION")))
        .build()
        .context("building HTTP client")
}

async fn fetch_passkeys(
    base_url: &str,
    api_key: &str,
    email: &str,
) -> Result<(String, Vec<String>)> {
    let api = api_base(base_url);
    let http = http_client()?;
    let auth = format!("API-Key {api_key}");

    #[derive(Deserialize)]
    struct UserId {
        id: String,
    }
    let user: UserId = http
        .get(format!("{api}/users/email/{}", percent_encode(email)))
        .header(reqwest::header::AUTHORIZATION, &auth)
        .send()
        .await
        .context("looking up Rauthy user")?
        .error_for_status()
        .context("looking up Rauthy user")?
        .json()
        .await
        .context("decoding Rauthy user")?;

    #[derive(Deserialize)]
    struct Passkey {
        name: String,
    }
    let passkeys: Vec<Passkey> = http
        .get(format!("{api}/users/{}/webauthn", percent_encode(&user.id)))
        .header(reqwest::header::AUTHORIZATION, &auth)
        .send()
        .await
        .context("listing Rauthy passkeys")?
        .error_for_status()
        .context("listing Rauthy passkeys")?
        .json()
        .await
        .context("decoding Rauthy passkeys")?;
    Ok((
        user.id,
        passkeys.into_iter().map(|passkey| passkey.name).collect(),
    ))
}

pub async fn list_passkeys(base_url: &str, api_key: &str, user: &EmailUser) -> Result<Vec<String>> {
    Ok(fetch_passkeys(base_url, api_key, &user.email).await?.1)
}

pub async fn reset_passkeys(
    base_url: &str,
    api_key: &str,
    user: &EmailUser,
    confirm: &str,
) -> Result<Vec<String>> {
    require_confirmed_email(user, confirm)?;
    let api = api_base(base_url);
    let http = http_client()?;
    let auth = format!("API-Key {api_key}");
    let (id, names) = fetch_passkeys(base_url, api_key, &user.email).await?;
    for name in &names {
        http.delete(format!(
            "{api}/users/{}/webauthn/delete/{}",
            percent_encode(&id),
            percent_encode(name)
        ))
        .header(reqwest::header::AUTHORIZATION, &auth)
        .json(&serde_json::json!({}))
        .send()
        .await
        .with_context(|| format!("deleting Rauthy passkey {name}"))?
        .error_for_status()
        .with_context(|| format!("deleting Rauthy passkey {name}"))?;
    }
    Ok(names)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    /// A temp state file with a per-test-unique name (cargo runs tests in
    /// parallel), removed on drop. No external dev-dependency.
    struct TempState(std::path::PathBuf);
    impl Drop for TempState {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    fn write_state(label: &str, json: &str) -> TempState {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "identity-cli-rauthy-{}-{label}.json",
            std::process::id()
        ));
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(json.as_bytes()).unwrap();
        TempState(path)
    }

    const STATE: &str = r#"{
      "users": {
        "can@tartanoglu.com":     { "send_password_email": false, "given_name": "Can" },
        "efirley@protonmail.com":  { "send_password_email": true, "given_name": "Eric",
                                     "password_email_redirect_uri": "https://raven.tartanoglu.com/login" },
        "carolinestahl@gmx.net":   { "send_password_email": true, "given_name": "Caroline",
                                     "password_email_redirect_uri": "https://raven.tartanoglu.com/login" }
      }
    }"#;

    #[test]
    fn lists_only_email_derived_users() {
        let t = write_state("list", STATE);
        let users = email_users(&t.0).unwrap();
        let emails: Vec<&str> = users.iter().map(|u| u.email.as_str()).collect();
        // can is excluded (kanidmLogin / send_password_email = false).
        assert_eq!(
            emails,
            vec!["carolinestahl@gmx.net", "efirley@protonmail.com"]
        );
    }

    #[test]
    fn matches_by_email_localpart_and_name() {
        let t = write_state("match", STATE);
        // exact email
        assert_eq!(
            find_user(&t.0, "efirley@protonmail.com")
                .unwrap()
                .name
                .as_deref(),
            Some("Eric")
        );
        // email local-part
        assert_eq!(
            find_user(&t.0, "carolinestahl").unwrap().name.as_deref(),
            Some("Caroline")
        );
        // given name, case-insensitive
        assert_eq!(
            find_user(&t.0, "eric").unwrap().email,
            "efirley@protonmail.com"
        );
        // non-email-derived user is not resettable
        assert!(find_user(&t.0, "can").is_err());
        // unknown identifier
        assert!(find_user(&t.0, "nobody").is_err());
    }

    #[tokio::test]
    async fn passkeys_mock_auth_encode_list_delete_and_confirm_mismatch() {
        use std::io::{BufRead, BufReader, Read, Write};
        use std::net::{TcpListener, TcpStream};
        use std::sync::{Arc, Mutex};
        use std::thread;

        struct Record {
            first: String,
            auth: String,
            body: String,
        }

        fn handle(mut stream: TcpStream, requests: &Arc<Mutex<Vec<Record>>>) {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut first = String::new();
            reader.read_line(&mut first).unwrap();
            let mut auth = String::new();
            let mut content_length = 0usize;
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                if line.is_empty() || line == "\n" || line == "\r\n" {
                    break;
                }
                let (name, value) = match line.split_once(':') {
                    Some(parts) => parts,
                    None => continue,
                };
                if name.eq_ignore_ascii_case("authorization") {
                    auth = value.trim().to_string();
                }
                if name.eq_ignore_ascii_case("content-length") {
                    content_length = value.trim().parse().unwrap_or(0);
                }
            }
            let mut body = vec![0; content_length];
            if content_length > 0 {
                reader.read_exact(&mut body).unwrap();
            }
            requests.lock().unwrap().push(Record {
                first: first.trim().to_string(),
                auth,
                body: String::from_utf8(body).unwrap(),
            });

            let path = first.split_whitespace().nth(1).unwrap_or("");
            let (status, body) = if path.contains("/users/email/") {
                ("200 OK", r#"{"id":"user-1","email":"foo+bar@example.com"}"#)
            } else if path.ends_with("/webauthn") {
                (
                    "200 OK",
                    r#"[{"name":"YubiKey 5","registered":1,"last_used":2},{"name":"iCloud Key","registered":1,"last_used":2}]"#,
                )
            } else {
                ("200 OK", "")
            };
            write!(
                stream,
                "HTTP/1.1 {status}\r\nContent-Length: {}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .unwrap();
        }

        let requests = Arc::new(Mutex::new(Vec::new()));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let recorded = requests.clone();
        thread::spawn(move || {
            for stream in listener.incoming().take(16) {
                handle(stream.unwrap(), &recorded);
            }
        });
        let base = format!("http://{addr}");

        let key_path = {
            let mut path = std::env::temp_dir();
            path.push(format!("identity-cli-rauthy-key-{}", std::process::id()));
            std::fs::write(&path, "  prov$key\n").unwrap();
            path
        };
        let api_key = api_key_from_file(&key_path).unwrap();
        assert_eq!(api_key, "prov$key");
        let _ = std::fs::remove_file(&key_path);

        let user = EmailUser {
            email: "foo+bar@example.com".into(),
            name: Some("Foo".into()),
            redirect_uri: None,
        };

        assert!(
            reset_passkeys(&base, &api_key, &user, "other@example.com")
                .await
                .is_err()
        );
        assert!(requests.lock().unwrap().is_empty());

        let names = list_passkeys(&base, &api_key, &user).await.unwrap();
        assert_eq!(names, vec!["YubiKey 5", "iCloud Key"]);

        let deleted = reset_passkeys(&base, &api_key, &user, "FOO+BAR@EXAMPLE.COM")
            .await
            .unwrap();
        assert_eq!(deleted, vec!["YubiKey 5", "iCloud Key"]);

        let recs = requests.lock().unwrap();
        assert!(recs.iter().all(|r| r.auth == "API-Key prov$key"));
        assert!(recs.iter().any(|r| {
            r.first
                .starts_with("GET /auth/v1/users/email/foo%2Bbar%40example.com ")
        }));
        assert!(
            recs.iter()
                .any(|r| r.first.starts_with("GET /auth/v1/users/user-1/webauthn "))
        );
        assert!(recs.iter().any(|r| {
            r.first
                .starts_with("DELETE /auth/v1/users/user-1/webauthn/delete/YubiKey%205 ")
                && r.body == "{}"
        }));
        assert!(recs.iter().any(|r| {
            r.first
                .starts_with("DELETE /auth/v1/users/user-1/webauthn/delete/iCloud%20Key ")
                && r.body == "{}"
        }));
    }
}
