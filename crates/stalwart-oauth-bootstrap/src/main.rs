//! Bootstrap a Stalwart OAuth refresh token without opening a browser.
//!
//! Stalwart's management API accepts the account secret and PKCE parameters at
//! `/api/auth`, then returns a one-use authorization code. This binary exchanges
//! that code at the discovered OAuth token endpoint and stores only the refresh
//! token in the user's Secret Service keyring.

use std::fs;
use std::path::PathBuf;
use std::process;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use clap::Parser;
use keyring::{Entry, Error as KeyringError};
use rand::RngCore;
use reqwest::Url;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

const USER_AGENT: &str = concat!("stalwart-oauth-bootstrap/", env!("CARGO_PKG_VERSION"));

/// Exit marker for failures that should not be retried by systemd.
#[derive(Debug)]
struct Permanent(String);

impl std::fmt::Display for Permanent {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for Permanent {}

/// Command-line configuration. The password is always read from a file, never
/// passed as an argument or environment variable.
#[derive(Debug, Parser)]
#[command(
    name = "stalwart-oauth-bootstrap",
    about = "Bootstrap a Stalwart OAuth refresh token into Secret Service",
    version
)]
struct Cli {
    /// Stalwart issuer URL, for example https://mail.example.com.
    #[arg(long)]
    issuer: String,

    /// Stalwart account name or email address.
    #[arg(long)]
    account_name: String,

    /// File containing the account password.
    #[arg(long)]
    password_file: PathBuf,

    /// Pre-registered public OAuth client identifier.
    #[arg(long)]
    client_id: String,

    /// Exact redirect URI registered for the public client.
    #[arg(long)]
    redirect_uri: String,

    /// RFC 6749/RFC 8707 scope string.
    #[arg(long, default_value = "urn:ietf:params:oauth:scope:mail")]
    scope: String,

    /// RFC 8707 protected-resource URL.
    #[arg(long)]
    resource: String,

    /// Secret Service service attribute.
    #[arg(long)]
    keyring_service: String,

    /// Secret Service username attribute.
    #[arg(long)]
    keyring_username: String,
}

#[derive(Debug, Clone)]
struct Config {
    issuer: Url,
    account_name: String,
    password_file: PathBuf,
    client_id: String,
    redirect_uri: String,
    scope: String,
    resource: String,
    keyring_service: String,
    keyring_username: String,
}

impl Config {
    fn from_cli(cli: Cli) -> Result<Self> {
        let issuer = Url::parse(cli.issuer.trim())
            .map_err(|error| permanent(format!("parsing Stalwart issuer URL: {error}")))?;
        validate_transport_url(&issuer, "issuer")?;

        for (name, value) in [
            ("account name", cli.account_name.as_str()),
            ("client id", cli.client_id.as_str()),
            ("redirect URI", cli.redirect_uri.as_str()),
            ("scope", cli.scope.as_str()),
            ("resource", cli.resource.as_str()),
            ("keyring service", cli.keyring_service.as_str()),
            ("keyring username", cli.keyring_username.as_str()),
        ] {
            if value.trim().is_empty() {
                return Err(permanent(format!("{name} must not be empty")));
            }
        }

        Ok(Self {
            issuer,
            account_name: cli.account_name,
            password_file: cli.password_file,
            client_id: cli.client_id,
            redirect_uri: cli.redirect_uri,
            scope: cli.scope,
            resource: cli.resource,
            keyring_service: cli.keyring_service,
            keyring_username: cli.keyring_username,
        })
    }
}

#[derive(Debug, Deserialize)]
struct OAuthMetadata {
    issuer: String,
    token_endpoint: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AuthCodeRequest<'a> {
    #[serde(rename = "type")]
    request_type: &'static str,
    account_name: &'a str,
    account_secret: &'a str,
    client_id: &'a str,
    redirect_uri: &'a str,
    scope: &'a str,
    code_challenge: &'a str,
    code_challenge_method: &'static str,
    resource: [&'a str; 1],
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
enum AuthCodeResponse {
    Authenticated { client_code: String, iss: String },
    MfaRequired,
    Failure,
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    #[serde(rename = "access_token")]
    _access_token: String,
    refresh_token: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
struct OAuthErrorResponse {
    error: Option<String>,
}

#[derive(Debug)]
enum RefreshError {
    InvalidGrant,
    Other(anyhow::Error),
}

impl std::fmt::Display for RefreshError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidGrant => formatter.write_str("Stalwart rejected the refresh token"),
            Self::Other(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for RefreshError {}

fn main() {
    let result = Config::from_cli(Cli::parse()).and_then(|config| run(&config));

    if let Err(error) = result {
        let permanent = error.downcast_ref::<Permanent>().is_some();
        eprintln!("stalwart-oauth-bootstrap: {error}");
        process::exit(if permanent { 2 } else { 1 });
    }
}

fn run(config: &Config) -> Result<()> {
    let client = provenance_core::http::build_blocking_client(
        USER_AGENT,
        false,
        Some(Duration::from_secs(30)),
    )?;
    let metadata = discover_metadata(&client, config)?;
    let entry = Entry::new(&config.keyring_service, &config.keyring_username)
        .context("creating Secret Service entry")?;

    match entry.get_password() {
        Ok(token) if !token.is_empty() => {
            let token = Zeroizing::new(token);
            match refresh_token(&client, &metadata.token_endpoint, config, &token) {
                Ok(tokens) => {
                    store_refresh_token(&entry, tokens.refresh_token.as_deref(), &token)?;
                    eprintln!("existing Stalwart OAuth token is valid");
                    return Ok(());
                }
                Err(RefreshError::InvalidGrant) => {
                    eprintln!("existing Stalwart OAuth token is invalid; bootstrapping again");
                }
                Err(RefreshError::Other(error)) => return Err(error),
            }
        }
        Ok(_) | Err(KeyringError::NoEntry) => {}
        Err(error) => return Err(anyhow!("reading Secret Service entry: {error}")),
    }

    let password = read_password(&config.password_file)?;
    let refresh_token = bootstrap_token(&client, &metadata, config, &password)?;
    entry
        .set_password(&refresh_token)
        .context("storing Stalwart OAuth refresh token in Secret Service")?;
    eprintln!("Stalwart OAuth refresh token bootstrapped");
    Ok(())
}

fn discover_metadata(client: &reqwest::blocking::Client, config: &Config) -> Result<OAuthMetadata> {
    let issuer = config.issuer.as_str().trim_end_matches('/');
    let url = format!("{issuer}/.well-known/oauth-authorization-server");
    let response = client
        .get(url)
        .send()
        .context("discovering Stalwart OAuth metadata")?;
    let status = response.status();
    if !status.is_success() {
        return Err(anyhow!("Stalwart OAuth metadata returned HTTP {status}"));
    }
    let metadata: OAuthMetadata = response
        .json()
        .context("decoding Stalwart OAuth metadata")?;
    let metadata_issuer = Url::parse(&metadata.issuer).map_err(|error| {
        permanent(format!("parsing Stalwart OAuth metadata issuer: {error}"))
    })?;
    validate_transport_url(&metadata_issuer, "metadata issuer")?;
    if metadata_issuer.as_str().trim_end_matches('/')
        != config.issuer.as_str().trim_end_matches('/')
    {
        return Err(permanent(
            "Stalwart OAuth metadata issuer does not match configured issuer",
        ));
    }
    let token_endpoint = Url::parse(&metadata.token_endpoint).map_err(|error| {
        permanent(format!("parsing discovered Stalwart token endpoint: {error}"))
    })?;
    validate_endpoint(&token_endpoint, config)?;
    Ok(metadata)
}

fn validate_endpoint(endpoint: &Url, config: &Config) -> Result<()> {
    validate_transport_url(endpoint, "discovered Stalwart token endpoint")?;
    if endpoint.host_str() != config.issuer.host_str()
        || endpoint.port_or_known_default() != config.issuer.port_or_known_default()
    {
        return Err(permanent(
            "discovered Stalwart token endpoint does not belong to the configured issuer",
        ));
    }
    Ok(())
}

fn validate_transport_url(url: &Url, label: &str) -> Result<()> {
    let loopback = matches!(url.host_str(), Some("127.0.0.1" | "localhost" | "::1"));
    if url.host_str().is_none() {
        return Err(permanent(format!("{label} must include a host")));
    }
    if url.scheme() != "https" && !(url.scheme() == "http" && loopback) {
        return Err(permanent(format!(
            "{label} must use HTTPS (HTTP is allowed only for loopback tests)"
        )));
    }
    if url.username() != ""
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(permanent(format!(
            "{label} contains disallowed URL credentials or components"
        )));
    }
    Ok(())
}

fn refresh_token(
    client: &reqwest::blocking::Client,
    token_endpoint: &str,
    config: &Config,
    refresh_token: &str,
) -> std::result::Result<TokenResponse, RefreshError> {
    let response = client
        .post(token_endpoint)
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
            ("client_id", config.client_id.as_str()),
            ("scope", config.scope.as_str()),
            ("resource", config.resource.as_str()),
        ])
        .send()
        .map_err(|error| {
            RefreshError::Other(anyhow!("refreshing Stalwart OAuth token: {error}"))
        })?;
    let status = response.status();
    if !status.is_success() {
        let error = response.json::<OAuthErrorResponse>().unwrap_or_default();
        if error.error.as_deref() == Some("invalid_grant") {
            return Err(RefreshError::InvalidGrant);
        }
        return Err(RefreshError::Other(anyhow!(
            "Stalwart OAuth refresh returned HTTP {status}"
        )));
    }
    response.json().map_err(|error| {
        RefreshError::Other(anyhow!("decoding Stalwart OAuth refresh response: {error}"))
    })
}

fn bootstrap_token(
    client: &reqwest::blocking::Client,
    metadata: &OAuthMetadata,
    config: &Config,
    password: &str,
) -> Result<String> {
    let (verifier, challenge) = pkce_pair();
    let auth_request = AuthCodeRequest {
        request_type: "authCode",
        account_name: &config.account_name,
        account_secret: password,
        client_id: &config.client_id,
        redirect_uri: &config.redirect_uri,
        scope: &config.scope,
        code_challenge: &challenge,
        code_challenge_method: "S256",
        resource: [&config.resource],
    };
    let issuer = config.issuer.as_str().trim_end_matches('/');
    let auth_url = format!("{issuer}/api/auth");
    let response = client
        .post(auth_url)
        .json(&auth_request)
        .send()
        .context("requesting Stalwart OAuth authorization code")?;
    let status = response.status();
    if !status.is_success() {
        return Err(permanent(format!(
            "Stalwart OAuth authorization returned HTTP {status}"
        )));
    }
    let response: AuthCodeResponse = response
        .json()
        .context("decoding Stalwart OAuth authorization response")?;
    let client_code = match response {
        AuthCodeResponse::Authenticated { client_code, iss } => {
            if iss.trim_end_matches('/') != metadata.issuer.trim_end_matches('/') {
                return Err(permanent(
                    "Stalwart authorization response issuer does not match metadata",
                ));
            }
            client_code
        }
        AuthCodeResponse::MfaRequired => {
            return Err(permanent(
                "Stalwart requires MFA; automatic OAuth bootstrap cannot continue",
            ));
        }
        AuthCodeResponse::Failure => {
            return Err(permanent(
                "Stalwart rejected the configured account credentials",
            ));
        }
    };

    let response = client
        .post(&metadata.token_endpoint)
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", client_code.as_str()),
            ("redirect_uri", config.redirect_uri.as_str()),
            ("client_id", config.client_id.as_str()),
            ("code_verifier", verifier.as_str()),
        ])
        .send()
        .context("exchanging Stalwart OAuth authorization code")?;
    let status = response.status();
    if !status.is_success() {
        return Err(anyhow!(
            "Stalwart OAuth code exchange returned HTTP {status}"
        ));
    }
    let tokens: TokenResponse = response
        .json()
        .context("decoding Stalwart OAuth token response")?;
    tokens
        .refresh_token
        .ok_or_else(|| permanent("Stalwart did not return an OAuth refresh token"))
}

fn store_refresh_token(entry: &Entry, replacement: Option<&str>, current: &str) -> Result<()> {
    if let Some(replacement) = replacement {
        entry
            .set_password(replacement)
            .context("storing rotated Stalwart OAuth refresh token")?;
    } else if current.is_empty() {
        bail!("Stalwart returned an empty OAuth refresh token");
    }
    Ok(())
}

fn read_password(path: &PathBuf) -> Result<Zeroizing<String>> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("reading Stalwart account password file {}", path.display()))?;
    let password = content.trim_end_matches(['\r', '\n']).to_owned();
    if password.is_empty() {
        return Err(permanent("Stalwart account password file is empty"));
    }
    Ok(Zeroizing::new(password))
}

fn pkce_pair() -> (String, String) {
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    let verifier = URL_SAFE_NO_PAD.encode(bytes);
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    (verifier, challenge)
}

fn permanent(message: impl Into<String>) -> anyhow::Error {
    anyhow::Error::new(Permanent(message.into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkce_matches_rfc7636_vector() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
        assert_eq!(challenge, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
    }

    #[test]
    fn config_rejects_non_https_non_loopback_issuer() {
        let result = Config::from_cli(Cli {
            issuer: "http://mail.example.test".into(),
            account_name: "can@example.test".into(),
            password_file: "/run/password".into(),
            client_id: "neverlight-mail".into(),
            redirect_uri: "http://127.0.0.1:49152/callback".into(),
            scope: "urn:ietf:params:oauth:scope:mail".into(),
            resource: "https://mail.example.test/jmap/session".into(),
            keyring_service: "neverlight-mail".into(),
            keyring_username: "oauth-refresh:can".into(),
        });
        assert!(result.is_err());
        assert!(result.unwrap_err().downcast_ref::<Permanent>().is_some());
    }

    #[test]
    fn discovered_endpoint_must_stay_on_the_issuer_origin() {
        let config = Config::from_cli(Cli {
            issuer: "https://mail.example.test".into(),
            account_name: "can@example.test".into(),
            password_file: "/run/password".into(),
            client_id: "neverlight-mail".into(),
            redirect_uri: "http://127.0.0.1:49152/callback".into(),
            scope: "urn:ietf:params:oauth:scope:mail".into(),
            resource: "https://mail.example.test/jmap/session".into(),
            keyring_service: "neverlight-mail".into(),
            keyring_username: "oauth-refresh:can".into(),
        })
        .unwrap();
        let endpoint = Url::parse("https://attacker.example.test/auth/token").unwrap();
        let error = validate_endpoint(&endpoint, &config).unwrap_err();
        assert!(error.downcast_ref::<Permanent>().is_some());
    }

    #[test]
    fn password_trimming_drops_only_line_endings() {
        let path =
            std::env::temp_dir().join(format!("stalwart-oauth-password-{}", std::process::id()));
        fs::write(&path, " secret with spaces \r\n").unwrap();
        assert_eq!(
            read_password(&path).unwrap().as_str(),
            " secret with spaces "
        );
        let _ = fs::remove_file(path);
    }
}
