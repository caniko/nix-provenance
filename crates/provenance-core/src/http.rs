//! Blocking HTTP helpers shared by the reconcilers.

use std::time::Duration;

use anyhow::{Context, Result, bail};
use reqwest::StatusCode;
use reqwest::blocking::{Client, Response};
use serde::de::DeserializeOwned;

/// Build a blocking reqwest client with a user agent and optional request
/// timeout.
///
/// This crate declares no TLS feature on `reqwest`, so the TLS backend is
/// whatever the *calling* crate enabled (`rustls-tls` vs
/// `rustls-tls-native-roots`) — features unify additively within a single
/// binary's build, so the leaf crate's choice wins and core never links openssl.
///
/// # Errors
///
/// Returns an error when the underlying [`Client`] builder rejects the supplied
/// configuration, such as an invalid user agent header value.
pub fn build_blocking_client(
    user_agent: &str,
    accept_invalid_certs: bool,
    timeout: Option<Duration>,
) -> Result<Client> {
    let mut builder = Client::builder()
        .danger_accept_invalid_certs(accept_invalid_certs)
        .user_agent(user_agent);
    if let Some(timeout) = timeout {
        builder = builder.timeout(timeout);
    }
    builder.build().context("building HTTP client")
}

/// Return the response unchanged if it is 2xx, otherwise an error carrying the
/// status and response body (with a dedicated message for 401 Unauthorized).
///
/// # Errors
///
/// Returns an error for every non-success HTTP status. If reading the response
/// body fails, the status is still reported and the body text is omitted.
pub fn ensure_success(resp: Response) -> Result<Response> {
    let status = resp.status();
    if status.is_success() {
        return Ok(resp);
    }
    let body = resp.text().unwrap_or_default();
    if status == StatusCode::UNAUTHORIZED {
        bail!("request was unauthorized ({status}); the credential was rejected: {body}");
    }
    bail!("request failed with HTTP {status}: {body}");
}

/// Decode a 2xx JSON response into `T`, attributing failures to `context`.
///
/// # Errors
///
/// Returns an error when [`ensure_success`] rejects the status or when the
/// response body cannot be decoded as `T`.
pub fn json_ok<T: DeserializeOwned>(resp: Response, context: &str) -> Result<T> {
    let resp = ensure_success(resp).with_context(|| format!("{context} request failed"))?;
    resp.json()
        .with_context(|| format!("decoding {context} response"))
}
