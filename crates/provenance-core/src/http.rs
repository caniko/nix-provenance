//! Blocking HTTP helpers shared by the reconcilers.

use std::time::Duration;

use reqwest::blocking::{Client, Response};
use serde::de::DeserializeOwned;

use crate::{Error, Result};

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
    if user_agent.trim().is_empty() {
        return Err(Error::invalid("user_agent must not be empty"));
    }
    if let Some(d) = timeout
        && d.is_zero()
    {
        return Err(Error::invalid("timeout must be positive"));
    }
    let mut builder = Client::builder()
        .danger_accept_invalid_certs(accept_invalid_certs)
        .user_agent(user_agent);
    if let Some(timeout) = timeout {
        builder = builder.timeout(timeout);
    }
    builder
        .build()
        .map_err(|source| Error::http("building HTTP client", source))
}

/// Return the response unchanged if it is 2xx, otherwise an error carrying only
/// the status (with a dedicated message for 401 Unauthorized).
///
/// Response bodies are deliberately not included in the error: external
/// services may echo credentials, tokens, or personal data. Callers that need
/// a protocol-specific error code must parse the body themselves after checking
/// the status.
///
/// # Errors
///
/// Returns an error for every non-success HTTP status without exposing the
/// response body.
pub fn ensure_success(resp: Response) -> Result<Response> {
    let status = resp.status();
    if status.is_success() {
        return Ok(resp);
    }
    Err(Error::HttpStatus { status })
}

/// Decode a 2xx JSON response into `T`, attributing failures to `context`.
///
/// # Errors
///
/// Returns an error when [`ensure_success`] rejects the status or when the
/// response body cannot be decoded as `T`.
pub fn json_ok<T: DeserializeOwned>(resp: Response, context: &str) -> Result<T> {
    let resp = ensure_success(resp)?;
    resp.json()
        .map_err(|source| Error::http(format!("decoding {context} response"), source))
}
