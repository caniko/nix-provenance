//! n8n internal REST API with a cookie session (`/rest/login`).
//!
//! The public API (`/api/v1/credentials`) has no list operation in n8n 2.x,
//! and by-name upsert needs one, so the owner session is used instead; this
//! also avoids minting a long-lived API key.

use std::thread::sleep;
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, anyhow, bail};
use reqwest::blocking::Client;
use serde_json::{Value, json};

pub struct N8n {
    base: String,
    http: Client,
}

/// n8n wraps REST payloads as `{"data": ...}` (lists add `count`). A credential
/// carries its own `data` field, so only envelope-shaped objects are unwrapped.
fn unwrap_data(mut v: Value) -> Value {
    while let Some(inner) = v
        .as_object()
        .filter(|o| o.contains_key("data") && o.keys().all(|k| k == "data" || k == "count"))
        .and_then(|o| o.get("data"))
    {
        v = inner.clone();
    }
    v
}

/// Extract `(id, name)` pairs from a list payload (`[..]`, `{data:[..]}` or
/// `{count, data:[..]}`).
pub fn credential_index(v: Value) -> Vec<(String, String)> {
    let v = unwrap_data(v);
    v.as_array()
        .into_iter()
        .flatten()
        .filter_map(|c| Some((c["id"].as_str()?.to_owned(), c["name"].as_str()?.to_owned())))
        .collect()
}

impl N8n {
    pub fn new(base: &str) -> Result<Self> {
        let http = Client::builder()
            .cookie_store(true)
            .user_agent("n8n-provision")
            // Credentials travel over this client: never via an environment proxy.
            .no_proxy()
            .timeout(Duration::from_secs(30))
            .build()?;
        Ok(Self {
            base: base.trim_end_matches('/').to_owned(),
            http,
        })
    }

    pub fn wait_ready(&self, timeout: Duration) -> Result<()> {
        let deadline = Instant::now() + timeout;
        loop {
            let ready = self
                .http
                .get(format!("{}/healthz/readiness", self.base))
                .send()
                .map(|r| r.status().is_success())
                .unwrap_or(false);
            if ready {
                return Ok(());
            }
            if Instant::now() >= deadline {
                bail!("n8n not ready after {timeout:?}");
            }
            sleep(Duration::from_secs(1));
        }
    }

    pub fn login(&self, email: &str, password: &str) -> Result<()> {
        let resp = self
            .http
            .post(format!("{}/rest/login", self.base))
            .json(&json!({ "emailOrLdapLoginId": email, "password": password }))
            .send()?;
        provenance_core::http::ensure_success(resp).context("n8n owner login")?;
        Ok(())
    }

    pub fn list_credentials(&self) -> Result<Vec<(String, String)>> {
        let resp = self
            .http
            .get(format!("{}/rest/credentials", self.base))
            .send()?;
        let body: Value = provenance_core::http::json_ok(resp, "credential list")?;
        Ok(credential_index(body))
    }

    pub fn create_credential(&self, name: &str, kind: &str, data: &Value) -> Result<String> {
        let resp = self
            .http
            .post(format!("{}/rest/credentials", self.base))
            .json(&json!({ "name": name, "type": kind, "data": data }))
            .send()?;
        let body: Value = provenance_core::http::json_ok(resp, "credential create")?;
        match &unwrap_data(body)["id"] {
            Value::String(id) => Ok(id.clone()),
            Value::Number(id) => Ok(id.to_string()),
            _ => Err(anyhow!("credential create response has no id")),
        }
    }

    pub fn delete_credential(&self, id: &str) -> Result<()> {
        let resp = self
            .http
            .delete(format!("{}/rest/credentials/{id}", self.base))
            .send()?;
        provenance_core::http::ensure_success(resp).context("credential delete")?;
        Ok(())
    }

    pub fn update_credential(&self, id: &str, name: &str, kind: &str, data: &Value) -> Result<()> {
        let resp = self
            .http
            .patch(format!("{}/rest/credentials/{id}", self.base))
            .json(&json!({ "name": name, "type": kind, "data": data }))
            .send()?;
        provenance_core::http::ensure_success(resp).context("credential update")?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_own_data_field_is_not_unwrapped() {
        let created = json!({"data": {"id": "7", "name": "hook", "data": {"name": "X"}}});
        assert_eq!(unwrap_data(created)["id"], "7");
    }

    #[test]
    fn list_shapes_are_all_understood() {
        let item = json!({"id": "1", "name": "hook", "type": "httpHeaderAuth"});
        for shape in [
            json!([item]),
            json!({"data": [item]}),
            json!({"count": 1, "data": [item]}),
            json!({"data": {"count": 1, "data": [item]}}),
        ] {
            assert_eq!(
                credential_index(shape),
                vec![("1".to_owned(), "hook".to_owned())]
            );
        }
    }
}
