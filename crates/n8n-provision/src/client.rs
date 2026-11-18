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
            // A 307/308 would replay the secret-bearing POST body elsewhere.
            .redirect(reqwest::redirect::Policy::none())
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

    pub fn list_workflows(&self) -> Result<Vec<(String, String)>> {
        let resp = self
            .http
            .get(format!("{}/rest/workflows", self.base))
            .send()?;
        let body: Value = provenance_core::http::json_ok(resp, "workflow list")?;
        Ok(workflow_index(body))
    }

    /// n8n's effective default `executionTimeout` (its `EXECUTIONS_TIMEOUT`, `-1`
    /// when unset), the value it deletes from a saved workflow's settings. Its
    /// own default stands in when the instance reports no figure.
    pub fn execution_timeout_default(&self) -> Result<i64> {
        let resp = self
            .http
            .get(format!("{}/rest/settings", self.base))
            .send()?;
        let body: Value = provenance_core::http::json_ok(resp, "settings")?;
        Ok(unwrap_data(body)["executionTimeout"].as_i64().unwrap_or(-1))
    }

    /// One workflow with its nodes, connections, settings, `active` flag and
    /// `versionId`.
    pub fn workflow(&self, id: &str) -> Result<Value> {
        let resp = self
            .http
            .get(format!("{}/rest/workflows/{id}", self.base))
            .send()?;
        let body: Value = provenance_core::http::json_ok(resp, "workflow get")?;
        Ok(unwrap_data(body))
    }

    /// Import a workflow into the owner's personal project. n8n always creates
    /// it inactive; the caller activates it.
    pub fn create_workflow(&self, payload: &Value) -> Result<WorkflowState> {
        let resp = self
            .http
            .post(format!("{}/rest/workflows", self.base))
            .json(payload)
            .send()?;
        json_state(resp, "workflow create")
    }

    pub fn update_workflow(&self, id: &str, payload: &Value) -> Result<WorkflowState> {
        let resp = self
            .http
            .patch(format!("{}/rest/workflows/{id}", self.base))
            .json(payload)
            .send()?;
        json_state(resp, "workflow update")
    }

    /// Publish `version` (the workflow's current `versionId`) so the workflow
    /// serves its triggers. n8n 2.x requires the version id here.
    pub fn activate_workflow(&self, id: &str, version: &str) -> Result<()> {
        let resp = self
            .http
            .post(format!("{}/rest/workflows/{id}/activate", self.base))
            .json(&json!({ "versionId": version }))
            .send()?;
        provenance_core::http::ensure_success(resp).context("workflow activate")?;
        Ok(())
    }

    pub fn deactivate_workflow(&self, id: &str) -> Result<()> {
        let resp = self
            .http
            .post(format!("{}/rest/workflows/{id}/deactivate", self.base))
            .json(&json!({}))
            .send()?;
        provenance_core::http::ensure_success(resp).context("workflow deactivate")?;
        Ok(())
    }
}

/// Identity and current version of a workflow n8n just wrote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkflowState {
    pub id: String,
    /// Null only when n8n did not version the write; activation then fails.
    pub version: Option<String>,
}

fn json_state(resp: reqwest::blocking::Response, context: &str) -> Result<WorkflowState> {
    let status = resp.status();
    let body = resp.text()?;
    if !status.is_success() {
        // The body is n8n's validation message (node names, structure): the
        // workflow carries credentials by id, never by value.
        bail!("{context}: HTTP {status}: {body}");
    }
    let value: Value = serde_json::from_str(&body).context("decoding workflow response")?;
    workflow_state(&unwrap_data(value))
}

fn workflow_state(v: &Value) -> Result<WorkflowState> {
    Ok(WorkflowState {
        id: v["id"]
            .as_str()
            .context("workflow response has no id")?
            .to_owned(),
        version: v["versionId"].as_str().map(str::to_owned),
    })
}

/// Extract `(id, name)` pairs from a workflow list (`[..]`, `{data:[..]}` or
/// `{count, data:[..]}`), which is the same envelope as the credential list.
pub fn workflow_index(v: Value) -> Vec<(String, String)> {
    let v = unwrap_data(v);
    v.as_array()
        .into_iter()
        .flatten()
        .filter_map(|w| Some((w["id"].as_str()?.to_owned(), w["name"].as_str()?.to_owned())))
        .collect()
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

    #[test]
    fn workflow_lists_and_states_are_understood() {
        let item = json!({"id": "w1", "name": "fleetix-hub-claim", "active": false});
        for shape in [
            json!([item]),
            json!({"data": [item]}),
            json!({"count": 1, "data": [item]}),
        ] {
            assert_eq!(
                workflow_index(shape),
                vec![("w1".to_owned(), "fleetix-hub-claim".to_owned())]
            );
        }
        let state = workflow_state(&json!({
            "id": "w1", "versionId": "v2", "activeVersionId": null, "nodes": [],
        }))
        .unwrap();
        assert_eq!(state.id, "w1");
        assert_eq!(state.version.as_deref(), Some("v2"));
        // A workflow carries its own `data`-looking keys: `unwrap_data` must not
        // mistake the object for an envelope, and unknown keys are ignored.
        assert_eq!(
            unwrap_data(json!({"id": "x", "data": {"id": "y"}}))["id"],
            "x"
        );
        assert!(workflow_state(&json!({"name": "no id"})).is_err());
        assert_eq!(workflow_state(&json!({"id": "x"})).unwrap().version, None);
    }
}
