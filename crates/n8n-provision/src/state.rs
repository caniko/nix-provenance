//! Nix-rendered desired state. Holds paths and credential names only, never
//! secret values.

use std::collections::BTreeMap;

use anyhow::{Result, ensure};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct State {
    pub url: String,
    pub owner: Owner,
    /// The instance default n8n drops from a saved workflow's `executionTimeout`
    /// (`EXECUTIONS_TIMEOUT`, `-1` when unset). Absent from an older state: the
    /// value is then compared as written.
    #[serde(default)]
    pub execution_timeout: Option<i64>,
    #[serde(default)]
    pub credentials: BTreeMap<String, Credential>,
    #[serde(default)]
    pub workflows: BTreeMap<String, Workflow>,
}

/// The owner-only pre-pass state: the URL, the owner and the names declared
/// inactive, and nothing the reconciler validates.
///
/// A credential declaration the reconciler must reject (an over-long name, a
/// missing field credential) must not keep the pre-pass from unpublishing a
/// workflow the declaration switched off.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeactivateState {
    pub url: String,
    pub owner: DeactivateOwner,
    /// Workflow names declared `active = false`.
    #[serde(default)]
    pub inactive_workflows: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeactivateOwner {
    pub email: String,
    /// systemd credential holding the owner's password.
    pub credential_name: String,
}

/// A declared workflow: a JSON export imported under `name`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Workflow {
    /// n8n workflow JSON (`nodes`, `connections`, optional `settings`/`meta`).
    pub file: std::path::PathBuf,
    #[serde(default = "default_true")]
    pub active: bool,
    /// Credential reference name inside the JSON -> declared credential name.
    /// A reference with no entry here must match a declared credential name.
    #[serde(default)]
    pub credentials: BTreeMap<String, String>,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Owner {
    pub email: String,
    pub first_name: String,
    pub last_name: String,
    /// systemd credential holding the owner's password.
    pub credential_name: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Credential {
    /// n8n credential type, for example `httpHeaderAuth`.
    #[serde(rename = "type")]
    pub kind: String,
    /// Non-secret fields.
    #[serde(default)]
    pub data: BTreeMap<String, serde_json::Value>,
    /// Secret fields: field name -> systemd credential name holding the value.
    #[serde(default)]
    pub data_files: BTreeMap<String, String>,
    /// Prefix prepended to a `data_files` value at run time: a raw token file
    /// plus `"Bearer "` becomes `"Bearer <token>"`. Never secret by itself.
    #[serde(default)]
    pub data_file_prefixes: BTreeMap<String, String>,
}

/// True when `key` or any nested object key names a secret; such values must
/// come from dataFiles, never the Nix-rendered state.
fn looks_secret(key: &str, value: &serde_json::Value) -> bool {
    let k = key.to_lowercase();
    [
        "pass", "secret", "token", "key", "value", "auth", "cred", "bearer", "private", "cert",
        "jwt", "cookie", "session", "sign", "pin",
    ]
    .iter()
    .any(|s| k.contains(s))
        || match value {
            serde_json::Value::Object(m) => m.iter().any(|(k, v)| looks_secret(k, v)),
            serde_json::Value::Array(a) => a.iter().any(|v| looks_secret("", v)),
            _ => false,
        }
}

impl State {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.owner.email.contains('@'),
            "owner email is not an email"
        );
        for (name, cred) in &self.credentials {
            ensure!(
                !name.is_empty() && name.len() <= 128,
                "credential name {name:?} must be 1-128 chars"
            );
            for (field, value) in &cred.data {
                ensure!(
                    !looks_secret(field, value),
                    "credential {name}: field {field} looks secret; use dataFiles"
                );
            }
            for field in cred.data_files.keys() {
                ensure!(
                    !cred.data.contains_key(field),
                    "credential {name}: field {field} is both data and dataFiles"
                );
            }
            for field in cred.data_file_prefixes.keys() {
                ensure!(
                    cred.data_files.contains_key(field),
                    "credential {name}: prefix for {field}, which dataFiles does not hold"
                );
                ensure!(
                    !cred.data.contains_key(field),
                    "credential {name}: prefix for {field}, which is a plain data field"
                );
            }
        }
        for (name, workflow) in &self.workflows {
            ensure!(
                !name.is_empty() && name.len() <= 128,
                "workflow name {name:?} must be 1-128 characters"
            );
            ensure!(
                workflow.file.is_absolute(),
                "workflow {name}: file must be absolute"
            );
            for (reference, credential) in &workflow.credentials {
                ensure!(
                    !reference.is_empty() && !credential.is_empty(),
                    "workflow {name}: credential references must be non-empty"
                );
                ensure!(
                    self.credentials.contains_key(credential),
                    "workflow {name}: credential reference {reference:?} names undeclared credential {credential:?}"
                );
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_authorization_data_field() {
        let s: State = serde_json::from_str(
            r#"{"url":"http://127.0.0.1:5678",
            "owner":{"email":"a@b.c","first_name":"A","last_name":"B","credential_name":"p"},
            "credentials":{"hook":{"type":"x","data":{"authorization":"y"}}}}"#,
        )
        .unwrap();
        assert!(s.validate().is_err());
    }

    #[test]
    fn rejects_nested_secret_looking_data_field() {
        let s: State = serde_json::from_str(
            r#"{"url":"http://127.0.0.1:5678",
            "owner":{"email":"a@b.c","first_name":"A","last_name":"B","credential_name":"p"},
            "credentials":{"hook":{"type":"x","data":{"client":{"secret":"y"}}}}}"#,
        )
        .unwrap();
        assert!(s.validate().is_err());
    }

    #[test]
    fn rejects_secret_looking_data_field() {
        let s: State = serde_json::from_str(
            r#"{"url":"http://127.0.0.1:5678",
            "owner":{"email":"a@b.c","first_name":"A","last_name":"B","credential_name":"p"},
            "credentials":{"hook":{"type":"httpHeaderAuth","data":{"value":"y"}}}}"#,
        )
        .unwrap();
        assert!(s.validate().is_err());
    }

    #[test]
    fn rejects_field_declared_twice() {
        let s: State = serde_json::from_str(
            r#"{"url":"http://127.0.0.1:5678",
            "owner":{"email":"a@b.c","first_name":"A","last_name":"B","credential_name":"p"},
            "credentials":{"hook":{"type":"httpHeaderAuth","data":{"name":"X"},"data_files":{"name":"c"}}}}"#,
        )
        .unwrap();
        assert!(s.validate().is_err());
    }

    #[test]
    fn accepts_a_workflow_whose_credentials_are_declared_or_mapped() {
        let s: State = serde_json::from_str(
            r#"{"url":"http://127.0.0.1:5678",
            "owner":{"email":"a@b.c","first_name":"A","last_name":"B","credential_name":"p"},
            "credentials":{"hub-webhook":{"type":"httpHeaderAuth"}},
            "workflows":{"fleetix-hub-claim":{
              "file":"/nix/store/x-claim.json",
              "credentials":{"Fleetix Hub webhook token":"hub-webhook"}}}}"#,
        )
        .unwrap();
        s.validate().unwrap();
        assert!(s.workflows["fleetix-hub-claim"].active);
    }

    #[test]
    fn rejects_workflows_referencing_undeclared_credentials_or_relative_files() {
        let bad_credential: State = serde_json::from_str(
            r#"{"url":"http://127.0.0.1:5678",
            "owner":{"email":"a@b.c","first_name":"A","last_name":"B","credential_name":"p"},
            "workflows":{"w":{"file":"/nix/store/x.json","credentials":{"hook":"ghost"}}}}"#,
        )
        .unwrap();
        assert!(bad_credential.validate().is_err());
        let relative: State = serde_json::from_str(
            r#"{"url":"http://127.0.0.1:5678",
            "owner":{"email":"a@b.c","first_name":"A","last_name":"B","credential_name":"p"},
            "workflows":{"w":{"file":"claim.json"}}}"#,
        )
        .unwrap();
        assert!(relative.validate().is_err());
    }

    #[test]
    fn rejects_a_prefix_without_its_data_file() {
        let s: State = serde_json::from_str(
            r#"{"url":"http://127.0.0.1:5678",
            "owner":{"email":"a@b.c","first_name":"A","last_name":"B","credential_name":"p"},
            "credentials":{"hook":{"type":"httpHeaderAuth","data_files":{"value":"v"},"data_file_prefixes":{"name":"Bearer "}}}}"#,
        )
        .unwrap();
        assert!(s.validate().is_err());
    }
}
