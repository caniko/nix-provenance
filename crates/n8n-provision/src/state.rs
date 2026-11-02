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
    #[serde(default)]
    pub credentials: BTreeMap<String, Credential>,
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
            for field in cred.data_files.keys() {
                ensure!(
                    !cred.data.contains_key(field),
                    "credential {name}: field {field} is both data and dataFiles"
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
    fn rejects_field_declared_twice() {
        let s: State = serde_json::from_str(
            r#"{"url":"http://127.0.0.1:5678",
            "owner":{"email":"a@b.c","first_name":"A","last_name":"B","credential_name":"p"},
            "credentials":{"hook":{"type":"httpHeaderAuth","data":{"name":"X","value":"y"},"data_files":{"value":"c"}}}}"#,
        )
        .unwrap();
        assert!(s.validate().is_err());
    }
}
