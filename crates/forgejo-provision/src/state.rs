//! Declarative Forgejo SSH-key state.

use std::collections::BTreeMap;

use anyhow::{Result, bail};
use provenance_core::serde_ext::default_true as default_present;
use serde::Deserialize;

/// Top-level state rendered by the NixOS module.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct State {
    /// SSH keys grouped by Forgejo username and stable key title.
    #[serde(default, rename = "sshKeys")]
    pub ssh_keys: BTreeMap<String, BTreeMap<String, KeySpec>>,
}

/// Desired presence and managed fields for one Forgejo SSH key.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeySpec {
    /// Whether the key should exist.
    #[serde(default = "default_present")]
    pub present: bool,
    /// OpenSSH public key. It is optional only when present is false.
    #[serde(default)]
    pub key: Option<String>,
    /// Whether Forgejo restricts this key to read-only access.
    #[serde(default)]
    pub read_only: bool,
}

impl State {
    /// Validate names and the fields needed by the reconciler.
    pub fn validate(&self) -> Result<()> {
        for (username, keys) in &self.ssh_keys {
            if username.is_empty() || username.contains('/') || username.contains('\0') {
                bail!("Forgejo SSH-key username must be a non-empty path-safe name");
            }
            for (title, spec) in keys {
                if title.is_empty() || title.contains(['\n', '\r', '\0']) {
                    bail!("Forgejo SSH-key title must be a non-empty single-line name");
                }
                if spec.present && spec.key.as_deref().is_none_or(|key| key.trim().is_empty()) {
                    bail!(
                        "Forgejo SSH-key {username}/{title} requires a public key when present = true"
                    );
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_empty_state() {
        let state: State = serde_json::from_str("{}").expect("empty state parses");
        assert!(state.ssh_keys.is_empty());
    }

    #[test]
    fn defaults_key_presence_and_read_only() {
        let state: State =
            serde_json::from_str(r#"{"sshKeys":{"can":{"laptop":{"key":"ssh-ed25519 AAAA"}}}}"#)
                .expect("key state parses");
        let key = &state.ssh_keys["can"]["laptop"];
        assert!(key.present);
        assert!(!key.read_only);
    }

    #[test]
    fn rejects_present_key_without_material() {
        let state: State =
            serde_json::from_str(r#"{"sshKeys":{"can":{"laptop":{}}}}"#).expect("key state parses");
        let error = state.validate().expect_err("missing key must fail");
        assert!(error.to_string().contains("requires a public key"));
    }
}
