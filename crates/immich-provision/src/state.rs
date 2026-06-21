use std::collections::BTreeMap;

use anyhow::{Result, bail};
use provenance_core::serde_ext::double_option;
use serde::Deserialize;

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct State {
    pub users: BTreeMap<String, UserSpec>,
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct UserSpec {
    pub present: bool,
    pub email: Option<String>,
    pub name: Option<String>,
    #[serde(rename = "isAdmin")]
    pub is_admin: Option<bool>,
    #[serde(
        default,
        rename = "storageLabel",
        deserialize_with = "double_option::deserialize"
    )]
    pub storage_label: Option<Option<String>>,
    #[serde(
        default,
        rename = "quotaSizeInBytes",
        deserialize_with = "double_option::deserialize"
    )]
    pub quota_size_in_bytes: Option<Option<u64>>,
    #[serde(
        default,
        rename = "avatarColor",
        deserialize_with = "double_option::deserialize"
    )]
    pub avatar_color: Option<Option<String>>,
    #[serde(rename = "shouldChangePassword")]
    pub should_change_password: Option<bool>,
    #[serde(rename = "passwordFile")]
    pub password_file: Option<String>,
    pub delete: DeleteSpec,
}

impl Default for UserSpec {
    fn default() -> Self {
        Self {
            present: true,
            email: None,
            name: None,
            is_admin: None,
            storage_label: None,
            quota_size_in_bytes: None,
            avatar_color: None,
            should_change_password: None,
            password_file: None,
            delete: DeleteSpec::default(),
        }
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DeleteSpec {
    pub force: bool,
}

impl UserSpec {
    pub fn identity_email(&self, key: &str) -> Result<String> {
        let email = self.email.as_deref().unwrap_or(key);
        if !email.contains('@') {
            bail!(
                "users.{key} must set email; map keys without '@' are names, not email identities"
            );
        }
        Ok(email.trim().to_lowercase())
    }

    pub fn validate(&self, key: &str) -> Result<()> {
        let _ = self.identity_email(key)?;
        if self.present && self.name.as_deref().unwrap_or("").trim().is_empty() {
            bail!("users.{key}.name is required when present = true");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;

    use super::*;

    #[test]
    fn parses_minimal_state() {
        let state: State = serde_json::from_str("{}").unwrap();
        assert!(state.users.is_empty());
    }

    #[test]
    fn present_defaults_true_and_email_can_come_from_key() {
        let state: State =
            serde_json::from_str(r#"{ "users": { "alice@example.com": { "name": "Alice" } } }"#)
                .unwrap();
        let user = &state.users["alice@example.com"];
        assert!(user.present);
        assert_eq!(
            user.identity_email("alice@example.com").unwrap(),
            "alice@example.com"
        );
    }

    #[test]
    fn camel_case_fields_parse() {
        let state: State = serde_json::from_str(
            r#"{
              "users": {
                "alice": {
                  "email": "ALICE@example.com",
                  "name": "Alice",
                  "isAdmin": true,
                  "storageLabel": null,
                  "quotaSizeInBytes": 100,
                  "avatarColor": "blue",
                  "shouldChangePassword": false,
                  "passwordFile": "/run/credentials/immich-provision.service/password-alice"
                }
              }
            }"#,
        )
        .unwrap();
        let user = &state.users["alice"];
        assert_eq!(user.identity_email("alice").unwrap(), "alice@example.com");
        assert_eq!(user.is_admin, Some(true));
        assert_eq!(user.storage_label, Some(None));
        assert_eq!(user.quota_size_in_bytes, Some(Some(100)));
        assert_eq!(user.avatar_color, Some(Some("blue".to_string())));
        assert_eq!(user.should_change_password, Some(false));
        assert_eq!(
            user.password_file.as_deref(),
            Some("/run/credentials/immich-provision.service/password-alice")
        );
    }

    #[test]
    fn named_key_requires_email() {
        let state: State =
            serde_json::from_str(r#"{ "users": { "alice": { "name": "Alice" } } }"#).unwrap();
        assert!(state.users["alice"].validate("alice").is_err());
    }
}
