use anyhow::{Result, bail};
use provenance_core::generated_secret::{GeneratedSecretStore, SecretFileStatus};
use provenance_core::password::{PasswordMarkerStore, read_password_file};
use provenance_core::reconcile::Summary;
use serde_json::{Map, Value, json};

use crate::client::{ImmichApiKey, ImmichClient, ImmichUser};
use crate::state::{State, UserSpec};

pub fn reconcile(
    client: &ImmichClient,
    state: &State,
    allow_user_delete: bool,
    password_markers: &PasswordMarkerStore,
) -> Result<Summary> {
    let config = client.system_config()?;
    let oauth_enabled = config.oauth.enabled;
    let existing = client.list_users()?;
    let mut summary = Summary::default();

    for (key, spec) in &state.users {
        spec.validate(key)?;
        let email = spec.identity_email(key)?;
        let current = existing
            .iter()
            .find(|user| normalize_email(&user.email) == email);

        match (spec.present, current) {
            (true, Some(user)) => {
                let mut update = build_update_user_request(user, spec);
                let password = resolve_password(spec)?;
                let password_marker_id = format!("immich:{email}");
                let password_changed = match password.as_deref() {
                    Some(password) => {
                        password_markers.needs_update(&password_marker_id, password)?
                    }
                    None => false,
                };
                if password_changed {
                    let pw = password
                        .as_deref()
                        .expect("password_changed guarantees password is Some");
                    update.insert("password".to_string(), json!(pw));
                }
                if update.is_empty() {
                    summary.unchanged += 1;
                } else {
                    client.update_user(&user.id, &update)?;
                    if let Some(password) = password.filter(|_| password_changed) {
                        password_markers.commit(&password_marker_id, &password)?;
                    }
                    summary.updated += 1;
                }
            }
            (true, None) => {
                if !oauth_enabled && spec.password_file.is_none() {
                    bail!(
                        "refusing to create OAuth-only user {key}: Immich OAuth is disabled in system config and no passwordFile is set"
                    );
                }
                let password = resolve_password(spec)?;
                let body = build_create_user_request(key, spec, password.as_deref())?;
                client.create_user(&body)?;
                if let Some(password) = password {
                    password_markers.commit(&format!("immich:{email}"), &password)?;
                }
                summary.created += 1;
            }
            (false, Some(user)) => {
                ensure_delete_allowed(key, spec, allow_user_delete)?;
                client.delete_user(&user.id, true)?;
                summary.deleted += 1;
            }
            (false, None) => summary.unchanged += 1,
        }
    }

    reconcile_api_keys(client, state, &mut summary)?;
    Ok(summary)
}

#[derive(Debug, PartialEq, Eq)]
enum ApiKeyAction {
    Keep,
    UpdatePermissions(String),
    /// Delete these stale keys of the same name, then create a new one.
    Recreate(Vec<String>),
}

/// Decide how to converge a declared key. The provisioner owns every key with
/// the declared name; the stored file is valid only if its secret still
/// authenticates as one of them.
fn api_key_action(
    name: &str,
    permissions: &[String],
    stored_id: Option<&str>,
    existing: &[ImmichApiKey],
) -> ApiKeyAction {
    let named = existing.iter().filter(|key| key.name == name);
    match stored_id.and_then(|id| existing.iter().find(|key| key.id == id && key.name == name)) {
        Some(key) if sorted(&key.permissions) == sorted(permissions) => ApiKeyAction::Keep,
        Some(key) => ApiKeyAction::UpdatePermissions(key.id.clone()),
        None => ApiKeyAction::Recreate(named.map(|key| key.id.clone()).collect()),
    }
}

fn sorted(values: &[String]) -> Vec<&str> {
    let mut values: Vec<&str> = values.iter().map(String::as_str).collect();
    values.sort_unstable();
    values.dedup();
    values
}

fn reconcile_api_keys(client: &ImmichClient, state: &State, summary: &mut Summary) -> Result<()> {
    if state.api_keys.is_empty() {
        return Ok(());
    }
    let existing = client.list_api_keys()?;
    for (name, spec) in &state.api_keys {
        spec.validate(name)?;
        let store = GeneratedSecretStore::at(&spec.file)?;
        let stored_id = match store.status()? {
            SecretFileStatus::Ready => client.api_key_id_for(store.read()?.expose())?,
            SecretFileStatus::Missing => None,
        };
        match api_key_action(name, &spec.permissions, stored_id.as_deref(), &existing) {
            ApiKeyAction::Keep => summary.unchanged += 1,
            ApiKeyAction::UpdatePermissions(id) => {
                client.update_api_key_permissions(&id, &spec.permissions)?;
                summary.updated += 1;
            }
            ApiKeyAction::Recreate(stale) => {
                for id in stale {
                    client.delete_api_key(&id)?;
                }
                // A crash between create and write leaves a named key without a
                // file; the next run deletes it as stale and creates another.
                let created = client.create_api_key(name, &spec.permissions)?;
                store.replace_text(&created.secret)?;
                eprintln!(
                    "[immich-provision] API key {name} ({}) written to {}",
                    created.id, spec.file
                );
                summary.created += 1;
            }
        }
    }
    Ok(())
}

pub fn normalize_email(email: &str) -> String {
    email.trim().to_lowercase()
}

pub fn build_create_user_request(
    key: &str,
    spec: &UserSpec,
    password: Option<&str>,
) -> Result<Map<String, Value>> {
    let mut body = Map::new();
    body.insert("email".to_string(), json!(spec.identity_email(key)?));
    body.insert("name".to_string(), json!(required_name(key, spec)?));
    insert_if_some(&mut body, "isAdmin", spec.is_admin);
    insert_nullable_string(&mut body, "storageLabel", &spec.storage_label);
    insert_nullable_u64(&mut body, "quotaSizeInBytes", spec.quota_size_in_bytes);
    insert_nullable_string(&mut body, "avatarColor", &spec.avatar_color);
    insert_if_some(
        &mut body,
        "shouldChangePassword",
        spec.should_change_password,
    );
    insert_if_some(&mut body, "password", password);
    Ok(body)
}

pub fn build_update_user_request(existing: &ImmichUser, spec: &UserSpec) -> Map<String, Value> {
    let mut body = Map::new();

    if let Some(name) = spec.name.as_deref()
        && existing.name != name
    {
        body.insert("name".to_string(), json!(name));
    }
    if let Some(is_admin) = spec.is_admin
        && existing.is_admin != is_admin
    {
        body.insert("isAdmin".to_string(), json!(is_admin));
    }
    if let Some(storage_label) = &spec.storage_label
        && &existing.storage_label != storage_label
    {
        body.insert("storageLabel".to_string(), json!(storage_label));
    }
    if let Some(quota) = spec.quota_size_in_bytes
        && existing.quota_size_in_bytes != quota
    {
        body.insert("quotaSizeInBytes".to_string(), json!(quota));
    }
    if let Some(avatar_color) = &spec.avatar_color
        && &existing.avatar_color != avatar_color
    {
        body.insert("avatarColor".to_string(), json!(avatar_color));
    }
    if let Some(should_change_password) = spec.should_change_password
        && existing.should_change_password != should_change_password
    {
        body.insert(
            "shouldChangePassword".to_string(),
            json!(should_change_password),
        );
    }

    body
}

fn resolve_password(spec: &UserSpec) -> Result<Option<String>> {
    Ok(spec
        .password_file
        .as_deref()
        .map(read_password_file)
        .transpose()?)
}

pub fn ensure_delete_allowed(key: &str, spec: &UserSpec, allow_user_delete: bool) -> Result<()> {
    if !allow_user_delete {
        bail!(
            "refusing to delete users.{key}: pass --allow-user-delete and set delete.force = true"
        );
    }
    if !spec.delete.force {
        bail!("refusing to delete users.{key}: delete.force must be true");
    }
    Ok(())
}

fn required_name<'a>(key: &str, spec: &'a UserSpec) -> Result<&'a str> {
    let name = spec.name.as_deref().unwrap_or("").trim();
    if name.is_empty() {
        bail!("users.{key}.name is required when present = true");
    }
    Ok(name)
}

fn insert_if_some<T>(body: &mut Map<String, Value>, key: &str, value: Option<T>)
where
    T: serde::Serialize,
{
    if let Some(value) = value {
        body.insert(key.to_string(), json!(value));
    }
}

fn insert_nullable_string(
    body: &mut Map<String, Value>,
    key: &str,
    value: &Option<Option<String>>,
) {
    if let Some(value) = value {
        body.insert(key.to_string(), json!(value));
    }
}

fn insert_nullable_u64(body: &mut Map<String, Value>, key: &str, value: Option<Option<u64>>) {
    if let Some(value) = value {
        body.insert(key.to_string(), json!(value));
    }
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;
    use serde_json::json;

    use super::*;

    fn user() -> ImmichUser {
        ImmichUser {
            id: "user-id".to_string(),
            email: "alice@example.com".to_string(),
            name: "Alice".to_string(),
            is_admin: false,
            storage_label: Some("alice".to_string()),
            quota_size_in_bytes: Some(100),
            avatar_color: Some("blue".to_string()),
            should_change_password: false,
        }
    }

    #[test]
    fn create_request_never_contains_password_or_oauth_id() {
        let state: State = serde_json::from_str(
            r#"{
              "users": {
                "alice": {
                  "email": "Alice@Example.com",
                  "name": "Alice",
                  "isAdmin": false,
                  "storageLabel": "alice",
                  "quotaSizeInBytes": 100,
                  "avatarColor": "blue",
                  "shouldChangePassword": false
                }
              }
            }"#,
        )
        .unwrap();
        let body = build_create_user_request("alice", &state.users["alice"], None).unwrap();
        assert_eq!(body["email"], json!("alice@example.com"));
        assert_eq!(body["name"], json!("Alice"));
        assert_eq!(body["avatarColor"], json!("blue"));
        assert!(!body.contains_key("password"));
        assert!(!body.contains_key("pinCode"));
        assert!(!body.contains_key("notify"));
        assert!(!body.contains_key("oauthId"));
    }

    #[test]
    fn create_request_contains_password_when_runtime_secret_is_supplied() {
        let state: State =
            serde_json::from_str(r#"{ "users": { "alice@example.com": { "name": "Alice" } } }"#)
                .unwrap();
        let body = build_create_user_request(
            "alice@example.com",
            &state.users["alice@example.com"],
            Some("runtime-secret"),
        )
        .unwrap();

        assert_eq!(body["password"], json!("runtime-secret"));
        assert!(!body.contains_key("pinCode"));
    }

    #[test]
    fn normalize_email_trims_and_lowercases() {
        assert_eq!(
            normalize_email(" Alice@Example.COM \n"),
            "alice@example.com"
        );
    }

    #[test]
    fn update_request_only_contains_declared_safe_drift() {
        let state: State = serde_json::from_str(
            r#"{
              "users": {
                "alice": {
                  "email": "alice@example.com",
                  "name": "Alice T",
                  "isAdmin": false,
                  "storageLabel": null,
                  "avatarColor": null,
                  "quotaSizeInBytes": 100,
                  "shouldChangePassword": false
                }
              }
            }"#,
        )
        .unwrap();
        let body = build_update_user_request(&user(), &state.users["alice"]);
        assert_eq!(body.len(), 3);
        assert_eq!(body["name"], json!("Alice T"));
        assert_eq!(body["storageLabel"], Value::Null);
        assert_eq!(body["avatarColor"], Value::Null);
        assert!(!body.contains_key("email"));
        assert!(!body.contains_key("oauthId"));
    }

    #[test]
    fn unchanged_user_has_empty_update_request() {
        let state: State = serde_json::from_str(
            r#"{
              "users": {
                "alice": {
                  "email": "alice@example.com",
                  "name": "Alice",
                  "isAdmin": false,
                  "storageLabel": "alice",
                  "quotaSizeInBytes": 100,
                  "avatarColor": "blue",
                  "shouldChangePassword": false
                }
              }
            }"#,
        )
        .unwrap();
        let body = build_update_user_request(&user(), &state.users["alice"]);
        assert!(body.is_empty());
    }

    #[test]
    fn deletion_requires_two_locks() {
        let state: State =
            serde_json::from_str(r#"{ "users": { "alice@example.com": { "present": false } } }"#)
                .unwrap();
        let spec = &state.users["alice@example.com"];
        assert!(ensure_delete_allowed("alice@example.com", spec, false).is_err());
        assert!(ensure_delete_allowed("alice@example.com", spec, true).is_err());

        let state: State = serde_json::from_str(
            r#"{ "users": { "alice@example.com": { "present": false, "delete": { "force": true } } } }"#,
        )
        .unwrap();
        assert!(
            ensure_delete_allowed("alice@example.com", &state.users["alice@example.com"], true)
                .is_ok()
        );
    }

    #[test]
    fn api_key_action_keeps_updates_or_recreates() {
        let key = |id: &str, name: &str, perms: &[&str]| ImmichApiKey {
            id: id.into(),
            name: name.into(),
            permissions: perms.iter().map(|p| p.to_string()).collect(),
        };
        let want = vec!["asset.read".to_string(), "user.read".to_string()];
        let existing = vec![
            key("k1", "conv", &["user.read", "asset.read"]),
            key("k2", "conv", &["asset.read"]),
            key("k3", "other", &["asset.read"]),
        ];

        assert_eq!(
            api_key_action("conv", &want, Some("k1"), &existing),
            ApiKeyAction::Keep
        );
        assert_eq!(
            api_key_action("conv", &want, Some("k2"), &existing),
            ApiKeyAction::UpdatePermissions("k2".into())
        );
        // No file, or a secret that no longer authenticates (or belongs to
        // another name): replace every key of this name, never other names.
        let recreate = ApiKeyAction::Recreate(vec!["k1".into(), "k2".into()]);
        assert_eq!(api_key_action("conv", &want, None, &existing), recreate);
        assert_eq!(
            api_key_action("conv", &want, Some("k3"), &existing),
            recreate
        );
    }
}
