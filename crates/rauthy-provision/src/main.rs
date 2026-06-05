//! rauthy-provision — declarative provisioning client for Rauthy.
//!
//! A kanidm-provision analogue: read a JSON state file describing the desired
//! groups, roles, users, and OIDC clients, and reconcile a running Rauthy
//! instance toward it over the `/auth/v1` admin API using an API key.
//!
//! Reconciliation is create-if-missing plus minimal drift updates, and is
//! idempotent. Deletion happens only for entities explicitly declared with
//! `present = false` (Rauthy has no tracking-group equivalent for safe orphan
//! removal). Pass `--no-auto-remove` to skip even those deletions.

mod client;
mod state;

use std::collections::BTreeMap;
use std::fmt::Arguments;
use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use provenance_core::setops::{is_subset, opt_vec, same_set, union};

use client::{
    NewClientRequest, NewUserRequest, RauthyClient, ScopeRequest, UpdateClientRequest,
    UpdateUserRequest, UserAttributeConfigRequest, UserAttributeValueRequest,
};
use state::{ClientSpec, ScopeSpec, State, UserAttributeSpec, UserSpec};

#[derive(Parser, Debug)]
#[command(
    name = "rauthy-provision",
    about = "Declaratively provision Rauthy users, groups, roles, and OIDC clients",
    version
)]
struct Cli {
    /// Rauthy base URL (the `/auth/v1` API path is appended automatically).
    #[arg(long)]
    url: String,

    /// Path to the JSON state file.
    #[arg(long)]
    state: PathBuf,

    /// File containing the API key (`<name>$<secret>`). Takes precedence over
    /// the `RAUTHY_PROVISION_API_KEY` environment variable.
    #[arg(long)]
    api_key_file: Option<PathBuf>,

    /// API key (`<name>$<secret>`). Prefer `--api-key-file` so the secret does
    /// not appear in the process table.
    #[arg(long, env = "RAUTHY_PROVISION_API_KEY", hide_env_values = true)]
    api_key: Option<String>,

    /// Accept invalid TLS certificates (e.g. talking to an internal endpoint
    /// with a name mismatch). Avoid in production.
    #[arg(long)]
    accept_invalid_certs: bool,

    /// Skip deletions: entities declared `present = false` are left untouched.
    #[arg(long)]
    no_auto_remove: bool,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let api_key = provenance_core::secret::resolve(
        cli.api_key_file.as_deref(),
        cli.api_key.as_deref(),
        "API key",
        "--api-key-file",
        "RAUTHY_PROVISION_API_KEY",
    )?;
    let raw = fs::read_to_string(&cli.state)
        .with_context(|| format!("reading state file {}", cli.state.display()))?;
    let state: State = serde_json::from_str(&raw)
        .with_context(|| format!("parsing state file {}", cli.state.display()))?;

    let client = RauthyClient::new(&cli.url, &api_key, cli.accept_invalid_certs)?;
    client
        .wait_ready(30, Duration::from_secs(2))
        .context("waiting for rauthy to be ready")?;

    // Groups and roles first — users reference them by name.
    reconcile_groups(&client, &state, cli.no_auto_remove)?;
    reconcile_roles(&client, &state, cli.no_auto_remove)?;
    reconcile_user_attributes(&client, &state, cli.no_auto_remove)?;
    reconcile_scopes(&client, &state, cli.no_auto_remove)?;
    reconcile_users(&client, &state, cli.no_auto_remove)?;
    reconcile_clients(&client, &state, cli.no_auto_remove)?;

    log(format_args!("done"));
    Ok(())
}

fn log(msg: Arguments<'_>) {
    eprintln!("[rauthy-provision] {msg}");
}

fn reconcile_groups(client: &RauthyClient, state: &State, no_auto_remove: bool) -> Result<()> {
    let existing = client.list_groups()?;
    for (name, spec) in &state.groups {
        let found = existing.iter().find(|g| &g.name == name);
        match (spec.present, found) {
            (true, None) => {
                log(format_args!("create group {name}"));
                client.create_group(name)?;
            }
            (false, Some(g)) if !no_auto_remove => {
                log(format_args!("delete group {name}"));
                client.delete_group(&g.id)?;
            }
            _ => {}
        }
    }
    Ok(())
}

fn reconcile_roles(client: &RauthyClient, state: &State, no_auto_remove: bool) -> Result<()> {
    let existing = client.list_roles()?;
    for (name, spec) in &state.roles {
        let found = existing.iter().find(|r| &r.name == name);
        match (spec.present, found) {
            (true, None) => {
                log(format_args!("create role {name}"));
                client.create_role(name)?;
            }
            (false, Some(r)) if !no_auto_remove => {
                log(format_args!("delete role {name}"));
                client.delete_role(&r.id)?;
            }
            _ => {}
        }
    }
    Ok(())
}

fn reconcile_user_attributes(
    client: &RauthyClient,
    state: &State,
    no_auto_remove: bool,
) -> Result<()> {
    if state.user_attributes.is_empty() {
        return Ok(());
    }
    let existing = client.list_user_attributes()?;
    for (name, spec) in &state.user_attributes {
        let found = existing.iter().find(|attr| &attr.name == name);
        match (spec.present, found) {
            (true, None) => {
                log(format_args!("create user attribute {name}"));
                client.create_user_attribute(&user_attribute_request(name, spec))?;
            }
            (true, Some(attr)) => {
                if user_attribute_drifted(attr, spec) {
                    log(format_args!("update user attribute {name}"));
                    client.update_user_attribute(name, &user_attribute_request(name, spec))?;
                }
            }
            (false, Some(_)) if !no_auto_remove => {
                log(format_args!("delete user attribute {name}"));
                client.delete_user_attribute(name)?;
            }
            _ => {}
        }
    }
    Ok(())
}

fn reconcile_scopes(client: &RauthyClient, state: &State, no_auto_remove: bool) -> Result<()> {
    if state.scopes.is_empty() {
        return Ok(());
    }
    let existing = client.list_scopes()?;
    for (name, spec) in &state.scopes {
        let found = existing.iter().find(|scope| &scope.name == name);
        match (spec.present, found) {
            (true, None) => {
                log(format_args!("create scope {name}"));
                client.create_scope(&scope_request(name, spec))?;
            }
            (true, Some(scope)) => {
                if scope_drifted(scope, spec) {
                    log(format_args!("update scope {name}"));
                    client.update_scope(&scope.id, &scope_request(name, spec))?;
                }
            }
            (false, Some(scope)) if !no_auto_remove => {
                log(format_args!("delete scope {name}"));
                client.delete_scope(&scope.id)?;
            }
            _ => {}
        }
    }
    Ok(())
}

fn reconcile_users(client: &RauthyClient, state: &State, no_auto_remove: bool) -> Result<()> {
    for (email, spec) in &state.users {
        let current = client.get_user_by_email(email)?;
        match (spec.present, current) {
            (true, None) => {
                log(format_args!("create user {email}"));
                client.create_user(&new_user(email, spec))?;
                if spec.preferred_username.is_some() || !spec.attributes.is_empty() {
                    let user = client.get_user_by_email(email)?.ok_or_else(|| {
                        anyhow!("Rauthy user {email} was created but could not be read back")
                    })?;
                    reconcile_user_preferred_username(client, &user, spec)?;
                    reconcile_user_attributes_values(client, &user, spec)?;
                }
                // Email a set-password link only on first create (never on
                // update), so at most one email is ever sent per user.
                if spec.send_password_email {
                    let redirect =
                        spec.password_email_redirect_uri.as_deref().ok_or_else(|| {
                            anyhow!(
                                "user {email} has send_password_email = true but no \
                             password_email_redirect_uri"
                            )
                        })?;
                    log(format_args!("send set-password email to {email}"));
                    client.request_password_reset(email, redirect)?;
                }
            }
            (true, Some(user)) => {
                if user_drifted(&user, spec) {
                    log(format_args!("update user {email} (roles/groups)"));
                    client.update_user(&user.id, &update_user(&user, spec))?;
                }
                reconcile_user_preferred_username(client, &user, spec)?;
                reconcile_user_attributes_values(client, &user, spec)?;
            }
            (false, Some(user)) if !no_auto_remove => {
                log(format_args!("delete user {email}"));
                client.delete_user(&user.id)?;
            }
            (false, _) => {}
        }
    }
    Ok(())
}

fn new_user(email: &str, spec: &UserSpec) -> NewUserRequest {
    NewUserRequest {
        email: email.to_string(),
        given_name: spec.given_name.clone(),
        family_name: spec.family_name.clone(),
        language: spec.language.clone(),
        roles: spec.roles.clone(),
        groups: opt_vec(&spec.groups),
    }
}

/// Roles and groups are reconciled ADDITIVELY: the tool ensures every declared
/// role/group is present but never removes ones it does not manage. This is
/// deliberate — a Rauthy user may carry roles/groups assigned out-of-band (the
/// bootstrap `rauthy_admin` role, or a manual Admin-UI assignment), and a full
/// replace would silently strip them. Names and language are applied at
/// creation only, so upstream federation profile-claim sync is never fought.
fn user_drifted(user: &client::UserResponse, spec: &UserSpec) -> bool {
    let cur_groups = user.groups.as_deref().unwrap_or_default();
    !is_subset(&spec.roles, &user.roles) || !is_subset(&spec.groups, cur_groups)
}

fn update_user(user: &client::UserResponse, spec: &UserSpec) -> UpdateUserRequest {
    // Carry the current name/language/enabled/email_verified through unchanged;
    // a PUT is a full replace, so omitting them would reset server-side values.
    // roles/groups are the UNION of current + declared so out-of-band roles
    // (e.g. rauthy_admin) survive.
    let cur_groups = user.groups.as_deref().unwrap_or_default();
    let groups = union(cur_groups, &spec.groups);
    UpdateUserRequest {
        email: user.email.clone(),
        given_name: user.given_name.clone(),
        family_name: user.family_name.clone(),
        language: user.language.clone(),
        roles: union(&user.roles, &spec.roles),
        groups: if groups.is_empty() {
            None
        } else {
            Some(groups)
        },
        enabled: user.enabled,
        email_verified: user.email_verified,
    }
}

fn reconcile_user_preferred_username(
    client: &RauthyClient,
    user: &client::UserResponse,
    spec: &UserSpec,
) -> Result<()> {
    let Some(desired) = spec.preferred_username.as_deref() else {
        return Ok(());
    };
    if user.user_values.preferred_username.as_deref() != Some(desired) {
        log(format_args!(
            "update user {} preferred_username",
            user.email
        ));
        client.update_preferred_username(&user.id, Some(desired))?;
    }
    Ok(())
}

fn reconcile_user_attributes_values(
    client: &RauthyClient,
    user: &client::UserResponse,
    spec: &UserSpec,
) -> Result<()> {
    if spec.attributes.is_empty() {
        return Ok(());
    }
    let current = client.get_user_attributes(&user.id)?;
    let current: BTreeMap<_, _> = current
        .into_iter()
        .map(|attr| (attr.key, attr.value))
        .collect();
    let mut updates = Vec::new();
    for (key, desired) in &spec.attributes {
        if current.get(key) != Some(desired) {
            updates.push(UserAttributeValueRequest {
                key: key.clone(),
                value: desired.clone(),
            });
        }
    }
    if !updates.is_empty() {
        log(format_args!("update user {} custom attributes", user.email));
        client.update_user_attributes(&user.id, updates)?;
    }
    Ok(())
}

fn scope_request(name: &str, spec: &ScopeSpec) -> ScopeRequest {
    ScopeRequest {
        scope: name.to_string(),
        attr_include_access: opt_vec(&spec.attr_include_access),
        attr_include_id: opt_vec(&spec.attr_include_id),
    }
}

fn scope_drifted(cur: &client::ScopeResponse, spec: &ScopeSpec) -> bool {
    let cur_access = cur.attr_include_access.as_deref().unwrap_or_default();
    let cur_id = cur.attr_include_id.as_deref().unwrap_or_default();
    !same_set(cur_access, &spec.attr_include_access) || !same_set(cur_id, &spec.attr_include_id)
}

fn user_attribute_request(name: &str, spec: &UserAttributeSpec) -> UserAttributeConfigRequest {
    UserAttributeConfigRequest {
        name: name.to_string(),
        desc: spec.desc.clone(),
        default_value: spec.default_value.clone(),
        user_editable: Some(spec.user_editable),
    }
}

fn user_attribute_drifted(
    cur: &client::UserAttributeConfigResponse,
    spec: &UserAttributeSpec,
) -> bool {
    cur.desc != spec.desc
        || cur.default_value != spec.default_value
        || cur.user_editable != spec.user_editable
}

fn reconcile_clients(client: &RauthyClient, state: &State, no_auto_remove: bool) -> Result<()> {
    for (id, spec) in &state.clients {
        if spec.generated_secret_file.is_some() && !spec.confidential {
            anyhow::bail!(
                "client {id} sets generated_secret_file but is not confidential; \
                 Rauthy only has client secrets for confidential clients"
            );
        }
        let current = client.get_client(id)?;
        match (spec.present, current) {
            (true, None) => {
                log(format_args!("create client {id}"));
                client.create_client(&new_client(id, spec))?;
                // POST sets only id/name/confidential/redirect_uris; the full
                // config (scopes, flows, PKCE) must follow via PUT.
                client.update_client(id, &update_client(id, spec))?;
            }
            (true, Some(cur)) => {
                if client_drifted(&cur, spec) {
                    log(format_args!("update client {id}"));
                    client.update_client(id, &update_client(id, spec))?;
                }
            }
            (false, Some(_)) if !no_auto_remove => {
                log(format_args!("delete client {id}"));
                client.delete_client(id)?;
            }
            (false, _) => {}
        }
        if spec.present {
            ensure_client_secret_file(client, id, spec)?;
        }
    }
    Ok(())
}

fn ensure_client_secret_file(client: &RauthyClient, id: &str, spec: &ClientSpec) -> Result<()> {
    let Some(path) = spec.generated_secret_file.as_deref() else {
        return Ok(());
    };
    let path = Path::new(path);
    match fs::metadata(path) {
        Ok(meta) => {
            if !meta.is_file() {
                anyhow::bail!(
                    "generated secret path {} exists but is not a regular file",
                    path.display()
                );
            }
            return Ok(());
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            return Err(e)
                .with_context(|| format!("checking generated secret file {}", path.display()));
        }
    }

    let parent = path.parent().ok_or_else(|| {
        anyhow::anyhow!(
            "generated secret path {} has no parent directory",
            path.display()
        )
    })?;
    fs::create_dir_all(parent)
        .with_context(|| format!("creating generated secret directory {}", parent.display()))?;

    log(format_args!(
        "generate client secret for {id} into {}",
        path.display()
    ));
    let secret = client.rotate_client_secret(id)?;
    let file_name = path.file_name().and_then(|s| s.to_str()).ok_or_else(|| {
        anyhow::anyhow!("generated secret path {} has no file name", path.display())
    })?;
    let tmp = parent.join(format!(".{file_name}.{}.tmp", std::process::id()));
    {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)
            .with_context(|| format!("creating temporary secret file {}", tmp.display()))?;
        f.write_all(secret.as_bytes())
            .with_context(|| format!("writing temporary secret file {}", tmp.display()))?;
        f.sync_all()
            .with_context(|| format!("syncing temporary secret file {}", tmp.display()))?;
    }
    fs::rename(&tmp, path).with_context(|| {
        format!(
            "installing generated secret file {} from {}",
            path.display(),
            tmp.display()
        )
    })?;
    Ok(())
}

fn new_client(id: &str, spec: &ClientSpec) -> NewClientRequest {
    NewClientRequest {
        id: id.to_string(),
        name: spec.name.clone(),
        confidential: spec.confidential,
        redirect_uris: spec.redirect_uris.clone(),
        post_logout_redirect_uris: opt_vec(&spec.post_logout_redirect_uris),
    }
}

fn update_client(id: &str, spec: &ClientSpec) -> UpdateClientRequest {
    UpdateClientRequest {
        id: id.to_string(),
        name: spec.name.clone(),
        confidential: spec.confidential,
        redirect_uris: spec.redirect_uris.clone(),
        post_logout_redirect_uris: opt_vec(&spec.post_logout_redirect_uris),
        allowed_origins: opt_vec(&spec.allowed_origins),
        enabled: true,
        flows_enabled: spec.flows_enabled.clone(),
        access_token_alg: "EdDSA".to_string(),
        id_token_alg: "EdDSA".to_string(),
        auth_code_lifetime: 60,
        access_token_lifetime: 3600,
        scopes: spec.scopes.clone(),
        default_scopes: spec.default_scopes.clone(),
        challenges: if spec.enable_pkce {
            Some(vec!["S256".to_string()])
        } else {
            None
        },
        force_mfa: false,
    }
}

fn client_drifted(cur: &client::ClientResponse, spec: &ClientSpec) -> bool {
    !cur.enabled
        || !same_set(&cur.redirect_uris, &spec.redirect_uris)
        || !same_set(&cur.scopes, &spec.scopes)
        || !same_set(&cur.flows_enabled, &spec.flows_enabled)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user(roles: &[&str], groups: Option<&[&str]>) -> client::UserResponse {
        client::UserResponse {
            id: "1".into(),
            email: "a@example.com".into(),
            given_name: None,
            family_name: None,
            language: Some("en".into()),
            roles: roles.iter().map(ToString::to_string).collect(),
            groups: groups.map(|g| g.iter().map(ToString::to_string).collect()),
            enabled: true,
            email_verified: false,
            user_values: client::UserValuesResponse::default(),
        }
    }

    fn spec(roles: &[&str], groups: &[&str]) -> UserSpec {
        serde_json::from_value(serde_json::json!({
            "roles": roles,
            "groups": groups,
        }))
        .unwrap()
    }

    #[test]
    fn no_drift_when_sets_match_unordered() {
        let u = user(&["a", "b"], Some(&["g1", "g2"]));
        let s = spec(&["b", "a"], &["g2", "g1"]);
        assert!(!user_drifted(&u, &s));
    }

    #[test]
    fn drift_when_roles_differ() {
        let u = user(&["a"], Some(&["g1"]));
        let s = spec(&["a", "b"], &["g1"]);
        assert!(user_drifted(&u, &s));
    }

    #[test]
    fn drift_when_group_added_to_userless_groups() {
        let u = user(&["a"], None);
        let s = spec(&["a"], &["g1"]);
        assert!(user_drifted(&u, &s));
    }

    #[test]
    fn no_drift_when_user_has_extra_unmanaged_role() {
        // The bootstrap admin carries rauthy_admin, which the spec does not
        // declare. Additive reconciliation must NOT treat that as drift.
        let u = user(&["rauthy_admin", "internal"], Some(&["internal"]));
        let s = spec(&["internal"], &["internal"]);
        assert!(!user_drifted(&u, &s));
    }

    #[test]
    fn update_preserves_unmanaged_roles_and_groups() {
        let u = user(&["rauthy_admin"], Some(&["other"]));
        let s = spec(&["internal", "bekiper"], &["internal"]);
        let upd = update_user(&u, &s);
        assert!(upd.roles.contains(&"rauthy_admin".to_string()));
        assert!(upd.roles.contains(&"internal".to_string()));
        assert!(upd.roles.contains(&"bekiper".to_string()));
        let g = upd.groups.unwrap();
        assert!(g.contains(&"other".to_string()));
        assert!(g.contains(&"internal".to_string()));
    }

    #[test]
    fn client_drift_ignores_unordered_sets() {
        let current = client::ClientResponse {
            redirect_uris: vec!["https://app/alt".to_string(), "https://app/cb".to_string()],
            scopes: vec![
                "email".to_string(),
                "openid".to_string(),
                "profile".to_string(),
            ],
            flows_enabled: vec![
                "refresh_token".to_string(),
                "authorization_code".to_string(),
            ],
            enabled: true,
        };
        let spec: ClientSpec = serde_json::from_value(serde_json::json!({
            "redirect_uris": ["https://app/cb", "https://app/alt"]
        }))
        .unwrap();

        assert!(!client_drifted(&current, &spec));
    }

    #[test]
    fn client_drift_detects_disabled_or_missing_redirect() {
        let spec: ClientSpec = serde_json::from_value(serde_json::json!({
            "redirect_uris": ["https://app/cb"]
        }))
        .unwrap();
        let disabled = client::ClientResponse {
            redirect_uris: vec!["https://app/cb".to_string()],
            scopes: vec![
                "openid".to_string(),
                "profile".to_string(),
                "email".to_string(),
            ],
            flows_enabled: vec![
                "authorization_code".to_string(),
                "refresh_token".to_string(),
            ],
            enabled: false,
        };
        assert!(client_drifted(&disabled, &spec));

        let missing_redirect = client::ClientResponse {
            enabled: true,
            redirect_uris: Vec::new(),
            ..disabled
        };
        assert!(client_drifted(&missing_redirect, &spec));
    }
}
