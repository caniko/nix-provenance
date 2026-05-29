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

use std::fs;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;

use client::{
    NewClientRequest, NewUserRequest, RauthyClient, UpdateClientRequest, UpdateUserRequest,
};
use state::{ClientSpec, State, UserSpec};

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

    let api_key = resolve_api_key(&cli)?;
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
    reconcile_users(&client, &state, cli.no_auto_remove)?;
    reconcile_clients(&client, &state, cli.no_auto_remove)?;

    log("done");
    Ok(())
}

fn resolve_api_key(cli: &Cli) -> Result<String> {
    if let Some(path) = &cli.api_key_file {
        let raw = fs::read_to_string(path)
            .with_context(|| format!("reading API key file {}", path.display()))?;
        let key = raw.trim().to_string();
        if key.is_empty() {
            bail!("API key file {} is empty", path.display());
        }
        return Ok(key);
    }
    cli.api_key
        .clone()
        .map(|k| k.trim().to_string())
        .filter(|k| !k.is_empty())
        .ok_or_else(|| {
            anyhow!("no API key: pass --api-key-file or set RAUTHY_PROVISION_API_KEY")
        })
}

fn log(msg: impl AsRef<str>) {
    eprintln!("[rauthy-provision] {}", msg.as_ref());
}

fn reconcile_groups(client: &RauthyClient, state: &State, no_auto_remove: bool) -> Result<()> {
    let existing = client.list_groups()?;
    for (name, spec) in &state.groups {
        let found = existing.iter().find(|g| &g.name == name);
        match (spec.present, found) {
            (true, None) => {
                log(format!("create group {name}"));
                client.create_group(name)?;
            }
            (false, Some(g)) if !no_auto_remove => {
                log(format!("delete group {name}"));
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
                log(format!("create role {name}"));
                client.create_role(name)?;
            }
            (false, Some(r)) if !no_auto_remove => {
                log(format!("delete role {name}"));
                client.delete_role(&r.id)?;
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
                log(format!("create user {email}"));
                client.create_user(&new_user(email, spec))?;
            }
            (true, Some(user)) => {
                if user_drifted(&user, spec) {
                    log(format!("update user {email} (roles/groups)"));
                    client.update_user(&user.id, &update_user(&user, spec))?;
                }
            }
            (false, Some(user)) if !no_auto_remove => {
                log(format!("delete user {email}"));
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

/// Only `roles` and `groups` are reconciled on update — names and language are
/// applied at creation only, so upstream profile-claim sync is never fought.
fn user_drifted(user: &client::UserResponse, spec: &UserSpec) -> bool {
    let cur_groups = user.groups.clone().unwrap_or_default();
    !same_set(&user.roles, &spec.roles) || !same_set(&cur_groups, &spec.groups)
}

fn update_user(user: &client::UserResponse, spec: &UserSpec) -> UpdateUserRequest {
    // Carry the current name/language/enabled/email_verified through unchanged;
    // a PUT is a full replace, so omitting them would reset server-side values.
    UpdateUserRequest {
        email: user.email.clone(),
        given_name: user.given_name.clone(),
        family_name: user.family_name.clone(),
        language: user.language.clone(),
        roles: spec.roles.clone(),
        groups: opt_vec(&spec.groups),
        enabled: user.enabled,
        email_verified: user.email_verified,
    }
}

fn reconcile_clients(client: &RauthyClient, state: &State, no_auto_remove: bool) -> Result<()> {
    for (id, spec) in &state.clients {
        let current = client.get_client(id)?;
        match (spec.present, current) {
            (true, None) => {
                log(format!("create client {id}"));
                client.create_client(&new_client(id, spec))?;
                // POST sets only id/name/confidential/redirect_uris; the full
                // config (scopes, flows, PKCE) must follow via PUT.
                client.update_client(id, &update_client(id, spec))?;
            }
            (true, Some(cur)) => {
                if client_drifted(&cur, spec) {
                    log(format!("update client {id}"));
                    client.update_client(id, &update_client(id, spec))?;
                }
            }
            (false, Some(_)) if !no_auto_remove => {
                log(format!("delete client {id}"));
                client.delete_client(id)?;
            }
            (false, _) => {}
        }
    }
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

fn opt_vec(v: &[String]) -> Option<Vec<String>> {
    if v.is_empty() {
        None
    } else {
        Some(v.to_vec())
    }
}

/// Order-insensitive equality of two string collections.
fn same_set(a: &[String], b: &[String]) -> bool {
    let mut a: Vec<&String> = a.iter().collect();
    let mut b: Vec<&String> = b.iter().collect();
    a.sort();
    b.sort();
    a == b
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
}
