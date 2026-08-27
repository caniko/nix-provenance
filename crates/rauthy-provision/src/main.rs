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
use std::collections::BTreeMap;
use std::fmt::Arguments;
use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail};
use clap::Parser;
use provenance_core::password::{PasswordMarkerStore, read_password_file, secret_digest};
use provenance_core::setops::{is_subset, opt_vec, same_set, union};
use serde_json::Value;

use client::{
    ApiKeyAccessRequest, ApiKeyRequest, NewClientRequest, NewUserRequest, ProviderRequest,
    RauthyClient, ScopeRequest, UpdateClientRequest, UpdateUserRequest, UserAttributeConfigRequest,
    UserAttributeValueRequest, UserPatchRequest, UserPatchValue,
};
use rauthy_provision::state::{
    ClientSpec, ProviderSpec, ScopeSpec, State, UserAttributeSpec, UserSpec,
};

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

    /// File containing a manager API key used to mint a transient
    /// reconciliation key. Takes precedence over
    /// `RAUTHY_PROVISION_KEY_MANAGER_API_KEY`.
    #[arg(long)]
    key_manager_api_key_file: Option<PathBuf>,

    /// Manager API key used to mint a transient reconciliation key.
    #[arg(
        long,
        env = "RAUTHY_PROVISION_KEY_MANAGER_API_KEY",
        hide_env_values = true
    )]
    key_manager_api_key: Option<String>,

    /// Mint a short-lived API key for this run, reconcile with it, then delete it.
    #[arg(long)]
    transient_api_key: bool,

    /// Name of the transient reconciliation API key.
    #[arg(long)]
    transient_api_key_name: Option<String>,

    /// Transient API-key lifetime in seconds.
    #[arg(long, default_value_t = 600)]
    transient_api_key_ttl: u64,

    /// Accept invalid TLS certificates (e.g. talking to an internal endpoint
    /// with a name mismatch). Avoid in production.
    #[arg(long)]
    accept_invalid_certs: bool,

    /// Skip deletions: entities declared `present = false` are left untouched.
    #[arg(long)]
    no_auto_remove: bool,

    /// Directory used to persist password rotation markers.
    #[arg(long)]
    password_marker_dir: Option<PathBuf>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let raw = fs::read_to_string(&cli.state)
        .with_context(|| format!("reading state file {}", cli.state.display()))?;
    let state: State = serde_json::from_str(&raw)
        .with_context(|| format!("parsing state file {}", cli.state.display()))?;
    validate_state(&state)?;

    if cli.transient_api_key {
        run_with_transient_api_key(&cli, &state)
    } else {
        let api_key = provenance_core::secret::resolve(
            cli.api_key_file.as_deref(),
            cli.api_key.as_deref(),
            "API key",
            "--api-key-file",
            "RAUTHY_PROVISION_API_KEY",
        )?;
        run_with_api_key(&cli, &state, &api_key)
    }
}

/// Validate all cross-entity and credential-strategy invariants before the
/// first readiness probe or other network request.
fn validate_state(state: &State) -> Result<()> {
    for (email, spec) in &state.users {
        validate_user_credential_strategy(email, spec)?;
        if let Some(provider) = spec.required_auth_provider.as_deref()
            && !state.providers.contains_key(provider)
        {
            bail!("user {email} requires upstream provider {provider}, but it is not declared");
        }
    }
    for (id, spec) in &state.clients {
        if spec.generated_secret_file.is_some() && !spec.confidential {
            bail!(
                "client {id} sets generated_secret_file but is not confidential; \
                 Rauthy only has client secrets for confidential clients"
            );
        }
        if !spec.confidential && !spec.enable_pkce {
            bail!("public client {id} must enable PKCE");
        }
    }
    for (id, spec) in &state.providers {
        if spec.client_secret_basic && spec.client_secret_post {
            bail!("provider {id} cannot enable both client_secret_basic and client_secret_post");
        }
        if (spec.client_secret_basic || spec.client_secret_post)
            && spec.client_secret_file.is_none()
        {
            bail!("provider {id} enables client-secret auth but has no client_secret_file");
        }
    }
    Ok(())
}

fn run_with_api_key(cli: &Cli, state: &State, api_key: &str) -> Result<()> {
    let client = RauthyClient::new(&cli.url, api_key, cli.accept_invalid_certs)?;
    client
        .wait_ready(30, Duration::from_secs(2))
        .context("waiting for rauthy to be ready")?;

    reconcile(
        &client,
        state,
        cli.no_auto_remove,
        password_marker_store(cli, state)?,
    )
}

fn password_marker_store(cli: &Cli, state: &State) -> Result<PasswordMarkerStore> {
    let dir = match &cli.password_marker_dir {
        Some(path) => path.clone(),
        None => match std::env::var_os("STATE_DIRECTORY").map(PathBuf::from) {
            Some(state_dir) => state_dir.join("password-markers"),
            None if state
                .users
                .values()
                .any(|user| user.initial_password_file.is_some()) =>
            {
                bail!("password markers require --password-marker-dir or STATE_DIRECTORY")
            }
            None => std::env::temp_dir().join("rauthy-provision-password-markers-unused"),
        },
    };
    Ok(PasswordMarkerStore::new(dir))
}

fn run_with_transient_api_key(cli: &Cli, state: &State) -> Result<()> {
    if cli.transient_api_key_ttl == 0 {
        bail!("--transient-api-key-ttl must be greater than zero");
    }

    let manager_api_key = provenance_core::secret::resolve(
        cli.key_manager_api_key_file.as_deref(),
        cli.key_manager_api_key.as_deref(),
        "API key manager",
        "--key-manager-api-key-file",
        "RAUTHY_PROVISION_KEY_MANAGER_API_KEY",
    )?;
    let manager = RauthyClient::new(&cli.url, &manager_api_key, cli.accept_invalid_certs)?;
    manager
        .wait_healthy(30, Duration::from_secs(2))
        .context("waiting for rauthy to be ready")?;

    let name = cli
        .transient_api_key_name
        .clone()
        .unwrap_or_else(|| "rauthy-prov-transient".to_string());
    let exp = transient_expiry(cli.transient_api_key_ttl)?;
    log(format_args!(
        "mint transient API key {name} with ttl {}s",
        cli.transient_api_key_ttl
    ));
    manager.create_or_update_api_key(&transient_api_key_request(&name, exp))?;
    let transient_api_key = manager.rotate_api_key_secret(&name)?;

    let provision_result = run_with_api_key(cli, state, &transient_api_key);
    log(format_args!("delete transient API key {name}"));
    let cleanup_result = manager.delete_api_key(&name);

    match (provision_result, cleanup_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(provision), Ok(())) => Err(provision),
        (Ok(()), Err(cleanup)) => Err(cleanup.context("cleaning up transient Rauthy API key")),
        (Err(provision), Err(cleanup)) => Err(provision.context(format!(
            "also failed to clean up transient Rauthy API key {name}: {cleanup:#}"
        ))),
    }
}

fn transient_expiry(ttl_secs: u64) -> Result<i64> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before Unix epoch")?
        .as_secs();
    let exp = now
        .checked_add(ttl_secs)
        .ok_or_else(|| anyhow!("transient API-key expiry overflow"))?;
    i64::try_from(exp).context("transient API-key expiry does not fit in i64")
}

fn transient_api_key_request(name: &str, exp: i64) -> ApiKeyRequest {
    ApiKeyRequest {
        name: name.to_string(),
        exp: Some(exp),
        access: vec![
            access("Users", &["read", "create", "update", "delete"]),
            access("Groups", &["read", "create", "update", "delete"]),
            access("Roles", &["read", "create", "update", "delete"]),
            access("Clients", &["read", "create", "update", "delete"]),
            access("Scopes", &["read", "create", "update", "delete"]),
            access("UserAttributes", &["read", "create", "update", "delete"]),
            access("AuthProviders", &["read", "create", "update", "delete"]),
            access("Secrets", &["read", "update"]),
        ],
    }
}

fn access(group: &'static str, access_rights: &[&'static str]) -> ApiKeyAccessRequest {
    ApiKeyAccessRequest {
        group,
        access_rights: access_rights.to_vec(),
    }
}

fn reconcile(
    client: &RauthyClient,
    state: &State,
    no_auto_remove: bool,
    password_markers: PasswordMarkerStore,
) -> Result<()> {
    // Groups and roles first — users reference them by name.
    reconcile_groups(client, state, no_auto_remove)?;
    reconcile_roles(client, state, no_auto_remove)?;
    reconcile_user_attributes(client, state, no_auto_remove)?;
    reconcile_scopes(client, state, no_auto_remove)?;
    let provider_bindings = reconcile_providers(client, state, no_auto_remove)?;
    reconcile_users(
        client,
        state,
        no_auto_remove,
        &password_markers,
        &provider_bindings,
    )?;
    reconcile_clients(client, state, no_auto_remove)?;

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

fn reconcile_users(
    client: &RauthyClient,
    state: &State,
    no_auto_remove: bool,
    password_markers: &PasswordMarkerStore,
    provider_bindings: &BTreeMap<String, String>,
) -> Result<()> {
    for (email, spec) in &state.users {
        let current = client.get_user_by_email(email)?;
        match (spec.present, current) {
            (true, None) => {
                log(format_args!("create user {email}"));
                let marker_id = format!("rauthy:{email}");
                if spec.initial_password_file.is_some() {
                    password_markers.mark_pending(&marker_id)?;
                }
                client.create_user(&new_user(email, spec))?;
                if spec.preferred_username.is_some()
                    || has_declared_profile_fields(spec)
                    || !spec.attributes.is_empty()
                    || spec.initial_password_file.is_some()
                    || spec.required_auth_provider.is_some()
                {
                    let user = client.get_user_by_email(email)?.ok_or_else(|| {
                        anyhow!("Rauthy user {email} was created but could not be read back")
                    })?;
                    reconcile_user_profile_fields(client, &user, spec)?;
                    reconcile_user_preferred_username(client, &user, spec)?;
                    reconcile_user_attributes_values(client, &user, spec)?;
                    reconcile_user_initial_password_on_create(
                        client,
                        &user,
                        spec,
                        password_markers,
                    )?;
                }
                audit_required_auth_provider_after_reconcile(
                    client,
                    email,
                    spec,
                    state,
                    provider_bindings,
                )?;
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
                reconcile_user_profile_fields(client, &user, spec)?;
                reconcile_user_preferred_username(client, &user, spec)?;
                reconcile_user_attributes_values(client, &user, spec)?;
                reconcile_existing_user_initial_password(client, &user, spec, password_markers)?;
                audit_required_auth_provider_after_reconcile(
                    client,
                    email,
                    spec,
                    state,
                    provider_bindings,
                )?;
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

fn validate_user_credential_strategy(email: &str, spec: &UserSpec) -> Result<()> {
    if spec.send_password_email && spec.initial_password_file.is_some() {
        bail!("user {email} cannot set both send_password_email and initial_password_file");
    }
    if spec
        .required_auth_provider
        .as_deref()
        .is_some_and(|provider| provider.trim().is_empty())
    {
        bail!("user {email} has an empty required_auth_provider");
    }
    if spec.required_auth_provider.is_some()
        && (spec.send_password_email || spec.initial_password_file.is_some())
    {
        bail!(
            "user {email} with required_auth_provider cannot use send_password_email or initial_password_file"
        );
    }
    Ok(())
}

fn audit_required_auth_provider_after_reconcile(
    client: &RauthyClient,
    email: &str,
    spec: &UserSpec,
    state: &State,
    provider_bindings: &BTreeMap<String, String>,
) -> Result<()> {
    let Some(required_provider) = spec.required_auth_provider.as_deref() else {
        return Ok(());
    };
    let provider_spec = state.providers.get(required_provider).ok_or_else(|| {
        anyhow!(
            "user {email} requires upstream provider {required_provider}, but it is not declared"
        )
    })?;
    if !provider_spec.present {
        bail!(
            "user {email} requires upstream provider {required_provider}, but it is declared present = false"
        );
    }
    if !provider_spec.enabled {
        bail!("user {email} requires upstream provider {required_provider}, but it is disabled");
    }
    if !provider_spec.auto_link {
        bail!(
            "user {email} requires upstream provider {required_provider}, but auto_link is disabled"
        );
    }
    let canonical_provider = provider_bindings.get(required_provider).ok_or_else(|| {
        anyhow!(
            "user {email} requires upstream provider {required_provider}, but no canonical Rauthy provider was reconciled"
        )
    })?;
    let user = client
        .get_user_by_email(email)?
        .ok_or_else(|| anyhow!("Rauthy user {email} disappeared during reconciliation"))?;

    let awaiting_first_login =
        validate_required_auth_provider_user(email, required_provider, canonical_provider, &user)?;
    if awaiting_first_login {
        log(format_args!(
            "Rauthy user {email} has no local credential and is awaiting first login through provider {required_provider}"
        ));
    }
    Ok(())
}

fn validate_required_auth_provider_user(
    email: &str,
    required_provider: &str,
    canonical_provider: &str,
    user: &client::UserResponse,
) -> Result<bool> {
    if user.webauthn_user_id.is_some() {
        bail!(
            "Rauthy user {email} requires provider {required_provider}, but a WebAuthn credential is present; remove it in Rauthy before retrying"
        );
    }

    match user.account_type.as_ref() {
        Some(client::AccountType::New) => {
            if user.auth_provider_id.is_some() || user.federation_uid.is_some() {
                bail!(
                    "Rauthy user {email} reports a new account with existing federation metadata; refusing to assume it is unlinked"
                );
            }
            Ok(true)
        }
        Some(client::AccountType::Federated) => {
            match user.auth_provider_id.as_deref() {
                Some(actual) if actual == canonical_provider => {
                    if user.federation_uid.is_none() {
                        bail!(
                            "Rauthy user {email} is linked to provider {required_provider} without a federation UID"
                        );
                    }
                }
                Some(actual) => {
                    bail!(
                        "Rauthy user {email} is linked to provider {actual}, expected {required_provider} ({canonical_provider})"
                    )
                }
                None => {
                    bail!(
                        "Rauthy user {email} reports a federated account without a provider link; refusing to assume it is safe"
                    )
                }
            }
            Ok(false)
        }
        Some(account_type) => bail!(
            "Rauthy user {email} requires provider {required_provider}, but has local credential state {account_type:?}; remove the password/passkey in Rauthy before retrying"
        ),
        None => bail!(
            "Rauthy user {email} requires provider {required_provider}, but the server did not return account_type; refusing to assume it is passwordless"
        ),
    }
}

fn set_user_initial_password(
    client: &RauthyClient,
    user: &client::UserResponse,
    spec: &UserSpec,
    markers: &PasswordMarkerStore,
) -> Result<()> {
    let Some(path) = spec.initial_password_file.as_deref() else {
        return Ok(());
    };
    let password = read_password_file(path).with_context(|| {
        format!(
            "resolving initial_password_file for Rauthy user {}",
            user.email
        )
    })?;
    let marker_id = format!("rauthy:{}", user.email);
    log(format_args!(
        "set initial password for new user {}",
        user.email
    ));
    let mut update = update_user(user, spec);
    update.password = Some(password.clone());
    client.update_user(&user.id, &update)?;
    markers.commit(&marker_id, &password)?;
    markers.clear_pending(&marker_id)?;
    Ok(())
}

fn reconcile_user_initial_password_on_create(
    client: &RauthyClient,
    user: &client::UserResponse,
    spec: &UserSpec,
    markers: &PasswordMarkerStore,
) -> Result<()> {
    set_user_initial_password(client, user, spec, markers).map(|_| ())
}

fn reconcile_existing_user_initial_password(
    client: &RauthyClient,
    user: &client::UserResponse,
    spec: &UserSpec,
    markers: &PasswordMarkerStore,
) -> Result<()> {
    let Some(path) = spec.initial_password_file.as_deref() else {
        return Ok(());
    };
    let password = read_password_file(path).with_context(|| {
        format!(
            "resolving initial_password_file for Rauthy user {}",
            user.email
        )
    })?;
    let marker_id = format!("rauthy:{}", user.email);
    if markers.is_pending(&marker_id)? {
        log(format_args!(
            "complete pending initial password for existing user {}",
            user.email
        ));
        let mut update = update_user(user, spec);
        update.password = Some(password.clone());
        client.update_user(&user.id, &update)?;
        markers.commit(&marker_id, &password)?;
        markers.clear_pending(&marker_id)?;
        return Ok(());
    }
    let desired = secret_digest(&password);
    match markers.current_digest(&marker_id)? {
        None => {
            eprintln!(
                "[rauthy-provision] warning: user {} already exists; adopting initial_password_file marker without changing the existing password",
                user.email
            );
            markers.commit(&marker_id, &password)?;
        }
        Some(current) if current != desired => {
            eprintln!(
                "[rauthy-provision] warning: initial_password_file changed for existing user {}; Rauthy passwords cannot be changed declaratively; adopting new marker without changing the existing password",
                user.email
            );
            markers.commit(&marker_id, &password)?;
        }
        Some(_) => {}
    }
    Ok(())
}

fn new_user(email: &str, spec: &UserSpec) -> NewUserRequest {
    NewUserRequest {
        email: email.to_string(),
        given_name: spec.given_name.clone().flatten(),
        family_name: spec.family_name.clone().flatten(),
        language: spec.language.clone(),
        roles: spec.roles.clone(),
        groups: opt_vec(&spec.groups),
        user_expires: spec.user_expires,
    }
}

/// Roles and groups are reconciled ADDITIVELY: the tool ensures every declared
/// role/group is present but never removes ones it does not manage. This is
/// deliberate — a Rauthy user may carry roles/groups assigned out-of-band (the
/// bootstrap `rauthy_admin` role, or a manual Admin-UI assignment), and a full
/// replace would silently strip them. Profile fields are reconciled separately
/// through PATCH, and only for fields explicitly declared in state.
fn user_drifted(user: &client::UserResponse, spec: &UserSpec) -> bool {
    let cur_groups = user.groups.as_deref().unwrap_or_default();
    !is_subset(&spec.roles, &user.roles)
        || !is_subset(&spec.groups, cur_groups)
        || spec
            .user_expires
            .is_some_and(|desired| user.user_expires != Some(desired))
}

fn update_user(user: &client::UserResponse, spec: &UserSpec) -> UpdateUserRequest {
    // A PUT is a full replace, so carry unmanaged fields through and apply
    // declared profile values in the same request as role/group changes.
    // roles/groups are the UNION of current + declared so out-of-band roles
    // (e.g. rauthy_admin) survive.
    let cur_groups = user.groups.as_deref().unwrap_or_default();
    let groups = union(cur_groups, &spec.groups);
    UpdateUserRequest {
        email: user.email.clone(),
        given_name: spec
            .given_name
            .clone()
            .unwrap_or_else(|| user.given_name.clone()),
        family_name: spec
            .family_name
            .clone()
            .unwrap_or_else(|| user.family_name.clone()),
        language: user.language.clone(),
        roles: union(&user.roles, &spec.roles),
        groups: if groups.is_empty() {
            None
        } else {
            Some(groups)
        },
        enabled: user.enabled,
        email_verified: user.email_verified,
        password: None,
        user_expires: spec.user_expires.or(user.user_expires),
    }
}

fn has_declared_profile_fields(spec: &UserSpec) -> bool {
    spec.given_name.is_some()
        || spec.family_name.is_some()
        || spec.birthdate.is_some()
        || spec.timezone.is_some()
        || spec.street.is_some()
        || spec.zip.is_some()
        || spec.city.is_some()
        || spec.country.is_some()
        || spec.phone.is_some()
}

fn push_profile_field(
    put: &mut Vec<UserPatchValue>,
    del: &mut Vec<String>,
    key: &'static str,
    desired: &Option<Option<String>>,
    current: Option<&str>,
) {
    match desired {
        Some(Some(desired)) if current != Some(desired.as_str()) => put.push(UserPatchValue {
            key,
            value: Value::String(desired.clone()),
        }),
        Some(None) if current.is_some() => del.push(key.to_string()),
        _ => {}
    }
}

fn profile_patch(user: &client::UserResponse, spec: &UserSpec) -> UserPatchRequest {
    let mut put = Vec::new();
    let mut del = Vec::new();
    push_profile_field(
        &mut put,
        &mut del,
        "given_name",
        &spec.given_name,
        user.given_name.as_deref(),
    );
    push_profile_field(
        &mut put,
        &mut del,
        "family_name",
        &spec.family_name,
        user.family_name.as_deref(),
    );
    push_profile_field(
        &mut put,
        &mut del,
        "user_values.birthdate",
        &spec.birthdate,
        user.user_values.birthdate.as_deref(),
    );
    push_profile_field(
        &mut put,
        &mut del,
        "user_values.tz",
        &spec.timezone,
        user.user_values.tz.as_deref(),
    );
    push_profile_field(
        &mut put,
        &mut del,
        "user_values.street",
        &spec.street,
        user.user_values.street.as_deref(),
    );
    push_profile_field(
        &mut put,
        &mut del,
        "user_values.zip",
        &spec.zip,
        user.user_values.zip.as_deref(),
    );
    push_profile_field(
        &mut put,
        &mut del,
        "user_values.city",
        &spec.city,
        user.user_values.city.as_deref(),
    );
    push_profile_field(
        &mut put,
        &mut del,
        "user_values.country",
        &spec.country,
        user.user_values.country.as_deref(),
    );
    push_profile_field(
        &mut put,
        &mut del,
        "user_values.phone",
        &spec.phone,
        user.user_values.phone.as_deref(),
    );

    UserPatchRequest { put, del }
}

#[cfg(test)]
fn profile_fields_drifted(user: &client::UserResponse, spec: &UserSpec) -> bool {
    let patch = profile_patch(user, spec);
    !patch.put.is_empty() || !patch.del.is_empty()
}

fn reconcile_user_profile_fields(
    client: &RauthyClient,
    user: &client::UserResponse,
    spec: &UserSpec,
) -> Result<()> {
    let patch = profile_patch(user, spec);
    if !patch.put.is_empty() || !patch.del.is_empty() {
        log(format_args!("patch user {} profile fields", user.email));
        client.patch_user(&user.id, &patch)?;
    }
    Ok(())
}

fn reconcile_user_preferred_username(
    client: &RauthyClient,
    user: &client::UserResponse,
    spec: &UserSpec,
) -> Result<()> {
    let Some(desired) = &spec.preferred_username else {
        return Ok(());
    };
    let desired = desired.as_deref();
    if user.user_values.preferred_username.as_deref() != desired {
        log(format_args!(
            "update user {} preferred_username",
            user.email
        ));
        client.update_preferred_username(&user.id, desired)?;
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
        claims_at_root: spec.claims_at_root,
    }
}

fn scope_drifted(cur: &client::ScopeResponse, spec: &ScopeSpec) -> bool {
    let cur_access = cur.attr_include_access.as_deref().unwrap_or_default();
    let cur_id = cur.attr_include_id.as_deref().unwrap_or_default();
    !same_set(cur_access, &spec.attr_include_access)
        || !same_set(cur_id, &spec.attr_include_id)
        || cur.claims_at_root != spec.claims_at_root
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

fn reconcile_providers(
    client: &RauthyClient,
    state: &State,
    no_auto_remove: bool,
) -> Result<BTreeMap<String, String>> {
    if state.providers.is_empty() {
        return Ok(BTreeMap::new());
    }
    let existing = client.list_providers()?;
    for (id, spec) in &state.providers {
        let matches = matching_providers(&existing, id, spec);
        match (spec.present, matches.is_empty()) {
            (true, true) => {
                log(format_args!("create upstream provider {id}"));
                client.create_provider(&provider_request(spec)?)?;
            }
            (true, false) => {
                let linked = provider_link_counts(client, &matches)?;
                let canonical = select_canonical_provider(&matches, &linked)
                    .with_context(|| format!("selecting canonical upstream provider {id}"))?;
                if provider_drifted(canonical, spec)? {
                    log(format_args!(
                        "update upstream provider {id} using Rauthy id {}",
                        canonical.id
                    ));
                    client.update_provider(&canonical.id, &provider_request(spec)?)?;
                }
                let duplicates = duplicate_provider_ids(&matches, &canonical.id);
                if !duplicates.is_empty() {
                    if no_auto_remove {
                        log(format_args!(
                            "skip deleting duplicate upstream providers for {id}: {}",
                            duplicates.join(", ")
                        ));
                    } else {
                        for duplicate in duplicates {
                            log(format_args!(
                                "delete duplicate upstream provider {duplicate}"
                            ));
                            client.delete_provider(&duplicate)?;
                        }
                    }
                }
            }
            (false, false) if !no_auto_remove => {
                for provider in matches {
                    log(format_args!("delete upstream provider {}", provider.id));
                    client.delete_provider(&provider.id)?;
                }
            }
            _ => {}
        }
    }
    let existing = client.list_providers()?;
    let mut bindings = BTreeMap::new();
    for (id, spec) in &state.providers {
        if !spec.present {
            continue;
        }
        let matches = matching_providers(&existing, id, spec);
        let linked = provider_link_counts(client, &matches)?;
        let canonical = select_canonical_provider(&matches, &linked)
            .with_context(|| format!("resolving canonical upstream provider {id}"))?;
        bindings.insert(id.clone(), canonical.id.clone());
    }
    Ok(bindings)
}

fn matching_providers<'a>(
    existing: &'a [client::ProviderResponse],
    desired_id: &str,
    spec: &ProviderSpec,
) -> Vec<&'a client::ProviderResponse> {
    existing
        .iter()
        .filter(|provider| {
            provider.id == desired_id
                || (provider.issuer == spec.issuer && provider.client_id == spec.client_id)
        })
        .collect()
}

fn provider_link_counts(
    client: &RauthyClient,
    providers: &[&client::ProviderResponse],
) -> Result<BTreeMap<String, usize>> {
    let mut linked = BTreeMap::new();
    for provider in providers {
        let users = client.provider_linked_user_count(&provider.id)?;
        linked.insert(provider.id.clone(), users);
    }
    Ok(linked)
}

fn select_canonical_provider<'a>(
    providers: &[&'a client::ProviderResponse],
    linked: &BTreeMap<String, usize>,
) -> Result<&'a client::ProviderResponse> {
    let linked_providers = providers
        .iter()
        .copied()
        .filter(|provider| linked.get(&provider.id).copied().unwrap_or_default() > 0)
        .collect::<Vec<_>>();

    match linked_providers.as_slice() {
        [provider] => return Ok(*provider),
        [] => {}
        _ => {
            let ids = linked_providers
                .iter()
                .map(|provider| provider.id.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            bail!("multiple duplicate upstream providers have linked users: {ids}");
        }
    }

    providers
        .iter()
        .copied()
        .min_by(|a, b| a.id.cmp(&b.id))
        .ok_or_else(|| anyhow!("no matching upstream provider candidates"))
}

fn duplicate_provider_ids(
    providers: &[&client::ProviderResponse],
    canonical_id: &str,
) -> Vec<String> {
    providers
        .iter()
        .filter_map(|provider| {
            if provider.id == canonical_id {
                None
            } else {
                Some(provider.id.clone())
            }
        })
        .collect()
}

fn provider_request(spec: &ProviderSpec) -> Result<ProviderRequest> {
    let client_secret = read_optional_secret(
        spec.client_secret_file.as_deref(),
        format_args!("provider {}", spec.name),
    )?;
    if client_secret.is_none() && (spec.client_secret_basic || spec.client_secret_post) {
        anyhow::bail!(
            "provider {} enables client-secret auth but has no client_secret_file",
            spec.name
        );
    }
    Ok(ProviderRequest {
        name: spec.name.clone(),
        typ: spec.typ.clone(),
        enabled: spec.enabled,
        issuer: spec.issuer.clone(),
        authorization_endpoint: spec.authorization_endpoint.clone(),
        token_endpoint: spec.token_endpoint.clone(),
        userinfo_endpoint: spec.userinfo_endpoint.clone(),
        jwks_endpoint: spec.jwks_endpoint.clone(),
        use_pkce: spec.use_pkce,
        client_secret_basic: spec.client_secret_basic,
        client_secret_post: spec.client_secret_post,
        auto_onboarding: spec.auto_onboarding,
        auto_link: spec.auto_link,
        client_id: spec.client_id.clone(),
        client_secret,
        scope: spec.scope.clone(),
        admin_claim_path: spec.admin_claim_path.clone(),
        admin_claim_value: spec.admin_claim_value.clone(),
        mfa_claim_path: spec.mfa_claim_path.clone(),
        mfa_claim_value: spec.mfa_claim_value.clone(),
    })
}

fn read_optional_secret(path: Option<&str>, label: Arguments<'_>) -> Result<Option<String>> {
    let Some(path) = path else {
        return Ok(None);
    };
    let value = fs::read_to_string(path).with_context(|| {
        format!(
            "reading secret file {} for {label}; this must be a runtime path, not a Nix store path",
            path
        )
    })?;
    let value = value.trim_end_matches(['\r', '\n']).to_string();
    if value.is_empty() {
        anyhow::bail!("secret file {path} for {label} is empty");
    }
    Ok(Some(value))
}

fn provider_drifted(cur: &client::ProviderResponse, spec: &ProviderSpec) -> Result<bool> {
    let desired_secret = read_optional_secret(
        spec.client_secret_file.as_deref(),
        format_args!("provider {}", spec.name),
    )?;
    Ok(cur.name != spec.name
        || cur.typ != spec.typ
        || cur.enabled != spec.enabled
        || cur.issuer != spec.issuer
        || cur.authorization_endpoint != spec.authorization_endpoint
        || cur.token_endpoint != spec.token_endpoint
        || cur.userinfo_endpoint != spec.userinfo_endpoint
        || cur.jwks_endpoint != spec.jwks_endpoint
        || cur.client_id != spec.client_id
        || cur.client_secret != desired_secret
        || cur.scope.split('+').collect::<Vec<_>>().join(" ") != spec.scope
        || cur.admin_claim_path != spec.admin_claim_path
        || cur.admin_claim_value != spec.admin_claim_value
        || cur.mfa_claim_path != spec.mfa_claim_path
        || cur.mfa_claim_value != spec.mfa_claim_value
        || cur.use_pkce != spec.use_pkce
        || cur.client_secret_basic != spec.client_secret_basic
        || cur.client_secret_post != spec.client_secret_post
        || cur.auto_onboarding != spec.auto_onboarding
        || cur.auto_link != spec.auto_link)
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
            Some(desired_client_challenges(spec))
        } else {
            None
        },
        force_mfa: false,
    }
}

fn desired_client_challenges(spec: &ClientSpec) -> Vec<String> {
    if spec.enable_pkce {
        vec!["S256".to_string()]
    } else {
        Vec::new()
    }
}

fn client_drifted(cur: &client::ClientResponse, spec: &ClientSpec) -> bool {
    let cur_challenges = cur.challenges.as_deref().unwrap_or(&[]);
    let desired_challenges = desired_client_challenges(spec);

    !cur.enabled
        || !same_set(&cur.redirect_uris, &spec.redirect_uris)
        || !same_set(
            &cur.post_logout_redirect_uris,
            &spec.post_logout_redirect_uris,
        )
        || !same_set(&cur.allowed_origins, &spec.allowed_origins)
        || !same_set(&cur.scopes, &spec.scopes)
        || !same_set(&cur.flows_enabled, &spec.flows_enabled)
        || !same_set(cur_challenges, &desired_challenges)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::{Arc, Mutex};
    use std::thread;

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
            user_expires: None,
            user_values: client::UserValuesResponse::default(),
            account_type: None,
            webauthn_user_id: None,
            auth_provider_id: None,
            federation_uid: None,
        }
    }

    fn provider(id: &str, issuer: &str, client_id: &str) -> client::ProviderResponse {
        client::ProviderResponse {
            id: id.into(),
            name: "Kanidm".into(),
            typ: "oidc".into(),
            enabled: true,
            issuer: issuer.into(),
            authorization_endpoint: format!("{issuer}/ui/oauth2"),
            token_endpoint: format!("{issuer}/oauth2/token"),
            userinfo_endpoint: format!("{issuer}/userinfo"),
            jwks_endpoint: Some(format!("{issuer}/public_key.jwk")),
            client_id: client_id.into(),
            client_secret: Some("secret".into()),
            scope: "openid+email+profile".into(),
            admin_claim_path: None,
            admin_claim_value: None,
            mfa_claim_path: None,
            mfa_claim_value: None,
            use_pkce: true,
            client_secret_basic: true,
            client_secret_post: false,
            auto_onboarding: false,
            auto_link: true,
        }
    }

    fn provider_spec(issuer: &str, client_id: &str) -> ProviderSpec {
        serde_json::from_value(serde_json::json!({
            "name": "Kanidm",
            "issuer": issuer,
            "authorization_endpoint": format!("{issuer}/ui/oauth2"),
            "token_endpoint": format!("{issuer}/oauth2/token"),
            "userinfo_endpoint": format!("{issuer}/userinfo"),
            "jwks_endpoint": format!("{issuer}/public_key.jwk"),
            "client_id": client_id,
            "scope": "openid email profile",
            "client_secret_file": null,
            "client_secret_basic": false,
            "auto_link": true
        }))
        .unwrap()
    }

    fn spec(roles: &[&str], groups: &[&str]) -> UserSpec {
        serde_json::from_value(serde_json::json!({
            "roles": roles,
            "groups": groups,
        }))
        .unwrap()
    }

    #[test]
    fn user_update_applies_declared_profile_fields() {
        let mut current = user(&[], Some(&["staff"]));
        current.given_name = Some("Upstream".into());
        current.family_name = Some("Invalid. Upstream".into());
        let desired: UserSpec = serde_json::from_value(serde_json::json!({
            "given_name": "Can",
            "family_name": "Tartanoglu",
            "groups": ["pink-raven"]
        }))
        .unwrap();

        let update = update_user(&current, &desired);

        assert_eq!(update.given_name.as_deref(), Some("Can"));
        assert_eq!(update.family_name.as_deref(), Some("Tartanoglu"));
        assert_eq!(
            update.groups,
            Some(vec!["staff".into(), "pink-raven".into()])
        );
    }

    #[test]
    fn validate_state_rejects_public_clients_without_pkce() {
        let state: State = serde_json::from_value(serde_json::json!({
            "clients": {
                "public": { "confidential": false, "enable_pkce": false }
            }
        }))
        .unwrap();

        let err = validate_state(&state).unwrap_err();
        assert!(err.to_string().contains("must enable PKCE"));
    }

    #[test]
    fn validate_state_rejects_duplicate_provider_auth_modes() {
        let state: State = serde_json::from_value(serde_json::json!({
            "providers": {
                "id": {
                    "name": "provider",
                    "issuer": "https://id.example",
                    "authorization_endpoint": "https://id.example/auth",
                    "token_endpoint": "https://id.example/token",
                    "userinfo_endpoint": "https://id.example/userinfo",
                    "client_id": "kanidm-client",
                    "client_secret_basic": true,
                    "client_secret_post": true,
                    "client_secret_file": "/run/credentials/secret"
                }
            }
        }))
        .unwrap();

        let err = validate_state(&state).unwrap_err();
        assert!(err.to_string().contains("both client_secret_basic"));
    }

    #[test]
    fn initial_password_file_conflicts_with_set_password_email() {
        let s: UserSpec = serde_json::from_value(serde_json::json!({
            "send_password_email": true,
            "password_email_redirect_uri": "https://app.example.com/login",
            "initial_password_file": "/run/credentials/rauthy-provision.service/password-a"
        }))
        .unwrap();

        let err = validate_user_credential_strategy("a@example.com", &s).unwrap_err();
        assert!(err.to_string().contains("cannot set both"));
    }

    #[test]
    fn required_auth_provider_conflicts_with_local_credential_strategy() {
        let s: UserSpec = serde_json::from_value(serde_json::json!({
            "required_auth_provider": "kanidm",
            "initial_password_file": "/run/credentials/rauthy-provision.service/password-a"
        }))
        .unwrap();

        let err = validate_user_credential_strategy("a@example.com", &s).unwrap_err();
        assert!(err.to_string().contains("required_auth_provider"));
    }

    #[test]
    fn required_auth_provider_rejects_local_passwords() {
        let mut current = user(&[], None);
        current.account_type = Some(client::AccountType::Password);

        let err = validate_required_auth_provider_user(
            "a@example.com",
            "kanidm",
            "provider-id",
            &current,
        )
        .unwrap_err();
        assert!(err.to_string().contains("local credential state"));
    }

    #[test]
    fn required_auth_provider_rejects_wrong_federated_provider() {
        let mut current = user(&[], None);
        current.account_type = Some(client::AccountType::Federated);
        current.auth_provider_id = Some("other-provider".into());
        current.federation_uid = Some("federated-user".into());

        let err = validate_required_auth_provider_user(
            "a@example.com",
            "kanidm",
            "provider-id",
            &current,
        )
        .unwrap_err();
        assert!(err.to_string().contains("expected kanidm"));
    }

    #[test]
    fn required_auth_provider_accepts_unlinked_and_linked_users() {
        let mut new_user = user(&[], None);
        new_user.account_type = Some(client::AccountType::New);
        assert!(
            validate_required_auth_provider_user(
                "a@example.com",
                "kanidm",
                "provider-id",
                &new_user,
            )
            .unwrap()
        );

        let mut federated_user = user(&[], None);
        federated_user.account_type = Some(client::AccountType::Federated);
        federated_user.auth_provider_id = Some("provider-id".into());
        federated_user.federation_uid = Some("federated-user".into());
        assert!(
            !validate_required_auth_provider_user(
                "a@example.com",
                "kanidm",
                "provider-id",
                &federated_user,
            )
            .unwrap()
        );
    }

    fn empty_state_file(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "rauthy-provision-{name}-{}.json",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::write(
            &path,
            r#"{"groups":{},"roles":{},"scopes":{},"user_attributes":{},"users":{},"clients":{},"providers":{}}"#,
        )
        .unwrap();
        path
    }

    fn handle_mock_request(mut stream: TcpStream, requests: Arc<Mutex<Vec<String>>>) {
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut first = String::new();
        reader.read_line(&mut first).unwrap();
        let first = first.trim().to_string();
        requests.lock().unwrap().push(first.clone());

        let mut status = "200 OK";
        let mut body = "";
        if first.starts_with("PUT /auth/v1/api_keys/rauthy-prov-transient/secret ") {
            body = "rauthy-prov-transient$secret";
        } else if first.starts_with("GET /auth/v1/groups ") {
            body = "[]";
        } else if first.starts_with("GET /auth/v1/roles ") {
            status = "500 Internal Server Error";
            body = "role failure";
        }

        write!(
            stream,
            "HTTP/1.1 {status}\r\nContent-Length: {}\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
        .unwrap();
    }

    fn start_mock_rauthy(requests: Arc<Mutex<Vec<String>>>) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        thread::spawn(move || {
            for stream in listener.incoming().take(8) {
                handle_mock_request(stream.unwrap(), requests.clone());
            }
        });
        format!("http://{addr}")
    }

    #[test]
    fn provider_matching_keeps_exact_id_and_identity_duplicates_together() {
        let spec = provider_spec("https://auth.example/oauth2/openid/rauthy", "rauthy");
        let providers = [
            provider("kanidm", "https://different.example", "other"),
            provider(
                "random",
                "https://auth.example/oauth2/openid/rauthy",
                "rauthy",
            ),
        ];

        let matches = matching_providers(&providers, "kanidm", &spec);
        assert_eq!(matches.len(), 2);
        assert!(matches.iter().any(|p| p.id == "kanidm"));
        assert!(matches.iter().any(|p| p.id == "random"));
    }

    #[test]
    fn provider_matching_falls_back_to_issuer_and_client_id() {
        let spec = provider_spec("https://auth.example/oauth2/openid/rauthy", "rauthy");
        let providers = [
            provider(
                "random-a",
                "https://auth.example/oauth2/openid/rauthy",
                "rauthy",
            ),
            provider("random-b", "https://other.example", "rauthy"),
        ];

        let matches = matching_providers(&providers, "kanidm", &spec);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].id, "random-a");
    }

    #[test]
    fn provider_canonical_uses_lexicographic_id_when_unlinked() {
        let providers = [
            provider(
                "z-random",
                "https://auth.example/oauth2/openid/rauthy",
                "rauthy",
            ),
            provider(
                "a-random",
                "https://auth.example/oauth2/openid/rauthy",
                "rauthy",
            ),
        ];
        let matches = providers.iter().collect::<Vec<_>>();
        let linked = BTreeMap::from([("z-random".to_string(), 0), ("a-random".to_string(), 0)]);

        let canonical = select_canonical_provider(&matches, &linked).unwrap();
        assert_eq!(canonical.id, "a-random");
        assert_eq!(
            duplicate_provider_ids(&matches, &canonical.id),
            vec!["z-random"]
        );
    }

    #[test]
    fn provider_canonical_preserves_single_linked_duplicate() {
        let providers = [
            provider(
                "a-random",
                "https://auth.example/oauth2/openid/rauthy",
                "rauthy",
            ),
            provider(
                "z-linked",
                "https://auth.example/oauth2/openid/rauthy",
                "rauthy",
            ),
        ];
        let matches = providers.iter().collect::<Vec<_>>();
        let linked = BTreeMap::from([("a-random".to_string(), 0), ("z-linked".to_string(), 2)]);

        let canonical = select_canonical_provider(&matches, &linked).unwrap();
        assert_eq!(canonical.id, "z-linked");
        assert_eq!(
            duplicate_provider_ids(&matches, &canonical.id),
            vec!["a-random"]
        );
    }

    #[test]
    fn provider_canonical_fails_when_multiple_duplicates_are_linked() {
        let providers = [
            provider(
                "a-linked",
                "https://auth.example/oauth2/openid/rauthy",
                "rauthy",
            ),
            provider(
                "z-linked",
                "https://auth.example/oauth2/openid/rauthy",
                "rauthy",
            ),
        ];
        let matches = providers.iter().collect::<Vec<_>>();
        let linked = BTreeMap::from([("a-linked".to_string(), 1), ("z-linked".to_string(), 2)]);

        let err = select_canonical_provider(&matches, &linked).unwrap_err();
        assert!(
            err.to_string()
                .contains("multiple duplicate upstream providers have linked users")
        );
    }

    #[test]
    fn transient_api_key_request_uses_reconciliation_rights_only() {
        let req = transient_api_key_request("rauthy-prov-transient", 123);
        assert_eq!(req.name, "rauthy-prov-transient");
        assert_eq!(req.exp, Some(123));
        assert!(req.access.iter().any(|a| a.group == "Users"));
        assert!(req.access.iter().any(|a| a.group == "Secrets"));
        assert!(!req.access.iter().any(|a| a.group == "ApiKeys"));
    }

    #[test]
    fn transient_api_key_is_deleted_when_reconcile_fails() {
        let requests = Arc::new(Mutex::new(Vec::new()));
        let url = start_mock_rauthy(requests.clone());
        let state = empty_state_file("transient-cleanup");
        let cli = Cli {
            url,
            state: state.clone(),
            api_key_file: None,
            api_key: None,
            key_manager_api_key_file: None,
            key_manager_api_key: Some("manager$key".to_string()),
            transient_api_key: true,
            transient_api_key_name: Some("rauthy-prov-transient".to_string()),
            transient_api_key_ttl: 600,
            accept_invalid_certs: false,
            no_auto_remove: false,
            password_marker_dir: Some(std::env::temp_dir()),
        };

        let err = run_with_transient_api_key(&cli, &State::default()).unwrap_err();
        assert!(err.to_string().contains("requesting Rauthy roles"));
        let requests = requests.lock().unwrap();
        assert!(
            requests
                .iter()
                .any(|r| r.starts_with("POST /auth/v1/api_keys "))
        );
        assert!(
            requests
                .iter()
                .any(|r| r.starts_with("PUT /auth/v1/api_keys/rauthy-prov-transient/secret "))
        );
        assert!(
            requests
                .iter()
                .any(|r| r.starts_with("DELETE /auth/v1/api_keys/rauthy-prov-transient "))
        );
        fs::remove_file(state).unwrap();
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
    fn user_drift_profile_fields_only_when_declared_fields_differ() {
        let mut u = user(&["a"], Some(&["g1"]));
        u.given_name = Some("Live".to_string());
        u.user_values.birthdate = Some("2000-01-01".to_string());
        u.user_values.phone = Some("+4711111111".to_string());

        let unmanaged = spec(&["a"], &["g1"]);
        assert!(!profile_fields_drifted(&u, &unmanaged));

        let same_declared: UserSpec = serde_json::from_value(serde_json::json!({
            "roles": ["a"],
            "groups": ["g1"],
            "birthdate": "2000-01-01"
        }))
        .unwrap();
        assert!(!profile_fields_drifted(&u, &same_declared));

        let changed_declared: UserSpec = serde_json::from_value(serde_json::json!({
            "roles": ["a"],
            "groups": ["g1"],
            "birthdate": "2001-02-03"
        }))
        .unwrap();
        assert!(profile_fields_drifted(&u, &changed_declared));

        let clear_declared: UserSpec = serde_json::from_value(serde_json::json!({
            "roles": ["a"],
            "groups": ["g1"],
            "birthdate": null
        }))
        .unwrap();
        assert!(profile_fields_drifted(&u, &clear_declared));
    }

    #[test]
    fn profile_patch_uses_rauthy_user_values_keys() {
        let mut u = user(&["a"], Some(&["g1"]));
        u.given_name = Some("Old".to_string());
        u.user_values.zip = Some("00000".to_string());

        let s: UserSpec = serde_json::from_value(serde_json::json!({
            "roles": ["a"],
            "groups": ["g1"],
            "given_name": "Alice",
            "family_name": "Smith",
            "birthdate": "1984-01-02",
            "timezone": "Europe/Oslo",
            "street": "Example Street 1",
            "zip": "12345",
            "city": "Oslo",
            "country": "Norway",
            "phone": "+4712345678"
        }))
        .unwrap();

        let patch = serde_json::to_value(profile_patch(&u, &s)).unwrap();
        assert_eq!(patch["del"], serde_json::json!([]));
        assert_eq!(
            patch["put"],
            serde_json::json!([
                {"key": "given_name", "value": "Alice"},
                {"key": "family_name", "value": "Smith"},
                {"key": "user_values.birthdate", "value": "1984-01-02"},
                {"key": "user_values.tz", "value": "Europe/Oslo"},
                {"key": "user_values.street", "value": "Example Street 1"},
                {"key": "user_values.zip", "value": "12345"},
                {"key": "user_values.city", "value": "Oslo"},
                {"key": "user_values.country", "value": "Norway"},
                {"key": "user_values.phone", "value": "+4712345678"}
            ])
        );
    }

    #[test]
    fn profile_patch_deletes_explicitly_cleared_fields_only_when_present() {
        let mut u = user(&["a"], Some(&["g1"]));
        u.given_name = Some("Old".to_string());
        u.user_values.birthdate = Some("2000-01-01".to_string());

        let s: UserSpec = serde_json::from_value(serde_json::json!({
            "given_name": null,
            "family_name": null,
            "birthdate": null,
            "timezone": null
        }))
        .unwrap();

        let patch = serde_json::to_value(profile_patch(&u, &s)).unwrap();
        assert_eq!(patch["put"], serde_json::json!([]));
        assert_eq!(
            patch["del"],
            serde_json::json!(["given_name", "user_values.birthdate"])
        );
    }

    #[test]
    fn user_expires_is_declared_only_drift_and_update_preserves_when_unmanaged() {
        let mut u = user(&["a"], Some(&["g1"]));
        u.user_expires = Some(1893456000);

        let unmanaged = spec(&["a"], &["g1"]);
        assert!(!user_drifted(&u, &unmanaged));
        assert_eq!(update_user(&u, &unmanaged).user_expires, Some(1893456000));

        let same: UserSpec = serde_json::from_value(serde_json::json!({
            "roles": ["a"],
            "groups": ["g1"],
            "user_expires": 1893456000
        }))
        .unwrap();
        assert!(!user_drifted(&u, &same));

        let changed: UserSpec = serde_json::from_value(serde_json::json!({
            "roles": ["a"],
            "groups": ["g1"],
            "user_expires": 1893542400
        }))
        .unwrap();
        assert!(user_drifted(&u, &changed));
        assert_eq!(update_user(&u, &changed).user_expires, Some(1893542400));
    }

    #[test]
    fn update_preserves_unmanaged_roles_and_groups() {
        let u = user(&["rauthy_admin"], Some(&["other"]));
        let s = spec(&["internal", "bekiper"], &["internal"]);
        let upd = update_user(&u, &s);
        assert!(upd.roles.contains(&"rauthy_admin".to_string()));
        assert!(upd.roles.contains(&"internal".to_string()));
        assert!(upd.roles.contains(&"bekiper".to_string()));
        assert!(upd.password.is_none());
        let g = upd.groups.unwrap();
        assert!(g.contains(&"other".to_string()));
        assert!(g.contains(&"internal".to_string()));
    }

    #[test]
    fn client_drift_ignores_unordered_sets() {
        let current = client::ClientResponse {
            redirect_uris: vec!["https://app/alt".to_string(), "https://app/cb".to_string()],
            post_logout_redirect_uris: vec![],
            allowed_origins: vec![],
            scopes: vec![
                "email".to_string(),
                "openid".to_string(),
                "profile".to_string(),
            ],
            flows_enabled: vec![
                "refresh_token".to_string(),
                "authorization_code".to_string(),
            ],
            challenges: Some(vec!["S256".to_string()]),
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
            post_logout_redirect_uris: vec![],
            allowed_origins: vec![],
            scopes: vec![
                "openid".to_string(),
                "profile".to_string(),
                "email".to_string(),
            ],
            flows_enabled: vec![
                "authorization_code".to_string(),
                "refresh_token".to_string(),
            ],
            challenges: Some(vec!["S256".to_string()]),
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

    #[test]
    fn client_drift_detects_pkce_challenge_change() {
        let current = client::ClientResponse {
            enabled: true,
            redirect_uris: vec!["https://app/cb".to_string()],
            post_logout_redirect_uris: vec![],
            allowed_origins: vec![],
            scopes: vec![
                "openid".to_string(),
                "profile".to_string(),
                "email".to_string(),
            ],
            flows_enabled: vec![
                "authorization_code".to_string(),
                "refresh_token".to_string(),
            ],
            challenges: Some(vec!["S256".to_string()]),
        };
        let spec: ClientSpec = serde_json::from_value(serde_json::json!({
            "redirect_uris": ["https://app/cb"],
            "enable_pkce": false
        }))
        .unwrap();

        assert!(client_drifted(&current, &spec));

        let current = client::ClientResponse {
            challenges: None,
            ..current
        };
        assert!(!client_drifted(&current, &spec));
    }

    #[test]
    fn client_drift_detects_logout_and_origin_changes() {
        let current = client::ClientResponse {
            enabled: true,
            redirect_uris: vec!["https://app/cb".to_string()],
            post_logout_redirect_uris: vec![],
            allowed_origins: vec![],
            scopes: vec![
                "openid".to_string(),
                "profile".to_string(),
                "email".to_string(),
            ],
            flows_enabled: vec![
                "authorization_code".to_string(),
                "refresh_token".to_string(),
            ],
            challenges: Some(vec!["S256".to_string()]),
        };
        let spec: ClientSpec = serde_json::from_value(serde_json::json!({
            "redirect_uris": ["https://app/cb"],
            "post_logout_redirect_uris": ["https://app/"],
            "allowed_origins": ["https://app"]
        }))
        .unwrap();

        assert!(client_drifted(&current, &spec));
    }

    #[test]
    fn disabled_pkce_serializes_null_challenges_for_update() {
        let spec: ClientSpec = serde_json::from_value(serde_json::json!({
            "redirect_uris": ["https://app/cb"],
            "enable_pkce": false
        }))
        .unwrap();
        let value = serde_json::to_value(update_client("app", &spec)).unwrap();

        assert!(value.get("challenges").is_some());
        assert!(value["challenges"].is_null());
    }
}
