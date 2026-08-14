use std::fmt;
use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use std::fmt::Display;

use anyhow::{Context, Result, anyhow, bail};
use kanidm_client::KanidmClientBuilder;
use kanidm_proto::internal::{CURegState, CUStatus, TotpAlgo, TotpSecret};
use provenance_core::generated_secret::{GeneratedSecretStore, SecretFileStatus, SecretSource};
use rand::distr::{Alphanumeric, SampleString};
use serde::Serialize;
use tokio::time::{Duration, sleep};
use totp_rs::{Algorithm, TOTP};
use zeroize::{Zeroize, Zeroizing};

const IDM_ADMIN: &str = "idm_admin";
const ADMIN: &str = "admin";
const GENERATED_PASSWORD_LEN: usize = 24;
const TOTP_LABEL: &str = "identity-cli";

/// Shared Kanidm connection and authentication settings.
#[derive(Debug, Clone)]
pub struct ClientConfig {
    /// Kanidm base URL.
    pub url: String,
    /// Path containing the `idm_admin` password.
    pub idm_admin_password_file: String,
    /// Optional path containing the `admin` password, required only for
    /// domain-level operations (e.g. `set-ldap-unix-bind`) that `idm_admin`
    /// cannot perform — kanidm's ACPs hide the domain entry from `idm_admin`,
    /// so those operations must authenticate as `admin`.
    pub admin_password_file: Option<String>,
}

impl ClientConfig {
    /// Build a config for an explicit Kanidm URL.
    pub fn new(url: String, idm_admin_password_file: String) -> Self {
        Self {
            url,
            idm_admin_password_file,
            admin_password_file: None,
        }
    }
}

/// Inputs for `identity-cli kanidm provision`.
#[derive(Debug, Clone)]
pub struct ProvisionRequest {
    /// Target account name.
    pub account: String,
    /// Enroll TOTP and backup codes with the primary credential.
    pub with_totp: bool,
    /// Optional path containing the desired POSIX/LDAP password.
    pub posix_password_file: Option<String>,
    /// Optional path containing the desired primary Kanidm password.
    pub primary_password_file: Option<String>,
}

/// Provisioned credential material emitted explicitly to stdout.
#[derive(Clone, Serialize, Zeroize)]
#[zeroize(drop)]
pub struct ProvisionResult {
    /// Target account name.
    pub account: String,
    /// Primary Kanidm password set during credential update.
    pub primary_password: String,
    /// POSIX password used by LDAP/mail binds.
    pub posix_password: String,
    /// TOTP provisioning URI, present only when TOTP enrollment was requested.
    pub totp_uri: Option<String>,
    /// Backup codes generated during TOTP enrollment.
    pub backup_codes: Vec<String>,
}

/// Result of reconciling a Kanidm OAuth2 basic secret with its local runtime
/// artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OAuth2SecretAction {
    /// The provider and local artifact already matched.
    Unchanged,
    /// The local artifact was initialized from the explicitly supplied legacy
    /// file and matched the provider value.
    Adopted,
    /// The local artifact was recreated or updated from the provider value.
    Recovered,
    /// The provider secret was reset and the new value was persisted locally.
    Rotated,
}

impl OAuth2SecretAction {
    /// Stable machine-readable action name for service logs.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unchanged => "unchanged",
            Self::Adopted => "adopted",
            Self::Recovered => "recovered",
            Self::Rotated => "rotated",
        }
    }
}

impl fmt::Debug for ProvisionResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProvisionResult")
            .field("account", &self.account)
            .field("primary_password", &"<redacted>")
            .field("posix_password", &"<redacted>")
            .field("totp_uri", &self.totp_uri.as_ref().map(|_| "<redacted>"))
            .field("backup_codes", &"<redacted>")
            .finish()
    }
}

/// Provision primary, optional TOTP/backup codes, and POSIX credentials.
pub async fn provision(
    config: &ClientConfig,
    request: ProvisionRequest,
) -> Result<ProvisionResult> {
    let client = authenticated_client(config).await?;
    let primary_password = secret_from_file_or_generated(request.primary_password_file.as_deref())
        .context("resolving primary password")?;
    let posix_password = secret_from_file_or_generated(request.posix_password_file.as_deref())
        .context("resolving posix password")?;

    let (session_token, _status) = client
        .idm_account_credential_update_begin(&request.account)
        .await
        .kanidm_context(format!(
            "beginning credential update for {}",
            request.account
        ))?;

    client
        .idm_account_credential_update_set_password(&session_token, &primary_password)
        .await
        .kanidm_context(format!("setting primary password for {}", request.account))?;

    let mut totp_uri = None;
    let mut backup_codes = Vec::new();
    if request.with_totp {
        let totp_secret = enroll_totp(&client, &session_token).await?;
        totp_uri = Some(totp_secret.to_uri());
        backup_codes = generate_backup_codes(&client, &session_token).await?;
    }

    let status = client
        .idm_account_credential_update_status(&session_token)
        .await
        .kanidm_context(format!(
            "checking credential update status for {}",
            request.account
        ))?;
    ensure_can_commit(&status)?;

    client
        .idm_account_credential_update_commit(&session_token)
        .await
        .kanidm_context(format!(
            "committing credential update for {}",
            request.account
        ))?;

    client
        .idm_person_account_unix_cred_put(&request.account, &posix_password)
        .await
        .kanidm_context(format!("setting POSIX password for {}", request.account))?;

    Ok(ProvisionResult {
        account: request.account,
        primary_password,
        posix_password,
        totp_uri,
        backup_codes,
    })
}

/// Toggle whether LDAP accepts Kanidm POSIX passwords for bind.
///
/// This mutates the kanidm *domain* entry, which `idm_admin` cannot see or
/// modify (kanidm returns `404 NoMatchingEntries`). It must authenticate as
/// `admin`, so `ClientConfig::admin_password_file` is required.
pub async fn set_ldap_unix_bind(config: &ClientConfig, enable: bool) -> Result<()> {
    let client = authenticated_admin_client(config).await?;
    client
        .idm_set_ldap_allow_unix_password_bind(enable)
        .await
        .kanidm_context("setting ldap allow unix password bind")
}

/// Set only the POSIX (unix) password for a person, without touching the
/// primary credential.
///
/// Unlike [`provision`], this never opens a credential-update session, so it is
/// not subject to the account's MFA policy (a password-only primary commit is
/// rejected with `MfaRequired` on MFA-required accounts). The POSIX credential
/// is single-factor by design and is what kanidm's LDAP unix-password bind
/// checks, so this is the correct path for LDAP/mail auth on MFA-required
/// accounts.
pub async fn set_posix_password(
    config: &ClientConfig,
    account: &str,
    posix_password_file: &str,
) -> Result<()> {
    let password = read_secret_file(posix_password_file)
        .with_context(|| format!("reading posix password file {posix_password_file}"))?;
    let client = authenticated_client(config).await?;
    client
        .idm_person_account_unix_cred_put(account, &password)
        .await
        .kanidm_context(format!("setting POSIX password for {account}"))
}

/// Set a person's primary credential only when no primary credential exists.
///
/// Returns `true` when the password was set, and `false` when Kanidm already
/// reports an existing credential. Existing credentials are intentionally left
/// untouched so passkey/TOTP enrollment remains authoritative in Kanidm.
pub async fn set_initial_primary_password(
    config: &ClientConfig,
    account: &str,
    primary_password_file: &str,
) -> Result<bool> {
    let password = read_secret_file(primary_password_file).with_context(|| {
        format!("reading initial primary password file {primary_password_file}")
    })?;
    let client = authenticated_client(config).await?;
    let status = client
        .idm_person_account_get_credential_status(account)
        .await;

    match status {
        Ok(status) if !status.creds.is_empty() => return Ok(false),
        Ok(_) => {}
        Err(kanidm_client::ClientError::EmptyResponse) => {}
        Err(err) => return Err(anyhow!("reading credential status for {account}: {err:?}")),
    }

    client
        .idm_person_account_primary_credential_set_password(account, &password)
        .await
        .kanidm_context(format!("setting initial primary password for {account}"))?;
    Ok(true)
}

/// Ensure a person's tagged SSH public key matches the declared OpenSSH key.
pub async fn ensure_ssh_public_key(
    config: &ClientConfig,
    account: &str,
    tag: &str,
    public_key: &str,
) -> Result<bool> {
    validate_ssh_tag(tag)?;
    let desired = ssh_public_key_material(public_key)
        .with_context(|| format!("parsing declared SSH public key {tag} for {account}"))?;
    let client = authenticated_client(config).await?;
    let existing = client
        .idm_account_get_ssh_pubkey(account, tag)
        .await
        .kanidm_context(format!("reading SSH public key {tag} for {account}"))?;
    if let Some(existing) = existing.as_deref() {
        let existing = ssh_public_key_material(existing)
            .with_context(|| format!("parsing existing SSH public key {tag} for {account}"))?;
        if existing == desired {
            return Ok(false);
        }
    }
    if existing.is_some() {
        client
            .idm_person_account_delete_ssh_pubkey(account, tag)
            .await
            .kanidm_context(format!("replacing SSH public key {tag} for {account}"))?;
    }
    client
        .idm_person_account_post_ssh_pubkey(account, tag, public_key)
        .await
        .kanidm_context(format!("adding SSH public key {tag} for {account}"))?;
    Ok(true)
}

/// Reconcile one Kanidm OAuth2 basic secret with a private local runtime file.
///
/// Kanidm is authoritative: a missing local file is recovered from Kanidm and
/// a provider-side rotation updates the local artifact. When the provider has
/// no secret, this resets it through Kanidm and persists the returned value.
/// `adopt_from` is used only to initialize a missing local artifact during a
/// migration; it is never allowed to overwrite a provider value.
pub async fn reconcile_oauth2_basic_secret(
    config: &ClientConfig,
    name: &str,
    state_file: &Path,
    adopt_from: Option<&Path>,
    rotate: bool,
) -> Result<OAuth2SecretAction> {
    if name.trim().is_empty() {
        bail!("OAuth2 client name must not be empty");
    }
    let store = GeneratedSecretStore::at(state_file)?;
    let client = authenticated_client(config).await?;
    let mut remote = client
        .idm_oauth2_rs_get_basic_secret(name)
        .await
        .kanidm_context(format!("reading OAuth2 basic secret for {name}"))?
        .map(Zeroizing::new);

    if remote.is_none() && adopt_from.is_some() && !rotate {
        bail!(
            "cannot adopt the legacy OAuth2 secret for {name}: Kanidm has no existing secret; run an explicit rotation instead"
        );
    }

    if rotate || remote.is_none() {
        client
            .idm_oauth2_rs_update(name, None, None, None, true)
            .await
            .kanidm_context(format!("resetting OAuth2 basic secret for {name}"))?;
        remote = client
            .idm_oauth2_rs_get_basic_secret(name)
            .await
            .kanidm_context(format!("reading reset OAuth2 basic secret for {name}"))?
            .map(Zeroizing::new);
        if remote
            .as_deref()
            .is_none_or(|secret| secret.trim().is_empty())
        {
            bail!("Kanidm returned no OAuth2 basic secret for {name} after reset");
        }
        store.replace_text(remote.as_deref().expect("checked above"))?;
        return Ok(OAuth2SecretAction::Rotated);
    }

    let remote = remote.as_deref().expect("checked above");
    if remote.trim().is_empty() {
        bail!("Kanidm returned an empty OAuth2 basic secret for {name}");
    }

    let action = match store.status()? {
        SecretFileStatus::Missing => {
            let source = match adopt_from {
                Some(path) => store.ensure(Some(path))?.source,
                None => {
                    store.recover(remote)?;
                    SecretSource::Generated
                }
            };
            let local = store.read()?;
            if local.expose() != remote.trim() {
                if source == SecretSource::Adopted {
                    bail!(
                        "legacy OAuth2 secret for {name} does not match Kanidm; refusing silent replacement"
                    );
                }
                store.replace_text(remote)?;
                OAuth2SecretAction::Recovered
            } else if source == SecretSource::Adopted {
                OAuth2SecretAction::Adopted
            } else {
                OAuth2SecretAction::Recovered
            }
        }
        SecretFileStatus::Ready => {
            let local = store.read()?;
            if local.expose() == remote.trim() {
                OAuth2SecretAction::Unchanged
            } else {
                store.replace_text(remote)?;
                OAuth2SecretAction::Recovered
            }
        }
    };

    Ok(action)
}

/// Delete a person's tagged SSH public key.
pub async fn delete_ssh_public_key(config: &ClientConfig, account: &str, tag: &str) -> Result<()> {
    validate_ssh_tag(tag)?;
    let client = authenticated_client(config).await?;
    let existing = client
        .idm_account_get_ssh_pubkey(account, tag)
        .await
        .kanidm_context(format!("reading SSH public key {tag} for {account}"))?;
    if existing.is_none() {
        return Ok(());
    }
    client
        .idm_person_account_delete_ssh_pubkey(account, tag)
        .await
        .kanidm_context(format!("deleting SSH public key {tag} for {account}"))
}

fn validate_ssh_tag(tag: &str) -> Result<()> {
    if tag.is_empty()
        || !tag
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '@' | ':'))
    {
        bail!("SSH public key tag must match [A-Za-z0-9_.@:-]+, got {tag:?}");
    }
    Ok(())
}

fn ssh_public_key_material(key: &str) -> Result<String> {
    let mut tokens = key.split_whitespace();
    while let Some(token) = tokens.next() {
        if is_ssh_key_type(token) {
            let material = tokens
                .next()
                .ok_or_else(|| anyhow!("OpenSSH public key is missing key material"))?;
            return Ok(format!("{token} {material}"));
        }
    }
    bail!("OpenSSH public key is missing a supported key type");
}

fn is_ssh_key_type(token: &str) -> bool {
    token.starts_with("ssh-") || token.starts_with("ecdsa-") || token.starts_with("sk-")
}

/// Extend a person with POSIX (unix) account attributes.
pub async fn extend_posix_account(
    config: &ClientConfig,
    account: &str,
    gid_number: Option<u32>,
    login_shell: Option<&str>,
) -> Result<()> {
    let client = authenticated_client(config).await?;
    client
        .idm_person_account_unix_extend(account, gid_number, login_shell)
        .await
        .kanidm_context(format!("extending {account} with POSIX attributes"))
}

/// Return whether a Kanidm person exists.
pub async fn person_exists(config: &ClientConfig, account: &str) -> Result<bool> {
    let client = authenticated_client(config).await?;
    let person = client
        .idm_person_account_get(account)
        .await
        .kanidm_context(format!("checking whether person {account} exists"))?;
    Ok(person.is_some())
}

/// Delete a Kanidm person account.
pub async fn delete_person(config: &ClientConfig, account: &str) -> Result<()> {
    let client = authenticated_client(config).await?;
    client
        .idm_person_account_delete(account)
        .await
        .kanidm_context(format!("deleting person {account}"))
}

/// Idempotently ensure a kanidm service account exists.
///
/// Service accounts are the idiomatic identity for an application's LDAP search
/// bind (bound as `dn=token` with an API token). `managed_by` is the group or
/// account that administers it afterwards (it must include the caller so the
/// caller can subsequently mint tokens). Returns `true` if the account was
/// created, `false` if it already existed.
pub async fn ensure_service_account(
    config: &ClientConfig,
    name: &str,
    display_name: &str,
    managed_by: &str,
) -> Result<bool> {
    let client = authenticated_client(config).await?;
    let existing = client
        .idm_service_account_get(name)
        .await
        .kanidm_context(format!("checking whether service account {name} exists"))?;
    if existing.is_some() {
        return Ok(false);
    }
    client
        .idm_service_account_create(name, display_name, managed_by)
        .await
        .kanidm_context(format!("creating service account {name}"))?;
    Ok(true)
}

/// Generate a fresh API token for a service account.
///
/// The returned token is a secret (a JWS) and is the bind secret used by an
/// LDAP consumer binding as `dn=token`. Read-only by default; `read_write`
/// only when the consumer must write to kanidm. No expiry is set.
pub async fn generate_api_token(
    config: &ClientConfig,
    account: &str,
    label: &str,
    read_write: bool,
) -> Result<String> {
    let client = authenticated_client(config).await?;
    client
        .idm_service_account_generate_api_token(account, label, None, read_write, false)
        .await
        .kanidm_context(format!("generating API token for {account}"))
}

/// Add members to a kanidm group.
///
/// Used to grant a service account the read access it needs over LDAP — e.g.
/// adding it to `idm_people_pii_read` so the search bind can read persons'
/// `mail` attribute (service accounts cannot read PII by default).
pub async fn group_add_members(
    config: &ClientConfig,
    group: &str,
    members: &[String],
) -> Result<()> {
    let client = authenticated_client(config).await?;
    let refs: Vec<&str> = members.iter().map(String::as_str).collect();
    client
        .idm_group_add_members(group, &refs)
        .await
        .kanidm_context(format!("adding members to group {group}"))
}

/// Remove members from a kanidm group (inverse of [`group_add_members`]).
pub async fn group_remove_members(
    config: &ClientConfig,
    group: &str,
    members: &[String],
) -> Result<()> {
    let client = authenticated_client(config).await?;
    let refs: Vec<&str> = members.iter().map(String::as_str).collect();
    client
        .idm_group_remove_members(group, &refs)
        .await
        .kanidm_context(format!("removing members from group {group}"))
}

/// Delete a service account (inverse of [`ensure_service_account`]). Also
/// destroys any API tokens it owns.
pub async fn delete_service_account(config: &ClientConfig, name: &str) -> Result<()> {
    let client = authenticated_client(config).await?;
    client
        .idm_service_account_delete(name)
        .await
        .kanidm_context(format!("deleting service account {name}"))
}

/// Delete a person's POSIX/unix credential (inverse of [`set_posix_password`]).
pub async fn delete_posix_password(config: &ClientConfig, account: &str) -> Result<()> {
    let client = authenticated_client(config).await?;
    client
        .idm_person_account_unix_cred_delete(account)
        .await
        .kanidm_context(format!("deleting POSIX credential for {account}"))
}

async fn authenticated_client(config: &ClientConfig) -> Result<kanidm_client::KanidmClient> {
    authenticated_client_as(&config.url, IDM_ADMIN, &config.idm_admin_password_file).await
}

async fn authenticated_admin_client(config: &ClientConfig) -> Result<kanidm_client::KanidmClient> {
    let password_file = config.admin_password_file.as_deref().ok_or_else(|| {
        anyhow!("this operation requires the kanidm `admin` account; pass --admin-password-file")
    })?;
    authenticated_client_as(&config.url, ADMIN, password_file).await
}

async fn authenticated_client_as(
    url: &str,
    account: &str,
    password_file: &str,
) -> Result<kanidm_client::KanidmClient> {
    let password = read_secret_file(password_file)
        .with_context(|| format!("reading {account} password file {password_file}"))?;
    let client = KanidmClientBuilder::new()
        .address(url.to_string())
        .build()
        .kanidm_context(format!("building kanidm client for {url}"))?;

    client
        .auth_simple_password(account, &password)
        .await
        .kanidm_context(format!("authenticating to kanidm as {account}"))?;

    Ok(client)
}

async fn enroll_totp(
    client: &kanidm_client::KanidmClient,
    session_token: &kanidm_proto::internal::CUSessionToken,
) -> Result<TotpSecret> {
    client
        .idm_account_credential_update_init_totp(session_token)
        .await
        .kanidm_context("initializing TOTP registration")?;

    let status = client
        .idm_account_credential_update_status(session_token)
        .await
        .kanidm_context("reading TOTP registration status")?;
    let secret = match status.mfaregstate {
        CURegState::TotpCheck(secret) => secret,
        other => bail!("expected TOTP check state after TOTP init, got {other:?}"),
    };

    let status = check_totp(client, session_token, &secret).await?;
    match status.mfaregstate {
        CURegState::None => Ok(secret),
        CURegState::TotpNameTryAgain(label) => {
            bail!("kanidm rejected TOTP label {label:?}; remove any existing duplicate TOTP first")
        }
        other => bail!("TOTP registration did not complete, got {other:?}"),
    }
}

async fn check_totp(
    client: &kanidm_client::KanidmClient,
    session_token: &kanidm_proto::internal::CUSessionToken,
    secret: &TotpSecret,
) -> Result<CUStatus> {
    let totp = totp_from_secret(secret)?;
    let code = current_totp_code(&totp)?;
    let status = client
        .idm_account_credential_update_check_totp(session_token, code, TOTP_LABEL)
        .await
        .kanidm_context("checking generated TOTP code")?;

    if !matches!(status.mfaregstate, CURegState::TotpTryAgain) {
        return Ok(status);
    }

    let delay = totp.ttl().context("calculating TOTP retry delay")? + 1;
    sleep(Duration::from_secs(delay)).await;
    let retry_code = current_totp_code(&totp)?;
    client
        .idm_account_credential_update_check_totp(session_token, retry_code, TOTP_LABEL)
        .await
        .kanidm_context("checking generated TOTP code after step-boundary retry")
}

async fn generate_backup_codes(
    client: &kanidm_client::KanidmClient,
    session_token: &kanidm_proto::internal::CUSessionToken,
) -> Result<Vec<String>> {
    let status = client
        .idm_account_credential_update_backup_codes_generate(session_token)
        .await
        .kanidm_context("generating backup codes")?;

    match status.mfaregstate {
        CURegState::BackupCodes(codes) if !codes.is_empty() => Ok(codes),
        CURegState::BackupCodes(_) => bail!("kanidm returned no backup codes"),
        other => bail!("expected backup-code state after generation, got {other:?}"),
    }
}

fn ensure_can_commit(status: &CUStatus) -> Result<()> {
    if !matches!(
        status.mfaregstate,
        CURegState::None | CURegState::BackupCodes(_)
    ) {
        bail!(
            "credential update still has pending MFA registration state: {:?}",
            status.mfaregstate
        );
    }
    if !status.can_commit {
        bail!(
            "kanidm credential update cannot commit; warnings: {:?}",
            status.warnings
        );
    }
    Ok(())
}

fn totp_from_secret(secret: &TotpSecret) -> Result<TOTP> {
    TOTP::new(
        match secret.algo {
            TotpAlgo::Sha1 => Algorithm::SHA1,
            TotpAlgo::Sha256 => Algorithm::SHA256,
            TotpAlgo::Sha512 => Algorithm::SHA512,
        },
        usize::from(secret.digits),
        0,
        secret.step,
        secret.secret.clone(),
    )
    .context("constructing TOTP generator from kanidm secret")
}

fn current_totp_code(totp: &TOTP) -> Result<u32> {
    let code = totp
        .generate_current()
        .context("generating current TOTP code")?;
    code.parse::<u32>()
        .context("parsing generated numeric TOTP code")
}

fn secret_from_file_or_generated(path: Option<&str>) -> Result<String> {
    match path {
        Some(path) => read_secret_file(path),
        None => Ok(generate_password()),
    }
}

fn read_secret_file(path: impl AsRef<Path>) -> Result<String> {
    let mut secret = fs::read_to_string(path.as_ref())
        .with_context(|| format!("reading secret file {}", path.as_ref().display()))?;
    while secret.ends_with(['\n', '\r']) {
        secret.pop();
    }
    if secret.is_empty() {
        bail!("secret file {} is empty", path.as_ref().display());
    }
    Ok(secret)
}

fn generate_password() -> String {
    Alphanumeric.sample_string(&mut rand::rng(), GENERATED_PASSWORD_LEN)
}

/// Current Unix timestamp, useful to label generated credentials in callers.
pub fn unix_timestamp() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before Unix epoch")?
        .as_secs())
}

trait KanidmResultExt<T> {
    fn kanidm_context(self, context: impl Display) -> Result<T>;
}

impl<T> KanidmResultExt<T> for std::result::Result<T, kanidm_client::ClientError> {
    fn kanidm_context(self, context: impl Display) -> Result<T> {
        self.map_err(|err| anyhow!("{context}: {err:?}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssh_public_key_material_ignores_comment() {
        assert_eq!(
            ssh_public_key_material("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA test@example").unwrap(),
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA"
        );
    }

    #[test]
    fn ssh_public_key_material_skips_options() {
        assert_eq!(
            ssh_public_key_material(
                r#"from="10.0.0.1" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA test@example"#
            )
            .unwrap(),
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA"
        );
    }

    #[test]
    fn ssh_tag_validation_rejects_shell_metacharacters() {
        validate_ssh_tag("hm-identity").unwrap();
        assert!(validate_ssh_tag("").is_err());
        assert!(validate_ssh_tag("hm identity").is_err());
        assert!(validate_ssh_tag("hm;identity").is_err());
    }
}
