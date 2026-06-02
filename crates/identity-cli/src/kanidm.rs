use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use std::fmt::Display;

use anyhow::{anyhow, bail, Context, Result};
use kanidm_client::KanidmClientBuilder;
use kanidm_proto::internal::{CURegState, CUStatus, TotpAlgo, TotpSecret};
use rand::distr::{Alphanumeric, SampleString};
use serde::Serialize;
use tokio::time::{sleep, Duration};
use totp_rs::{Algorithm, TOTP};

const DEFAULT_URL: &str = "https://auth.tartanoglu.com";
const IDM_ADMIN: &str = "idm_admin";
const GENERATED_PASSWORD_LEN: usize = 24;
const TOTP_LABEL: &str = "identity-cli";

/// Shared Kanidm connection and authentication settings.
#[derive(Debug, Clone)]
pub struct ClientConfig {
    /// Kanidm base URL.
    pub url: String,
    /// Path containing the `idm_admin` password.
    pub idm_admin_password_file: String,
}

impl ClientConfig {
    /// Build a config with the default production Kanidm URL.
    pub fn new(idm_admin_password_file: String) -> Self {
        Self {
            url: DEFAULT_URL.to_string(),
            idm_admin_password_file,
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
#[derive(Debug, Clone, Serialize)]
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
pub async fn set_ldap_unix_bind(config: &ClientConfig, enable: bool) -> Result<()> {
    let client = authenticated_client(config).await?;
    client
        .idm_set_ldap_allow_unix_password_bind(enable)
        .await
        .kanidm_context("setting ldap allow unix password bind")
}

async fn authenticated_client(config: &ClientConfig) -> Result<kanidm_client::KanidmClient> {
    let password = read_secret_file(&config.idm_admin_password_file).with_context(|| {
        format!(
            "reading idm_admin password file {}",
            config.idm_admin_password_file
        )
    })?;
    let client = KanidmClientBuilder::new()
        .address(config.url.clone())
        .build()
        .kanidm_context(format!("building kanidm client for {}", config.url))?;

    client
        .auth_simple_password(IDM_ADMIN, &password)
        .await
        .kanidm_context("authenticating to kanidm as idm_admin")?;

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
