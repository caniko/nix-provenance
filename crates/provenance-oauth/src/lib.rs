//! OAuth lifecycle owned by nix-provenance. Consumer responses contain access
//! credentials only for OpenAI; Google consumers refresh their own grants.

pub mod age_file;
pub mod antigravity_cli;
pub mod budget;
pub mod google;
pub mod google_client;
pub mod openai;
pub mod opencode;
pub mod opencode_cli;
pub mod state;

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{fmt, path::PathBuf, process::ExitCode, time::SystemTime};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Structured CLI error with an explicit process exit code and optional stderr message.
#[derive(Debug)]
pub struct CliError {
    pub code: u8,
    pub message: Option<String>,
}

impl CliError {
    pub fn runtime(message: impl Into<String>) -> Self {
        Self {
            code: 1,
            message: Some(message.into()),
        }
    }

    pub fn validation(message: impl Into<String>) -> Self {
        Self {
            code: 2,
            message: Some(message.into()),
        }
    }

    pub fn with_code(code: u8, message: impl Into<String>) -> Self {
        Self {
            code,
            message: Some(message.into()),
        }
    }

    pub fn silent(code: u8) -> Self {
        Self {
            code,
            message: None,
        }
    }

    pub fn exit_code(&self) -> ExitCode {
        ExitCode::from(self.code)
    }
}

impl From<anyhow::Error> for CliError {
    fn from(error: anyhow::Error) -> Self {
        Self::runtime(format!("{error:#}"))
    }
}

#[derive(Clone, Default, Deserialize, Serialize, Zeroize, ZeroizeOnDrop)]
#[serde(transparent)]
pub struct Secret(pub String);

impl Secret {
    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Target {
    pub host: String,
    pub user: String,
    pub provider: String,
    pub profile: String,
    pub account: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enrollment: Option<String>,
}

impl Target {
    pub fn google_refresh_owner_message(&self) -> &'static str {
        if self.profile == "antigravity" {
            "google/antigravity grants are refreshed by agy"
        } else {
            "google grants are refreshed by their rclone consumer"
        }
    }

    pub fn validate(&self) -> Result<()> {
        let values = [&self.host, &self.user];
        for value in values
            .into_iter()
            .chain((self.profile != "opencode").then_some(&self.account))
        {
            ensure!(
                !value.is_empty()
                    && value.len() <= 128
                    && value
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b)),
                "host, user and account must be nonempty identifiers (letters, digits, '-' or '_')"
            );
        }
        ensure!(
            matches!(
                (self.provider.as_str(), self.profile.as_str()),
                ("openai", "chatgpt" | "opencode")
                    | ("google", "drive-file" | "drive" | "antigravity")
            ),
            "unsupported OAuth profile"
        );
        ensure!(
            self.profile != "opencode" || opencode::valid_label(&self.account),
            "invalid OpenCode credential label"
        );
        ensure!(
            self.enrollment.as_ref().is_none_or(|id| {
                id.len() <= 48
                    && id
                        .bytes()
                        .next()
                        .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
                    && id
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            }),
            "invalid OAuth enrollment ID"
        );
        Ok(())
    }

    pub fn require_access(&self) -> Result<()> {
        ensure!(
            self.profile != "opencode",
            "openai/opencode grants are refreshed only by OpenCode"
        );
        ensure!(
            self.provider == "openai",
            "{}",
            self.google_refresh_owner_message()
        );
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Config {
    pub version: u32,
    pub target: Target,
    pub state_directory: PathBuf,
    /// Public age recipients only. The current checkpoint is encrypted on every
    /// successful enrollment/rotation before credentials are released to apps.
    pub recovery_recipients: Vec<String>,
}

impl Config {
    pub fn validate(&self) -> Result<()> {
        ensure!(self.version == 1, "unsupported OAuth config version");
        self.target.validate()?;
        ensure!(
            self.state_directory.is_absolute(),
            "stateDirectory must be absolute"
        );
        ensure!(
            !self.state_directory.starts_with("/nix/store"),
            "OAuth state must be outside the Nix store"
        );
        age_file::validate_recipients(&self.recovery_recipients)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Grant {
    // Antigravity grants export only refresh credentials.
    #[serde(default, skip_serializing_if = "Secret::is_empty")]
    pub access_token: Secret,
    pub refresh_token: Secret,
    #[serde(default)]
    pub expires_at: u64,
    /// For `openai/opencode`, the native OpenCode credential ID.
    pub account_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client: Option<OAuthClient>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scopes: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub opencode: Option<opencode::Details>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OAuthClient {
    pub client_id: String,
    pub client_secret: Secret,
}

impl OAuthClient {
    pub fn validate(&self) -> Result<()> {
        for value in [&self.client_id, &self.client_secret.0] {
            ensure!(
                valid_google_credential(value, b"-_.", 256),
                "invalid Google client credentials"
            );
        }
        Ok(())
    }
}

fn valid_google_credential(value: &str, punctuation: &[u8], max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || punctuation.contains(&b))
}

impl Grant {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            !self.access_token.0.is_empty() && !self.refresh_token.0.is_empty(),
            "OAuth grant is missing tokens"
        );
        ensure!(self.expires_at > 0, "OAuth grant is missing expiry");
        self.validate_account_id()
    }

    fn validate_account_id(&self) -> Result<()> {
        ensure!(
            !self.account_id.is_empty()
                && self.account_id.len() <= 256
                && self.account_id.bytes().all(|b| b.is_ascii_graphic()),
            "OAuth grant is missing a valid account ID"
        );
        Ok(())
    }

    fn validate_antigravity_credentials(&self) -> Result<()> {
        let client = self
            .client
            .as_ref()
            .context("Google grant is missing client credentials")?;
        client.validate()?;
        ensure!(
            client.client_id.ends_with(".apps.googleusercontent.com"),
            "invalid Antigravity client ID"
        );
        // Google refresh tokens may use a `1//` prefix and run to 512 bytes.
        ensure!(
            valid_google_credential(&self.refresh_token.0, b"-_./", 512),
            "invalid Antigravity refresh token"
        );
        ensure!(
            self.scopes.as_ref().is_some_and(|scopes| {
                scopes
                    .iter()
                    .any(|scope| scope == google::CLOUD_PLATFORM_SCOPE)
            }),
            "Antigravity token requires the cloud-platform scope"
        );
        Ok(())
    }

    pub fn validate_for(&self, target: &Target) -> Result<()> {
        ensure!(
            self.opencode.is_some() == (target.profile == "opencode"),
            "OpenCode credential details do not match the OAuth profile"
        );
        if target.provider == "google" && target.profile == "antigravity" {
            self.validate_antigravity_credentials()?;
            self.validate_account_id()?;
            ensure!(
                self.access_token.is_empty() && self.expires_at == 0,
                "Antigravity grant must not store an access token"
            );
            ensure!(
                target.account == "default" || target.account == self.account_id,
                "Antigravity Google account does not match the manifest account"
            );
            return Ok(());
        }
        self.validate()?;
        match (&*target.provider, &self.client) {
            ("openai", None) if target.profile == "opencode" => opencode::validate(self),
            ("openai", None) => Ok(()),
            ("google", Some(client)) => {
                client.validate()?;
                ensure!(
                    target.profile != "drive"
                        || self.scopes.as_ref().is_some_and(|scopes| scopes
                            .iter()
                            .any(|scope| scope == google::DRIVE_SCOPE)),
                    "Google Drive grant lacks the full Drive scope"
                );
                Ok(())
            }
            _ => anyhow::bail!("OAuth client credentials do not match provider"),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Enrollment {
    pub version: u32,
    pub target: Target,
    /// Monotonic enrollment epoch (Unix milliseconds). Token rotations do not
    /// change this number, so old agenix files cannot overwrite rotated state.
    pub generation: u64,
    pub grant: Grant,
}

impl Enrollment {
    pub fn validate(&self, target: &Target) -> Result<()> {
        ensure!(
            self.version == 1 && self.generation > 0,
            "unsupported enrollment version or generation"
        );
        ensure!(
            &self.target == target,
            "enrollment belongs to another host, user or profile"
        );
        self.grant.validate_for(target)
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Access {
    pub access_token: Secret,
    pub expires_at: u64,
    pub account_id: String,
}

pub fn now() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)?
        .as_millis()
        .try_into()?)
}
