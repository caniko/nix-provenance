//! OAuth lifecycle owned by nix-provenance. Consumer responses contain access
//! credentials only for OpenAI; Google refreshes are owned by rclone.

pub mod age_file;
pub mod google;
pub mod openai;
pub mod state;

use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::{fmt, path::PathBuf, time::SystemTime};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Clone, Deserialize, Serialize, Zeroize, ZeroizeOnDrop)]
#[serde(transparent)]
pub struct Secret(pub String);

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
}

impl Target {
    pub fn validate(&self) -> Result<()> {
        for value in [&self.host, &self.user, &self.account] {
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
                ("openai", "chatgpt") | ("google", "drive-file")
            ),
            "unsupported OAuth profile"
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
    pub access_token: Secret,
    pub refresh_token: Secret,
    pub expires_at: u64,
    pub account_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client: Option<OAuthClient>,
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
                !value.is_empty()
                    && value.len() <= 256
                    && value
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b)),
                "invalid Google client credentials"
            );
        }
        Ok(())
    }
}

impl Grant {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            !self.access_token.0.is_empty() && !self.refresh_token.0.is_empty(),
            "OAuth grant is missing tokens"
        );
        ensure!(self.expires_at > 0, "OAuth grant is missing expiry");
        ensure!(
            !self.account_id.is_empty()
                && self.account_id.len() <= 256
                && self.account_id.bytes().all(|b| b.is_ascii_graphic()),
            "OAuth grant is missing a valid account ID"
        );
        Ok(())
    }

    pub fn validate_for(&self, target: &Target) -> Result<()> {
        self.validate()?;
        match (&*target.provider, &self.client) {
            ("openai", None) => Ok(()),
            ("google", Some(client)) => client.validate(),
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
