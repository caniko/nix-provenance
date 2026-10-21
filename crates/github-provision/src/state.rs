//! Declarative state for one GitHub account, rendered by the Home Manager module.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Result, bail};
use provenance_core::serde_ext::default_true as default_present;
use serde::{Deserialize, Serialize};

/// Everything reconciled with one account's token.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct State {
    /// Login the token must authenticate as; a mismatch fails closed.
    pub login: String,
    /// OpenPGP public keys by stable name.
    #[serde(default, rename = "gpgKeys")]
    pub gpg_keys: BTreeMap<String, GpgKeySpec>,
    /// SSH authentication keys by stable title.
    #[serde(default, rename = "sshKeys")]
    pub ssh_keys: BTreeMap<String, SshKeySpec>,
    /// Users to invite as collaborators on this account's repositories.
    #[serde(default)]
    pub collaborators: BTreeMap<String, CollaboratorSpec>,
    /// Accept repository invitations only when both the inviter and the
    /// repository owner are listed here.
    #[serde(default, rename = "acceptInvitationsFrom")]
    pub accept_invitations_from: BTreeSet<String>,
}

/// One OpenPGP public key.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GpgKeySpec {
    /// Whether the key should exist.
    #[serde(default = "default_present")]
    pub present: bool,
    /// ASCII-armored public key. Optional only when present is false.
    #[serde(default)]
    pub key: Option<String>,
    /// Full primary-key fingerprint; GitHub reports its last 16 digits as `key_id`.
    pub fingerprint: String,
}

impl GpgKeySpec {
    /// GitHub's 16-digit long key id for this fingerprint.
    pub fn key_id(&self) -> String {
        let fpr = self.fingerprint.to_ascii_uppercase();
        fpr[fpr.len() - 16..].to_owned()
    }
}

/// One SSH authentication key.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SshKeySpec {
    /// Whether the key should exist.
    #[serde(default = "default_present")]
    pub present: bool,
    /// OpenSSH public key. Optional only when present is false.
    #[serde(default)]
    pub key: Option<String>,
}

/// Repository permission granted to a collaborator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Permission {
    Pull,
    Triage,
    Push,
    Maintain,
    Admin,
}

/// Which repositories a collaborator is invited to.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum Repositories {
    /// Every non-archived repository the account owns.
    Owned(OwnedTag),
    /// Explicit `owner/name` repositories.
    Named(BTreeSet<String>),
}

/// The literal string `"owned"`.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OwnedTag {
    Owned,
}

/// One declared collaborator.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CollaboratorSpec {
    /// Permission requested in the invitation.
    pub permission: Permission,
    /// Repository selection.
    pub repositories: Repositories,
}

fn path_safe(name: &str) -> bool {
    !name.is_empty() && !name.contains(['/', '\n', '\r', '\0'])
}

impl State {
    /// Validate names and the fields needed by the reconciler.
    pub fn validate(&self) -> Result<()> {
        if !path_safe(&self.login) {
            bail!("GitHub login must be a non-empty path-safe name");
        }
        for (name, spec) in &self.gpg_keys {
            if name.trim().is_empty() || name.contains(['\n', '\r', '\0']) {
                bail!("GitHub GPG-key name must be a non-empty single-line name");
            }
            if spec.fingerprint.len() < 16
                || !spec.fingerprint.bytes().all(|b| b.is_ascii_hexdigit())
            {
                bail!(
                    "GitHub GPG key {name} needs a hexadecimal fingerprint of at least 16 digits"
                );
            }
            if spec.present && spec.key.as_deref().is_none_or(|key| key.trim().is_empty()) {
                bail!("GitHub GPG key {name} requires an armored public key when present = true");
            }
        }
        for (title, spec) in &self.ssh_keys {
            if title.trim().is_empty() || title.contains(['\n', '\r', '\0']) {
                bail!("GitHub SSH-key title must be a non-empty single-line name");
            }
            if spec.present && spec.key.as_deref().is_none_or(|key| key.trim().is_empty()) {
                bail!("GitHub SSH key {title} requires a public key when present = true");
            }
        }
        for (user, spec) in &self.collaborators {
            if !path_safe(user) {
                bail!("GitHub collaborator must be a non-empty path-safe login");
            }
            if user.eq_ignore_ascii_case(&self.login) {
                bail!("GitHub account {user} cannot be its own collaborator");
            }
            if let Repositories::Named(repos) = &spec.repositories {
                for repo in repos {
                    if !matches!(repo.split('/').collect::<Vec<_>>()[..], [owner, name] if path_safe(owner) && path_safe(name))
                    {
                        bail!("GitHub repository {repo:?} must be written owner/name");
                    }
                }
            }
        }
        for login in &self.accept_invitations_from {
            if !path_safe(login) {
                bail!("acceptInvitationsFrom entries must be path-safe logins");
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_full_state() {
        let state: State = serde_json::from_str(
            r#"{"login":"bot",
                "gpgKeys":{"atlas":{"key":"-----BEGIN PGP PUBLIC KEY BLOCK-----","fingerprint":"156ab02bb1a3e9cb59fe933a41d0f8d92b7498f2"}},
                "sshKeys":{"atlas":{"key":"ssh-ed25519 AAAA"}},
                "collaborators":{"friend":{"permission":"push","repositories":"owned"}},
                "acceptInvitationsFrom":["owner"]}"#,
        )
        .expect("state parses");
        state.validate().expect("state is valid");
        assert_eq!(state.gpg_keys["atlas"].key_id(), "41D0F8D92B7498F2");
        assert!(matches!(
            state.collaborators["friend"].repositories,
            Repositories::Owned(OwnedTag::Owned)
        ));
    }

    #[test]
    fn rejects_unqualified_repository() {
        let state: State = serde_json::from_str(
            r#"{"login":"owner","collaborators":{"bot":{"permission":"push","repositories":["repo"]}}}"#,
        )
        .expect("state parses");
        let error = state.validate().expect_err("bare repo name must fail");
        assert!(error.to_string().contains("owner/name"));
    }

    #[test]
    fn rejects_unknown_selector() {
        assert!(
            serde_json::from_str::<State>(
                r#"{"login":"owner","collaborators":{"bot":{"permission":"push","repositories":"all"}}}"#,
            )
            .is_err()
        );
    }
}
