//! Idempotent, additive GitHub reconciliation with guarded deletion.
//!
//! Undeclared keys, collaborators, and invitations are never touched. Planning
//! is pure; only `reconcile` performs network mutations.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result, bail};
use provenance_core::reconcile::Summary;

use crate::client::{GithubClient, GpgKey, Invitation, Repository, SshKey};
use crate::state::{GpgKeySpec, Repositories, SshKeySpec, State};

/// One key mutation selected by the planning pass.
#[derive(Debug, PartialEq, Eq)]
pub enum Operation {
    /// Register a missing OpenPGP key.
    AddGpg { name: String, key: String },
    /// Remove an explicitly absent OpenPGP key.
    DeleteGpg { name: String, id: i64 },
    /// Register a missing SSH key.
    AddSsh { title: String, key: String },
    /// Remove an explicitly absent SSH key.
    DeleteSsh { title: String, id: i64 },
    /// Leave a matching (or deletion-gated) key untouched.
    Noop,
}

/// Normalize the managed portion of an OpenSSH public key.
///
/// Comments are ignored, so changing one is not drift. Options, private keys,
/// and malformed bodies are rejected before any mutation.
pub fn normalize_key(raw: &str) -> Result<String> {
    if raw.contains(['\n', '\r']) {
        bail!("SSH public keys must be single-line values");
    }
    let mut fields = raw.split_whitespace();
    let kind = fields
        .next()
        .ok_or_else(|| anyhow::anyhow!("SSH public key is empty"))?;
    let blob = fields
        .next()
        .ok_or_else(|| anyhow::anyhow!("SSH public key is missing its encoded body"))?;
    if !(kind.starts_with("ssh-") || kind.starts_with("ecdsa-") || kind.starts_with("sk-")) {
        bail!("unsupported SSH public-key type");
    }
    if !blob
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'='))
    {
        bail!("SSH public-key body is not valid base64 text");
    }
    Ok(format!("{kind} {blob}"))
}

/// Plan OpenPGP keys, matched by GitHub's long key id.
pub fn plan_gpg(
    desired: &BTreeMap<String, GpgKeySpec>,
    current: &[GpgKey],
    allow_delete: bool,
) -> Result<Vec<Operation>> {
    let mut seen = BTreeMap::new();
    for (name, spec) in desired {
        if let Some(other) = seen.insert(spec.key_id(), name) {
            bail!("GitHub GPG keys {other} and {name} declare the same fingerprint");
        }
    }
    Ok(desired
        .iter()
        .map(|(name, spec)| {
            let key_id = spec.key_id();
            let existing = current
                .iter()
                .find(|key| key.key_id.eq_ignore_ascii_case(&key_id));
            match (spec.present, existing) {
                (true, None) => Operation::AddGpg {
                    name: name.clone(),
                    key: spec.key.clone().unwrap_or_default(),
                },
                (false, Some(key)) if allow_delete => Operation::DeleteGpg {
                    name: name.clone(),
                    id: key.id,
                },
                _ => Operation::Noop,
            }
        })
        .collect())
}

/// Plan SSH keys, matched by title. Key drift under a title fails closed.
pub fn plan_ssh(
    desired: &BTreeMap<String, SshKeySpec>,
    current: &[SshKey],
    allow_delete: bool,
) -> Result<Vec<Operation>> {
    let observed = current
        .iter()
        .map(|key| {
            normalize_key(&key.key)
                .with_context(|| format!("GitHub returned malformed SSH key {}", key.id))
                .map(|normalized| (key, normalized))
        })
        .collect::<Result<Vec<_>>>()?;
    let mut seen = BTreeMap::new();
    let mut operations = Vec::new();
    for (title, spec) in desired {
        let by_title: Vec<_> = observed
            .iter()
            .filter(|(key, _)| key.title == *title)
            .collect();
        if by_title.len() > 1 {
            bail!("GitHub has multiple SSH keys titled {title}");
        }
        let operation = if spec.present {
            let key = normalize_key(spec.key.as_deref().unwrap_or_default())?;
            if let Some(other) = seen.insert(key.clone(), title) {
                bail!("GitHub SSH keys {other} and {title} declare the same key");
            }
            match by_title.first() {
                Some((_, current)) if *current == key => Operation::Noop,
                Some(_) => bail!("GitHub SSH key {title} drifted; refusing implicit key rotation"),
                None if observed.iter().any(|(_, current)| *current == key) => {
                    bail!("GitHub already has SSH key {title} under another title")
                }
                None => Operation::AddSsh {
                    title: title.clone(),
                    key,
                },
            }
        } else {
            match by_title.first() {
                Some((key, _)) if allow_delete => Operation::DeleteSsh {
                    title: title.clone(),
                    id: key.id,
                },
                _ => Operation::Noop,
            }
        };
        operations.push(operation);
    }
    Ok(operations)
}

/// `(owner, name)` pairs selected for one collaborator.
pub fn selected_repositories(
    owned: &[Repository],
    selection: &Repositories,
) -> Vec<(String, String)> {
    let split = |full: &str| {
        let (owner, name) = full.split_once('/').unwrap_or((full, ""));
        (owner.to_owned(), name.to_owned())
    };
    match selection {
        Repositories::Owned(_) => owned
            .iter()
            .filter(|repo| !repo.archived)
            .map(|repo| split(&repo.full_name))
            .collect(),
        Repositories::Named(names) => names.iter().map(|full| split(full)).collect(),
    }
}

/// Invitations whose inviter and repository owner are both trusted.
pub fn trusted_invitations<'a>(
    invitations: &'a [Invitation],
    trusted: &BTreeSet<String>,
) -> Vec<&'a Invitation> {
    let trusted = |login: &str| trusted.iter().any(|name| name.eq_ignore_ascii_case(login));
    invitations
        .iter()
        .filter(|invite| {
            invite
                .inviter
                .as_ref()
                .is_some_and(|inviter| trusted(&inviter.login))
                && trusted(&invite.repository.owner.login)
        })
        .collect()
}

/// Reconcile one account and return an operation summary.
///
/// Collaborator invitations continue past individual repository failures, which
/// are reported together at the end.
pub fn reconcile(client: &GithubClient, state: &State, allow_delete: bool) -> Result<Summary> {
    let mut operations = Vec::new();
    if !state.gpg_keys.is_empty() {
        operations.extend(plan_gpg(
            &state.gpg_keys,
            &client.gpg_keys()?,
            allow_delete,
        )?);
    }
    if !state.ssh_keys.is_empty() {
        operations.extend(plan_ssh(
            &state.ssh_keys,
            &client.ssh_keys()?,
            allow_delete,
        )?);
    }

    let mut summary = Summary::default();
    for operation in operations {
        match operation {
            Operation::AddGpg { name, key } => {
                client.add_gpg_key(&name, &key)?;
                summary.created += 1;
            }
            Operation::DeleteGpg { name, id } => {
                client.delete_gpg_key(&name, id)?;
                summary.deleted += 1;
            }
            Operation::AddSsh { title, key } => {
                client.add_ssh_key(&title, &key)?;
                summary.created += 1;
            }
            Operation::DeleteSsh { title, id } => {
                client.delete_ssh_key(&title, id)?;
                summary.deleted += 1;
            }
            Operation::Noop => summary.unchanged += 1,
        }
    }

    let mut failures = Vec::new();
    if !state.collaborators.is_empty() {
        let wants_owned = state
            .collaborators
            .values()
            .any(|spec| matches!(spec.repositories, Repositories::Owned(_)));
        let owned = if wants_owned {
            client.owned_repositories()?
        } else {
            Vec::new()
        };
        for (user, spec) in &state.collaborators {
            for (owner, name) in selected_repositories(&owned, &spec.repositories) {
                let result = client
                    .has_access_or_invite(&owner, &name, user)
                    .and_then(|present| {
                        if present {
                            summary.unchanged += 1;
                        } else {
                            client.invite(&owner, &name, user, spec.permission)?;
                            summary.created += 1;
                        }
                        Ok(())
                    });
                if let Err(error) = result {
                    eprintln!("[github-provision] {owner}/{name}: {error:#}");
                    failures.push(format!("{owner}/{name}"));
                }
            }
        }
    }

    if !state.accept_invitations_from.is_empty() {
        let invitations = client.invitations()?;
        for invite in trusted_invitations(&invitations, &state.accept_invitations_from) {
            client.accept(invite)?;
            summary.updated += 1;
        }
    }

    if !failures.is_empty() {
        bail!(
            "collaborator reconciliation failed for {}",
            failures.join(", ")
        );
    }
    Ok(summary)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::Account;
    use crate::state::OwnedTag;

    const FPR: &str = "156AB02BB1A3E9CB59FE933A41D0F8D92B7498F2";

    fn gpg(present: bool) -> BTreeMap<String, GpgKeySpec> {
        BTreeMap::from([(
            "atlas".to_owned(),
            GpgKeySpec {
                present,
                key: present.then(|| "armored".to_owned()),
                fingerprint: FPR.to_lowercase(),
            },
        )])
    }

    fn ssh(key: &str) -> BTreeMap<String, SshKeySpec> {
        BTreeMap::from([(
            "atlas".to_owned(),
            SshKeySpec {
                present: true,
                key: Some(key.to_owned()),
            },
        )])
    }

    fn observed_ssh(id: i64, title: &str, key: &str) -> SshKey {
        SshKey {
            id,
            title: title.to_owned(),
            key: key.to_owned(),
        }
    }

    fn repo(full_name: &str, archived: bool) -> Repository {
        Repository {
            full_name: full_name.to_owned(),
            archived,
            owner: Account {
                login: full_name.split('/').next().unwrap().to_owned(),
            },
        }
    }

    #[test]
    fn gpg_matches_github_long_key_id() {
        let current = [GpgKey {
            id: 3,
            key_id: "41D0F8D92B7498F2".to_owned(),
        }];
        assert_eq!(
            plan_gpg(&gpg(true), &current, false).unwrap(),
            [Operation::Noop]
        );
        assert!(matches!(
            &plan_gpg(&gpg(true), &[], false).unwrap()[0],
            Operation::AddGpg { name, key } if name == "atlas" && key == "armored"
        ));
    }

    #[test]
    fn gpg_deletion_requires_gate() {
        let current = [GpgKey {
            id: 3,
            key_id: "41D0F8D92B7498F2".to_owned(),
        }];
        assert_eq!(
            plan_gpg(&gpg(false), &current, false).unwrap(),
            [Operation::Noop]
        );
        assert_eq!(
            plan_gpg(&gpg(false), &current, true).unwrap(),
            [Operation::DeleteGpg {
                name: "atlas".to_owned(),
                id: 3
            }]
        );
    }

    #[test]
    fn ssh_comment_is_not_drift_but_key_change_is() {
        let current = [observed_ssh(1, "atlas", "ssh-ed25519 AAAA")];
        assert_eq!(
            plan_ssh(&ssh("ssh-ed25519 AAAA bot@atlas"), &current, false).unwrap(),
            [Operation::Noop]
        );
        let error = plan_ssh(&ssh("ssh-ed25519 BBBB"), &current, false).expect_err("drift fails");
        assert!(error.to_string().contains("refusing implicit key rotation"));
    }

    #[test]
    fn ssh_missing_key_is_added_and_undeclared_left_alone() {
        let current = [observed_ssh(9, "manual", "ssh-ed25519 CCCC")];
        assert_eq!(
            plan_ssh(&ssh("ssh-ed25519 AAAA"), &current, true).unwrap(),
            [Operation::AddSsh {
                title: "atlas".to_owned(),
                key: "ssh-ed25519 AAAA".to_owned()
            }]
        );
    }

    #[test]
    fn owned_selection_skips_archived_repositories() {
        let owned = [repo("owner/live", false), repo("owner/old", true)];
        assert_eq!(
            selected_repositories(&owned, &Repositories::Owned(OwnedTag::Owned)),
            [("owner".to_owned(), "live".to_owned())]
        );
    }

    #[test]
    fn only_trusted_inviter_and_owner_are_accepted() {
        let invite = |id, inviter: &str, full_name: &str| Invitation {
            id,
            inviter: Some(Account {
                login: inviter.to_owned(),
            }),
            repository: repo(full_name, false),
        };
        let invitations = [
            invite(1, "Owner", "owner/repo"),
            invite(2, "stranger", "owner/repo"),
            invite(3, "owner", "stranger/repo"),
        ];
        let trusted = BTreeSet::from(["owner".to_owned()]);
        let accepted: Vec<i64> = trusted_invitations(&invitations, &trusted)
            .iter()
            .map(|invite| invite.id)
            .collect();
        assert_eq!(accepted, [1]);
    }
}
