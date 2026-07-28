//! Idempotent and deletion-guarded Forgejo SSH-key reconciliation.

use std::collections::BTreeMap;

use anyhow::{Context, Result, bail};
use provenance_core::reconcile::Summary;

use crate::client::{ForgejoClient, PublicKey};
use crate::state::{KeySpec, State};

/// One safe mutation selected by the pure planning pass.
#[derive(Debug, PartialEq, Eq)]
pub enum Operation {
    /// Add a missing key.
    Create {
        /// Stable Forgejo username.
        username: String,
        /// Stable Forgejo key title.
        title: String,
        /// Normalized OpenSSH public key.
        key: String,
        /// Desired read-only flag.
        read_only: bool,
    },
    /// Remove an explicitly absent key after the global deletion gate passed.
    Delete {
        /// Stable Forgejo username.
        username: String,
        /// Stable Forgejo key title.
        title: String,
        /// Forgejo key id.
        id: i64,
    },
    /// Leave a matching (or deletion-gated) key untouched.
    Noop,
}

/// Normalize the managed portion of an OpenSSH public key.
///
/// Comments are intentionally ignored, so adding or changing a local comment
/// does not cause a key rotation. Private keys, options, and malformed key
/// bodies are rejected before any HTTP mutation is attempted.
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
    if blob.is_empty()
        || !blob
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'='))
    {
        bail!("SSH public-key body is not valid base64 text");
    }
    Ok(format!("{kind} {blob}"))
}

/// Plan operations for one username without touching the network.
pub fn plan(
    username: &str,
    desired: &BTreeMap<String, KeySpec>,
    current: &[PublicKey],
    allow_delete: bool,
) -> Result<Vec<Operation>> {
    let mut desired_keys = BTreeMap::new();
    for (title, spec) in desired {
        if spec.present {
            let key = normalize_key(spec.key.as_deref().ok_or_else(|| {
                anyhow::anyhow!("Forgejo SSH-key {username}/{title} has no public key")
            })?)?;
            if let Some(other_title) = desired_keys.insert(key, title)
                && other_title != title
            {
                bail!(
                    "Forgejo user {username} declares the same SSH key under titles {other_title} and {title}"
                );
            }
        }
    }

    let observed = current
        .iter()
        .map(|key| {
            normalize_key(&key.key)
                .with_context(|| format!("Forgejo returned malformed SSH key {}", key.id))
                .map(|normalized| (key, normalized))
        })
        .collect::<Result<Vec<_>>>()?;

    desired
        .iter()
        .map(|(title, spec)| {
            let matches: Vec<(&PublicKey, &String)> = observed
                .iter()
                .filter(|(key, _)| key.title == *title)
                .map(|(key, normalized)| (*key, normalized))
                .collect();
            if matches.len() > 1 {
                bail!("Forgejo user {username} has multiple SSH keys titled {title}");
            }

            if spec.present {
                let desired_key = normalize_key(spec.key.as_deref().ok_or_else(|| {
                    anyhow::anyhow!("Forgejo SSH-key {username}/{title} has no public key")
                })?)?;
                if let Some((current_key, current_normalized)) = matches.first().copied() {
                    if observed.iter().any(|(other, normalized)| {
                        other.title != *title && normalized == &desired_key
                    }) {
                        bail!(
                            "Forgejo user {username} has the desired SSH key under more than one title"
                        );
                    }
                    if current_normalized != &desired_key
                        || current_key.read_only != spec.read_only
                    {
                        bail!(
                            "Forgejo SSH key {username}/{title} drifted; refusing implicit key rotation"
                        );
                    }
                    Ok(Operation::Noop)
                } else if observed
                    .iter()
                    .any(|(_, normalized)| normalized == &desired_key)
                {
                    bail!(
                        "Forgejo user {username} already has the desired SSH key under another title"
                    );
                } else {
                    Ok(Operation::Create {
                        username: username.to_owned(),
                        title: title.to_owned(),
                        key: desired_key,
                        read_only: spec.read_only,
                    })
                }
            } else if let Some((current_key, _)) = matches.first().copied() {
                if allow_delete {
                    Ok(Operation::Delete {
                        username: username.to_owned(),
                        title: title.to_owned(),
                        id: current_key.id,
                    })
                } else {
                    Ok(Operation::Noop)
                }
            } else {
                Ok(Operation::Noop)
            }
        })
        .collect()
}

/// Reconcile every declared Forgejo user and return an operation summary.
pub fn reconcile(client: &ForgejoClient, state: &State, allow_delete: bool) -> Result<Summary> {
    let mut operations = Vec::new();
    for (username, desired) in &state.ssh_keys {
        let current = client.list_keys(username)?;
        operations.extend(plan(username, desired, &current, allow_delete)?);
    }

    let mut summary = Summary::default();
    for operation in operations {
        match operation {
            Operation::Create {
                username,
                title,
                key,
                read_only,
            } => {
                client.create_key(&username, &title, &key, read_only)?;
                summary.created += 1;
            }
            Operation::Delete {
                username,
                title,
                id,
            } => {
                client.delete_key(&username, &title, id)?;
                summary.deleted += 1;
            }
            Operation::Noop => summary.unchanged += 1,
        }
    }
    Ok(summary)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(key: &str) -> KeySpec {
        KeySpec {
            present: true,
            key: Some(key.to_owned()),
            read_only: false,
        }
    }

    fn observed(id: i64, title: &str, key: &str, read_only: bool) -> PublicKey {
        PublicKey {
            id,
            title: title.to_owned(),
            key: key.to_owned(),
            read_only,
        }
    }

    #[test]
    fn comments_do_not_create_drift() {
        let mut desired = BTreeMap::new();
        desired.insert("laptop".to_owned(), spec("ssh-ed25519 AAAA desired"));
        let current = [observed(1, "laptop", "ssh-ed25519 AAAA old-comment", false)];
        assert_eq!(
            plan("can", &desired, &current, false).unwrap(),
            [Operation::Noop]
        );
    }

    #[test]
    fn missing_key_is_created() {
        let mut desired = BTreeMap::new();
        desired.insert("laptop".to_owned(), spec("ssh-ed25519 AAAA"));
        let operations = plan("can", &desired, &[], false).unwrap();
        assert!(matches!(
            &operations[0],
            Operation::Create { title, key, .. } if title == "laptop" && key == "ssh-ed25519 AAAA"
        ));
    }

    #[test]
    fn title_drift_fails_closed() {
        let mut desired = BTreeMap::new();
        desired.insert("laptop".to_owned(), spec("ssh-ed25519 AAAA desired"));
        let current = [observed(1, "laptop", "ssh-ed25519 BBBB", false)];
        let error = plan("can", &desired, &current, false).expect_err("drift must fail");
        assert!(error.to_string().contains("refusing implicit key rotation"));
    }

    #[test]
    fn duplicate_desired_keys_fail_before_mutation() {
        let mut desired = BTreeMap::new();
        desired.insert("laptop".to_owned(), spec("ssh-ed25519 AAAA"));
        desired.insert("desktop".to_owned(), spec("ssh-ed25519 AAAA local"));
        let error = plan("can", &desired, &[], false).expect_err("duplicate keys must fail");
        assert!(error.to_string().contains("same SSH key under titles"));
    }

    #[test]
    fn deletion_requires_global_gate() {
        let mut desired = BTreeMap::new();
        desired.insert(
            "old".to_owned(),
            KeySpec {
                present: false,
                key: None,
                read_only: false,
            },
        );
        let current = [observed(7, "old", "ssh-ed25519 AAAA", false)];
        assert_eq!(
            plan("can", &desired, &current, false).unwrap(),
            [Operation::Noop]
        );
        assert!(matches!(
            &plan("can", &desired, &current, true).unwrap()[0],
            Operation::Delete { id: 7, .. }
        ));
    }

    #[test]
    fn undeclared_keys_are_left_alone() {
        let desired = BTreeMap::new();
        let current = [observed(7, "manual", "ssh-ed25519 AAAA", false)];
        assert!(plan("can", &desired, &current, true).unwrap().is_empty());
    }
}
