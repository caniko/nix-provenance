//! Small blocking client for the GitHub REST API, authenticated as the account itself.

use std::fmt;

use anyhow::{Context, Result, bail};
use provenance_core::http::{ensure_success, json_ok};
use reqwest::blocking::{Client, RequestBuilder};
use reqwest::{StatusCode, Url};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::state::Permission;

const PAGE_SIZE: usize = 100;
const API_VERSION: &str = "2022-11-28";

/// GitHub client holding a personal access token.
pub struct GithubClient {
    http: Client,
    api: Url,
    token: String,
}

impl fmt::Debug for GithubClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GithubClient")
            .field("api", &self.api)
            .field("token", &"<redacted>")
            .finish_non_exhaustive()
    }
}

/// A login reference embedded in other objects.
#[derive(Debug, Clone, Deserialize)]
pub struct Account {
    /// Account login.
    pub login: String,
}

/// An OpenPGP key registered on the authenticated account.
#[derive(Debug, Clone, Deserialize)]
pub struct GpgKey {
    /// GitHub's key id, used for deletion.
    pub id: i64,
    /// 16-digit long key id of the primary key.
    pub key_id: String,
}

/// An SSH authentication key registered on the authenticated account.
#[derive(Debug, Clone, Deserialize)]
pub struct SshKey {
    /// GitHub's key id, used for deletion.
    pub id: i64,
    /// Key title.
    pub title: String,
    /// OpenSSH public key without comment.
    pub key: String,
}

/// A repository owned by the authenticated account.
#[derive(Debug, Clone, Deserialize)]
pub struct Repository {
    /// `owner/name`.
    pub full_name: String,
    /// Archived repositories are read-only and cannot gain collaborators.
    #[serde(default)]
    pub archived: bool,
    /// Owning account.
    pub owner: Account,
}

/// A pending invitation addressed to the authenticated account.
#[derive(Debug, Clone, Deserialize)]
pub struct Invitation {
    /// Invitation id, used to accept it.
    pub id: i64,
    /// Inviting account; GitHub omits it for deleted accounts.
    #[serde(default)]
    pub inviter: Option<Account>,
    /// Target repository.
    pub repository: Repository,
}

#[derive(Debug, Deserialize)]
struct RepoInvitation {
    #[serde(default)]
    invitee: Option<Account>,
}

#[derive(Serialize)]
struct NewGpgKey<'a> {
    name: &'a str,
    armored_public_key: &'a str,
}

#[derive(Serialize)]
struct NewSshKey<'a> {
    title: &'a str,
    key: &'a str,
}

#[derive(Serialize)]
struct Invite {
    permission: Permission,
}

impl GithubClient {
    /// Build a client for a GitHub REST API root (normally https://api.github.com).
    pub fn new(api_url: &str, token: &str) -> Result<Self> {
        if token.trim().is_empty() {
            bail!("GitHub token must not be empty");
        }
        let mut api = Url::parse(api_url.trim()).context("parsing GitHub API URL")?;
        if !matches!(api.scheme(), "http" | "https") || api.host_str().is_none() {
            bail!("GitHub API URL must use http or https and include a host");
        }
        let path = format!("{}/", api.path().trim_end_matches('/'));
        api.set_path(&path);
        let http = provenance_core::http::build_blocking_client(
            concat!("github-provision/", env!("CARGO_PKG_VERSION")),
            false,
            Some(std::time::Duration::from_secs(30)),
        )?;
        Ok(Self {
            http,
            api,
            token: token.trim().to_owned(),
        })
    }

    /// Login the token authenticates as.
    pub fn login(&self) -> Result<String> {
        let response = self
            .request(self.http.get(self.url(&["user"])?))
            .send()
            .context("reading the authenticated GitHub user")?;
        Ok(json_ok::<Account>(response, "GitHub user")?.login)
    }

    /// OpenPGP keys on the authenticated account.
    pub fn gpg_keys(&self) -> Result<Vec<GpgKey>> {
        self.get_all(&["user", "gpg_keys"], &[], "GitHub GPG-key list")
    }

    /// Register an armored OpenPGP public key.
    pub fn add_gpg_key(&self, name: &str, armored_public_key: &str) -> Result<()> {
        let response = self
            .request(self.http.post(self.url(&["user", "gpg_keys"])?))
            .json(&NewGpgKey {
                name,
                armored_public_key,
            })
            .send()
            .with_context(|| format!("adding GitHub GPG key {name}"))?;
        ensure_success(response)?;
        Ok(())
    }

    /// Delete an OpenPGP key by GitHub id.
    pub fn delete_gpg_key(&self, name: &str, id: i64) -> Result<()> {
        self.delete(
            &["user", "gpg_keys", &id.to_string()],
            &format!("GitHub GPG key {name}"),
        )
    }

    /// SSH authentication keys on the authenticated account.
    pub fn ssh_keys(&self) -> Result<Vec<SshKey>> {
        self.get_all(&["user", "keys"], &[], "GitHub SSH-key list")
    }

    /// Register an SSH authentication key.
    pub fn add_ssh_key(&self, title: &str, key: &str) -> Result<()> {
        let response = self
            .request(self.http.post(self.url(&["user", "keys"])?))
            .json(&NewSshKey { title, key })
            .send()
            .with_context(|| format!("adding GitHub SSH key {title}"))?;
        ensure_success(response)?;
        Ok(())
    }

    /// Delete an SSH authentication key by GitHub id.
    pub fn delete_ssh_key(&self, title: &str, id: i64) -> Result<()> {
        self.delete(
            &["user", "keys", &id.to_string()],
            &format!("GitHub SSH key {title}"),
        )
    }

    /// Repositories owned by the authenticated account.
    pub fn owned_repositories(&self) -> Result<Vec<Repository>> {
        self.get_all(
            &["user", "repos"],
            &[("affiliation", "owner")],
            "GitHub repository list",
        )
    }

    /// Whether `user` already collaborates on `owner/name`, or has a pending invitation.
    pub fn has_access_or_invite(&self, owner: &str, name: &str, user: &str) -> Result<bool> {
        let response = self
            .request(
                self.http
                    .get(self.url(&["repos", owner, name, "collaborators", user])?),
            )
            .send()
            .with_context(|| format!("checking {user} on {owner}/{name}"))?;
        match response.status() {
            StatusCode::NO_CONTENT => return Ok(true),
            StatusCode::NOT_FOUND => {}
            _ => {
                ensure_success(response)?;
            }
        }
        let invites: Vec<RepoInvitation> = self.get_all(
            &["repos", owner, name, "invitations"],
            &[],
            "GitHub repository invitation list",
        )?;
        Ok(invites.iter().any(|invite| {
            invite
                .invitee
                .as_ref()
                .is_some_and(|invitee| invitee.login.eq_ignore_ascii_case(user))
        }))
    }

    /// Invite `user` to `owner/name` with `permission`.
    pub fn invite(
        &self,
        owner: &str,
        name: &str,
        user: &str,
        permission: Permission,
    ) -> Result<()> {
        let response = self
            .request(
                self.http
                    .put(self.url(&["repos", owner, name, "collaborators", user])?),
            )
            .json(&Invite { permission })
            .send()
            .with_context(|| format!("inviting {user} to {owner}/{name}"))?;
        ensure_success(response)?;
        Ok(())
    }

    /// Pending invitations addressed to the authenticated account.
    pub fn invitations(&self) -> Result<Vec<Invitation>> {
        self.get_all(
            &["user", "repository_invitations"],
            &[],
            "GitHub invitation list",
        )
    }

    /// Accept one invitation.
    pub fn accept(&self, invitation: &Invitation) -> Result<()> {
        let response = self
            .request(self.http.patch(self.url(&[
                "user",
                "repository_invitations",
                &invitation.id.to_string(),
            ])?))
            .send()
            .with_context(|| {
                format!(
                    "accepting the invitation to {}",
                    invitation.repository.full_name
                )
            })?;
        ensure_success(response)?;
        Ok(())
    }

    fn get_all<T: DeserializeOwned>(
        &self,
        segments: &[&str],
        query: &[(&str, &str)],
        what: &str,
    ) -> Result<Vec<T>> {
        let mut items = Vec::new();
        for page in 1_u32.. {
            let response = self
                .request(self.http.get(self.url(segments)?))
                .query(query)
                .query(&[("per_page", PAGE_SIZE as u32), ("page", page)])
                .send()
                .with_context(|| format!("listing {what}"))?;
            let page_items: Vec<T> = json_ok(response, what)?;
            let count = page_items.len();
            items.extend(page_items);
            if count < PAGE_SIZE {
                break;
            }
        }
        Ok(items)
    }

    fn delete(&self, segments: &[&str], what: &str) -> Result<()> {
        let response = self
            .request(self.http.delete(self.url(segments)?))
            .send()
            .with_context(|| format!("deleting {what}"))?;
        ensure_success(response)?;
        Ok(())
    }

    fn request(&self, request: RequestBuilder) -> RequestBuilder {
        request
            .bearer_auth(&self.token)
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", API_VERSION)
    }

    fn url(&self, segments: &[&str]) -> Result<Url> {
        let mut url = self.api.clone();
        url.path_segments_mut()
            .map_err(|_| anyhow::anyhow!("GitHub API URL cannot accept path segments"))?
            .pop_if_empty()
            .extend(segments.iter().copied());
        Ok(url)
    }
}
