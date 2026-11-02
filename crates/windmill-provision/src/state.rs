//! Nix-rendered desired state. Holds paths and credential names only, never
//! secret values.

use std::collections::BTreeMap;
use std::path::PathBuf;

use anyhow::{Result, bail, ensure};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct State {
    pub url: String,
    /// Local PostgreSQL database holding Windmill's tables.
    pub database: String,
    /// Credential (file name inside `--credential-dir`) with SUPERADMIN_SECRET.
    pub superadmin_credential: String,
    pub disable_default_admin: bool,
    #[serde(default)]
    pub workspaces: BTreeMap<String, Workspace>,
    #[serde(default)]
    pub users: BTreeMap<String, User>,
    #[serde(default)]
    pub tokens: BTreeMap<String, Token>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Workspace {
    pub name: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct User {
    pub email: String,
    pub credential_name: String,
    #[serde(default)]
    pub workspaces: Vec<String>,
    pub admin: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Token {
    pub user: String,
    pub workspace: Option<String>,
    #[serde(default)]
    pub scopes: Vec<String>,
    pub path: PathBuf,
    pub owner: String,
    pub group: String,
    /// Octal file mode, for example `0640`.
    pub mode: String,
}

impl Token {
    pub fn mode_bits(&self) -> Result<u32> {
        let mode = u32::from_str_radix(self.mode.trim_start_matches("0o"), 8)?;
        ensure!(mode <= 0o777, "token mode {} out of range", self.mode);
        Ok(mode)
    }
}

/// Characters allowed in values that are later spliced into SQL literals.
pub fn is_safe_ident(value: &str) -> bool {
    !value.is_empty()
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "@._+-".contains(c))
}

/// Windmill's instance username rule: starts with a letter, then letters,
/// digits or underscores (max 50).
pub fn is_username(value: &str) -> bool {
    let mut chars = value.chars();
    chars.next().is_some_and(|c| c.is_ascii_alphabetic())
        && value.len() <= 50
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

impl State {
    pub fn validate(&self) -> Result<()> {
        let mut emails = std::collections::BTreeSet::new();
        let mut paths = std::collections::BTreeSet::new();
        for user in self.users.values() {
            ensure!(
                emails.insert(user.email.to_lowercase()),
                "duplicate user email {}",
                user.email
            );
        }
        for (label, token) in &self.tokens {
            ensure!(
                paths.insert(&token.path),
                "token {label}: path {} used twice",
                token.path.display()
            );
        }
        for (name, user) in &self.users {
            ensure!(is_safe_ident(&user.email), "user {name}: unsafe email");
            ensure!(
                is_username(name),
                "user {name}: name must match [A-Za-z][A-Za-z0-9_]*"
            );
            for ws in &user.workspaces {
                ensure!(
                    self.workspaces.contains_key(ws),
                    "user {name}: undeclared workspace {ws}"
                );
            }
        }
        for (id, ws) in &self.workspaces {
            ensure!(
                !id.is_empty()
                    && id
                        .chars()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || "_-".contains(c)),
                "workspace id {id} must match [a-z0-9_-]+"
            );
            ensure!(!ws.name.is_empty(), "workspace {id}: empty name");
        }
        for (label, token) in &self.tokens {
            ensure!(
                self.users.contains_key(&token.user),
                "token {label}: undeclared user {}",
                token.user
            );
            if let Some(ws) = &token.workspace {
                ensure!(
                    self.workspaces.contains_key(ws),
                    "token {label}: undeclared workspace {ws}"
                );
            }
            token.mode_bits()?;
        }
        if self.disable_default_admin && !self.users.values().any(|u| u.admin) {
            bail!("disable_default_admin needs at least one admin user to keep a login");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state(json: &str) -> State {
        serde_json::from_str(json).unwrap()
    }

    const BASE: &str = r#"{"url":"http://127.0.0.1:8001","database":"windmill",
        "superadmin_credential":"sa","disable_default_admin":true,
        "workspaces":{"studio":{"name":"Studio"}},
        "users":{"can":{"email":"can@example.com","credential_name":"p","workspaces":["studio"],"admin":true}},
        "tokens":{"t":{"user":"can","workspace":"studio","path":"/x/t","owner":"root","group":"studio","mode":"0640"}}}"#;

    #[test]
    fn valid_state_passes() {
        let s = state(BASE);
        s.validate().unwrap();
        assert_eq!(s.tokens["t"].mode_bits().unwrap(), 0o640);
    }

    #[test]
    fn rejects_duplicate_emails_and_token_paths() {
        let mut s = state(BASE);
        s.users.insert(
            "other".into(),
            User {
                email: "CAN@example.com".into(),
                credential_name: "q".into(),
                workspaces: vec![],
                admin: false,
            },
        );
        assert!(s.validate().is_err());
        let mut s = state(BASE);
        s.tokens.insert(
            "u".into(),
            Token {
                user: "can".into(),
                workspace: None,
                scopes: vec![],
                path: "/x/t".into(),
                owner: "root".into(),
                group: "root".into(),
                mode: "0600".into(),
            },
        );
        assert!(s.validate().is_err());
    }

    #[test]
    fn rejects_lockout_and_sql_metacharacters() {
        let mut s = state(BASE);
        s.users.get_mut("can").unwrap().admin = false;
        assert!(s.validate().is_err());
        let mut s = state(BASE);
        s.users.get_mut("can").unwrap().email = "a'; drop table password;--".into();
        assert!(s.validate().is_err());
        let mut s = state(BASE);
        let user = s.users.remove("can").unwrap();
        s.users.insert("bad-name".into(), user);
        assert!(s.validate().is_err());
        let mut s = state(BASE);
        s.tokens.get_mut("t").unwrap().user = "ghost".into();
        assert!(s.validate().is_err());
    }
}
