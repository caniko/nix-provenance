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

/// Lexical identity of a token path: absolute, no `.`/`..`, longest existing ancestor resolved
/// through symlinks, so aliases collide.
fn same_file_key(path: &std::path::Path) -> PathBuf {
    // Resolve the longest existing ancestor; ensure_dir creates the rest below it.
    let mut existing = path.parent().unwrap_or(path).to_path_buf();
    let mut rest = vec![path.file_name().unwrap_or_default().to_owned()];
    while !existing.exists() {
        let Some(name) = existing.file_name().map(|n| n.to_owned()) else {
            break;
        };
        rest.push(name);
        existing.pop();
    }
    let mut key = existing.canonicalize().unwrap_or(existing);
    key.extend(rest.iter().rev());
    key
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
                token.path.is_absolute()
                    && token.path.file_name().is_some()
                    && !token.path.components().any(|c| matches!(
                        c,
                        std::path::Component::ParentDir | std::path::Component::CurDir
                    )),
                "token {label}: path must be absolute, name a file and have no . or .. components"
            );
        }
        for (label, token) in &self.tokens {
            ensure!(
                paths.insert(same_file_key(&token.path)),
                "token {label}: path {} used twice",
                token.path.display()
            );
        }
        for (name, user) in &self.users {
            ensure!(
                user.email == user.email.to_ascii_lowercase(),
                "user {name}: email must be lowercase (Windmill lowercases logins)"
            );
            ensure!(
                !user.email.eq_ignore_ascii_case(crate::db::DEFAULT_ADMIN),
                "user {name}: {} is the stock admin that disableDefaultAdmin locks",
                user.email
            );
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
            ensure!(is_safe_ident(label), "token label {label:?} is unsafe");
            ensure!(
                label != "session",
                "token label \"session\" is reserved by Windmill"
            );
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
                // A non-admin non-member has no identity on that workspace, so
                // the token would be unusable and re-minted on every run.
                let owner = &self.users[&token.user];
                ensure!(
                    owner.admin || owner.workspaces.contains(ws),
                    "token {label}: user {} is not a member of workspace {ws}",
                    token.user
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
    use std::fs;

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
                email: "can@example.com".into(),
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
    fn rejects_uppercase_emails() {
        let mut s = state(BASE);
        s.users.get_mut("can").unwrap().email = "Can@example.com".into();
        assert!(s.validate().is_err());
    }

    #[test]
    fn aliased_token_paths_through_a_symlink_collide() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real");
        fs::create_dir(&real).unwrap();
        std::os::unix::fs::symlink(&real, dir.path().join("link")).unwrap();
        assert_eq!(
            same_file_key(&real.join("new/t")),
            same_file_key(&dir.path().join("link/new/t"))
        );
    }

    #[test]
    fn rejects_dotdot_token_paths() {
        let mut s = state(BASE);
        s.tokens.get_mut("t").unwrap().path = "/x/../x/t".into();
        assert!(s.validate().is_err());
    }

    #[test]
    fn rejects_token_path_without_a_file_name() {
        let mut s = state(BASE);
        s.tokens.get_mut("t").unwrap().path = "/".into();
        assert!(s.validate().is_err());
    }

    #[test]
    fn rejects_reserved_session_label() {
        let mut s = state(BASE);
        let t = s.tokens.remove("t").unwrap();
        s.tokens.insert("session".into(), t);
        assert!(s.validate().is_err());
    }

    #[test]
    fn rejects_stock_admin_email_case_insensitively() {
        let mut s = state(BASE);
        s.users.get_mut("can").unwrap().email = "admin@windmill.dev".into();
        assert!(s.validate().is_err());
    }

    #[test]
    fn rejects_workspace_token_for_non_member_non_admin() {
        let mut s = state(BASE);
        s.workspaces.insert(
            "other".into(),
            Workspace {
                name: "Other".into(),
            },
        );
        s.tokens.get_mut("t").unwrap().workspace = Some("other".into());
        s.users.get_mut("can").unwrap().admin = true;
        s.validate().unwrap(); // admins have an identity everywhere
        s.users.insert(
            "ops".into(),
            User {
                email: "ops@example.com".into(),
                credential_name: "q".into(),
                workspaces: vec![],
                admin: false,
            },
        );
        s.tokens.get_mut("t").unwrap().user = "ops".into();
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
