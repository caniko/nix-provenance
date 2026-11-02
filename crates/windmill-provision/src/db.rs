//! Direct PostgreSQL writes for the one thing Windmill's open-source server
//! cannot do over HTTP: create users and set passwords
//! (`users_oss::{create_user,set_password}` return "not implemented").
//!
//! Only an argon2id hash ever leaves this process, on psql's stdin.

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use anyhow::{Context as _, Result, bail};
use argon2::password_hash::SaltString;
use argon2::{Algorithm, Argon2, Params, PasswordHasher, Version};
use rand::RngCore;

/// Default account seeded by Windmill's first migration with password `changeme`.
pub const DEFAULT_ADMIN: &str = "admin@windmill.dev";
/// Hash that no password verifies against; works on every Windmill version
/// (the `disabled` column only exists in newer ones).
const LOCKED_HASH: &str = "!locked-by-windmill-provision";

/// Argon2id with the parameters Windmill seeds its own accounts with
/// (m=4096,t=3,p=1); the PHC string carries them, so Windmill verifies any.
pub fn hash_password(password: &str) -> Result<String> {
    let mut salt = [0u8; 16];
    rand::rng().fill_bytes(&mut salt);
    let salt = SaltString::encode_b64(&salt).map_err(|e| anyhow::anyhow!("salt: {e}"))?;
    let params = Params::new(4096, 3, 1, None).map_err(|e| anyhow::anyhow!("params: {e}"))?;
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| anyhow::anyhow!("hashing password: {e}"))
}

/// `email` must satisfy `state::is_safe_ident` and `name` Windmill's username
/// rule (`state::is_username`); `hash` is a PHC string (no quotes). The
/// instance-wide `username` is required by workspace `add_user`.
pub fn upsert_user_sql(email: &str, name: &str, hash: &str, super_admin: bool) -> String {
    format!(
        "INSERT INTO password (email, verified, password_hash, login_type, super_admin, name, company, username) \
         VALUES ('{email}', true, '{hash}', 'password', {super_admin}, '{name}', 'provisioned', '{name}') \
         ON CONFLICT (email) DO UPDATE SET password_hash = EXCLUDED.password_hash, \
         login_type = 'password', super_admin = EXCLUDED.super_admin, verified = true, \
         username = COALESCE(password.username, EXCLUDED.username);\n\
         DELETE FROM token WHERE email = '{email}' AND label = 'session';\n"
    )
}

/// Windmill stores the first 10 characters of a token as its `token_prefix`.
pub const TOKEN_PREFIX_LEN: usize = 10;

pub fn token_prefix(token: &str) -> Option<&str> {
    let prefix = token.get(..TOKEN_PREFIX_LEN)?;
    prefix
        .chars()
        .all(|c| c.is_ascii_alphanumeric())
        .then_some(prefix)
}

/// Delete every previous token of `label`, keeping only `keep_prefix`: the
/// declared user's older tokens of that label, plus the one the previous token
/// file held (it may belong to a different user if the spec changed).
/// `prefix_column` is `token_prefix`, or `left(token, 10)` on Windmill versions
/// that predate that column. `label` and `email` must satisfy `state::is_safe_ident`; prefixes come from
/// [`token_prefix`].
pub fn revoke_old_tokens_sql(
    label: &str,
    email: &str,
    keep_prefix: &str,
    old_prefix: Option<&str>,
    prefix_column: &str,
) -> String {
    let old = old_prefix
        .map(|p| format!(" OR {prefix_column} = '{p}'"))
        .unwrap_or_default();
    format!(
        "DELETE FROM token WHERE label = '{label}' AND {prefix_column} <> '{keep_prefix}' \
         AND (email = '{email}'{old});\n"
    )
}

pub fn lock_default_admin_sql() -> String {
    format!(
        "UPDATE password SET password_hash = '{LOCKED_HASH}' WHERE email = '{DEFAULT_ADMIN}' \
         AND password_hash <> '{LOCKED_HASH}';\n\
         DELETE FROM token WHERE email = '{DEFAULT_ADMIN}';\n"
    )
}

pub struct Psql {
    pub runuser: PathBuf,
    pub psql: PathBuf,
    pub database: String,
}

impl Psql {
    /// Run `sql` as the local `postgres` superuser (peer auth) and return stdout.
    pub fn run(&self, sql: &str) -> Result<String> {
        let mut child = Command::new(&self.runuser)
            .args(["-u", "postgres", "--"])
            .arg(&self.psql)
            .args(["-X", "-q", "-A", "-t", "-v", "ON_ERROR_STOP=1", "-d"])
            .arg(&self.database)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .context("spawning psql")?;
        child
            .stdin
            .take()
            .context("psql stdin")?
            .write_all(sql.as_bytes())?;
        let out = child.wait_with_output()?;
        if !out.status.success() {
            bail!("psql failed with {}", out.status);
        }
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    }

    /// The SQL expression yielding a token's prefix on this Windmill version.
    pub fn token_prefix_column(&self) -> Result<&'static str> {
        let out = self.run(
            "SELECT 1 FROM information_schema.columns WHERE table_name = 'token' AND column_name = 'token_prefix';\n",
        )?;
        Ok(if out.trim() == "1" {
            "token_prefix"
        } else {
            "left(token, 10)"
        })
    }

    pub fn user_has_argon2_hash(&self, email: &str) -> Result<bool> {
        let out = self.run(&format!(
            "SELECT 1 FROM password WHERE email = '{email}' AND password_hash LIKE '$argon2%';\n"
        ))?;
        Ok(out.trim() == "1")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use argon2::PasswordVerifier;
    use argon2::password_hash::PasswordHash;

    #[test]
    fn hash_verifies_and_fits_the_password_column() {
        let hash = hash_password("correct horse").unwrap();
        assert!(hash.len() <= 100, "password_hash is VARCHAR(100): {hash}");
        let parsed = PasswordHash::new(&hash).unwrap();
        assert!(
            Argon2::default()
                .verify_password(b"correct horse", &parsed)
                .is_ok()
        );
        assert!(
            Argon2::default()
                .verify_password(b"wrong", &parsed)
                .is_err()
        );
        assert!(!hash.contains('\''));
    }

    #[test]
    fn revocation_keeps_only_the_new_token() {
        let sql = revoke_old_tokens_sql(
            "lbl",
            "can@example.com",
            "NEWPREFIX1",
            Some("OLDPREFIX2"),
            "token_prefix",
        );
        assert!(sql.contains("label = 'lbl'"));
        assert!(sql.contains("token_prefix <> 'NEWPREFIX1'"));
        assert!(sql.contains("OR token_prefix = 'OLDPREFIX2'"));
        assert!(
            !revoke_old_tokens_sql("l", "e@x.y", "N", None, "left(token, 10)")
                .contains("OR token_prefix")
        );
        assert_eq!(token_prefix("abcdefghijKLM"), Some("abcdefghij"));
        assert_eq!(token_prefix("short"), None);
        assert_eq!(token_prefix("abc'defghijk"), None);
    }

    #[test]
    fn sql_targets_only_the_named_rows() {
        let sql = upsert_user_sql("can@example.com", "can", "$argon2id$x", true);
        assert!(sql.contains("ON CONFLICT (email) DO UPDATE"));
        assert!(sql.contains("'can@example.com'"));
        assert!(lock_default_admin_sql().contains(DEFAULT_ADMIN));
    }
}
