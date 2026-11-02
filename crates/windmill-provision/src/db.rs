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
    fn sql_targets_only_the_named_rows() {
        let sql = upsert_user_sql("can@example.com", "can", "$argon2id$x", true);
        assert!(sql.contains("ON CONFLICT (email) DO UPDATE"));
        assert!(sql.contains("'can@example.com'"));
        assert!(lock_default_admin_sql().contains(DEFAULT_ADMIN));
    }
}
