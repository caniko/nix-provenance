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
    // Windmill snapshots the admin flag into tokens at mint time, so a demotion
    // must drop every token the user already holds, not just tracked ones.
    let demote = if super_admin {
        String::new()
    } else {
        format!(
            "DELETE FROM token WHERE email = '{email}' \
             AND EXISTS (SELECT 1 FROM password WHERE email = '{email}' AND super_admin);\n"
        )
    };
    format!(
        "{demote}INSERT INTO password (email, verified, password_hash, login_type, super_admin, name, company, username) \
         VALUES ('{email}', true, '{hash}', 'password', {super_admin}, '{name}', 'provisioned', '{name}') \
         ON CONFLICT (email) DO UPDATE SET password_hash = EXCLUDED.password_hash, \
         login_type = 'password', super_admin = EXCLUDED.super_admin, verified = true, \
         company = 'provisioned', \
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

/// Reduce psql stderr to SQLSTATE codes only; anything else (statement text,
/// row detail) is dropped so a hash can never reach the journal.
pub fn sqlstate_summary(stderr: &str) -> String {
    let codes: Vec<&str> = stderr
        .lines()
        .filter_map(|l| l.strip_prefix("ERROR:").map(str::trim))
        .filter(|c| c.len() == 5 && c.chars().all(|ch| ch.is_ascii_alphanumeric()))
        .collect();
    if codes.is_empty() {
        "no SQLSTATE".to_owned()
    } else {
        format!("SQLSTATE {}", codes.join(","))
    }
}

/// Lock a provisioned user that is no longer declared: no password verifies,
/// no admin, no tokens. Only rows this tenant created (`company =
/// 'provisioned'`) are touched. Its workspace membership rows are deleted too,
/// which frees the username for a replacement login (an email change).
/// `email` must satisfy `state::is_safe_ident`.
pub fn lock_user_sql(email: &str) -> String {
    format!(
        "UPDATE password SET password_hash = '{LOCKED_HASH}', super_admin = false \
         WHERE email = '{email}' AND company = 'provisioned';\n\
         DELETE FROM token WHERE email = '{email}' \
         AND EXISTS (SELECT 1 FROM password WHERE email = '{email}' AND company = 'provisioned');\n\
         DELETE FROM usr_to_group WHERE (workspace_id, usr) IN \
         (SELECT workspace_id, username FROM usr WHERE email = '{email}') \
         AND EXISTS (SELECT 1 FROM password WHERE email = '{email}' AND company = 'provisioned');\n\
         DELETE FROM usr WHERE email = '{email}' \
         AND EXISTS (SELECT 1 FROM password WHERE email = '{email}' AND company = 'provisioned');\n"
    )
}

/// Revoke a removed token by its recorded identity: label plus owner email,
/// and the recorded file's prefix when it can still be read. Works for adopted
/// accounts too (no `provisioned` marker required). `label` and `email` must
/// satisfy `state::is_safe_ident`; the prefix comes from [`token_prefix`].
pub fn revoke_label_sql(
    label: &str,
    email: &str,
    old_prefix: Option<&str>,
    prefix_column: &str,
) -> String {
    let by_prefix = old_prefix
        .map(|p| format!(" OR {prefix_column} = '{p}'"))
        .unwrap_or_default();
    format!("DELETE FROM token WHERE label = '{label}' AND (email = '{email}'{by_prefix});\n")
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
            // VERBOSITY=sqlstate: errors carry only the SQLSTATE, never the
            // statement text or row values (which would echo the hash).
            .args(["-X", "-q", "-A", "-t", "-v", "ON_ERROR_STOP=1"])
            .args(["-v", "VERBOSITY=sqlstate", "-v", "SHOW_CONTEXT=never", "-d"])
            .arg(&self.database)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("spawning psql")?;
        child
            .stdin
            .take()
            .context("psql stdin")?
            .write_all(sql.as_bytes())?;
        let out = child.wait_with_output()?;
        if !out.status.success() {
            bail!(
                "psql failed with {}: {}",
                out.status,
                sqlstate_summary(&String::from_utf8_lossy(&out.stderr))
            );
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

    /// Emails of every login this tenant ever created.
    pub fn provisioned_emails(&self) -> Result<Vec<String>> {
        let out = self.run("SELECT email FROM password WHERE company = 'provisioned';\n")?;
        Ok(out
            .lines()
            .map(|l| l.trim().to_owned())
            .filter(|l| !l.is_empty())
            .collect())
    }

    /// The workspace username of `email` (it need not equal the declared key).
    pub fn workspace_username(&self, ws: &str, email: &str) -> Result<Option<String>> {
        let out = self.run(&format!(
            "SELECT username FROM usr WHERE workspace_id = '{ws}' AND email = '{email}';\n"
        ))?;
        Ok(out
            .lines()
            .map(str::trim)
            .find(|l| !l.is_empty())
            .map(str::to_owned))
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
    fn stderr_is_reduced_to_sqlstate() {
        let leaked =
            "ERROR:  23502\nERROR:  null value\nDETAIL:  Failing row contains ($argon2id$secret)\n";
        let summary = sqlstate_summary(leaked);
        assert_eq!(summary, "SQLSTATE 23502");
        assert!(!summary.contains("argon2"));
        assert_eq!(sqlstate_summary("garbage"), "no SQLSTATE");
    }

    #[test]
    fn pruning_sql_only_touches_provisioned_rows() {
        let lock = lock_user_sql("gone@example.com");
        assert!(lock.contains("company = 'provisioned'"));
        assert!(lock.contains("super_admin = false"));
        assert!(lock.contains("DELETE FROM token WHERE email = 'gone@example.com'"));
        assert!(lock.contains("DELETE FROM usr WHERE email = 'gone@example.com'"));
        // Revocation of a removed token does not require the provisioned marker.
        let revoke = revoke_label_sql("lbl", "a@b.c", Some("PREFIX0001"), "token_prefix");
        assert!(!revoke.contains("provisioned"));
        assert!(
            revoke.contains("label = 'lbl' AND (email = 'a@b.c' OR token_prefix = 'PREFIX0001')")
        );
    }

    #[test]
    fn sql_targets_only_the_named_rows() {
        let sql = upsert_user_sql("can@example.com", "can", "$argon2id$x", true);
        assert!(sql.contains("ON CONFLICT (email) DO UPDATE"));
        assert!(sql.contains("'can@example.com'"));
        assert!(sql.contains("company = 'provisioned', username"));
        assert!(!sql.contains("AND super_admin)"));
        let demote = upsert_user_sql("can@example.com", "can", "$argon2id$x", false);
        assert!(demote.starts_with("DELETE FROM token WHERE email = 'can@example.com'"));
        assert!(lock_default_admin_sql().contains(DEFAULT_ADMIN));
    }
}
