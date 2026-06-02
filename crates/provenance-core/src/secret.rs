//! Resolve a secret from a file (preferred) or an inline value, keeping it out
//! of argv and the Nix store.

use std::fs;
use std::path::Path;

use anyhow::{anyhow, bail, Context, Result};

/// Resolve a secret, preferring `file` over `inline`, trimming surrounding
/// whitespace and rejecting empties. `what` names the secret in error messages;
/// `flag_hint` and `env_hint` are surfaced when neither source is provided.
pub fn resolve(
    file: Option<&Path>,
    inline: Option<&str>,
    what: &str,
    flag_hint: &str,
    env_hint: &str,
) -> Result<String> {
    if let Some(path) = file {
        let raw = fs::read_to_string(path)
            .with_context(|| format!("reading {what} file {}", path.display()))?;
        let value = raw.trim().to_owned();
        if value.is_empty() {
            bail!("{what} file {} is empty", path.display());
        }
        return Ok(value);
    }
    inline
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow!("no {what}: pass {flag_hint} or set {env_hint}"))
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    fn write_secret(contents: &str) -> std::path::PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before Unix epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("nix-provenance-secret-test-{nanos}"));
        fs::write(&path, contents).expect("write secret fixture");
        path
    }

    #[test]
    fn file_takes_precedence_and_is_trimmed() {
        let path = write_secret(" file-secret \n");
        let value = resolve(
            Some(&path),
            Some("inline-secret"),
            "token",
            "--token-file",
            "TOKEN",
        )
        .expect("file secret resolves");

        assert_eq!(value, "file-secret");
        fs::remove_file(path).expect("remove secret fixture");
    }

    #[test]
    fn empty_file_is_rejected() {
        let path = write_secret(" \n\t");
        let err = resolve(Some(&path), None, "token", "--token-file", "TOKEN")
            .expect_err("empty file must fail");

        assert!(err.to_string().contains("token file"));
        assert!(err.to_string().contains("is empty"));
        fs::remove_file(path).expect("remove secret fixture");
    }

    #[test]
    fn inline_secret_is_trimmed_when_no_file_is_set() {
        let value = resolve(
            None,
            Some(" inline-secret\n"),
            "token",
            "--token-file",
            "TOKEN",
        )
        .expect("inline secret resolves");

        assert_eq!(value, "inline-secret");
    }

    #[test]
    fn missing_secret_reports_sources() {
        let err = resolve(None, None, "token", "--token-file", "TOKEN")
            .expect_err("missing secret must fail");

        let message = err.to_string();
        assert!(message.contains("no token"));
        assert!(message.contains("--token-file"));
        assert!(message.contains("TOKEN"));
    }
}
