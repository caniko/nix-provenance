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
