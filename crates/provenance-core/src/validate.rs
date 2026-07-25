//! Fail-fast validation primitives.

use crate::{Error, Result};

/// Reject an empty trimmed string with a descriptive error naming the
/// parameter.
///
/// # Errors
///
/// Returns an error when `value` is empty or whitespace-only.
pub fn require_non_empty(value: &str, label: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(Error::invalid(format!("{label} must not be empty")));
    }
    Ok(())
}
