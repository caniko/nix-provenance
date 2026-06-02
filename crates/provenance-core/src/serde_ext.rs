//! serde helpers shared by the state schemas.

/// serde `default` for `bool` fields that should default to `true`.
#[must_use]
pub fn default_true() -> bool {
    true
}

/// Distinguish "field absent" from "field present and explicitly null" by
/// deserializing into `Option<Option<T>>`: outer `None` = absent, `Some(None)`
/// = present-and-null, `Some(Some(v))` = present-with-value. This lets a
/// reconciler tell "leave unchanged" from "clear to null". Use as
/// `#[serde(default, deserialize_with = "…::serde_ext::double_option::deserialize")]`.
pub mod double_option {
    use serde::{Deserialize, Deserializer};

    pub fn deserialize<'de, D, T>(deserializer: D) -> Result<Option<Option<T>>, D::Error>
    where
        D: Deserializer<'de>,
        T: Deserialize<'de>,
    {
        Option::<T>::deserialize(deserializer).map(Some)
    }
}
