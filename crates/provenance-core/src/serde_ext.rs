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

    /// Deserialize an optional field into `Option<Option<T>>`, preserving the
    /// distinction between an absent field and an explicit JSON `null`.
    ///
    /// # Errors
    ///
    /// Returns the deserializer's error when the present value cannot be
    /// deserialized as `T`.
    pub fn deserialize<'de, D, T>(deserializer: D) -> Result<Option<Option<T>>, D::Error>
    where
        D: Deserializer<'de>,
        T: Deserialize<'de>,
    {
        Option::<T>::deserialize(deserializer).map(Some)
    }
}

#[cfg(test)]
mod tests {
    use serde::Deserialize;

    use super::*;

    #[derive(Debug, Deserialize)]
    struct Enabled {
        #[serde(default = "default_true")]
        enabled: bool,
    }

    #[derive(Debug, Deserialize)]
    struct Patch {
        #[serde(default, deserialize_with = "double_option::deserialize")]
        label: Option<Option<String>>,
    }

    #[test]
    fn default_true_sets_absent_bool_to_true() {
        let parsed: Enabled = serde_json::from_str("{}").unwrap();
        assert!(parsed.enabled);
    }

    #[test]
    fn double_option_distinguishes_absent_null_and_value() {
        let absent: Patch = serde_json::from_str("{}").unwrap();
        assert_eq!(absent.label, None);

        let null: Patch = serde_json::from_str(r#"{ "label": null }"#).unwrap();
        assert_eq!(null.label, Some(None));

        let value: Patch = serde_json::from_str(r#"{ "label": "photos" }"#).unwrap();
        assert_eq!(value.label, Some(Some("photos".to_string())));
    }
}
