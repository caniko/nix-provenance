//! Declarative Vikunja team state schema.
//!
//! The state file is a JSON document with one top-level `teams` map, keyed by
//! Vikunja team name. `members` and `admins` contain kanidm usernames, not
//! numeric Vikunja user ids; Vikunja resolves usernames on member add/remove.

use std::collections::BTreeMap;

use provenance_core::serde_ext::default_true as default_present;
use serde::Deserialize;

/// Top-level declarative state. Keys are Vikunja team names.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct State {
    #[serde(default)]
    pub teams: BTreeMap<String, TeamSpec>,
}

/// Desired state for one API-managed local Vikunja team.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TeamSpec {
    #[serde(default = "default_present")]
    pub present: bool,
    /// Non-admin team members, by kanidm username.
    #[serde(default)]
    pub members: Vec<String>,
    /// Admin team members, by kanidm username.
    #[serde(default)]
    pub admins: Vec<String>,
    #[serde(default)]
    pub description: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_minimal_state() {
        let s: State = serde_json::from_str("{}").unwrap();
        assert!(s.teams.is_empty());
    }

    #[test]
    fn team_defaults_present_and_empty_membership() {
        let s: State =
            serde_json::from_str(r#"{ "teams": { "ops": { "description": "Ops" } } }"#).unwrap();
        let t = &s.teams["ops"];
        assert!(t.present);
        assert!(t.members.is_empty());
        assert!(t.admins.is_empty());
        assert_eq!(t.description.as_deref(), Some("Ops"));
    }
}
