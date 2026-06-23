//! Declarative Vikunja team and webhook state schema.
//!
//! The state file is a JSON document with two top-level maps:
//! - `teams` — keyed by Vikunja team name
//! - `webhooks` — keyed by Vikunja project ID (string)

use std::collections::BTreeMap;

use provenance_core::serde_ext::default_true as default_present;
use serde::Deserialize;

/// Top-level declarative state.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct State {
    #[serde(default)]
    pub teams: BTreeMap<String, TeamSpec>,
    #[serde(default)]
    pub webhooks: BTreeMap<String, WebhookSpec>,
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

/// Desired state for one Vikunja project webhook.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebhookSpec {
    #[serde(default = "default_present")]
    pub present: bool,
    /// Webhook target URL.
    pub url: String,
    /// Vikunja events to subscribe to.
    #[serde(default)]
    pub events: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_minimal_state() {
        let s: State = serde_json::from_str("{}").unwrap();
        assert!(s.teams.is_empty());
        assert!(s.webhooks.is_empty());
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

    #[test]
    fn webhook_parses() {
        let s: State = serde_json::from_str(
            r#"{ "webhooks": { "4": { "url": "https://example.com/hook", "events": ["task.created"] } } }"#,
        )
        .unwrap();
        let w = &s.webhooks["4"];
        assert!(w.present);
        assert_eq!(w.url, "https://example.com/hook");
        assert_eq!(w.events, vec!["task.created"]);
    }
}
