//! vikunja-provision -- declarative provisioning client for Vikunja teams and
//! webhooks.
//!
//! Reads a JSON state file describing desired API-managed local Vikunja teams,
//! memberships, and project webhooks, then reconciles a running Vikunja instance
//! over `/api/v1` with a long-lived scoped API token.

mod client;
mod state;

use std::fmt::Arguments;
use std::fs;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use provenance_core::setops::{is_subset, same_set, union};

use client::{AddMemberOutcome, TeamMember, VikunjaClient, WebhookSummary};
use state::{State, TeamSpec, WebhookSpec};

#[derive(Parser, Debug)]
#[command(
    name = "vikunja-provision",
    about = "Declaratively provision Vikunja teams, memberships, and webhooks",
    version
)]
struct Cli {
    /// Vikunja base URL (the `/api/v1` API path is appended automatically).
    #[arg(long)]
    url: String,

    /// Path to the JSON state file.
    #[arg(long)]
    state: PathBuf,

    /// File containing the Vikunja API token. Takes precedence over the
    /// `VIKUNJA_PROVISION_TOKEN` environment variable.
    #[arg(long)]
    token_file: Option<PathBuf>,

    /// Vikunja API token. Prefer `--token-file` so the secret does not appear
    /// in the process table.
    #[arg(long, env = "VIKUNJA_PROVISION_TOKEN", hide_env_values = true)]
    token: Option<String>,

    /// Service-account username to exclude from desired and observed membership.
    #[arg(long)]
    bot_username: String,

    /// File containing the HMAC secret for webhook creation. When provided,
    /// created webhooks include a signature for verification.
    #[arg(long)]
    webhook_secret_file: Option<PathBuf>,

    /// Seconds to wait for Vikunja readiness before failing.
    #[arg(long, default_value_t = 30)]
    ready_timeout: u32,

    /// Accept invalid TLS certificates (e.g. talking to an internal endpoint
    /// with a name mismatch). Avoid in production.
    #[arg(long)]
    accept_invalid_certs: bool,

    /// Skip destructive membership removals and explicit team deletions.
    #[arg(long)]
    no_auto_remove: bool,

    /// Allow deleting teams declared with `present = false`.
    #[arg(long)]
    allow_team_delete: bool,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let token = provenance_core::secret::resolve(
        cli.token_file.as_deref(),
        cli.token.as_deref(),
        "API token",
        "--token-file",
        "VIKUNJA_PROVISION_TOKEN",
    )?;
    let raw = fs::read_to_string(&cli.state)
        .with_context(|| format!("reading state file {}", cli.state.display()))?;
    let state: State = serde_json::from_str(&raw)
        .with_context(|| format!("parsing state file {}", cli.state.display()))?;

    let webhook_secret = cli
        .webhook_secret_file
        .as_ref()
        .map(|p| {
            fs::read_to_string(p)
                .with_context(|| format!("reading webhook secret file {}", p.display()))
                .map(|s| s.trim().to_owned())
        })
        .transpose()?;

    let client = VikunjaClient::new(&cli.url, &token, cli.accept_invalid_certs)?;
    client
        .wait_ready(cli.ready_timeout, Duration::from_secs(1))
        .context("waiting for vikunja to be ready")?;

    reconcile_teams(
        &client,
        &state,
        &cli.bot_username,
        cli.no_auto_remove,
        cli.allow_team_delete,
    )?;

    reconcile_webhooks(&client, &state, webhook_secret.as_deref())?;

    log(format_args!("done"));
    Ok(())
}

fn log(msg: Arguments<'_>) {
    eprintln!("[vikunja-provision] {msg}");
}

// ---------------------------------------------------------------------------
// Team reconciliation
// ---------------------------------------------------------------------------

fn reconcile_teams(
    client: &VikunjaClient,
    state: &State,
    bot_username: &str,
    no_auto_remove: bool,
    allow_team_delete: bool,
) -> Result<()> {
    let mut existing = client.list_teams()?;
    for (name, spec) in &state.teams {
        let current = existing.iter().find(|team| &team.name == name);
        match (spec.present, current) {
            (true, None) => {
                log(format_args!("create team {name}"));
                client.create_team(name, spec.description.as_deref())?;
                existing = client.list_teams()?;
            }
            (true, Some(team)) => {
                if description_drifted(team.description.as_deref(), spec.description.as_deref()) {
                    log(format_args!("update team {name} description"));
                    client.update_team(team.id, name, spec.description.as_deref())?;
                }
            }
            (false, Some(team)) if allow_team_delete && !no_auto_remove => {
                log(format_args!("delete team {name}"));
                client.delete_team(team.id, name)?;
            }
            _ => {}
        }
    }

    let existing = client.list_teams()?;
    for (name, spec) in &state.teams {
        if !spec.present {
            continue;
        }
        if let Some(team) = existing.iter().find(|team| &team.name == name) {
            reconcile_memberships(client, team.id, name, spec, bot_username, no_auto_remove)?;
        }
    }

    Ok(())
}

fn description_drifted(current: Option<&str>, desired: Option<&str>) -> bool {
    current.unwrap_or_default() != desired.unwrap_or_default()
}

fn reconcile_memberships(
    client: &VikunjaClient,
    team_id: i64,
    team_name: &str,
    spec: &TeamSpec,
    bot_username: &str,
    no_auto_remove: bool,
) -> Result<()> {
    let detail = client.get_team(team_id)?;
    let observed_members = observed_usernames(&detail.members);
    let desired_members = desired_usernames(spec);
    let diff = membership_diff(&desired_members, &observed_members, bot_username);

    let desired_admins = effective_admins(spec, bot_username);
    for username in &diff.to_add {
        let admin = desired_admins.contains(username);
        log(format_args!(
            "add member {username} to team {team_name}{}",
            if admin { " as admin" } else { "" }
        ));
        match client.add_member(team_id, username, admin)? {
            AddMemberOutcome::Added | AddMemberOutcome::AlreadyMember => {}
            AddMemberOutcome::UserMissing => log(format_args!(
                "skip member {username} for team {team_name}: Vikunja user does not exist yet"
            )),
        }
    }

    if !no_auto_remove {
        for username in &diff.to_remove {
            log(format_args!(
                "remove member {username} from team {team_name}"
            ));
            client.remove_member(team_id, username)?;
        }
    }

    Ok(())
}

fn desired_usernames(spec: &TeamSpec) -> Vec<String> {
    union(&spec.members, &spec.admins)
}

fn effective_admins(spec: &TeamSpec, bot_username: &str) -> Vec<String> {
    spec.admins
        .iter()
        .filter(|username| username.as_str() != bot_username)
        .cloned()
        .collect()
}

fn observed_usernames(members: &[TeamMember]) -> Vec<String> {
    members
        .iter()
        .map(|member| member.username.clone())
        .collect()
}

#[derive(Debug, PartialEq, Eq)]
struct MembershipDiff {
    to_add: Vec<String>,
    to_remove: Vec<String>,
}

fn membership_diff(desired: &[String], observed: &[String], bot_username: &str) -> MembershipDiff {
    let desired = without_bot(desired, bot_username);
    let observed = without_bot(observed, bot_username);
    if same_set(&desired, &observed) {
        return MembershipDiff {
            to_add: Vec::new(),
            to_remove: Vec::new(),
        };
    }

    let to_add = desired
        .iter()
        .filter(|username| !is_subset(std::slice::from_ref(*username), &observed))
        .cloned()
        .collect();
    let to_remove = observed
        .iter()
        .filter(|username| !is_subset(std::slice::from_ref(*username), &desired))
        .cloned()
        .collect();
    MembershipDiff { to_add, to_remove }
}

fn without_bot(usernames: &[String], bot_username: &str) -> Vec<String> {
    let mut out = Vec::with_capacity(usernames.len());
    let mut seen = Vec::with_capacity(usernames.len());
    for username in usernames {
        if username.as_str() == bot_username || seen.contains(&username.as_str()) {
            continue;
        }
        seen.push(username.as_str());
        out.push(username.clone());
    }
    out
}

// ---------------------------------------------------------------------------
// Webhook reconciliation
// ---------------------------------------------------------------------------

fn reconcile_webhooks(
    client: &VikunjaClient,
    state: &State,
    webhook_secret: Option<&str>,
) -> Result<()> {
    for (project_id_str, spec) in &state.webhooks {
        let project_id: i64 = match project_id_str.parse() {
            Ok(id) => id,
            Err(_) => {
                log(format_args!(
                    "skip webhook for invalid project id {project_id_str}"
                ));
                continue;
            }
        };

        let existing = client.list_webhooks(project_id)?;

        match (spec.present, find_matching_webhook(&existing, spec)) {
            (true, None) => {
                log(format_args!(
                    "create webhook for project {project_id}"
                ));
                client.create_webhook(project_id, &spec.url, &spec.events, webhook_secret)?;
            }
            (true, Some(hook)) => {
                if webhook_drifted(hook, spec) {
                    log(format_args!(
                        "update webhook {} for project {project_id}",
                        hook.id
                    ));
                    client.update_webhook(
                        project_id,
                        hook.id,
                        &spec.url,
                        &spec.events,
                        webhook_secret,
                    )?;
                }
            }
            (false, Some(hook)) => {
                log(format_args!(
                    "delete webhook {} from project {project_id}",
                    hook.id
                ));
                client.delete_webhook(project_id, hook.id)?;
            }
            (false, None) => {}
        }
    }

    Ok(())
}

fn find_matching_webhook<'a>(
    existing: &'a [WebhookSummary],
    spec: &WebhookSpec,
) -> Option<&'a WebhookSummary> {
    existing.iter().find(|hook| hook.url == spec.url)
}

fn webhook_drifted(hook: &WebhookSummary, spec: &WebhookSpec) -> bool {
    hook.url != spec.url || !same_set(&hook.events, &spec.events)
}

#[cfg(test)]
mod tests {
    use super::*;
    use client::WebhookSummary;

    fn v(xs: &[&str]) -> Vec<String> {
        xs.iter().map(ToString::to_string).collect()
    }

    fn hook(url: &str, events: &[&str]) -> WebhookSummary {
        WebhookSummary {
            id: 1,
            url: url.to_owned(),
            events: v(events),
        }
    }

    fn spec(url: &str, events: &[&str]) -> WebhookSpec {
        WebhookSpec {
            present: true,
            url: url.to_owned(),
            events: v(events),
        }
    }

    #[test]
    fn webhook_match_found_by_url() {
        let hooks = vec![hook("https://a.com/hook", &["task.created"])];
        let s = spec("https://a.com/hook", &["task.created"]);
        assert!(find_matching_webhook(&hooks, &s).is_some());
    }

    #[test]
    fn webhook_match_missing_when_url_differs() {
        let hooks = vec![hook("https://a.com/hook", &["task.created"])];
        let s = spec("https://b.com/hook", &["task.created"]);
        assert!(find_matching_webhook(&hooks, &s).is_none());
    }

    #[test]
    fn webhook_drift_detected_on_url_change() {
        let h = hook("https://old.com/hook", &["task.created"]);
        let s = spec("https://new.com/hook", &["task.created"]);
        assert!(webhook_drifted(&h, &s));
    }

    #[test]
    fn webhook_drift_detected_on_event_change() {
        let h = hook("https://a.com/hook", &["task.created"]);
        let s = spec("https://a.com/hook", &["task.created", "task.updated"]);
        assert!(webhook_drifted(&h, &s));
    }

    #[test]
    fn webhook_no_drift_when_identical() {
        let h = hook("https://a.com/hook", &["task.created", "task.updated"]);
        let s = spec("https://a.com/hook", &["task.created", "task.updated"]);
        assert!(!webhook_drifted(&h, &s));
    }

    #[test]
    fn webhook_no_drift_with_unordered_events() {
        let h = hook("https://a.com/hook", &["task.updated", "task.created"]);
        let s = spec("https://a.com/hook", &["task.created", "task.updated"]);
        assert!(!webhook_drifted(&h, &s));
    }

    // preserve existing team tests
    #[test]
    fn set_match_has_empty_deltas() {
        let diff = membership_diff(&v(&["alice", "bob"]), &v(&["alice", "bob"]), "bot");
        assert_eq!(diff.to_add, Vec::<String>::new());
        assert_eq!(diff.to_remove, Vec::<String>::new());
    }

    #[test]
    fn missing_member_is_added() {
        let diff = membership_diff(&v(&["alice", "bob"]), &v(&["alice"]), "bot");
        assert_eq!(diff.to_add, v(&["bob"]));
        assert_eq!(diff.to_remove, Vec::<String>::new());
    }

    #[test]
    fn extra_member_is_removed() {
        let diff = membership_diff(&v(&["alice"]), &v(&["alice", "bob"]), "bot");
        assert_eq!(diff.to_add, Vec::<String>::new());
        assert_eq!(diff.to_remove, v(&["bob"]));
    }

    #[test]
    fn bot_in_observed_is_never_removed() {
        let diff = membership_diff(&v(&["alice"]), &v(&["alice", "bot"]), "bot");
        assert_eq!(diff.to_add, Vec::<String>::new());
        assert_eq!(diff.to_remove, Vec::<String>::new());
    }

    #[test]
    fn bot_in_desired_is_never_added() {
        let diff = membership_diff(&v(&["alice", "bot"]), &v(&["alice"]), "bot");
        assert_eq!(diff.to_add, Vec::<String>::new());
        assert_eq!(diff.to_remove, Vec::<String>::new());
    }

    #[test]
    fn unordered_sets_have_no_spurious_delta() {
        let diff = membership_diff(
            &v(&["carol", "alice", "bob"]),
            &v(&["bob", "carol", "alice"]),
            "bot",
        );
        assert_eq!(diff.to_add, Vec::<String>::new());
        assert_eq!(diff.to_remove, Vec::<String>::new());
    }
}
