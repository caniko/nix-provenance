//! Render a generic offline Kanidm model into kanidm-provision JSON.
//!
//! The input schema mirrors Kanidm provisioning concepts instead of any one
//! fleet's identity registry. Consumer-specific policy belongs in the adapter
//! that produces this generic model.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use clap::Parser;
use serde::{Deserialize, Serialize};

#[derive(Debug, Parser)]
#[command(
    name = "kanidm-state-render",
    about = "Render a generic Kanidm model into kanidm-provision JSON",
    version
)]
struct Cli {
    /// Generic Kanidm model JSON to read.
    #[arg(long)]
    input: PathBuf,

    /// Output path for kanidm-provision JSON.
    #[arg(long)]
    out: PathBuf,

    /// Pretty-print the rendered JSON.
    #[arg(long)]
    pretty: bool,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let raw = fs::read_to_string(&cli.input)
        .with_context(|| format!("reading input {}", cli.input.display()))?;
    let input: RenderInput = serde_json::from_str(&raw)
        .with_context(|| format!("parsing input {}", cli.input.display()))?;
    let state = input.render().context("render Kanidm provision JSON")?;
    let json = if cli.pretty {
        serde_json::to_string_pretty(&state).context("serialize pretty Kanidm state")?
    } else {
        serde_json::to_string(&state).context("serialize Kanidm state")?
    };
    fs::write(&cli.out, format!("{json}\n"))
        .with_context(|| format!("writing output {}", cli.out.display()))?;
    Ok(())
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RenderInput {
    #[serde(default)]
    groups: BTreeMap<String, GroupInput>,
    #[serde(default)]
    persons: BTreeMap<String, PersonInput>,
    #[serde(default)]
    systems: SystemsInput,
}

impl RenderInput {
    fn render(self) -> Result<State> {
        let mut errors = Vec::new();
        validate_keys("group", self.groups.keys(), &mut errors);
        validate_keys("person", self.persons.keys(), &mut errors);
        validate_keys("oauth2 system", self.systems.oauth2.keys(), &mut errors);
        validate_global_entity_names(&self, &mut errors);

        let group_names = self.groups.keys().cloned().collect::<BTreeSet<_>>();
        let entity_names = self
            .groups
            .keys()
            .chain(self.persons.keys())
            .chain(self.systems.oauth2.keys())
            .cloned()
            .collect::<BTreeSet<_>>();

        for (name, group) in &self.groups {
            group.validate(name, &entity_names, &mut errors);
        }
        for (name, person) in &self.persons {
            person.validate(name, &group_names, &mut errors);
        }
        for (name, system) in &self.systems.oauth2 {
            system.validate(name, &group_names, &mut errors);
        }

        if !errors.is_empty() {
            bail!("generic Kanidm model invalid:\n{}", errors.join("\n"));
        }

        Ok(State {
            groups: self.groups,
            persons: self.persons,
            systems: self.systems,
        })
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct State {
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    groups: BTreeMap<String, GroupInput>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    persons: BTreeMap<String, PersonInput>,
    #[serde(default, skip_serializing_if = "SystemsInput::is_empty")]
    systems: SystemsInput,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct GroupInput {
    #[serde(default = "default_true")]
    present: bool,
    #[serde(default)]
    members: Vec<String>,
    #[serde(default = "default_true", skip_serializing_if = "is_true")]
    overwrite_members: bool,
}

impl GroupInput {
    fn validate(&self, name: &str, entity_names: &BTreeSet<String>, errors: &mut Vec<String>) {
        validate_non_empty_values(
            format!("group '{name}' member"),
            self.members.iter(),
            errors,
        );
        for member in &self.members {
            if !entity_names.contains(member) {
                errors.push(format!(
                    "group '{name}' references unknown member '{member}'"
                ));
            }
        }
    }
}

impl Default for GroupInput {
    fn default() -> Self {
        Self {
            present: true,
            members: Vec::new(),
            overwrite_members: true,
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PersonInput {
    #[serde(default = "default_true")]
    present: bool,
    display_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    legal_name: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    mail_addresses: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    groups: Vec<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    enable_unix: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    gid_number: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    login_shell: Option<String>,
}

impl PersonInput {
    fn validate(&self, name: &str, group_names: &BTreeSet<String>, errors: &mut Vec<String>) {
        if self.display_name.trim().is_empty() {
            errors.push(format!("person '{name}' has an empty displayName"));
        }
        validate_non_empty_values(
            format!("person '{name}' mail address"),
            self.mail_addresses.iter(),
            errors,
        );
        validate_non_empty_values(format!("person '{name}' group"), self.groups.iter(), errors);
        for group in &self.groups {
            if !group_names.contains(group) {
                errors.push(format!(
                    "person '{name}' references unknown group '{group}'"
                ));
            }
        }
        if !self.enable_unix && (self.gid_number.is_some() || self.login_shell.is_some()) {
            errors.push(format!(
                "person '{name}' sets POSIX fields but enableUnix is false"
            ));
        }
        if self.enable_unix && self.gid_number.is_none() {
            errors.push(format!("person '{name}' has enableUnix but no gidNumber"));
        }
        if let Some(shell) = &self.login_shell
            && !shell.starts_with('/')
        {
            errors.push(format!(
                "person '{name}' loginShell must be an absolute path"
            ));
        }
    }
}

#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SystemsInput {
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    oauth2: BTreeMap<String, OAuth2Input>,
}

impl SystemsInput {
    fn is_empty(&self) -> bool {
        self.oauth2.is_empty()
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct OAuth2Input {
    #[serde(default = "default_true")]
    present: bool,
    #[serde(default)]
    public: bool,
    display_name: String,
    origin_url: OriginUrl,
    origin_landing: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    basic_secret_file: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    image_file: Option<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    enable_localhost_redirects: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    enable_legacy_crypto: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    allow_insecure_client_disable_pkce: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    prefer_short_username: bool,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    scope_maps: BTreeMap<String, Vec<String>>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    supplementary_scope_maps: BTreeMap<String, Vec<String>>,
    #[serde(default = "default_true", skip_serializing_if = "is_true")]
    remove_orphaned_claim_maps: bool,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    claim_maps: BTreeMap<String, ClaimMapInput>,
}

impl OAuth2Input {
    fn validate(&self, name: &str, group_names: &BTreeSet<String>, errors: &mut Vec<String>) {
        if self.display_name.trim().is_empty() {
            errors.push(format!("oauth2 system '{name}' has an empty displayName"));
        }
        if self.origin_landing.trim().is_empty() {
            errors.push(format!("oauth2 system '{name}' has an empty originLanding"));
        }
        self.origin_url.validate(name, errors);
        if self.public && self.basic_secret_file.is_some() {
            errors.push(format!(
                "oauth2 system '{name}' is public and cannot set basicSecretFile"
            ));
        }
        if !self.public && self.basic_secret_file.is_none() {
            errors.push(format!(
                "oauth2 system '{name}' is confidential and must set basicSecretFile"
            ));
        }
        if self.public && self.allow_insecure_client_disable_pkce {
            errors.push(format!(
                "oauth2 system '{name}' is public and cannot disable PKCE"
            ));
        }
        if !self.public && self.enable_localhost_redirects {
            errors.push(format!(
                "oauth2 system '{name}' is confidential and cannot enable localhost redirects"
            ));
        }
        validate_group_map(
            format!("oauth2 system '{name}' scopeMaps"),
            &self.scope_maps,
            group_names,
            errors,
        );
        validate_group_map(
            format!("oauth2 system '{name}' supplementaryScopeMaps"),
            &self.supplementary_scope_maps,
            group_names,
            errors,
        );
        for (claim, map) in &self.claim_maps {
            map.validate(name, claim, group_names, errors);
        }
    }
}

impl Default for OAuth2Input {
    fn default() -> Self {
        Self {
            present: true,
            public: false,
            display_name: String::new(),
            origin_url: OriginUrl::One(String::new()),
            origin_landing: String::new(),
            basic_secret_file: None,
            image_file: None,
            enable_localhost_redirects: false,
            enable_legacy_crypto: false,
            allow_insecure_client_disable_pkce: false,
            prefer_short_username: false,
            scope_maps: BTreeMap::new(),
            supplementary_scope_maps: BTreeMap::new(),
            remove_orphaned_claim_maps: true,
            claim_maps: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
enum OriginUrl {
    One(String),
    Many(Vec<String>),
}

impl OriginUrl {
    fn validate(&self, system: &str, errors: &mut Vec<String>) {
        let urls: Vec<&str> = match self {
            Self::One(url) => vec![url],
            Self::Many(urls) => urls.iter().map(String::as_str).collect(),
        };
        if urls.is_empty() {
            errors.push(format!("oauth2 system '{system}' has no originUrl"));
        }
        for url in urls {
            if !url.contains("://") {
                errors.push(format!(
                    "oauth2 system '{system}' originUrl '{url}' is not an absolute URI"
                ));
            }
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ClaimMapInput {
    #[serde(default)]
    join_type: JoinType,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    values_by_group: BTreeMap<String, Vec<String>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, Default)]
enum JoinType {
    #[serde(rename = "array")]
    #[default]
    Array,
    #[serde(rename = "csv")]
    Csv,
    #[serde(rename = "ssv")]
    Ssv,
}

impl ClaimMapInput {
    fn validate(
        &self,
        system: &str,
        claim: &str,
        group_names: &BTreeSet<String>,
        errors: &mut Vec<String>,
    ) {
        if self.values_by_group.values().all(Vec::is_empty) {
            errors.push(format!(
                "oauth2 system '{system}' claimMap '{claim}' has no values"
            ));
        }
        validate_group_map(
            format!("oauth2 system '{system}' claimMap '{claim}' valuesByGroup"),
            &self.values_by_group,
            group_names,
            errors,
        );
    }
}

fn validate_global_entity_names(input: &RenderInput, errors: &mut Vec<String>) {
    let mut seen = BTreeMap::<&str, Vec<&str>>::new();
    for name in input.groups.keys() {
        seen.entry(name).or_default().push("group");
    }
    for name in input.persons.keys() {
        seen.entry(name).or_default().push("person");
    }
    for name in input.systems.oauth2.keys() {
        seen.entry(name).or_default().push("oauth2");
    }
    for (name, kinds) in seen {
        if kinds.len() > 1 {
            errors.push(format!(
                "entity name '{name}' is used for multiple entity types: {}",
                kinds.join(", ")
            ));
        }
    }
}

fn validate_group_map(
    label: String,
    map: &BTreeMap<String, Vec<String>>,
    group_names: &BTreeSet<String>,
    errors: &mut Vec<String>,
) {
    validate_keys(&label, map.keys(), errors);
    for (group, values) in map {
        if !group_names.contains(group) {
            errors.push(format!("{label} references unknown group '{group}'"));
        }
        validate_non_empty_values(
            format!("{label} value for group '{group}'"),
            values.iter(),
            errors,
        );
    }
}

fn validate_keys<'a>(
    kind: &str,
    keys: impl IntoIterator<Item = &'a String>,
    errors: &mut Vec<String>,
) {
    for key in keys {
        if key.trim().is_empty() {
            errors.push(format!("{kind} key must not be empty"));
        }
    }
}

fn validate_non_empty_values<'a>(
    label: String,
    values: impl IntoIterator<Item = &'a String>,
    errors: &mut Vec<String>,
) {
    for value in values {
        if value.trim().is_empty() {
            errors.push(format!("{label} must not be empty"));
        }
    }
}

fn default_true() -> bool {
    true
}

fn is_true(value: &bool) -> bool {
    *value
}

fn is_false(value: &bool) -> bool {
    !*value
}

#[cfg(test)]
mod tests {
    use super::*;

    fn render(raw: &str) -> Result<State> {
        serde_json::from_str::<RenderInput>(raw)?.render()
    }

    #[test]
    fn renders_groups_persons_posix_and_oauth2() {
        let state = render(
            r#"
            {
              "groups": {
                "staff": {},
                "app-users": { "members": ["alice"] }
              },
              "persons": {
                "alice": {
                  "displayName": "Alice Example",
                  "legalName": "Alice Legal",
                  "mailAddresses": ["alice@example.com"],
                  "groups": ["staff", "app-users"],
                  "enableUnix": true,
                  "gidNumber": 1000,
                  "loginShell": "/run/current-system/sw/bin/bash"
                }
              },
              "systems": {
                "oauth2": {
                  "internal-tool": {
                    "displayName": "Internal Tool",
                    "originUrl": ["https://tool.example.com/callback"],
                    "originLanding": "https://tool.example.com/",
                    "basicSecretFile": "/run/secrets/internal-tool",
                    "preferShortUsername": true,
                    "scopeMaps": { "app-users": ["openid", "email"] },
                    "supplementaryScopeMaps": { "staff": ["groups"] },
                    "claimMaps": {
                      "roles": {
                        "joinType": "array",
                        "valuesByGroup": { "staff": ["admin"] }
                      }
                    }
                  },
                  "native-app": {
                    "public": true,
                    "displayName": "Native App",
                    "originUrl": "http://127.0.0.1/callback",
                    "originLanding": "http://127.0.0.1/",
                    "enableLocalhostRedirects": true,
                    "scopeMaps": { "staff": ["openid"] }
                  }
                }
              }
            }
            "#,
        )
        .expect("valid render");

        let json = serde_json::to_value(state).expect("serialize state");
        assert_eq!(json["groups"]["staff"]["present"], true);
        assert_eq!(json["groups"]["staff"]["members"], serde_json::json!([]));
        assert!(json["groups"]["staff"].get("overwriteMembers").is_none());
        assert_eq!(json["persons"]["alice"]["enableUnix"], true);
        assert_eq!(json["persons"]["alice"]["gidNumber"], 1000);
        assert_eq!(
            json["systems"]["oauth2"]["internal-tool"]["basicSecretFile"],
            "/run/secrets/internal-tool"
        );
        assert_eq!(
            json["systems"]["oauth2"]["internal-tool"]["claimMaps"]["roles"]["valuesByGroup"]["staff"]
                [0],
            "admin"
        );
        assert!(
            json["systems"]["oauth2"]["internal-tool"]
                .get("removeOrphanedClaimMaps")
                .is_none()
        );
        assert_eq!(json["systems"]["oauth2"]["native-app"]["public"], true);
    }

    #[test]
    fn rejects_unknown_group_and_confidential_without_secret() {
        let err = render(
            r#"
            {
              "groups": { "staff": {} },
              "persons": {
                "alice": {
                  "displayName": "Alice",
                  "groups": ["missing"]
                }
              },
              "systems": {
                "oauth2": {
                  "tool": {
                    "displayName": "Tool",
                    "originUrl": "https://tool.example.com/callback",
                    "originLanding": "https://tool.example.com/",
                    "scopeMaps": { "missing": ["openid"] }
                  }
                }
              }
            }
            "#,
        )
        .expect_err("invalid model");

        let msg = err.to_string();
        assert!(msg.contains("person 'alice' references unknown group 'missing'"));
        assert!(msg.contains("oauth2 system 'tool' is confidential and must set basicSecretFile"));
        assert!(msg.contains("scopeMaps references unknown group 'missing'"));
    }

    #[test]
    fn rejects_duplicate_entity_names_and_invalid_public_secret() {
        let err = render(
            r#"
            {
              "groups": { "tool": {} },
              "systems": {
                "oauth2": {
                  "tool": {
                    "public": true,
                    "displayName": "Tool",
                    "originUrl": "https://tool.example.com/callback",
                    "originLanding": "https://tool.example.com/",
                    "basicSecretFile": "/run/secrets/tool"
                  }
                }
              }
            }
            "#,
        )
        .expect_err("invalid model");

        let msg = err.to_string();
        assert!(msg.contains("entity name 'tool' is used for multiple entity types"));
        assert!(msg.contains("is public and cannot set basicSecretFile"));
    }
}
