//! Render a generic offline Rauthy model into `rauthy-provision` state JSON.
//!
//! The input schema deliberately mirrors Rauthy/provisioning concepts instead
//! of any one consumer's identity registry. Fleet-specific policy belongs in
//! the consumer-side adapter that produces this generic model.

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use clap::Parser;
use rauthy_provision::state::{
    ClientSpec, GroupSpec, ProviderSpec, RoleSpec, ScopeSpec, State, UserAttributeSpec, UserSpec,
};
use serde::Deserialize;
use serde_json::Value;

#[derive(Debug, Parser)]
#[command(
    name = "rauthy-state-render",
    about = "Render a generic Rauthy model into rauthy-provision state JSON",
    version
)]
struct Cli {
    /// Generic Rauthy model JSON to read.
    #[arg(long)]
    input: PathBuf,

    /// Output path for the rauthy-provision state JSON.
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
    let state = input.render().context("render Rauthy provision state")?;
    let json = if cli.pretty {
        serde_json::to_string_pretty(&state).context("serialize pretty Rauthy state")?
    } else {
        serde_json::to_string(&state).context("serialize Rauthy state")?
    };
    fs::write(&cli.out, format!("{json}\n"))
        .with_context(|| format!("writing output {}", cli.out.display()))?;
    Ok(())
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RenderInput {
    #[serde(default)]
    groups: BTreeMap<String, PresentInput>,
    #[serde(default)]
    roles: BTreeMap<String, PresentInput>,
    #[serde(default)]
    scopes: BTreeMap<String, ScopeInput>,
    #[serde(default)]
    user_attributes: BTreeMap<String, UserAttributeInput>,
    #[serde(default)]
    users: BTreeMap<String, UserInput>,
    #[serde(default)]
    clients: BTreeMap<String, ClientInput>,
    #[serde(default)]
    providers: BTreeMap<String, ProviderInput>,
}

impl RenderInput {
    fn render(self) -> Result<State> {
        let mut errors = Vec::new();
        validate_keys("group", self.groups.keys(), &mut errors);
        validate_keys("role", self.roles.keys(), &mut errors);
        validate_keys("scope", self.scopes.keys(), &mut errors);
        validate_keys("user attribute", self.user_attributes.keys(), &mut errors);
        validate_keys("user email", self.users.keys(), &mut errors);
        validate_keys("client", self.clients.keys(), &mut errors);
        validate_keys("provider", self.providers.keys(), &mut errors);

        for (email, user) in &self.users {
            user.validate(email, &mut errors);
        }
        for (client_id, client) in &self.clients {
            client.validate(client_id, &mut errors);
        }
        for (provider_id, provider) in &self.providers {
            provider.validate(provider_id, &mut errors);
        }

        if !errors.is_empty() {
            bail!("generic Rauthy model invalid:\n{}", errors.join("\n"));
        }

        Ok(State {
            groups: self
                .groups
                .into_iter()
                .map(|(name, input)| {
                    (
                        name,
                        GroupSpec {
                            present: input.present,
                        },
                    )
                })
                .collect(),
            roles: self
                .roles
                .into_iter()
                .map(|(name, input)| {
                    (
                        name,
                        RoleSpec {
                            present: input.present,
                        },
                    )
                })
                .collect(),
            scopes: self
                .scopes
                .into_iter()
                .map(|(name, input)| {
                    (
                        name,
                        ScopeSpec {
                            present: input.present,
                            attr_include_access: input.attr_include_access,
                            attr_include_id: input.attr_include_id,
                            claims_at_root: input.claims_at_root,
                        },
                    )
                })
                .collect(),
            user_attributes: self
                .user_attributes
                .into_iter()
                .map(|(name, input)| {
                    (
                        name,
                        UserAttributeSpec {
                            present: input.present,
                            desc: input.desc,
                            default_value: input.default_value,
                            user_editable: input.user_editable,
                        },
                    )
                })
                .collect(),
            users: self
                .users
                .into_iter()
                .map(|(email, input)| (email, input.into_spec()))
                .collect(),
            clients: self
                .clients
                .into_iter()
                .map(|(client_id, input)| (client_id, input.into_spec()))
                .collect(),
            providers: self
                .providers
                .into_iter()
                .map(|(provider_id, input)| (provider_id, input.into_spec()))
                .collect(),
        })
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PresentInput {
    #[serde(default = "default_true")]
    present: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ScopeInput {
    #[serde(default = "default_true")]
    present: bool,
    #[serde(default)]
    attr_include_access: Vec<String>,
    #[serde(default)]
    attr_include_id: Vec<String>,
    #[serde(default)]
    claims_at_root: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct UserAttributeInput {
    #[serde(default = "default_true")]
    present: bool,
    #[serde(default)]
    desc: Option<String>,
    #[serde(default)]
    default_value: Option<Value>,
    #[serde(default)]
    user_editable: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct UserInput {
    #[serde(default = "default_true")]
    present: bool,
    #[serde(default)]
    given_name: Option<String>,
    #[serde(default)]
    family_name: Option<String>,
    #[serde(default)]
    birthdate: Option<String>,
    #[serde(default)]
    timezone: Option<String>,
    #[serde(default)]
    street: Option<String>,
    #[serde(default)]
    zip: Option<String>,
    #[serde(default)]
    city: Option<String>,
    #[serde(default)]
    country: Option<String>,
    #[serde(default)]
    phone: Option<String>,
    #[serde(default = "default_language")]
    language: String,
    #[serde(default)]
    user_expires: Option<i64>,
    #[serde(default)]
    roles: Vec<String>,
    #[serde(default)]
    groups: Vec<String>,
    #[serde(default)]
    preferred_username: Option<String>,
    #[serde(default)]
    attributes: BTreeMap<String, Value>,
    #[serde(default)]
    send_password_email: bool,
    #[serde(default)]
    password_email_redirect_uri: Option<String>,
    #[serde(default)]
    initial_password_file: Option<String>,
}

impl UserInput {
    fn validate(&self, email: &str, errors: &mut Vec<String>) {
        if self.send_password_email && self.password_email_redirect_uri.is_none() {
            errors.push(format!(
                "user '{email}' sets sendPasswordEmail but no passwordEmailRedirectUri"
            ));
        }
        if self.send_password_email && self.initial_password_file.is_some() {
            errors.push(format!(
                "user '{email}' cannot set both sendPasswordEmail and initialPasswordFile"
            ));
        }
        if let Some(expires) = self.user_expires
            && expires <= 0
        {
            errors.push(format!("user '{email}' has non-positive userExpires"));
        }
        validate_non_empty_values(format!("user '{email}' role"), self.roles.iter(), errors);
        validate_non_empty_values(format!("user '{email}' group"), self.groups.iter(), errors);
    }

    fn into_spec(self) -> UserSpec {
        UserSpec {
            present: self.present,
            given_name: self.given_name.map(Some),
            family_name: self.family_name.map(Some),
            birthdate: self.birthdate.map(Some),
            timezone: self.timezone.map(Some),
            street: self.street.map(Some),
            zip: self.zip.map(Some),
            city: self.city.map(Some),
            country: self.country.map(Some),
            phone: self.phone.map(Some),
            language: self.language,
            user_expires: self.user_expires,
            roles: self.roles,
            groups: self.groups,
            preferred_username: self.preferred_username.map(Some),
            attributes: self.attributes,
            send_password_email: self.send_password_email,
            password_email_redirect_uri: self.password_email_redirect_uri,
            initial_password_file: self.initial_password_file,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ClientInput {
    #[serde(default = "default_true")]
    present: bool,
    #[serde(default)]
    name: Option<String>,
    #[serde(default = "default_true")]
    confidential: bool,
    #[serde(default)]
    redirect_uris: Vec<String>,
    #[serde(default)]
    post_logout_redirect_uris: Vec<String>,
    #[serde(default)]
    allowed_origins: Vec<String>,
    #[serde(default = "default_user_scopes")]
    scopes: Vec<String>,
    #[serde(default = "default_user_scopes")]
    default_scopes: Vec<String>,
    #[serde(default = "default_flows")]
    flows_enabled: Vec<String>,
    #[serde(default = "default_true")]
    enable_pkce: bool,
    #[serde(default)]
    generated_secret_file: Option<String>,
}

impl ClientInput {
    fn validate(&self, client_id: &str, errors: &mut Vec<String>) {
        if !self.confidential && self.generated_secret_file.is_some() {
            errors.push(format!(
                "client '{client_id}' is public but sets generatedSecretFile"
            ));
        }
        if !self.confidential && !self.enable_pkce {
            errors.push(format!("public client '{client_id}' must enable PKCE"));
        }
        validate_non_empty_values(
            format!("client '{client_id}' redirect URI"),
            self.redirect_uris.iter(),
            errors,
        );
        validate_non_empty_values(
            format!("client '{client_id}' scope"),
            self.scopes.iter(),
            errors,
        );
        validate_non_empty_values(
            format!("client '{client_id}' default scope"),
            self.default_scopes.iter(),
            errors,
        );
        if self.flows_enabled.is_empty() {
            errors.push(format!(
                "client '{client_id}' flowsEnabled must not be empty"
            ));
        }
        validate_non_empty_values(
            format!("client '{client_id}' flow"),
            self.flows_enabled.iter(),
            errors,
        );
    }

    fn into_spec(self) -> ClientSpec {
        ClientSpec {
            present: self.present,
            name: self.name,
            confidential: self.confidential,
            redirect_uris: self.redirect_uris,
            post_logout_redirect_uris: self.post_logout_redirect_uris,
            allowed_origins: self.allowed_origins,
            scopes: self.scopes,
            default_scopes: self.default_scopes,
            flows_enabled: self.flows_enabled,
            enable_pkce: self.enable_pkce,
            generated_secret_file: self.generated_secret_file,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProviderInput {
    #[serde(default = "default_true")]
    present: bool,
    name: String,
    #[serde(default = "default_provider_type")]
    typ: String,
    #[serde(default = "default_true")]
    enabled: bool,
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    userinfo_endpoint: String,
    #[serde(default)]
    jwks_endpoint: Option<String>,
    client_id: String,
    #[serde(default)]
    client_secret_file: Option<String>,
    #[serde(default = "default_provider_scope")]
    scope: String,
    #[serde(default = "default_true")]
    use_pkce: bool,
    #[serde(default = "default_true")]
    client_secret_basic: bool,
    #[serde(default)]
    client_secret_post: bool,
    #[serde(default)]
    auto_onboarding: bool,
    #[serde(default)]
    auto_link: bool,
    #[serde(default)]
    admin_claim_path: Option<String>,
    #[serde(default)]
    admin_claim_value: Option<String>,
    #[serde(default)]
    mfa_claim_path: Option<String>,
    #[serde(default)]
    mfa_claim_value: Option<String>,
}

impl ProviderInput {
    fn validate(&self, provider_id: &str, errors: &mut Vec<String>) {
        for (field, value) in [
            ("name", self.name.as_str()),
            ("issuer", self.issuer.as_str()),
            (
                "authorizationEndpoint",
                self.authorization_endpoint.as_str(),
            ),
            ("tokenEndpoint", self.token_endpoint.as_str()),
            ("userinfoEndpoint", self.userinfo_endpoint.as_str()),
            ("clientId", self.client_id.as_str()),
            ("scope", self.scope.as_str()),
        ] {
            if value.trim().is_empty() {
                errors.push(format!("provider '{provider_id}' has empty {field}"));
            }
        }
        if (self.client_secret_basic || self.client_secret_post)
            && self.client_secret_file.is_none()
        {
            errors.push(format!(
                "provider '{provider_id}' uses client-secret authentication but no clientSecretFile"
            ));
        }
    }

    fn into_spec(self) -> ProviderSpec {
        ProviderSpec {
            present: self.present,
            name: self.name,
            typ: self.typ,
            enabled: self.enabled,
            issuer: self.issuer,
            authorization_endpoint: self.authorization_endpoint,
            token_endpoint: self.token_endpoint,
            userinfo_endpoint: self.userinfo_endpoint,
            jwks_endpoint: self.jwks_endpoint,
            client_id: self.client_id,
            client_secret_file: self.client_secret_file,
            scope: self.scope,
            use_pkce: self.use_pkce,
            client_secret_basic: self.client_secret_basic,
            client_secret_post: self.client_secret_post,
            auto_onboarding: self.auto_onboarding,
            auto_link: self.auto_link,
            admin_claim_path: self.admin_claim_path,
            admin_claim_value: self.admin_claim_value,
            mfa_claim_path: self.mfa_claim_path,
            mfa_claim_value: self.mfa_claim_value,
        }
    }
}

fn default_true() -> bool {
    true
}

fn default_language() -> String {
    "en".to_string()
}

fn default_user_scopes() -> Vec<String> {
    vec![
        "openid".to_string(),
        "profile".to_string(),
        "email".to_string(),
    ]
}

fn default_flows() -> Vec<String> {
    vec![
        "authorization_code".to_string(),
        "refresh_token".to_string(),
    ]
}

fn default_provider_type() -> String {
    "oidc".to_string()
}

fn default_provider_scope() -> String {
    "openid email profile".to_string()
}

fn validate_keys<'a>(
    label: &str,
    keys: impl Iterator<Item = &'a String>,
    errors: &mut Vec<String>,
) {
    for key in keys {
        if key.trim().is_empty() {
            errors.push(format!("{label} key must not be empty"));
        }
    }
}

fn validate_non_empty_values<'a>(
    label: String,
    values: impl Iterator<Item = &'a String>,
    errors: &mut Vec<String>,
) {
    for value in values {
        if value.trim().is_empty() {
            errors.push(format!("{label} must not be empty"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const INPUT: &str = r#"{
      "groups": {
        "internal": {},
        "vikunja-users": {"present": true}
      },
      "userAttributes": {
        "vikunja_groups": {
          "desc": "Vikunja OIDC team memberships",
          "userEditable": false
        }
      },
      "scopes": {
        "vikunja_groups": {
          "attrIncludeId": ["vikunja_groups"],
          "claimsAtRoot": true
        }
      },
      "providers": {
        "kanidm": {
          "name": "Kanidm",
          "issuer": "https://auth.example.com/oauth2/openid/rauthy",
          "authorizationEndpoint": "https://auth.example.com/ui/oauth2",
          "tokenEndpoint": "https://auth.example.com/oauth2/token",
          "userinfoEndpoint": "https://auth.example.com/oauth2/openid/rauthy/userinfo",
          "jwksEndpoint": "https://auth.example.com/oauth2/openid/rauthy/public_key.jwk",
          "clientId": "rauthy",
          "clientSecretFile": "/run/secrets/kanidm",
          "scope": "openid email profile groups",
          "autoLink": true
        }
      },
      "clients": {
        "bekiper-annotate": {
          "confidential": false,
          "enablePkce": true,
          "redirectUris": ["http://127.0.0.1/callback"],
          "scopes": ["openid", "profile", "email", "groups"],
          "defaultScopes": ["openid", "profile", "email", "groups"],
          "flowsEnabled": [
            "authorization_code",
            "refresh_token",
            "urn:ietf:params:oauth:grant-type:device_code"
          ]
        },
        "vikunja": {
          "name": "Vikunja",
          "confidential": true,
          "enablePkce": false,
          "redirectUris": ["https://tasks.example.com/auth/openid/rauthy"],
          "postLogoutRedirectUris": ["https://tasks.example.com/"],
          "allowedOrigins": ["https://tasks.example.com"],
          "scopes": ["openid", "profile", "email", "groups", "vikunja_groups"],
          "defaultScopes": ["openid", "profile", "email", "groups", "vikunja_groups"],
          "generatedSecretFile": "/var/lib/rauthy-provision/clients/vikunja.secret"
        }
      },
      "users": {
        "can@example.com": {
          "givenName": "Can",
          "familyName": "Tartanoglu",
          "preferredUsername": "can",
          "groups": ["internal", "vikunja-users"],
          "attributes": {
            "vikunja_groups": [{"name": "pink-raven", "oidcID": "pink-raven"}]
          }
        },
        "external@example.com": {
          "preferredUsername": "external",
          "sendPasswordEmail": true,
          "passwordEmailRedirectUri": "https://app.example.com/login"
        }
      }
    }"#;

    #[test]
    fn renders_generic_model_into_rauthy_state() {
        let input: RenderInput = serde_json::from_str(INPUT).unwrap();
        let state = input.render().unwrap();
        let json = serde_json::to_value(&state).unwrap();

        assert_eq!(json["groups"]["internal"]["present"], true);
        assert_eq!(json["groups"]["vikunja-users"]["present"], true);
        assert_eq!(json["scopes"]["vikunja_groups"]["claims_at_root"], true);
        assert_eq!(
            json["providers"]["kanidm"]["authorization_endpoint"],
            "https://auth.example.com/ui/oauth2"
        );
        assert_eq!(json["clients"]["bekiper-annotate"]["enable_pkce"], true);
        assert_eq!(
            json["clients"]["vikunja"]["generated_secret_file"],
            "/var/lib/rauthy-provision/clients/vikunja.secret"
        );
        assert_eq!(
            json["users"]["can@example.com"]["attributes"]["vikunja_groups"][0]["oidcID"],
            "pink-raven"
        );
        assert_eq!(
            json["users"]["external@example.com"]["password_email_redirect_uri"],
            "https://app.example.com/login"
        );
    }

    #[test]
    fn validates_password_email_redirects() {
        let input: RenderInput = serde_json::from_str(
            r#"{ "users": { "external@example.com": { "sendPasswordEmail": true } } }"#,
        )
        .unwrap();
        let err = input.render().unwrap_err().to_string();
        assert!(err.contains("passwordEmailRedirectUri"));
    }

    #[test]
    fn validates_public_clients_use_pkce() {
        let input: RenderInput = serde_json::from_str(
            r#"{ "clients": { "public": { "confidential": false, "enablePkce": false } } }"#,
        )
        .unwrap();
        let err = input.render().unwrap_err().to_string();
        assert!(err.contains("must enable PKCE"));
    }

    #[test]
    fn validates_empty_client_flows() {
        let input: RenderInput =
            serde_json::from_str(r#"{ "clients": { "vikunja": { "flowsEnabled": [] } } }"#)
                .unwrap();
        let err = input.render().unwrap_err().to_string();
        assert!(err.contains("flowsEnabled must not be empty"));
    }

    #[test]
    fn output_is_valid_rauthy_provision_state_schema() {
        let input: RenderInput = serde_json::from_str(INPUT).unwrap();
        let state = input.render().unwrap();
        let json = serde_json::to_string(&state).unwrap();
        let parsed: State = serde_json::from_str(&json).unwrap();
        assert!(parsed.clients.contains_key("vikunja"));
        assert!(parsed.providers.contains_key("kanidm"));
    }
}
