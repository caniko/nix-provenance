//! Declarative state schema.
//!
//! The state file is a JSON document with top-level maps mirroring the entity
//! types Rauthy's admin API exposes to an API key. Each entity carries a `present` flag (default
//! `true`); setting it `false` deletes the entity if it exists.
//!
//! This is the analogue of kanidm-provision's `state.json`, adapted to
//! Rauthy's data model. There is intentionally **no** orphan auto-removal:
//! Rauthy has no tracking-group equivalent, so the only way to delete an
//! entity is to declare it with `present = false`.

use std::collections::BTreeMap;

use provenance_core::serde_ext::default_true;
use serde::Deserialize;
use serde_json::Value;

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

/// Top-level declarative state. Keys are the natural identifier for each
/// entity type (group name, role name, user email, client id).
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct State {
    #[serde(default)]
    pub groups: BTreeMap<String, GroupSpec>,
    #[serde(default)]
    pub roles: BTreeMap<String, RoleSpec>,
    #[serde(default)]
    pub scopes: BTreeMap<String, ScopeSpec>,
    #[serde(default)]
    pub user_attributes: BTreeMap<String, UserAttributeSpec>,
    /// Keyed by the user's primary email address.
    #[serde(default)]
    pub users: BTreeMap<String, UserSpec>,
    /// Keyed by the OIDC client id.
    #[serde(default)]
    pub clients: BTreeMap<String, ClientSpec>,
    /// Keyed by the upstream auth provider id.
    #[serde(default)]
    pub providers: BTreeMap<String, ProviderSpec>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupSpec {
    #[serde(default = "default_true")]
    pub present: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleSpec {
    #[serde(default = "default_true")]
    pub present: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeSpec {
    #[serde(default = "default_true")]
    pub present: bool,
    #[serde(default)]
    pub attr_include_access: Vec<String>,
    #[serde(default)]
    pub attr_include_id: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserAttributeSpec {
    #[serde(default = "default_true")]
    pub present: bool,
    #[serde(default)]
    pub desc: Option<String>,
    #[serde(default)]
    pub default_value: Option<Value>,
    #[serde(default)]
    pub user_editable: bool,
}

/// A Rauthy user. Created passwordless: no credential is set and no email is
/// sent. When Rauthy is wired to an upstream OIDC provider (e.g. kanidm) with
/// "Auto-Link User" enabled, a passwordless local user whose email matches the
/// upstream identity is auto-linked on first federated login.
///
/// Profile fields are reconciled only when explicitly set. Unset fields remain
/// unmanaged, so federated profile-claim sync from an upstream IdP can keep
/// owning them.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserSpec {
    #[serde(default = "default_true")]
    pub present: bool,
    #[serde(default)]
    pub given_name: Option<String>,
    #[serde(default)]
    pub family_name: Option<String>,
    #[serde(default)]
    pub birthdate: Option<String>,
    #[serde(default)]
    pub timezone: Option<String>,
    #[serde(default)]
    pub street: Option<String>,
    #[serde(default)]
    pub zip: Option<String>,
    #[serde(default)]
    pub city: Option<String>,
    #[serde(default)]
    pub country: Option<String>,
    #[serde(default)]
    pub phone: Option<String>,
    #[serde(default = "default_language")]
    pub language: String,
    #[serde(default)]
    pub roles: Vec<String>,
    #[serde(default)]
    pub groups: Vec<String>,
    #[serde(default)]
    pub preferred_username: Option<String>,
    #[serde(default)]
    pub attributes: BTreeMap<String, Value>,
    /// On user CREATION only, ask Rauthy to email the user a set-password link
    /// (Rauthy's `request_reset` flow). A no-op when the user already exists, so
    /// at most one email is ever sent per user. Use for external users who have
    /// no upstream IdP and must set a native Rauthy password.
    #[serde(default)]
    pub send_password_email: bool,
    /// Where Rauthy redirects the user after they finish setting their password.
    /// Point this at the consuming app's login-initiating route (e.g.
    /// `https://app.example.com/login`), NOT a raw OIDC callback. Only meaningful
    /// when `send_password_email` is true.
    #[serde(default)]
    pub password_email_redirect_uri: Option<String>,
}

/// An OIDC client (relying party).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientSpec {
    #[serde(default = "default_true")]
    pub present: bool,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default = "default_true")]
    pub confidential: bool,
    #[serde(default)]
    pub redirect_uris: Vec<String>,
    #[serde(default)]
    pub post_logout_redirect_uris: Vec<String>,
    #[serde(default)]
    pub allowed_origins: Vec<String>,
    #[serde(default = "default_user_scopes")]
    pub scopes: Vec<String>,
    #[serde(default = "default_user_scopes")]
    pub default_scopes: Vec<String>,
    #[serde(default = "default_flows")]
    pub flows_enabled: Vec<String>,
    /// Enable PKCE (S256). Strongly recommended; required for public clients.
    #[serde(default = "default_true")]
    pub enable_pkce: bool,
    /// Runtime path where rauthy-provision stores the generated confidential
    /// client secret. The file is created only if missing, so existing client
    /// credentials are not rotated on every reconcile.
    #[serde(default)]
    pub generated_secret_file: Option<String>,
}

fn default_provider_type() -> String {
    "oidc".to_string()
}

fn default_provider_scope() -> String {
    "openid email profile".to_string()
}

/// An upstream auth provider, for example kanidm as Rauthy's source IdP.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderSpec {
    #[serde(default = "default_true")]
    pub present: bool,
    pub name: String,
    #[serde(default = "default_provider_type")]
    pub typ: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub userinfo_endpoint: String,
    #[serde(default)]
    pub jwks_endpoint: Option<String>,
    pub client_id: String,
    #[serde(default)]
    pub client_secret_file: Option<String>,
    #[serde(default = "default_provider_scope")]
    pub scope: String,
    #[serde(default = "default_true")]
    pub use_pkce: bool,
    #[serde(default = "default_true")]
    pub client_secret_basic: bool,
    #[serde(default)]
    pub client_secret_post: bool,
    #[serde(default)]
    pub auto_onboarding: bool,
    #[serde(default)]
    pub auto_link: bool,
    #[serde(default)]
    pub admin_claim_path: Option<String>,
    #[serde(default)]
    pub admin_claim_value: Option<String>,
    #[serde(default)]
    pub mfa_claim_path: Option<String>,
    #[serde(default)]
    pub mfa_claim_value: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_minimal_state() {
        let s: State = serde_json::from_str("{}").unwrap();
        assert!(s.users.is_empty());
        assert!(s.groups.is_empty());
        assert!(s.scopes.is_empty());
        assert!(s.user_attributes.is_empty());
        assert!(s.providers.is_empty());
    }

    #[test]
    fn user_defaults_present_and_language() {
        let s: State =
            serde_json::from_str(r#"{ "users": { "a@example.com": { "roles": ["admin"] } } }"#)
                .unwrap();
        let u = &s.users["a@example.com"];
        assert!(u.present);
        assert_eq!(u.language, "en");
        assert_eq!(u.roles, vec!["admin".to_string()]);
        assert!(u.groups.is_empty());
        assert!(u.attributes.is_empty());
        assert!(u.preferred_username.is_none());
    }

    #[test]
    fn parses_scope_user_attribute_and_user_values() {
        let s: State = serde_json::from_str(
            r#"{ "scopes": { "vikunja_groups": { "attr_include_id": ["vikunja_groups"] } },
              "user_attributes": { "vikunja_groups": { "user_editable": false } },
              "users": { "a@example.com": {
                "preferred_username": "alice",
                "given_name": "Alice",
                "family_name": "Smith",
                "birthdate": "1984-01-02",
                "timezone": "Europe/Oslo",
                "street": "Example Street 1",
                "zip": "12345",
                "city": "Oslo",
                "country": "Norway",
                "phone": "+4712345678",
                "attributes": {
                  "vikunja_groups": [{"name": "ops", "oidcID": "ops"}]
                }
              } } }"#,
        )
        .unwrap();
        assert_eq!(
            s.scopes["vikunja_groups"].attr_include_id,
            vec!["vikunja_groups".to_string()]
        );
        assert!(!s.user_attributes["vikunja_groups"].user_editable);
        assert_eq!(
            s.users["a@example.com"].preferred_username.as_deref(),
            Some("alice")
        );
        let user = &s.users["a@example.com"];
        assert_eq!(user.given_name.as_deref(), Some("Alice"));
        assert_eq!(user.family_name.as_deref(), Some("Smith"));
        assert_eq!(user.birthdate.as_deref(), Some("1984-01-02"));
        assert_eq!(user.timezone.as_deref(), Some("Europe/Oslo"));
        assert_eq!(user.street.as_deref(), Some("Example Street 1"));
        assert_eq!(user.zip.as_deref(), Some("12345"));
        assert_eq!(user.city.as_deref(), Some("Oslo"));
        assert_eq!(user.country.as_deref(), Some("Norway"));
        assert_eq!(user.phone.as_deref(), Some("+4712345678"));
        assert!(s.users["a@example.com"]
            .attributes
            .contains_key("vikunja_groups"));
    }

    #[test]
    fn client_defaults() {
        let s: State = serde_json::from_str(
            r#"{ "clients": { "app": { "redirect_uris": ["https://app/cb"] } } }"#,
        )
        .unwrap();
        let c = &s.clients["app"];
        assert!(c.present);
        assert!(c.confidential);
        assert!(c.enable_pkce);
        assert!(c.generated_secret_file.is_none());
        assert_eq!(c.scopes, vec!["openid", "profile", "email"]);
        assert_eq!(c.flows_enabled, vec!["authorization_code", "refresh_token"]);
    }

    #[test]
    fn client_secret_file_parses() {
        let s: State = serde_json::from_str(
            r#"{ "clients": { "app": {
              "confidential": true,
              "generated_secret_file": "/run/rauthy-clients/app.secret"
            } } }"#,
        )
        .unwrap();
        let c = &s.clients["app"];
        assert_eq!(
            c.generated_secret_file.as_deref(),
            Some("/run/rauthy-clients/app.secret")
        );
    }

    #[test]
    fn provider_defaults_and_secret_file_parse() {
        let s: State = serde_json::from_str(
            r#"{ "providers": { "kanidm": {
              "name": "Kanidm",
              "issuer": "https://auth.example.com/oauth2/openid/rauthy",
              "authorization_endpoint": "https://auth.example.com/oauth2/openid/rauthy/auth",
              "token_endpoint": "https://auth.example.com/oauth2/openid/rauthy/token",
              "userinfo_endpoint": "https://auth.example.com/oauth2/openid/rauthy/userinfo",
              "client_id": "rauthy",
              "client_secret_file": "/run/secrets/rauthy-kanidm",
              "auto_link": true
            } } }"#,
        )
        .unwrap();
        let p = &s.providers["kanidm"];
        assert!(p.present);
        assert_eq!(p.typ, "oidc");
        assert_eq!(p.scope, "openid email profile");
        assert!(p.use_pkce);
        assert!(p.client_secret_basic);
        assert!(!p.client_secret_post);
        assert_eq!(
            p.client_secret_file.as_deref(),
            Some("/run/secrets/rauthy-kanidm")
        );
    }
}
