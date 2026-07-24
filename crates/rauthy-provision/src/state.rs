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

use provenance_core::serde_ext::{default_true, double_option};
use serde::{Deserialize, Serialize};
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
#[derive(Debug, Default, Deserialize, Serialize)]
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

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GroupSpec {
    #[serde(default = "default_true")]
    pub present: bool,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RoleSpec {
    #[serde(default = "default_true")]
    pub present: bool,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeSpec {
    #[serde(default = "default_true")]
    pub present: bool,
    #[serde(default)]
    pub attr_include_access: Vec<String>,
    #[serde(default)]
    pub attr_include_id: Vec<String>,
    #[serde(default)]
    pub claims_at_root: bool,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UserAttributeSpec {
    #[serde(default = "default_true")]
    pub present: bool,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub desc: Option<String>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
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
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UserSpec {
    #[serde(default = "default_true")]
    pub present: bool,
    #[serde(default, deserialize_with = "double_option::deserialize")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub given_name: Option<Option<String>>,
    #[serde(default, deserialize_with = "double_option::deserialize")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub family_name: Option<Option<String>>,
    #[serde(default, deserialize_with = "double_option::deserialize")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub birthdate: Option<Option<String>>,
    #[serde(default, deserialize_with = "double_option::deserialize")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timezone: Option<Option<String>>,
    #[serde(default, deserialize_with = "double_option::deserialize")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub street: Option<Option<String>>,
    #[serde(default, deserialize_with = "double_option::deserialize")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub zip: Option<Option<String>>,
    #[serde(default, deserialize_with = "double_option::deserialize")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub city: Option<Option<String>>,
    #[serde(default, deserialize_with = "double_option::deserialize")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<Option<String>>,
    #[serde(default, deserialize_with = "double_option::deserialize")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone: Option<Option<String>>,
    #[serde(default = "default_language")]
    pub language: String,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_expires: Option<i64>,
    #[serde(default)]
    pub roles: Vec<String>,
    #[serde(default)]
    pub groups: Vec<String>,
    #[serde(default, deserialize_with = "double_option::deserialize")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preferred_username: Option<Option<String>>,
    #[serde(default)]
    pub attributes: BTreeMap<String, Value>,
    /// Rauthy provider key that must own this user's federated login. This is
    /// audited during reconciliation; the current Rauthy API has no per-user
    /// runtime enforcement switch.
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub required_auth_provider: Option<String>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password_email_redirect_uri: Option<String>,
    /// Runtime file containing the user's initial native Rauthy password. The
    /// password is applied only while creating the user. Existing user
    /// passwords are never changed declaratively; marker drift emits a warning.
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub initial_password_file: Option<String>,
}

/// An OIDC client (relying party).
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClientSpec {
    #[serde(default = "default_true")]
    pub present: bool,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub generated_secret_file: Option<String>,
}

fn default_provider_type() -> String {
    "oidc".to_string()
}

fn default_provider_scope() -> String {
    "openid email profile".to_string()
}

/// An upstream auth provider, for example kanidm as Rauthy's source IdP.
#[derive(Debug, Deserialize, Serialize)]
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwks_endpoint: Option<String>,
    pub client_id: String,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub admin_claim_path: Option<String>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub admin_claim_value: Option<String>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mfa_claim_path: Option<String>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
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
        assert!(u.user_expires.is_none());
        assert!(u.initial_password_file.is_none());
        assert!(u.required_auth_provider.is_none());
    }

    #[test]
    fn parses_required_auth_provider() {
        let s: State = serde_json::from_str(
            r#"{ "users": { "a@example.com": { "required_auth_provider": "kanidm" } } }"#,
        )
        .unwrap();
        assert_eq!(
            s.users["a@example.com"].required_auth_provider.as_deref(),
            Some("kanidm")
        );
    }

    #[test]
    fn parses_initial_password_file_reference() {
        let s: State = serde_json::from_str(
            r#"{ "users": { "a@example.com": { "initial_password_file": "/run/credentials/rauthy-provision.service/password-a" } } }"#,
        )
        .unwrap();
        assert_eq!(
            s.users["a@example.com"].initial_password_file.as_deref(),
            Some("/run/credentials/rauthy-provision.service/password-a")
        );
    }

    #[test]
    fn parses_scope_user_attribute_and_user_values() {
        let s: State = serde_json::from_str(
            r#"{ "scopes": { "vikunja_groups": { "attr_include_id": ["vikunja_groups"], "claims_at_root": true } },
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
                "user_expires": 1893456000,
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
        assert!(s.scopes["vikunja_groups"].claims_at_root);
        assert!(!s.user_attributes["vikunja_groups"].user_editable);
        assert_eq!(
            s.users["a@example.com"].preferred_username,
            Some(Some("alice".to_string()))
        );
        let user = &s.users["a@example.com"];
        assert_eq!(user.given_name, Some(Some("Alice".to_string())));
        assert_eq!(user.family_name, Some(Some("Smith".to_string())));
        assert_eq!(user.birthdate, Some(Some("1984-01-02".to_string())));
        assert_eq!(user.timezone, Some(Some("Europe/Oslo".to_string())));
        assert_eq!(user.street, Some(Some("Example Street 1".to_string())));
        assert_eq!(user.zip, Some(Some("12345".to_string())));
        assert_eq!(user.city, Some(Some("Oslo".to_string())));
        assert_eq!(user.country, Some(Some("Norway".to_string())));
        assert_eq!(user.phone, Some(Some("+4712345678".to_string())));
        assert_eq!(user.user_expires, Some(1893456000));
        assert!(
            s.users["a@example.com"]
                .attributes
                .contains_key("vikunja_groups")
        );
    }

    #[test]
    fn user_nullable_fields_distinguish_absent_set_and_clear() {
        let s: State = serde_json::from_str(
            r#"{
              "users": {
                "a@example.com": {
                  "given_name": null,
                  "family_name": "Smith",
                  "timezone": "Europe/Oslo",
                  "preferred_username": null
                }
              }
            }"#,
        )
        .unwrap();
        let u = &s.users["a@example.com"];
        assert_eq!(u.given_name, Some(None));
        assert_eq!(u.family_name, Some(Some("Smith".to_string())));
        assert_eq!(u.timezone, Some(Some("Europe/Oslo".to_string())));
        assert_eq!(u.preferred_username, Some(None));
        assert!(u.birthdate.is_none());
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
