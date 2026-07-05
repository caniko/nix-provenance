use std::collections::BTreeMap;

use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct State {
    pub server_name: String,
    pub port: u16,
    pub admin_token_user: Option<String>,
    pub users: BTreeMap<String, UserSpec>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserSpec {
    pub admin: bool,
    pub display_name: Option<String>,
    pub credential_name: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_minimal_state() {
        let s: State = serde_json::from_str(
            r#"{"server_name":"example.com","port":6167,"admin_token_user":null,"users":{}}"#,
        )
        .unwrap();
        assert_eq!(s.server_name, "example.com");
        assert_eq!(s.port, 6167);
        assert!(s.admin_token_user.is_none());
        assert!(s.users.is_empty());
    }

    #[test]
    fn parses_user_state() {
        let s: State = serde_json::from_str(
            r#"{
                "server_name": "matrix.tartanoglu.com",
                "port": 6167,
                "admin_token_user": "can",
                "users": {
                    "can": {
                        "admin": true,
                        "display_name": "Can H. Tartanoglu",
                        "credential_name": "password-can-abc123"
                    }
                }
            }"#,
        )
        .unwrap();
        assert_eq!(s.admin_token_user.as_deref(), Some("can"));
        let can = &s.users["can"];
        assert!(can.admin);
        assert_eq!(can.display_name.as_deref(), Some("Can H. Tartanoglu"));
        assert_eq!(can.credential_name, "password-can-abc123");
    }

    #[test]
    fn display_name_is_optional() {
        let s: State = serde_json::from_str(
            r#"{
                "server_name": "example.com",
                "port": 6167,
                "admin_token_user": null,
                "users": {
                    "bot": {
                        "admin": false,
                        "credential_name": "password-bot-def456"
                    }
                }
            }"#,
        )
        .unwrap();
        assert!(s.users["bot"].display_name.is_none());
    }
}
