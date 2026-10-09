use std::collections::BTreeMap;

use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct State {
    pub server_name: String,
    pub port: u16,
    pub admin_token_user: Option<String>,
    pub users: BTreeMap<String, UserSpec>,
    #[serde(default)]
    pub rooms: BTreeMap<String, RoomSpec>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserSpec {
    pub admin: bool,
    pub display_name: Option<String>,
    pub credential_name: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoomSpec {
    pub alias: String,
    pub name: Option<String>,
    #[serde(default)]
    pub topic: Option<String>,
    #[serde(default)]
    pub invite: Vec<String>,
    /// Localpart of a provisioned account that creates and reconciles this room.
    /// Unlike the legacy admin-created rooms, the admin is never a member.
    #[serde(default)]
    pub creator: Option<String>,
    /// Encryption must be present in the room's initial state; it cannot safely
    /// be added after a room has already accepted messages.
    #[serde(default)]
    pub encrypted: bool,
    #[serde(default, rename = "expectedRoomId")]
    pub expected_room_id: Option<String>,
}

pub fn valid_room_id(id: &str) -> bool {
    let Some(opaque) = id.strip_prefix('!') else {
        return false;
    };
    if id.len() > 255 || id.contains('\0') {
        return false;
    }
    match opaque.split_once(':') {
        Some((localpart, server)) => !localpart.is_empty() && valid_server_name(server),
        None => {
            opaque.len() == 43
                // A 32-byte hash leaves two zero padding bits in the last sextet.
                && b"AEIMQUYcgkosw048".contains(&opaque.as_bytes()[42])
                && opaque
                    .bytes()
                    .all(|ch| ch.is_ascii_alphanumeric() || ch == b'_' || ch == b'-')
        }
    }
}

fn valid_server_name(server: &str) -> bool {
    let valid_port = |port: &str| {
        !port.is_empty() && port.len() <= 5 && port.bytes().all(|ch| ch.is_ascii_digit())
    };
    if let Some(ipv6) = server.strip_prefix('[') {
        return ipv6.split_once(']').is_some_and(|(host, suffix)| {
            host.parse::<std::net::Ipv6Addr>().is_ok()
                && (suffix.is_empty() || suffix.strip_prefix(':').is_some_and(valid_port))
        });
    }
    let host = match server.split_once(':') {
        Some((host, port)) if valid_port(port) => host,
        Some(_) => return false,
        None => server,
    };
    if host.is_empty()
        || host.len() > 255
        || !host
            .bytes()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == b'.' || ch == b'-')
    {
        return false;
    }
    let octets: Vec<_> = host.split('.').collect();
    // The Matrix grammar permits zero-padded IPv4 octets; std::net rejects them.
    octets.len() != 4
        || !octets
            .iter()
            .all(|part| !part.is_empty() && part.bytes().all(|ch| ch.is_ascii_digit()))
        || octets
            .iter()
            .all(|part| part.len() <= 3 && part.parse::<u8>().is_ok())
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
        assert!(s.rooms.is_empty());
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

    #[test]
    fn parses_room_state() {
        let s: State = serde_json::from_str(
            r##"{
                "server_name": "matrix.tartanoglu.com",
                "port": 6167,
                "admin_token_user": "matrix-admin",
                "users": {},
                "rooms": {
                    "alerts": {
                        "alias": "#canix-alerts:matrix.tartanoglu.com",
                        "name": "canix-alerts",
                        "topic": "Canix fleet alerts",
                        "invite": ["@matrix-alerts:matrix.tartanoglu.com"]
                    }
                }
            }"##,
        )
        .unwrap();
        let room = &s.rooms["alerts"];
        assert_eq!(room.alias, "#canix-alerts:matrix.tartanoglu.com");
        assert_eq!(room.name.as_deref(), Some("canix-alerts"));
        assert_eq!(room.invite, ["@matrix-alerts:matrix.tartanoglu.com"]);
        assert!(room.creator.is_none());
        assert!(!room.encrypted);
        assert!(room.expected_room_id.is_none());
    }

    #[test]
    fn v12_hash_tail_requires_zero_base64_padding_bits() {
        for (index, tail) in b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
            .iter()
            .enumerate()
        {
            let id = format!("!{}{}", "A".repeat(42), char::from(*tail));
            assert_eq!(
                valid_room_id(&id),
                index % 4 == 0,
                "hash tail {}",
                char::from(*tail)
            );
        }
    }

    #[test]
    fn room_id_validation_checks_complete_legacy_grammar_and_byte_limits() {
        for id in [
            "!room:example.test",
            "!room:example.test:8448",
            "!room:1.2.3.4",
            "!room:001.2.3.4:8448",
            "!room:[::1]",
            "!room:[2001:db8::1]:8448",
            "!room:[::ffff:192.0.2.1]:8448",
            "!é\n:example.test",
            "!AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        ] {
            assert!(valid_room_id(id), "valid ID {id:?}");
        }
        let boundary = format!("!{}:example.test", "a".repeat(241));
        assert_eq!(boundary.len(), 255);
        assert!(valid_room_id(&boundary));
        assert!(!valid_room_id(&format!("!{boundary}")));
        for id in [
            "",
            "!",
            "!short",
            "#room:example.test",
            "!:example.test",
            "!room:",
            "!room:not a server",
            "!room:example.test:garbage",
            "!room:example.test:",
            "!room:example.test:123456",
            "!room:example.test/path",
            "!room:user@example.test",
            "!room:[12345::]",
            "!room:[:::]",
            "!room:[::1]junk",
            "!room:999.1.2.3",
            "!room\0:example.test",
            "!AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        ] {
            assert!(!valid_room_id(id), "invalid ID {id:?}");
        }
        assert!(!valid_room_id(&format!(
            "!{}:example.test",
            "é".repeat(122)
        )));
    }

    #[test]
    fn parses_private_encrypted_room() {
        let s: State = serde_json::from_str(
            r##"{
                "server_name": "matrix.example.test", "port": 6167,
                "admin_token_user": "matrix-admin", "users": {},
                "rooms": {"iris": {
                    "alias": "#hermes-iris:matrix.example.test", "name": "hermes-iris",
                    "creator": "iris", "invite": ["@can:matrix.example.test"],
                    "encrypted": true
                }}
            }"##,
        )
        .unwrap();
        let room = &s.rooms["iris"];
        assert_eq!(room.creator.as_deref(), Some("iris"));
        assert!(room.encrypted);
        assert!(room.expected_room_id.is_none());
    }
}
