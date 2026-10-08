//! Exercise the real provisioner against a bounded localhost Matrix fixture.
//! Credentials and rooms here are synthetic; no production service is contacted.
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::process::{Command, Output, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{Value, json};

#[derive(Debug)]
struct Request {
    method: String,
    path: String,
    auth: String,
    body: Value,
}

fn private_state() -> Value {
    json!([
        {"type":"m.room.join_rules", "state_key":"", "content":{"join_rule":"invite"}},
        {"type":"m.room.guest_access", "state_key":"", "content":{"guest_access":"forbidden"}},
        {"type":"m.room.encryption", "state_key":"", "content":{"algorithm":"m.megolm.v1.aes-sha2"}},
        {"type":"m.room.history_visibility", "state_key":"", "content":{"history_visibility":"joined"}},
        {"type":"m.room.create", "state_key":"", "sender":"@iris:example.test", "content":{}},
        {"type":"m.room.power_levels", "state_key":"", "content":{"users":{"@iris:example.test":100},"invite":100,"events":{"m.room.redaction":100}}},
        {"type":"m.room.member", "state_key":"@iris:example.test", "content":{"membership":"join"}}
    ])
}

struct Scenario {
    alias_status: u16,
    alias_room: &'static str,
    expected_room: Option<&'static str>,
    state: Value,
    logout_status: u16,
    invite_status: u16,
    legacy: bool,
    lost_login_response: bool,
    malformed_login_response: bool,
    lost_logout_response: bool,
    fail_first_logout: bool,
}

impl Default for Scenario {
    fn default() -> Self {
        Self {
            alias_status: 200,
            alias_room: "!iris:example.test",
            expected_room: None,
            state: private_state(),
            logout_status: 200,
            invite_status: 200,
            legacy: false,
            lost_login_response: false,
            malformed_login_response: false,
            lost_logout_response: false,
            fail_first_logout: false,
        }
    }
}

fn run(scenario: Scenario) -> (Output, Vec<Request>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();
    let temp = tempfile::tempdir().unwrap();
    std::fs::write(temp.path().join("iris-password"), "fixture-password").unwrap();
    std::fs::write(temp.path().join("admin-token"), "fixture-admin").unwrap();
    let state = json!({
        "server_name":"example.test", "port":port, "admin_token_user":null,
        "users":{"iris":{"admin":false,"credential_name":"iris-password"}},
        "rooms":{"iris":{
            "alias":"#hermes-iris:example.test", "name":"hermes-iris",
            "creator": if scenario.legacy { None } else { Some("iris") },
            "encrypted":!scenario.legacy, "expectedRoomId":scenario.expected_room,
            "invite":["@can:example.test"]
        }}
    });
    std::fs::write(temp.path().join("state.json"), state.to_string()).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let server_stop = stop.clone();
    let server = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(15);
        let mut requests = Vec::new();
        let mut invited = false;
        while !server_stop.load(Ordering::Acquire) && Instant::now() < deadline {
            let (mut stream, _) = match listener.accept() {
                Ok(connection) => connection,
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                    continue;
                }
                Err(err) => panic!("fixture accept failed: {err}"),
            };
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut reader = BufReader::new(&stream);
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            let mut parts = line.split_whitespace();
            let method = parts.next().unwrap().to_owned();
            let path = parts.next().unwrap().to_owned();
            let mut length = 0;
            let mut auth = String::new();
            loop {
                line.clear();
                reader.read_line(&mut line).unwrap();
                if line == "\r\n" {
                    break;
                }
                let (key, value) = line.split_once(':').unwrap();
                match key.to_ascii_lowercase().as_str() {
                    "content-length" => length = value.trim().parse::<usize>().unwrap(),
                    "authorization" => auth = value.trim().to_owned(),
                    _ => {}
                }
            }
            let mut bytes = vec![0; length];
            reader.read_exact(&mut bytes).unwrap();
            let body = if bytes.is_empty() {
                Value::Null
            } else {
                serde_json::from_slice(&bytes).unwrap()
            };
            let (status, response) = match (method.as_str(), path.as_str()) {
                ("GET", "/_matrix/client/versions") => (200, json!({"versions":["v1.11"]})),
                ("POST", "/_synapse/admin/v2/users/@iris:example.test") => (200, json!({})),
                ("POST", "/_matrix/client/v3/login") => {
                    if scenario.malformed_login_response
                        && !requests
                            .iter()
                            .any(|r: &Request| r.path.ends_with("/login"))
                    {
                        (200, json!({}))
                    } else {
                        (200, json!({"access_token":"fixture-owner"}))
                    }
                }
                ("GET", path) if path.starts_with("/_matrix/client/v3/directory/room/") => (
                    scenario.alias_status,
                    json!({"room_id":scenario.alias_room}),
                ),
                ("POST", "/_matrix/client/v3/createRoom") => {
                    invited = true;
                    (200, json!({"room_id":"!iris:example.test"}))
                }
                ("GET", "/_matrix/client/v3/rooms/%21iris%3Aexample.test/state") => {
                    let mut state = scenario.state.clone();
                    if invited {
                        state.as_array_mut().unwrap().push(json!({"type":"m.room.member","state_key":"@can:example.test","content":{"membership":"invite"}}));
                    }
                    (200, state)
                }
                ("POST", "/_matrix/client/v3/rooms/%21iris%3Aexample.test/invite") => {
                    invited = scenario.invite_status == 200;
                    (scenario.invite_status, json!({}))
                }
                ("POST", "/_matrix/client/v3/logout") => {
                    let first = !requests
                        .iter()
                        .any(|r: &Request| r.path.ends_with("/logout"));
                    (
                        if first && scenario.fail_first_logout {
                            500
                        } else {
                            scenario.logout_status
                        },
                        json!({}),
                    )
                }
                _ => (500, json!({"error":"Unexpected fixture request"})),
            };
            requests.push(Request {
                method,
                path,
                auth,
                body,
            });
            if scenario.lost_login_response
                && requests.last().unwrap().path.ends_with("/login")
                && requests
                    .iter()
                    .filter(|r| r.path.ends_with("/login"))
                    .count()
                    == 1
            {
                continue;
            }
            if scenario.lost_logout_response
                && requests.last().unwrap().path.ends_with("/logout")
                && requests
                    .iter()
                    .filter(|r| r.path.ends_with("/logout"))
                    .count()
                    == 1
            {
                continue;
            }
            let response = response.to_string();
            write!(stream, "HTTP/1.1 {status} Fixture\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response}", response.len()).unwrap();
        }
        requests
    });
    let mut child = Command::new(env!("CARGO_BIN_EXE_tuwunel-provision"))
        .args([
            "--state",
            temp.path().join("state.json").to_str().unwrap(),
            "--admin-token-file",
            temp.path().join("admin-token").to_str().unwrap(),
            "--credential-dir",
            temp.path().to_str().unwrap(),
            "--marker-dir",
            temp.path().join("markers").to_str().unwrap(),
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut timed_out = false;
    while child.try_wait().unwrap().is_none() {
        if Instant::now() >= deadline {
            child.kill().unwrap();
            timed_out = true;
            break;
        }
        thread::sleep(Duration::from_millis(5));
    }
    let output = child.wait_with_output().unwrap();
    stop.store(true, Ordering::Release);
    let requests = server.join().unwrap();
    assert!(
        !timed_out,
        "provisioner exceeded fixture deadline: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    (output, requests)
}

fn assert_logged_out(requests: &[Request]) {
    let last = requests.last().unwrap();
    assert_eq!(last.method, "POST");
    assert_eq!(last.path, "/_matrix/client/v3/logout");
    assert_eq!(last.auth, "Bearer fixture-owner");
}

#[test]
fn creates_encrypted_room_as_owner_and_revokes_provisioning_session() {
    let (output, requests) = run(Scenario {
        alias_status: 404,
        ..Scenario::default()
    });
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let login = requests
        .iter()
        .find(|r| r.path.ends_with("/login"))
        .unwrap();
    assert_eq!(login.body["identifier"]["user"], "iris");
    assert_eq!(login.body["device_id"], "TUWUNEL_PROVISION");
    let create = requests
        .iter()
        .find(|r| r.path.ends_with("/createRoom"))
        .unwrap();
    assert_eq!(create.auth, "Bearer fixture-owner");
    assert_eq!(create.body["visibility"], "private");
    assert_eq!(create.body["preset"], "private_chat");
    assert_eq!(create.body["invite"], json!(["@can:example.test"]));
    assert_eq!(create.body["power_level_content_override"]["invite"], 100);
    assert_eq!(
        create.body["power_level_content_override"]["events"]["m.room.redaction"],
        100
    );
    assert_eq!(create.body["initial_state"][2]["state_key"], "");
    assert_eq!(
        create.body["initial_state"][2]["content"]["algorithm"],
        "m.megolm.v1.aes-sha2"
    );
    assert_logged_out(&requests);
}

#[test]
fn reconciles_missing_invitation_only_after_private_state_verification() {
    let (output, requests) = run(Scenario::default());
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let state_index = requests
        .iter()
        .position(|r| r.path.ends_with("/state"))
        .unwrap();
    let invite_index = requests
        .iter()
        .position(|r| r.path.ends_with("/invite"))
        .unwrap();
    assert!(state_index < invite_index);
    assert_eq!(requests[invite_index].auth, "Bearer fixture-owner");
    assert_eq!(requests[invite_index].body["user_id"], "@can:example.test");
    assert_eq!(
        requests
            .iter()
            .filter(|r| r.path.ends_with("/state"))
            .count(),
        2
    );
    assert_logged_out(&requests);
}

#[test]
fn pinned_alias_missing_or_drifted_never_creates_a_replacement() {
    for alias_status in [404, 200] {
        let (output, requests) = run(Scenario {
            alias_status,
            alias_room: "!replacement:example.test",
            expected_room: Some("!iris:example.test"),
            ..Scenario::default()
        });
        assert!(!output.status.success());
        assert!(
            !requests
                .iter()
                .any(|r| r.path.ends_with("/createRoom") || r.path.ends_with("/invite"))
        );
        assert_logged_out(&requests);
    }
}

#[test]
fn unsuitable_existing_room_is_rejected_before_inviting_and_logs_out() {
    for index in 0..3 {
        let mut state = private_state();
        state[index]["content"] = json!({});
        let (output, requests) = run(Scenario {
            state,
            ..Scenario::default()
        });
        assert!(!output.status.success());
        assert!(!requests.iter().any(|r| r.path.ends_with("/invite")));
        assert_logged_out(&requests);
    }
}

#[test]
fn alias_lookup_failure_still_revokes_the_owner_session() {
    let (output, requests) = run(Scenario {
        alias_status: 500,
        ..Scenario::default()
    });
    assert!(!output.status.success());
    assert_logged_out(&requests);
}

#[test]
fn ambiguous_login_failure_recovers_and_revokes_the_same_device() {
    for lost_login_response in [false, true] {
        let (output, requests) = run(Scenario {
            lost_login_response,
            malformed_login_response: !lost_login_response,
            ..Scenario::default()
        });
        assert!(!output.status.success());
        let logins: Vec<_> = requests
            .iter()
            .filter(|r| r.path.ends_with("/login"))
            .collect();
        assert_eq!(logins.len(), 2);
        for login in logins {
            assert_eq!(login.body["device_id"], "TUWUNEL_PROVISION");
        }
        assert!(
            !requests
                .iter()
                .any(|r| r.path.ends_with("/createRoom") || r.path.ends_with("/invite"))
        );
        assert_logged_out(&requests);
    }
}

#[test]
fn existing_room_with_public_history_or_wrong_owner_is_not_adopted() {
    for bad_state in [
        json!({"type":"m.room.history_visibility", "state_key":"", "content":{"history_visibility":"world_readable"}}),
        json!({"type":"m.room.create", "state_key":"", "sender":"@other:example.test", "content":{}}),
        json!({"type":"m.room.power_levels", "state_key":"", "content":{"users":{"@iris:example.test":0}}}),
        json!({"type":"m.room.power_levels", "state_key":"", "content":{"users":{"@iris:example.test":100, "@other:example.test":100}}}),
    ] {
        let mut state = private_state();
        for event in state.as_array_mut().unwrap() {
            if event["type"] == bad_state["type"] {
                *event = bad_state.clone();
            }
        }
        let (output, requests) = run(Scenario {
            state,
            ..Scenario::default()
        });
        assert!(!output.status.success());
        assert!(!requests.iter().any(|r| r.path.ends_with("/invite")));
        assert_logged_out(&requests);
    }
}

#[test]
fn invitation_failure_still_revokes_the_owner_session() {
    let (output, requests) = run(Scenario {
        invite_status: 500,
        ..Scenario::default()
    });
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("inviting"));
    assert_logged_out(&requests);
}

#[test]
fn unexpected_active_member_is_rejected_before_inviting() {
    let mut state = private_state();
    state.as_array_mut().unwrap().push(json!({
        "type":"m.room.member", "state_key":"@matrix-admin:example.test",
        "content":{"membership":"join"}
    }));
    let (output, requests) = run(Scenario {
        state,
        ..Scenario::default()
    });
    assert!(!output.status.success());
    assert!(!requests.iter().any(|r| r.path.ends_with("/invite")));
    assert_logged_out(&requests);
}

#[test]
fn logout_failure_prevents_successful_reconciliation() {
    let (output, requests) = run(Scenario {
        logout_status: 500,
        ..Scenario::default()
    });
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("logging out"));
    assert_logged_out(&requests);
    assert_eq!(
        requests
            .iter()
            .filter(|r| r.path.ends_with("/login"))
            .count(),
        2
    );
    assert_eq!(
        requests
            .iter()
            .filter(|r| r.path.ends_with("/logout"))
            .count(),
        2
    );
}

#[test]
fn ambiguous_logout_recovers_and_revokes_same_device_without_repeating_reconciliation() {
    for lost_logout_response in [false, true] {
        let (output, requests) = run(Scenario {
            lost_logout_response,
            fail_first_logout: !lost_logout_response,
            ..Scenario::default()
        });
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let logins: Vec<_> = requests
            .iter()
            .filter(|r| r.path.ends_with("/login"))
            .collect();
        assert_eq!(logins.len(), 2);
        for login in logins {
            assert_eq!(login.body["device_id"], "TUWUNEL_PROVISION");
        }
        assert_eq!(
            requests
                .iter()
                .filter(|r| r.path.ends_with("/logout"))
                .count(),
            2
        );
        assert_eq!(
            requests
                .iter()
                .filter(|r| r.path.ends_with("/invite"))
                .count(),
            1
        );
        assert_logged_out(&requests);
    }
}

#[test]
fn logout_recovery_preserves_the_original_reconciliation_failure() {
    for logout_status in [200, 500] {
        let (output, requests) = run(Scenario {
            alias_status: 500,
            fail_first_logout: true,
            logout_status,
            ..Scenario::default()
        });
        assert!(!output.status.success());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("resolving Matrix room"), "{stderr}");
        assert_eq!(
            requests
                .iter()
                .filter(|r| r.path.ends_with("/login"))
                .count(),
            2
        );
        assert_eq!(
            requests
                .iter()
                .filter(|r| r.path.ends_with("/logout"))
                .count(),
            2
        );
        if logout_status == 500 {
            assert!(stderr.contains("same-device cleanup also failed"));
        }
        assert_logged_out(&requests);
    }
}

#[test]
fn every_room_version_checks_redaction_before_inviting() {
    for version in 1..=12 {
        for safe in [false, true] {
            let mut state = private_state();
            state[4]["content"]["room_version"] = version.to_string().into();
            state[5]["content"] = json!({"invite":100,"events":{"m.poll.response":0}});
            if version < 12 {
                state[5]["content"]["users"]["@iris:example.test"] = 100.into();
            }
            if safe {
                state[5]["content"]["events"]["m.room.redaction"] = 100.into();
            }
            let (output, requests) = run(Scenario {
                state,
                ..Scenario::default()
            });
            assert_eq!(
                output.status.success(),
                safe,
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert_eq!(requests.iter().any(|r| r.path.ends_with("/invite")), safe);
            assert_logged_out(&requests);
        }
    }
}

#[test]
fn legacy_string_powers_are_versioned_and_checked_before_inviting() {
    for version in 1..=12 {
        for safe in [false, true] {
            let mut state = private_state();
            state[4]["content"]["room_version"] = version.to_string().into();
            state[5]["content"] = json!({
                "users":{"@iris:example.test":" +00100 ","@can:example.test":" -01 "},
                "users_default":"-01", "events_default":"000", "state_default":"+050",
                "invite":" 100 ", "kick":"50", "ban":"50", "redact":"50",
                "events":{"m.room.redaction":if safe { "\t+100\n" } else { "-01" },"m.room.encrypted":"0"}
            });
            let (output, requests) = run(Scenario {
                state,
                ..Scenario::default()
            });
            let expected = version < 10 && safe;
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert_eq!(
                output.status.success(),
                expected,
                "room version {version}: {stderr}"
            );
            assert_eq!(
                requests.iter().any(|r| r.path.ends_with("/invite")),
                expected
            );
            if !expected {
                assert!(
                    stderr.contains(if version < 10 {
                        "nonowner can change room policy through m.room.redaction"
                    } else {
                        "invalid Matrix power level"
                    }),
                    "{stderr}"
                );
            }
            assert_logged_out(&requests);
        }
    }
}

#[test]
fn nonowner_policy_power_and_third_party_invites_are_rejected_before_inviting() {
    for bad_state in [
        json!({"type":"m.room.power_levels", "state_key":"", "content":{"users":{"@iris:example.test":100,"@can:example.test":50},"invite":100}}),
        json!({"type":"m.room.power_levels", "state_key":"", "content":{"users":{"@iris:example.test":100},"invite":0}}),
        json!({"type":"m.room.third_party_invite", "state_key":"invitation-token", "content":{"display_name":"outsider","public_key":"key"}}),
    ] {
        let mut state = private_state();
        state
            .as_array_mut()
            .unwrap()
            .retain(|event| event["type"] != bad_state["type"]);
        state.as_array_mut().unwrap().push(bad_state);
        let (output, requests) = run(Scenario {
            state,
            ..Scenario::default()
        });
        assert!(!output.status.success());
        assert!(!requests.iter().any(|r| r.path.ends_with("/invite")));
        assert_logged_out(&requests);
    }
}

#[test]
fn legacy_room_uses_admin_without_owner_login_or_encryption_retrofit() {
    let (output, requests) = run(Scenario {
        alias_status: 404,
        legacy: true,
        ..Scenario::default()
    });
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let create = requests
        .iter()
        .find(|r| r.path.ends_with("/createRoom"))
        .unwrap();
    assert_eq!(create.auth, "Bearer fixture-admin");
    assert!(create.body.get("initial_state").is_none());
    assert!(
        !requests
            .iter()
            .any(|r| r.path.ends_with("/login") || r.path.ends_with("/logout"))
    );
}
