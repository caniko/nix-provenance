mod support;

use serde_json::{Value, json};
use std::io::{ErrorKind, Write};
use std::process::{Command, Output, Stdio};
use support::LogindFixture;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_proton-vpn-auth")
}

fn run_with_stdin(args: &[&str], stdin_bytes: &[u8]) -> Output {
    let logind = LogindFixture::new();
    let mut command = Command::new(bin());
    command.args(args);
    logind.configure(&mut command);
    let mut child = command
        .env_remove("XDG_RUNTIME_DIR")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn proton-vpn-auth");
    if let Err(error) = child.stdin.take().unwrap().write_all(stdin_bytes) {
        // The helper may reject input and close the pipe before the full write.
        assert_eq!(error.kind(), ErrorKind::BrokenPipe, "write stdin: {error}");
    }
    child.wait_with_output().expect("wait for proton-vpn-auth")
}

#[test]
fn capabilities_emits_descriptor_without_logind_or_secrets() {
    for args in [&["capabilities"][..], &["capabilities", "--json"][..]] {
        let output = Command::new(bin())
            .args(args)
            .env_remove("DBUS_SYSTEM_BUS_ADDRESS")
            .output()
            .expect("run capabilities");
        assert_eq!(output.status.code(), Some(0));
        let doc: Value = serde_json::from_slice(&output.stdout).expect("capabilities json");
        assert_eq!(doc["version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(
            doc["subcommands"],
            json!(["login", "enroll", "capabilities", "validate"])
        );
        assert_eq!(
            doc["enroll"],
            json!({
                "stdin": true,
                "stdout": true,
                "passwordOnly": true,
                "rbwJson": true,
                "maxDocumentBytes": 65536
            })
        );
    }
}

#[test]
fn validate_accepts_valid_documents_and_never_echoes_secrets() {
    let payload = json!({
        "username": "alice@proton.me",
        "password": "super-secret-proton-password",
        "totpSecret": "otpauth://totp/Proton:alice?secret=gezdgnbvgy3tqojq&issuer=Proton"
    })
    .to_string();
    let output = run_with_stdin(&["validate", "--stdin", "--json"], payload.as_bytes());
    assert_eq!(output.status.code(), Some(0));
    let raw = String::from_utf8_lossy(&output.stdout);
    assert!(!raw.contains("super-secret-proton-password"));
    assert!(!raw.contains("gezdgnbvgy3tqojq"));
    assert!(!raw.contains("GEZDGNBVGY3TQOJQ"));
    let report: Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(report["valid"], true);
    assert_eq!(report["username"], "alice@proton.me");
    assert_eq!(report["hasTotp"], true);
    assert_eq!(report["totpNormalized"], true);
    assert!(report["error"].is_null());

    // Password-only validation
    let pw_only = json!({
        "username": "bob@proton.me",
        "password": "bob-secret-password"
    })
    .to_string();
    let out = run_with_stdin(
        &["validate", "--stdin", "--password-only", "--json"],
        pw_only.as_bytes(),
    );
    assert_eq!(out.status.code(), Some(0));
    let report: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["valid"], true);
    assert_eq!(report["hasTotp"], false);
    assert_eq!(report["totpNormalized"], false);
    assert!(!String::from_utf8_lossy(&out.stdout).contains("bob-secret-password"));
}

#[test]
fn validate_rejects_otp_codes_and_malformed_json_with_exit_2() {
    let otp = json!({
        "username": "alice@proton.me",
        "password": "super-secret-proton-password",
        "totpSecret": "234567"
    })
    .to_string();
    for (input, error) in [
        (otp.as_bytes(), "Invalid base32 Proton TOTP seed"),
        (
            b"{",
            "Invalid Proton credential JSON; expected username, password, and optional totpSecret",
        ),
    ] {
        let out = run_with_stdin(&["validate", "--stdin", "--json"], input);
        assert_validation_error(&out, error);
    }
}

fn assert_validation_error(out: &Output, error: &str) {
    assert_eq!(out.status.code(), Some(2));
    assert!(out.stderr.is_empty());
    let report: Value = serde_json::from_slice(&out.stdout).expect("validation error JSON");
    assert_eq!(
        report,
        json!({
            "valid": false,
            "username": null,
            "hasTotp": false,
            "totpNormalized": false,
            "error": error,
        })
    );
}

#[test]
fn validate_reports_protection_failure_as_json() {
    let out = Command::new(bin())
        .args(["validate", "--stdin", "--json"])
        .env("DBUS_SYSTEM_BUS_ADDRESS", "unix:path=/dev/null")
        .output()
        .expect("run validate without a system bus");
    assert_validation_error(
        &out,
        "Cannot contact logind for credential sleep protection",
    );
}

#[test]
fn enroll_rbw_json_projects_default_and_custom_fields() {
    // 1. Default mapping from data.{username, password, totp}
    let rbw_item = json!({
        "id": "item-1",
        "name": "Proton VPN",
        "data": {
            "username": "rbw-user",
            "password": "rbw-secret-password",
            "totp": "otpauth://totp/Proton:rbw?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
        },
        "fields": []
    })
    .to_string();
    let out = run_with_stdin(
        &["enroll", "--rbw-json", "--stdin", "--stdout"],
        rbw_item.as_bytes(),
    );
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let doc: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(doc["username"], "rbw-user");
    assert_eq!(doc["password"], "rbw-secret-password");
    assert_eq!(doc["totpSecret"], "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");

    // 2. Custom --rbw-map overrides reading from fields[{name, value}]
    let custom_item = json!({
        "id": "item-2",
        "name": "Proton Custom",
        "data": {
            "username": "ignored-user",
            "password": "rbw-custom-password"
        },
        "fields": [
            {"name": "proton_user", "value": "custom-user", "type": "text"},
            {"name": "vpn_totp", "value": "gezd gnbv gy3t qojq", "type": "hidden"}
        ]
    })
    .to_string();
    let out = run_with_stdin(
        &[
            "enroll",
            "--rbw-json",
            "--rbw-map",
            "username=custom:proton_user",
            "--rbw-map",
            "totpSecret=custom:vpn_totp",
            "--stdin",
            "--stdout",
        ],
        custom_item.as_bytes(),
    );
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let doc: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(doc["username"], "custom-user");
    assert_eq!(doc["password"], "rbw-custom-password");
    assert_eq!(doc["totpSecret"], "GEZDGNBVGY3TQOJQ");

    // 3. Password-only with --rbw-json
    let pw_item = json!({
        "data": {
            "username": "pw-user",
            "password": "pw-secret"
        }
    })
    .to_string();
    let out = run_with_stdin(
        &[
            "enroll",
            "--rbw-json",
            "--password-only",
            "--stdin",
            "--stdout",
        ],
        pw_item.as_bytes(),
    );
    assert_eq!(out.status.code(), Some(0));
    let doc: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(doc["username"], "pw-user");
    assert_eq!(doc["password"], "pw-secret");
    assert!(doc["totpSecret"].is_null());

    // 4. Rejects totpSecret mapping when --password-only is set
    let bad = run_with_stdin(
        &[
            "enroll",
            "--rbw-json",
            "--password-only",
            "--rbw-map",
            "totpSecret=totp",
            "--stdin",
            "--stdout",
        ],
        pw_item.as_bytes(),
    );
    assert_eq!(bad.status.code(), Some(2));
    assert!(bad.stdout.is_empty());
}

#[test]
fn enroll_rbw_json_distinguishes_notes_and_custom_password() {
    let item = br#"{
        "notes":"gezd gnbv gy3t qojq",
        "data":{"username":"fixture","password":"built-in","notes":"ignored"},
        "fields":[{"name":"password","value":"custom-password"}]
    }"#;
    let out = run_with_stdin(
        &[
            "enroll",
            "--rbw-json",
            "--stdin",
            "--stdout",
            "--rbw-map",
            "totpSecret=notes",
            "--rbw-map",
            "password=custom:password",
        ],
        item,
    );
    assert_eq!(out.status.code(), Some(0), "stderr: {:?}", out.stderr);
    let doc: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(doc["totpSecret"], "GEZDGNBVGY3TQOJQ");
    assert_eq!(doc["password"], "custom-password");
}

#[test]
fn enroll_rbw_json_rejects_duplicate_and_unprefixed_custom_fields() {
    let duplicate = br#"{
        "data":{"username":"fixture"},
        "fields":[{"name":"x","value":null},{"name":"x","value":"val"}]
    }"#;
    let unprefixed = br#"{
        "data":{"username":"fixture"},
        "fields":[{"name":"x","value":"val"}]
    }"#;
    for (selector, item, error) in [
        (
            "password=custom:x",
            &duplicate[..],
            "Ambiguous duplicate custom field",
        ),
        ("password=x", &unprefixed[..], "custom: prefix"),
    ] {
        let out = run_with_stdin(
            &[
                "enroll",
                "--rbw-json",
                "--stdin",
                "--stdout",
                "--password-only",
                "--rbw-map",
                selector,
            ],
            item,
        );
        assert_eq!(out.status.code(), Some(2));
        assert!(out.stdout.is_empty());
        assert!(String::from_utf8_lossy(&out.stderr).contains(error));
    }
}

#[test]
fn audit_rejects_oversized_canonical_enrollment() {
    let item = json!({"data":{
        "username":"fixture", "password":"fixture-password", "totp":"A".repeat(65_536)
    }});
    let out = run_with_stdin(
        &["enroll", "--rbw-json", "--stdin", "--stdout"],
        item.to_string().as_bytes(),
    );
    assert_eq!(out.status.code(), Some(2));
    assert!(out.stdout.is_empty());
    assert!(String::from_utf8_lossy(&out.stderr).contains("document is too large"));
}

#[test]
fn enroll_rbw_json_accepts_one_mib_but_keeps_the_proton_document_cap() {
    let mut item =
        br#"{"data":{"username":"fixture","password":"fixture-password"},"history":[""#.to_vec();
    item.resize(1024 * 1024 - 3, b'x');
    item.extend_from_slice(br#""]}"#);
    let args = [
        "enroll",
        "--rbw-json",
        "--stdin",
        "--stdout",
        "--password-only",
    ];
    let out = run_with_stdin(&args, &item);
    assert_eq!(out.status.code(), Some(0), "stderr: {:?}", out.stderr);

    item.push(b' ');
    let out = run_with_stdin(&args, &item);
    assert_eq!(out.status.code(), Some(2));
    assert!(out.stdout.is_empty());
    assert!(String::from_utf8_lossy(&out.stderr).contains("input is too large"));

    let mut document = br#"{"username":"fixture","password":"fixture-password"}"#.to_vec();
    document.resize(65_537, b' ');
    let out = run_with_stdin(
        &["enroll", "--stdin", "--stdout", "--password-only"],
        &document,
    );
    assert_eq!(out.status.code(), Some(2));
    assert!(out.stdout.is_empty());
    assert!(String::from_utf8_lossy(&out.stderr).contains("input is too large"));
}
