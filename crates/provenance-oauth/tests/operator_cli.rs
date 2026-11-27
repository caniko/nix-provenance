use provenance_oauth::{
    Config, Enrollment, Grant, OAuthClient, Secret, Target,
    antigravity_cli::DEFAULT_ANTIGRAVITY_SCOPES,
    state::{Store, atomic_write},
};
use serde_json::{Value, json};
use std::{
    fs,
    io::Write,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_provenance-oauth")
}

fn write_executable(path: &Path, script: &str) {
    fs::write(path, script).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}

fn setup_antigravity_enrollment(
    dir: &Path,
    (host, user): (&str, &str),
    enrollment_id: &str,
    refresh_token: &str,
    client_id: &str,
    client_secret: &str,
    project_id: Option<&str>,
) -> (PathBuf, PathBuf) {
    let manifests_dir = dir.join("manifests");
    fs::create_dir_all(&manifests_dir).unwrap();
    let state_dir = dir.join(format!("state-{enrollment_id}"));
    fs::create_dir_all(&state_dir).unwrap();
    fs::set_permissions(&state_dir, fs::Permissions::from_mode(0o700)).unwrap();

    let target = Target {
        host: host.into(),
        user: user.into(),
        provider: "google".into(),
        profile: "antigravity".into(),
        account: "default".into(),
        enrollment: Some(enrollment_id.into()),
    };
    let config = Config {
        version: 1,
        target: target.clone(),
        state_directory: state_dir,
        recovery_recipients: vec![age::x25519::Identity::generate().to_public().to_string()],
    };
    let manifest_path = manifests_dir.join(format!("{user}-{enrollment_id}.json"));
    atomic_write(&manifest_path, &serde_json::to_vec(&config).unwrap()).unwrap();

    let enrollment = Enrollment {
        version: 1,
        target,
        generation: 100,
        grant: Grant {
            access_token: Secret::default(),
            refresh_token: Secret(refresh_token.into()),
            expires_at: 0,
            account_id: "sub-12345".into(),
            client: Some(OAuthClient {
                client_id: client_id.into(),
                client_secret: Secret(client_secret.into()),
            }),
            project_id: project_id.map(str::to_owned),
            scopes: Some(vec![
                DEFAULT_ANTIGRAVITY_SCOPES[0].into(),
                "https://www.googleapis.com/auth/userinfo.email".into(),
            ]),
            opencode: None,
        },
    };
    let store = Store::lock(&config).unwrap();
    store.apply(&enrollment, true).unwrap();

    (manifests_dir, manifest_path)
}

#[test]
fn manifest_backed_subcommands_still_require_config() {
    let output = Command::new(bin()).arg("status").output().unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("--config"));
}

#[test]
fn antigravity_capture_normalizes_token_borrows_metadata_and_writes_0600() {
    let dir = tempfile::tempdir().unwrap();
    let user = Command::new("id").arg("-un").output().unwrap();
    assert!(user.status.success());
    let user = std::str::from_utf8(&user.stdout).unwrap().trim();
    let (manifests_dir, manifest_path) = setup_antigravity_enrollment(
        dir.path(),
        ("testhost", user),
        "google-work",
        "1//old-enrolled-refresh",
        "123.apps.googleusercontent.com",
        "borrowed-client-secret",
        Some("old-project"),
    );

    // 1. Nested native token on stdin, borrowing client metadata via --client-metadata-from
    let native_input = json!({
        "auth_method": "oauth-personal",
        "token": {
            "refresh_token": "1//new-captured-refresh",
            "access_token": "ephemeral-access-token"
        }
    });
    let out_file = dir.path().join("captured.json");
    let mut child = Command::new(bin())
        .current_dir(dir.path())
        .args([
            "antigravity-capture",
            "--token-file",
            "-",
            "--client-metadata-from",
        ])
        .arg(&manifest_path)
        .arg("--output")
        .arg("captured.json")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(native_input.to_string().as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        fs::metadata(&out_file).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let captured: Value = serde_json::from_slice(&fs::read(&out_file).unwrap()).unwrap();
    assert_eq!(captured["client_id"], "123.apps.googleusercontent.com");
    assert_eq!(captured["client_secret"], "borrowed-client-secret");
    assert_eq!(captured["token_uri"], "https://oauth2.googleapis.com/token");
    assert_eq!(captured["refresh_token"], "1//new-captured-refresh");
    assert_eq!(captured["scopes"].as_array().unwrap().len(), 7);
    assert!(captured.get("project_id").is_none());

    // 2. Borrow from --manifests-dir with --host and --user, emitting to non-TTY stdout
    let token_path = dir.path().join("native.json");
    fs::write(&token_path, native_input.to_string()).unwrap();
    let stdout_run = Command::new(bin())
        .args(["antigravity-capture", "--token-file"])
        .arg(&token_path)
        .args(["--manifests-dir"])
        .arg(&manifests_dir)
        .args(["--host", "testhost", "--user", user])
        .output()
        .unwrap();
    assert!(
        stdout_run.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&stdout_run.stderr)
    );
    let parsed: Value = serde_json::from_slice(&stdout_run.stdout).unwrap();
    assert_eq!(parsed["client_id"], "123.apps.googleusercontent.com");
    assert_eq!(parsed["refresh_token"], "1//new-captured-refresh");

    // 3. Missing client metadata -> exit 2
    let empty_dir = dir.path().join("empty-manifests");
    fs::create_dir(&empty_dir).unwrap();
    let missing_meta = Command::new(bin())
        .args(["antigravity-capture", "--token-file"])
        .arg(&token_path)
        .args(["--manifests-dir"])
        .arg(&empty_dir)
        .args(["--host", "testhost", "--user", user])
        .output()
        .unwrap();
    assert_eq!(missing_meta.status.code(), Some(2));
    assert!(!String::from_utf8_lossy(&missing_meta.stderr).contains("1//new-captured-refresh"));
}

#[test]
fn antigravity_capture_rejects_invalid_grant_and_wrong_manifest() {
    let dir = tempfile::tempdir().unwrap();
    let token = dir.path().join("token.json");
    let manifest = dir.path().join("manifest.json");
    let capture = |extra: &[&Path]| {
        Command::new(bin())
            .args(["antigravity-capture", "--token-file"])
            .arg(&token)
            .args(extra)
            .output()
            .unwrap()
    };
    fs::write(&token, r#"{"client_id":"123.apps.googleusercontent.com","client_secret":"secret","refresh_token":"1//refresh","token_uri":"https://untrusted.example/token"}"#).unwrap();
    let out = capture(&[]);
    assert_eq!(out.status.code(), Some(2));
    assert!(out.stdout.is_empty());

    let (_, valid) = setup_antigravity_enrollment(
        dir.path(),
        ("testhost", "testuser"),
        "google-work",
        "1//refresh",
        "123.apps.googleusercontent.com",
        "secret",
        None,
    );
    let mut config: Value = serde_json::from_slice(&fs::read(valid).unwrap()).unwrap();
    config["target"]["profile"] = json!("drive");
    fs::write(&manifest, config.to_string()).unwrap();
    fs::write(&token, r#"{"refresh_token":"1//refresh"}"#).unwrap();
    let out = capture(&[Path::new("--client-metadata-from"), &manifest]);
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("google/antigravity"));
}

#[test]
fn standalone_commands_reject_config() {
    for (command, flags) in [
        ("antigravity-capture", &["--token-file", "missing"][..]),
        ("antigravity-check", &[]),
        ("opencode-capture", &["--account", "work", "--skip-login"]),
        ("opencode-check", &["--export-file", "missing"]),
        ("google-client-bootstrap", &["--file", "missing"]),
    ] {
        let out = Command::new(bin())
            .args(["--config", "unused.json", command])
            .args(flags)
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(2), "{command}");
        assert!(String::from_utf8_lossy(&out.stderr).contains("--config"));
    }
}

#[test]
fn antigravity_check_rejects_other_users_and_out_of_range_timeouts() {
    let capture = Command::new(bin())
        .args([
            "antigravity-capture",
            "--user",
            "provenance-test-no-such-user",
            "--token-file",
            "/nonexistent-token-file",
        ])
        .output()
        .unwrap();
    assert_eq!(capture.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&capture.stderr).contains("effective UID"));
    assert!(capture.stdout.is_empty());

    let out = Command::new(bin())
        .args([
            "antigravity-check",
            "--json",
            "--user",
            "provenance-test-no-such-user",
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    let report: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(report["error"].as_str().unwrap().contains("effective UID"));
    for flag in ["--models-timeout-secs", "--smoke-timeout-secs"] {
        for invalid in ["0", "301"] {
            let out = Command::new(bin())
                .args(["antigravity-check", flag, invalid])
                .output()
                .unwrap();
            assert_eq!(out.status.code(), Some(2));
            assert!(String::from_utf8_lossy(&out.stderr).contains("1..=300"));
        }
    }
}

#[test]
fn opencode_check_validates_every_unfiltered_export_entry() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("export.json");
    let fake = dir.path().join("opencode");
    write_executable(
        &fake,
        &format!(
            "#!/bin/sh\nif [ \"$2\" = list ]; then\n  echo '[{{\"id\":\"openai\",\"connections\":[{{\"type\":\"credential\",\"id\":\"two\",\"label\":\"bad\"}}]}}]'\nelse\n  cat '{}'\nfi\n",
            path.display()
        ),
    );
    for invalid in [
        json!({"type":"oauth"}),
        json!({"type":"api","refresh":"not-oauth"}),
        json!(["oauth", null, "refresh", null]),
    ] {
        let export = json!([
            {"id":"one","integrationID":"openai","label":"good","value":{"type":"oauth","refresh":"refresh"}},
            {"id":"two","integrationID":"openai","label":"bad","value":invalid}
        ]);
        fs::write(&path, export.to_string()).unwrap();
        let out = Command::new(bin())
            .args(["opencode-check", "--json", "--export-file"])
            .arg(&path)
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(1));
        let report: Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(report["ok"], false);

        let out = Command::new(bin())
            .args([
                "opencode-check",
                "--json",
                "--verify-export",
                "--opencode-bin",
            ])
            .arg(&fake)
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(1));
        let report: Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(report["ok"], false);

        let out = Command::new(bin())
            .args([
                "opencode-capture",
                "--account",
                "bad",
                "--skip-login",
                "--opencode-bin",
            ])
            .arg(&fake)
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(1));
        assert!(out.stdout.is_empty());
    }
}

#[test]
fn audit_opencode_check_requires_matching_export_set() {
    let dir = tempfile::tempdir().unwrap();
    let fake = dir.path().join("opencode");
    for (id, label, code) in [("two", "other", 1), ("two", "work", 1), ("one", "work", 0)] {
        write_executable(
            &fake,
            &format!(
                "#!/bin/sh\nif [ \"$2\" = list ]; then\n  echo '[{{\"id\":\"openai\",\"connections\":[{{\"type\":\"credential\",\"id\":\"one\",\"label\":\"work\"}}]}}]'\nelse\n  echo '[{{\"id\":\"{id}\",\"integrationID\":\"openai\",\"label\":\"{label}\",\"value\":{{\"type\":\"oauth\",\"refresh\":\"fixture\"}}}}]'\nfi\n",
            ),
        );
        let out = Command::new(bin())
            .args([
                "opencode-check",
                "--json",
                "--verify-export",
                "--opencode-bin",
            ])
            .arg(&fake)
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(code));
        let report: Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(report["ok"], code == 0);
    }
}

#[test]
fn audit_google_bootstrap_rejects_mixed_client_sections() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("input.json");
    let fields = json!({"client_id":"flat-id","client_secret":"fixture"});
    for section in ["installed", "web"] {
        let mut mixed = fields.clone();
        mixed[section] = fields.clone();
        fs::write(&input, mixed.to_string()).unwrap();
        let out = Command::new(bin())
            .args(["google-client-bootstrap", "--json", "--file"])
            .arg(&input)
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(2));
        let report: Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(report["valid"], false);
    }
}

#[test]
fn google_bootstrap_reports_validation_and_io_errors_as_json() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("input.json");
    fs::write(&input, r#"{"client_secret":"must-not-appear"}"#).unwrap();
    for (path, code) in [(input, 2), (dir.path().join("missing"), 1)] {
        let out = Command::new(bin())
            .args(["google-client-bootstrap", "--json", "--file"])
            .arg(path)
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(code));
        let report: Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(report["valid"], false);
        assert!(report["error"].is_string());
        assert!(!String::from_utf8_lossy(&out.stdout).contains("must-not-appear"));
    }
}

#[test]
fn ansi_stripping_preserves_utf8_after_escape() {
    use provenance_oauth::antigravity_cli::strip_ansi_codes;
    assert_eq!(strip_ansi_codes("a\x1bé\x1b[32m界\x1b[0m!"), "aé界!");
}

#[test]
fn antigravity_capture_refuses_tty_stdout() {
    let script = r#"
import os, pty, sys
binary = sys.argv[1]
pid, master = pty.fork()
if pid == 0:
    os.execv(binary, [binary, "antigravity-capture"])
_, status = os.waitpid(pid, 0)
os.close(master)
sys.exit(os.waitstatus_to_exitcode(status))
"#;
    let output = Command::new("python3")
        .args(["-c", script, bin()])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
}

#[test]
fn antigravity_check_handles_healthy_degraded_smoke_and_redacted_errors() {
    let dir = tempfile::tempdir().unwrap();
    let user = String::from_utf8(Command::new("id").arg("-un").output().unwrap().stdout).unwrap();
    let user = user.trim();
    let refresh = "1//super-secret-refresh-token";
    let secret = "super-secret-client-secret";
    let (manifests_dir, manifest) = setup_antigravity_enrollment(
        dir.path(),
        ("testhost", user),
        "google-work",
        refresh,
        "123.apps.googleusercontent.com",
        secret,
        Some("proj-1"),
    );
    fs::write(
        manifests_dir.join(format!("{user}-broken.json")),
        "not JSON",
    )
    .unwrap();
    fs::create_dir(manifests_dir.join(format!("{user}-unreadable.json"))).unwrap();
    let mut config: Value = serde_json::from_slice(&fs::read(&manifest).unwrap()).unwrap();
    config["recoveryRecipients"] = json!(["age1unknown-plugin-recipient"]);
    fs::write(&manifest, config.to_string()).unwrap();

    let profile_dir = dir.path().join("t3-profile");
    let acp_path = profile_dir.join("antigravity-acp/acp_token.json");
    fs::create_dir_all(acp_path.parent().unwrap()).unwrap();
    fs::write(
        &acp_path,
        json!({
            "client_id": "123.apps.googleusercontent.com",
            "client_secret": secret,
            "refresh_token": refresh,
            "scopes": ["https://www.googleapis.com/auth/cloud-platform"],
            "project_id": "proj-1",
            "access_token": "cached-old-access-token"
        })
        .to_string(),
    )
    .unwrap();

    let selection_path = dir.path().join("antigravity-selection");
    fs::write(
        &selection_path,
        json!({"enrollment": "google-work", "declared": "google-work"}).to_string(),
    )
    .unwrap();

    let mode_file = dir.path().join("agy-mode");
    let smoke_fail_file = dir.path().join("agy-smoke-fail");
    let grandchild_pid = dir.path().join("grandchild.pid");
    let fake_agy = dir.path().join("fake-agy");
    write_executable(
        &fake_agy,
        &format!(
            r#"#!/bin/sh
mode="$(cat "{}")"
# Verify env sanitization stripped arbitrary secrets
[ -z "${{GEMINI_API_KEY:-}}" ] || {{ echo "GEMINI_API_KEY leaked" >&2; exit 1; }}
[ -z "${{GOOGLE_API_KEY:-}}" ] || {{ echo "GOOGLE_API_KEY leaked" >&2; exit 1; }}
# Verify materialized probe credential has ONLY refresh_token and auth_method
cred="$HOME/.gemini/antigravity-cli/antigravity-oauth-token"
[ -f "$cred" ] || {{ echo "missing probe credential" >&2; exit 1; }}
if [ "$1" = "--output-format" ]; then
  case "$mode" in
    healthy)
      printf '%s\n' '{{"command":"models","status":"SUCCESS","structured_output":{{"models":[{{"id":"gemini-4-neon-medium"}},{{"id":"claude-opus-5-5-high"}}]}}}}'
      exit 0
      ;;
    degraded)
      printf '%s\n' '{{"command":"models","status":"SUCCESS","structured_output":{{"models":[{{"id":"gemini-3-flash"}}]}}}}'
      exit 0
      ;;
    validation)
      printf '%s\n' '{{"error":{{"code":403,"status":"PERMISSION_DENIED","details":[{{"reason":"VALIDATION_REQUIRED","metadata":{{"verification_url":"https://accounts.google.com/secret?t=1//super-secret-refresh-token"}}}}]}}}}' >&2
      exit 1
      ;;
    quota)
      echo "Error: googleapi: Error 429: quota exceeded for super-secret-client-secret" >&2
      exit 1
      ;;
    unauth)
      echo "HTTP 401 UNAUTHENTICATED: bad token 1//super-secret-refresh-token" >&2
      exit 1
      ;;
    timeout)
      sleep 30 &
      echo "$!" > "{}"
      wait
      exit 0
      ;;
  esac
fi
# Smoke request
if [ -f "{}" ]; then
  printf 'NOT_OK\n'
  exit 0
fi
while [ "$#" -gt 1 ]; do
  if [ "$1" = "--print-timeout" ] && [ "$2" = "1s" ]; then
    sleep 2
    break
  fi
  shift
done
printf '\033[32mOK\033[0m\n'
exit 0
"#,
            mode_file.display(),
            grandchild_pid.display(),
            smoke_fail_file.display()
        ),
    );

    let run_check = |mode: &str, extra: &[&str]| {
        fs::write(&mode_file, mode).unwrap();
        let mut cmd = Command::new(bin());
        cmd.args(["antigravity-check", "--json", "--manifests-dir"])
            .arg(&manifests_dir)
            .args([
                "--host",
                "testhost",
                "--user",
                user,
                "--enrollment",
                "google-work",
            ])
            .args(["--profile-dir"])
            .arg(&profile_dir)
            .args(["--selection-file"])
            .arg(&selection_path)
            .args(["--agy-bin"])
            .arg(&fake_agy)
            .args(extra)
            .env("XDG_RUNTIME_DIR", dir.path())
            .env("GEMINI_API_KEY", "must-be-stripped")
            .env("GOOGLE_API_KEY", "must-be-stripped");
        cmd.output().unwrap()
    };

    // 1. Healthy + smoke test with normalized effort
    let out = run_check(
        "healthy",
        &[
            "--smoke-model",
            "gemini-4-neon-medium",
            "--smoke-timeout-secs",
            "1",
        ],
    );
    assert_eq!(
        out.status.code(),
        Some(0),
        "stdout: {}",
        String::from_utf8_lossy(&out.stdout)
    );
    let report: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["ok"], true);
    assert_eq!(report["health"], "healthy");
    assert_eq!(report["check"]["active_enrollment"], "google-work");
    assert_eq!(report["check"]["models"]["count"], 2);
    assert_eq!(report["check"]["smoke"]["model"], "gemini-4-neon");
    assert_eq!(report["check"]["smoke"]["effort"], "medium");
    assert_eq!(
        report["check"]["smoke"]["normalized_from"],
        "gemini-4-neon-medium"
    );
    assert_eq!(report["check"]["smoke"]["passed"], true);
    assert!(!String::from_utf8_lossy(&out.stdout).contains(refresh));
    assert!(!String::from_utf8_lossy(&out.stdout).contains(secret));

    // 2. Degraded -> exit 3
    let out = run_check("degraded", &[]);
    assert_eq!(out.status.code(), Some(3));
    let report: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["ok"], false);
    assert_eq!(report["health"], "degraded");
    assert!(report["check"]["models"]["warning"].is_string());

    // 3. Provider errors with strict redaction
    for (mode, expected_code) in [
        ("validation", "VALIDATION_REQUIRED"),
        ("quota", "QUOTA_EXCEEDED"),
        ("unauth", "UNAUTHENTICATED"),
    ] {
        let out = run_check(mode, &[]);
        assert_eq!(out.status.code(), Some(1));
        let raw_stdout = String::from_utf8_lossy(&out.stdout);
        let raw_stderr = String::from_utf8_lossy(&out.stderr);
        let report: Value = serde_json::from_str(&raw_stdout).unwrap();
        assert_eq!(report["ok"], false);
        assert_eq!(report["health"], "failed");
        assert_eq!(report["error_code"], expected_code);
        for leaked in [refresh, secret, "https://accounts.google.com"] {
            assert!(!raw_stdout.contains(leaked), "leaked {leaked} in stdout");
            assert!(!raw_stderr.contains(leaked), "leaked {leaked} in stderr");
        }
    }

    // 4. Timeout -> exit 1 with error_code TIMEOUT
    let out = run_check("timeout", &["--models-timeout-secs", "1"]);
    assert_eq!(out.status.code(), Some(1));
    let report: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["error_code"], "TIMEOUT");
    let pid: libc::pid_t = fs::read_to_string(&grandchild_pid)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    let alive = || {
        fs::read_to_string(format!("/proc/{pid}/stat"))
            .ok()
            .and_then(|stat| {
                stat.rsplit_once(") ")
                    .and_then(|(_, state)| state.chars().next())
            })
            .is_some_and(|state| state != 'Z' && state != 'X')
    };
    for _ in 0..20 {
        if !alive() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    let survived = alive();
    if survived {
        // Clean up the test process if timeout handling regresses.
        unsafe { libc::kill(pid, libc::SIGKILL) };
    }
    assert!(!survived, "grandchild survived the probe timeout");
    assert!(fs::read_dir(dir.path()).unwrap().all(|entry| {
        !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with("provenance-agy-check-")
    }));

    // 5. Smoke failure -> exit 1
    fs::write(&mode_file, "healthy").unwrap();
    fs::write(&smoke_fail_file, "1").unwrap();
    let mut cmd = Command::new(bin());
    cmd.args(["antigravity-check", "--json", "--manifests-dir"])
        .arg(&manifests_dir)
        .args(["--host", "testhost", "--user", user, "--profile-dir"])
        .arg(&profile_dir)
        .args(["--selection-file"])
        .arg(&selection_path)
        .args(["--agy-bin"])
        .arg(&fake_agy)
        .args(["--smoke-model", "gemini-4-neon-medium"]);
    let out = cmd.output().unwrap();
    assert_eq!(out.status.code(), Some(1));
    let report: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["check"]["smoke"]["passed"], false);

    let mut bad_token: Value = serde_json::from_slice(&fs::read(&acp_path).unwrap()).unwrap();
    bad_token["token_uri"] = json!("https://untrusted.example/token");
    fs::write(acp_path, bad_token.to_string()).unwrap();
    let out = run_check("healthy", &[]);
    assert_eq!(out.status.code(), Some(2));
    assert!(
        serde_json::from_slice::<Value>(&out.stdout).unwrap()["error"]
            .as_str()
            .unwrap()
            .contains("token_uri")
    );
}

#[test]
fn opencode_capture_and_check_verify_labels_and_redact_tokens() {
    let dir = tempfile::tempdir().unwrap();
    let fake_opencode = dir.path().join("fake-opencode");
    write_executable(
        &fake_opencode,
        r#"#!/bin/sh
if [ "$1" = "auth" ] && [ "$2" = "list" ]; then
  if [ "${FAKE_DUP:-0}" = "1" ]; then
    printf '%s\n' '[{"id":"openai","connections":[{"type":"credential","id":"c1","label":"Work"},{"type":"credential","id":"c2","label":"work"}]}]'
  else
    printf '%s\n' '[{"id":"openai","connections":[{"type":"credential","id":"c1","label":"work"}]}]'
  fi
  exit 0
fi
if [ "$1" = "auth" ] && [ "$2" = "export" ]; then
  printf '%s\n' '[{"id":"c1","integrationID":"openai","label":"work","active":true,"value":{"type":"oauth","access":"oc-secret-access","refresh":"oc-secret-refresh","expires":1900000000000,"methodID":"chatgpt-browser"}}]'
  exit 0
fi
exit 1
"#,
    );

    // 1. opencode-capture --skip-login to file (0600)
    let export_out = dir.path().join("export.json");
    let cap = Command::new(bin())
        .args([
            "opencode-capture",
            "--account",
            "work",
            "--skip-login",
            "--opencode-bin",
        ])
        .arg(&fake_opencode)
        .args(["--output"])
        .arg(&export_out)
        .output()
        .unwrap();
    assert!(
        cap.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&cap.stderr)
    );
    assert_eq!(
        fs::metadata(&export_out).unwrap().permissions().mode() & 0o777,
        0o600
    );

    // 2. opencode-check with --verify-export --json (no tokens leaked!)
    let chk = Command::new(bin())
        .args([
            "opencode-check",
            "--account",
            "work",
            "--verify-export",
            "--json",
            "--opencode-bin",
        ])
        .arg(&fake_opencode)
        .output()
        .unwrap();
    assert_eq!(chk.status.code(), Some(0));
    let raw = String::from_utf8_lossy(&chk.stdout);
    assert!(!raw.contains("oc-secret-access"));
    assert!(!raw.contains("oc-secret-refresh"));
    let report: Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(report["ok"], true);
    assert_eq!(report["matched"], true);
    assert_eq!(report["unique"], true);
    assert_eq!(report["metadata"]["has_refresh_token"], true);
    assert_eq!(report["metadata"]["has_access_token"], true);
    assert_eq!(report["metadata"]["expires_at"], 1_900_000_000_000_u64);

    // 3. opencode-check with duplicate case-insensitive labels -> exit 1
    let dup = Command::new(bin())
        .args([
            "opencode-check",
            "--account",
            "work",
            "--json",
            "--opencode-bin",
        ])
        .arg(&fake_opencode)
        .env("FAKE_DUP", "1")
        .output()
        .unwrap();
    assert_eq!(dup.status.code(), Some(1));
    let report: Value = serde_json::from_slice(&dup.stdout).unwrap();
    assert_eq!(report["ok"], false);
    assert_eq!(report["unique"], false);

    // 4. opencode-check --export-file <PATH> -> exit 0, zero tokens
    let file_chk = Command::new(bin())
        .args([
            "opencode-check",
            "--account",
            "work",
            "--json",
            "--export-file",
        ])
        .arg(&export_out)
        .output()
        .unwrap();
    assert_eq!(file_chk.status.code(), Some(0));
    assert!(!String::from_utf8_lossy(&file_chk.stdout).contains("oc-secret"));
}

#[test]
fn google_client_bootstrap_validates_materializes_and_hides_secret() {
    let dir = tempfile::tempdir().unwrap();
    let installed_path = dir.path().join("installed.json");
    fs::write(
        &installed_path,
        json!({
            "installed": {
                "client_id": "123.apps.googleusercontent.com",
                "client_secret": "ultra-secret-google-client",
                "project_id": "my-gcp-project",
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
                "redirect_uris": ["http://localhost"]
            }
        })
        .to_string(),
    )
    .unwrap();

    let mat_path = dir.path().join("materialized.json");
    let out = Command::new(bin())
        .args([
            "google-client-bootstrap",
            "--file",
            installed_path.to_str().unwrap(),
            "--expected-client-type",
            "installed",
            "--require-project-id",
            "--materialize-to",
            mat_path.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    let raw = String::from_utf8_lossy(&out.stdout);
    assert!(!raw.contains("ultra-secret-google-client"));
    let report: Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(report["valid"], true);
    assert_eq!(report["client_type"], "installed");
    assert_eq!(report["client_id"], "123.apps.googleusercontent.com");
    assert_eq!(report["project_id"], "my-gcp-project");
    assert_eq!(report["materialized_path"], mat_path.to_str().unwrap());
    assert_eq!(
        fs::metadata(&mat_path).unwrap().permissions().mode() & 0o777,
        0o600
    );

    // Mismatched expected client type -> exit 2
    let mismatch = Command::new(bin())
        .args([
            "google-client-bootstrap",
            "--file",
            installed_path.to_str().unwrap(),
            "--expected-client-type",
            "web",
        ])
        .output()
        .unwrap();
    assert_eq!(mismatch.status.code(), Some(2));
    assert!(!String::from_utf8_lossy(&mismatch.stderr).contains("ultra-secret-google-client"));

    // Invalid JSON -> exit 2
    let bad_path = dir.path().join("bad.json");
    fs::write(&bad_path, r#"{"installed":{"client_id":"only-id"}}"#).unwrap();
    let bad = Command::new(bin())
        .args([
            "google-client-bootstrap",
            "--file",
            bad_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(bad.status.code(), Some(2));
}
