use provenance_oauth::{Config, Enrollment, Target, state::atomic_write};
use serde_json::json;
use std::{
    fs,
    path::Path,
    process::{Command, Output},
};

#[test]
fn target_pairs_and_old_openai_document() {
    let old = r#"{"version":1,"target":{"host":"atlas","user":"root","provider":"openai","profile":"chatgpt","account":"default"},"generation":1,"grant":{"accessToken":"a","refreshToken":"r","expiresAt":123,"accountId":"id"}}"#;
    let enrollment: Enrollment = serde_json::from_str(old).unwrap();
    enrollment.validate(&enrollment.target).unwrap();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(old).unwrap(),
        serde_json::to_value(&enrollment).unwrap()
    );
    let mut target: Target = enrollment.target;
    target.provider = "google".into();
    assert!(target.validate().is_err());
    target.profile = "drive-file".into();
    assert!(target.validate().is_ok());
    target.profile = "antigravity".into();
    assert!(target.validate().is_ok());
    target.provider = "openai".into();
    assert!(target.validate().is_err());
}

#[test]
fn google_client_credentials_reject_ini_metacharacters() {
    let mut enrollment: Enrollment = serde_json::from_str(r#"{"version":1,"target":{"host":"atlas","user":"root","provider":"google","profile":"drive-file","account":"default"},"generation":1,"grant":{"accessToken":"a","refreshToken":"r","expiresAt":123,"accountId":"id","client":{"clientId":"123-abc.apps.googleusercontent.com","clientSecret":"GOCSPX-secret"}}}"#).unwrap();
    assert!(enrollment.validate(&enrollment.target).is_ok());
    for bad in ["%(type)s", "\"quoted\"", "", &"a".repeat(257)] {
        let client = enrollment.grant.client.as_mut().unwrap();
        client.client_id = bad.into();
        assert!(enrollment.validate(&enrollment.target).is_err());
        let client = enrollment.grant.client.as_mut().unwrap();
        client.client_id = "valid".into();
        client.client_secret.0 = bad.into();
        assert!(enrollment.validate(&enrollment.target).is_err());
        enrollment.grant.client.as_mut().unwrap().client_secret.0 = "valid".into();
    }
}

fn manifest(directory: &Path, provider: &str, profile: &str) -> Config {
    let config = Config {
        version: 1,
        target: Target {
            host: fs::read_to_string("/proc/sys/kernel/hostname")
                .unwrap()
                .trim()
                .into(),
            user: String::from_utf8(Command::new("id").arg("-un").output().unwrap().stdout)
                .unwrap()
                .trim()
                .into(),
            provider: provider.into(),
            profile: profile.into(),
            account: "default".into(),
        },
        state_directory: directory.join("state"),
        recovery_recipients: vec![age::x25519::Identity::generate().to_public().to_string()],
    };
    atomic_write(
        &directory.join("config.json"),
        &serde_json::to_vec(&config).unwrap(),
    )
    .unwrap();
    config
}

fn run(directory: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_provenance-oauth"))
        .arg("--config")
        .arg(directory.join("config.json"))
        .args(args)
        .output()
        .unwrap()
}

fn refuses(output: Output, reason: &str) {
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let error = String::from_utf8(output.stderr).unwrap();
    assert!(error.contains(reason), "{error}");
}

#[test]
fn agy_token_flags_and_export_are_profile_specific() {
    for (provider, profile, flag) in [
        ("google", "drive-file", "--token-file"),
        ("openai", "chatgpt", "--token-file"),
        ("google", "antigravity", "--client-file"),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let config = manifest(dir.path(), provider, profile);
        let pending = dir.path().join("pending");
        let host = &config.target.host;
        let user = &config.target.user;
        refuses(
            run(
                dir.path(),
                &[
                    "authorize",
                    host,
                    provider,
                    "--user",
                    user,
                    "--profile",
                    profile,
                    "--secret",
                    "fixture.age",
                    "--pending-directory",
                    pending.to_str().unwrap(),
                    flag,
                    "never-read.json",
                ],
            ),
            &format!("{flag} is rejected"),
        );
        assert!(!pending.exists());
        if profile != "antigravity" {
            refuses(
                run(dir.path(), &["agy-token"]),
                "requires google/antigravity",
            );
        }
    }
}

#[test]
fn agy_token_exports_only_the_enrolled_refresh_grant() {
    let dir = tempfile::tempdir().unwrap();
    let config = manifest(dir.path(), "google", "antigravity");
    let file = dir.path().join("enrollment.json");
    let scopes = [
        "https://www.googleapis.com/auth/cloud-platform",
        "https://www.googleapis.com/auth/userinfo.email",
        "https://www.googleapis.com/auth/aicode",
    ];
    let enrollment = json!({
        "version": 1, "target": config.target, "generation": 1,
        "grant": {
            "refreshToken": "1//fixture-refresh", "accountId": "1234",
            "client": {"clientId": "123.apps.googleusercontent.com", "clientSecret": "fixture-secret"},
            "projectId": "fixture-project", "scopes": scopes
        }
    });
    atomic_write(&file, &serde_json::to_vec(&enrollment).unwrap()).unwrap();
    let path = file.to_str().unwrap();
    let applied = run(dir.path(), &["apply", "--initialize", "--enrollment", path]);
    assert!(
        applied.status.success(),
        "{}",
        String::from_utf8_lossy(&applied.stderr)
    );
    assert!(
        serde_json::from_slice::<serde_json::Value>(&applied.stdout).unwrap()["expiresAt"]
            .is_null()
    );
    let exported = run(dir.path(), &["agy-token"]);
    assert!(
        exported.status.success(),
        "{}",
        String::from_utf8_lossy(&exported.stderr)
    );
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&exported.stdout).unwrap(),
        json!({
            "client_id": "123.apps.googleusercontent.com", "client_secret": "fixture-secret",
            "project_id": "fixture-project", "refresh_token": "1//fixture-refresh", "scopes": scopes,
            "token_uri": "https://oauth2.googleapis.com/token"
        })
    );
    refuses(
        run(dir.path(), &["rclone-config", "--remote", "gdrive"]),
        "requires google/drive-file",
    );
    refuses(run(dir.path(), &["access"]), "refreshed by agy");
    let state_file = config.state_directory.join("state.json");
    let mut state: serde_json::Value =
        serde_json::from_slice(&fs::read(&state_file).unwrap()).unwrap();
    state["refreshPending"] = json!(true);
    atomic_write(&state_file, &serde_json::to_vec(&state).unwrap()).unwrap();
    refuses(
        run(dir.path(), &["agy-token"]),
        "refresh outcome is uncertain",
    );
    assert!(run(dir.path(), &["remove"]).status.success());
    refuses(
        run(dir.path(), &["agy-token"]),
        "enrollment has been removed",
    );
}
