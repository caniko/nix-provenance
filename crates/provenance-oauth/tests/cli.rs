use provenance_oauth::{Config, Enrollment, Grant, Secret, Target, state::atomic_write};
use std::{fs, os::unix::fs::PermissionsExt, process::Command};

#[test]
fn agenix_handoff_is_resumable_and_contains_only_paths_in_argv() {
    let dir = tempfile::tempdir().unwrap();
    let pending = dir.path().join("pending");
    fs::create_dir(&pending).unwrap();
    fs::set_permissions(&pending, fs::Permissions::from_mode(0o700)).unwrap();
    let target = Target {
        host: "target-host".into(),
        user: "target-user".into(),
        provider: "openai".into(),
        profile: "chatgpt".into(),
        account: "default".into(),
    };
    let config = Config {
        version: 1,
        target: target.clone(),
        state_directory: dir.path().join("unused-host-state"),
        recovery_recipients: vec![age::x25519::Identity::generate().to_public().to_string()],
    };
    let config_file = dir.path().join("config.json");
    atomic_write(&config_file, &serde_json::to_vec(&config).unwrap()).unwrap();
    let config_link = dir.path().join("manifest.json");
    std::os::unix::fs::symlink(config_file, &config_link).unwrap();
    let debug = Command::new(env!("CARGO_BIN_EXE_provenance-oauth"))
        .arg("--config")
        .arg(&config_link)
        .arg("status")
        .env("AGEDEBUG", "plugin")
        .output()
        .unwrap();
    assert!(String::from_utf8_lossy(&debug.stderr).contains("AGEDEBUG=plugin is not supported"));
    let enrollment = Enrollment {
        version: 1,
        target,
        generation: 100,
        grant: Grant {
            access_token: Secret("private-access-fixture".into()),
            refresh_token: Secret("private-refresh-fixture".into()),
            expires_at: 1000,
            account_id: "account".into(),
        },
    };
    atomic_write(
        &pending.join("enrollment.json"),
        &serde_json::to_vec(&enrollment).unwrap(),
    )
    .unwrap();
    let secret = dir.path().join("enrollment.age");
    let original =
        provenance_oauth::age_file::encrypt(b"previous fixture", &config.recovery_recipients)
            .unwrap();
    fs::write(&secret, &original).unwrap();
    let encrypted = provenance_oauth::age_file::encrypt(
        &serde_json::to_vec(&enrollment).unwrap(),
        &config.recovery_recipients,
    )
    .unwrap();
    let encrypted_fixture = dir.path().join("encrypted-fixture.age");
    fs::write(&encrypted_fixture, &encrypted).unwrap();
    let agenix = dir.path().join("agenix-fixture");
    // Match agenix-rekey's actual --input contract, including refusing overwrite.
    fs::write(&agenix, "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$CAPTURE\"\n[ \"$EXIT\" = 0 ] || exit \"$EXIT\"\n[ ! -e \"$4\" ] || exit 2\ncp \"$ENCRYPTED_FIXTURE\" \"$4\"\n").unwrap();
    fs::set_permissions(&agenix, fs::Permissions::from_mode(0o700)).unwrap();
    let capture = dir.path().join("argv");
    let command = |exit: &str| {
        Command::new(env!("CARGO_BIN_EXE_provenance-oauth"))
            .args(["--config"])
            .arg(&config_link)
            .args([
                "authorize",
                "target-host",
                "openai",
                "--user",
                "target-user",
                "--secret",
            ])
            .arg(&secret)
            .arg("--pending-directory")
            .arg(&pending)
            .arg("--agenix")
            .arg(&agenix)
            .env("CAPTURE", &capture)
            .env("EXIT", exit)
            .env("ENCRYPTED_FIXTURE", &encrypted_fixture)
            .output()
            .unwrap()
    };
    let failed = command("1");
    assert!(!failed.status.success());
    assert!(
        String::from_utf8_lossy(&failed.stderr)
            .contains("retry authorize with the same pending directory"),
        "{}",
        String::from_utf8_lossy(&failed.stderr)
    );
    assert_eq!(
        fs::read(&secret).unwrap(),
        original,
        "failed encryption preserves the existing source"
    );
    let resumed = command("0");
    assert!(
        resumed.status.success(),
        "{}",
        String::from_utf8_lossy(&resumed.stderr)
    );
    let status: serde_json::Value = serde_json::from_slice(&resumed.stdout).unwrap();
    assert_eq!(status["stage"], "encrypted");
    assert_eq!(status["generation"], 100);
    assert_eq!(fs::read(&secret).unwrap(), encrypted);
    assert!(
        command("0").status.success(),
        "retry after successful encryption also works"
    );
    let args = fs::read_to_string(&capture).unwrap();
    assert!(args.starts_with("edit\n-i\n"));
    assert!(args.contains("pending/enrollment.json\n"));
    for output in [
        args.as_str(),
        &String::from_utf8_lossy(&resumed.stdout),
        &String::from_utf8_lossy(&resumed.stderr),
    ] {
        assert!(!output.contains("private-access-fixture"));
        assert!(!output.contains("private-refresh-fixture"));
    }
    assert!(
        !config.state_directory.exists(),
        "authorizing another host must not create local live state"
    );

    let finalize = |generation: &str| {
        Command::new(env!("CARGO_BIN_EXE_provenance-oauth"))
            .arg("--config")
            .arg(&config_link)
            .arg("finalize")
            .arg("--pending-directory")
            .arg(&pending)
            .arg("--generation")
            .arg(generation)
            .output()
            .unwrap()
    };
    assert!(
        !finalize("99").status.success(),
        "must not discard another generation"
    );
    let finished = finalize("100");
    assert!(
        finished.status.success(),
        "{}",
        String::from_utf8_lossy(&finished.stderr)
    );
    assert!(
        !pending.join("enrollment.json").exists(),
        "successful apply can discard operator-side plaintext"
    );
    assert!(
        finalize("100").status.success(),
        "finalization is idempotent"
    );
    let repeated = command("1");
    assert!(
        repeated.status.success(),
        "finalized retry must not invoke agenix or authorize again"
    );
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&repeated.stdout).unwrap()["stage"],
        "finalized"
    );
}
