use provenance_oauth::{Config, Enrollment, Grant, Secret, Target, state::atomic_write};
use std::{fs, os::unix::fs::PermissionsExt, process::Command};

#[test]
fn authorize_checks_client_file_for_provider_before_resuming() {
    let dir = tempfile::tempdir().unwrap();
    for (provider, profile, flag) in [("google", "drive-file", false), ("openai", "chatgpt", true)]
    {
        let config = Config {
            version: 1,
            target: Target {
                host: "host".into(),
                user: "user".into(),
                provider: provider.into(),
                profile: profile.into(),
                account: "default".into(),
                enrollment: None,
            },
            state_directory: dir.path().join("state"),
            recovery_recipients: vec![age::x25519::Identity::generate().to_public().to_string()],
        };
        let path = dir.path().join("config.json");
        atomic_write(&path, &serde_json::to_vec(&config).unwrap()).unwrap();
        let mut command = Command::new(env!("CARGO_BIN_EXE_provenance-oauth"));
        command.arg("--config").arg(&path).args([
            "authorize",
            "host",
            provider,
            "--user",
            "user",
            "--profile",
            profile,
            "--secret",
            "secret",
            "--pending-directory",
            "pending",
        ]);
        if flag {
            command.args(["--client-file", "client.json"]);
        }
        let output = command.output().unwrap();
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("--client-file"));
    }
}

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
        enrollment: None,
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
            client: None,
            project_id: None,
            scopes: None,
            opencode: None,
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
    fs::write(&agenix, "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$CAPTURE\"\nif [ \"$1\" = rekey ]; then exit \"$REKEY_EXIT\"; fi\n[ \"$EXIT\" = 0 ] || exit \"$EXIT\"\n[ ! -e \"$4\" ] || exit 2\ncp \"$ENCRYPTED_FIXTURE\" \"$4\"\n").unwrap();
    fs::set_permissions(&agenix, fs::Permissions::from_mode(0o700)).unwrap();
    let capture = dir.path().join("argv");
    let command = |exit: &str, rekey_exit: Option<&str>| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_provenance-oauth"));
        command
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
            .env("ENCRYPTED_FIXTURE", &encrypted_fixture);
        if let Some(exit) = rekey_exit {
            command.arg("--rekey").env("REKEY_EXIT", exit);
        }
        command.output().unwrap()
    };
    let failed = command("1", None);
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
    let resumed = command("0", None);
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
        command("0", None).status.success(),
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

    // Rekey is a separate failure boundary. Its failure must retain the grant,
    // and repeating authorize must never contact the provider for another one.
    let pending_before = fs::read(pending.join("enrollment.json")).unwrap();
    assert!(!command("0", Some("1")).status.success());
    assert_eq!(
        fs::read(pending.join("enrollment.json")).unwrap(),
        pending_before
    );
    let rekeyed = command("0", Some("0"));
    assert!(rekeyed.status.success());
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&rekeyed.stdout).unwrap()["stage"],
        "rekeyed"
    );
    assert_eq!(
        fs::read(pending.join("enrollment.json")).unwrap(),
        pending_before
    );
    // The same importer supports first enrollment without an existing source.
    fs::remove_file(&secret).unwrap();
    assert!(command("0", None).status.success());
    assert_eq!(fs::read(&secret).unwrap(), encrypted);

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
    let repeated = command("1", None);
    assert!(
        repeated.status.success(),
        "finalized retry must not invoke agenix or authorize again"
    );
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&repeated.stdout).unwrap()["stage"],
        "finalized"
    );
}

#[test]
fn expired_google_export_and_removal_do_not_refresh() {
    let dir = tempfile::tempdir().unwrap();
    let target = Target {
        host: fs::read_to_string("/proc/sys/kernel/hostname")
            .unwrap()
            .trim()
            .into(),
        user: String::from_utf8(Command::new("id").arg("-un").output().unwrap().stdout)
            .unwrap()
            .trim()
            .into(),
        provider: "google".into(),
        profile: "drive-file".into(),
        account: "default".into(),
        enrollment: None,
    };
    let config = Config {
        version: 1,
        target: target.clone(),
        state_directory: dir.path().join("state"),
        recovery_recipients: vec![age::x25519::Identity::generate().to_public().to_string()],
    };
    let enrollment = Enrollment {
        version: 1,
        target,
        generation: 1,
        grant: Grant {
            access_token: Secret("expired".into()),
            refresh_token: Secret("refresh".into()),
            expires_at: 1,
            account_id: "id".into(),
            client: Some(provenance_oauth::OAuthClient {
                client_id: "client".into(),
                client_secret: Secret("secret".into()),
            }),
            project_id: None,
            scopes: None,
            opencode: None,
        },
    };
    let config_file = dir.path().join("config.json");
    let enrollment_file = dir.path().join("enrollment.json");
    atomic_write(&config_file, &serde_json::to_vec(&config).unwrap()).unwrap();
    atomic_write(&enrollment_file, &serde_json::to_vec(&enrollment).unwrap()).unwrap();
    let run = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_provenance-oauth"))
            .arg("--config")
            .arg(&config_file)
            .args(args)
            .output()
            .unwrap()
    };
    let path = enrollment_file.to_str().unwrap();
    assert!(
        run(&["apply", "--enrollment", path, "--initialize"])
            .status
            .success()
    );
    let before = fs::read(config.state_directory.join("state.json")).unwrap();
    {
        let store = provenance_oauth::state::Store::lock(&config).unwrap();
        assert!(
            store
                .access(
                    || panic!("clock must not run"),
                    |_| panic!("must not refresh")
                )
                .is_err()
        );
    }
    assert_eq!(
        before,
        fs::read(config.state_directory.join("state.json")).unwrap()
    );
    let exported = run(&["rclone-config", "--remote", "gdrive"]);
    assert!(
        exported.status.success(),
        "{}",
        String::from_utf8_lossy(&exported.stderr)
    );
    assert!(String::from_utf8_lossy(&exported.stdout).contains("[gdrive]"));
    assert_eq!(
        before,
        fs::read(config.state_directory.join("state.json")).unwrap()
    );
    let access = run(&["access"]);
    assert!(!access.status.success());
    assert!(String::from_utf8_lossy(&access.stderr).contains("refreshed by their rclone consumer"));
    assert_eq!(
        before,
        fs::read(config.state_directory.join("state.json")).unwrap()
    );
    assert!(run(&["remove"]).status.success());
    let _ = run(&["apply", "--enrollment", path]);
    let removed = run(&["rclone-config", "--remote", "gdrive"]);
    assert!(!removed.status.success());
    assert!(removed.stdout.is_empty());
}

#[test]
fn real_access_cli_reuses_unexpired_test_grant_without_refresh_material() {
    let dir = tempfile::tempdir().unwrap();
    let user = Command::new("id").arg("-un").output().unwrap();
    assert!(user.status.success());
    let config = Config {
        version: 1,
        target: Target {
            host: fs::read_to_string("/proc/sys/kernel/hostname")
                .unwrap()
                .trim()
                .into(),
            user: String::from_utf8(user.stdout).unwrap().trim().into(),
            provider: "openai".into(),
            profile: "chatgpt".into(),
            account: "default".into(),
            enrollment: None,
        },
        state_directory: dir.path().join("isolated-state"),
        recovery_recipients: vec![age::x25519::Identity::generate().to_public().to_string()],
    };
    let config_file = dir.path().join("manifest.json");
    atomic_write(&config_file, &serde_json::to_vec(&config).unwrap()).unwrap();
    let enrollment = Enrollment {
        version: 1,
        target: config.target.clone(),
        generation: 100,
        grant: Grant {
            access_token: Secret("test-only-cli-access".into()),
            refresh_token: Secret("test-only-cli-refresh".into()),
            expires_at: provenance_oauth::now().unwrap() + 3_600_000,
            account_id: "fixture-account".into(),
            client: None,
            project_id: None,
            scopes: None,
            opencode: None,
        },
    };
    provenance_oauth::state::Store::lock(&config)
        .unwrap()
        .apply(&enrollment, true)
        .unwrap();
    for raw in [false, false, true] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_provenance-oauth"));
        command.arg("--config").arg(&config_file).arg("access");
        if raw {
            command.arg("--raw");
        }
        let output = command.output().unwrap();
        assert!(output.status.success());
        let access = String::from_utf8(output.stdout).unwrap();
        assert!(!access.contains("test-only-cli-refresh"));
        if raw {
            assert_eq!(access.trim(), "test-only-cli-access");
        } else {
            let value: serde_json::Value = serde_json::from_str(&access).unwrap();
            assert_eq!(value["accessToken"], "test-only-cli-access");
            assert_eq!(value["accountId"], "fixture-account");
            assert!(value.get("refreshToken").is_none());
        }
    }
    let status = provenance_oauth::state::Store::lock(&config)
        .unwrap()
        .status()
        .unwrap();
    assert_eq!(status["generation"], 100);
    assert_eq!(status["revision"], 0);
    assert!(config.state_directory.join("checkpoint.age").is_file());
}
