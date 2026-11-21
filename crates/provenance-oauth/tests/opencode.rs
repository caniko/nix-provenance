use provenance_oauth::{Config, state::atomic_write};
use serde_json::{Value, json};
use std::{
    fs,
    io::{Read, Write},
    os::unix::fs::PermissionsExt,
    process::{Command, Stdio},
};

#[test]
fn backs_up_and_restores_only_the_named_opencode_credential() {
    let dir = tempfile::tempdir().unwrap();
    let dir = dir.path();
    let identity = age::x25519::Identity::generate();
    let manifest = dir.join("manifest.json");
    let config: Config = serde_json::from_value(json!({
        "version": 1,
        "target": {
            "host": fs::read_to_string("/proc/sys/kernel/hostname").unwrap().trim(),
            "user": String::from_utf8(Command::new("id").arg("-un").output().unwrap().stdout).unwrap().trim(),
            "provider": "openai", "profile": "opencode", "account": "Work Account",
            "enrollment": "work"
        },
        "stateDirectory": dir.join("state"),
        "recoveryRecipients":[identity.to_public().to_string()]
    })).unwrap();
    atomic_write(&manifest, &serde_json::to_vec(&config).unwrap()).unwrap();
    let native = dir.join("opencode");
    fs::write(
        &native,
        r#"#!/bin/sh
set -eu
[ "$1" = auth ]
case "$2" in
export) [ "$#" = 3 ] && [ "$3" = openai ]; cat db.json ;;
import) [ "$#" = 2 ]; cat > db.json; echo 'sidecar-output-must-be-hidden' ;;
switch) [ "$#" = 5 ] && [ "$3" = openai ] && [ "$4" = -- ] && [ "$5" = cred_work ]; touch switched ;;
*) exit 90 ;;
esac
"#,
    )
    .unwrap();
    fs::set_permissions(&native, fs::Permissions::from_mode(0o700)).unwrap();
    let fake_agenix = dir.join("agenix");
    fs::write(
        &fake_agenix,
        "#!/bin/sh\n[ \"$#\" = 4 ] && cp test.age \"$4\"\n",
    )
    .unwrap();
    fs::set_permissions(&fake_agenix, fs::Permissions::from_mode(0o700)).unwrap();
    let ciphertext =
        provenance_oauth::age_file::encrypt(b"fixture", &config.recovery_recipients).unwrap();
    fs::write(dir.join("test.age"), ciphertext).unwrap();

    let credential = |refresh: &str, expires: u64| {
        json!({
            "id":"cred_work", "integrationID":"openai", "label":"Work Account", "active":true,
            "value":{"type":"oauth","methodID":"chatgpt","access":"fake-access","refresh":refresh,
                     "expires":expires,"metadata":{"accountId":"my-account"}}
        })
    };
    let run = || {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_provenance-oauth"));
        cmd.current_dir(dir).args(["--config", "manifest.json"]);
        cmd
    };
    let pending = dir.join("pending");
    let authorize = |token_file: &str| {
        let mut cmd = run();
        cmd.args([
            "authorize",
            &config.target.host,
            "openai",
            "--user",
            &config.target.user,
            "--profile",
            "opencode",
            "--account",
            "Work Account",
            "--token-file",
            token_file,
            "--secret",
            dir.join("enrollment.age").to_str().unwrap(),
            "--agenix",
            "./agenix",
            "--pending-directory",
        ])
        .arg(&pending);
        cmd
    };
    let mut input = authorize("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    serde_json::to_writer(
        input.stdin.take().unwrap(),
        &json!([
            {"id":"cred_unrelated","integrationID":"other","label":"Work Account","active":true,
             "value":{"type":"key","key":"unrelated-provider-secret"}},
            credential("initial-refresh", 200)
        ]),
    )
    .unwrap();
    let result = input.wait_with_output().unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let enrollment = pending.join("enrollment.json");
    let enrolled = fs::read_to_string(&enrollment).unwrap();
    assert!(!enrolled.contains("unrelated-provider-secret"));
    assert!(enrolled.contains("initial-refresh"));
    let file_input = authorize("export.json").output().unwrap();
    assert!(!file_input.status.success());
    assert!(String::from_utf8_lossy(&file_input.stderr).contains("--token-file -"));
    assert!(
        run()
            .args(["apply", "--initialize", "--enrollment"])
            .arg(enrollment)
            .output()
            .unwrap()
            .status
            .success()
    );

    let native_action = |action: &str, args: &[&str]| {
        let output = run()
            .arg(action)
            .arg("--opencode")
            .arg(&native)
            .args(args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.stdout.is_empty());
        assert!(output.stderr.is_empty());
    };
    let db = dir.join("db.json");
    let state = config.state_directory.join("state.json");
    let checkpoint_path = config.state_directory.join("checkpoint.age");
    assert!(!run().arg("access").output().unwrap().status.success());

    // Simulate a checkpoint publication failure after the rotated state is saved.
    let stale_checkpoint = fs::read(&checkpoint_path).unwrap();
    fs::remove_file(&checkpoint_path).unwrap();
    fs::create_dir(&checkpoint_path).unwrap();
    atomic_write(
        &db,
        &serde_json::to_vec(&[credential("rotated-refresh", 200)]).unwrap(),
    )
    .unwrap();
    assert!(
        !run()
            .args(["opencode-sync", "--opencode"])
            .arg(&native)
            .output()
            .unwrap()
            .status
            .success()
    );
    assert!(
        fs::read_to_string(&state)
            .unwrap()
            .contains("rotated-refresh")
    );
    fs::remove_dir(&checkpoint_path).unwrap();
    atomic_write(&checkpoint_path, &stale_checkpoint).unwrap();
    atomic_write(&db, b"[]").unwrap();
    native_action("opencode-sync", &[]);
    let rotate_backup = fs::read(&checkpoint_path).unwrap();
    let mut decrypt = age::Decryptor::new(&rotate_backup[..])
        .unwrap()
        .decrypt(std::iter::once(&identity as &dyn age::Identity))
        .unwrap();
    let mut bytes = Vec::new();
    decrypt.read_to_end(&mut bytes).unwrap();
    let checkpoint: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(checkpoint["revision"], 1);
    assert_eq!(checkpoint["grant"]["refreshToken"], "rotated-refresh");

    atomic_write(
        &db,
        &serde_json::to_vec(&[credential("older-refresh", 150)]).unwrap(),
    )
    .unwrap();
    native_action("opencode-sync", &[]);
    assert!(
        fs::read_to_string(&state)
            .unwrap()
            .contains("rotated-refresh")
    );

    // The existing DB label remains untouched even if state has a newer backup.
    let before = fs::read(&db).unwrap();
    native_action("opencode-install", &[]);
    assert_eq!(fs::read(&db).unwrap(), before);
    assert!(!dir.join("switched").exists());
    let mut duplicate = credential("must-not-leak", 300);
    duplicate["id"] = "another-credential".into();
    let reassigned = serde_json::to_vec(&[&duplicate]).unwrap();
    atomic_write(&db, &reassigned).unwrap();
    let previous_state = fs::read(&state).unwrap();
    let previous_checkpoint = fs::read(&checkpoint_path).unwrap();
    for (action, args) in [
        ("opencode-install", &["--activate"][..]),
        ("opencode-sync", &[][..]),
    ] {
        let output = run()
            .args([action, "--opencode"])
            .arg(&native)
            .args(args)
            .output()
            .unwrap();
        assert!(!output.status.success(), "{action} accepted a different ID");
        let error = String::from_utf8_lossy(&output.stderr);
        assert!(error.contains("re-enroll"));
        assert!(!error.contains("must-not-leak"));
        assert_eq!(fs::read(&db).unwrap(), reassigned);
        assert_eq!(fs::read(&state).unwrap(), previous_state);
        assert_eq!(fs::read(&checkpoint_path).unwrap(), previous_checkpoint);
        assert!(!dir.join("switched").exists());
    }
    atomic_write(
        &db,
        &serde_json::to_vec(&[credential("older-refresh", 150), duplicate]).unwrap(),
    )
    .unwrap();
    let ambiguous = run()
        .args(["opencode-install", "--activate", "--opencode"])
        .arg(&native)
        .output()
        .unwrap();
    assert!(!ambiguous.status.success());
    let error = String::from_utf8_lossy(&ambiguous.stderr);
    assert!(error.contains("label is ambiguous"));
    assert!(!error.contains("must-not-leak"));
    assert!(!dir.join("switched").exists());
    fs::File::create(&db).unwrap().write_all(b"[]").unwrap();
    native_action("opencode-install", &["--activate"]);
    assert!(dir.join("switched").exists());
    let restored: Value = serde_json::from_slice(&fs::read(&db).unwrap()).unwrap();
    let mut expected = credential("rotated-refresh", 200);
    expected["active"] = false.into();
    assert_eq!(restored, json!([expected]));
}
