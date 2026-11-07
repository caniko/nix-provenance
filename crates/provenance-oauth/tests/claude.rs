use std::{fs, os::unix::fs::PermissionsExt, process::Command};

#[test]
fn native_claude_gets_a_private_descriptor_and_unsafe_sources_fail_closed() {
    let dir = tempfile::tempdir().unwrap();
    let token = dir.path().join("token");
    let native = dir.path().join("claude");
    fs::write(&native, "#!/bin/sh\n[ \"$(cat <&3)\" = synthetic-token ] || exit 90\n[ \"$CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR\" = 3 ] || exit 91\n[ -z \"${CLAUDE_CODE_OAUTH_TOKEN-}${CLAUDE_CODE_OAUTH_REFRESH_TOKEN-}${ANTHROPIC_API_KEY-}${ANTHROPIC_AUTH_TOKEN-}\" ] || exit 92\n[ \"$1\" = --version ] || exit 93\nprintf 'descriptor-only\\n'\nexit 23\n").unwrap();
    fs::set_permissions(&native, fs::Permissions::from_mode(0o700)).unwrap();
    let run = |source: &std::path::Path| {
        Command::new(env!("CARGO_BIN_EXE_provenance-claude"))
            .arg(source)
            .arg(&native)
            .arg("--version")
            .env("CLAUDE_CODE_OAUTH_TOKEN", "ambient-secret")
            .env("CLAUDE_CODE_OAUTH_REFRESH_TOKEN", "ambient-secret")
            .env("ANTHROPIC_API_KEY", "ambient-secret")
            .env("ANTHROPIC_AUTH_TOKEN", "ambient-secret")
            .output()
            .unwrap()
    };
    let refused = |source: &std::path::Path| {
        let output = run(source);
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty());
        assert_eq!(
            output.stderr,
            b"provenance-claude: native credential launch failed\n"
        );
    };
    refused(&token);
    refused(std::path::Path::new("relative-token"));
    for content in [
        b"".as_slice(),
        b" \n",
        b"token\nother",
        b"token\x00other",
        b"token\xff",
    ] {
        fs::write(&token, content).unwrap();
        fs::set_permissions(&token, fs::Permissions::from_mode(0o400)).unwrap();
        refused(&token);
        fs::remove_file(&token).unwrap();
    }
    fs::write(&token, vec![b'a'; 16 * 1024 + 1]).unwrap();
    fs::set_permissions(&token, fs::Permissions::from_mode(0o400)).unwrap();
    refused(&token);
    fs::remove_file(&token).unwrap();
    fs::write(&token, b"synthetic-token\n").unwrap();
    fs::set_permissions(&token, fs::Permissions::from_mode(0o640)).unwrap();
    refused(&token);
    fs::set_permissions(&token, fs::Permissions::from_mode(0o400)).unwrap();
    let link = dir.path().join("link");
    std::os::unix::fs::symlink(&token, &link).unwrap();
    refused(&link);
    refused(dir.path());
    let output = run(&token);
    assert_eq!(output.status.code(), Some(23));
    assert_eq!(output.stdout, b"descriptor-only\n");
    assert!(output.stderr.is_empty());
}
