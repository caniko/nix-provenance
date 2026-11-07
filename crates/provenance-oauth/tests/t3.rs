use std::{fs, os::unix::fs::PermissionsExt, process::Command};

#[test]
fn t3_handoff_requires_explicit_runner_paths_and_preserves_helper_exit() {
    let dir = tempfile::tempdir().unwrap();
    let helper = dir.path().join("helper");
    let config = dir.path().join("public manifest.json");
    fs::write(&helper, "#!/bin/sh\nprintf '%s\\n' \"$@\"\nexit 23\n").unwrap();
    fs::set_permissions(&helper, fs::Permissions::from_mode(0o700)).unwrap();
    let run = |command: Option<&std::path::Path>, manifest: Option<&std::path::Path>| {
        let mut child = Command::new(env!("CARGO_BIN_EXE_provenance-t3-openai"));
        child.env_remove("T3CODE_OPENAI_OAUTH_COMMAND");
        child.env_remove("T3CODE_OPENAI_OAUTH_CONFIG_FILE");
        if let Some(path) = command {
            child.env("T3CODE_OPENAI_OAUTH_COMMAND", path);
        }
        if let Some(path) = manifest {
            child.env("T3CODE_OPENAI_OAUTH_CONFIG_FILE", path);
        }
        child.output().unwrap()
    };
    let unbound = run(None, None);
    assert!(unbound.status.success());
    assert_eq!(unbound.stdout, b"null\n");
    for (command, manifest) in [
        (Some(helper.as_path()), None),
        (
            Some(std::path::Path::new("relative-helper")),
            Some(config.as_path()),
        ),
        (
            Some(helper.as_path()),
            Some(std::path::Path::new("relative-manifest")),
        ),
    ] {
        let result = run(command, manifest);
        assert!(!result.status.success());
        assert!(result.stdout.is_empty());
    }
    let result = run(Some(&helper), Some(&config));
    assert_eq!(result.status.code(), Some(23));
    assert_eq!(
        String::from_utf8(result.stdout).unwrap(),
        format!("--config\n{}\naccess\n", config.display())
    );
}
