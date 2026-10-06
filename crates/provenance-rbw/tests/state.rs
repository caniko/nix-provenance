use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::Path;

use provenance_rbw::{Config, prepare, profile_name, status};

fn config(root: &Path) -> Config {
    Config {
        state_directory: root.join("state"),
        legacy_cache_directory: root.join("legacy-cache"),
        legacy_data_directory: root.join("legacy-data"),
        // The test harness accepts "stop-agent" as a filter matching no tests.
        rbw_binary: std::env::current_exe().unwrap(),
        agent_binary: std::env::current_exe().unwrap(),
    }
}

fn write(path: &Path, value: &[u8]) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, value).unwrap();
}

#[test]
fn migration_preserves_database_and_device_identity_and_is_idempotent() {
    let root = tempfile::tempdir().unwrap();
    let config = config(root.path());
    let database = b"{\"refresh_token\":\"fixture-secret\",\"entries\":[]}";
    write(
        &config
            .legacy_cache_directory
            .join("rbw/default:fixture.json"),
        database,
    );
    write(
        &config.legacy_data_directory.join("rbw/device_id"),
        b"fixture-device",
    );
    prepare(&config, "rbw").unwrap();
    prepare(&config, "rbw").unwrap();
    let path = config.cache_home().join("rbw/default:fixture.json");
    assert_eq!(fs::read(&path).unwrap(), database);
    assert_eq!(
        fs::read(config.data_home().join("rbw/device_id")).unwrap(),
        b"fixture-device"
    );
    assert_eq!(
        fs::metadata(path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        fs::metadata(config.state_directory.clone())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    assert!(!config.legacy_cache_directory.join("rbw").exists());
    let status = status(&config, "rbw").unwrap();
    assert_eq!(status["vaultDatabases"], 1);
    assert!(!status.to_string().contains("fixture-secret"));
}

#[test]
fn cache_recreation_and_purge_never_restore_old_tokens() {
    let root = tempfile::tempdir().unwrap();
    let config = config(root.path());
    prepare(&config, "rbw").unwrap();
    write(
        &config.legacy_cache_directory.join("rbw/old.json"),
        b"obsolete-token",
    );
    prepare(&config, "rbw").unwrap();
    assert!(!config.cache_home().join("rbw/old.json").exists());
    assert_eq!(status(&config, "rbw").unwrap()["vaultDatabases"], 0);
}

#[test]
fn missing_durable_state_requires_explicit_recovery() {
    let root = tempfile::tempdir().unwrap();
    let config = config(root.path());
    prepare(&config, "rbw").unwrap();
    fs::remove_dir(config.cache_home().join("rbw")).unwrap();
    assert!(
        prepare(&config, "rbw")
            .unwrap_err()
            .to_string()
            .contains("durable state is missing")
    );
    assert!(!config.cache_home().join("rbw").exists());
}

#[test]
fn competing_state_trees_fail_before_moving_any_files() {
    let root = tempfile::tempdir().unwrap();
    let config = config(root.path());
    write(&config.legacy_cache_directory.join("rbw/old.json"), b"old");
    write(&config.cache_home().join("rbw/new.json"), b"new");
    assert!(prepare(&config, "rbw").is_err());
    assert_eq!(
        fs::read(config.legacy_cache_directory.join("rbw/old.json")).unwrap(),
        b"old"
    );
    assert_eq!(
        fs::read(config.cache_home().join("rbw/new.json")).unwrap(),
        b"new"
    );
}

#[test]
fn symlinks_and_hardlinks_are_rejected_without_touching_the_target() {
    for hardlink in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let config = config(root.path());
        let outside = root.path().join("outside");
        write(&outside, b"unrelated");
        let link = config.legacy_cache_directory.join("rbw/linked.json");
        fs::create_dir_all(link.parent().unwrap()).unwrap();
        if hardlink {
            fs::hard_link(&outside, &link).unwrap();
        } else {
            symlink(&outside, &link).unwrap();
        }
        assert!(prepare(&config, "rbw").is_err());
        assert_eq!(fs::read(outside).unwrap(), b"unrelated");
    }
}

#[test]
fn interrupted_directory_migration_can_finish() {
    let root = tempfile::tempdir().unwrap();
    let config = config(root.path());
    write(&config.cache_home().join("rbw/vault.json"), b"moved");
    write(
        &config.legacy_data_directory.join("rbw/device_id"),
        b"still-legacy",
    );
    prepare(&config, "rbw").unwrap();
    assert_eq!(
        fs::read(config.cache_home().join("rbw/vault.json")).unwrap(),
        b"moved"
    );
    assert_eq!(
        fs::read(config.data_home().join("rbw/device_id")).unwrap(),
        b"still-legacy"
    );
}

#[test]
fn profiles_have_independent_state_and_reject_path_traversal() {
    let root = tempfile::tempdir().unwrap();
    let config = config(root.path());
    prepare(&config, &profile_name(Some("work")).unwrap()).unwrap();
    prepare(&config, &profile_name(None).unwrap()).unwrap();
    assert!(config.cache_home().join("rbw-work").is_dir());
    assert!(config.cache_home().join("rbw").is_dir());
    for profile in ["../escape", "a/b", "..", "a:b"] {
        assert!(profile_name(Some(profile)).is_err());
    }
}

#[test]
fn client_and_agent_share_paths_without_changing_config_or_runtime() {
    let root = tempfile::tempdir().unwrap();
    let config = config(root.path());
    for agent in [false, true] {
        let command = config.command(agent);
        let environment: Vec<_> = command.get_envs().collect();
        assert!(
            environment
                .iter()
                .any(|(key, value)| *key == "XDG_CACHE_HOME"
                    && *value == Some(config.cache_home().as_os_str()))
        );
        assert!(environment.iter().any(|(key, _)| *key == "RBW_AGENT"));
        assert!(
            !environment
                .iter()
                .any(|(key, _)| *key == "XDG_CONFIG_HOME" || *key == "XDG_RUNTIME_DIR")
        );
    }
}
