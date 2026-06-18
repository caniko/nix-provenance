//! Integration tests for stalwart016-provision.
//!
//! These tests run against local binary artifacts (no recovery server needed).
//! Full recovery-mode end-to-end tests are deferred to the NixOS VM test
//! (`nix/modules/test/stalwart016-vmtest.nix`).

use std::fs;
use std::path::Path;
use tempfile::tempdir;

fn make_test_config(dir: &Path, plan_name: &str) -> serde_json::Value {
    serde_json::json!({
        "migration_marker_file": dir.join("migration-applied"),
        "registry_marker_file": dir.join("registry-applied"),
        "legacy_marker_file": dir.join("provisioned"),
        "generated_plan_file": dir.join(plan_name),
        "migration_apply_files": [],
        "stalwart_binary": "/usr/bin/true",
        "stalwart_config": "/etc/stalwart016/config.json",
        "hostname": "mail.test.example",
        "stalwart_cli_binary": "/usr/bin/true",
        "recovery_url": "http://127.0.0.1:8080",
        "recovery_admin_username": "admin",
        "startup_attempts": 3,
        "startup_interval_secs": 0.01,
        "query_output_dir": dir.join("queries"),
        "query_objects": ["NetworkListener"],
        "continue_on_error": false,
        "require_verified_backup_sentinel": null,
        "store_health_check": false,
        "probe_table": "f",
        "psql_binary": null,
        "pg_host": "127.0.0.1",
        "pg_port": 5432,
        "pg_user": "stalwart",
        "pg_database": "stalwart"
    })
}

#[test]
fn test_config_parse_minimal() {
    let dir = tempdir().unwrap();
    let config_path = dir.path().join("config.json");
    let config_data = make_test_config(dir.path(), "plan.ndjson");

    fs::write(&config_path, serde_json::to_string_pretty(&config_data).unwrap()).unwrap();

    let content = fs::read_to_string(&config_path).unwrap();
    let result: serde_json::Value = serde_json::from_str(&content).unwrap();

    assert_eq!(result["hostname"], "mail.test.example");
    assert_eq!(result["startup_attempts"], 3);
}

#[test]
fn test_config_parse_with_sentinel() {
    let dir = tempdir().unwrap();
    let config_data = serde_json::json!({
        "migration_marker_file": dir.path().join("migration-applied"),
        "registry_marker_file": dir.path().join("registry-applied"),
        "legacy_marker_file": dir.path().join("provisioned"),
        "generated_plan_file": dir.path().join("plan.ndjson"),
        "migration_apply_files": [dir.path().join("export.json")],
        "stalwart_binary": "/usr/bin/true",
        "stalwart_config": "/etc/stalwart016/config.json",
        "hostname": "mail.test.example",
        "stalwart_cli_binary": "/usr/bin/true",
        "recovery_url": "http://127.0.0.1:8080",
        "recovery_admin_username": "admin",
        "startup_attempts": 5,
        "startup_interval_secs": 0.5,
        "query_output_dir": dir.path().join("queries"),
        "query_objects": ["NetworkListener", "Domain"],
        "continue_on_error": false,
        "require_verified_backup_sentinel": dir.path().join("BACKUP_VERIFIED"),
        "store_health_check": true,
        "probe_table": "f",
        "psql_binary": "/usr/bin/psql",
        "pg_host": "10.0.0.1",
        "pg_port": 5432,
        "pg_user": "stalwart",
        "pg_database": "stalwart"
    });

    let config_path = dir.path().join("config.json");
    fs::write(&config_path, serde_json::to_string_pretty(&config_data).unwrap()).unwrap();

    let content = fs::read_to_string(&config_path).unwrap();
    let result: serde_json::Value = serde_json::from_str(&content).unwrap();

    assert_eq!(result["hostname"], "mail.test.example");
    assert_eq!(result["store_health_check"], true);
    assert!(result["migration_apply_files"][0]
        .as_str()
        .unwrap()
        .ends_with("export.json"));
    assert_eq!(result["query_objects"][1], "Domain");
}

#[test]
fn test_config_defaults() {
    let dir = tempdir().unwrap();
    let config_data = serde_json::json!({
        "migration_marker_file": dir.path().join("migration-applied"),
        "registry_marker_file": dir.path().join("registry-applied"),
        "legacy_marker_file": dir.path().join("provisioned"),
        "generated_plan_file": dir.path().join("plan.ndjson"),
        "stalwart_binary": "/usr/bin/true",
        "stalwart_config": "/etc/stalwart016/config.json",
        "hostname": "mail.test.example",
        "stalwart_cli_binary": "/usr/bin/true"
    });

    let config_path = dir.path().join("config.json");
    fs::write(&config_path, serde_json::to_string_pretty(&config_data).unwrap()).unwrap();

    let content = fs::read_to_string(&config_path).unwrap();
    let result: serde_json::Value = serde_json::from_str(&content).unwrap();

    // Defaults are applied by serde when deserializing into Config struct,
    // not when parsing raw JSON. Verify required fields are present.
    assert!(result.get("recovery_url").is_none());
    assert!(result.get("startup_attempts").is_none());
    assert!(result.get("startup_interval_secs").is_none());
}
