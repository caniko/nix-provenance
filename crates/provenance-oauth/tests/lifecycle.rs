use provenance_oauth::{
    Config, Enrollment, Grant, Secret, Target,
    state::{Store, read_json},
};
use std::{
    cell::Cell,
    fs,
    io::Read,
    os::unix::fs::PermissionsExt,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    thread,
};

fn fixture() -> (tempfile::TempDir, Config, age::x25519::Identity) {
    let dir = tempfile::tempdir().unwrap();
    let identity = age::x25519::Identity::generate();
    let config = Config {
        version: 1,
        target: Target {
            host: "test-host".into(),
            user: "test-user".into(),
            provider: "openai".into(),
            profile: "chatgpt".into(),
            account: "default".into(),
        },
        state_directory: dir.path().join("state"),
        recovery_recipients: vec![identity.to_public().to_string()],
    };
    (dir, config, identity)
}

fn enrollment(config: &Config, generation: u64) -> Enrollment {
    Enrollment {
        version: 1,
        target: config.target.clone(),
        generation,
        grant: Grant {
            access_token: Secret("initial-access".into()),
            refresh_token: Secret("initial-refresh".into()),
            expires_at: 1,
            account_id: "chatgpt-account".into(),
        },
    }
}

fn rotate(grant: &Grant) -> anyhow::Result<Grant> {
    assert_eq!(grant.refresh_token.0, "initial-refresh");
    Ok(Grant {
        access_token: Secret("rotated-access".into()),
        refresh_token: Secret("rotated-refresh".into()),
        expires_at: 9_000_000,
        account_id: grant.account_id.clone(),
    })
}

#[test]
fn parallel_consumers_rotate_once_and_reboot_does_not_replay_enrollment() {
    let (_dir, config, _) = fixture();
    let initial = enrollment(&config, 100);
    Store::lock(&config).unwrap().apply(&initial, true).unwrap();
    let count = Arc::new(AtomicUsize::new(0));
    let threads: Vec<_> = (0..8)
        .map(|_| {
            let config = config.clone();
            let count = count.clone();
            thread::spawn(move || {
                let access = Store::lock(&config)
                    .unwrap()
                    .access(
                        || Ok(1000),
                        |grant| {
                            count.fetch_add(1, Ordering::SeqCst);
                            rotate(grant)
                        },
                    )
                    .unwrap();
                let json = serde_json::to_string(&access).unwrap();
                assert!(json.contains("rotated-access"));
                assert!(!json.contains("refresh"));
            })
        })
        .collect();
    for thread in threads {
        thread.join().unwrap();
    }
    assert_eq!(count.load(Ordering::SeqCst), 1);
    let store = Store::lock(&config).unwrap();
    store.apply(&initial, false).unwrap();
    store.apply(&enrollment(&config, 99), false).unwrap();
    assert_eq!(
        store
            .access(|| Ok(1001), |_| panic!("must not refresh twice"))
            .unwrap()
            .access_token
            .0,
        "rotated-access"
    );
    assert_eq!(store.status().unwrap()["revision"], 1);
}

#[test]
fn ambiguous_refresh_is_fenced_across_restart_and_checkpoint() {
    let (_dir, config, identity) = fixture();
    {
        let store = Store::lock(&config).unwrap();
        store.apply(&enrollment(&config, 100), true).unwrap();
        assert!(
            store
                .access(
                    || Ok(1000),
                    |_| anyhow::bail!("connection dropped after dispatch")
                )
                .is_err()
        );
    }
    let store = Store::lock(&config).unwrap();
    assert!(
        store
            .access(
                || Ok(1001),
                |_| panic!("must not replay an uncertain refresh")
            )
            .is_err()
    );
    assert_eq!(store.status().unwrap()["state"], "reauthorization-required");
    let checkpoint = decrypt(&config, &identity);
    assert_eq!(checkpoint["refreshPending"], true);
    store.apply(&enrollment(&config, 101), false).unwrap();
    assert!(store.access(|| Ok(1001), rotate).is_ok());
}

#[test]
fn failed_checkpoint_before_dispatch_keeps_refresh_retryable() {
    let (_dir, config, _) = fixture();
    let store = Store::lock(&config).unwrap();
    store.apply(&enrollment(&config, 100), true).unwrap();
    let checkpoint = config.state_directory.join("checkpoint.age");
    fs::remove_file(&checkpoint).unwrap();
    fs::create_dir(&checkpoint).unwrap();
    assert!(
        store
            .access(
                || Ok(1000),
                |_| panic!("must not dispatch without a durable checkpoint")
            )
            .is_err()
    );
    assert_eq!(store.status().unwrap()["state"], "enrolled");
    fs::remove_dir(&checkpoint).unwrap();
    assert_eq!(
        store.access(|| Ok(1001), rotate).unwrap().access_token.0,
        "rotated-access"
    );
}

fn decrypt(config: &Config, identity: &age::x25519::Identity) -> serde_json::Value {
    let data = fs::read(config.state_directory.join("checkpoint.age")).unwrap();
    assert!(!String::from_utf8_lossy(&data).contains("refresh"));
    let decryptor = age::Decryptor::new(&data[..]).unwrap();
    let mut reader = decryptor
        .decrypt(std::iter::once(identity as &dyn age::Identity))
        .unwrap();
    let mut plaintext = Vec::new();
    reader.read_to_end(&mut plaintext).unwrap();
    serde_json::from_slice(&plaintext).unwrap()
}

#[test]
fn current_encrypted_checkpoint_restores_rotated_credentials() {
    let (dir, config, identity) = fixture();
    let store = Store::lock(&config).unwrap();
    store.apply(&enrollment(&config, 100), true).unwrap();
    store.access(|| Ok(1000), rotate).unwrap();
    let current = decrypt(&config, &identity);
    assert_eq!(current["grant"]["refreshToken"], "rotated-refresh");
    let plaintext = dir.path().join("restore.json");
    fs::write(&plaintext, serde_json::to_vec(&current).unwrap()).unwrap();
    fs::set_permissions(&plaintext, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(store.restore(&plaintext).is_err());
    fs::remove_file(config.state_directory.join("state.json")).unwrap();
    assert!(store.apply(&enrollment(&config, 100), false).is_err());
    store.restore(&plaintext).unwrap();
    assert_eq!(
        store
            .access(|| Ok(1001), |_| panic!("restored token still valid"))
            .unwrap()
            .access_token
            .0,
        "rotated-access"
    );
}

#[test]
fn revocation_target_isolation_and_generation_collision() {
    let (_dir, config, _) = fixture();
    let store = Store::lock(&config).unwrap();
    let initial = enrollment(&config, 100);
    let mut wrong = initial.clone();
    wrong.target.user = "another-user".into();
    assert!(store.apply(&wrong, true).is_err());
    assert!(!config.state_directory.join("state.json").exists());
    store.apply(&initial, true).unwrap();
    let mut conflict = initial.clone();
    conflict.grant.refresh_token = Secret("different".into());
    assert!(store.apply(&conflict, false).is_err());
    store.remove().unwrap();
    store.apply(&initial, false).unwrap();
    assert_eq!(store.status().unwrap()["state"], "removed");
    assert!(store.access(|| Ok(1000), |_| panic!("revoked")).is_err());
    let state: serde_json::Value =
        read_json(&config.state_directory.join("state.json"), true).unwrap();
    assert_eq!(state["grant"], serde_json::Value::Null);
}

#[test]
fn refresh_expiry_is_checked_after_exchange() {
    let (_dir, config, identity) = fixture();
    let clock = Cell::new(1000);
    let store = Store::lock(&config).unwrap();
    store.apply(&enrollment(&config, 100), true).unwrap();
    let result = store.access(
        || Ok(clock.get()),
        |grant| {
            clock.set(200_000);
            let mut next = rotate(grant)?;
            next.expires_at = 150_000;
            Ok(next)
        },
    );
    assert!(
        result.is_err(),
        "must not emit a grant that expired during the exchange"
    );
    assert_eq!(store.status().unwrap()["state"], "reauthorization-required");
    assert_eq!(decrypt(&config, &identity)["refreshPending"], true);
}

#[test]
fn private_files_and_symlink_boundaries() {
    let (dir, config, _) = fixture();
    let store = Store::lock(&config).unwrap();
    store.apply(&enrollment(&config, 100), true).unwrap();
    for file in ["state.json", "checkpoint.age", "lock"] {
        assert_eq!(
            fs::metadata(config.state_directory.join(file))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
    drop(store);
    let link = dir.path().join("link");
    std::os::unix::fs::symlink(&config.state_directory, &link).unwrap();
    let mut linked = config.clone();
    linked.state_directory = link;
    assert!(Store::lock(&linked).is_err());
    fs::set_permissions(&config.state_directory, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(Store::lock(&config).is_err());
}
