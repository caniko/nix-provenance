//! Focused regression cluster for native T3 enrollment: trust boundaries,
//! secret-file inputs, idempotency, retry, and the fake native adapters.

use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

use provenance_t3_enroll::{Config, ImportSummary, Summary, load_manifest, run};
use serde_json::{Value, json};

fn config(attempts: u32) -> Config {
    Config {
        attempts,
        retry_delay: Duration::ZERO,
        desktop_timeout: Duration::from_secs(5),
        owner_timeout: Duration::from_secs(5),
        command_timeout: Duration::from_secs(5),
        ssh: PathBuf::from("ssh"),
    }
}

fn current_user() -> String {
    let euid = fs::metadata("/proc/self").unwrap().uid();
    for line in fs::read_to_string("/etc/passwd").unwrap().lines() {
        let fields: Vec<_> = line.split(':').collect();
        if fields.get(2).and_then(|uid| uid.parse::<u32>().ok()) == Some(euid) {
            return fields[0].to_owned();
        }
    }
    panic!("current user is not in /etc/passwd");
}

fn write_file(path: &Path, value: &str, mode: u32) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, value).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

fn secret(path: &Path, value: &str) {
    write_file(path, value, 0o600);
}

fn shell(value: &str) -> String {
    assert!(
        !value.contains('\''),
        "fixture paths must not contain quotes"
    );
    format!("'{value}'")
}

fn quote(path: &Path) -> String {
    shell(&path.display().to_string())
}

fn manifest_file(root: &Path, value: &Value) -> PathBuf {
    let path = root.join("manifest.json");
    write_file(&path, &value.to_string(), 0o644);
    path
}

fn execute(path: &Path, options: Config) -> anyhow::Result<Summary> {
    let manifest = load_manifest(path)?;
    run(&manifest, &options)
}

fn peer_value(
    urls: &[&str],
    access: &str,
    pairing: Option<&Path>,
    desktop: Option<Value>,
) -> Value {
    json!({
        "environmentId": "env_atlas",
        "access": access,
        "urls": urls,
        "pairingCodeFile": pairing.map(|path| path.to_string_lossy().to_string()),
        "desktop": desktop,
    })
}

fn base_dir_for(t3: &Path) -> PathBuf {
    let base = t3
        .parent()
        .expect("fake t3 path has a parent")
        .join("t3-base");
    fs::create_dir_all(&base).unwrap();
    fs::set_permissions(&base, fs::Permissions::from_mode(0o700)).unwrap();
    base
}

fn manifest_value(t3: &Path, desktop: Option<&Path>, peers: Vec<Value>) -> Value {
    json!({
        "user": current_user(),
        "baseDir": base_dir_for(t3).to_string_lossy(),
        "t3": t3.to_string_lossy(),
        "desktop": desktop.map(|path| path.to_string_lossy().to_string()),
        "peers": peers,
    })
}

fn links(entries: &[(&str, &str, &[&str], &str, &str)]) -> String {
    let values: Vec<Value> = entries
        .iter()
        .map(|(id, label, urls, access, status)| {
            json!({
                "environmentId": id,
                "label": label,
                "urls": urls,
                "access": access,
                "linkedAt": "2026-11-07T00:00:00Z",
                "expiresAt": "2027-11-07T00:00:00Z",
                "lastReachedAt": "2026-11-07T00:00:00Z",
                "lastError": null,
                "status": status,
            })
        })
        .collect();
    serde_json::to_string(&values).unwrap()
}

fn fake_t3(root: &Path, initial: &str, after: Option<&str>, fail_links: u32) -> (PathBuf, PathBuf) {
    fake_t3_for(root, initial, after, fail_links, "env_atlas")
}

fn fake_t3_for(
    root: &Path,
    initial: &str,
    after: Option<&str>,
    fail_links: u32,
    expected_environment: &str,
) -> (PathBuf, PathBuf) {
    let binary = root.join("t3");
    let log = root.join("t3.log");
    let state = root.join("t3-state");
    fs::create_dir_all(&state).unwrap();
    write_file(&state.join("links.json"), initial, 0o600);
    let after_line = after
        .map(|value| {
            let path = root.join("after.json");
            write_file(&path, value, 0o600);
            format!("    cp {} \"$state/links.json\"\n", quote(&path))
        })
        .unwrap_or_default();
    let script = format!(
        r#"#!/bin/sh
log={log}
state={state}
printf '%s\n' "$*" >> "$log"
expect=''
previous=''
for argument in "$@"; do
  if [ "$previous" = "--expect-environment-id" ]; then expect="$argument"; fi
  previous="$argument"
done
case "$1 $2" in
  "environment list")
    cat "$state/links.json"
    ;;
  "environment link")
    cat >> "$state/stdin"
    if [ -z "$expect" ]; then
      printf 'missing --expect-environment-id\n' >&2
      exit 8
    fi
    if [ "$expect" != {expected_environment} ]; then
      printf 'refusing pairing code for unexpected environment\n' >&2
      exit 9
    fi
    printf '1' > "$state/exchanged"
    n=0
    if [ -f "$state/link-count" ]; then n=$(cat "$state/link-count"); fi
    n=$((n+1))
    printf '%s' "$n" > "$state/link-count"
    if [ "$n" -le {fail_links} ]; then
      printf 'simulated offline peer\n' >&2
      exit 1
    fi
{after_line}    printf 'Linked fixture.\n'
    ;;
  "environment unlink")
    printf '%s\n' "$3" >> "$state/unlinked"
    ;;
  *)
    printf 'unexpected command\n' >&2
    exit 1
    ;;
esac
"#,
        log = quote(&log),
        state = quote(&state),
        expected_environment = shell(expected_environment),
    );
    write_file(&binary, &script, 0o700);
    (binary, state)
}

fn fake_desktop(root: &Path, fail_imports: u32, sleep_seconds: Option<u32>) -> (PathBuf, PathBuf) {
    fake_desktop_with(root, fail_imports, sleep_seconds, false)
}

fn fake_desktop_with(
    root: &Path,
    fail_imports: u32,
    sleep_seconds: Option<u32>,
    plain_version: bool,
) -> (PathBuf, PathBuf) {
    let binary = root.join("t3-code");
    let log = root.join("desktop.log");
    let state = root.join("desktop-state");
    fs::create_dir_all(&state).unwrap();
    let sleep_line = sleep_seconds
        .map(|seconds| format!("sleep {seconds}\n"))
        .unwrap_or_default();
    let version_line = if plain_version {
        "  printf '9.9.9\\n'\n".to_owned()
    } else {
        "  printf '{\"version\":\"9.9.9\",\"capabilities\":[\"import-connections\"]}\\n'\n"
            .to_owned()
    };
    let script = format!(
        r#"#!/bin/sh
log={log}
state={state}
printf '%s\n' "$*" >> "$log"
if [ "$1" = "--version" ] && [ "$2" = "--json" ]; then
{version_line}  exit 0
fi
printf '%s' "$T3CODE_HOME" > "$state/t3code-home"
printf '%s\n' "$2" >> "$state/import-path"
n=0
if [ -f "$state/import-count" ]; then n=$(cat "$state/import-count"); fi
n=$((n+1))
printf '%s' "$n" > "$state/import-count"
if [ "$n" -le {fail_imports} ]; then
  cat "$2" >&2
  exit 1
fi
{sleep_line}cp "$2" "$state/imported.json"
stat -c '%a' "$2" > "$state/import-mode"
printf 'Imported fixture connections.\n'
"#,
        log = quote(&log),
        state = quote(&state),
    );
    write_file(&binary, &script, 0o700);
    (binary, state)
}

fn log_lines(path: &Path) -> Vec<String> {
    fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .map(str::to_owned)
        .collect()
}

fn link_command(urls: &[&str], access: &str) -> String {
    let mut command = format!("environment link {}", urls[0]);
    for url in &urls[1..] {
        command.push_str(&format!(" --url {url}"));
    }
    command.push_str(&format!(
        " --expect-environment-id env_atlas --pairing-code - --access {access}"
    ));
    command
}

fn fake_owner_t3(
    root: &Path,
    environment_id: &str,
    after: Option<&str>,
    fail_links: u32,
) -> PathBuf {
    fake_owner_t3_with(root, environment_id, after, fail_links, false)
}

fn fake_owner_t3_with(
    root: &Path,
    environment_id: &str,
    after: Option<&str>,
    fail_links: u32,
    malformed_secret: bool,
) -> PathBuf {
    let binary = root.join("owner-t3");
    let state = root.join("owner-state");
    fs::create_dir_all(&state).unwrap();
    write_file(&state.join("links.json"), "[]", 0o600);
    write_file(&state.join("session-list.json"), "[]", 0o600);
    let after_line = after
        .map(|value| {
            let path = root.join("owner-after.json");
            write_file(&path, value, 0o600);
            format!("    cp {} \"$state/links.json\"\n", quote(&path))
        })
        .unwrap_or_default();
    let script = format!(
        r#"#!/bin/sh
state={state}
printf '%s\n' "$*" >> "$state/args.log"
env > "$state/env.log"
case "$1 $2" in
  "environment describe")
    printf '{{"environmentId":"%s","label":"Atlas"}}\n' {environment_id}
    ;;
  "environment list")
    cat "$state/links.json"
    ;;
  "auth pairing")
    if [ {malformed} = 1 ]; then printf '{{"credential":"CANARY-TOPLEVEL'; exit 0; fi
    n=0
    if [ -f "$state/pairing-count" ]; then n=$(cat "$state/pairing-count"); fi
    n=$((n+1))
    printf '%s' "$n" > "$state/pairing-count"
    printf '{{"credential":"PAIR-%s"}}\n' "$n"
    ;;
  "auth session")
    case "$3" in
      list)
        cat "$state/session-list.json"
        ;;
      revoke)
        printf '%s\n' "$4" >> "$state/revoked.log"
        ;;
      issue)
        if [ {malformed} = 1 ]; then printf '{{"token":"CANARY-TOPLEVEL'; exit 0; fi
        n=0
        if [ -f "$state/session-count" ]; then n=$(cat "$state/session-count"); fi
        n=$((n+1))
        printf '%s' "$n" > "$state/session-count"
        printf '{{"token":"TOKEN-%s","sessionId":"SESSION-%s"}}\n' "$n" "$n"
        ;;
    esac
    ;;
  "environment link")
    cat >> "$state/link-stdin"
    n=0
    if [ -f "$state/link-count" ]; then n=$(cat "$state/link-count"); fi
    n=$((n+1))
    printf '%s' "$n" > "$state/link-count"
    if [ "$n" -le {fail_links} ]; then exit 1; fi
{after_line}    exit 0
    ;;
  *)
    exit 1
    ;;
esac
"#,
        state = quote(&state),
        environment_id = shell(environment_id),
        malformed = malformed_secret as u8,
    );
    write_file(&binary, &script, 0o700);
    binary
}

fn fake_ssh(root: &Path, wrong_owner: bool) -> PathBuf {
    fake_ssh_with(root, wrong_owner, None)
}

fn fake_ssh_with(root: &Path, wrong_owner: bool, stat_override: Option<&str>) -> PathBuf {
    let binary = root.join("ssh");
    let state = root.join("ssh-state");
    fs::create_dir_all(&state).unwrap();
    let owner = if wrong_owner {
        "mallory".to_owned()
    } else {
        current_user()
    };
    let stat_block = stat_override
        .map(|line| format!("  printf '%s\\n' {}\n  exit 0\n", shell(line)))
        .unwrap_or_default();
    let script = format!(
        r#"#!/bin/sh
state={state}
printf '%s\n' "$*" >> "$state/ssh.log"
while [ "$1" != "--" ]; do shift; done
shift
shift
command="$*"
if [ "$command" = "'id' '-un'" ]; then
  printf '%s\n' {owner}
  exit 0
fi
if [ "$command" = "'id' '-u'" ]; then
  id -u
  exit 0
fi
case "$command" in
  "'stat'"*)
{stat_block}    ;;
esac
exec /bin/sh -c "$command"
"#,
        state = quote(&state),
        owner = shell(&owner),
    );
    write_file(&binary, &script, 0o700);
    binary
}

fn owner_base_dir(owner_t3: &Path) -> PathBuf {
    let base = owner_t3
        .parent()
        .expect("fake owner t3 path has a parent")
        .join("owner-base");
    fs::create_dir_all(&base).unwrap();
    fs::set_permissions(&base, fs::Permissions::from_mode(0o700)).unwrap();
    base
}

fn owner_manifest(
    t3: &Path,
    desktop: &Path,
    owner_host: &str,
    owner_t3: &Path,
    environment_id: Option<&str>,
    desktop_routes: Value,
) -> Value {
    json!({
        "user": current_user(),
        "baseDir": base_dir_for(t3).to_string_lossy(),
        "t3": t3.to_string_lossy(),
        "desktop": desktop.to_string_lossy(),
        "peers": [{
            "environmentId": environment_id,
            "access": "approval-required",
            "urls": ["https://atlas.example.ts.net"],
            "owner": {
                "host": owner_host,
                "t3": owner_t3.to_string_lossy(),
                "baseDir": owner_base_dir(owner_t3).to_string_lossy(),
            },
            "desktop": desktop_routes,
        }],
    })
}

#[test]
fn malformed_secret_json_never_leaks_canary() {
    let pairing = tempfile::tempdir().unwrap();
    let t3 = fake_owner_t3_with(pairing.path(), "env_atlas", None, 0, true);
    let ssh = fake_ssh(pairing.path(), false);
    let desktop = pairing.path().join("desktop");
    write_file(&desktop, "#!/bin/sh\nexit 0\n", 0o700);
    let manifest = manifest_file(
        pairing.path(),
        &owner_manifest(&t3, &desktop, "peer.example", &t3, None, Value::Null),
    );
    let options = Config {
        attempts: 1,
        retry_delay: Duration::ZERO,
        desktop_timeout: Duration::from_secs(5),
        owner_timeout: Duration::from_secs(5),
        command_timeout: Duration::from_secs(5),
        ssh,
    };
    let error = format!("{:#}", execute(&manifest, options.clone()).unwrap_err());
    assert!(!error.contains("CANARY"), "{error}");
    assert!(
        error.contains("native pairing create output was invalid"),
        "{error}"
    );

    let session = tempfile::tempdir().unwrap();
    let urls = ["https://atlas.example.ts.net"];
    let after = links(&[(
        "env_atlas",
        "Atlas",
        &urls,
        "approval-required",
        "reachable",
    )]);
    let t3 = fake_owner_t3_with(session.path(), "env_atlas", Some(&after), 0, true);
    write_file(
        &session.path().join("owner-state/links.json"),
        &after,
        0o600,
    );
    let ssh = fake_ssh(session.path(), false);
    let (desktop, desktop_state) = fake_desktop(session.path(), 0, None);
    let manifest = manifest_file(
        session.path(),
        &owner_manifest(
            &t3,
            &desktop,
            "peer.example",
            &t3,
            Some("env_atlas"),
            json!({
                "bearer": {
                    "httpBaseUrl": "https://atlas.example.ts.net/",
                    "wsBaseUrl": "wss://atlas.example.ts.net/",
                },
            }),
        ),
    );
    let options = Config {
        attempts: 1,
        retry_delay: Duration::ZERO,
        desktop_timeout: Duration::from_secs(5),
        owner_timeout: Duration::from_secs(5),
        command_timeout: Duration::from_secs(5),
        ssh,
    };
    let error = format!("{:#}", execute(&manifest, options).unwrap_err());
    assert!(!error.contains("CANARY"), "{error}");
    assert!(
        error.contains("native session issue output was invalid"),
        "{error}"
    );
    assert!(
        !log_lines(&desktop_state.join("../desktop.log"))
            .iter()
            .any(|line| line.starts_with("--import-connections"))
    );

    let list = tempfile::tempdir().unwrap();
    let urls = ["https://atlas.example.ts.net"];
    let after = links(&[(
        "env_atlas",
        "Atlas",
        &urls,
        "approval-required",
        "reachable",
    )]);
    let t3 = fake_owner_t3(list.path(), "env_atlas", None, 0);
    write_file(&list.path().join("owner-state/links.json"), &after, 0o600);
    write_file(
        &list.path().join("owner-state/session-list.json"),
        "\"CANARY-SESSION-LIST\"",
        0o600,
    );
    let ssh = fake_ssh(list.path(), false);
    let (desktop, _) = fake_desktop(list.path(), 0, None);
    let manifest = manifest_file(
        list.path(),
        &owner_manifest(
            &t3,
            &desktop,
            "peer.example",
            &t3,
            Some("env_atlas"),
            json!({
                "bearer": {
                    "httpBaseUrl": "https://atlas.example.ts.net/",
                    "wsBaseUrl": "wss://atlas.example.ts.net/",
                },
            }),
        ),
    );
    let options = Config {
        attempts: 1,
        retry_delay: Duration::ZERO,
        desktop_timeout: Duration::from_secs(5),
        owner_timeout: Duration::from_secs(5),
        command_timeout: Duration::from_secs(5),
        ssh,
    };
    let error = format!("{:#}", execute(&manifest, options).unwrap_err());
    assert!(!error.contains("CANARY"), "{error}");
    assert!(
        error.contains("native auth session list output was invalid"),
        "{error}"
    );
}

#[test]
fn bounded_runner_terminates_hung_children_and_descendant_pipes() {
    let list = tempfile::tempdir().unwrap();
    let t3 = list.path().join("t3");
    let holder_pid = list.path().join("holder.pid");
    let script = format!(
        "#!/bin/sh\n(sleep 30) &\nprintf '%s' $! > {}\nexit 0\n",
        shell(&holder_pid.to_string_lossy())
    );
    write_file(&t3, &script, 0o700);
    let manifest = manifest_file(
        list.path(),
        &manifest_value(
            &t3,
            None,
            vec![peer_value(
                &["https://atlas.example.ts.net"],
                "read-only",
                None,
                None,
            )],
        ),
    );
    let options = Config {
        attempts: 1,
        retry_delay: Duration::ZERO,
        desktop_timeout: Duration::from_secs(5),
        owner_timeout: Duration::from_secs(5),
        command_timeout: Duration::from_millis(150),
        ssh: PathBuf::from("ssh"),
    };
    let error = format!("{:#}", execute(&manifest, options).unwrap_err());
    assert!(error.contains("did not finish within"), "{error}");
    let holder = fs::read_to_string(&holder_pid).unwrap();
    let _ = std::process::Command::new("kill")
        .args(["-9", holder.trim()])
        .status();

    let link = tempfile::tempdir().unwrap();
    let t3 = link.path().join("t3");
    write_file(
        &t3,
        "#!/bin/sh\nif [ \"$1 $2\" = \"environment list\" ]; then printf '[]'; exit 0; fi\nsleep 30\n",
        0o700,
    );
    let pairing = link.path().join("pairing-code");
    secret(&pairing, "PAIRING-CODE\n");
    let manifest = manifest_file(
        link.path(),
        &manifest_value(
            &t3,
            None,
            vec![peer_value(
                &["https://atlas.example.ts.net"],
                "read-only",
                Some(&pairing),
                None,
            )],
        ),
    );
    let options = Config {
        attempts: 1,
        retry_delay: Duration::ZERO,
        desktop_timeout: Duration::from_secs(5),
        owner_timeout: Duration::from_secs(5),
        command_timeout: Duration::from_millis(150),
        ssh: PathBuf::from("ssh"),
    };
    let error = format!("{:#}", execute(&manifest, options).unwrap_err());
    assert!(error.contains("did not finish within"), "{error}");

    let preserve = tempfile::tempdir().unwrap();
    let marker = preserve.path().join("survived");
    let script = format!(
        "#!/bin/sh\n(sleep 1; printf 'survived' > {}) &\nexit 0\n",
        shell(&marker.to_string_lossy())
    );
    let t3 = preserve.path().join("t3");
    write_file(&t3, &script, 0o700);
    let manifest = manifest_file(
        preserve.path(),
        &manifest_value(
            &t3,
            None,
            vec![peer_value(
                &["https://atlas.example.ts.net"],
                "read-only",
                None,
                None,
            )],
        ),
    );
    let options = Config {
        attempts: 1,
        retry_delay: Duration::ZERO,
        desktop_timeout: Duration::from_secs(5),
        owner_timeout: Duration::from_secs(5),
        command_timeout: Duration::from_millis(100),
        ssh: PathBuf::from("ssh"),
    };
    assert!(execute(&manifest, options).is_err());
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    while !marker.exists() && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(25));
    }
    assert!(
        marker.exists(),
        "a descendant of an already-exited child was killed after the direct child was reaped"
    );

    let flood = tempfile::tempdir().unwrap();
    let t3 = flood.path().join("t3");
    write_file(&t3, "#!/bin/sh\nexec yes flood\n", 0o700);
    let manifest = manifest_file(
        flood.path(),
        &manifest_value(
            &t3,
            None,
            vec![peer_value(
                &["https://atlas.example.ts.net"],
                "read-only",
                None,
                None,
            )],
        ),
    );
    let options = Config {
        attempts: 1,
        retry_delay: Duration::ZERO,
        desktop_timeout: Duration::from_secs(5),
        owner_timeout: Duration::from_secs(5),
        command_timeout: Duration::from_millis(300),
        ssh: PathBuf::from("ssh"),
    };
    let error = format!("{:#}", execute(&manifest, options).unwrap_err());
    assert!(
        error.contains("exceeded the 65536-byte output limit"),
        "stdout flood did not fail at the output bound: {error}"
    );
}

#[test]
fn owner_import_failure_revokes_only_new_sessions() {
    let root = tempfile::tempdir().unwrap();
    let urls = ["https://atlas.example.ts.net"];
    let after = links(&[(
        "env_atlas",
        "Atlas",
        &urls,
        "approval-required",
        "reachable",
    )]);
    let t3 = fake_owner_t3(root.path(), "env_atlas", Some(&after), 0);
    write_file(&root.path().join("owner-state/links.json"), &after, 0o600);
    let ssh = fake_ssh(root.path(), false);
    let (desktop, desktop_state) = fake_desktop(root.path(), 99, None);
    let user = current_user();
    let bearer_marker = format!("provenance-t3-enroll:{user}:env_atlas:bearer");
    let ssh_marker = format!("provenance-t3-enroll:{user}:env_atlas:ssh");
    write_file(
        &root.path().join("owner-state/session-list.json"),
        &serde_json::to_string(&json!([
            {"sessionId": "SESSION-OLD-1", "subject": bearer_marker, "client": {"label": bearer_marker}},
            {"sessionId": "SESSION-OLD-2", "subject": ssh_marker, "client": {"label": ssh_marker}},
            {"sessionId": "SESSION-M", "subject": "manual", "client": {"label": "manual"}},
        ]))
        .unwrap(),
        0o600,
    );
    let manifest = manifest_file(
        root.path(),
        &owner_manifest(
            &t3,
            &desktop,
            "peer.example",
            &t3,
            Some("env_atlas"),
            json!({
                "bearer": {
                    "httpBaseUrl": "https://atlas.example.ts.net/",
                    "wsBaseUrl": "wss://atlas.example.ts.net/",
                },
                "ssh": {
                    "alias": "atlas",
                    "hostname": "atlas.example",
                },
            }),
        ),
    );
    let options = Config {
        attempts: 1,
        retry_delay: Duration::ZERO,
        desktop_timeout: Duration::from_secs(5),
        owner_timeout: Duration::from_secs(5),
        command_timeout: Duration::from_secs(5),
        ssh,
    };
    assert!(execute(&manifest, options).is_err());
    assert_eq!(
        fs::read_to_string(root.path().join("owner-state/revoked.log")).unwrap(),
        "SESSION-1\nSESSION-2\n"
    );
    assert!(!desktop_state.join("imported.json").exists());
}

#[test]
fn owner_local_skips_self_link_and_imports_desktop() {
    let root = tempfile::tempdir().unwrap();
    let t3 = fake_owner_t3(root.path(), "env_atlas", None, 1);
    let ssh = fake_ssh(root.path(), false);
    let (desktop, desktop_state) = fake_desktop(root.path(), 0, None);
    let base = base_dir_for(&t3);
    fs::create_dir_all(base.join("userdata")).unwrap();
    fs::set_permissions(base.join("userdata"), fs::Permissions::from_mode(0o700)).unwrap();
    write_file(
        &base.join("userdata/server-runtime.json"),
        &format!(
            "{{\"origin\":\"http://127.0.0.1:3774\",\"pid\":{}}}",
            std::process::id()
        ),
        0o644,
    );
    let mut manifest_value = owner_manifest(
        &t3,
        &desktop,
        "localhost",
        &t3,
        Some("env_atlas"),
        json!({
            "bearer": {
                "httpBaseUrl": "http://127.0.0.1:3774/",
                "wsBaseUrl": "ws://127.0.0.1:3774/",
            },
        }),
    );
    manifest_value["baseDir"] = json!(base.to_string_lossy());
    manifest_value["peers"][0]["owner"]["baseDir"] = json!(base.to_string_lossy());
    manifest_value["peers"][0]["urls"] = json!(["http://127.0.0.1:3774"]);
    let manifest = manifest_file(root.path(), &manifest_value);
    let options = Config {
        attempts: 1,
        retry_delay: Duration::ZERO,
        desktop_timeout: Duration::from_secs(5),
        owner_timeout: Duration::from_secs(5),
        command_timeout: Duration::from_secs(5),
        ssh,
    };
    let summary = execute(&manifest, options.clone()).unwrap();
    assert_eq!(summary.peers[0].environment_id, "env_atlas");
    assert_eq!(
        summary.imported,
        Some(ImportSummary {
            targets: 1,
            profiles: 1,
            credentials: 1,
        })
    );
    let state = root.path().join("owner-state");
    let args = fs::read_to_string(state.join("args.log")).unwrap();
    assert!(!args.contains("environment link"));
    assert!(!args.contains("auth pairing"));
    assert!(args.contains("environment describe"));
    assert!(args.contains("auth session"));
    assert!(!state.join("pairing-count").exists());
    assert_eq!(
        fs::read_to_string(state.join("session-count")).unwrap(),
        "1"
    );
    let imported: Value =
        serde_json::from_slice(&fs::read(desktop_state.join("imported.json")).unwrap()).unwrap();
    assert_eq!(imported["targets"][0]["connectionId"], "bearer:env_atlas");
    assert_eq!(
        fs::read_to_string(desktop_state.join("t3code-home")).unwrap(),
        base.to_string_lossy().as_ref()
    );

    write_file(
        &base.join("userdata/server-runtime.json"),
        &format!(
            "{{\"origin\":\"http://127.0.0.1:3999\",\"pid\":{}}}",
            std::process::id()
        ),
        0o644,
    );
    let error = format!("{:#}", execute(&manifest, options).unwrap_err());
    assert!(error.contains("local T3 runtime origin"), "{error}");
    assert_eq!(
        fs::read_to_string(state.join("session-count")).unwrap(),
        "1"
    );
}

#[test]
fn owner_state_directory_boundaries_never_describe_or_mint() {
    let local = tempfile::tempdir().unwrap();
    let t3 = fake_owner_t3(local.path(), "env_atlas", None, 0);
    let desktop = local.path().join("desktop");
    write_file(&desktop, "#!/bin/sh\nexit 0\n", 0o700);
    let writable = local.path().join("writable");
    fs::create_dir_all(&writable).unwrap();
    fs::set_permissions(&writable, fs::Permissions::from_mode(0o777)).unwrap();
    let target = local.path().join("target");
    fs::create_dir_all(&target).unwrap();
    let symlink = local.path().join("symlink");
    std::os::unix::fs::symlink(&target, &symlink).unwrap();
    let missing = local.path().join("missing");
    for base in [
        PathBuf::from("/etc"),
        writable.clone(),
        symlink.clone(),
        missing.clone(),
    ] {
        let mut manifest = owner_manifest(
            &t3,
            &desktop,
            "localhost",
            &t3,
            Some("env_atlas"),
            Value::Null,
        );
        manifest["peers"][0]["owner"]["baseDir"] = json!(base.to_string_lossy());
        manifest["baseDir"] = json!(base.to_string_lossy());
        let path = manifest_file(local.path(), &manifest);
        let options = Config {
            attempts: 1,
            retry_delay: Duration::ZERO,
            desktop_timeout: Duration::from_secs(5),
            owner_timeout: Duration::from_secs(5),
            command_timeout: Duration::from_secs(5),
            ssh: fake_ssh(local.path(), false),
        };
        let error = format!("{:#}", execute(&path, options).unwrap_err());
        assert!(
            !local.path().join("owner-state/args.log").exists(),
            "{error}"
        );
    }

    let remote = tempfile::tempdir().unwrap();
    let t3 = fake_owner_t3(remote.path(), "env_atlas", None, 0);
    let desktop = remote.path().join("desktop");
    write_file(&desktop, "#!/bin/sh\nexit 0\n", 0o700);
    let writable = remote.path().join("writable");
    fs::create_dir_all(&writable).unwrap();
    fs::set_permissions(&writable, fs::Permissions::from_mode(0o777)).unwrap();
    let target = remote.path().join("target");
    fs::create_dir_all(&target).unwrap();
    let symlink = remote.path().join("symlink");
    std::os::unix::fs::symlink(&target, &symlink).unwrap();

    for (base, override_stat) in [
        (owner_base_dir(&t3), Some("999999 40700")),
        (writable, None),
        (symlink, None),
    ] {
        let mut manifest = owner_manifest(
            &t3,
            &desktop,
            "peer.example",
            &t3,
            Some("env_atlas"),
            Value::Null,
        );
        manifest["peers"][0]["owner"]["baseDir"] = json!(base.to_string_lossy());
        let path = manifest_file(remote.path(), &manifest);
        let options = Config {
            attempts: 1,
            retry_delay: Duration::ZERO,
            desktop_timeout: Duration::from_secs(5),
            owner_timeout: Duration::from_secs(5),
            command_timeout: Duration::from_secs(5),
            ssh: fake_ssh_with(remote.path(), false, override_stat),
        };
        let error = format!("{:#}", execute(&path, options).unwrap_err());
        assert!(
            !remote.path().join("owner-state/args.log").exists(),
            "{error}"
        );
    }
}

#[test]
fn owner_automatic_mints_fresh_codes_and_completes_records() {
    let root = tempfile::tempdir().unwrap();
    let urls = ["https://atlas.example.ts.net"];
    let after = links(&[(
        "env_atlas",
        "Atlas",
        &urls,
        "approval-required",
        "reachable",
    )]);
    let t3 = fake_owner_t3(root.path(), "env_atlas", Some(&after), 1);
    let ssh = fake_ssh(root.path(), false);
    let (desktop, desktop_state) = fake_desktop(root.path(), 0, None);
    let manifest = manifest_file(
        root.path(),
        &owner_manifest(
            &t3,
            &desktop,
            "peer.example",
            &t3,
            None,
            json!({
                "bearer": {
                    "httpBaseUrl": "https://atlas.example.ts.net/",
                    "wsBaseUrl": "wss://atlas.example.ts.net/",
                },
                "ssh": {
                    "alias": "atlas",
                    "hostname": "atlas.example",
                },
            }),
        ),
    );
    let options = Config {
        attempts: 2,
        retry_delay: Duration::ZERO,
        desktop_timeout: Duration::from_secs(5),
        owner_timeout: Duration::from_secs(5),
        command_timeout: Duration::from_secs(5),
        ssh,
    };
    let summary = execute(&manifest, options.clone()).unwrap();
    assert_eq!(summary.peers[0].environment_id, "env_atlas");
    assert_eq!(
        summary.imported,
        Some(ImportSummary {
            targets: 2,
            profiles: 2,
            credentials: 2,
        })
    );
    let state = root.path().join("owner-state");
    let args = fs::read_to_string(state.join("args.log")).unwrap();
    assert!(args.contains("--ttl 5m"));
    assert!(args.contains("--ttl 30d"));
    assert!(args.contains("--scope orchestration:read"));
    assert!(args.contains("--scope orchestration:operate"));
    assert!(!args.contains("--scope settings:write"));
    assert_eq!(
        fs::read_to_string(state.join("link-stdin")).unwrap(),
        "PAIR-1\nPAIR-2\n"
    );
    assert_eq!(
        fs::read_to_string(state.join("session-count")).unwrap(),
        "2"
    );
    let imported: Value =
        serde_json::from_slice(&fs::read(desktop_state.join("imported.json")).unwrap()).unwrap();
    let credentials = imported["credentials"].as_array().unwrap();
    assert!(
        credentials
            .iter()
            .any(|entry| entry["credential"]["token"] == "TOKEN-1")
    );
    assert!(
        credentials
            .iter()
            .any(|entry| entry["credential"]["token"] == "TOKEN-2")
    );
    for log in [
        state.join("args.log"),
        state.join("env.log"),
        root.path().join("ssh-state/ssh.log"),
        desktop_state.join("../desktop.log"),
    ] {
        let text = fs::read_to_string(&log).unwrap();
        assert!(
            !text.contains("PAIR-"),
            "pairing code leaked into {}",
            log.display()
        );
        assert!(
            !text.contains("TOKEN-"),
            "bearer token leaked into {}",
            log.display()
        );
    }

    let user = current_user();
    let bearer_marker = format!("provenance-t3-enroll:{user}:env_atlas:bearer");
    let ssh_marker = format!("provenance-t3-enroll:{user}:env_atlas:ssh");
    write_file(
        &state.join("session-list.json"),
        &serde_json::to_string(&json!([
            {"sessionId": "SESSION-1", "subject": bearer_marker, "client": {"label": bearer_marker}},
            {"sessionId": "SESSION-2", "subject": ssh_marker, "client": {"label": ssh_marker}},
            {"sessionId": "SESSION-M", "subject": "manual", "client": {"label": "manual"}},
        ]))
        .unwrap(),
        0o600,
    );
    execute(&manifest, options).unwrap();
    let imported: Value =
        serde_json::from_slice(&fs::read(desktop_state.join("imported.json")).unwrap()).unwrap();
    let credentials = imported["credentials"].as_array().unwrap();
    assert!(
        credentials
            .iter()
            .any(|entry| entry["credential"]["token"] == "TOKEN-3")
    );
    assert!(
        credentials
            .iter()
            .any(|entry| entry["credential"]["token"] == "TOKEN-4")
    );
    assert_eq!(
        fs::read_to_string(state.join("revoked.log")).unwrap(),
        "SESSION-1\nSESSION-2\n"
    );
    assert_eq!(
        fs::read_to_string(state.join("session-count")).unwrap(),
        "4"
    );
}

#[test]
fn owner_never_mints_for_wrong_remote_owner_or_environment() {
    let wrong_owner = tempfile::tempdir().unwrap();
    let t3 = fake_owner_t3(wrong_owner.path(), "env_atlas", None, 0);
    let ssh = fake_ssh(wrong_owner.path(), true);
    let desktop = wrong_owner.path().join("desktop");
    write_file(&desktop, "#!/bin/sh\nexit 0\n", 0o700);
    let manifest = manifest_file(
        wrong_owner.path(),
        &owner_manifest(
            &t3,
            &desktop,
            "peer.example",
            &t3,
            Some("env_atlas"),
            Value::Null,
        ),
    );
    let options = Config {
        attempts: 1,
        retry_delay: Duration::ZERO,
        desktop_timeout: Duration::from_secs(5),
        owner_timeout: Duration::from_secs(5),
        command_timeout: Duration::from_secs(5),
        ssh,
    };
    let error = format!("{:#}", execute(&manifest, options.clone()).unwrap_err());
    assert!(
        error.contains("does not match the manifest user"),
        "{error}"
    );
    assert!(
        !wrong_owner
            .path()
            .join("owner-state/pairing-count")
            .exists()
    );
    assert!(
        !wrong_owner
            .path()
            .join("owner-state/session-count")
            .exists()
    );

    let mut ambiguous = owner_manifest(
        &t3,
        &desktop,
        "peer.example",
        &t3,
        Some("env_atlas"),
        Value::Null,
    );
    ambiguous["peers"][0]["pairingCodeFile"] = json!("/run/pairing-code");
    let manifest = manifest_file(wrong_owner.path(), &ambiguous);
    let error = format!("{:#}", execute(&manifest, options.clone()).unwrap_err());
    assert!(error.contains("cannot combine"), "{error}");

    let mut ambiguous = owner_manifest(
        &t3,
        &desktop,
        "peer.example",
        &t3,
        Some("env_atlas"),
        json!({
            "bearer": {
                "httpBaseUrl": "https://atlas.example.ts.net/",
                "wsBaseUrl": "wss://atlas.example.ts.net/",
                "credentialFile": "/run/bearer-token",
            },
        }),
    );
    ambiguous["peers"][0]["pairingCodeFile"] = Value::Null;
    let manifest = manifest_file(wrong_owner.path(), &ambiguous);
    let error = format!("{:#}", execute(&manifest, options.clone()).unwrap_err());
    assert!(error.contains("cannot combine"), "{error}");

    let wrong_env = tempfile::tempdir().unwrap();
    let t3 = fake_owner_t3(wrong_env.path(), "env_other", None, 0);
    let ssh = fake_ssh(wrong_env.path(), false);
    let desktop = wrong_env.path().join("desktop");
    write_file(&desktop, "#!/bin/sh\nexit 0\n", 0o700);
    let manifest = manifest_file(
        wrong_env.path(),
        &owner_manifest(
            &t3,
            &desktop,
            "peer.example",
            &t3,
            Some("env_atlas"),
            Value::Null,
        ),
    );
    let options = Config {
        attempts: 1,
        retry_delay: Duration::ZERO,
        desktop_timeout: Duration::from_secs(5),
        owner_timeout: Duration::from_secs(5),
        command_timeout: Duration::from_secs(5),
        ssh,
    };
    let error = format!("{:#}", execute(&manifest, options).unwrap_err());
    assert!(
        error.contains("does not match declared `env_atlas`"),
        "{error}"
    );
    assert!(!wrong_env.path().join("owner-state/pairing-count").exists());
    assert!(!wrong_env.path().join("owner-state/session-count").exists());
}

#[test]
fn secret_straddling_the_diagnostic_bound_never_leaks() {
    let link = tempfile::tempdir().unwrap();
    let pairing_code = format!("CANARY-PAIRING-{}", "a".repeat(80));
    let pairing = link.path().join("pairing-code");
    secret(&pairing, &pairing_code);
    let t3 = link.path().join("t3");
    write_file(
        &t3,
        r#"#!/bin/sh
if [ "$1 $2" = "environment list" ]; then printf '[]'; exit 0; fi
code=$(cat)
padding=$(printf '%4090s' '')
printf '%s%s\n' "$padding" "$code" >&2
exit 1
"#,
        0o700,
    );
    let urls = ["https://atlas.example.ts.net"];
    let manifest = manifest_file(
        link.path(),
        &manifest_value(
            &t3,
            None,
            vec![peer_value(&urls, "read-only", Some(&pairing), None)],
        ),
    );
    let error = format!("{:#}", execute(&manifest, config(1)).unwrap_err());
    assert!(!error.contains("CANARY"), "{error}");
    assert!(error.contains("output was not captured"), "{error}");

    let desktop_case = tempfile::tempdir().unwrap();
    let token_value = format!("CANARY-TOKEN-{}", "b".repeat(80));
    let token = desktop_case.path().join("bearer-token");
    secret(&token, &token_value);
    let (t3, _) = fake_t3(
        desktop_case.path(),
        &links(&[(
            "env_atlas",
            "Atlas",
            &urls,
            "approval-required",
            "reachable",
        )]),
        None,
        0,
    );
    let desktop = desktop_case.path().join("t3-code");
    let script = format!(
        r#"#!/bin/sh
if [ "$1" = "--version" ] && [ "$2" = "--json" ]; then
  printf '{{"version":"9.9.9","capabilities":["import-connections"]}}\n'
  exit 0
fi
padding=$(printf '%4090s' '')
printf '%s%s\n' "$padding" {token} >&2
exit 1
"#,
        token = shell(&token_value),
    );
    write_file(&desktop, &script, 0o700);
    let manifest = manifest_file(
        desktop_case.path(),
        &manifest_value(
            &t3,
            Some(&desktop),
            vec![peer_value(
                &urls,
                "approval-required",
                None,
                Some(json!({
                    "bearer": {
                        "httpBaseUrl": "https://atlas.example.ts.net/",
                        "wsBaseUrl": "wss://atlas.example.ts.net/",
                        "credentialFile": token.to_string_lossy(),
                    },
                })),
            )],
        ),
    );
    let error = format!("{:#}", execute(&manifest, config(1)).unwrap_err());
    assert!(!error.contains("CANARY"), "{error}");
    assert!(error.contains("output was not captured"), "{error}");
}

#[test]
fn preflight_rejects_wrong_destinations_and_non_capable_desktops() {
    let wrong = tempfile::tempdir().unwrap();
    let pairing = wrong.path().join("pairing-code");
    secret(&pairing, "PAIRING-CODE\n");
    let urls = ["https://atlas.example.ts.net"];
    let (t3, t3_state) = fake_t3_for(wrong.path(), "[]", None, 0, "env_other");
    let manifest = manifest_file(
        wrong.path(),
        &manifest_value(
            &t3,
            None,
            vec![peer_value(&urls, "read-only", Some(&pairing), None)],
        ),
    );
    let error = format!("{:#}", execute(&manifest, config(1)).unwrap_err());
    assert!(error.contains("output was not captured"), "{error}");
    assert!(
        !t3_state.join("exchanged").exists(),
        "a link token exchange ran for a destination that was not the expected environment"
    );
    let log = log_lines(&t3_state.join("../t3.log"));
    assert!(log[0].starts_with("environment list --json --base-dir "));
    assert!(log[1].starts_with(&link_command(&urls, "read-only")));

    let old = tempfile::tempdir().unwrap();
    let pairing = old.path().join("pairing-code");
    secret(&pairing, "PAIRING-CODE\n");
    let token = old.path().join("bearer-token");
    secret(&token, "BEARER-TOKEN\n");
    let t3 = old.path().join("t3");
    let (desktop, desktop_state) = fake_desktop_with(old.path(), 0, None, true);
    let manifest = manifest_file(
        old.path(),
        &manifest_value(
            &t3,
            Some(&desktop),
            vec![peer_value(
                &urls,
                "approval-required",
                Some(&pairing),
                Some(json!({
                    "bearer": {
                        "httpBaseUrl": "https://atlas.example.ts.net/",
                        "wsBaseUrl": "wss://atlas.example.ts.net/",
                        "credentialFile": token.to_string_lossy(),
                    },
                })),
            )],
        ),
    );
    let error = format!("{:#}", execute(&manifest, config(1)).unwrap_err());
    assert!(error.contains("capability document"), "{error}");
    assert!(
        !old.path().join("t3.log").exists(),
        "the helper paired before proving the desktop capability"
    );
    assert_eq!(
        log_lines(&desktop_state.join("../desktop.log")),
        vec!["--version --json".to_owned()]
    );
    assert!(!desktop_state.join("import-path").exists());
}

#[test]
fn enrolls_with_private_pipes_and_native_desktop_import() {
    let root = tempfile::tempdir().unwrap();
    let pairing = root.path().join("pairing-code");
    let bearer = root.path().join("bearer-token");
    let ssh = root.path().join("ssh-token");
    secret(&pairing, "PAIRING-CODE\n");
    secret(&bearer, "BEARER-TOKEN\n");
    secret(&ssh, "SSH-TOKEN\n");
    let urls = ["https://atlas.example.ts.net"];
    let (t3, t3_state) = fake_t3(
        root.path(),
        "[]",
        Some(&links(&[(
            "env_atlas",
            "Atlas",
            &urls,
            "approval-required",
            "reachable",
        )])),
        0,
    );
    let (desktop, desktop_state) = fake_desktop(root.path(), 0, None);
    let desktop_routes = json!({
        "bearer": {
            "httpBaseUrl": "https://atlas.example.ts.net/",
            "wsBaseUrl": "wss://atlas.example.ts.net/",
            "credentialFile": bearer.to_string_lossy(),
        },
        "ssh": {
            "alias": "atlas",
            "hostname": "atlas.example",
            "port": 22,
            "credentialFile": ssh.to_string_lossy(),
        },
    });
    let manifest = manifest_file(
        root.path(),
        &manifest_value(
            &t3,
            Some(&desktop),
            vec![peer_value(
                &urls,
                "approval-required",
                Some(&pairing),
                Some(desktop_routes),
            )],
        ),
    );

    let summary = execute(&manifest, config(1)).unwrap();
    assert_eq!(summary.peers.len(), 1);
    assert!(summary.peers[0].linked);
    assert_eq!(summary.peers[0].environment_id, "env_atlas");
    assert_eq!(
        summary.imported,
        Some(ImportSummary {
            targets: 2,
            profiles: 2,
            credentials: 2,
        })
    );

    let t3_log = log_lines(&t3_state.join("../t3.log"));
    assert_eq!(t3_log.len(), 3);
    assert!(t3_log[0].starts_with("environment list --json --base-dir "));
    assert!(t3_log[1].starts_with(&link_command(&urls, "approval-required")));
    assert!(t3_log[2].starts_with("environment list --json --base-dir "));
    assert_eq!(
        fs::read_to_string(t3_state.join("stdin")).unwrap(),
        "PAIRING-CODE\n"
    );
    let t3_text = t3_log.join("\n");
    for secret in ["PAIRING-CODE", "BEARER-TOKEN", "SSH-TOKEN"] {
        assert!(!t3_text.contains(secret), "secret reached T3 argv");
    }

    let desktop_log = log_lines(&desktop_state.join("../desktop.log"));
    assert_eq!(desktop_log.len(), 2);
    assert_eq!(desktop_log[0], "--version --json");
    assert!(desktop_log[1].starts_with("--import-connections "));
    for secret in ["PAIRING-CODE", "BEARER-TOKEN", "SSH-TOKEN"] {
        assert!(
            !desktop_log[1].contains(secret),
            "secret reached desktop argv"
        );
    }
    let import_path = fs::read_to_string(desktop_state.join("import-path"))
        .unwrap()
        .trim()
        .to_owned();
    assert!(
        !Path::new(&import_path).exists(),
        "the private import document was not removed"
    );
    assert_eq!(
        fs::read_to_string(desktop_state.join("import-mode"))
            .unwrap()
            .trim(),
        "600"
    );

    let imported: Value =
        serde_json::from_slice(&fs::read(desktop_state.join("imported.json")).unwrap()).unwrap();
    assert_eq!(imported["schemaVersion"], 1);
    assert_eq!(imported["remoteDpopTokens"], json!([]));
    assert_eq!(imported["disabledEnvironmentIds"], json!([]));
    assert_eq!(
        imported["targets"],
        json!([
            {
                "_tag": "BearerConnectionTarget",
                "environmentId": "env_atlas",
                "label": "Atlas",
                "connectionId": "bearer:env_atlas",
            },
            {
                "_tag": "SshConnectionTarget",
                "environmentId": "env_atlas",
                "label": "Atlas",
                "connectionId": "ssh:env_atlas",
            },
        ])
    );
    assert_eq!(
        imported["profiles"],
        json!([
            {
                "_tag": "BearerConnectionProfile",
                "connectionId": "bearer:env_atlas",
                "environmentId": "env_atlas",
                "label": "Atlas",
                "httpBaseUrl": "https://atlas.example.ts.net/",
                "wsBaseUrl": "wss://atlas.example.ts.net/",
            },
            {
                "_tag": "SshConnectionProfile",
                "connectionId": "ssh:env_atlas",
                "environmentId": "env_atlas",
                "label": "Atlas",
                "target": {
                    "alias": "atlas",
                    "hostname": "atlas.example",
                    "username": current_user(),
                    "port": 22,
                },
            },
        ])
    );
    let credentials = imported["credentials"].as_array().unwrap();
    assert_eq!(credentials.len(), 2);
    assert!(credentials.iter().any(|entry| {
        entry["connectionId"] == "bearer:env_atlas"
            && entry["credential"]["_tag"] == "BearerConnectionCredential"
            && entry["credential"]["token"] == "BEARER-TOKEN"
    }));
    assert!(credentials.iter().any(|entry| {
        entry["connectionId"] == "ssh:env_atlas"
            && entry["credential"]["_tag"] == "BearerConnectionCredential"
            && entry["credential"]["token"] == "SSH-TOKEN"
    }));
    // Every imported non-relay target owns exactly one matching profile and
    // credential; the import never borrows an existing keyring token.
    for target in imported["targets"].as_array().unwrap() {
        let connection_id = &target["connectionId"];
        assert_eq!(
            imported["profiles"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|profile| profile["connectionId"] == *connection_id)
                .count(),
            1,
            "target {connection_id} must own one profile"
        );
        assert_eq!(
            credentials
                .iter()
                .filter(|entry| entry["connectionId"] == *connection_id)
                .count(),
            1,
            "target {connection_id} must own one credential"
        );
    }
    assert!(!imported.to_string().contains("PAIRING-CODE"));
}

#[test]
fn rejects_trust_and_input_boundary_violations_before_linking() {
    let root = tempfile::tempdir().unwrap();
    let pairing = root.path().join("pairing-code");
    secret(&pairing, "PAIRING-CODE\n");
    let (t3, t3_state) = fake_t3(root.path(), "[]", None, 0);
    let t3_log = t3_state.join("../t3.log");

    let rejected_before_t3 = |peers: Vec<Value>, t3: &Path, desktop: Option<&Path>| {
        fs::remove_file(&t3_log).ok();
        let manifest = manifest_file(root.path(), &manifest_value(t3, desktop, peers));
        let error = execute(&manifest, config(1)).unwrap_err();
        let detail = format!("{error:#}");
        assert!(
            !t3_log.exists(),
            "T3 ran before the manifest was validated: {detail}"
        );
        detail
    };

    let error = rejected_before_t3(
        vec![peer_value(
            &["http://atlas.example.com"],
            "read-only",
            Some(&pairing),
            None,
        )],
        &t3,
        None,
    );
    assert!(error.contains("unencrypted"), "{error}");

    let error = rejected_before_t3(
        vec![peer_value(
            &["https://atlas.example.com/api"],
            "read-only",
            Some(&pairing),
            None,
        )],
        &t3,
        None,
    );
    assert!(error.contains("bare origin"), "{error}");

    let error = rejected_before_t3(
        vec![peer_value(
            &["https://atlas.example.com"],
            "read-only",
            Some(&pairing),
            Some(json!({
                "ssh": {
                    "alias": "atlas",
                    "hostname": "atlas\n.example",
                    "credentialFile": root.path().join("ssh-token").to_string_lossy(),
                },
            })),
        )],
        &t3,
        Some(&root.path().join("t3-code")),
    );
    assert!(error.contains("control characters"), "{error}");

    let error = rejected_before_t3(
        vec![peer_value(
            &["https://atlas.example.com"],
            "read-only",
            Some(&pairing),
            Some(json!({
                "ssh": {
                    "alias": "atlas",
                    "hostname": "atlas.example",
                },
            })),
        )],
        &t3,
        Some(&root.path().join("t3-code")),
    );
    assert!(
        error.contains("manual desktop SSH credential file is required"),
        "{error}"
    );

    let error = rejected_before_t3(
        vec![peer_value(
            &["https://atlas.example.com"],
            "read-only",
            Some(&pairing),
            Some(json!({
                "ssh": {
                    "alias": "atlas",
                    "hostname": "atlas.example",
                    "username": "mallory",
                    "credentialFile": root.path().join("ssh-token").to_string_lossy(),
                },
            })),
        )],
        &t3,
        Some(&root.path().join("t3-code")),
    );
    assert!(error.contains("manifest user"), "{error}");

    let error = rejected_before_t3(
        vec![peer_value(
            &["https://atlas.example.com"],
            "read-only",
            Some(Path::new("relative/pairing")),
            None,
        )],
        &t3,
        None,
    );
    assert!(error.contains("absolute"), "{error}");

    let error = rejected_before_t3(
        vec![peer_value(
            &["https://atlas.example.com"],
            "read-only",
            Some(Path::new("/nix/store/not-a-secret")),
            None,
        )],
        &t3,
        None,
    );
    assert!(error.contains("Nix store"), "{error}");

    let error = rejected_before_t3(
        vec![peer_value(
            &["https://atlas.example.com"],
            "read-only",
            Some(&pairing),
            Some(json!({})),
        )],
        &t3,
        Some(Path::new("/run/current-system/sw/bin/t3-code")),
    );
    assert!(
        error.contains("neither a bearer nor an SSH route"),
        "{error}"
    );

    let error = rejected_before_t3(
        vec![peer_value(
            &["https://atlas.example.com"],
            "read-only",
            Some(&pairing),
            Some(json!({
                "bearer": {
                    "httpBaseUrl": "https://atlas.example.com/",
                    "wsBaseUrl": "wss://atlas.example.com/",
                    "credentialFile": root.path().join("token").to_string_lossy(),
                },
            })),
        )],
        &t3,
        None,
    );
    assert!(error.contains("no desktop command"), "{error}");

    let error = rejected_before_t3(
        vec![peer_value(
            &["https://atlas.example.com"],
            "read-only",
            Some(&pairing),
            Some(json!({
                "bearer": {
                    "httpBaseUrl": "http://atlas.example.com/",
                    "wsBaseUrl": "ws://atlas.example.com/",
                    "credentialFile": root.path().join("token").to_string_lossy(),
                },
            })),
        )],
        &t3,
        Some(&root.path().join("t3-code")),
    );
    assert!(error.contains("unencrypted"), "{error}");

    let error = rejected_before_t3(
        vec![peer_value(
            &["https://atlas.example.com"],
            "read-only",
            Some(&pairing),
            Some(json!({
                "bearer": {
                    "httpBaseUrl": "https://atlas.example.com/",
                    "wsBaseUrl": "ws://atlas.example.com/",
                    "credentialFile": root.path().join("token").to_string_lossy(),
                },
            })),
        )],
        &t3,
        Some(&root.path().join("t3-code")),
    );
    assert!(error.contains("websocket URL"), "{error}");

    let error = rejected_before_t3(
        vec![peer_value(
            &["https://atlas.example.com"],
            "read-only",
            Some(&pairing),
            Some(json!({
                "bearer": {
                    "httpBaseUrl": "https://other.example/",
                    "wsBaseUrl": "wss://other.example/",
                    "credentialFile": root.path().join("token").to_string_lossy(),
                },
            })),
        )],
        &t3,
        Some(&root.path().join("t3-code")),
    );
    assert!(error.contains("one of its declared URLs"), "{error}");

    let mut other_user = manifest_value(
        &t3,
        None,
        vec![peer_value(
            &["https://atlas.example.com"],
            "read-only",
            Some(&pairing),
            None,
        )],
    );
    other_user["user"] = json!(format!("{}-other", current_user()));
    fs::remove_file(&t3_log).ok();
    let manifest = manifest_file(root.path(), &other_user);
    let error = format!("{:#}", execute(&manifest, config(1)).unwrap_err());
    assert!(error.contains("is not the effective user"), "{error}");
    assert!(!t3_log.exists());

    // These pass manifest validation but fail when the private input is read.
    let permissive = root.path().join("permissive-pairing");
    write_file(&permissive, "PAIRING-CODE\n", 0o644);
    fs::remove_file(&t3_log).ok();
    let manifest = manifest_file(
        root.path(),
        &manifest_value(
            &t3,
            None,
            vec![peer_value(
                &["https://atlas.example.com"],
                "read-only",
                Some(&permissive),
                None,
            )],
        ),
    );
    let error = format!("{:#}", execute(&manifest, config(1)).unwrap_err());
    assert!(error.contains("mode 0600"), "{error}");
    assert_eq!(
        log_lines(&t3_log).len(),
        1,
        "no link may run before the secret is validated"
    );

    let target = root.path().join("symlink-target");
    secret(&target, "PAIRING-CODE\n");
    let symlinked = root.path().join("symlinked-pairing");
    std::os::unix::fs::symlink(&target, &symlinked).unwrap();
    fs::remove_file(&t3_log).ok();
    let manifest = manifest_file(
        root.path(),
        &manifest_value(
            &t3,
            None,
            vec![peer_value(
                &["https://atlas.example.com"],
                "read-only",
                Some(&symlinked),
                None,
            )],
        ),
    );
    assert!(execute(&manifest, config(1)).is_err());
    assert_eq!(log_lines(&t3_log).len(), 1);

    let oversized = root.path().join("oversized-pairing");
    secret(&oversized, &"x".repeat(8193));
    fs::remove_file(&t3_log).ok();
    let manifest = manifest_file(
        root.path(),
        &manifest_value(
            &t3,
            None,
            vec![peer_value(
                &["https://atlas.example.com"],
                "read-only",
                Some(&oversized),
                None,
            )],
        ),
    );
    let error = format!("{:#}", execute(&manifest, config(1)).unwrap_err());
    assert!(error.contains("8 KiB"), "{error}");
    assert_eq!(log_lines(&t3_log).len(), 1);

    // The desktop token is read only after the peer link verifies, and its file
    // boundary is enforced independently of the pairing code.
    let token_case = tempfile::tempdir().unwrap();
    let pairing = token_case.path().join("pairing-code");
    secret(&pairing, "PAIRING-CODE\n");
    let permissive_token = token_case.path().join("bearer-token");
    write_file(&permissive_token, "BEARER-TOKEN\n", 0o644);
    let (t3, _) = fake_t3(
        token_case.path(),
        "[]",
        Some(&links(&[(
            "env_atlas",
            "Atlas",
            &["https://atlas.example.ts.net"],
            "approval-required",
            "reachable",
        )])),
        0,
    );
    let (desktop, desktop_state) = fake_desktop(token_case.path(), 0, None);
    let manifest = manifest_file(
        token_case.path(),
        &manifest_value(
            &t3,
            Some(&desktop),
            vec![peer_value(
                &["https://atlas.example.ts.net"],
                "approval-required",
                Some(&pairing),
                Some(json!({
                    "bearer": {
                        "httpBaseUrl": "https://atlas.example.ts.net/",
                        "wsBaseUrl": "wss://atlas.example.ts.net/",
                        "credentialFile": permissive_token.to_string_lossy(),
                    },
                })),
            )],
        ),
    );
    let error = format!("{:#}", execute(&manifest, config(1)).unwrap_err());
    assert!(error.contains("mode 0600"), "{error}");
    assert!(
        !log_lines(&desktop_state.join("../desktop.log"))
            .iter()
            .any(|line| line.starts_with("--import-connections"))
    );
}

#[test]
fn keeps_matching_links_and_narrows_mismatched_access() {
    let root = tempfile::tempdir().unwrap();
    let urls = ["https://atlas.example.ts.net"];
    let (t3, t3_state) = fake_t3(
        root.path(),
        &links(&[(
            "env_atlas",
            "Atlas",
            &urls,
            "approval-required",
            "reachable",
        )]),
        None,
        0,
    );
    let manifest = manifest_file(
        root.path(),
        &manifest_value(
            &t3,
            None,
            vec![peer_value(&urls, "approval-required", None, None)],
        ),
    );

    for _ in 0..2 {
        let summary = execute(&manifest, config(1)).unwrap();
        assert!(!summary.peers[0].linked);
        assert_eq!(summary.imported, None);
    }
    let kept_log = log_lines(&t3_state.join("../t3.log"));
    assert_eq!(kept_log.len(), 2);
    assert!(
        kept_log
            .iter()
            .all(|line| line.starts_with("environment list --json --base-dir "))
    );
    assert!(!t3_state.join("stdin").exists());

    // Declared route order is policy: a reversed link does not match, while an
    // ordered subset (offline primary) is a verified alternate route.
    let order = ["https://lan.example.ts.net", "https://vpn.example.ts.net"];
    let reversed = tempfile::tempdir().unwrap();
    let pairing = reversed.path().join("pairing-code");
    secret(&pairing, "PAIRING-CODE\n");
    let (t3, t3_state) = fake_t3(
        reversed.path(),
        &links(&[(
            "env_atlas",
            "Atlas",
            &[order[1], order[0]],
            "approval-required",
            "reachable",
        )]),
        Some(&links(&[(
            "env_atlas",
            "Atlas",
            &order,
            "approval-required",
            "reachable",
        )])),
        0,
    );
    let manifest = manifest_file(
        reversed.path(),
        &manifest_value(
            &t3,
            None,
            vec![peer_value(
                &order,
                "approval-required",
                Some(&pairing),
                None,
            )],
        ),
    );
    let summary = execute(&manifest, config(1)).unwrap();
    assert!(summary.peers[0].linked);
    let log = log_lines(&t3_state.join("../t3.log"));
    assert!(log[1].starts_with(&link_command(&order, "approval-required")));

    let subset = tempfile::tempdir().unwrap();
    let (t3, t3_state) = fake_t3(
        subset.path(),
        &links(&[(
            "env_atlas",
            "Atlas",
            &[order[1]],
            "approval-required",
            "reachable",
        )]),
        None,
        0,
    );
    let manifest = manifest_file(
        subset.path(),
        &manifest_value(
            &t3,
            None,
            vec![peer_value(&order, "approval-required", None, None)],
        ),
    );
    let summary = execute(&manifest, config(1)).unwrap();
    assert!(!summary.peers[0].linked);
    let subset_log = log_lines(&t3_state.join("../t3.log"));
    assert_eq!(subset_log.len(), 1);
    assert!(subset_log[0].starts_with("environment list --json --base-dir "));

    // A broader existing link is replaced with the narrower declaration, and
    // a failed attempt reports the declared access instead of keeping it.
    let narrow = tempfile::tempdir().unwrap();
    let pairing = narrow.path().join("pairing-code");
    secret(&pairing, "PAIRING-CODE\n");
    let (t3, t3_state) = fake_t3(
        narrow.path(),
        &links(&[("env_atlas", "Atlas", &urls, "full-access", "reachable")]),
        Some(&links(&[(
            "env_atlas",
            "Atlas",
            &urls,
            "read-only",
            "reachable",
        )])),
        0,
    );
    let manifest = manifest_file(
        narrow.path(),
        &manifest_value(
            &t3,
            None,
            vec![peer_value(&urls, "read-only", Some(&pairing), None)],
        ),
    );
    let summary = execute(&manifest, config(1)).unwrap();
    assert!(summary.peers[0].linked);
    let log = log_lines(&t3_state.join("../t3.log"));
    assert!(log[1].starts_with(&link_command(&urls, "read-only")));
    assert!(!log.iter().any(|line| line.contains("full-access")));

    let failed = tempfile::tempdir().unwrap();
    let pairing = failed.path().join("pairing-code");
    secret(&pairing, "PAIRING-CODE\n");
    let (t3, t3_state) = fake_t3(
        failed.path(),
        &links(&[("env_atlas", "Atlas", &urls, "full-access", "reachable")]),
        None,
        1,
    );
    let manifest = manifest_file(
        failed.path(),
        &manifest_value(
            &t3,
            None,
            vec![peer_value(&urls, "read-only", Some(&pairing), None)],
        ),
    );
    let error = format!("{:#}", execute(&manifest, config(1)).unwrap_err());
    assert!(error.contains("read-only"), "{error}");
    let log = log_lines(&t3_state.join("../t3.log"));
    assert!(log[1].starts_with(&link_command(&urls, "read-only")));
    assert!(!log.iter().any(|line| line.contains("full-access")));
}

#[test]
fn retries_repeat_the_declared_capability_and_roll_back_wrong_identities() {
    let root = tempfile::tempdir().unwrap();
    let urls = ["https://atlas.example.ts.net"];
    let pairing = root.path().join("pairing-code");
    secret(&pairing, "PAIRING-CODE\n");
    let after = links(&[(
        "env_atlas",
        "Atlas",
        &urls,
        "approval-required",
        "reachable",
    )]);
    let (t3, t3_state) = fake_t3(root.path(), "[]", Some(&after), 1);
    let manifest = manifest_file(
        root.path(),
        &manifest_value(
            &t3,
            None,
            vec![peer_value(&urls, "approval-required", Some(&pairing), None)],
        ),
    );
    let summary = execute(&manifest, config(2)).unwrap();
    assert!(summary.peers[0].linked);
    let log = log_lines(&t3_state.join("../t3.log"));
    assert_eq!(log.len(), 4);
    assert!(log[0].starts_with("environment list --json --base-dir "));
    assert!(log[1].starts_with(&link_command(&urls, "approval-required")));
    assert!(log[2].starts_with(&link_command(&urls, "approval-required")));
    assert!(log[3].starts_with("environment list --json --base-dir "));
    assert_eq!(
        fs::read_to_string(t3_state.join("stdin")).unwrap(),
        "PAIRING-CODE\nPAIRING-CODE\n"
    );

    let exhausted = tempfile::tempdir().unwrap();
    let pairing = exhausted.path().join("pairing-code");
    secret(&pairing, "PAIRING-CODE\n");
    let (t3, t3_state) = fake_t3(exhausted.path(), "[]", None, 2);
    let manifest = manifest_file(
        exhausted.path(),
        &manifest_value(
            &t3,
            None,
            vec![peer_value(&urls, "approval-required", Some(&pairing), None)],
        ),
    );
    assert!(execute(&manifest, config(1)).is_err());
    let exhausted_log = log_lines(&t3_state.join("../t3.log"));
    assert_eq!(exhausted_log.len(), 2);
    assert!(exhausted_log[0].starts_with("environment list --json --base-dir "));
    assert!(exhausted_log[1].starts_with(&link_command(&urls, "approval-required")));

    // A native process that exits before reading stdin must surface the native
    // failure, not a broken-pipe write error.
    let early = tempfile::tempdir().unwrap();
    let pairing = early.path().join("pairing-code");
    secret(&pairing, "PAIRING-CODE\n");
    let t3 = early.path().join("t3");
    write_file(
        &t3,
        "#!/bin/sh\nif [ \"$1 $2\" = \"environment list\" ]; then printf '[]'; exit 0; fi\nprintf 'pairing rejected before stdin\\n' >&2\nexit 3\n",
        0o700,
    );
    let manifest = manifest_file(
        early.path(),
        &manifest_value(
            &t3,
            None,
            vec![peer_value(&urls, "approval-required", Some(&pairing), None)],
        ),
    );
    let error = format!("{:#}", execute(&manifest, config(1)).unwrap_err());
    assert!(error.contains("output was not captured"), "{error}");
    assert!(!error.contains("writing the pairing code"), "{error}");

    let wrong_identity = tempfile::tempdir().unwrap();
    let pairing = wrong_identity.path().join("pairing-code");
    secret(&pairing, "PAIRING-CODE\n");
    let (t3, t3_state) = fake_t3(
        wrong_identity.path(),
        "[]",
        Some(&links(&[(
            "env_other",
            "Other",
            &urls,
            "approval-required",
            "reachable",
        )])),
        0,
    );
    let (desktop, desktop_state) = fake_desktop(wrong_identity.path(), 0, None);
    let manifest = manifest_file(
        wrong_identity.path(),
        &manifest_value(
            &t3,
            Some(&desktop),
            vec![peer_value(
                &urls,
                "approval-required",
                Some(&pairing),
                Some(json!({
                    "bearer": {
                        "httpBaseUrl": "https://atlas.example.ts.net/",
                        "wsBaseUrl": "wss://atlas.example.ts.net/",
                        "credentialFile": wrong_identity.path().join("token").to_string_lossy(),
                    },
                })),
            )],
        ),
    );
    let error = format!("{:#}", execute(&manifest, config(1)).unwrap_err());
    assert!(
        error.contains("does not show that environment id"),
        "{error}"
    );
    assert!(!t3_state.join("unlinked").exists());
    assert!(
        !log_lines(&desktop_state.join("../desktop.log"))
            .iter()
            .any(|line| line.starts_with("--import-connections"))
    );

    let wrong_access = tempfile::tempdir().unwrap();
    let pairing = wrong_access.path().join("pairing-code");
    secret(&pairing, "PAIRING-CODE\n");
    let (t3, t3_state) = fake_t3(
        wrong_access.path(),
        "[]",
        Some(&links(&[(
            "env_atlas",
            "Atlas",
            &urls,
            "full-access",
            "reachable",
        )])),
        0,
    );
    let manifest = manifest_file(
        wrong_access.path(),
        &manifest_value(
            &t3,
            None,
            vec![peer_value(&urls, "read-only", Some(&pairing), None)],
        ),
    );
    let error = format!("{:#}", execute(&manifest, config(1)).unwrap_err());
    assert!(error.contains("not the declared `read-only`"), "{error}");
    assert!(!t3_state.join("unlinked").exists());
}

#[test]
fn retries_desktop_import_with_the_same_private_document_and_bounds_it() {
    let root = tempfile::tempdir().unwrap();
    let urls = ["https://atlas.example.ts.net"];
    let token = root.path().join("bearer-token");
    secret(&token, "BEARER-TOKEN\n");
    let (t3, _) = fake_t3(
        root.path(),
        &links(&[(
            "env_atlas",
            "Atlas",
            &urls,
            "approval-required",
            "reachable",
        )]),
        None,
        0,
    );
    let (desktop, desktop_state) = fake_desktop(root.path(), 1, None);
    let manifest = manifest_file(
        root.path(),
        &manifest_value(
            &t3,
            Some(&desktop),
            vec![peer_value(
                &urls,
                "approval-required",
                None,
                Some(json!({
                    "bearer": {
                        "httpBaseUrl": "https://atlas.example.ts.net/",
                        "wsBaseUrl": "wss://atlas.example.ts.net/",
                        "credentialFile": token.to_string_lossy(),
                    },
                })),
            )],
        ),
    );
    let summary = execute(&manifest, config(2)).unwrap();
    assert_eq!(
        summary.imported,
        Some(ImportSummary {
            targets: 1,
            profiles: 1,
            credentials: 1,
        })
    );
    let log = log_lines(&desktop_state.join("../desktop.log"));
    assert_eq!(log[0], "--version --json");
    let imports: Vec<_> = log
        .iter()
        .filter(|line| line.starts_with("--import-connections"))
        .collect();
    assert_eq!(imports.len(), 2);
    assert_eq!(
        imports[0], imports[1],
        "retries must reuse the same document"
    );
    for secret in ["PAIRING-CODE", "BEARER-TOKEN"] {
        assert!(!log.join("\n").contains(secret));
    }

    // A broken adapter that echoes its input must not leak the token through
    // the helper's error output.
    let leak = tempfile::tempdir().unwrap();
    let token = leak.path().join("bearer-token");
    secret(&token, "BEARER-TOKEN\n");
    let (t3, _) = fake_t3(
        leak.path(),
        &links(&[(
            "env_atlas",
            "Atlas",
            &urls,
            "approval-required",
            "reachable",
        )]),
        None,
        0,
    );
    let (desktop, _) = fake_desktop(leak.path(), 1, None);
    let manifest = manifest_file(
        leak.path(),
        &manifest_value(
            &t3,
            Some(&desktop),
            vec![peer_value(
                &urls,
                "approval-required",
                None,
                Some(json!({
                    "bearer": {
                        "httpBaseUrl": "https://atlas.example.ts.net/",
                        "wsBaseUrl": "wss://atlas.example.ts.net/",
                        "credentialFile": token.to_string_lossy(),
                    },
                })),
            )],
        ),
    );
    let error = format!("{:#}", execute(&manifest, config(1)).unwrap_err());
    assert!(!error.contains("BEARER-TOKEN"), "{error}");
    assert!(error.contains("output was not captured"), "{error}");

    let timed_out = tempfile::tempdir().unwrap();
    let token = timed_out.path().join("bearer-token");
    secret(&token, "BEARER-TOKEN\n");
    let (t3, _) = fake_t3(
        timed_out.path(),
        &links(&[(
            "env_atlas",
            "Atlas",
            &urls,
            "approval-required",
            "reachable",
        )]),
        None,
        0,
    );
    let (desktop, desktop_state) = fake_desktop(timed_out.path(), 0, Some(2));
    let manifest = manifest_file(
        timed_out.path(),
        &manifest_value(
            &t3,
            Some(&desktop),
            vec![peer_value(
                &urls,
                "approval-required",
                None,
                Some(json!({
                    "bearer": {
                        "httpBaseUrl": "https://atlas.example.ts.net/",
                        "wsBaseUrl": "wss://atlas.example.ts.net/",
                        "credentialFile": token.to_string_lossy(),
                    },
                })),
            )],
        ),
    );
    let options = Config {
        attempts: 1,
        retry_delay: Duration::ZERO,
        desktop_timeout: Duration::from_millis(100),
        owner_timeout: Duration::from_secs(5),
        command_timeout: Duration::from_secs(5),
        ssh: PathBuf::from("ssh"),
    };
    let error = format!("{:#}", execute(&manifest, options).unwrap_err());
    assert!(error.contains("did not finish"), "{error}");
    let import_path = fs::read_to_string(desktop_state.join("import-path"))
        .unwrap()
        .trim()
        .to_owned();
    assert!(
        !Path::new(&import_path).exists(),
        "a timed-out import left the private document behind"
    );
}
