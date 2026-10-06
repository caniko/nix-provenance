use std::fs::{self, File};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Output};
use std::time::{Duration, Instant};
use tempfile::{TempDir, tempdir};

const PASSWORD: &str = "private-password-not-an-argument";
const SEED: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

// Exercise Python's actual getpass fallback, as used by the pinned stock CLI.
const CLIENT: &str = r#"#!/usr/bin/env python3
import base64, getpass, hashlib, hmac, os, pathlib, struct, sys, time
scenario = os.environ['SCENARIO']
state = pathlib.Path(os.environ['STATE'])
with open(os.environ['CALLS'], 'a') as log:
    log.write(' '.join(sys.argv[1:]) + '\n')
assert 'private-password-not-an-argument' not in sys.argv
assert 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ' not in sys.argv
assert not any('private-password-not-an-argument' in v or 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ' in v for v in os.environ.values())
if scenario == 'busy':
    print('Error: Proton VPN desktop app is currently running')
    sys.exit(0)
if scenario == 'network':
    print('Error: Network connectivity issues detected.', file=sys.stderr)
    sys.exit(1)
if scenario == 'hang':
    time.sleep(60)
if sys.argv[1] == 'info':
    print("Account: '%s'" % (state.read_text() if state.exists() else 'None'))
else:
    assert sys.argv[1:] == ['signin', '--', 'test-user']
    assert getpass.getpass() == 'private-password-not-an-argument'
    if scenario == 'reject':
        print('Error: private-password-not-an-argument GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', file=sys.stderr)
        sys.exit(1)
    if scenario != 'password-only':
        code = getpass.getpass('2FA Token: ')
        valid = []
        for step in [-1, 0, 1]:
            digest = hmac.new(base64.b32decode('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'), struct.pack('>Q', int(time.time()) // 30 + step), hashlib.sha1).digest()
            offset = digest[-1] & 15
            valid.append('%06d' % ((struct.unpack('>I', digest[offset:offset+4])[0] & 0x7fffffff) % 1000000))
        assert code in valid
    if scenario != 'not-persisted':
        state.write_text('test-user')
    print("Successfully signed in as 'test-user'")
"#;

struct Fixture(TempDir);

impl Fixture {
    fn new(totp: bool) -> Self {
        let dir = tempdir().expect("test directory");
        let python = Command::new("python3")
            .args(["-c", "import sys; print(sys.executable)"])
            .output()
            .expect("Python must be present in the project development/test environment");
        assert!(python.status.success(), "resolve fixture interpreter");
        let interpreter = String::from_utf8(python.stdout).expect("Python interpreter path");
        // Nix sandboxes do not have /usr/bin/env.
        let client = CLIENT.replacen(
            "#!/usr/bin/env python3",
            &format!("#!{}", interpreter.trim()),
            1,
        );
        fs::write(dir.path().join("client"), client).expect("fake client");
        fs::set_permissions(dir.path().join("client"), fs::Permissions::from_mode(0o700))
            .expect("client executable");
        let mut credentials = serde_json::json!({"username": "test-user", "password": PASSWORD});
        if totp {
            credentials["totpSecret"] = SEED.into();
        }
        let file = dir.path().join("account.json");
        fs::write(&file, credentials.to_string()).expect("credentials");
        fs::set_permissions(file, fs::Permissions::from_mode(0o600)).expect("private credentials");
        Self(dir)
    }

    fn path(&self) -> &Path {
        self.0.path()
    }

    fn run(&self, scenario: &str) -> Output {
        Command::new(env!("CARGO_BIN_EXE_proton-vpn-auth"))
            .arg("login")
            .arg("--credentials-file")
            .arg(self.path().join("account.json"))
            .arg("--cli")
            .arg(self.path().join("client"))
            .args(["--setsid", "setsid", "--timeout-seconds", "1"])
            .env("XDG_RUNTIME_DIR", self.path())
            .env("SCENARIO", scenario)
            .env("STATE", self.path().join("state"))
            .env("CALLS", self.path().join("calls"))
            .output()
            .expect("run adapter")
    }
}

fn redacted(output: &Output) {
    let logs = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !logs.contains(PASSWORD),
        "password escaped into adapter output"
    );
    assert!(
        !logs.contains(SEED),
        "TOTP seed escaped into adapter output"
    );
}

#[test]
fn authenticates_with_totp_and_reuses_persisted_session() {
    let fixture = Fixture::new(true);
    for _ in 0..2 {
        let output = fixture.run("totp");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        redacted(&output);
    }
    assert_eq!(
        fs::read_to_string(fixture.path().join("calls")).expect("calls"),
        "info\nsignin -- test-user\ninfo\ninfo\n"
    );
}

#[test]
fn supports_password_only_accounts() {
    let output = Fixture::new(false).run("password-only");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    redacted(&output);
}

#[test]
fn missing_second_factor_and_rejected_credentials_are_terminal_and_redacted() {
    for (totp, scenario) in [(false, "totp"), (true, "reject")] {
        let output = Fixture::new(totp).run(scenario);
        assert_eq!(output.status.code(), Some(2));
        redacted(&output);
    }
}

#[test]
fn gui_zero_exit_and_network_failure_are_retryable() {
    for scenario in ["busy", "network"] {
        let output = Fixture::new(true).run(scenario);
        assert_eq!(output.status.code(), Some(75));
        redacted(&output);
    }
}

#[test]
fn preserves_a_different_account_without_signing_out() {
    let fixture = Fixture::new(true);
    fs::write(fixture.path().join("state"), "other-user").expect("existing account");
    let output = fixture.run("totp");
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(
        fs::read_to_string(fixture.path().join("calls")).expect("calls"),
        "info\n"
    );
}

#[test]
fn successful_exit_without_persisted_session_is_not_accepted() {
    assert_eq!(
        Fixture::new(true).run("not-persisted").status.code(),
        Some(2)
    );
}

#[test]
fn timeouts_and_competing_logins_are_bounded() {
    let fixture = Fixture::new(true);
    let started = Instant::now();
    assert_eq!(fixture.run("hang").status.code(), Some(75));
    assert!(started.elapsed() < Duration::from_secs(5));
    let lock = File::create(fixture.path().join("nix-provenance-proton-vpn.lock")).expect("lock");
    lock.lock().expect("hold lock");
    assert_eq!(fixture.run("totp").status.code(), Some(75));
}

#[test]
fn rejects_public_or_malformed_credential_files_without_echoing_them() {
    let fixture = Fixture::new(true);
    let path = fixture.path().join("account.json");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("public mode");
    assert_eq!(fixture.run("totp").status.code(), Some(2));
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("private mode");
    fs::write(path, format!("{{\"{PASSWORD}\": true}}")).expect("invalid JSON");
    let output = fixture.run("totp");
    assert_eq!(output.status.code(), Some(2));
    redacted(&output);
}
