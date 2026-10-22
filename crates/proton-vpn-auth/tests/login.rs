//! Exercise actual client prompts using ciphertext-only account fixtures.
mod support;
use age::secrecy::ExposeSecret;
use std::fs::{self, File};
use std::io::Write;
use std::os::unix::{fs::PermissionsExt, process::CommandExt};
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};
use support::LogindFixture;
use tempfile::{TempDir, tempdir};

const PASSWORD: &str = "private-password-not-an-argument";
const SEED: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
const CLIENT: &str = r#"#!/usr/bin/env python3
import base64, getpass, hashlib, hmac, os, pathlib, resource, struct, sys, time
scenario = os.environ['SCENARIO']
state = pathlib.Path(os.environ['STATE'])
with open(os.environ['CALLS'], 'a') as log:
    log.write(' '.join(sys.argv[1:]) + '\n')
assert 'private-password-not-an-argument' not in sys.argv
assert 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ' not in sys.argv
assert not any('private-password-not-an-argument' in v or 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ' in v for v in os.environ.values())
assert resource.getrlimit(resource.RLIMIT_CORE) == (0, 0)
assert pathlib.Path('/proc/self/coredump_filter').read_text().strip() == '00000000'
status = pathlib.Path('/proc/%d/status' % os.getppid()).read_text()
locked = next(line for line in status.splitlines() if line.startswith('VmLck:'))
assert int(locked.split()[1]) > 0, 'credential memory was not locked'
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

struct Fixture {
    directory: TempDir,
    logind: LogindFixture,
    identity: age::x25519::Identity,
}

impl Fixture {
    fn new(totp: bool) -> Self {
        let directory = tempdir().expect("ciphertext fixture directory");
        let python = Command::new("python3")
            .args(["-c", "import sys; print(sys.executable)"])
            .output()
            .expect("fixture Python");
        assert!(python.status.success());
        let interpreter = String::from_utf8(python.stdout).expect("Python path");
        fs::write(
            directory.path().join("client"),
            CLIENT.replacen(
                "#!/usr/bin/env python3",
                &format!("#!{}", interpreter.trim()),
                1,
            ),
        )
        .expect("fixture client");
        fs::set_permissions(
            directory.path().join("client"),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        let identity = age::x25519::Identity::generate();
        fs::write(
            directory.path().join("identity"),
            identity.to_string().expose_secret(),
        )
        .expect("synthetic identity");
        fs::set_permissions(
            directory.path().join("identity"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        let fixture = Self {
            directory,
            logind: LogindFixture::new(),
            identity,
        };
        let mut account = serde_json::json!({"username": "test-user", "password": PASSWORD});
        if totp {
            account["totpSecret"] = SEED.into();
        }
        fixture.encrypt(&account);
        fixture
    }

    fn path(&self) -> &Path {
        self.directory.path()
    }

    fn encrypt(&self, document: &serde_json::Value) {
        let recipient = self.identity.to_public();
        let encryptor =
            age::Encryptor::with_recipients(std::iter::once(&recipient as &dyn age::Recipient))
                .expect("fixture recipient");
        let file = File::create(self.path().join("account.age")).expect("fixture ciphertext");
        let mut encrypted = encryptor.wrap_output(file).expect("age output");
        serde_json::to_writer(&mut encrypted, document)
            .expect("stream synthetic document into encryption");
        encrypted.finish().expect("finish encrypted document");
    }

    fn command(&self, scenario: &str) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_proton-vpn-auth"));
        command
            .args(["login", "--encrypted-file"])
            .arg(self.path().join("account.age"))
            .arg("--identity")
            .arg(self.path().join("identity"))
            .arg("--cli")
            .arg(self.path().join("client"))
            .args(["--setsid", "setsid", "--timeout-seconds", "1"])
            .env("XDG_RUNTIME_DIR", self.path())
            .env("SCENARIO", scenario)
            .env("STATE", self.path().join("state"))
            .env("CALLS", self.path().join("calls"));
        self.logind.configure(&mut command);
        command
    }

    fn run(&self, scenario: &str) -> Output {
        self.command(scenario).output().expect("adapter execution")
    }

    fn no_plaintext(&self) {
        for entry in fs::read_dir(self.path()).expect("fixture artifacts") {
            let entry = entry.expect("artifact");
            let name = entry.file_name();
            assert!(
                matches!(
                    name.to_str(),
                    Some(
                        "identity"
                            | "client"
                            | "account.age"
                            | "calls"
                            | "state"
                            | "nix-provenance-proton-vpn.lock"
                    )
                ),
                "unexpected credential artifact: {name:?}"
            );
            if name != "client" {
                let bytes = fs::read(entry.path()).expect("artifact contents");
                assert!(
                    !bytes
                        .windows(SEED.len())
                        .any(|bytes| bytes == SEED.as_bytes())
                );
                assert!(
                    !bytes
                        .windows(PASSWORD.len())
                        .any(|bytes| bytes == PASSWORD.as_bytes())
                );
            }
        }
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
    assert!(!logs.contains(SEED), "seed escaped into adapter output");
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
        fixture.no_plaintext();
    }
    assert_eq!(
        fs::read_to_string(fixture.path().join("calls")).unwrap(),
        "info\nsignin -- test-user\ninfo\ninfo\n"
    );
}

#[test]
fn supports_password_only_accounts() {
    let fixture = Fixture::new(false);
    let output = fixture.run("password-only");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    redacted(&output);
    fixture.no_plaintext();
}

#[test]
fn missing_second_factor_and_rejected_credentials_are_terminal_and_redacted() {
    for (totp, scenario) in [(false, "totp"), (true, "reject")] {
        let fixture = Fixture::new(totp);
        let output = fixture.run(scenario);
        assert_eq!(output.status.code(), Some(2));
        redacted(&output);
        fixture.no_plaintext();
    }
}

#[test]
fn gui_zero_exit_and_network_failure_are_retryable() {
    for scenario in ["busy", "network"] {
        let fixture = Fixture::new(true);
        let output = fixture.run(scenario);
        assert_eq!(
            output.status.code(),
            Some(75),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        redacted(&output);
    }
}

#[test]
fn preserves_a_different_account_without_signing_out() {
    let fixture = Fixture::new(true);
    fs::write(fixture.path().join("state"), "other-user").unwrap();
    assert_eq!(fixture.run("totp").status.code(), Some(2));
    assert_eq!(
        fs::read_to_string(fixture.path().join("calls")).unwrap(),
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
    fixture.no_plaintext();
    let lock = File::create(fixture.path().join("nix-provenance-proton-vpn.lock")).unwrap();
    lock.lock().unwrap();
    assert_eq!(fixture.run("totp").status.code(), Some(75));
}

#[test]
fn rejects_public_identities_and_malformed_documents_without_echoing_them() {
    let fixture = Fixture::new(true);
    fs::set_permissions(
        fixture.path().join("identity"),
        fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    assert_eq!(fixture.run("totp").status.code(), Some(2));
    assert!(!fixture.path().join("calls").exists());
    fs::set_permissions(
        fixture.path().join("identity"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    fixture.encrypt(&serde_json::json!({PASSWORD: true}));
    let output = fixture.run("totp");
    assert_eq!(output.status.code(), Some(2));
    redacted(&output);
    fixture.no_plaintext();
}

#[test]
fn wrong_identity_and_corrupted_ciphertext_fail_before_client_invocation() {
    let fixture = Fixture::new(true);
    let wrong = age::x25519::Identity::generate();
    fs::write(
        fixture.path().join("identity"),
        wrong.to_string().expose_secret(),
    )
    .unwrap();
    let output = fixture.run("totp");
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("Cannot decrypt"));
    redacted(&output);
    assert!(!fixture.path().join("calls").exists());
    fs::write(
        fixture.path().join("identity"),
        fixture.identity.to_string().expose_secret(),
    )
    .unwrap();
    let mut ciphertext = fs::read(fixture.path().join("account.age")).unwrap();
    *ciphertext.last_mut().unwrap() ^= 1;
    fs::write(fixture.path().join("account.age"), ciphertext).unwrap();
    let output = fixture.run("totp");
    assert_eq!(output.status.code(), Some(2));
    redacted(&output);
    assert!(!fixture.path().join("calls").exists());
    fixture.no_plaintext();
}

#[test]
fn denied_memory_lock_fails_before_client_invocation() {
    let fixture = Fixture::new(true);
    let mut command = fixture.command("totp");
    // SAFETY: pre_exec only changes a process-local limit using a stack rlimit.
    unsafe {
        command.pre_exec(|| {
            let limit = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            if libc::setrlimit(libc::RLIMIT_MEMLOCK, &limit) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let output = command.output().unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("lock credential memory"));
    assert!(!fixture.path().join("calls").exists());
    fixture.no_plaintext();
}

#[test]
fn in_progress_sleep_blocks_credential_handling_before_client_invocation() {
    let fixture = Fixture::new(true);
    let sleeping = LogindFixture::with_sleep_state(true);
    let mut command = fixture.command("totp");
    sleeping.configure(&mut command);
    let output = command.output().unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("sleep transition"));
    redacted(&output);
    assert!(!fixture.path().join("calls").exists());
    fixture.no_plaintext();
}

#[test]
fn forced_termination_does_not_leave_plaintext() {
    let fixture = Fixture::new(true);
    let mut command = fixture.command("hang");
    command.stdout(Stdio::null()).stderr(Stdio::null());
    let mut child = command.spawn().unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    while !fixture.path().join("calls").exists() && Instant::now() < deadline {
        std::thread::yield_now();
    }
    assert!(
        fixture.path().join("calls").exists(),
        "client did not start before deadline"
    );
    child.kill().unwrap();
    child.wait().unwrap();
    fixture.no_plaintext();
}

#[test]
fn rekeyed_ssh_recipient_is_supported_without_plaintext_files() {
    let fixture = Fixture::new(true);
    // Synthetic disposable key; metadata identity overrides are explicitly fixture-only.
    assert!(
        Command::new("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "", "-f"])
            .arg(fixture.path().join("ssh-identity"))
            .status()
            .unwrap()
            .success()
    );
    let recipient: age::ssh::Recipient =
        fs::read_to_string(fixture.path().join("ssh-identity.pub"))
            .unwrap()
            .trim()
            .parse()
            .unwrap();
    let encryptor =
        age::Encryptor::with_recipients(std::iter::once(&recipient as &dyn age::Recipient))
            .unwrap();
    let mut encrypted = encryptor
        .wrap_output(File::create(fixture.path().join("account.age")).unwrap())
        .unwrap();
    encrypted.write_all(serde_json::to_string(&serde_json::json!({"username":"test-user", "password":PASSWORD, "totpSecret":SEED})).unwrap().as_bytes()).unwrap();
    encrypted.finish().unwrap();
    let mut command = fixture.command("totp");
    command
        .arg("--identity")
        .arg(fixture.path().join("ssh-identity"));
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    redacted(&output);
    assert!(!fixture.path().join("account.json").exists());
}

#[test]
fn rsa_home_identities_are_rejected_before_any_private_key_decryption() {
    let fixture = Fixture::new(true);
    assert!(
        Command::new("ssh-keygen")
            .args(["-q", "-t", "rsa", "-b", "2048", "-N", "", "-f"])
            .arg(fixture.path().join("rsa-identity"))
            .status()
            .unwrap()
            .success()
    );
    let mut command = fixture.command("totp");
    command
        .arg("--identity")
        .arg(fixture.path().join("rsa-identity"));
    let output = command.output().unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("only SSH-ed25519 or X25519"));
    redacted(&output);
    assert!(!fixture.path().join("calls").exists());
}
