//! Exercise actual controlling-terminal prompts, not a substituted input reader.
mod support;
use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Output, Stdio};
use support::LogindFixture;
use tempfile::{TempDir, tempdir};

const INTERACTIVE: &str = r#"
import errno, os, pty, select, signal, sys, termios, time
binary, path, mode = sys.argv[1:]
readfd, writefd = os.pipe()
pid, master = pty.fork()
if pid == 0:
    os.close(readfd)
    os.dup2(writefd, 1)
    os.close(writefd)
    os.execv(binary, [binary, 'enroll', '--stdout'])
os.close(writefd)
responses = [
    (b'Proton account username: ', b'enrollment-fixture-user'),
    (b'Proton account password: ', b'enrollment-fixture-password'),
    (b'Repeat password: ', b'other-password' if mode == 'mismatch' else b'enrollment-fixture-password'),
]
if mode != 'mismatch':
    responses += [
        (b'not the six-digit code): ', b'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'),
        (b'Repeat authenticator seed: ', b'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'),
    ]
transcript = b''
pending = b''
deadline = time.monotonic() + 10
status = None
try:
    while time.monotonic() < deadline:
        if select.select([master], [], [], 0.02)[0]:
            try:
                chunk = os.read(master, 8192)
            except OSError as error:
                if error.errno != errno.EIO:
                    raise
                chunk = b''
            transcript += chunk
            pending += chunk
        # rpassword prints its prompt before switching the tty to raw/noecho.
        # Deliver input only once the terminal is actually ready for secrets.
        if responses and responses[0][0] in pending:
            if not termios.tcgetattr(master)[3] & termios.ECHO:
                prompt, response = responses.pop(0)
                pending = pending.split(prompt, 1)[1]
                os.write(master, response + b'\n')
        exited, observed = os.waitpid(pid, os.WNOHANG)
        if exited:
            status = os.waitstatus_to_exitcode(observed)
            break
    assert status is not None, 'enrollment prompt exceeded deadline'
    assert not responses, 'enrollment skipped a required prompt'
    assert status == (2 if mode == 'mismatch' else 0), 'enrollment exit status'
    for secret in [b'enrollment-fixture-user', b'enrollment-fixture-password', b'other-password', b'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ']:
        assert secret not in transcript, 'credential echoed on the controlling terminal'
    document = os.read(readfd, 65537)
    if mode == 'mismatch':
        assert not document, 'rejected credentials reached encryption pipe'
    else:
        import json
        assert json.loads(document) == {'username':'enrollment-fixture-user', 'password':'enrollment-fixture-password', 'totpSecret':'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'}
    assert not os.path.exists(path), 'plaintext document was written'
finally:
    if status is None:
        os.kill(pid, signal.SIGKILL)
        os.waitpid(pid, 0)
    os.close(master)
    os.close(readfd)
"#;

fn runtime() -> TempDir {
    let directory = tempdir().expect("runtime fixture");
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
        .expect("private runtime");
    directory
}

fn interactive(mode: &str, directory: &TempDir) {
    let logind = LogindFixture::new();
    let mut command = Command::new("python3");
    command
        .args(["-c", INTERACTIVE, env!("CARGO_BIN_EXE_proton-vpn-auth")])
        .arg(directory.path().join("account.json"))
        .arg(mode)
        .env("XDG_RUNTIME_DIR", directory.path());
    logind.configure(&mut command);
    let output = command.output().expect("PTY test interpreter");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn hidden_prompts_stream_the_exact_document_without_plaintext_files() {
    let directory = runtime();
    interactive("success", &directory);
    assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 0);
}

#[test]
fn confirmation_failure_leaves_no_document_and_no_echo() {
    let directory = runtime();
    interactive("mismatch", &directory);
    assert!(!directory.path().join("account.json").exists());
}

#[test]
fn destinations_outside_runtime_and_symlink_escapes_fail_before_prompting() {
    let directory = runtime();
    let outside = runtime();
    std::os::unix::fs::symlink(outside.path(), directory.path().join("escape"))
        .expect("symlink fixture");
    for path in [
        outside.path().join("account.json"),
        directory.path().join("escape/account.json"),
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_proton-vpn-auth"))
            .args(["enroll", "--out"])
            .arg(&path)
            .env("XDG_RUNTIME_DIR", directory.path())
            .output()
            .expect("enrollment executable");
        assert_eq!(output.status.code(), Some(2));
        let error = String::from_utf8_lossy(&output.stderr);
        assert!(error.contains("unexpected argument '--out'"));
        assert!(!error.contains("username:"));
        assert!(!path.exists());
    }
}

fn piped(document: &[u8], password_only: bool) -> Output {
    let logind = LogindFixture::new();
    let mut command = Command::new(env!("CARGO_BIN_EXE_proton-vpn-auth"));
    command.args(["enroll", "--stdin", "--stdout"]);
    if password_only {
        command.arg("--password-only");
    }
    logind.configure(&mut command);
    let mut child = command
        .env_remove("XDG_RUNTIME_DIR")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("pipe enrollment executable");
    let _ = child
        .stdin
        .take()
        .expect("private input pipe")
        .write_all(document);
    child.wait_with_output().expect("pipe enrollment result")
}

#[test]
fn regular_file_output_is_rejected_before_plaintext_is_read_or_written() {
    let logind = LogindFixture::new();
    let directory = tempdir().unwrap();
    let destination = directory.path().join("forbidden.json");
    let mut command = Command::new(env!("CARGO_BIN_EXE_proton-vpn-auth"));
    command
        .args(["enroll", "--stdin", "--stdout"])
        .stdin(Stdio::null())
        .stdout(Stdio::from(fs::File::create(&destination).unwrap()));
    logind.configure(&mut command);
    let output = command.output().unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("private stdout pipe"));
    assert_eq!(fs::metadata(destination).unwrap().len(), 0);
}

#[test]
fn pipe_enrollment_normalizes_seed_and_uri_without_creating_runtime_files() {
    for seed in [
        "gezd gnbv gy3t qojq gezd gnbv gy3t qojq",
        "otpauth://totp/Proton:fixture?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Proton&algorithm=SHA1&digits=6&period=30",
        "otpauth://totp/Proton:fixture?secret=%47EZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
    ] {
        let input = serde_json::to_vec(&serde_json::json!({
            "username": "pipe-fixture-user",
            "password": "pipe-fixture-password",
            "totpSecret": seed,
        }))
        .expect("credential fixture");
        let output = piped(&input, false);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let account: serde_json::Value =
            serde_json::from_slice(&output.stdout).expect("canonical document");
        assert_eq!(account["username"], "pipe-fixture-user");
        assert_eq!(account["password"], "pipe-fixture-password");
        assert_eq!(account["totpSecret"], "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
        assert!(output.stderr.is_empty());
    }
}

#[test]
fn pipe_enrollment_rejects_incompatible_or_ambiguous_totp_without_output() {
    for seed in [
        "otpauth://hotp/fixture?secret=GEZDGNBVGY3TQOJQ&counter=1",
        "otpauth://totp/fixture?secret=GEZDGNBVGY3TQOJQ&algorithm=SHA256",
        "otpauth://totp/fixture?secret=GEZDGNBVGY3TQOJQ&digits=8",
        "otpauth://totp/fixture?secret=GEZDGNBVGY3TQOJQ&period=60",
        "otpauth://totp/fixture?secret=GEZDGNBVGY3TQOJQ&secret=OTHERSEED",
        "otpauth://totp/fixture?secret=GEZDGNBVGY3TQOJQ&%73ecret=OTHERSEED",
        "otpauth://totp/fixture?secret=GEZDGNBVGY3TQOJQ&Secret=OTHERSEED",
        "otpauth://totp/fixture?secret=%ZZ",
        "otpauth://totp/%ZZ?secret=GEZDGNBVGY3TQOJQ",
        "otpauth://totp/%00?secret=GEZDGNBVGY3TQOJQ",
        "otpauth://totp/fixture?secret=GEZDGNBVGY3TQOJQ#fragment",
        "otpauth://totp/fixture?issuer=Proton",
        "234567",
        " 234564 ",
        "2345 6723",
    ] {
        let input = serde_json::to_vec(&serde_json::json!({
            "username": "pipe-fixture-user",
            "password": "pipe-fixture-password",
            "totpSecret": seed,
        }))
        .expect("credential fixture");
        let output = piped(&input, false);
        assert_eq!(output.status.code(), Some(2));
        assert!(
            output.stdout.is_empty(),
            "invalid enrollment emitted plaintext"
        );
        let error = String::from_utf8_lossy(&output.stderr);
        assert!(!error.contains("pipe-fixture-password"));
        assert!(!error.contains(seed));
    }
}

#[test]
fn pipe_enrollment_requires_explicit_password_only_and_bounds_input() {
    let without_seed = br#"{"username":"pipe-fixture-user","password":"pipe-fixture-password"}"#;
    assert_eq!(piped(without_seed, false).status.code(), Some(2));
    let accepted = piped(without_seed, true);
    assert!(accepted.status.success());
    let account: serde_json::Value =
        serde_json::from_slice(&accepted.stdout).expect("password-only document");
    assert!(account["totpSecret"].is_null());
    for input in [
        b"{private-malformed-fixture".to_vec(),
        br#"{"username":"fixture","password":"pipe-fixture-password","private-unexpected-field":"fixture"}"#.to_vec(),
        vec![b'x'; 65_537],
    ] {
        let output = piped(&input, true);
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        let error = String::from_utf8_lossy(&output.stderr);
        assert!(!error.contains("private-malformed-fixture"));
        assert!(!error.contains("private-unexpected-field"));
        assert!(!error.contains("pipe-fixture-password"));
    }
    assert_eq!(
        piped(
            br#"{"username":"fixture","password":"fixture","totpSecret":"GEZDGNBVGY3TQOJQ"}"#,
            true
        )
        .status
        .code(),
        Some(2)
    );
}
