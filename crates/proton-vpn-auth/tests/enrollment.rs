//! Exercise actual controlling-terminal prompts, not a substituted input reader.
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;
use tempfile::{TempDir, tempdir};

const INTERACTIVE: &str = r#"
import errno, os, pty, select, signal, sys, termios, time
binary, path, mode = sys.argv[1:]
pid, master = pty.fork()
if pid == 0:
    os.execv(binary, [binary, 'enroll', '--out', path])
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
finally:
    if status is None:
        os.kill(pid, signal.SIGKILL)
        os.waitpid(pid, 0)
    os.close(master)
"#;

fn runtime() -> TempDir {
    let directory = tempdir().expect("runtime fixture");
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
        .expect("private runtime");
    directory
}

fn interactive(mode: &str, directory: &TempDir) {
    let output = Command::new("python3")
        .args(["-c", INTERACTIVE, env!("CARGO_BIN_EXE_proton-vpn-auth")])
        .arg(directory.path().join("account.json"))
        .arg(mode)
        .env("XDG_RUNTIME_DIR", directory.path())
        .output()
        .expect("PTY test interpreter");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn hidden_prompts_produce_the_exact_private_document() {
    let directory = runtime();
    interactive("success", &directory);
    let path = directory.path().join("account.json");
    let document: serde_json::Value =
        serde_json::from_slice(&fs::read(&path).expect("credential fixture"))
            .expect("valid document");
    assert_eq!(document["username"], "enrollment-fixture-user");
    assert_eq!(document["password"], "enrollment-fixture-password");
    assert_eq!(document["totpSecret"], "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
    assert_eq!(
        fs::metadata(&path).expect("metadata").permissions().mode() & 0o777,
        0o600
    );
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
        assert!(error.contains("must stay under XDG_RUNTIME_DIR"));
        assert!(!error.contains("username:"));
        assert!(!path.exists());
    }
}
