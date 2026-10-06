//! Drive the stock client over private pipes; Proton owns SRP and session storage.
use clap::Parser;
use data_encoding::BASE32_NOPAD;
use hmac::{Hmac, Mac};
use serde::Deserialize;
use sha1::Sha1;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc::{self, SyncSender};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const MAX_BYTES: usize = 65_536;

#[derive(Parser)]
#[command(version, about)]
struct Args {
    /// Private runtime JSON containing username, password, and optional totpSecret.
    #[arg(long)]
    credentials_file: PathBuf,
    /// Official protonvpn executable, including its Nix wrapper.
    #[arg(long)]
    cli: PathBuf,
    /// util-linux setsid executable; detach getpass from any controlling terminal.
    #[arg(long)]
    setsid: PathBuf,
    /// Maximum duration of each client invocation.
    #[arg(long, default_value_t = 45, value_parser = clap::value_parser!(u64).range(1..=300))]
    timeout_seconds: u64,
}

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Account {
    username: String,
    password: String,
    #[serde(default)]
    totp_secret: Option<String>,
}

struct Failure {
    message: &'static str,
    retry: bool,
}

impl Failure {
    fn permanent(message: &'static str) -> Self {
        Self {
            message,
            retry: false,
        }
    }

    fn retry(message: &'static str) -> Self {
        Self {
            message,
            retry: true,
        }
    }
}

type Result<T> = std::result::Result<T, Failure>;

fn read_account(path: &Path) -> Result<Account> {
    let file = File::open(path)
        .map_err(|_| Failure::permanent("Proton credential file is unavailable"))?;
    let metadata = file
        .metadata()
        .map_err(|_| Failure::permanent("Cannot inspect Proton credential file"))?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o077 != 0 {
        return Err(Failure::permanent(
            "Proton credentials require a private regular file (0400 or 0600)",
        ));
    }
    let mut bytes = Zeroizing::new(Vec::new());
    file.take((MAX_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| Failure::permanent("Cannot read Proton credential file"))?;
    if bytes.len() > MAX_BYTES {
        return Err(Failure::permanent("Proton credential file is too large"));
    }
    // Never forward serde errors: unknown field names can themselves be secrets.
    let account: Account = serde_json::from_slice(&bytes).map_err(|_| {
        Failure::permanent(
            "Invalid Proton credential JSON; expected username, password, and optional totpSecret",
        )
    })?;
    if account.username.is_empty()
        || account.username.len() > 254
        || account.username.chars().any(char::is_control)
        || account.username.trim() != account.username
        || account.password.is_empty()
        || account.password.len() > 1024
        || account.password.contains(['\r', '\n'])
    {
        return Err(Failure::permanent("Invalid Proton username or password"));
    }
    if let Some(seed) = &account.totp_secret {
        let _ = decode_seed(seed)?;
    }
    Ok(account)
}

fn decode_seed(seed: &str) -> Result<Zeroizing<Vec<u8>>> {
    let normalized = Zeroizing::new(
        seed.chars()
            .filter(|c| !c.is_ascii_whitespace())
            .map(|c| c.to_ascii_uppercase())
            .collect::<String>(),
    );
    let decoded = BASE32_NOPAD
        .decode(normalized.trim_end_matches('=').as_bytes())
        .map_err(|_| Failure::permanent("Invalid base32 Proton TOTP seed"))?;
    if decoded.is_empty() {
        return Err(Failure::permanent("Empty Proton TOTP seed"));
    }
    Ok(Zeroizing::new(decoded))
}

/// RFC 6238, the SHA-1 / six-digit / 30-second profile used by Proton.
fn totp(seed: &str, seconds: u64, digits: u32) -> Result<Zeroizing<String>> {
    let secret = decode_seed(seed)?;
    let mut mac = Hmac::<Sha1>::new_from_slice(&secret)
        .map_err(|_| Failure::permanent("Invalid Proton TOTP key"))?;
    mac.update(&(seconds / 30).to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let offset = usize::from(digest[19] & 0xf);
    let value = ((u32::from(digest[offset]) & 0x7f) << 24)
        | (u32::from(digest[offset + 1]) << 16)
        | (u32::from(digest[offset + 2]) << 8)
        | u32::from(digest[offset + 3]);
    Ok(Zeroizing::new(format!(
        "{:0width$}",
        value % 10_u32.pow(digits),
        width = digits as usize
    )))
}

struct Client(Child);

impl Drop for Client {
    fn drop(&mut self) {
        // Also covers prompt failures and timeouts; never leave getpass waiting.
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

enum Event {
    Bytes(bool, Zeroizing<Vec<u8>>),
    Closed,
    ReadFailed,
}

fn read_stream(mut stream: impl Read + Send + 'static, stderr: bool, tx: SyncSender<Event>) {
    std::thread::spawn(move || {
        let mut buffer = Zeroizing::new([0_u8; 4096]);
        loop {
            match stream.read(buffer.as_mut()) {
                Ok(0) => {
                    let _ = tx.send(Event::Closed);
                    break;
                }
                Ok(count) => {
                    if tx
                        .send(Event::Bytes(
                            stderr,
                            Zeroizing::new(buffer[..count].to_vec()),
                        ))
                        .is_err()
                    {
                        break;
                    }
                    buffer.zeroize();
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => {
                    let _ = tx.send(Event::ReadFailed);
                    break;
                }
            }
        }
    });
}

struct Output {
    status: ExitStatus,
    stdout: Zeroizing<Vec<u8>>,
    stderr: Zeroizing<Vec<u8>>,
}

impl Output {
    fn contains(&self, value: &str) -> bool {
        [&*self.stdout, &*self.stderr].into_iter().any(|bytes| {
            bytes
                .windows(value.len())
                .any(|window| window == value.as_bytes())
        })
    }

    fn check(&self) -> Result<()> {
        // Stock CLI 1.0.1 exits zero when the GUI holds its D-Bus name.
        if self.contains("desktop app is currently running") {
            return Err(Failure::retry(
                "Proton GUI is running; login will retry when the client is available",
            ));
        }
        if self.contains("Network connectivity issues") {
            return Err(Failure::retry("Proton login could not reach the network"));
        }
        if !self.status.success() || self.contains("Error:") {
            return Err(Failure::permanent(
                "Proton client rejected authentication; check credentials, 2FA, and the unlocked keyring",
            ));
        }
        Ok(())
    }
}

fn invoke(args: &Args, command: &[&str], account: Option<&Account>) -> Result<Output> {
    let mut client = Client(
        Command::new(&args.setsid)
            .arg(&args.cli)
            .args(command)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|_| Failure::permanent("Cannot launch the official Proton client"))?,
    );
    let (tx, rx) = mpsc::sync_channel(16);
    let stdout = client
        .0
        .stdout
        .take()
        .ok_or_else(|| Failure::permanent("Missing Proton stdout pipe"))?;
    let stderr = client
        .0
        .stderr
        .take()
        .ok_or_else(|| Failure::permanent("Missing Proton stderr pipe"))?;
    read_stream(stdout, false, tx.clone());
    read_stream(stderr, true, tx);
    let mut out = Zeroizing::new(Vec::new());
    let mut err = Zeroizing::new(Vec::new());
    let mut password_sent = false;
    let mut totp_sent = false;
    let mut closed = 0;
    let deadline = Instant::now() + Duration::from_secs(args.timeout_seconds);
    loop {
        if Instant::now() >= deadline {
            return Err(Failure::retry(
                "Proton client timed out; check network and keyring availability",
            ));
        }
        match rx.recv_timeout(
            Duration::from_millis(50).min(deadline.saturating_duration_since(Instant::now())),
        ) {
            Ok(Event::Bytes(is_stderr, bytes)) => {
                if out.len() + err.len() + bytes.len() > MAX_BYTES {
                    return Err(Failure::permanent(
                        "Proton client exceeded its output limit",
                    ));
                }
                if is_stderr {
                    err.extend_from_slice(&bytes);
                } else {
                    out.extend_from_slice(&bytes);
                }
                if let Some(account) = account {
                    let prompts = String::from_utf8_lossy(&err);
                    if !password_sent && prompts.contains("Password: ") {
                        let stdin = client
                            .0
                            .stdin
                            .as_mut()
                            .ok_or_else(|| Failure::permanent("Missing Proton input pipe"))?;
                        writeln!(stdin, "{}", account.password)
                            .map_err(|_| Failure::permanent("Cannot deliver Proton password"))?;
                        password_sent = true;
                    }
                    if prompts.matches("2FA Token: ").count() > 1 {
                        return Err(Failure::permanent(
                            "Proton rejected the generated TOTP code",
                        ));
                    }
                    if !totp_sent && prompts.contains("2FA Token: ") {
                        let seed = account.totp_secret.as_deref()
                            .ok_or_else(|| Failure::permanent("Proton requires 2FA; enroll totpSecret in the encrypted credential document"))?;
                        let seconds = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .map_err(|_| {
                                Failure::permanent("System clock is unavailable for Proton TOTP")
                            })?
                            .as_secs();
                        let code = totp(seed, seconds, 6)?;
                        let stdin = client
                            .0
                            .stdin
                            .as_mut()
                            .ok_or_else(|| Failure::permanent("Missing Proton input pipe"))?;
                        writeln!(stdin, "{}", *code)
                            .map_err(|_| Failure::permanent("Cannot deliver Proton TOTP code"))?;
                        totp_sent = true;
                    }
                }
            }
            Ok(Event::Closed) => closed += 1,
            Ok(Event::ReadFailed) => {
                return Err(Failure::permanent("Cannot read Proton client response"));
            }
            Err(mpsc::RecvTimeoutError::Timeout | mpsc::RecvTimeoutError::Disconnected) => {}
        }
        if closed == 2
            && let Some(status) = client
                .0
                .try_wait()
                .map_err(|_| Failure::permanent("Cannot wait for Proton client"))?
        {
            return Ok(Output {
                status,
                stdout: out,
                stderr: err,
            });
        }
    }
}

fn signed_in(output: &Output, username: &str) -> Result<bool> {
    output.check()?;
    let expected = format!("Account: '{username}'");
    let text = std::str::from_utf8(&output.stdout)
        .map_err(|_| Failure::permanent("Unrecognized Proton account response"))?;
    if text.lines().any(|line| line == expected) {
        return Ok(true);
    }
    if text.lines().any(|line| line == "Account: 'None'") {
        return Ok(false);
    }
    Err(Failure::permanent(
        "A different Proton account or unsupported client state is present; sign out explicitly before switching accounts",
    ))
}

fn run(args: &Args) -> Result<()> {
    let runtime = std::env::var_os("XDG_RUNTIME_DIR")
        .ok_or_else(|| Failure::permanent("Proton login requires a user runtime directory"))?;
    let lock = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(PathBuf::from(runtime).join("nix-provenance-proton-vpn.lock"))
        .map_err(|_| Failure::permanent("Cannot open Proton login lock"))?;
    lock.try_lock()
        .map_err(|_| Failure::retry("Another Proton login attempt is running"))?;
    let account = read_account(&args.credentials_file)?;
    if signed_in(&invoke(args, &["info"], None)?, &account.username)? {
        println!("Proton account session is already enrolled");
        return Ok(());
    }
    let login = invoke(args, &["signin", "--", &account.username], Some(&account))?;
    login.check()?;
    if !signed_in(&invoke(args, &["info"], None)?, &account.username)? {
        return Err(Failure::permanent(
            "Proton did not persist the authenticated account session",
        ));
    }
    println!("Proton account session enrolled");
    Ok(())
}

fn main() {
    if let Err(error) = run(&Args::parse()) {
        eprintln!("proton-vpn-auth: {}", error.message);
        std::process::exit(if error.retry { 75 } else { 2 });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc_6238_sha1_vectors() {
        let seed = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        for (seconds, expected) in [
            (59, "94287082"),
            (1_111_111_109, "07081804"),
            (1_111_111_111, "14050471"),
            (1_234_567_890, "89005924"),
            (2_000_000_000, "69279037"),
            (20_000_000_000, "65353130"),
        ] {
            assert_eq!(
                &*totp(seed, seconds, 8).unwrap_or_else(|_| panic!("valid RFC seed")),
                expected
            );
        }
        assert_eq!(
            &*totp(seed, 59, 6).unwrap_or_else(|_| panic!("valid RFC seed")),
            "287082"
        );
    }
}
