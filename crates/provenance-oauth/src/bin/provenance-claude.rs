//! Native Claude OAuth handoff without putting the token in argv or environment.
use anyhow::{Result, ensure};
use std::{
    fs::OpenOptions,
    io::{Read, Seek},
    os::{
        fd::AsRawFd,
        unix::{
            fs::{MetadataExt, OpenOptionsExt},
            process::CommandExt,
        },
    },
    path::PathBuf,
    process::Command,
};
use zeroize::Zeroizing;

fn run() -> Result<()> {
    let mut args = std::env::args_os().skip(1);
    let source = PathBuf::from(args.next().ok_or_else(|| anyhow::anyhow!("source"))?);
    let native = PathBuf::from(args.next().ok_or_else(|| anyhow::anyhow!("executable"))?);
    ensure!(
        source.is_absolute() && !source.starts_with("/nix/store") && native.is_absolute(),
        "paths"
    );
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(source)?;
    let metadata = file.metadata()?;
    // SAFETY: geteuid has no preconditions.
    ensure!(
        metadata.is_file()
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.mode() & 0o077 == 0
            && (1..=16 * 1024).contains(&metadata.len()),
        "private file"
    );
    let mut content = Zeroizing::new(Vec::new());
    Read::by_ref(&mut file)
        .take(16 * 1024 + 1)
        .read_to_end(&mut content)?;
    ensure!(
        content.len() <= 16 * 1024 && content.is_ascii(),
        "size or encoding"
    );
    let token = std::str::from_utf8(&content)?.trim();
    ensure!(
        !token.is_empty() && token.bytes().all(|b| (0x21..=0x7e).contains(&b)),
        "content"
    );
    drop(content);
    file.rewind()?;

    let mut command = Command::new(native);
    command.args(args);
    for (key, _) in std::env::vars_os() {
        if key
            .to_str()
            .is_some_and(|key| key.starts_with("CLAUDE_CODE_OAUTH_"))
        {
            command.env_remove(key);
        }
    }
    command
        .env_remove("ANTHROPIC_API_KEY")
        .env_remove("ANTHROPIC_AUTH_TOKEN")
        .env("CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR", "3");
    let fd = file.as_raw_fd();
    // SAFETY: only async-signal-safe descriptor operations run before exec.
    unsafe {
        command.pre_exec(move || {
            let result = if fd == 3 {
                libc::fcntl(fd, libc::F_SETFD, 0)
            } else {
                libc::dup2(fd, 3)
            };
            if result < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    Err(command.exec().into())
}

fn main() {
    if run().is_err() {
        eprintln!("provenance-claude: native credential launch failed");
        std::process::exit(1);
    }
}
