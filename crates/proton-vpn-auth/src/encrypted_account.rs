//! Native age decryption: plaintext never crosses a filesystem boundary.
use super::{Account, Args, Failure, MAX_BYTES, Result};
use std::fs::OpenOptions;
use std::io::{Cursor, Read};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;
use zeroize::Zeroizing;

fn read_bounded(path: &Path, identity: bool) -> Result<Zeroizing<Vec<u8>>> {
    let mut options = OpenOptions::new();
    options.read(true).custom_flags(libc::O_NONBLOCK);
    if identity {
        options.custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW);
    }
    let file = options
        .open(path)
        .map_err(|_| Failure::permanent("Encrypted account or private identity is unavailable"))?;
    let metadata = file
        .metadata()
        .map_err(|_| Failure::permanent("Cannot inspect account input"))?;
    // SAFETY: geteuid has no arguments or preconditions.
    if !metadata.is_file()
        || identity
            && (metadata.permissions().mode() & 0o077 != 0
                || metadata.uid() != unsafe { libc::geteuid() })
    {
        return Err(Failure::permanent(
            "Account inputs require regular files; identities must be private and user-owned",
        ));
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(MAX_BYTES + 1));
    file.take((MAX_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| Failure::permanent("Cannot read account input"))?;
    if bytes.len() > MAX_BYTES {
        return Err(Failure::permanent("Account input exceeds its size limit"));
    }
    Ok(bytes)
}

pub(super) fn read(args: &Args) -> Result<Account> {
    let mut identities: Vec<Box<dyn age::Identity>> = Vec::new();
    for path in &args.identity {
        let bytes = read_bounded(path, true)?;
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| Failure::permanent("Invalid private age identity"))?;
        if text.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----") {
            let identity = age::ssh::Identity::from_buffer(Cursor::new(&*bytes), None)
                .map_err(|_| Failure::permanent("Invalid private SSH identity"))?;
            if !matches!(identity, age::ssh::Identity::Unencrypted(_)) {
                return Err(Failure::permanent(
                    "Unattended login requires a supported noninteractive home identity",
                ));
            }
            // age's SSH feature also compiles RSA support. Never expose its
            // private-key decryption operation (RUSTSEC-2023-0071) here.
            if !matches!(
                age::ssh::Recipient::try_from(identity.clone()),
                Ok(age::ssh::Recipient::SshEd25519(..))
            ) {
                return Err(Failure::permanent(
                    "Proton login supports only SSH-ed25519 or X25519 home identities",
                ));
            }
            identities.push(Box::new(identity));
        } else {
            for line in text
                .lines()
                .map(str::trim)
                .filter(|line| !line.is_empty() && !line.starts_with('#'))
            {
                let identity: age::x25519::Identity = line.parse()
                    .map_err(|_| Failure::permanent("Unsupported private age identity; use the declared SSH or X25519 recipient"))?;
                identities.push(Box::new(identity));
            }
        }
    }
    let ciphertext = read_bounded(&args.encrypted_file, false)?;
    let decryptor = age::Decryptor::new_buffered(Cursor::new(&*ciphertext))
        .map_err(|_| Failure::permanent("Invalid encrypted Proton account"))?;
    if decryptor.is_scrypt() {
        return Err(Failure::permanent(
            "Proton account requires recipient-encrypted age ciphertext",
        ));
    }
    let mut plaintext = Zeroizing::new(Vec::with_capacity(MAX_BYTES + 1));
    decryptor
        .decrypt(identities.iter().map(|identity| identity.as_ref()))
        .map_err(|_| {
            Failure::permanent("Cannot decrypt Proton account with the declared home identities")
        })?
        .take((MAX_BYTES + 1) as u64)
        .read_to_end(&mut plaintext)
        .map_err(|_| Failure::permanent("Cannot authenticate encrypted Proton account"))?;
    if plaintext.len() > MAX_BYTES {
        return Err(Failure::permanent(
            "Proton account document exceeds its size limit",
        ));
    }
    let account: Account = serde_json::from_slice(&plaintext).map_err(|_| {
        Failure::permanent(
            "Invalid Proton credential JSON; expected username, password, and optional totpSecret",
        )
    })?;
    account.validate()?;
    Ok(account)
}
