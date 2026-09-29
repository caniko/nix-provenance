use crate::{Access, Config, Enrollment, Grant, Target, age_file};
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    thread,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

const MAX_JSON: u64 = 128 * 1024;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct State {
    version: u32,
    target: Target,
    generation: u64,
    enrollment_digest: String,
    revision: u64,
    refresh_pending: bool,
    grant: Option<Grant>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Status<'a> {
    pub target: &'a Target,
    pub generation: u64,
    pub revision: u64,
    pub state: &'static str,
    pub expires_at: Option<u64>,
}

/// Kept open through network exchange, fsync, and checkpoint publication. The
/// stable lock inode is never renamed or removed, including on revocation.
pub struct Store<'a> {
    config: &'a Config,
    _lock: File,
}

pub fn read_json<T: serde::de::DeserializeOwned>(path: &Path, private: bool) -> Result<T> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_NONBLOCK | if private { libc::O_NOFOLLOW } else { 0 });
    let file = options.open(path).context("cannot open OAuth input file")?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file() && metadata.len() <= MAX_JSON,
        "OAuth input must be a bounded regular file"
    );
    if private {
        ensure!(
            metadata.mode() & 0o077 == 0,
            "OAuth input must not be group/world accessible"
        );
    }
    let mut data = Zeroizing::new(Vec::new());
    file.take(MAX_JSON + 1).read_to_end(&mut data)?;
    ensure!(
        data.len() as u64 <= MAX_JSON,
        "OAuth input exceeds size limit"
    );
    // Serde errors can contain the invalid value, which may be a secret.
    serde_json::from_slice(&data).map_err(|_| anyhow::anyhow!("invalid OAuth JSON document"))
}

pub fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .context("OAuth output needs a parent directory")?;
    let mut temp = tempfile::NamedTempFile::new_in(parent)?;
    temp.as_file()
        .set_permissions(fs::Permissions::from_mode(0o600))?;
    temp.write_all(bytes)?;
    temp.as_file().sync_all()?;
    temp.persist(path).map_err(|e| e.error)?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

impl<'a> Store<'a> {
    pub fn lock(config: &'a Config) -> Result<Self> {
        config.validate()?;
        // Nix/systemd supplies the parent; never create a broad tree with secret
        // material under unchecked, potentially shared parent permissions.
        match fs::DirBuilder::new()
            .mode(0o700)
            .create(&config.state_directory)
        {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error).context("cannot create OAuth state directory"),
        }
        let metadata = fs::symlink_metadata(&config.state_directory)?;
        let uid = rust_uid()?;
        ensure!(
            metadata.is_dir() && metadata.uid() == uid && metadata.mode() & 0o077 == 0,
            "OAuth state directory must be owned by the current user with mode 0700"
        );
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(config.state_directory.join("lock"))?;
        let meta = lock.metadata()?;
        ensure!(
            meta.is_file() && meta.uid() == uid && meta.mode() & 0o077 == 0 && meta.nlink() == 1,
            "invalid OAuth state lock"
        );
        // Allow a peer's five-second token exchange to finish within the stock
        // consumer's ten-second command budget.
        let deadline = Instant::now() + Duration::from_secs(6);
        loop {
            match lock.try_lock() {
                Ok(()) => break,
                Err(std::fs::TryLockError::WouldBlock) if Instant::now() < deadline => {
                    thread::sleep(Duration::from_millis(20))
                }
                Err(std::fs::TryLockError::WouldBlock) => {
                    bail!("OAuth refresh is busy; retry the request")
                }
                Err(std::fs::TryLockError::Error(error)) => return Err(error.into()),
            }
        }
        Ok(Self {
            config,
            _lock: lock,
        })
    }

    fn path(&self) -> PathBuf {
        self.config.state_directory.join("state.json")
    }

    fn load(&self) -> Result<State> {
        let state: State = read_json(&self.path(), true).context(
            "OAuth state unavailable; explicitly initialize once or restore a current checkpoint",
        )?;
        ensure!(
            state.version == 1 && state.target == self.config.target && state.generation > 0,
            "OAuth state has an incompatible version or target"
        );
        if let Some(grant) = &state.grant {
            grant.validate()?;
        }
        Ok(state)
    }

    fn save(&self, state: &State) -> Result<()> {
        let data = Zeroizing::new(serde_json::to_vec(state)?);
        atomic_write(&self.path(), &data)
    }

    fn checkpoint(&self, state: &State) -> Result<()> {
        let data = Zeroizing::new(serde_json::to_vec(state)?);
        let encrypted = age_file::encrypt(&data, &self.config.recovery_recipients)?;
        atomic_write(
            &self.config.state_directory.join("checkpoint.age"),
            &encrypted,
        )
    }

    pub fn apply(&self, enrollment: &Enrollment, initialize: bool) -> Result<()> {
        enrollment.validate(&self.config.target)?;
        let input = Zeroizing::new(serde_json::to_vec(enrollment)?);
        let digest = format!("{:x}", Sha256::digest(&*input));
        let previous = match fs::symlink_metadata(self.path()) {
            Ok(_) => Some(self.load()?),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound && initialize => None,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => bail!(
                "state is missing; use apply --initialize for first enrollment, or restore a current checkpoint"
            ),
            Err(error) => return Err(error.into()),
        };
        if let Some(previous) = &previous
            && enrollment.generation <= previous.generation
        {
            ensure!(
                enrollment.generation != previous.generation
                    || digest == previous.enrollment_digest,
                "enrollment generation was reused with different contents"
            );
            // Includes rollbacks, repeated boots, and revoked generations.
            // Never copy the original refresh token back into live state.
            self.checkpoint(previous)?;
            return Ok(());
        }
        let state = State {
            version: 1,
            target: self.config.target.clone(),
            generation: enrollment.generation,
            enrollment_digest: digest,
            revision: 0,
            refresh_pending: false,
            grant: Some(enrollment.grant.clone()),
        };
        self.save(&state)?;
        self.checkpoint(&state)
    }

    pub fn access(
        &self,
        clock: impl Fn() -> Result<u64>,
        refresh: impl FnOnce(&Grant) -> Result<Grant>,
    ) -> Result<Access> {
        let now = clock()?;
        let mut state = self.load()?;
        ensure!(
            !state.refresh_pending,
            "OAuth refresh outcome is uncertain; reauthorize instead of replaying a refresh token"
        );
        let grant = state
            .grant
            .as_ref()
            .context("OAuth enrollment has been removed; authorize a new generation")?;
        if grant.expires_at <= now.saturating_add(60_000) {
            state.refresh_pending = true;
            // A crash or transport failure after dispatch cannot prove that the
            // provider did not rotate. Record intent before sending anything.
            if let Err(error) = self.save(&state).and_then(|()| self.checkpoint(&state)) {
                // This process knows no exchange was dispatched. Clear its
                // intent if storage permits; an interrupted/failed rollback
                // remains conservatively fenced across restart.
                state.refresh_pending = false;
                self.save(&state)
                    .context("could not clear undispatched refresh intent")?;
                return Err(error)
                    .context("could not checkpoint refresh intent; no exchange was sent");
            }
            let next = refresh(grant)?;
            next.validate()?;
            ensure!(
                next.account_id == grant.account_id,
                "refresh changed the authorized account"
            );
            ensure!(
                next.expires_at > clock()?.saturating_add(60_000),
                "refresh returned an expired or unusable grant"
            );
            state.grant = Some(next);
            state.refresh_pending = false;
            state.revision = state
                .revision
                .checked_add(1)
                .context("OAuth revision overflow")?;
            self.save(&state)?;
        }
        // Also repairs a previous interrupted checkpoint publication, without
        // repeating the already committed refresh.
        self.checkpoint(&state)?;
        let grant = state.grant.context("OAuth enrollment has been removed")?;
        ensure!(
            grant.expires_at > clock()?.saturating_add(60_000),
            "access grant became unusable during checkpoint publication; retry access"
        );
        Ok(Access {
            access_token: grant.access_token,
            expires_at: grant.expires_at,
            account_id: grant.account_id,
        })
    }

    pub fn status(&self) -> Result<serde_json::Value> {
        let state = self.load()?;
        Ok(serde_json::to_value(Status {
            target: &state.target,
            generation: state.generation,
            revision: state.revision,
            state: if state.refresh_pending {
                "reauthorization-required"
            } else if state.grant.is_none() {
                "removed"
            } else {
                "enrolled"
            },
            expires_at: state.grant.map(|grant| grant.expires_at),
        })?)
    }

    pub fn remove(&self) -> Result<()> {
        let mut state = self.load()?;
        state.grant = None;
        state.refresh_pending = false;
        self.save(&state)?;
        self.checkpoint(&state)
    }

    pub fn restore(&self, plaintext_checkpoint: &Path) -> Result<()> {
        ensure!(
            !self.path().try_exists()?,
            "restore requires missing state; it must not roll back live tokens"
        );
        let state: State = read_json(plaintext_checkpoint, true)?;
        ensure!(
            state.version == 1 && state.target == self.config.target && state.generation > 0,
            "checkpoint has an incompatible version or target"
        );
        ensure!(
            !state.refresh_pending,
            "checkpoint has an uncertain refresh; reauthorize"
        );
        if let Some(grant) = &state.grant {
            grant.validate()?;
        }
        self.save(&state)?;
        self.checkpoint(&state)
    }
}

fn rust_uid() -> Result<u32> {
    // /proc is available on the Linux hosts supported by this module. Avoid an
    // unsafe libc call solely to obtain the effective UID.
    Ok(fs::metadata("/proc/self")?.uid())
}
