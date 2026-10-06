//! Keep rbw's mutable login database out of disposable XDG caches.
//!
//! rbw remains the sole login/refresh owner. Migration is serialized, stops its
//! agent before moving state, and never replays the old cache after completion.

use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail, ensure};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Config {
    pub state_directory: PathBuf,
    pub legacy_cache_directory: PathBuf,
    pub legacy_data_directory: PathBuf,
    pub rbw_binary: PathBuf,
    pub agent_binary: PathBuf,
}

impl Config {
    pub fn validate(&self) -> Result<()> {
        for path in [
            &self.state_directory,
            &self.legacy_cache_directory,
            &self.legacy_data_directory,
            &self.rbw_binary,
            &self.agent_binary,
        ] {
            ensure!(
                path.is_absolute()
                    && path != Path::new("/")
                    && path
                        .components()
                        .all(|part| matches!(part, Component::RootDir | Component::Normal(_))),
                "rbw manifest paths must be absolute, normalized, non-root paths"
            );
        }
        for legacy in [&self.legacy_cache_directory, &self.legacy_data_directory] {
            ensure!(
                !self.state_directory.starts_with(legacy)
                    && !legacy.starts_with(&self.state_directory),
                "rbw durable state must be separate from its legacy XDG directories"
            );
        }
        Ok(())
    }

    pub fn cache_home(&self) -> PathBuf {
        self.state_directory.join("cache")
    }

    pub fn data_home(&self) -> PathBuf {
        self.state_directory.join("data")
    }

    pub fn command(&self, agent: bool) -> Command {
        let mut command = Command::new(if agent {
            &self.agent_binary
        } else {
            &self.rbw_binary
        });
        command.env("XDG_CACHE_HOME", self.cache_home());
        command.env("XDG_DATA_HOME", self.data_home());
        // A direct, matching agent inherits these paths. No second wrapper or
        // competing credential owner is involved in an rbw agent launch.
        command.env("RBW_AGENT", &self.agent_binary);
        command
    }
}

pub fn profile_name(profile: Option<&str>) -> Result<String> {
    match profile.filter(|value| !value.is_empty()) {
        None => Ok("rbw".to_owned()),
        Some(value) => {
            ensure!(
                value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
                    && value != "."
                    && value != "..",
                "RBW_PROFILE must be a single safe profile name"
            );
            Ok(format!("rbw-{value}"))
        }
    }
}

/// Prepare one profile. The marker is authoritative even when the legacy cache
/// is recreated later; intentional `rbw purge` must not resurrect old tokens.
pub fn prepare(config: &Config, profile: &str) -> Result<()> {
    config.validate()?;
    validate_profile(profile)?;
    private_directory(&config.state_directory)?;
    let _lock = lock(&config.state_directory.join("migration.lock"))?;
    let cache = config.cache_home().join(profile);
    let data = config.data_home().join(profile);
    let marker = config.state_directory.join(format!("migrated-{profile}"));
    if marker.try_exists()? {
        validate_file(&marker)?;
        for path in [&cache, &data] {
            ensure!(
                path.try_exists()?,
                "rbw durable state is missing at {}; restore the current backup or explicitly re-enroll after investigating state loss",
                path.display()
            );
            private_directory(path)?;
        }
        return Ok(());
    }

    let sources = [
        config.legacy_cache_directory.join(profile),
        config.legacy_data_directory.join(profile),
    ];
    let destinations = [&cache, &data];
    // Preflight both trees before stopping the agent or moving either one.
    for (source, destination) in sources.iter().zip(destinations) {
        if path_exists(source)? {
            validate_tree(source)?;
            ensure!(
                !path_exists(destination)?,
                "both legacy and durable rbw state exist; refusing to choose between {} and {}",
                source.display(),
                destination.display()
            );
        } else if path_exists(destination)? {
            // A previous migration may have stopped between directory renames.
            validate_tree(destination)?;
        }
    }
    stop_agent(config)?;
    for path in [config.cache_home(), config.data_home()] {
        private_directory(&path)?;
    }
    for (source, destination) in sources.iter().zip(destinations) {
        if path_exists(source)? {
            fs::rename(source, destination).with_context(|| format!(
                "moving rbw state from {} to {}; legacy and durable state must be on the same filesystem",
                source.display(), destination.display()
            ))?;
            sync_directory(
                source
                    .parent()
                    .context("legacy rbw directory has no parent")?,
            )?;
        } else if !destination.try_exists()? {
            private_directory(destination)?;
        }
        tighten_tree(destination)?;
        sync_directory(
            destination
                .parent()
                .context("durable rbw directory has no parent")?,
        )?;
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&marker)?;
    file.write_all(b"provenance-rbw migration v1\n")?;
    file.sync_all()?;
    sync_directory(&config.state_directory)?;
    Ok(())
}

/// Metadata-only status: no credential values or vault contents are read.
pub fn status(config: &Config, profile: &str) -> Result<serde_json::Value> {
    config.validate()?;
    validate_profile(profile)?;
    let cache = config.cache_home().join(profile);
    let databases = if cache.try_exists()? {
        validate_directory(&cache)?;
        fs::read_dir(&cache)?.try_fold(0usize, |count, entry| -> Result<_> {
            let entry = entry?;
            Ok(count
                + usize::from(
                    entry
                        .path()
                        .extension()
                        .is_some_and(|extension| extension == "json")
                        && entry.file_type()?.is_file(),
                ))
        })?
    } else {
        0
    };
    Ok(serde_json::json!({
        "profile": profile,
        "stateDirectory": config.state_directory,
        "migrated": config.state_directory.join(format!("migrated-{profile}")).try_exists()?,
        "cachePresent": cache.try_exists()?,
        "deviceIdPresent": config.data_home().join(profile).join("device_id").try_exists()?,
        "vaultDatabases": databases,
    }))
}

fn current_uid() -> u32 {
    // SAFETY: geteuid has no arguments or memory-safety preconditions.
    unsafe { libc::geteuid() }
}

fn validate_profile(profile: &str) -> Result<()> {
    let selected = if profile == "rbw" {
        None
    } else {
        Some(
            profile
                .strip_prefix("rbw-")
                .context("invalid rbw profile")?,
        )
    };
    ensure!(profile_name(selected)? == profile, "invalid rbw profile");
    Ok(())
}

fn path_exists(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

fn validate_directory(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_dir() && metadata.uid() == current_uid(),
        "rbw state directory must be a real directory owned by the current user: {}",
        path.display()
    );
    Ok(())
}

fn validate_file(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_file() && metadata.uid() == current_uid() && metadata.nlink() == 1,
        "rbw state must contain only current-user-owned regular files without hard links: {}",
        path.display()
    );
    Ok(())
}

fn validate_tree(path: &Path) -> Result<()> {
    validate_directory(path)?;
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            validate_tree(&entry.path())?;
        } else {
            validate_file(&entry.path())?;
        }
    }
    Ok(())
}

fn private_directory(path: &Path) -> Result<()> {
    for ancestor in path.ancestors().skip(1) {
        match fs::symlink_metadata(ancestor) {
            Ok(metadata) => ensure!(
                metadata.is_dir(),
                "rbw state parent must not be a symbolic link: {}",
                ancestor.display()
            ),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    if let Some(parent) = path.parent().filter(|parent| *parent != Path::new("/")) {
        match fs::symlink_metadata(parent) {
            Ok(metadata) => ensure!(
                metadata.is_dir(),
                "rbw state parent must not be a symbolic link: {}",
                parent.display()
            ),
            Err(error) if error.kind() == io::ErrorKind::NotFound => private_directory(parent)?,
            Err(error) => return Err(error.into()),
        }
    }
    match DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    validate_directory(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

fn tighten_tree(path: &Path) -> Result<()> {
    validate_tree(path)?;
    private_directory(path)?;
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            tighten_tree(&entry.path())?;
        } else {
            fs::set_permissions(entry.path(), fs::Permissions::from_mode(0o600))?;
            File::open(entry.path())?.sync_all()?;
        }
    }
    sync_directory(path)
}

fn sync_directory(path: &Path) -> Result<()> {
    File::open(path)?
        .sync_all()
        .with_context(|| format!("syncing rbw state directory {}", path.display()))
}

fn lock(path: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    validate_file(path)?;
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    let deadline = Instant::now() + Duration::from_secs(8);
    loop {
        match file.try_lock() {
            Ok(()) => return Ok(file),
            Err(std::fs::TryLockError::WouldBlock) if Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(50))
            }
            Err(error) => bail!("acquiring rbw migration lock: {error}"),
        }
    }
}

fn stop_agent(config: &Config) -> Result<()> {
    let mut child = Command::new(&config.rbw_binary)
        .arg("stop-agent")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("stopping the old rbw agent before state migration")?;
    let deadline = Instant::now() + Duration::from_secs(8);
    loop {
        if let Some(status) = child.try_wait()? {
            ensure!(
                status.success(),
                "rbw stop-agent failed; state migration was not started"
            );
            return Ok(());
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            bail!("rbw stop-agent timed out; state migration was not started");
        }
        thread::sleep(Duration::from_millis(50));
    }
}
