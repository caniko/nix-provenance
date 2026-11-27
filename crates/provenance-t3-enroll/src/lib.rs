//! Enroll native T3 Code environments for one existing Unix user.
//!
//! The helper drives T3's native surfaces only: `t3 environment link` reads the
//! one-time pairing code from a private stdin pipe, `t3 environment list
//! --json` reports the identity T3 actually linked, and the desktop app imports
//! a private `--import-connections` document. T3 owns pairing, session issuance,
//! credential storage, and keyring encryption. This crate never reads or
//! rewrites T3's connection catalog, secret store, or database.

use std::collections::HashSet;
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize, Serializer};
use zeroize::{Zeroize, Zeroizing};

const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;
const MAX_SECRET_BYTES: u64 = 8 * 1024;
const MAX_URL_CHARS: usize = 2048;
const MAX_LABEL_CHARS: usize = 512;
const MAX_ENVIRONMENT_ID_CHARS: usize = 256;
const MAX_URLS_PER_PEER: usize = 8;
const MAX_CHILD_DETAIL_CHARS: usize = 4096;

/// A public, non-secret enrollment manifest. Secret files are referenced by
/// literal runtime paths and are never read at manifest load time.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Manifest {
    /// Existing Unix user whose T3 environments are enrolled.
    pub user: String,
    /// Explicit local T3 data directory for list/link operations.
    pub base_dir: PathBuf,
    /// T3 CLI command or absolute path.
    #[serde(default = "default_t3")]
    pub t3: PathBuf,
    /// T3 Code desktop command or absolute path, required for desktop imports.
    #[serde(default)]
    pub desktop: Option<PathBuf>,
    #[serde(default)]
    pub peers: Vec<Peer>,
}

fn default_t3() -> PathBuf {
    PathBuf::from("t3")
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Peer {
    /// Expected environment id. Optional only when an owner executor can
    /// discover it natively; a declared value is cross-checked.
    #[serde(default)]
    pub environment_id: Option<String>,
    pub access: Access,
    /// Where the peer answers, tried in order. Each entry is a bare origin.
    pub urls: Vec<String>,
    /// Optional same-owner executor. When present, pairing codes and desktop
    /// bearer tokens are minted over this owner path instead of supplied files.
    #[serde(default)]
    pub owner: Option<OwnerExecutor>,
    /// Private one-time `t3 pair` code. Only needed in manual file mode.
    #[serde(default)]
    pub pairing_code_file: Option<PathBuf>,
    #[serde(default)]
    pub desktop: Option<DesktopRoutes>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OwnerExecutor {
    /// Local hostname, loopback name, or an already-trusted SSH alias.
    pub host: String,
    /// Explicit T3 CLI path on the target.
    pub t3: PathBuf,
    /// Explicit T3 data directory on the target.
    pub base_dir: PathBuf,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DesktopRoutes {
    #[serde(default)]
    pub bearer: Option<BearerRoute>,
    #[serde(default)]
    pub ssh: Option<SshRoute>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BearerRoute {
    /// T3-normalized `http://host/` or `https://host/` endpoint.
    pub http_base_url: String,
    /// The matching `ws://host/` or `wss://host/` endpoint.
    pub ws_base_url: String,
    /// Manual-mode private bearer token. Forbidden with an owner executor.
    #[serde(default)]
    pub credential_file: Option<PathBuf>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SshRoute {
    pub alias: String,
    pub hostname: String,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub port: Option<u16>,
    /// Manual-mode private bearer credential. Forbidden with an owner executor.
    #[serde(default)]
    pub credential_file: Option<PathBuf>,
}

/// The T3 `AuthMcpClientAccess` values, declared explicitly per peer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Access {
    ReadOnly,
    ApprovalRequired,
    AutoAcceptEdits,
    Auto,
    FullAccess,
}

impl Access {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReadOnly => "read-only",
            Self::ApprovalRequired => "approval-required",
            Self::AutoAcceptEdits => "auto-accept-edits",
            Self::Auto => "auto",
            Self::FullAccess => "full-access",
        }
    }

    /// Native `mcpClientScopes`: the least grant that satisfies this access.
    fn scopes(self) -> &'static [&'static str] {
        match self {
            Self::ReadOnly => &["orchestration:read"],
            Self::FullAccess => &[
                "orchestration:read",
                "orchestration:operate",
                "settings:write",
                "source-control:write",
            ],
            Self::ApprovalRequired | Self::AutoAcceptEdits | Self::Auto => {
                &["orchestration:read", "orchestration:operate"]
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct Config {
    /// Total attempts per native operation. Retries repeat the same declaration.
    pub attempts: u32,
    /// Delay between attempts.
    pub retry_delay: Duration,
    /// Upper bound for one desktop import invocation.
    pub desktop_timeout: Duration,
    /// Upper bound for one owner executor command (describe, mint, owner check).
    pub owner_timeout: Duration,
    /// Upper bound for one local T3 list/link/desktop-probe command.
    pub command_timeout: Duration,
    /// SSH client used for owner executors; tests substitute a fake.
    pub ssh: PathBuf,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            attempts: 1,
            retry_delay: Duration::from_secs(2),
            desktop_timeout: Duration::from_secs(120),
            owner_timeout: Duration::from_secs(30),
            command_timeout: Duration::from_secs(30),
            ssh: PathBuf::from("ssh"),
        }
    }
}

#[derive(Debug)]
pub struct Summary {
    pub peers: Vec<PeerOutcome>,
    pub imported: Option<ImportSummary>,
}

#[derive(Debug)]
pub struct PeerOutcome {
    pub environment_id: String,
    pub label: String,
    pub linked: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub struct ImportSummary {
    pub targets: usize,
    pub profiles: usize,
    pub credentials: usize,
}

pub fn load_manifest(path: &Path) -> Result<Manifest> {
    let file = File::open(path)
        .with_context(|| format!("reading enrollment manifest {}", path.display()))?;
    let mut bytes = Vec::new();
    file.take(MAX_MANIFEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("reading enrollment manifest {}", path.display()))?;
    ensure!(
        bytes.len() as u64 <= MAX_MANIFEST_BYTES,
        "enrollment manifest is larger than 1 MiB"
    );
    serde_json::from_slice(&bytes).context("parsing enrollment manifest")
}

/// Reconcile every declared peer, then import the declared desktop routes.
///
/// Links for peers that already match the declaration are kept without reading
/// a pairing code. A failed relink never falls back to a broader existing link.
pub fn run(manifest: &Manifest, config: &Config) -> Result<Summary> {
    ensure!(
        (1..=10).contains(&config.attempts),
        "attempts must be between 1 and 10"
    );
    let user = current_user()?;
    ensure!(
        manifest.user == user,
        "manifest user `{}` is not the effective user `{}`",
        manifest.user,
        user
    );
    validate_local_state_dir(&manifest.base_dir, "manifest base directory")?;
    validate_command(&manifest.t3, "t3 command")?;
    if let Some(desktop) = &manifest.desktop {
        validate_command(desktop, "desktop command")?;
    }
    let declarations = validate_peers(manifest)?;
    let desktop_used = manifest.peers.iter().any(|peer| peer.desktop.is_some());
    if desktop_used {
        let desktop = manifest
            .desktop
            .as_deref()
            .context("desktop routes are declared, but the manifest has no desktop command")?;
        verify_desktop_capability(desktop, config)?;
    }

    let mut declarations = declarations;
    for declaration in &declarations {
        if let Some(OwnerTarget::Local { base_dir, .. }) = &declaration.owner {
            ensure!(
                base_dir == &manifest.base_dir,
                "local owner baseDir must equal the manifest baseDir"
            );
        }
    }
    for (declaration, peer) in declarations.iter_mut().zip(&manifest.peers) {
        if let Some(owner) = &declaration.owner {
            let discovered = resolve_owner_environment(
                owner,
                &manifest.user,
                declaration.expected_environment_id.as_deref(),
                config,
            )?;
            declaration.environment_id = Some(discovered.environment_id.clone());
            if matches!(owner, OwnerTarget::Local { .. })
                && peer
                    .desktop
                    .as_ref()
                    .is_some_and(|desktop| desktop.bearer.is_some())
            {
                let origin = read_local_runtime_origin(owner.base_dir())?;
                validate_local_origin(peer, declaration, &origin)?;
                declaration.local_origin = Some(origin);
            }
            declaration.resolved = Some(discovered);
        }
    }
    let mut resolved_ids = HashSet::new();
    for declaration in &declarations {
        let id = declaration
            .environment_id
            .as_deref()
            .context("peer environment id was not resolved")?;
        ensure!(
            resolved_ids.insert(id),
            "resolved environment id `{id}` is declared by more than one peer"
        );
    }

    let needs_links = declarations
        .iter()
        .any(|declaration| !matches!(declaration.owner, Some(OwnerTarget::Local { .. })));
    let links = if needs_links {
        list_links(&manifest.t3, &manifest.base_dir, config)?
    } else {
        Vec::new()
    };
    let mut outcomes = Vec::with_capacity(manifest.peers.len());
    let mut verified = Vec::with_capacity(manifest.peers.len());

    for (index, (peer, declaration)) in manifest.peers.iter().zip(&declarations).enumerate() {
        let environment_id = declaration
            .environment_id
            .as_deref()
            .context("peer environment id was not resolved")?;
        let (link, linked) = if matches!(declaration.owner, Some(OwnerTarget::Local { .. })) {
            let resolved = declaration
                .resolved
                .as_ref()
                .context("local owner descriptor is missing")?;
            (
                VerifiedPeer {
                    environment_id: resolved.environment_id.clone(),
                    label: resolved.label.clone(),
                },
                false,
            )
        } else {
            let current = links
                .iter()
                .find(|link| link.environment_id == environment_id);
            match current.filter(|link| declaration.matches(link)) {
                Some(link) => (verified_from(link)?, false),
                None => (reconcile_peer(manifest, peer, declaration, config)?, true),
            }
        };
        outcomes.push(PeerOutcome {
            environment_id: link.environment_id.clone(),
            label: link.label.clone(),
            linked,
        });
        verified.push((index, link));
    }

    let imported = if desktop_used {
        Some(import_desktop(manifest, &declarations, &verified, config)?)
    } else {
        None
    };

    Ok(Summary {
        peers: outcomes,
        imported,
    })
}

// Manifest validation ------------------------------------------------------

struct PeerDeclaration {
    expected_environment_id: Option<String>,
    environment_id: Option<String>,
    resolved: Option<ResolvedEnvironment>,
    local_origin: Option<String>,
    access: Access,
    urls: Vec<String>,
    owner: Option<OwnerTarget>,
}

impl PeerDeclaration {
    fn environment_id(&self) -> Result<&str> {
        self.environment_id
            .as_deref()
            .context("peer environment id was not resolved")
    }
    fn matches(&self, link: &ListedLink) -> bool {
        link.access == self.access && link.status == LinkStatus::Reachable && self.urls_match(link)
    }

    fn urls_match(&self, link: &ListedLink) -> bool {
        let mut linked = Vec::with_capacity(link.urls.len());
        for url in &link.urls {
            let Ok(origin) = Origin::parse(url) else {
                return false;
            };
            linked.push(origin.to_string());
        }
        if linked.is_empty() {
            return false;
        }
        // The verified link keeps the declared route order, but an offline
        // primary leaves an ordered subset. Every linked origin must be
        // declared, no extra origin is accepted, and the order cannot change.
        let mut next = 0;
        for origin in linked {
            let Some(offset) = self.urls[next..].iter().position(|url| *url == origin) else {
                return false;
            };
            next += offset + 1;
        }
        true
    }

    fn primary(&self) -> &str {
        &self.urls[0]
    }

    fn alternates(&self) -> &[String] {
        &self.urls[1..]
    }
}

fn validate_peers(manifest: &Manifest) -> Result<Vec<PeerDeclaration>> {
    let mut environment_ids = HashSet::new();
    let mut origins = HashSet::new();
    let mut desktop_used = false;
    let mut declarations = Vec::with_capacity(manifest.peers.len());

    for peer in &manifest.peers {
        let peer_name = peer
            .environment_id
            .as_deref()
            .unwrap_or("<owner-discovered>");
        if let Some(expected) = &peer.environment_id {
            validate_text(expected, "environment id", MAX_ENVIRONMENT_ID_CHARS)?;
            ensure!(
                environment_ids.insert(expected.as_str()),
                "duplicate environment id `{expected}`"
            );
        }
        ensure!(
            !peer.urls.is_empty() && peer.urls.len() <= MAX_URLS_PER_PEER,
            "peer `{peer_name}` must declare 1 to {MAX_URLS_PER_PEER} URLs"
        );

        let manual = peer.owner.is_none();
        ensure!(
            !manual || peer.environment_id.is_some(),
            "peer `{peer_name}` without an owner executor must declare environmentId"
        );
        ensure!(
            peer.owner.is_some() || peer.environment_id.is_some(),
            "peer `{peer_name}` must declare environmentId or an owner executor"
        );
        if let Some(path) = &peer.pairing_code_file {
            ensure!(
                manual,
                "peer `{peer_name}` cannot combine an owner executor with pairingCodeFile"
            );
            validate_runtime_path(path, "pairing code file")?;
        }

        let mut urls = Vec::with_capacity(peer.urls.len());
        for raw in &peer.urls {
            let origin = Origin::parse(raw).with_context(|| format!("peer `{peer_name}` URL"))?;
            origin.ensure_credential_safe()?;
            let canonical = origin.to_string();
            ensure!(
                !urls.contains(&canonical),
                "peer `{peer_name}` declares duplicate URL `{canonical}`"
            );
            ensure!(
                origins.insert(canonical.clone()),
                "URL `{canonical}` is declared by more than one peer"
            );
            urls.push(canonical);
        }

        if let Some(desktop) = &peer.desktop {
            desktop_used = true;
            validate_desktop(peer, desktop, &urls, &manifest.user, manual)?;
        }

        declarations.push(PeerDeclaration {
            expected_environment_id: peer.environment_id.clone(),
            environment_id: peer.environment_id.clone(),
            resolved: None,
            local_origin: None,
            access: peer.access,
            urls,
            owner: peer
                .owner
                .as_ref()
                .map(|owner| validate_owner(owner, &manifest.user))
                .transpose()?,
        });
    }

    if desktop_used {
        ensure!(
            manifest.desktop.is_some(),
            "a peer declares a desktop route, but the manifest has no desktop command"
        );
    }
    Ok(declarations)
}

fn validate_desktop(
    peer: &Peer,
    desktop: &DesktopRoutes,
    peer_urls: &[String],
    owner: &str,
    manual: bool,
) -> Result<()> {
    let peer_name = peer
        .environment_id
        .as_deref()
        .unwrap_or("<owner-discovered>");
    ensure!(
        desktop.bearer.is_some() || desktop.ssh.is_some(),
        "peer `{peer_name}` desktop route declares neither a bearer nor an SSH route"
    );
    if let Some(bearer) = &desktop.bearer {
        let http = Origin::parse(&bearer.http_base_url)
            .with_context(|| format!("peer `{peer_name}` desktop bearer URL"))?;
        http.ensure_credential_safe()?;
        ensure!(
            peer_urls.contains(&http.to_string()),
            "peer `{peer_name}` desktop bearer endpoint must be one of its declared URLs"
        );
        ensure!(
            bearer.http_base_url == format!("{http}/"),
            "peer `{peer_name}` desktop bearer URL must be the normalized endpoint `{http}/`"
        );
        let ws_scheme = if http.scheme == Scheme::Https {
            "wss"
        } else {
            "ws"
        };
        ensure!(
            bearer.ws_base_url == format!("{ws_scheme}://{}/", http.authority()),
            "peer `{peer_name}` desktop websocket URL does not match its HTTP endpoint"
        );
        validate_credential_source(
            bearer.credential_file.as_deref(),
            manual,
            peer_name,
            "desktop bearer credential file",
        )?;
    }
    if let Some(ssh) = &desktop.ssh {
        validate_ssh_field(&ssh.alias, "desktop SSH alias")?;
        validate_ssh_field(&ssh.hostname, "desktop SSH hostname")?;
        if let Some(username) = &ssh.username {
            validate_ssh_field(username, "desktop SSH username")?;
            ensure!(
                username == owner,
                "peer `{peer_name}` desktop SSH username must be the manifest user `{owner}` or omitted"
            );
        }
        if let Some(port) = ssh.port {
            ensure!(port != 0, "desktop SSH port must be between 1 and 65535");
        }
        validate_credential_source(
            ssh.credential_file.as_deref(),
            manual,
            peer_name,
            "desktop SSH credential file",
        )?;
    }
    Ok(())
}

fn validate_credential_source(
    path: Option<&Path>,
    manual: bool,
    peer_name: &str,
    what: &str,
) -> Result<()> {
    if manual {
        let path = path.with_context(|| format!("peer `{peer_name}` manual {what} is required"))?;
        validate_runtime_path(path, what)?;
    } else {
        ensure!(
            path.is_none(),
            "peer `{peer_name}` cannot combine an owner executor with {what}"
        );
    }
    Ok(())
}

#[derive(Clone, Debug)]
enum OwnerTarget {
    Local {
        t3: PathBuf,
        base_dir: PathBuf,
    },
    Ssh {
        host: String,
        t3: PathBuf,
        base_dir: PathBuf,
    },
}

fn validate_owner(owner: &OwnerExecutor, user: &str) -> Result<OwnerTarget> {
    validate_owner_host(&owner.host)?;
    ensure!(
        !user.contains('@') && !user.chars().any(char::is_whitespace) && !user.starts_with('-'),
        "manifest user is not a safe SSH login user"
    );
    validate_absolute_path(&owner.t3, "owner t3 command")?;
    validate_absolute_path(&owner.base_dir, "owner base directory")?;
    let base = owner
        .base_dir
        .to_str()
        .context("owner base directory is not UTF-8")?;
    ensure!(
        base != "/nix/store" && !base.starts_with("/nix/store/"),
        "owner base directory must not be in the Nix store"
    );
    if is_local_host(&owner.host) {
        Ok(OwnerTarget::Local {
            t3: owner.t3.clone(),
            base_dir: owner.base_dir.clone(),
        })
    } else {
        Ok(OwnerTarget::Ssh {
            host: owner.host.clone(),
            t3: owner.t3.clone(),
            base_dir: owner.base_dir.clone(),
        })
    }
}

fn validate_owner_host(host: &str) -> Result<()> {
    ensure!(
        !host.is_empty() && host.len() <= 255,
        "owner host must be a bounded SSH alias or local hostname"
    );
    ensure!(
        !host.starts_with('-')
            && !host.contains('@')
            && !host.chars().any(char::is_whitespace)
            && !host.chars().any(char::is_control)
            && host
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ':')),
        "owner host contains unsafe characters"
    );
    Ok(())
}

fn validate_absolute_path(path: &Path, what: &str) -> Result<()> {
    let raw = path
        .to_str()
        .with_context(|| format!("{what} is not valid UTF-8"))?;
    ensure!(
        !raw.is_empty() && raw.len() <= MAX_URL_CHARS,
        "{what} must be a bounded absolute path"
    );
    ensure!(path.is_absolute(), "{what} must be absolute");
    ensure!(raw != "/", "{what} must not be the root directory");
    ensure!(
        !raw.contains("//")
            && !raw.contains("/./")
            && !raw.contains("/../")
            && !raw.ends_with("/.")
            && !raw.ends_with("/.."),
        "{what} must be a normalized path"
    );
    ensure!(
        !raw.chars().any(char::is_control),
        "{what} contains control characters"
    );
    Ok(())
}

fn validate_local_state_dir(path: &Path, what: &str) -> Result<()> {
    validate_absolute_path(path, what)?;
    let raw = path.to_str().context("state directory path is not UTF-8")?;
    ensure!(
        raw != "/nix/store" && !raw.starts_with("/nix/store/"),
        "{what} must not be in the Nix store"
    );
    let metadata = fs::symlink_metadata(path).with_context(|| {
        format!(
            "{what} must already exist as an owner-created directory (for example a Canix StateDirectory or mkdir 0700 by that user)"
        )
    })?;
    ensure!(
        !metadata.file_type().is_symlink() && metadata.is_dir(),
        "{what} must be a real directory, not a symlink"
    );
    ensure!(
        metadata.uid() == current_euid(),
        "{what} must be owned by the effective user"
    );
    ensure!(
        metadata.permissions().mode() & 0o022 == 0,
        "{what} must not be group- or other-writable"
    );
    Ok(())
}

fn local_hostname() -> Option<String> {
    fs::read_to_string("/proc/sys/kernel/hostname")
        .ok()
        .map(|name| name.trim().to_ascii_lowercase())
        .filter(|name| !name.is_empty())
}

fn is_local_host(host: &str) -> bool {
    let host = host.to_ascii_lowercase();
    host == "localhost"
        || host == "127.0.0.1"
        || host == "::1"
        || local_hostname().as_deref() == Some(host.as_str())
}

fn resolve_owner_environment(
    target: &OwnerTarget,
    user: &str,
    expected: Option<&str>,
    config: &Config,
) -> Result<ResolvedEnvironment> {
    target.verify_owner_state(user, config)?;
    let mut bytes = target.run_native(
        &[
            "environment".to_owned(),
            "describe".to_owned(),
            "--json".to_owned(),
            "--base-dir".to_owned(),
            target.base_dir_arg()?.to_owned(),
        ],
        user,
        config,
    )?;
    let described: Descriptor = serde_json::from_slice(&bytes)
        .map_err(|_| anyhow::anyhow!("native environment describe output was invalid"))?;
    bytes.zeroize();
    validate_text(
        &described.environment_id,
        "discovered environment id",
        MAX_ENVIRONMENT_ID_CHARS,
    )?;
    validate_text(
        &described.label,
        "discovered environment label",
        MAX_LABEL_CHARS,
    )?;
    if let Some(expected) = expected {
        ensure!(
            described.environment_id == expected,
            "discovered environment id `{}` does not match declared `{expected}`",
            described.environment_id
        );
    }
    Ok(ResolvedEnvironment {
        environment_id: described.environment_id,
        label: described.label,
    })
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct LocalRuntimeState {
    origin: String,
    #[serde(default)]
    pid: Option<u32>,
}

fn read_local_runtime_origin(base_dir: &Path) -> Result<String> {
    let path = base_dir.join("userdata/server-runtime.json");
    let bytes = fs::read(&path)
        .with_context(|| format!("reading local T3 runtime state {}", path.display()))?;
    ensure!(
        bytes.len() <= 64 * 1024,
        "local T3 runtime state is unexpectedly large"
    );
    let state: LocalRuntimeState = serde_json::from_slice(&bytes)
        .map_err(|_| anyhow::anyhow!("local T3 runtime state is invalid"))?;
    if let Some(pid) = state.pid {
        ensure!(
            Path::new("/proc").join(pid.to_string()).exists(),
            "local T3 runtime pid {pid} is not alive"
        );
    }
    let origin = Origin::parse(&state.origin).context("local T3 runtime origin is invalid")?;
    ensure!(
        origin.scheme == Scheme::Http && origin.is_loopback(),
        "local T3 runtime origin must be a loopback http origin"
    );
    Ok(origin.to_string())
}

fn validate_local_origin(peer: &Peer, declaration: &PeerDeclaration, origin: &str) -> Result<()> {
    ensure!(
        declaration.urls.iter().any(|url| url == origin),
        "local T3 runtime origin `{origin}` is not a declared peer URL"
    );
    if let Some(bearer) = peer
        .desktop
        .as_ref()
        .and_then(|desktop| desktop.bearer.as_ref())
    {
        ensure!(
            bearer.http_base_url == format!("{origin}/"),
            "local desktop bearer URL must equal the native runtime origin"
        );
    }
    Ok(())
}

fn mint_pairing_code(
    target: &OwnerTarget,
    user: &str,
    access: Access,
    config: &Config,
) -> Result<Secret> {
    let mut args = vec![
        "auth".to_owned(),
        "pairing".to_owned(),
        "create".to_owned(),
        "--json".to_owned(),
        "--ttl".to_owned(),
        "5m".to_owned(),
    ];
    for scope in access.scopes() {
        args.push("--scope".to_owned());
        args.push((*scope).to_owned());
    }
    args.push("--base-dir".to_owned());
    args.push(target.base_dir_arg()?.to_owned());
    let bytes = Zeroizing::new(target.run_native(&args, user, config)?);
    let mut parsed: PairingCreated = serde_json::from_slice(bytes.as_slice())
        .map_err(|_| anyhow::anyhow!("native pairing create output was invalid"))?;
    if parsed.credential.is_empty() || parsed.credential.chars().any(char::is_control) {
        parsed.credential.zeroize();
        bail!("native pairing credential is empty or contains control characters");
    }
    Ok(Secret(parsed.credential))
}

fn mint_session_token(
    target: &OwnerTarget,
    user: &str,
    marker: &str,
    config: &Config,
) -> Result<(Secret, MintedSession)> {
    let args = [
        "auth".to_owned(),
        "session".to_owned(),
        "issue".to_owned(),
        "--json".to_owned(),
        "--ttl".to_owned(),
        "30d".to_owned(),
        "--label".to_owned(),
        marker.to_owned(),
        "--subject".to_owned(),
        marker.to_owned(),
        "--base-dir".to_owned(),
        target.base_dir_arg()?.to_owned(),
    ];
    let bytes = Zeroizing::new(target.run_native(&args, user, config)?);
    let mut parsed: SessionIssued = serde_json::from_slice(bytes.as_slice())
        .map_err(|_| anyhow::anyhow!("native session issue output was invalid"))?;
    if parsed.token.is_empty() || parsed.token.chars().any(char::is_control) {
        parsed.token.zeroize();
        bail!("native session token is empty or contains control characters");
    }
    if parsed.session_id.is_empty() || parsed.session_id.chars().any(char::is_control) {
        parsed.token.zeroize();
        bail!("native session id is empty or contains control characters");
    }
    Ok((
        Secret(parsed.token),
        MintedSession {
            owner: target.clone(),
            id: parsed.session_id,
        },
    ))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Descriptor {
    environment_id: String,
    label: String,
}

struct ResolvedEnvironment {
    environment_id: String,
    label: String,
}

#[derive(Deserialize)]
struct PairingCreated {
    credential: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SessionIssued {
    token: String,
    session_id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SessionListEntry {
    session_id: String,
    subject: String,
    client: SessionClient,
}

#[derive(Deserialize)]
struct SessionClient {
    label: Option<String>,
}

#[derive(Clone)]
struct MintedSession {
    owner: OwnerTarget,
    id: String,
}

fn managed_marker(user: &str, environment_id: &str, kind: &str) -> String {
    format!("provenance-t3-enroll:{user}:{environment_id}:{kind}")
}

fn managed_markers(peer: &Peer, environment_id: &str, user: &str) -> Vec<String> {
    let Some(desktop) = &peer.desktop else {
        return Vec::new();
    };
    let mut markers = Vec::new();
    if desktop.bearer.is_some() {
        markers.push(managed_marker(user, environment_id, "bearer"));
    }
    if desktop.ssh.is_some() {
        markers.push(managed_marker(user, environment_id, "ssh"));
    }
    markers
}

fn list_managed_sessions(
    owner: &OwnerTarget,
    user: &str,
    markers: &[String],
    config: &Config,
) -> Result<Vec<String>> {
    let args = vec![
        "auth".to_owned(),
        "session".to_owned(),
        "list".to_owned(),
        "--json".to_owned(),
        "--base-dir".to_owned(),
        owner.base_dir_arg()?.to_owned(),
    ];
    let bytes = Zeroizing::new(owner.run_native(&args, user, config)?);
    let sessions: Vec<SessionListEntry> = serde_json::from_slice(bytes.as_slice())
        .map_err(|_| anyhow::anyhow!("native auth session list output was invalid"))?;
    Ok(sessions
        .into_iter()
        .filter(|session| {
            markers.contains(&session.subject)
                && session.client.label.as_deref() == Some(session.subject.as_str())
        })
        .map(|session| session.session_id)
        .collect())
}

fn revoke_session(
    owner: &OwnerTarget,
    user: &str,
    session_id: &str,
    config: &Config,
) -> Result<()> {
    ensure!(
        !session_id.is_empty() && !session_id.chars().any(char::is_control),
        "managed session id is invalid"
    );
    let args = vec![
        "auth".to_owned(),
        "session".to_owned(),
        "revoke".to_owned(),
        session_id.to_owned(),
        "--base-dir".to_owned(),
        owner.base_dir_arg()?.to_owned(),
    ];
    owner.run_native_quiet(&args, user, config)
}

fn revoke_all(sessions: &[MintedSession], user: &str, config: &Config) -> Result<()> {
    for session in sessions {
        revoke_session(&session.owner, user, &session.id, config)?;
    }
    Ok(())
}

impl OwnerTarget {
    fn base_dir(&self) -> &Path {
        match self {
            Self::Local { base_dir, .. } | Self::Ssh { base_dir, .. } => base_dir,
        }
    }

    fn base_dir_arg(&self) -> Result<&str> {
        self.base_dir()
            .to_str()
            .context("owner base directory is not valid UTF-8")
    }

    fn run_native(&self, args: &[String], user: &str, config: &Config) -> Result<Vec<u8>> {
        let mut command = self.command(args, user, config)?;
        run_bounded(
            &mut command,
            None,
            true,
            config.owner_timeout,
            "owner command",
        )
    }

    fn run_native_quiet(&self, args: &[String], user: &str, config: &Config) -> Result<()> {
        let mut command = self.command(args, user, config)?;
        run_bounded(
            &mut command,
            None,
            false,
            config.owner_timeout,
            "owner command",
        )?;
        Ok(())
    }

    fn command(&self, args: &[String], user: &str, config: &Config) -> Result<Command> {
        let mut argv = vec![self.t3().to_string_lossy().into_owned()];
        argv.extend(args.iter().cloned());
        match self {
            Self::Local { .. } => {
                let mut command = Command::new(self.t3());
                command.args(&argv[1..]).env_remove("T3CODE_HOME");
                Ok(command)
            }
            Self::Ssh { host, .. } => ssh_command(&config.ssh, host, user, &argv),
        }
    }

    fn t3(&self) -> &Path {
        match self {
            Self::Local { t3, .. } | Self::Ssh { t3, .. } => t3,
        }
    }

    fn verify_owner_state(&self, user: &str, config: &Config) -> Result<()> {
        match self {
            Self::Local { base_dir, .. } => {
                validate_local_state_dir(base_dir, "owner base directory")
            }
            Self::Ssh { host, base_dir, .. } => {
                let login = self.remote_scalar(host, user, &["id", "-un"], config)?;
                ensure!(
                    login == user,
                    "remote login owner `{login}` does not match the manifest user `{user}`"
                );
                let uid: u32 = self
                    .remote_scalar(host, user, &["id", "-u"], config)?
                    .parse()
                    .context("remote owner uid is not numeric")?;
                let stat = self.remote_scalar(
                    host,
                    user,
                    &["stat", "-c", "%u %f", self.base_dir_arg()?],
                    config,
                )?;
                let mut fields = stat.split_whitespace();
                let stat_uid: u32 = fields
                    .next()
                    .context("remote base directory stat has no uid")?
                    .parse()
                    .context("remote base directory stat uid is not numeric")?;
                let mode = u32::from_str_radix(
                    fields
                        .next()
                        .context("remote base directory stat has no mode")?,
                    16,
                )
                .context("remote base directory stat mode is not hexadecimal")?;
                ensure!(
                    fields.next().is_none(),
                    "remote base directory stat returned unexpected fields"
                );
                ensure!(
                    stat_uid == uid,
                    "owner base directory is not owned by the remote login user"
                );
                ensure!(
                    mode & 0o170000 == 0o040000,
                    "owner base directory is not a real directory"
                );
                ensure!(
                    mode & 0o022 == 0,
                    "owner base directory is group- or other-writable"
                );
                let _ = base_dir;
                Ok(())
            }
        }
    }

    fn remote_scalar(
        &self,
        host: &str,
        user: &str,
        argv: &[&str],
        config: &Config,
    ) -> Result<String> {
        let remote = argv.iter().map(|arg| (*arg).to_owned()).collect::<Vec<_>>();
        let mut command = ssh_command(&config.ssh, host, user, &remote)?;
        let bytes = run_bounded(
            &mut command,
            None,
            true,
            config.owner_timeout,
            "owner check",
        )?;
        String::from_utf8(bytes)
            .context("owner check returned invalid UTF-8")
            .map(|value| value.trim().to_owned())
    }
}

fn ssh_command(ssh: &Path, host: &str, user: &str, remote_argv: &[String]) -> Result<Command> {
    validate_owner_host(host)?;
    let mut command = Command::new(ssh);
    command.args([
        "-T",
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        "ConnectTimeout=10",
        "-l",
        user,
        "--",
        host,
    ]);
    for arg in remote_argv {
        command.arg(shell_quote(arg)?);
    }
    Ok(command)
}

fn shell_quote(value: &str) -> Result<String> {
    ensure!(
        !value.chars().any(char::is_control),
        "remote argument contains control characters"
    );
    Ok(format!("'{}'", value.replace('\'', "'\\''")))
}

fn validate_text(value: &str, what: &str, max_chars: usize) -> Result<()> {
    ensure!(
        !value.trim().is_empty() && value.trim() == value,
        "{what} must be non-blank without surrounding whitespace"
    );
    ensure!(value.len() <= max_chars, "{what} is too long");
    ensure!(
        !value.chars().any(char::is_control),
        "{what} contains control characters"
    );
    Ok(())
}

fn validate_ssh_field(value: &str, what: &str) -> Result<()> {
    validate_text(value, what, 255)?;
    ensure!(
        !value.chars().any(char::is_whitespace),
        "{what} must not contain whitespace"
    );
    Ok(())
}

fn validate_command(path: &Path, what: &str) -> Result<()> {
    let raw = path
        .to_str()
        .with_context(|| format!("{what} is not valid UTF-8"))?;
    ensure!(
        !raw.is_empty() && raw.len() <= MAX_URL_CHARS,
        "{what} must be a bounded command"
    );
    ensure!(
        !raw.chars().any(char::is_control),
        "{what} contains control characters"
    );
    if raw.contains('/') {
        ensure!(path.is_absolute(), "{what} must be an absolute path");
        ensure!(
            !raw.contains("//")
                && !raw.contains("/./")
                && !raw.contains("/../")
                && !raw.ends_with("/.")
                && !raw.ends_with("/.."),
            "{what} must be a normalized path"
        );
    } else {
        ensure!(
            raw.chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '+')),
            "{what} must be an absolute path or a bare command name"
        );
    }
    Ok(())
}

/// Secret files stay in private runtime storage. The Nix store, argv, and
/// environment variables are never valid carriers for them.
fn validate_runtime_path(path: &Path, what: &str) -> Result<()> {
    let raw = path
        .to_str()
        .with_context(|| format!("{what} is not valid UTF-8"))?;
    ensure!(
        !raw.is_empty() && raw.len() <= MAX_URL_CHARS,
        "{what} must be a bounded absolute path"
    );
    ensure!(path.is_absolute(), "{what} must be absolute");
    ensure!(raw != "/", "{what} must not be the root directory");
    ensure!(
        !raw.contains("//")
            && !raw.contains("/./")
            && !raw.contains("/../")
            && !raw.ends_with("/.")
            && !raw.ends_with("/.."),
        "{what} must be a normalized path"
    );
    ensure!(
        !raw.chars().any(char::is_control),
        "{what} contains control characters"
    );
    ensure!(
        !raw.contains('%') && !raw.contains(':') && !raw.contains('\\'),
        "{what} contains a reserved character"
    );
    ensure!(
        raw != "/nix/store" && !raw.starts_with("/nix/store/"),
        "{what} must not be in the Nix store"
    );
    Ok(())
}

// Native T3 CLI ------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
enum LinkStatus {
    Reachable,
    Unreachable,
    Expired,
}

impl LinkStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Reachable => "reachable",
            Self::Unreachable => "unreachable",
            Self::Expired => "expired",
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ListedLink {
    environment_id: String,
    label: String,
    urls: Vec<String>,
    access: Access,
    status: LinkStatus,
}

#[derive(Debug)]
struct VerifiedPeer {
    environment_id: String,
    label: String,
}

fn verified_from(link: &ListedLink) -> Result<VerifiedPeer> {
    validate_text(&link.label, "linked environment label", MAX_LABEL_CHARS)?;
    Ok(VerifiedPeer {
        environment_id: link.environment_id.clone(),
        label: link.label.clone(),
    })
}

fn list_links(t3: &Path, base_dir: &Path, config: &Config) -> Result<Vec<ListedLink>> {
    let mut command = Command::new(t3);
    command
        .args(["environment", "list", "--json", "--base-dir"])
        .arg(base_dir)
        .env_remove("T3CODE_HOME");
    let output = run_bounded(
        &mut command,
        None,
        true,
        config.command_timeout,
        "t3 environment list",
    )?;
    serde_json::from_slice(&output).map_err(|_| {
        anyhow::anyhow!(
            "native `t3 environment list --json` output was invalid; this T3 build may not provide the native environment commands"
        )
    })
}

fn reconcile_peer(
    manifest: &Manifest,
    peer: &Peer,
    declaration: &PeerDeclaration,
    config: &Config,
) -> Result<VerifiedPeer> {
    let environment_id = declaration.environment_id()?;
    let manual_code = if declaration.owner.is_none() {
        let pairing_path = peer.pairing_code_file.as_deref().with_context(|| {
            format!("peer `{environment_id}` needs a link but declares no pairing code file")
        })?;
        Some(read_private_secret(pairing_path, "pairing code file")?)
    } else {
        None
    };

    let mut args = vec![
        "environment".to_owned(),
        "link".to_owned(),
        declaration.primary().to_owned(),
    ];
    for alternate in declaration.alternates() {
        args.push("--url".to_owned());
        args.push(alternate.clone());
    }
    args.push("--expect-environment-id".to_owned());
    args.push(environment_id.to_owned());
    args.push("--pairing-code".to_owned());
    args.push("-".to_owned());
    args.push("--access".to_owned());
    args.push(declaration.access.as_str().to_owned());
    args.push("--base-dir".to_owned());
    args.push(
        manifest
            .base_dir
            .to_str()
            .context("manifest base directory is not valid UTF-8")?
            .to_owned(),
    );

    let mut last_error = None;
    for attempt in 0..config.attempts {
        if attempt > 0 {
            std::thread::sleep(config.retry_delay);
        }
        let minted;
        let code = match &manual_code {
            Some(code) => code,
            None => {
                let owner = declaration
                    .owner
                    .as_ref()
                    .context("owner executor is required to mint a pairing code")?;
                minted = mint_pairing_code(owner, &manifest.user, declaration.access, config)?;
                &minted
            }
        };
        let mut command = Command::new(&manifest.t3);
        command.args(&args).env_remove("T3CODE_HOME");
        match run_bounded(
            &mut command,
            Some(code),
            false,
            config.command_timeout,
            "t3 environment link",
        ) {
            Ok(_) => {
                last_error = None;
                break;
            }
            Err(error) => last_error = Some(error),
        }
    }
    if let Some(error) = last_error {
        return Err(error).with_context(|| {
            format!(
                "linking peer `{environment_id}` with the declared `{}` access",
                declaration.access.as_str()
            )
        });
    }

    let links = list_links(&manifest.t3, &manifest.base_dir, config)?;
    let actual = links
        .iter()
        .find(|link| link.environment_id == environment_id)
        .with_context(|| {
            format!(
                "peer `{environment_id}` was linked, but `t3 environment list` does not show that environment id; the link was left unchanged"
            )
        })?;
    ensure!(
        declaration.urls_match(actual),
        "peer `{environment_id}` is linked with URLs or route order that do not match the declaration; the link was left unchanged"
    );
    ensure!(
        actual.access == declaration.access,
        "peer `{environment_id}` is linked with `{}` access, not the declared `{}`; the link was left unchanged",
        actual.access.as_str(),
        declaration.access.as_str()
    );
    if actual.status != LinkStatus::Reachable {
        bail!(
            "peer `{environment_id}` is linked but reports {}; retry later with a fresh pairing code",
            actual.status.as_str()
        );
    }
    verified_from(actual)
}

// Desktop import -----------------------------------------------------------

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DesktopCapability {
    version: String,
    capabilities: Vec<String>,
}

/// A version probe is the only safe way to reject an older desktop before it
/// starts Electron's GUI. Older builds print a plain version even with
/// `--json`, which is not the explicit capability document.
fn verify_desktop_capability(desktop: &Path, config: &Config) -> Result<()> {
    let mut command = Command::new(desktop);
    command.args(["--version", "--json"]);
    let output = run_bounded(
        &mut command,
        None,
        true,
        config.command_timeout,
        "desktop version",
    )
    .with_context(|| format!("probing `{}` version capabilities", desktop.display()))?;
    let declared: DesktopCapability = serde_json::from_slice(&output).map_err(|_| {
        anyhow::anyhow!(
            "`{}` did not return the native `--version --json` capability document; this desktop build is unsupported and no import was attempted",
            desktop.display()
        )
    })?;
    ensure!(
        !declared.version.trim().is_empty(),
        "`{}` returned an empty version in its capability document",
        desktop.display()
    );
    ensure!(
        declared
            .capabilities
            .iter()
            .any(|capability| capability == "import-connections"),
        "`{}` does not declare the `import-connections` capability; no import was attempted",
        desktop.display()
    );
    Ok(())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ConnectionDocument {
    schema_version: u8,
    targets: Vec<Target>,
    profiles: Vec<Profile>,
    credentials: Vec<CredentialEntry>,
    remote_dpop_tokens: Vec<serde_json::Value>,
    disabled_environment_ids: Vec<String>,
}

#[derive(Serialize)]
#[serde(tag = "_tag", rename_all_fields = "camelCase")]
enum Target {
    BearerConnectionTarget {
        environment_id: String,
        label: String,
        connection_id: String,
    },
    SshConnectionTarget {
        environment_id: String,
        label: String,
        connection_id: String,
    },
}

#[derive(Serialize)]
#[serde(tag = "_tag", rename_all_fields = "camelCase")]
enum Profile {
    BearerConnectionProfile {
        connection_id: String,
        environment_id: String,
        label: String,
        http_base_url: String,
        ws_base_url: String,
    },
    SshConnectionProfile {
        connection_id: String,
        environment_id: String,
        label: String,
        target: SshTarget,
    },
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SshTarget {
    alias: String,
    hostname: String,
    username: String,
    port: Option<u16>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CredentialEntry {
    connection_id: String,
    credential: Credential,
}

#[derive(Serialize)]
#[serde(tag = "_tag", rename_all_fields = "camelCase")]
enum Credential {
    BearerConnectionCredential { token: Secret },
}

fn import_desktop(
    manifest: &Manifest,
    declarations: &[PeerDeclaration],
    verified: &[(usize, VerifiedPeer)],
    config: &Config,
) -> Result<ImportSummary> {
    let desktop = manifest
        .desktop
        .as_deref()
        .context("desktop routes are declared, but the manifest has no desktop command")?;
    let mut old = Vec::new();
    for (index, link) in verified {
        let peer = &manifest.peers[*index];
        let Some(desktop_routes) = &peer.desktop else {
            continue;
        };
        let Some(owner) = declarations[*index].owner.as_ref() else {
            continue;
        };
        let markers = managed_markers(peer, &link.environment_id, &manifest.user);
        if desktop_routes.bearer.is_some() || desktop_routes.ssh.is_some() {
            for id in list_managed_sessions(owner, &manifest.user, &markers, config)? {
                old.push(MintedSession {
                    owner: owner.clone(),
                    id,
                });
            }
        }
    }

    let mut minted = Vec::new();
    let document = match build_document(manifest, declarations, verified, config, &mut minted) {
        Ok(document) => document,
        Err(error) => {
            if let Err(cleanup) = revoke_all(&minted, &manifest.user, config) {
                return Err(cleanup)
                    .context("cleaning up newly minted sessions after a build failure");
            }
            return Err(error);
        }
    };
    let summary = ImportSummary {
        targets: document.targets.len(),
        profiles: document.profiles.len(),
        credentials: document.credentials.len(),
    };

    let directory = match private_directory() {
        Ok(directory) => directory,
        Err(error) => {
            if let Err(cleanup) = revoke_all(&minted, &manifest.user, config) {
                return Err(cleanup)
                    .context("cleaning up newly minted sessions after private state failed");
            }
            return Err(error);
        }
    };
    let import_path = match write_import_file(&directory.0, &document) {
        Ok(path) => path,
        Err(error) => {
            if let Err(cleanup) = revoke_all(&minted, &manifest.user, config) {
                return Err(cleanup)
                    .context("cleaning up newly minted sessions after import file failed");
            }
            return Err(error);
        }
    };

    let mut last_error = None;
    for attempt in 0..config.attempts {
        if attempt > 0 {
            std::thread::sleep(config.retry_delay);
        }
        match run_desktop_import(
            desktop,
            &import_path,
            &manifest.base_dir,
            config.desktop_timeout,
        ) {
            Ok(()) => {
                let new_ids = minted
                    .iter()
                    .map(|session| session.id.as_str())
                    .collect::<std::collections::HashSet<_>>();
                for session in &old {
                    if !new_ids.contains(session.id.as_str()) {
                        revoke_session(&session.owner, &manifest.user, &session.id, config)?;
                    }
                }
                return Ok(summary);
            }
            Err(error) => last_error = Some(error),
        }
    }
    if let Err(cleanup) = revoke_all(&minted, &manifest.user, config) {
        return Err(cleanup).context("cleaning up newly minted sessions after a failed import");
    }
    Err(last_error.expect("attempts is at least one"))
        .context("importing saved desktop connections")
}

fn build_document(
    manifest: &Manifest,
    declarations: &[PeerDeclaration],
    verified: &[(usize, VerifiedPeer)],
    config: &Config,
    minted: &mut Vec<MintedSession>,
) -> Result<ConnectionDocument> {
    let mut targets = Vec::new();
    let mut profiles = Vec::new();
    let mut credentials = Vec::new();

    for (index, link) in verified {
        let peer = &manifest.peers[*index];
        let Some(desktop) = &peer.desktop else {
            continue;
        };
        let owner = declarations[*index].owner.as_ref();
        let environment_id = link.environment_id.clone();
        let label = link.label.clone();

        if let Some(bearer) = &desktop.bearer {
            let token = desktop_token(
                owner,
                bearer.credential_file.as_deref(),
                &manifest.user,
                &managed_marker(&manifest.user, &environment_id, "bearer"),
                "desktop bearer credential file",
                config,
                minted,
            )?;
            let connection_id = format!("bearer:{environment_id}");
            targets.push(Target::BearerConnectionTarget {
                environment_id: environment_id.clone(),
                label: label.clone(),
                connection_id: connection_id.clone(),
            });
            profiles.push(Profile::BearerConnectionProfile {
                connection_id: connection_id.clone(),
                environment_id: environment_id.clone(),
                label: label.clone(),
                http_base_url: bearer.http_base_url.clone(),
                ws_base_url: bearer.ws_base_url.clone(),
            });
            credentials.push(CredentialEntry {
                connection_id,
                credential: Credential::BearerConnectionCredential { token },
            });
        }

        if let Some(ssh) = &desktop.ssh {
            let token = desktop_token(
                owner,
                ssh.credential_file.as_deref(),
                &manifest.user,
                &managed_marker(&manifest.user, &environment_id, "ssh"),
                "desktop SSH credential file",
                config,
                minted,
            )?;
            let connection_id = format!("ssh:{environment_id}");
            targets.push(Target::SshConnectionTarget {
                environment_id: environment_id.clone(),
                label: label.clone(),
                connection_id: connection_id.clone(),
            });
            profiles.push(Profile::SshConnectionProfile {
                connection_id: connection_id.clone(),
                environment_id,
                label,
                target: SshTarget {
                    alias: ssh.alias.clone(),
                    hostname: ssh.hostname.clone(),
                    username: ssh
                        .username
                        .clone()
                        .unwrap_or_else(|| manifest.user.clone()),
                    port: ssh.port,
                },
            });
            credentials.push(CredentialEntry {
                connection_id,
                credential: Credential::BearerConnectionCredential { token },
            });
        }
    }

    ensure!(
        !targets.is_empty(),
        "desktop routes are declared, but no verified peer produced a connection"
    );
    Ok(ConnectionDocument {
        schema_version: 1,
        targets,
        profiles,
        credentials,
        remote_dpop_tokens: Vec::new(),
        disabled_environment_ids: Vec::new(),
    })
}

fn desktop_token(
    owner: Option<&OwnerTarget>,
    manual_file: Option<&Path>,
    user: &str,
    marker: &str,
    what: &str,
    config: &Config,
    minted: &mut Vec<MintedSession>,
) -> Result<Secret> {
    match owner {
        Some(owner) => {
            let (secret, session) = mint_session_token(owner, user, marker, config)?;
            minted.push(session);
            Ok(secret)
        }
        None => {
            let path = manual_file.with_context(|| format!("manual {what} is required"))?;
            read_private_secret(path, what)
        }
    }
}

fn run_desktop_import(
    command: &Path,
    import_path: &Path,
    base_dir: &Path,
    timeout: Duration,
) -> Result<()> {
    let mut process = Command::new(command);
    process
        .arg("--import-connections")
        .arg(import_path)
        .env("T3CODE_HOME", base_dir);
    run_bounded(&mut process, None, false, timeout, "desktop import")?;
    Ok(())
}

// Private runtime files ----------------------------------------------------

struct Secret(String);

impl Secret {
    fn expose(&self) -> &str {
        &self.0
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl Serialize for Secret {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

struct PrivateDirectory(PathBuf);

impl Drop for PrivateDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn private_directory() -> Result<PrivateDirectory> {
    let euid = current_euid();
    let mut bases = Vec::new();
    if let Some(runtime) = std::env::var_os("XDG_RUNTIME_DIR") {
        let runtime = PathBuf::from(runtime);
        if private_base_owned(&runtime, euid) {
            bases.push(runtime);
        }
    }
    let temp = std::env::temp_dir();
    if !bases.contains(&temp) && temp.is_absolute() {
        bases.push(temp);
    }

    let mut last_error = None;
    for base in bases {
        for attempt in 0..128u32 {
            let path = base.join(format!(
                "provenance-t3-enroll-{euid}-{}-{attempt}-{}",
                std::process::id(),
                nonce()
            ));
            match DirBuilder::new().mode(0o700).create(&path) {
                Ok(()) => {
                    let metadata = fs::symlink_metadata(&path).with_context(|| {
                        format!("inspecting private directory {}", path.display())
                    })?;
                    ensure!(
                        metadata.is_dir()
                            && metadata.uid() == euid
                            && metadata.permissions().mode() & 0o077 == 0,
                        "private directory {} is not owned by the effective user with mode 0700",
                        path.display()
                    );
                    return Ok(PrivateDirectory(path));
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => {
                    last_error = Some((path, error));
                    break;
                }
            }
        }
    }
    let (path, error) = last_error.context("no private runtime directory is available")?;
    Err(error).with_context(|| format!("creating private directory in {}", path.display()))
}

fn private_base_owned(path: &Path, euid: u32) -> bool {
    fs::symlink_metadata(path)
        .map(|metadata| {
            metadata.is_dir()
                && !metadata.file_type().is_symlink()
                && metadata.uid() == euid
                && metadata.permissions().mode() & 0o077 == 0
        })
        .unwrap_or(false)
}

fn nonce() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0)
}

fn write_import_file(directory: &Path, document: &ConnectionDocument) -> Result<PathBuf> {
    let path = directory.join("connections.json");
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&path)
        .context("creating the private desktop connection import file")?;
    serde_json::to_writer(&mut file, document)
        .context("writing the private desktop connection import file")?;
    file.flush()
        .context("flushing the desktop connection import")?;
    file.sync_all()
        .context("syncing the desktop connection import")?;
    drop(file);
    let mode = fs::metadata(&path)
        .context("inspecting the desktop connection import file")?
        .permissions()
        .mode()
        & 0o777;
    ensure!(
        mode == 0o600,
        "desktop connection import file is not private (mode {mode:o})"
    );
    Ok(path)
}

fn read_private_secret(path: &Path, what: &str) -> Result<Secret> {
    validate_runtime_path(path, what)?;
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .with_context(|| format!("opening {what}"))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("inspecting {what}"))?;
    ensure!(metadata.is_file(), "{what} must be a regular file");
    ensure!(
        metadata.uid() == current_euid(),
        "{what} must be owned by the effective user"
    );
    ensure!(
        metadata.permissions().mode() & 0o077 == 0,
        "{what} must not be readable or writable by another user (mode 0600)"
    );
    ensure!(
        metadata.len() > 0 && metadata.len() <= MAX_SECRET_BYTES,
        "{what} must be non-empty and no larger than 8 KiB"
    );

    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.read_to_end(&mut bytes)
        .with_context(|| format!("reading {what}"))?;
    ensure!(
        bytes.len() as u64 <= MAX_SECRET_BYTES,
        "{what} grew beyond 8 KiB while being read"
    );
    let mut text = match String::from_utf8(bytes) {
        Ok(text) => text,
        Err(error) => {
            let mut bytes = error.into_bytes();
            bytes.zeroize();
            bail!("{what} must be UTF-8");
        }
    };
    let value = Zeroizing::new(text.trim().to_owned());
    text.zeroize();
    ensure!(!value.is_empty(), "{what} is empty");
    ensure!(
        !value.chars().any(char::is_control),
        "{what} contains control characters"
    );
    ensure!(value.len() <= MAX_CHILD_DETAIL_CHARS, "{what} is too long");
    let mut value = value;
    Ok(Secret(std::mem::take(&mut *value)))
}

// Generic command and identity helpers -------------------------------------

const CHILD_OUTPUT_LIMIT: usize = 64 * 1024;

/// One bounded child runner. Credential stdin and captured stdout share one
/// deadline; captured stdout is capped and drained, stderr is discarded, and a
/// timeout kills only the process group created and tracked at spawn.
fn run_bounded(
    command: &mut Command,
    stdin: Option<&Secret>,
    capture: bool,
    timeout: Duration,
    label: &str,
) -> Result<Vec<u8>> {
    command
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(if capture {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stderr(Stdio::null())
        .process_group(0);
    let mut child = command
        .spawn()
        .with_context(|| format!("running {label}"))?;
    let pid = child.id();
    let input = stdin.map(|secret| {
        let mut bytes = Vec::with_capacity(secret.expose().len() + 1);
        bytes.extend_from_slice(secret.expose().as_bytes());
        bytes.push(b'\n');
        Zeroizing::new(bytes)
    });
    let mut input_offset = 0;
    let mut stdin_pipe = child.stdin.take();
    if stdin.is_some() && stdin_pipe.is_none() {
        kill_child_group(pid, &mut child);
        bail!("child did not provide stdin");
    }
    let mut stdout_pipe = child.stdout.take();
    if capture && stdout_pipe.is_none() {
        kill_child_group(pid, &mut child);
        bail!("child did not provide stdout");
    }
    if let Some(pipe) = &stdin_pipe
        && let Err(error) = set_nonblocking(pipe.as_raw_fd())
    {
        kill_child_group(pid, &mut child);
        return Err(error).context("configuring child stdin");
    }
    if let Some(pipe) = &stdout_pipe
        && let Err(error) = set_nonblocking(pipe.as_raw_fd())
    {
        kill_child_group(pid, &mut child);
        return Err(error).context("configuring child stdout");
    }
    let mut output = Zeroizing::new(Vec::new());
    let mut stdout_eof = stdout_pipe.is_none();
    let deadline = Instant::now() + timeout;
    let mut status = None;
    loop {
        if status.is_none() {
            status = child
                .try_wait()
                .with_context(|| format!("waiting for {label}"))?;
            if status.is_some() {
                stdin_pipe = None;
            }
        }
        if status.is_some() && stdout_eof {
            break;
        }
        if Instant::now() >= deadline {
            abort_child(pid, &mut child, status.is_some());
            bail!("{label} did not finish within {timeout:?}; no output was captured");
        }

        let mut fds = Vec::with_capacity(2);
        let mut stdin_index = None;
        let mut stdout_index = None;
        if let Some(pipe) = &stdin_pipe {
            let input_len = input.as_ref().map_or(0, |bytes| bytes.len());
            if input_offset < input_len {
                stdin_index = Some(fds.len());
                fds.push(libc::pollfd {
                    fd: pipe.as_raw_fd(),
                    events: libc::POLLOUT,
                    revents: 0,
                });
            }
        }
        if let Some(pipe) = &stdout_pipe
            && !stdout_eof
        {
            stdout_index = Some(fds.len());
            fds.push(libc::pollfd {
                fd: pipe.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            });
        }
        if fds.is_empty() {
            std::thread::sleep(Duration::from_millis(5));
            continue;
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        let timeout_ms = remaining.as_millis().min(50) as i32;
        let result = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as _, timeout_ms) };
        if result < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            abort_child(pid, &mut child, status.is_some());
            bail!("{label} polling failed: {error}");
        }

        if let (Some(index), Some(pipe)) = (stdin_index, &mut stdin_pipe)
            && fds[index].revents != 0
        {
            if let Some(bytes) = &input {
                loop {
                    match pipe.write(&bytes[input_offset..]) {
                        Ok(0) => break,
                        Ok(written) => input_offset += written,
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                        Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                        Err(error) if error.kind() == io::ErrorKind::BrokenPipe => {
                            input_offset = bytes.len();
                            break;
                        }
                        Err(error) => {
                            abort_child(pid, &mut child, status.is_some());
                            bail!("{label} stdin write failed: {error}");
                        }
                    }
                    if input_offset >= bytes.len() {
                        break;
                    }
                }
            }
            if input
                .as_ref()
                .is_some_and(|bytes| input_offset >= bytes.len())
            {
                stdin_pipe = None;
            }
        }

        if let (Some(index), Some(pipe)) = (stdout_index, &mut stdout_pipe)
            && fds[index].revents != 0
        {
            loop {
                let mut chunk = Zeroizing::new([0u8; 8192]);
                match pipe.read(&mut chunk[..]) {
                    Ok(0) => {
                        stdout_eof = true;
                        break;
                    }
                    Ok(read) => {
                        if output.len() + read > CHILD_OUTPUT_LIMIT {
                            abort_child(pid, &mut child, status.is_some());
                            bail!("{label} exceeded the {CHILD_OUTPUT_LIMIT}-byte output limit");
                        }
                        output.extend_from_slice(&chunk[..read]);
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    Err(error) => {
                        abort_child(pid, &mut child, status.is_some());
                        bail!("{label} stdout read failed: {error}");
                    }
                }
            }
        }
    }

    let status = status.expect("status is set before leaving the runner loop");
    if !status.success() {
        bail!("{label} failed ({status}); output was not captured");
    }
    Ok(std::mem::take(&mut *output))
}

fn abort_child(pid: u32, child: &mut Child, direct_child_reaped: bool) {
    // Once try_wait returned the direct child, its pid/pgid may be reused. Never
    // send a group signal after that point; dropping the pipe is the only safe
    // cleanup for an unrelated holder/descendant.
    if !direct_child_reaped {
        kill_child_group(pid, child);
    }
}

fn set_nonblocking(fd: RawFd) -> Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    ensure!(flags >= 0, "fcntl(F_GETFL) failed");
    ensure!(
        unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } >= 0,
        "fcntl(F_SETFL) failed"
    );
    Ok(())
}

fn kill_child_group(pid: u32, child: &mut Child) {
    // The child is its own process group from spawn; kill only that group and
    // the direct child. No PID lookup or pattern matching is involved.
    unsafe {
        libc::kill(-(pid as i32), libc::SIGKILL);
    }
    let _ = child.kill();
    let _ = child.wait();
}

fn current_euid() -> u32 {
    // SAFETY: geteuid has no preconditions and does not touch memory.
    unsafe { libc::geteuid() }
}

fn current_user() -> Result<String> {
    let euid = current_euid();
    let passwd =
        fs::read_to_string("/etc/passwd").context("reading /etc/passwd for the effective user")?;
    for line in passwd.lines() {
        let mut fields = line.split(':');
        let Some(name) = fields.next() else { continue };
        let Some(_password) = fields.next() else {
            continue;
        };
        let Some(uid) = fields.next() else { continue };
        if uid.parse::<u32>().ok() == Some(euid) {
            return Ok(name.to_owned());
        }
    }
    bail!("effective user {euid} is not listed in /etc/passwd")
}

// URL and trust policy -----------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
enum Scheme {
    Http,
    Https,
}

struct Origin {
    scheme: Scheme,
    host: String,
    port: Option<u16>,
    ipv6: bool,
}

impl Origin {
    fn parse(raw: &str) -> Result<Self> {
        ensure!(
            !raw.is_empty() && raw.len() <= MAX_URL_CHARS,
            "URL must be a bounded absolute URL"
        );
        ensure!(
            raw.trim() == raw && !raw.chars().any(char::is_control),
            "URL contains surrounding whitespace or control characters"
        );
        let (scheme, rest) = raw
            .split_once("://")
            .context("URL must start with http:// or https://")?;
        let scheme = match scheme {
            "http" => Scheme::Http,
            "https" => Scheme::Https,
            _ => bail!("URL must use http or https"),
        };
        let authority = rest.strip_suffix('/').unwrap_or(rest);
        ensure!(!authority.is_empty(), "URL has no host");
        ensure!(
            !authority.contains(['/', '?', '#', '@']),
            "URL must be a bare origin without path, query, fragment, or user information"
        );

        let (host, port, ipv6) = if let Some(after) = authority.strip_prefix('[') {
            let (host, tail) = after
                .split_once(']')
                .context("URL has an unterminated IPv6 host")?;
            ensure!(!host.is_empty(), "URL has no host");
            let port = if tail.is_empty() {
                None
            } else {
                Some(
                    tail.strip_prefix(':')
                        .context("URL has an invalid IPv6 authority")?,
                )
            };
            (host.to_ascii_lowercase(), port, true)
        } else {
            let (host, port) = match authority.split_once(':') {
                Some((host, port)) => (host, Some(port)),
                None => (authority, None),
            };
            ensure!(!host.is_empty(), "URL has no host");
            ensure!(
                host.chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_')),
                "URL host contains invalid characters"
            );
            (host.to_ascii_lowercase(), port, false)
        };

        if ipv6 {
            host.parse::<Ipv6Addr>()
                .with_context(|| format!("invalid IPv6 host `{host}`"))?;
        }
        let port = port
            .map(|port| port.parse::<u16>().context("URL has an invalid port"))
            .transpose()?;
        ensure!(port != Some(0), "URL port must be between 1 and 65535");
        let port = match (scheme, port) {
            (Scheme::Http, Some(80)) | (Scheme::Https, Some(443)) => None,
            (_, port) => port,
        };
        Ok(Self {
            scheme,
            host,
            port,
            ipv6,
        })
    }

    fn authority(&self) -> String {
        let host = if self.ipv6 {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        match self.port {
            Some(port) => format!("{host}:{port}"),
            None => host,
        }
    }

    fn ensure_credential_safe(&self) -> Result<()> {
        if self.scheme == Scheme::Https {
            return Ok(());
        }
        ensure!(
            self.is_loopback() || self.is_tailnet(),
            "plain http would send pairing credentials unencrypted; use the https or Tailscale address"
        );
        Ok(())
    }

    fn is_loopback(&self) -> bool {
        if self.host == "localhost" {
            return true;
        }
        self.host
            .parse::<Ipv4Addr>()
            .map(|address| address.is_loopback())
            .unwrap_or(false)
            || self
                .host
                .parse::<Ipv6Addr>()
                .map(|address| address.is_loopback())
                .unwrap_or(false)
    }

    fn is_tailnet(&self) -> bool {
        if self.host.ends_with(".ts.net") {
            return true;
        }
        self.host
            .parse::<Ipv6Addr>()
            .map(|address| {
                let segments = address.segments();
                segments[0] == 0xfd7a && segments[1] == 0x115c && segments[2] == 0xa1e0
            })
            .unwrap_or(false)
    }
}

impl std::fmt::Display for Origin {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let scheme = match self.scheme {
            Scheme::Http => "http",
            Scheme::Https => "https",
        };
        write!(formatter, "{scheme}://{}", self.authority())
    }
}
