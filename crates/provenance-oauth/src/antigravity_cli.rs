//! Standalone operator subcommands for Google Antigravity (`antigravity-capture`,
//! `antigravity-check`).

use crate::{
    CliError, Config, Grant, OAuthClient, Secret, deserialize_optional_secret,
    google::{CLOUD_PLATFORM_SCOPE, parse_agy_token},
    state::{Store, atomic_write, read_json},
};
use anyhow::{Context, Result, bail, ensure};
use clap::Args;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json, value::RawValue};
use std::{
    collections::BTreeSet,
    fs,
    io::{ErrorKind, IsTerminal, Read, Write},
    os::unix::{
        fs::{OpenOptionsExt, PermissionsExt},
        process::CommandExt,
    },
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    time::{Duration, Instant},
};
use zeroize::{Zeroize, Zeroizing};

pub const DEFAULT_MANIFESTS_DIR: &str = "/etc/provenance/oauth";
pub const GOOGLE_TOKEN_URI: &str = "https://oauth2.googleapis.com/token";
pub const ACP_TOKEN_REL: &str = "antigravity-acp/acp_token.json";
const NO_SESSION_BUS: &str = "unix:path=/dev/null/no-session-bus";
const EFFORTS: &[&str] = &["minimal", "low", "medium", "high", "xhigh", "max"];
const MAX_CREDENTIAL_BYTES: u64 = 512 * 1024;
const MAX_SELECTION_BYTES: u64 = 64 * 1024;
const MAX_PROBE_OUTPUT: u64 = 1024 * 1024;

pub const DEFAULT_ANTIGRAVITY_SCOPES: &[&str] = &[
    CLOUD_PLATFORM_SCOPE,
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/userinfo.profile",
    "https://www.googleapis.com/auth/cclog",
    "https://www.googleapis.com/auth/experimentsandconfigs",
    "https://www.googleapis.com/auth/aicode",
    "openid",
];

#[derive(Args, Debug)]
pub struct AntigravityCaptureArgs {
    /// Path to the `agy` executable.
    #[arg(long, default_value = "agy")]
    pub agy_bin: PathBuf,
    /// Directory containing deployed public OAuth manifests.
    #[arg(long, default_value = DEFAULT_MANIFESTS_DIR)]
    pub manifests_dir: PathBuf,
    /// Optional host filter when borrowing client metadata from deployed manifests.
    #[arg(long)]
    pub host: Option<String>,
    /// Optional user filter when borrowing client metadata from deployed manifests.
    #[arg(long)]
    pub user: Option<String>,
    /// Explicit manifest path from which to borrow OAuth client metadata.
    #[arg(long, value_name = "MANIFEST_PATH")]
    pub client_metadata_from: Option<PathBuf>,
    /// Normalize an existing token JSON file (or `-` for stdin) instead of running `agy acp --login`.
    #[arg(long, value_name = "PATH")]
    pub token_file: Option<PathBuf>,
    /// Destination path (`-` for non-TTY stdout, or a file path written atomically with mode 0600).
    #[arg(long, default_value = "-")]
    pub output: PathBuf,
}

#[derive(Args, Debug)]
pub struct AntigravityCheckArgs {
    /// Directory containing deployed public OAuth manifests.
    #[arg(long, default_value = DEFAULT_MANIFESTS_DIR)]
    pub manifests_dir: PathBuf,
    /// Target host (defaults to local hostname).
    #[arg(long)]
    pub host: Option<String>,
    /// Target Linux user (defaults to current effective user).
    #[arg(long)]
    pub user: Option<String>,
    /// Expected enrollment ID.
    #[arg(long)]
    pub enrollment: Option<String>,
    /// T3 Antigravity profile directory containing `antigravity-acp/acp_token.json`.
    #[arg(long, value_name = "DIR")]
    pub profile_dir: Option<PathBuf>,
    /// Antigravity selection record file.
    #[arg(long, value_name = "PATH")]
    pub selection_file: Option<PathBuf>,
    /// Opt in to a short inference smoke test with this discovered model.
    #[arg(long)]
    pub smoke_model: Option<String>,
    /// Effort for the smoke request.
    #[arg(
        long,
        requires = "smoke_model",
        ignore_case = true,
        value_parser = clap::builder::PossibleValuesParser::new(EFFORTS.iter().copied())
    )]
    pub smoke_effort: Option<String>,
    /// Path to the `agy` executable.
    #[arg(long, default_value = "agy")]
    pub agy_bin: PathBuf,
    /// Timeout in seconds for `agy models` discovery.
    #[arg(long, default_value_t = 35, value_parser = clap::value_parser!(u64).range(1..=300))]
    pub models_timeout_secs: u64,
    /// Timeout in seconds for the optional smoke inference test.
    #[arg(long, default_value_t = 25, value_parser = clap::value_parser!(u64).range(1..=300))]
    pub smoke_timeout_secs: u64,
    /// Emit structured JSON output.
    #[arg(long)]
    pub json: bool,
}

#[derive(Deserialize, Serialize)]
struct CanonicalAgyToken {
    client_id: String,
    client_secret: Secret,
    token_uri: String,
    refresh_token: Secret,
    scopes: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    project_id: Option<String>,
}

struct ClientMetadata {
    client_id: String,
    client_secret: Secret,
    token_uri: String,
}

pub fn run_capture(args: AntigravityCaptureArgs) -> std::result::Result<(), CliError> {
    if let Some(user) = &args.user {
        require_effective_user(user)?;
    }
    if args.output == Path::new("-") && std::io::stdout().is_terminal() {
        return Err(CliError::validation(
            "refusing to write Antigravity credentials to a terminal; redirect stdout or pass --output <PATH>",
        ));
    }

    let manifest = args
        .client_metadata_from
        .as_deref()
        .map(read_client_manifest)
        .transpose()?;
    let borrow_client = || borrow_client_metadata(&args, manifest.as_ref());
    let token = if let Some(token_file) = &args.token_file {
        let bytes = read_bounded_input(token_file, MAX_CREDENTIAL_BYTES)?;
        normalize_token_bytes(&bytes, borrow_client)?
    } else {
        capture_interactive(&args, borrow_client)?
    };

    let mut encoded = Zeroizing::new(Vec::new());
    serde_json::to_writer(&mut *encoded, &token)
        .map_err(|_| CliError::runtime("could not encode Antigravity token JSON"))?;
    parse_agy_token(&encoded).map_err(|e| CliError::validation(e.to_string()))?;

    if args.output == Path::new("-") {
        let mut stdout = std::io::stdout().lock();
        stdout
            .write_all(&encoded)
            .and_then(|()| writeln!(stdout))
            .map_err(|e| CliError::runtime(format!("could not write token to stdout: {e}")))?;
    } else {
        atomic_write(&args.output, &encoded).map_err(|e| {
            CliError::runtime(format!(
                "could not write token to {}: {e:#}",
                args.output.display()
            ))
        })?;
    }
    Ok(())
}

fn read_bounded_input(
    path: &Path,
    limit: u64,
) -> std::result::Result<Zeroizing<Vec<u8>>, CliError> {
    let mut bytes = Zeroizing::new(Vec::new());
    if path == Path::new("-") {
        std::io::stdin()
            .lock()
            .take(limit + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| CliError::runtime(format!("could not read token from stdin: {e}")))?;
    } else {
        let file = open_credential(path).map_err(|e| {
            CliError::runtime(format!("could not open token file {}: {e}", path.display()))
        })?;
        let meta = file.metadata().map_err(|e| {
            CliError::runtime(format!("could not stat token file {}: {e}", path.display()))
        })?;
        if !meta.is_file() {
            return Err(CliError::validation("token file must be a regular file"));
        }
        if meta.len() > limit {
            return Err(CliError::validation(
                "token file exceeds 512 KiB size limit",
            ));
        }
        file.take(limit + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| CliError::runtime(format!("could not read token file: {e}")))?;
    }
    if bytes.len() as u64 > limit {
        return Err(CliError::validation(
            "token input exceeds 512 KiB size limit",
        ));
    }
    Ok(bytes)
}

fn open_credential(path: &Path) -> std::io::Result<fs::File> {
    fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)
}

fn capture_interactive(
    args: &AntigravityCaptureArgs,
    borrow_client: impl FnOnce() -> std::result::Result<ClientMetadata, CliError>,
) -> std::result::Result<CanonicalAgyToken, CliError> {
    let runtime =
        std::env::var_os("XDG_RUNTIME_DIR").map_or_else(std::env::temp_dir, PathBuf::from);
    let profile = tempfile::Builder::new()
        .prefix("provenance-agy-capture-")
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir_in(runtime)
        .map_err(|e| CliError::runtime(format!("could not create isolated agy profile: {e}")))?;
    let home = profile.path();

    let mut command = Command::new(&args.agy_bin);
    command
        .args(["acp", "--login", "--disable-telemetry"])
        .current_dir(home)
        .env("HOME", home)
        .env("GEMINI_HOME", home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("XDG_DATA_HOME", home.join("data"))
        .env("XDG_STATE_HOME", home.join("state"))
        .env("XDG_CACHE_HOME", home.join("cache"))
        .env("XDG_RUNTIME_DIR", home)
        .env(
            "DBUS_SESSION_BUS_ADDRESS",
            format!("unix:path={}/no-session-bus", home.display()),
        )
        .env_remove("GEMINI_API_KEY")
        .env_remove("GOOGLE_API_KEY");

    let result = run_attended(&mut command).and_then(|status| {
        if !status.success() {
            return Err(CliError::runtime(
                "agy ACP login failed; no credential was captured",
            ));
        }
        scan_profile_credential(home, borrow_client)
    });
    if let Err(error) = profile.close() {
        let cleanup = format!(
            "could not remove isolated agy login directory: {:?}",
            error.kind()
        );
        return Err(match result {
            Err(original) => CliError::with_code(original.code, format!("{original}; {cleanup}")),
            Ok(_) => CliError::runtime(cleanup),
        });
    }
    result
}

pub(crate) fn run_attended(command: &mut Command) -> std::result::Result<ExitStatus, CliError> {
    let tty = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .map_err(|e| {
            CliError::runtime(format!(
                "interactive sign-in requires a controlling terminal (/dev/tty): {e}"
            ))
        })?;
    let stdout = tty
        .try_clone()
        .map_err(|e| CliError::runtime(format!("clone /dev/tty: {e}")))?;
    let stderr = tty
        .try_clone()
        .map_err(|e| CliError::runtime(format!("clone /dev/tty: {e}")))?;
    command
        .stdin(tty)
        .stdout(stdout)
        .stderr(stderr)
        .status()
        .map_err(|e| CliError::runtime(format!("failed to execute interactive command: {e}")))
}

#[derive(Deserialize)]
#[serde(untagged)]
enum Scopes {
    List(Vec<String>),
    Text(String),
}

#[derive(Deserialize)]
struct TokenFields {
    #[serde(default, deserialize_with = "deserialize_optional_secret")]
    refresh_token: Option<Zeroizing<String>>,
    scopes: Option<Scopes>,
    scope: Option<Scopes>,
}

#[derive(Deserialize)]
struct TokenInput {
    // Keep secrets out of serde's generic flatten/untagged buffers.
    #[serde(default, deserialize_with = "deserialize_optional_secret")]
    refresh_token: Option<Zeroizing<String>>,
    #[serde(default, deserialize_with = "deserialize_optional_secret")]
    client_secret: Option<Zeroizing<String>>,
    client_id: Option<String>,
    token_uri: Option<String>,
    project_id: Option<String>,
    scopes: Option<Scopes>,
    scope: Option<Scopes>,
    token: Option<TokenFields>,
}

impl TokenInput {
    fn refresh_tokens(&self) -> (Option<&str>, Option<&str>) {
        (
            self.refresh_token.as_deref().map(String::as_str),
            self.token
                .as_ref()
                .and_then(|t| t.refresh_token.as_deref())
                .map(String::as_str),
        )
    }

    fn extract_scopes(&mut self) -> std::result::Result<Option<Vec<String>>, CliError> {
        let nested = self.token.as_mut();
        let (nested_scopes, nested_scope) =
            nested.map_or((None, None), |t| (t.scopes.take(), t.scope.take()));
        let scopes = match self
            .scopes
            .take()
            .or(nested_scopes)
            .or(self.scope.take())
            .or(nested_scope)
        {
            None => return Ok(None),
            Some(Scopes::Text(text)) => text.split_whitespace().map(str::to_owned).collect(),
            Some(Scopes::List(scopes)) => scopes,
        };
        if scopes.iter().any(|scope| scope.trim().is_empty()) {
            return Err(CliError::validation(
                "invalid scope entry in agy credential",
            ));
        }
        Ok(Some(scopes))
    }

    fn client(
        &mut self,
        borrow_client: impl FnOnce() -> std::result::Result<ClientMetadata, CliError>,
    ) -> std::result::Result<ClientMetadata, CliError> {
        match (self.client_id.take(), self.client_secret.take()) {
            (Some(client_id), Some(secret)) => Ok(ClientMetadata {
                client_id,
                client_secret: Secret(secret.to_string()),
                token_uri: self
                    .token_uri
                    .take()
                    .unwrap_or_else(|| GOOGLE_TOKEN_URI.to_owned()),
            }),
            (None, None) => {
                let mut client = borrow_client()?;
                if let Some(uri) = self.token_uri.take() {
                    client.token_uri = uri;
                }
                Ok(client)
            }
            _ => Err(CliError::validation(
                "incomplete Antigravity OAuth client metadata",
            )),
        }
    }
}

fn default_scopes() -> Vec<String> {
    DEFAULT_ANTIGRAVITY_SCOPES
        .iter()
        .map(|s| (*s).to_owned())
        .collect()
}

fn normalize_token_bytes(
    bytes: &[u8],
    borrow_client: impl FnOnce() -> std::result::Result<ClientMetadata, CliError>,
) -> std::result::Result<CanonicalAgyToken, CliError> {
    let value: TokenInput = serde_json::from_slice(bytes)
        .map_err(|_| CliError::validation("input is not valid Antigravity token JSON"))?;
    if !bytes
        .iter()
        .find(|byte| !byte.is_ascii_whitespace())
        .is_some_and(|&byte| byte == b'{')
    {
        return Err(CliError::validation(
            "Antigravity token input must be a JSON object",
        ));
    }

    normalize_token(value, borrow_client)
}

fn normalize_token(
    mut value: TokenInput,
    borrow_client: impl FnOnce() -> std::result::Result<ClientMetadata, CliError>,
) -> std::result::Result<CanonicalAgyToken, CliError> {
    let (top, nested) = value.refresh_tokens();
    let refresh_token = match (top, nested) {
        (Some(a), Some(b)) if a != b => {
            return Err(CliError::validation(
                "token input contains conflicting refresh_token values",
            ));
        }
        (Some(a), _) => Secret(a.to_owned()),
        (None, Some(b)) => Secret(b.to_owned()),
        (None, None) => {
            return Err(CliError::validation(
                "Antigravity token JSON is missing refresh_token",
            ));
        }
    };

    let scopes = value.extract_scopes()?.unwrap_or_else(default_scopes);
    let client = value.client(borrow_client)?;

    Ok(CanonicalAgyToken {
        client_id: client.client_id,
        client_secret: client.client_secret,
        token_uri: client.token_uri,
        refresh_token,
        scopes,
        project_id: value
            .project_id
            .filter(|project| !project.trim().is_empty()),
    })
}

fn scan_profile_credential(
    profile: &Path,
    borrow_client: impl FnOnce() -> std::result::Result<ClientMetadata, CliError>,
) -> std::result::Result<CanonicalAgyToken, CliError> {
    #[derive(Deserialize)]
    struct RefreshOnly<'a> {
        #[serde(borrow)]
        refresh_token: Option<&'a RawValue>,
        #[serde(borrow)]
        token: Option<&'a RawValue>,
    }

    let xdg_cache = profile.join("cache");
    let mut files = Vec::new();
    let mut directories = vec![profile.to_owned()];
    while let Some(directory) = directories.pop() {
        let entries = fs::read_dir(&directory)
            .map_err(|e| CliError::runtime(format!("read isolated agy profile: {e}")))?;
        for entry in entries {
            let entry = entry
                .map_err(|e| CliError::runtime(format!("read isolated agy profile entry: {e}")))?;
            let path = entry.path();
            let kind = entry
                .file_type()
                .map_err(|e| CliError::runtime(format!("inspect agy profile entry: {e}")))?;
            if kind.is_dir() {
                if path != xdg_cache {
                    directories.push(path);
                }
            } else if kind.is_file() {
                files.push(path);
            }
        }
    }
    files.sort_unstable();

    let mut refresh_token: Option<Secret> = None;
    let mut found_complete_input = false;
    let mut full_acp: Option<CanonicalAgyToken> = None;
    let mut scopes: Option<Vec<String>> = None;

    for path in &files {
        let file = open_credential(path)
            .map_err(|e| CliError::runtime(format!("open isolated agy profile file: {e}")))?;
        let metadata = file
            .metadata()
            .map_err(|e| CliError::runtime(format!("stat isolated agy profile file: {e}")))?;
        if !metadata.is_file() || metadata.len() > MAX_CREDENTIAL_BYTES {
            continue;
        }
        let mut bytes = Zeroizing::new(Vec::new());
        file.take(MAX_CREDENTIAL_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| CliError::runtime(format!("read isolated agy profile file: {e}")))?;
        if bytes.len() as u64 > MAX_CREDENTIAL_BYTES
            || !bytes
                .iter()
                .find(|byte| !byte.is_ascii_whitespace())
                .is_some_and(|byte| *byte == b'{')
        {
            continue;
        }
        let probe: RefreshOnly<'_> = match serde_json::from_slice(&bytes) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let nested = probe.token.and_then(parse_raw_object::<RefreshOnly<'_>>);
        let mut tokens = [
            probe.refresh_token,
            nested.and_then(|token| token.refresh_token),
        ]
        .into_iter()
        .flatten()
        .filter_map(parse_raw_string);
        // Count refresh tokens even if the corresponding OAuth metadata cannot be parsed.
        let Some(first) = tokens.next() else {
            continue;
        };
        for tok in std::iter::once(first).chain(tokens) {
            let selected = refresh_token.get_or_insert_with(|| Secret(tok.to_string()));
            if selected.0 != tok.as_str() {
                return Err(CliError::validation(
                    "isolated agy profile contains multiple distinct refresh tokens",
                ));
            }
        }
        let Ok(mut value) = serde_json::from_slice::<TokenInput>(&bytes) else {
            continue;
        };
        found_complete_input = true;
        if value
            .token_uri
            .as_deref()
            .is_some_and(|uri| uri != GOOGLE_TOKEN_URI)
        {
            return Err(CliError::validation("invalid Antigravity token URI"));
        }
        if value.client_id.is_some() || value.client_secret.is_some() {
            let token = normalize_token(value, || {
                Err(CliError::validation(
                    "missing Antigravity OAuth client metadata",
                ))
            })?;
            full_acp.get_or_insert(token);
        } else if scopes.is_none() {
            scopes = value.extract_scopes()?;
        }
    }

    let refresh_token = refresh_token
        .filter(|_| found_complete_input)
        .ok_or_else(|| {
            CliError::runtime("agy ACP login wrote no refresh token in the isolated profile")
        })?;

    if let Some(acp) = full_acp {
        return Ok(acp);
    }

    let client = borrow_client()?;
    Ok(CanonicalAgyToken {
        client_id: client.client_id,
        client_secret: client.client_secret,
        token_uri: client.token_uri,
        refresh_token,
        scopes: scopes.unwrap_or_else(default_scopes),
        project_id: None,
    })
}

fn export_grant_in_process(config: &Config) -> Result<Option<Grant>> {
    let store = match Store::lock_for_inspection(config) {
        Ok(s) => s,
        Err(_) => return Ok(None),
    };
    match store.grant() {
        Ok(grant) => Ok(Some(grant)),
        Err(_) => Ok(None),
    }
}

fn read_client_manifest(manifest_path: &Path) -> std::result::Result<Config, CliError> {
    let config: Config = read_json(manifest_path, false).map_err(|e| {
        CliError::validation(format!(
            "invalid --client-metadata-from manifest {}: {e:#}",
            manifest_path.display()
        ))
    })?;
    if config.target.provider != "google" || config.target.profile != "antigravity" {
        return Err(CliError::validation(
            "--client-metadata-from requires a google/antigravity manifest",
        ));
    }
    config
        .validate_state_location()
        .map_err(|e| CliError::validation(format!("invalid manifest config: {e:#}")))?;
    Ok(config)
}

fn borrow_client_metadata(
    args: &AntigravityCaptureArgs,
    manifest: Option<&Config>,
) -> std::result::Result<ClientMetadata, CliError> {
    if let Some(config) = manifest {
        let grant = export_grant_in_process(config)
            .map_err(|e| CliError::runtime(format!("read manifest grant: {e:#}")))?
            .ok_or_else(|| {
                CliError::validation(
                    "--client-metadata-from manifest has no initialized Antigravity grant to borrow client metadata from",
                )
            })?;
        let client: OAuthClient = grant.client.ok_or_else(|| {
            CliError::validation("borrowed grant is missing OAuth client metadata")
        })?;
        return Ok(ClientMetadata {
            client_id: client.client_id,
            client_secret: client.client_secret,
            token_uri: GOOGLE_TOKEN_URI.to_owned(),
        });
    }

    let host = match &args.host {
        Some(h) => h.clone(),
        None => local_hostname().map_err(|e| CliError::runtime(format!("{e:#}")))?,
    };
    let user = match &args.user {
        Some(u) => u.clone(),
        None => local_user().map_err(|e| CliError::runtime(format!("{e:#}")))?,
    };

    let manifests = discover_agy_manifests(&host, &user, &args.manifests_dir)
        .map_err(|e| CliError::runtime(format!("{e:#}")))?;

    if manifests.is_empty() {
        return Err(CliError::validation(format!(
            "no deployed google/antigravity enrollment for {user} on {host}; pass --client-metadata-from or an ACP-format --token-file"
        )));
    }

    for (_, config) in &manifests {
        if let Ok(Some(grant)) = export_grant_in_process(config)
            && let Some(client) = grant.client
        {
            return Ok(ClientMetadata {
                client_id: client.client_id,
                client_secret: client.client_secret,
                token_uri: GOOGLE_TOKEN_URI.to_owned(),
            });
        }
    }

    Err(CliError::validation(format!(
        "no deployed google/antigravity enrollment for {user} on {host} could export OAuth client metadata; initialize an enrollment or pass --client-metadata-from"
    )))
}

fn local_hostname() -> Result<String> {
    let host = fs::read_to_string("/proc/sys/kernel/hostname")
        .context("read /proc/sys/kernel/hostname")?;
    let trimmed = host.trim();
    ensure!(!trimmed.is_empty(), "empty local hostname");
    Ok(trimmed.to_owned())
}

fn local_user() -> Result<String> {
    let out = Command::new("id")
        .arg("-un")
        .stdin(Stdio::null())
        .output()
        .context("resolve current local user")?;
    ensure!(out.status.success(), "id -un failed");
    let user = String::from_utf8(out.stdout)
        .context("decode id -un output")?
        .trim()
        .to_owned();
    ensure!(!user.is_empty(), "empty current local user");
    Ok(user)
}

fn discover_agy_manifests(
    host: &str,
    user: &str,
    directory: &Path,
) -> Result<Vec<(String, Config)>> {
    let entries = match fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => return Err(err).context("list deployed OAuth manifests"),
    };
    let prefix = format!("{user}-");
    let mut paths = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(id_from_name) = name
            .to_str()
            .and_then(|n| n.strip_prefix(&prefix)?.strip_suffix(".json"))
        else {
            continue;
        };
        paths.push((id_from_name.to_owned(), entry.path()));
    }
    paths.sort_unstable_by(|a, b| a.1.cmp(&b.1));

    let mut matched = Vec::new();
    for (id_from_name, path) in paths {
        let Ok(config) = read_json::<Config>(&path, false) else {
            continue;
        };
        if config.target.host != host
            || config.target.user != user
            || config.target.provider != "google"
            || config.target.profile != "antigravity"
            || config.validate_state_location().is_err()
        {
            continue;
        }
        let id = config.target.enrollment.clone().unwrap_or(id_from_name);
        if valid_enrollment_id(&id) {
            matched.push((id, config));
        }
    }
    Ok(matched)
}

// ---------------------------------------------------------------------------
// antigravity-check
// ---------------------------------------------------------------------------

#[derive(Deserialize, Serialize, Clone, Debug, PartialEq, Eq)]
pub struct Selection {
    pub enrollment: String,
    pub declared: String,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckHealth {
    #[default]
    Failed,
    Degraded,
    Healthy,
}

#[derive(Serialize, Debug)]
pub struct ModelDiscovery {
    pub ids: BTreeSet<String>,
    pub count: usize,
    pub gemini_neon: bool,
    pub claude: bool,
    pub warning: Option<&'static str>,
}

#[derive(Serialize, Debug)]
pub struct SmokeReport {
    pub model: String,
    pub effort: Option<String>,
    pub normalized_from: Option<String>,
    pub passed: bool,
}

#[derive(Default, Serialize, Debug)]
pub struct CheckReport {
    pub host: String,
    pub user: String,
    pub requested_enrollment: Option<String>,
    pub active_enrollment: Option<String>,
    pub enrollment_status: Option<String>,
    pub selection: Option<Selection>,
    pub warnings: Vec<String>,
    pub models: Option<ModelDiscovery>,
    pub smoke: Option<SmokeReport>,
    #[serde(skip)]
    pub health: CheckHealth,
}

impl CheckReport {
    fn to_json(&self, result: &Result<()>) -> Value {
        let error = result.as_ref().err();
        json!({
            "ok": result.is_ok(),
            "health": self.health,
            "check": self,
            "error_code": error.and_then(|e| e.downcast_ref::<ProviderError>()),
            "error": error.map(|e| format!("{e:#}")),
        })
    }

    fn record_models(&mut self, models: ModelDiscovery) -> Result<()> {
        let warning = models.warning;
        self.models = Some(models);
        if let Some(warning) = warning {
            self.health = CheckHealth::Degraded;
            bail!("{warning}");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProviderError {
    ValidationRequired,
    QuotaExceeded,
    Unauthenticated,
    NotFound,
    HttpError,
    Timeout,
    UnknownError,
}

impl ProviderError {
    fn reason(reason: &str) -> Option<Self> {
        Some(match reason {
            "VALIDATION_REQUIRED" => Self::ValidationRequired,
            "QUOTA_EXCEEDED" | "RESOURCE_EXHAUSTED" | "RATE_LIMIT_EXCEEDED" => Self::QuotaExceeded,
            "UNAUTHENTICATED" | "invalid_grant" | "invalid_token" | "invalid_client" => {
                Self::Unauthenticated
            }
            "NOT_FOUND" => Self::NotFound,
            "HTTP_ERROR" | "PERMISSION_DENIED" | "FAILED_PRECONDITION" => Self::HttpError,
            "TIMEOUT" | "DEADLINE_EXCEEDED" => Self::Timeout,
            "UNKNOWN_ERROR" => Self::UnknownError,
            _ => return None,
        })
    }

    fn http(status: u64) -> Option<Self> {
        Some(match status {
            401 => Self::Unauthenticated,
            404 => Self::NotFound,
            429 => Self::QuotaExceeded,
            400..=599 => Self::HttpError,
            _ => return None,
        })
    }
}

impl std::fmt::Display for ProviderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::ValidationRequired => {
                "VALIDATION_REQUIRED: Verify the enrolled account through Google, then retry."
            }
            Self::QuotaExceeded => {
                "QUOTA_EXCEEDED: Wait for quota to reset or check usage in Google Antigravity."
            }
            Self::Unauthenticated => {
                "UNAUTHENTICATED: Check that the enrolled Google grant is still authorized."
            }
            Self::NotFound => "NOT_FOUND: Check that the requested model is still available.",
            Self::HttpError => {
                "HTTP_ERROR: Check provider availability and the enrolled grant, then retry."
            }
            Self::Timeout => "TIMEOUT: agy probe timed out before completing.",
            Self::UnknownError => {
                "UNKNOWN_ERROR: agy failed without a recognized provider error code."
            }
        })
    }
}

impl std::error::Error for ProviderError {}

#[derive(PartialEq, Eq)]
struct AgyGrant {
    client_id: String,
    client_secret: String,
    refresh_token: String,
    project_id: Option<String>,
}

impl Drop for AgyGrant {
    fn drop(&mut self) {
        self.client_secret.zeroize();
        self.refresh_token.zeroize();
    }
}

impl AgyGrant {
    fn parse(bytes: &[u8]) -> Result<Self> {
        let grant = parse_agy_token(bytes)?;
        Self::from_grant(&grant).context("ACP grant is missing OAuth client metadata")
    }

    fn from_grant(grant: &Grant) -> Option<Self> {
        let client = grant.client.as_ref()?;
        Some(Self {
            client_id: client.client_id.clone(),
            client_secret: client.client_secret.0.clone(),
            refresh_token: grant.refresh_token.0.clone(),
            project_id: grant.project_id.clone(),
        })
    }
}

pub fn run_check(args: AntigravityCheckArgs) -> std::result::Result<(), CliError> {
    let host = match &args.host {
        Some(h) => h.clone(),
        None => local_hostname().unwrap_or_default(),
    };
    let user = match &args.user {
        Some(u) => u.clone(),
        None => local_user().unwrap_or_default(),
    };
    let mut report = CheckReport {
        host,
        user,
        requested_enrollment: args.enrollment.clone(),
        ..Default::default()
    };

    let result = execute_check(&args, &mut report);
    let failure_code = result.as_ref().err().map_or(1, |error| {
        error
            .downcast_ref::<CliError>()
            .map_or(1, |error| error.code)
    });

    if args.json {
        let payload = report.to_json(&result);
        println!(
            "{}",
            serde_json::to_string_pretty(&payload).unwrap_or_else(|_| payload.to_string())
        );
        return match result {
            Ok(()) => Ok(()),
            Err(_) if report.health == CheckHealth::Degraded => Err(CliError::silent(3)),
            Err(_) => Err(CliError::silent(failure_code)),
        };
    }

    println!("Google/Antigravity on {} as {}", report.host, report.user);
    println!(
        "T3 active enrollment: {}",
        report.active_enrollment.as_deref().unwrap_or("unverified")
    );
    if let Some(id) = report
        .requested_enrollment
        .as_deref()
        .or(report.active_enrollment.as_deref())
    {
        println!(
            "Enrollment {id}: {}",
            report.enrollment_status.as_deref().unwrap_or("unverified")
        );
    }
    match &report.selection {
        Some(selection) => println!(
            "Recorded selection: {} (deployed default: {})",
            selection.enrollment, selection.declared
        ),
        None => println!("Recorded selection: unavailable"),
    }
    for warning in &report.warnings {
        eprintln!("WARNING: {warning}");
    }
    if let Some(models) = &report.models {
        println!(
            "{} models; Gemini 4 Neon: {}; Claude: {}",
            models.count, models.gemini_neon, models.claude
        );
        if report.health == CheckHealth::Degraded {
            println!("Model health: degraded");
        }
    }
    if let Some(smoke) = &report.smoke {
        if let Some(original) = &smoke.normalized_from {
            println!(
                "Smoke model {original} normalized to --model {} --effort {}",
                smoke.model,
                smoke.effort.as_deref().unwrap_or_default()
            );
        }
        if smoke.passed {
            println!("Smoke passed: OK");
        }
    }

    match result {
        Ok(()) => Ok(()),
        Err(e) if report.health == CheckHealth::Degraded => {
            Err(CliError::with_code(3, format!("{e:#}")))
        }
        Err(e) => Err(CliError::with_code(failure_code, format!("{e:#}"))),
    }
}

fn require_effective_user(user: &str) -> std::result::Result<(), CliError> {
    let output = Command::new("id")
        .args(["-u", "--", user])
        .output()
        .map_err(|err| CliError::runtime(format!("resolve UID for requested --user: {err}")))?;
    // SAFETY: geteuid takes no arguments and has no failure mode.
    let uid = unsafe { libc::geteuid() };
    if !output.status.success()
        || String::from_utf8_lossy(&output.stdout)
            .trim()
            .parse::<libc::uid_t>()
            .ok()
            != Some(uid)
    {
        return Err(CliError::validation(format!(
            "--user {user:?} does not match the effective UID; run as the requested user"
        )));
    }
    Ok(())
}

fn execute_check(args: &AntigravityCheckArgs, report: &mut CheckReport) -> Result<()> {
    ensure!(!report.host.is_empty(), "could not resolve local hostname");
    ensure!(!report.user.is_empty(), "could not resolve local user");
    if let Some(user) = &args.user {
        require_effective_user(user)?;
    }

    let selection_path = match &args.selection_file {
        Some(p) => p.clone(),
        None => {
            xdg_home("XDG_STATE_HOME", ".local/state")?.join("nix-provenance/antigravity-selection")
        }
    };
    match read_selection(&selection_path) {
        Ok(selection) => report.selection = selection,
        Err(err) => report
            .warnings
            .push(format!("cannot read Antigravity selection: {err}")),
    }

    let manifests = discover_agy_manifests(&report.host, &report.user, &args.manifests_dir)?;

    let requested_state = report
        .requested_enrollment
        .as_deref()
        .map(|id| enrollment_state(&manifests, id))
        .transpose();
    match &requested_state {
        Ok(state) => report.enrollment_status.clone_from(state),
        Err(err) => report.warnings.push(err.to_string()),
    }

    let profile = match &args.profile_dir {
        Some(p) => p.clone(),
        None => discover_t3_profile(
            &xdg_home("XDG_DATA_HOME", ".local/share")?
                .join("t3code-native/userdata/providers/antigravity"),
        )?,
    };

    let token_path = profile.join(ACP_TOKEN_REL);
    let bytes = read_bounded_input(&token_path, MAX_CREDENTIAL_BYTES)
        .context("read T3's Antigravity ACP grant; agy probe not run")?;
    let grant = AgyGrant::parse(&bytes).map_err(|e| CliError::validation(e.to_string()))?;

    report.active_enrollment = match_active_enrollment(&manifests, &grant)?;
    let active = require_matching_enrollment(
        report.requested_enrollment.as_deref(),
        report.active_enrollment.as_deref(),
        report.selection.as_ref(),
    )?
    .to_owned();

    requested_state?;
    if report.enrollment_status.is_none() {
        report.enrollment_status = Some(enrollment_state(&manifests, &active)?);
    }
    ensure!(
        report.enrollment_status.as_deref() == Some("enrolled"),
        "enrollment {active} is not enrolled; agy probe not run"
    );

    let (stdout, _) = run_agy_probe(
        &args.agy_bin,
        &["--output-format", "json", "models"],
        &grant,
        Duration::from_secs(args.models_timeout_secs),
        "model discovery",
    )?;
    report.record_models(parse_models(&stdout)?)?;

    if let Some(model) = &args.smoke_model {
        let models = report
            .models
            .as_ref()
            .context("missing agy discovery result")?;
        let (base, effort) = resolve_smoke_model(&models.ids, model, args.smoke_effort.as_deref())?;
        let timeout_arg = format!("{}s", args.smoke_timeout_secs);
        let mut cmd_args = vec!["--mode", "plan", "--model", base];
        if let Some(effort) = effort {
            cmd_args.extend(["--effort", effort]);
        }
        report.smoke = Some(SmokeReport {
            model: base.to_owned(),
            effort: effort.map(str::to_owned),
            normalized_from: (model != base).then(|| model.clone()),
            passed: false,
        });
        cmd_args.extend([
            "--print-timeout",
            &timeout_arg,
            "--print",
            "Reply with exactly OK. Do not use tools.",
        ]);
        let (response, _) = run_agy_probe(
            &args.agy_bin,
            &cmd_args,
            &grant,
            Duration::from_secs(args.smoke_timeout_secs + 10),
            "smoke test",
        )?;
        let stripped = strip_ansi_codes(&response);
        ensure!(
            stripped.trim() == "OK",
            "agy smoke request did not reply with exactly OK"
        );
        if let Some(smoke) = &mut report.smoke {
            smoke.passed = true;
        }
    }

    report.health = CheckHealth::Healthy;
    Ok(())
}

fn xdg_home(var: &str, fallback: &str) -> Result<PathBuf> {
    if let Some(path) = std::env::var_os(var)
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
    {
        return Ok(path);
    }
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .context("HOME is not set")?;
    Ok(home.join(fallback))
}

fn valid_enrollment_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 48
        && id
            .bytes()
            .next()
            .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

fn read_selection(path: &Path) -> Result<Option<Selection>> {
    let file = match open_credential(path) {
        Ok(file) => file,
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err).context("open Antigravity selection record"),
    };
    let meta = file
        .metadata()
        .context("stat Antigravity selection record")?;
    ensure!(
        meta.is_file(),
        "Antigravity selection record must be a regular file"
    );
    ensure!(
        meta.len() <= MAX_SELECTION_BYTES,
        "Antigravity selection record is too large"
    );
    let mut bytes = Vec::new();
    file.take(MAX_SELECTION_BYTES + 1)
        .read_to_end(&mut bytes)
        .context("read Antigravity selection record")?;
    ensure!(
        bytes.len() as u64 <= MAX_SELECTION_BYTES,
        "Antigravity selection record is too large"
    );
    let sel: Selection =
        serde_json::from_slice(&bytes).context("invalid Antigravity selection record")?;
    ensure!(
        valid_enrollment_id(&sel.enrollment),
        "invalid recorded enrollment ID"
    );
    ensure!(
        valid_enrollment_id(&sel.declared),
        "invalid recorded declaration ID"
    );
    Ok(Some(sel))
}

fn discover_t3_profile(directory: &Path) -> Result<PathBuf> {
    let mut profiles = BTreeSet::new();
    match fs::read_dir(directory) {
        Ok(entries) => {
            for entry in entries {
                let profile = entry?.path();
                match profile.join(ACP_TOKEN_REL).metadata() {
                    Ok(meta) if meta.is_file() => {
                        profiles.insert(profile.canonicalize()?);
                    }
                    Ok(_) => {}
                    Err(err)
                        if matches!(err.kind(), ErrorKind::NotFound | ErrorKind::NotADirectory) => {
                    }
                    Err(err) => return Err(err).context("inspect T3 Antigravity profile"),
                }
            }
        }
        Err(err) if err.kind() == ErrorKind::NotFound => {}
        Err(err) => return Err(err).context("discover T3 Antigravity profiles"),
    }
    match profiles.len() {
        0 => bail!("no T3 Antigravity profile found under {directory:?}"),
        1 => profiles
            .pop_first()
            .context("no T3 Antigravity profile found"),
        _ => bail!(
            "multiple T3 Antigravity profiles found; specify --profile-dir with one of {profiles:?}"
        ),
    }
}

fn enrollment_state(manifests: &[(String, Config)], id: &str) -> Result<String> {
    let Some((_, config)) = manifests.iter().find(|(candidate, _)| candidate == id) else {
        return Ok("not deployed".into());
    };
    let store = Store::lock_for_inspection(config)
        .with_context(|| format!("cannot read enrollment {id} status"))?;
    let status = store
        .status()
        .with_context(|| format!("cannot read enrollment {id} status"))?;
    let state = status["state"]
        .as_str()
        .filter(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_lowercase() || b == b'-'))
        .context("missing or invalid OAuth enrollment state")?;
    Ok(state.to_owned())
}

fn match_active_enrollment(
    manifests: &[(String, Config)],
    grant: &AgyGrant,
) -> Result<Option<String>> {
    let mut active = None;
    for (id, config) in manifests {
        if let Ok(Some(exported)) = export_grant_in_process(config)
            && AgyGrant::from_grant(&exported).is_some_and(|candidate| candidate == *grant)
        {
            ensure!(
                active.is_none(),
                "T3's grant matches more than one deployed enrollment; agy probe not run"
            );
            active = Some(id.clone());
        }
    }
    Ok(active)
}

fn require_matching_enrollment<'a>(
    requested: Option<&str>,
    active: Option<&'a str>,
    selection: Option<&Selection>,
) -> Result<&'a str> {
    let Some(active) = active else {
        bail!("T3's active Google enrollment could not be verified; agy probe not run");
    };
    if let Some(selection) = selection {
        ensure!(
            selection.enrollment == active,
            "recorded enrollment {} differs from the installed T3 enrollment {active}; switch explicitly to sync it; agy probe not run",
            selection.enrollment
        );
    }
    if let Some(requested) = requested {
        ensure!(
            requested == active,
            "requested enrollment {requested}, but T3 is using {active}; switch accounts explicitly first; agy probe not run"
        );
    }
    Ok(active)
}

fn write_probe_credential(directory: &Path, grant: &AgyGrant) -> Result<()> {
    #[derive(Serialize)]
    struct Credential<'a> {
        auth_method: &'static str,
        token: RefreshToken<'a>,
    }
    #[derive(Serialize)]
    struct RefreshToken<'a> {
        token_type: &'static str,
        refresh_token: &'a str,
    }
    let profile = directory.join(".gemini/antigravity-cli");
    fs::create_dir_all(&profile)?;
    let file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(profile.join("antigravity-oauth-token"))?;
    serde_json::to_writer(
        file,
        &Credential {
            auth_method: "consumer",
            token: RefreshToken {
                token_type: "Bearer",
                refresh_token: &grant.refresh_token,
            },
        },
    )?;
    Ok(())
}

struct ChildGuard {
    child: Child,
    reaped: bool,
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if !self.reaped {
            // SAFETY: the unreaped child is the leader of its own process group.
            unsafe { libc::kill(-(self.child.id() as libc::pid_t), libc::SIGKILL) };
            let _ = self.child.wait();
        }
    }
}

fn run_agy_probe(
    agy_bin: &Path,
    args: &[&str],
    grant: &AgyGrant,
    timeout: Duration,
    probe_name: &str,
) -> Result<(Zeroizing<String>, Zeroizing<String>)> {
    let runtime =
        std::env::var_os("XDG_RUNTIME_DIR").map_or_else(std::env::temp_dir, PathBuf::from);
    let temp = tempfile::Builder::new()
        .prefix("provenance-agy-check-")
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir_in(runtime)
        .context("prepare a fresh agy probe directory")?;
    let result = run_isolated_probe(temp.path(), agy_bin, args, grant, timeout, probe_name);
    match temp.close() {
        Ok(()) => result,
        Err(err) => {
            let cleanup = format!(
                "could not remove isolated agy probe directory: {:?}",
                err.kind()
            );
            match result {
                Ok(_) => Err(anyhow::anyhow!(cleanup)),
                Err(error) => Err(error.context(cleanup)),
            }
        }
    }
}

fn run_isolated_probe(
    directory: &Path,
    agy_bin: &Path,
    args: &[&str],
    grant: &AgyGrant,
    timeout: Duration,
    probe_name: &str,
) -> Result<(Zeroizing<String>, Zeroizing<String>)> {
    write_probe_credential(directory, grant)
        .context("prepare the private agy credential snapshot")?;

    let stdout_file = tempfile::NamedTempFile::new_in(directory)?;
    let stderr_file = tempfile::NamedTempFile::new_in(directory)?;

    let mut command = Command::new(agy_bin);
    command
        .args(args)
        .process_group(0)
        .current_dir(directory)
        .stdin(Stdio::null())
        .stdout(stdout_file.reopen()?)
        .stderr(stderr_file.reopen()?)
        .env_clear()
        .envs(std::env::vars_os().filter(|(key, _)| {
            matches!(
                key.to_str(),
                Some(
                    "PATH"
                        | "SSL_CERT_FILE"
                        | "SSL_CERT_DIR"
                        | "NIX_SSL_CERT_FILE"
                        | "HTTP_PROXY"
                        | "HTTPS_PROXY"
                        | "NO_PROXY"
                        | "http_proxy"
                        | "https_proxy"
                        | "no_proxy"
                )
            )
        }))
        .env("HOME", directory)
        .env("GEMINI_HOME", directory)
        .env("XDG_CONFIG_HOME", directory.join("config"))
        .env("XDG_DATA_HOME", directory.join("data"))
        .env("XDG_STATE_HOME", directory.join("state"))
        .env("XDG_CACHE_HOME", directory.join("cache"))
        .env("XDG_RUNTIME_DIR", directory)
        .env("DBUS_SESSION_BUS_ADDRESS", NO_SESSION_BUS)
        .env("BROWSER", "false");

    let mut child = ChildGuard {
        child: command.spawn().context("start agy")?,
        reaped: false,
    };
    let deadline = Instant::now() + timeout;
    let status = loop {
        if let Some(status) = child.child.try_wait().context("wait for agy")? {
            child.reaped = true;
            break status;
        }
        if Instant::now() >= deadline {
            return Err(anyhow::Error::new(ProviderError::Timeout)
                .context(format!("agy {probe_name} failed")));
        }
        std::thread::sleep(Duration::from_millis(20));
    };

    let read_capped = |file: fs::File| -> Result<Zeroizing<String>> {
        let mut data = Zeroizing::new(String::new());
        file.take(MAX_PROBE_OUTPUT + 1)
            .read_to_string(&mut data)
            .map_err(|_| anyhow::anyhow!("cannot read agy probe output"))?;
        ensure!(
            data.len() as u64 <= MAX_PROBE_OUTPUT,
            "agy probe output exceeded the capture limit"
        );
        Ok(data)
    };
    let stdout = read_capped(stdout_file.into_file())?;
    let stderr = read_capped(stderr_file.into_file())?;

    if let Some(error) = classify_provider_error(&stdout, &stderr)
        .or_else(|| (!status.success()).then_some(ProviderError::UnknownError))
    {
        return Err(anyhow::Error::new(error).context(format!("agy {probe_name} failed")));
    }
    Ok((stdout, stderr))
}

pub fn valid_model_id(id: &str) -> bool {
    let bytes = id.as_bytes();
    let edge = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    !bytes.is_empty()
        && bytes.len() <= 64
        && edge(bytes[0])
        && edge(*bytes.last().unwrap())
        && bytes
            .iter()
            .all(|&b| edge(b) || matches!(b, b'.' | b'_' | b'-'))
        && !bytes
            .windows(2)
            .any(|pair| !edge(pair[0]) && !edge(pair[1]))
        && !["ya29.", "gocspx-", "aiza", "eyj", "ghp_", "sk-", "xoxb-"]
            .iter()
            .any(|prefix| id.starts_with(prefix))
}

pub fn effort_variant(model: &str) -> Option<(&str, &str)> {
    let (base, effort) = model.rsplit_once('-')?;
    EFFORTS.contains(&effort).then_some((base, effort))
}

pub fn parse_models(stdout: &str) -> Result<ModelDiscovery> {
    let value: Value = serde_json::from_str(stdout)
        .map_err(|_| anyhow::anyhow!("agy models did not return a structured JSON report"))?;
    ensure!(
        value["status"] == "SUCCESS",
        "agy models did not report success"
    );
    let rows = value["structured_output"]["models"]
        .as_array()
        .context("agy model report is missing its models array")?;
    let mut ids = BTreeSet::new();
    for row in rows {
        let id = row
            .as_object()
            .and_then(|obj| obj.get("id"))
            .and_then(Value::as_str)
            .filter(|id| valid_model_id(id))
            .context("agy models returned a malformed or unrecognized model row")?;
        ids.insert(id.to_owned());
    }
    let gemini_neon = ids
        .iter()
        .any(|id| effort_variant(id).map_or(id.as_str(), |(base, _)| base) == "gemini-4-neon");
    let claude = ids.iter().any(|id| {
        id.strip_prefix("claude-")
            .and_then(|variant| variant.as_bytes().first())
            .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
    });
    let warning = (!gemini_neon || !claude).then_some(
        "Flagship models are missing (Gemini 4 Neon or Claude); the list does not establish an account tier or cause.",
    );
    Ok(ModelDiscovery {
        count: ids.len(),
        ids,
        gemini_neon,
        claude,
        warning,
    })
}

pub fn resolve_smoke_model<'a>(
    ids: &BTreeSet<String>,
    model: &'a str,
    explicit: Option<&str>,
) -> Result<(&'a str, Option<&'a str>)> {
    let explicit = explicit
        .map(|effort| {
            EFFORTS
                .iter()
                .copied()
                .find(|known| known.eq_ignore_ascii_case(effort))
                .context("invalid agy smoke effort")
        })
        .transpose()?;
    if ids.contains(model)
        && let Some((base, suffix)) = effort_variant(model)
    {
        ensure!(
            explicit.is_none_or(|effort| effort == suffix),
            "{model} already selects effort {suffix}; use --smoke-model {base} --smoke-effort {suffix}"
        );
        return Ok((base, Some(suffix)));
    }
    if let Some(effort) = explicit {
        let has_effort_variants = ids
            .iter()
            .any(|id| effort_variant(id).is_some_and(|(base, _)| base == model));
        let variant = ids.contains(&format!("{model}-{effort}"));
        ensure!(
            variant || (!has_effort_variants && ids.contains(model)),
            "agy models did not advertise {model} with effort {effort}"
        );
        return Ok((model, Some(effort)));
    }
    ensure!(
        ids.contains(model),
        "agy models did not advertise {model} with the requested effort"
    );
    Ok((model, None))
}

pub fn strip_ansi_codes(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == 0x1b && i + 1 < bytes.len() {
            match bytes[i + 1] {
                b'[' => {
                    i += 2;
                    while i < bytes.len() && !(0x40..=0x7e).contains(&bytes[i]) {
                        i += 1;
                    }
                    if i < bytes.len() {
                        i += 1;
                    }
                }
                b']' => {
                    i += 2;
                    while i < bytes.len() {
                        if bytes[i] == 0x07 {
                            i += 1;
                            break;
                        }
                        if bytes[i] == 0x1b && i + 1 < bytes.len() && bytes[i + 1] == b'\\' {
                            i += 2;
                            break;
                        }
                        i += 1;
                    }
                }
                0x20..=0x7e => {
                    i += 2;
                }
                _ => i += 1,
            }
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).unwrap_or_default()
}

fn parse_http_status_line(line: &str) -> Option<u64> {
    let lower = line.to_ascii_lowercase();
    let rest = if let Some(after) = lower.strip_prefix("http") {
        let after = if let Some(v) = after.strip_prefix('/') {
            let digits_end = v
                .bytes()
                .take_while(|b| b.is_ascii_digit() || *b == b'.')
                .count();
            if digits_end == 0 {
                return None;
            }
            &v[digits_end..]
        } else {
            after
        };
        after.strip_prefix(" status").unwrap_or(after)
    } else if let Some(after) = lower.strip_prefix("status") {
        after.strip_prefix(" code").unwrap_or(after)
    } else if let Some(after) = lower.strip_prefix("googleapi:") {
        after.trim_start().strip_prefix("error")?
    } else {
        lower.strip_prefix("error")?
    };

    let rest = rest.trim_start();
    let rest = rest
        .strip_prefix(':')
        .or_else(|| rest.strip_prefix('='))
        .unwrap_or(rest)
        .trim_start();
    let bytes = rest.as_bytes();
    if bytes.len() < 3
        || !matches!(bytes[0], b'4' | b'5')
        || !bytes[1].is_ascii_digit()
        || !bytes[2].is_ascii_digit()
    {
        return None;
    }
    if bytes.len() > 3 && bytes[3].is_ascii_alphanumeric() {
        return None;
    }
    rest[..3].parse().ok()
}

fn parse_raw_object<'a, T: Deserialize<'a>>(raw: &'a RawValue) -> Option<T> {
    raw.get()
        .starts_with('{')
        .then(|| serde_json::from_str(raw.get()).ok())
        .flatten()
}

fn parse_raw_string(raw: &RawValue) -> Option<Zeroizing<String>> {
    serde_json::from_str::<String>(raw.get())
        .ok()
        .map(Zeroizing::new)
}

pub fn classify_provider_error(stdout: &str, stderr: &str) -> Option<ProviderError> {
    // Borrow only fields used for classification. Unknown fields (and invalid
    // types in known fields) must not copy secrets or mask valid signals.
    #[derive(Deserialize)]
    struct ErrorFields<'a> {
        #[serde(borrow)]
        error: Option<&'a RawValue>,
        #[serde(borrow)]
        details: Option<&'a RawValue>,
        #[serde(borrow)]
        reason: Option<&'a RawValue>,
        #[serde(borrow)]
        status: Option<&'a RawValue>,
        code: Option<&'a RawValue>,
    }

    fn classify_reason(raw: &RawValue) -> Option<ProviderError> {
        ProviderError::reason(&parse_raw_string(raw)?)
    }

    for stream in [stderr, stdout] {
        let stream = Zeroizing::new(strip_ansi_codes(stream));
        for (start, _) in stream.match_indices('{').take(32) {
            let mut json =
                serde_json::Deserializer::from_str(&stream[start..]).into_iter::<ErrorFields<'_>>();
            let Some(Ok(envelope)) = json.next() else {
                continue;
            };
            let nested = envelope.error.and_then(parse_raw_object::<ErrorFields<'_>>);
            let error = nested.as_ref().unwrap_or(&envelope);
            let classified = error
                .details
                .and_then(|details| serde_json::from_str::<Vec<&RawValue>>(details.get()).ok())
                .into_iter()
                .flatten()
                .filter_map(parse_raw_object::<ErrorFields<'_>>)
                .find_map(|detail| detail.reason.and_then(classify_reason))
                .or_else(|| error.reason.and_then(classify_reason))
                .or_else(|| error.status.and_then(classify_reason))
                .or_else(|| {
                    error
                        .code
                        .and_then(|code| serde_json::from_str(code.get()).ok())
                        .and_then(ProviderError::http)
                })
                .or_else(|| envelope.error.and_then(classify_reason));
            if classified.is_some() {
                return classified;
            }
        }
        for line in stream.lines().map(str::trim) {
            let line = line.strip_prefix("Error: ").unwrap_or(line);
            if let Some(code) = line
                .split(|c: char| c == ':' || c.is_ascii_whitespace())
                .next()
                .and_then(ProviderError::reason)
                .or_else(|| parse_http_status_line(line).and_then(ProviderError::http))
            {
                return Some(code);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_profile_scan_counts_tokens_with_malformed_metadata() {
        let profile = tempfile::tempdir().unwrap();
        fs::write(
            profile.path().join("a.json"),
            r#"{"refresh_token":"first","client_id":"fixture","client_secret":"fixture"}"#,
        )
        .unwrap();
        for malformed in [
            r#"{"refresh_token":"second","client_id":false}"#,
            r#"{"token":{"refresh_token":"second","scopes":false}}"#,
            r#"{"refresh_token":"second","token":false}"#,
        ] {
            fs::write(profile.path().join("b.json"), malformed).unwrap();
            let result = scan_profile_credential(profile.path(), || panic!("unexpected fallback"));
            assert!(
                matches!(result, Err(e) if e.to_string().contains("multiple distinct refresh tokens"))
            );
        }
    }

    #[test]
    fn audit_selection_rejects_oversized_files() {
        let profile = tempfile::tempdir().unwrap();
        let selection = profile.path().join("selection");
        let mut bytes = br#"{"enrollment":"fixture","declared":"fixture"}"#.to_vec();
        bytes.resize(65_537, b' ');
        fs::write(&selection, bytes).unwrap();
        assert!(
            matches!(read_selection(&selection), Err(e) if e.to_string().contains("too large"))
        );
    }

    #[test]
    fn selection_rejects_fifo_without_waiting_for_a_writer() {
        let profile = tempfile::tempdir().unwrap();
        let selection = profile.path().join("fifo");
        let path = std::ffi::CString::new(selection.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: path is NUL-terminated and kept alive for the call.
        assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || tx.send(read_selection(&selection)).unwrap());
        let result = rx
            .recv_timeout(Duration::from_secs(2))
            .expect("blocked on FIFO");
        assert!(matches!(result, Err(e) if e.to_string().contains("regular file")));
    }

    fn models_fixture(ids: &[&str]) -> String {
        let rows: Vec<_> = ids
            .iter()
            .map(|id| json!({"id": id, "label": "fixture model"}))
            .collect();
        json!({
            "command": "models",
            "status": "SUCCESS",
            "structured_output": {"models": rows},
        })
        .to_string()
    }

    #[test]
    fn parses_and_filters_model_ids() {
        let models = parse_models(&models_fixture(&[
            "gemini-4-neon-medium",
            "claude-opus-5-5-high",
        ]))
        .unwrap();
        assert_eq!(models.count, 2);
        assert!(models.gemini_neon && models.claude && models.warning.is_none());

        for bad in [
            "ya29.secret",
            "gocspx-secret",
            "sk-secret",
            "1//refresh",
            "https://example.invalid",
            "-flag",
            "UPPERCASE",
        ] {
            assert!(
                parse_models(&models_fixture(&["gemini-4-neon-medium", bad])).is_err(),
                "expected rejection of {bad:?}"
            );
        }

        let degraded = parse_models(&models_fixture(&["gemini-3-flash"])).unwrap();
        assert!(!degraded.gemini_neon && !degraded.claude && degraded.warning.is_some());
    }

    #[test]
    fn classifies_provider_errors_without_leaking_secrets() {
        let raw = r#"Fetch failed: {"error":{"code":403,"status":"PERMISSION_DENIED","details":[{"reason":"VALIDATION_REQUIRED","metadata":{"verification_url":"https://example.invalid/secret?t=1//leak"}}]}}"#;
        let code = classify_provider_error("", raw).unwrap();
        assert_eq!(code, ProviderError::ValidationRequired);
        assert!(!code.to_string().contains("1//leak"));
        assert!(!code.to_string().contains("https://"));

        assert_eq!(
            classify_provider_error("Error: googleapi: Error 429: quota exceeded", ""),
            Some(ProviderError::QuotaExceeded)
        );
        assert_eq!(
            classify_provider_error("HTTP 401 UNAUTHENTICATED: invalid", ""),
            Some(ProviderError::Unauthenticated)
        );
        assert_eq!(
            classify_provider_error("", r#"{"error":{"code":404}}"#),
            Some(ProviderError::NotFound)
        );
        assert_eq!(
            classify_provider_error(
                "",
                r#"{"error":{"code":404,"reason":false,"details":[null,{"message":"fixture"}]}}"#
            ),
            Some(ProviderError::NotFound)
        );
        assert_eq!(
            classify_provider_error("", "https://example.invalid/?error=VALIDATION_REQUIRED"),
            None
        );
    }

    #[test]
    fn strips_ansi_escapes() {
        assert_eq!(strip_ansi_codes("\x1b[32mOK\x1b[0m\n").trim(), "OK");
        assert_eq!(
            strip_ansi_codes("\x1b]0;title\x07\x1b[1;34mOK\x1b[0m"),
            "OK"
        );
    }

    #[test]
    fn normalizes_smoke_model_and_effort() {
        let models = parse_models(&models_fixture(&[
            "gemini-4-neon-medium",
            "claude-opus-5-5-high",
            "gemini-3-flash",
        ]))
        .unwrap();
        assert_eq!(
            resolve_smoke_model(&models.ids, "gemini-4-neon-medium", None).unwrap(),
            ("gemini-4-neon", Some("medium"))
        );
        assert_eq!(
            resolve_smoke_model(&models.ids, "claude-opus-5-5", Some("HIGH")).unwrap(),
            ("claude-opus-5-5", Some("high"))
        );
        assert!(resolve_smoke_model(&models.ids, "gemini-4-neon-medium", Some("high")).is_err());
    }
}
