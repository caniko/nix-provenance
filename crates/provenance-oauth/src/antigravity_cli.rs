//! Standalone operator subcommands for Google Antigravity (`antigravity-capture`,
//! `antigravity-check`).

use crate::{
    CliError, Config, Grant, OAuthClient, Secret,
    google::CLOUD_PLATFORM_SCOPE,
    state::{Store, atomic_write, read_json},
};
use anyhow::{Context, Result, bail, ensure};
use clap::Args;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::BTreeSet,
    fs,
    io::{BufRead, BufReader, ErrorKind, IsTerminal, Read, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
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
    #[arg(long, default_value_t = 35)]
    pub models_timeout_secs: u64,
    /// Timeout in seconds for the optional smoke inference test.
    #[arg(long, default_value_t = 25)]
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
    if args.output == Path::new("-") && std::io::stdout().is_terminal() {
        return Err(CliError::validation(
            "refusing to write Antigravity credentials to a terminal; redirect stdout or pass --output <PATH>",
        ));
    }

    let token = if let Some(token_file) = &args.token_file {
        let bytes = read_bounded_input(token_file, MAX_CREDENTIAL_BYTES)?;
        normalize_token_bytes(&bytes, || borrow_client_metadata(&args))?
    } else {
        capture_interactive(&args)?
    };

    let encoded = Zeroizing::new(
        serde_json::to_vec(&token)
            .map_err(|_| CliError::runtime("could not encode Antigravity token JSON"))?,
    );

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
        let file = fs::File::open(path).map_err(|e| {
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

fn capture_interactive(
    args: &AntigravityCaptureArgs,
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

    let status = run_attended(&mut command)?;
    if !status.success() {
        return Err(CliError::runtime(
            "agy ACP login failed; no credential was captured",
        ));
    }
    scan_profile_credential(home, || borrow_client_metadata(args))
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

fn nonempty_string(value: &Value) -> Option<&str> {
    value.as_str().filter(|s| !s.trim().is_empty())
}

fn extract_scopes(value: &Value) -> std::result::Result<Option<Vec<String>>, CliError> {
    let raw = [
        &value["scopes"],
        &value["token"]["scopes"],
        &value["scope"],
        &value["token"]["scope"],
    ]
    .into_iter()
    .find(|v| !v.is_null());

    match raw {
        None => Ok(None),
        Some(Value::String(s)) => {
            let scopes: Vec<String> = s.split_whitespace().map(str::to_owned).collect();
            if scopes.is_empty() {
                Ok(None)
            } else {
                Ok(Some(scopes))
            }
        }
        Some(Value::Array(arr)) => {
            let mut scopes = Vec::with_capacity(arr.len());
            for item in arr {
                let s = nonempty_string(item)
                    .ok_or_else(|| CliError::validation("invalid scope entry in agy credential"))?;
                scopes.push(s.to_owned());
            }
            if scopes.is_empty() {
                Ok(None)
            } else {
                Ok(Some(scopes))
            }
        }
        Some(_) => Err(CliError::validation("invalid scopes in agy credential")),
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
    let value: Value = serde_json::from_slice(bytes)
        .map_err(|_| CliError::validation("input is not valid Antigravity token JSON"))?;
    if !value.is_object() {
        return Err(CliError::validation(
            "Antigravity token input must be a JSON object",
        ));
    }

    let top = nonempty_string(&value["refresh_token"]);
    let nested = nonempty_string(&value["token"]["refresh_token"]);
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

    let scopes = extract_scopes(&value)?.unwrap_or_else(default_scopes);
    let project_id = nonempty_string(&value["project_id"]).map(str::to_owned);

    let (client_id, client_secret, token_uri) = match (
        nonempty_string(&value["client_id"]),
        nonempty_string(&value["client_secret"]),
    ) {
        (Some(id), Some(secret)) => (
            id.to_owned(),
            Secret(secret.to_owned()),
            nonempty_string(&value["token_uri"])
                .unwrap_or(GOOGLE_TOKEN_URI)
                .to_owned(),
        ),
        _ => {
            let borrowed = borrow_client()?;
            (
                borrowed.client_id,
                borrowed.client_secret,
                borrowed.token_uri,
            )
        }
    };

    Ok(CanonicalAgyToken {
        client_id,
        client_secret,
        token_uri,
        refresh_token,
        scopes,
        project_id,
    })
}

fn scan_profile_credential(
    profile: &Path,
    borrow_client: impl FnOnce() -> std::result::Result<ClientMetadata, CliError>,
) -> std::result::Result<CanonicalAgyToken, CliError> {
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
    let mut full_acp: Option<CanonicalAgyToken> = None;
    let mut scopes: Option<Vec<String>> = None;

    for path in &files {
        let relative = path.strip_prefix(profile).unwrap_or(path);
        let len = fs::metadata(path)
            .map_err(|e| CliError::runtime(format!("stat agy profile file {relative:?}: {e}")))?
            .len();
        if len > MAX_CREDENTIAL_BYTES {
            continue;
        }
        let file = fs::File::open(path)
            .map_err(|e| CliError::runtime(format!("open agy profile file {relative:?}: {e}")))?;
        let mut reader = BufReader::new(file);
        let head = reader
            .fill_buf()
            .map_err(|e| CliError::runtime(format!("read agy profile file {relative:?}: {e}")))?;
        if !head
            .iter()
            .find(|byte| !byte.is_ascii_whitespace())
            .is_some_and(|byte| *byte == b'{')
        {
            continue;
        }
        let value: Value = match serde_json::from_reader(reader) {
            Ok(v) => v,
            Err(err) if err.is_io() => {
                return Err(CliError::runtime(format!(
                    "could not read agy profile file {relative:?}"
                )));
            }
            Err(_) => continue,
        };
        let top = nonempty_string(&value["refresh_token"]);
        let nested = nonempty_string(&value["token"]["refresh_token"]);
        for tok in top.into_iter().chain(nested) {
            let selected = refresh_token.get_or_insert_with(|| Secret(tok.to_owned()));
            if selected.0 != tok {
                return Err(CliError::validation(
                    "isolated agy profile contains multiple distinct refresh tokens",
                ));
            }
        }
        if top.is_none() && nested.is_none() {
            continue;
        }
        if top.is_some()
            && let (Some(cid), Some(csec)) = (
                nonempty_string(&value["client_id"]),
                nonempty_string(&value["client_secret"]),
            )
            && value["scopes"].is_array()
        {
            let parsed_scopes = extract_scopes(&value)?.unwrap_or_else(default_scopes);
            full_acp.get_or_insert(CanonicalAgyToken {
                client_id: cid.to_owned(),
                client_secret: Secret(csec.to_owned()),
                token_uri: nonempty_string(&value["token_uri"])
                    .unwrap_or(GOOGLE_TOKEN_URI)
                    .to_owned(),
                refresh_token: Secret(top.unwrap().to_owned()),
                scopes: parsed_scopes,
                project_id: nonempty_string(&value["project_id"]).map(str::to_owned),
            });
        } else if scopes.is_none() {
            scopes = extract_scopes(&value)?;
        }
    }

    let refresh_token = refresh_token.ok_or_else(|| {
        let names: Vec<_> = files
            .iter()
            .filter_map(|p| p.strip_prefix(profile).ok())
            .collect();
        CliError::runtime(format!(
            "agy ACP login wrote no refresh token in the isolated profile; files: {names:?}"
        ))
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
    let store = match Store::lock(config) {
        Ok(s) => s,
        Err(_) => return Ok(None),
    };
    match store.grant() {
        Ok(grant) => Ok(Some(grant)),
        Err(_) => Ok(None),
    }
}

fn borrow_client_metadata(
    args: &AntigravityCaptureArgs,
) -> std::result::Result<ClientMetadata, CliError> {
    if let Some(manifest_path) = &args.client_metadata_from {
        let config: Config = read_json(manifest_path, false).map_err(|e| {
            CliError::validation(format!(
                "invalid --client-metadata-from manifest {}: {e:#}",
                manifest_path.display()
            ))
        })?;
        config
            .validate()
            .map_err(|e| CliError::validation(format!("invalid manifest config: {e:#}")))?;
        let grant = export_grant_in_process(&config)
            .map_err(|e| CliError::runtime(format!("read manifest grant: {e:#}")))?
            .ok_or_else(|| {
                CliError::validation(format!(
                    "manifest {} has no initialized Antigravity grant to borrow client metadata from",
                    manifest_path.display()
                ))
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
    for entry in entries {
        let entry = entry?;
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
        let config: Config = read_json(&path, false)
            .with_context(|| format!("invalid deployed OAuth manifest {:?}", path.file_name()))?;
        if config.target.host != host
            || config.target.user != user
            || config.target.provider != "google"
            || config.target.profile != "antigravity"
        {
            continue;
        }
        config.validate()?;
        let id = config.target.enrollment.clone().unwrap_or(id_from_name);
        matched.push((id, config));
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

#[derive(Deserialize, PartialEq, Eq)]
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
        let grant: Self =
            serde_json::from_slice(bytes).map_err(|_| anyhow::anyhow!("invalid ACP grant JSON"))?;
        ensure!(
            [&grant.client_id, &grant.client_secret, &grant.refresh_token]
                .iter()
                .all(|v| !v.trim().is_empty()),
            "ACP grant is missing client or refresh fields"
        );
        Ok(grant)
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

    if args.json {
        let payload = report.to_json(&result);
        println!(
            "{}",
            serde_json::to_string_pretty(&payload).unwrap_or_else(|_| payload.to_string())
        );
        return match result {
            Ok(()) => Ok(()),
            Err(_) if report.health == CheckHealth::Degraded => Err(CliError::silent(3)),
            Err(_) => Err(CliError::silent(1)),
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
        Err(e) => Err(CliError::runtime(format!("{e:#}"))),
    }
}

fn execute_check(args: &AntigravityCheckArgs, report: &mut CheckReport) -> Result<()> {
    ensure!(!report.host.is_empty(), "could not resolve local hostname");
    ensure!(!report.user.is_empty(), "could not resolve local user");

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
    let bytes = Zeroizing::new(
        fs::read(&token_path).context("read T3's Antigravity ACP grant; agy probe not run")?,
    );
    let grant = AgyGrant::parse(&bytes)?;

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
            Duration::from_secs(args.smoke_timeout_secs),
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
    match fs::read(path) {
        Ok(bytes) => {
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
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err).context("read Antigravity selection record"),
    }
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
    let store =
        Store::lock(config).with_context(|| format!("cannot read enrollment {id} status"))?;
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

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
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
    let directory = temp.path();
    write_probe_credential(directory, grant)
        .context("prepare the private agy credential snapshot")?;

    let stdout_file = tempfile::NamedTempFile::new_in(directory)?;
    let stderr_file = tempfile::NamedTempFile::new_in(directory)?;

    let mut command = Command::new(agy_bin);
    command
        .args(args)
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

    let mut child = ChildGuard(command.spawn().context("start agy")?);
    let deadline = Instant::now() + timeout;
    let status = loop {
        if let Some(status) = child.0.try_wait().context("wait for agy")? {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.0.kill();
            let _ = child.0.wait();
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
                _ => {
                    i += 2;
                }
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

pub fn classify_provider_error(stdout: &str, stderr: &str) -> Option<ProviderError> {
    for stream in [stderr, stdout] {
        let stream = strip_ansi_codes(stream);
        for (start, _) in stream.match_indices('{').take(32) {
            let mut json =
                serde_json::Deserializer::from_str(&stream[start..]).into_iter::<Value>();
            let Some(Ok(value)) = json.next() else {
                continue;
            };
            let error = value
                .get("error")
                .filter(|error| error.is_object())
                .unwrap_or(&value);
            let classified = error["details"]
                .as_array()
                .into_iter()
                .flatten()
                .find_map(|detail| detail["reason"].as_str().and_then(ProviderError::reason))
                .or_else(|| error["reason"].as_str().and_then(ProviderError::reason))
                .or_else(|| error["status"].as_str().and_then(ProviderError::reason))
                .or_else(|| error["code"].as_u64().and_then(ProviderError::http))
                .or_else(|| value["error"].as_str().and_then(ProviderError::reason));
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
