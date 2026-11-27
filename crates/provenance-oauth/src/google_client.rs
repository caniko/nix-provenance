//! Standalone operator subcommand for validating and materializing Google OAuth
//! client JSON (`google-client-bootstrap`).

use crate::{CliError, OAuthClient, Secret, state::atomic_write};
use clap::{Args, ValueEnum};
use serde::Serialize;
use serde_json::{Map, Value, json};
use std::{
    fs,
    io::{IsTerminal, Read, Write},
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

const MAX_CLIENT_BYTES: u64 = 64 * 1024;
const DEFAULT_AUTH_URI: &str = "https://accounts.google.com/o/oauth2/auth";
const DEFAULT_TOKEN_URI: &str = "https://oauth2.googleapis.com/token";

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum ExpectedClientType {
    Installed,
    Web,
}

impl ExpectedClientType {
    fn as_str(self) -> &'static str {
        match self {
            Self::Installed => "installed",
            Self::Web => "web",
        }
    }
}

#[derive(Args, Debug)]
pub struct GoogleClientBootstrapArgs {
    /// Google OAuth client JSON file (or `-` for stdin; bounded to 64 KiB).
    #[arg(long, value_name = "PATH")]
    pub file: PathBuf,
    /// Optional destination to write normalized client JSON atomically (mode 0600), or `-` for non-TTY stdout.
    #[arg(long, value_name = "PATH")]
    pub materialize_to: Option<PathBuf>,
    /// Require the client JSON to be of type `installed` or `web`.
    #[arg(long, value_enum)]
    pub expected_client_type: Option<ExpectedClientType>,
    /// Require a non-empty `project_id` field.
    #[arg(long)]
    pub require_project_id: bool,
    /// Emit non-secret metadata as JSON.
    #[arg(long)]
    pub json: bool,
}

#[derive(Serialize, Debug, PartialEq, Eq)]
pub struct ClientBootstrapReport {
    pub valid: bool,
    pub client_type: String,
    pub client_id: String,
    pub project_id: Option<String>,
    pub auth_uri: String,
    pub token_uri: String,
    pub redirect_uris: Vec<String>,
    pub materialized_path: Option<String>,
}

struct ParsedClient {
    client_type: String,
    client_id: String,
    client_secret: Secret,
    project_id: Option<String>,
    auth_uri: String,
    token_uri: String,
    redirect_uris: Vec<String>,
}

impl ParsedClient {
    fn normalized_json(&self) -> Value {
        let mut inner = Map::new();
        inner.insert("client_id".into(), json!(self.client_id));
        inner.insert("client_secret".into(), json!(self.client_secret.0));
        if let Some(project_id) = &self.project_id {
            inner.insert("project_id".into(), json!(project_id));
        }
        inner.insert("auth_uri".into(), json!(self.auth_uri));
        inner.insert("token_uri".into(), json!(self.token_uri));
        if !self.redirect_uris.is_empty() {
            inner.insert("redirect_uris".into(), json!(self.redirect_uris));
        }
        match self.client_type.as_str() {
            "installed" => json!({ "installed": inner }),
            "web" => json!({ "web": inner }),
            _ => Value::Object(inner),
        }
    }
}

pub fn run_bootstrap(args: GoogleClientBootstrapArgs) -> std::result::Result<(), CliError> {
    let materialize_stdout = args
        .materialize_to
        .as_deref()
        .is_some_and(|p| p == Path::new("-"));

    if materialize_stdout && args.json {
        return Err(CliError::validation(
            "--materialize-to - cannot be combined with --json (refusing to mix secret client JSON and metadata on stdout)",
        ));
    }
    if materialize_stdout && std::io::stdout().is_terminal() {
        return Err(CliError::validation(
            "refusing to write Google OAuth client secret to a terminal; redirect stdout or pass a file path to --materialize-to",
        ));
    }

    let bytes = read_client_input(&args.file)?;
    let parsed = parse_client_json(&bytes, args.expected_client_type, args.require_project_id)?;

    let mut materialized_path = None;
    if let Some(dest) = &args.materialize_to {
        let normalized = Zeroizing::new(
            serde_json::to_vec(&parsed.normalized_json())
                .map_err(|_| CliError::runtime("could not serialize normalized client JSON"))?,
        );
        if dest == Path::new("-") {
            let mut stdout = std::io::stdout().lock();
            stdout
                .write_all(&normalized)
                .and_then(|()| writeln!(stdout))
                .map_err(|e| CliError::runtime(format!("could not write client JSON: {e}")))?;
            return Ok(());
        }
        atomic_write(dest, &normalized).map_err(|e| {
            CliError::runtime(format!(
                "could not materialize client JSON to {}: {e:#}",
                dest.display()
            ))
        })?;
        materialized_path = Some(dest.display().to_string());
    }

    let report = ClientBootstrapReport {
        valid: true,
        client_type: parsed.client_type,
        client_id: parsed.client_id,
        project_id: parsed.project_id,
        auth_uri: parsed.auth_uri,
        token_uri: parsed.token_uri,
        redirect_uris: parsed.redirect_uris,
        materialized_path,
    };

    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).unwrap_or_else(|_| "{}".into())
        );
    } else {
        println!(
            "Valid Google OAuth client (type: {}, client_id: {}, project_id: {})",
            report.client_type,
            report.client_id,
            report.project_id.as_deref().unwrap_or("unset")
        );
        if let Some(path) = &report.materialized_path {
            println!("Materialized to: {path}");
        }
    }
    Ok(())
}

fn read_client_input(path: &Path) -> std::result::Result<Zeroizing<Vec<u8>>, CliError> {
    let mut bytes = Zeroizing::new(Vec::new());
    if path == Path::new("-") {
        std::io::stdin()
            .lock()
            .take(MAX_CLIENT_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| {
                CliError::runtime(format!("could not read client JSON from stdin: {e}"))
            })?;
    } else {
        let file = fs::File::open(path).map_err(|e| {
            CliError::runtime(format!(
                "could not open client file {}: {e}",
                path.display()
            ))
        })?;
        let meta = file.metadata().map_err(|e| {
            CliError::runtime(format!(
                "could not stat client file {}: {e}",
                path.display()
            ))
        })?;
        if !meta.is_file() {
            return Err(CliError::validation("client file must be a regular file"));
        }
        if meta.len() > MAX_CLIENT_BYTES {
            return Err(CliError::validation(
                "client file exceeds 64 KiB size limit",
            ));
        }
        file.take(MAX_CLIENT_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| CliError::runtime(format!("could not read client file: {e}")))?;
    }
    if bytes.len() as u64 > MAX_CLIENT_BYTES {
        return Err(CliError::validation(
            "client JSON exceeds 64 KiB size limit",
        ));
    }
    Ok(bytes)
}

fn nonempty_str(obj: &Map<String, Value>, key: &str) -> Option<String> {
    obj.get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
}

fn valid_https_uri(uri: &str) -> bool {
    reqwest::Url::parse(uri).is_ok_and(|url| url.scheme() == "https" && url.host_str().is_some())
}

fn parse_client_json(
    bytes: &[u8],
    expected_type: Option<ExpectedClientType>,
    require_project_id: bool,
) -> std::result::Result<ParsedClient, CliError> {
    let document: Value = serde_json::from_slice(bytes)
        .map_err(|_| CliError::validation("invalid Google OAuth client JSON"))?;
    let root = document
        .as_object()
        .ok_or_else(|| CliError::validation("Google OAuth client JSON must be an object"))?;

    let (client_type, fields) = if root.contains_key("client_id")
        || root.contains_key("client_secret")
    {
        ("flat", root)
    } else {
        let mut entries = root
            .iter()
            .filter_map(|(k, v)| v.as_object().map(|o| (k.as_str(), o)));
        let Some((kind, obj)) = entries.next() else {
            return Err(CliError::validation(
                "invalid Google OAuth client JSON: missing installed/web section or client fields",
            ));
        };
        if entries.next().is_some() || !matches!(kind, "installed" | "web") {
            return Err(CliError::validation(
                "invalid Google OAuth client JSON: expected a single `installed` or `web` object",
            ));
        }
        (kind, obj)
    };

    if let Some(expected) = expected_type
        && client_type != expected.as_str()
    {
        return Err(CliError::validation(format!(
            "expected Google OAuth client type `{}`, found `{client_type}`",
            expected.as_str()
        )));
    }

    let client_id = nonempty_str(fields, "client_id")
        .ok_or_else(|| CliError::validation("missing or empty client_id"))?;
    let client_secret = Secret(
        nonempty_str(fields, "client_secret")
            .ok_or_else(|| CliError::validation("missing or empty client_secret"))?,
    );
    OAuthClient {
        client_id: client_id.clone(),
        client_secret: client_secret.clone(),
    }
    .validate()
    .map_err(|_| CliError::validation("invalid Google OAuth client_id or client_secret"))?;

    let project_id = nonempty_str(fields, "project_id");
    if require_project_id && project_id.is_none() {
        return Err(CliError::validation(
            "Google OAuth client JSON is missing required project_id",
        ));
    }

    let auth_uri = nonempty_str(fields, "auth_uri").unwrap_or_else(|| DEFAULT_AUTH_URI.to_owned());
    let token_uri =
        nonempty_str(fields, "token_uri").unwrap_or_else(|| DEFAULT_TOKEN_URI.to_owned());
    if !valid_https_uri(&auth_uri) {
        return Err(CliError::validation("invalid auth_uri (must be https://)"));
    }
    if !valid_https_uri(&token_uri) {
        return Err(CliError::validation("invalid token_uri (must be https://)"));
    }

    let redirect_uris = match fields.get("redirect_uris") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(arr)) => {
            let mut uris = Vec::with_capacity(arr.len());
            for item in arr {
                let s = item
                    .as_str()
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .ok_or_else(|| CliError::validation("invalid entry in redirect_uris"))?;
                uris.push(s.to_owned());
            }
            uris
        }
        Some(_) => {
            return Err(CliError::validation(
                "redirect_uris must be an array of strings",
            ));
        }
    };

    Ok(ParsedClient {
        client_type: client_type.to_owned(),
        client_id,
        client_secret,
        project_id,
        auth_uri,
        token_uri,
        redirect_uris,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_installed_web_and_flat_formats() {
        let installed = br#"{"installed":{"client_id":"123.apps.googleusercontent.com","client_secret":"secret-val","project_id":"my-proj","redirect_uris":["http://localhost"]}}"#;
        let parsed =
            parse_client_json(installed, Some(ExpectedClientType::Installed), true).unwrap();
        assert_eq!(parsed.client_type, "installed");
        assert_eq!(parsed.project_id.as_deref(), Some("my-proj"));
        assert_eq!(parsed.redirect_uris, ["http://localhost"]);

        let web = br#"{"web":{"client_id":"456.apps.googleusercontent.com","client_secret":"secret-val"}}"#;
        let parsed = parse_client_json(web, Some(ExpectedClientType::Web), false).unwrap();
        assert_eq!(parsed.client_type, "web");
        assert!(parse_client_json(web, Some(ExpectedClientType::Installed), false).is_err());
        assert!(parse_client_json(web, None, true).is_err());

        let flat =
            br#"{"client_id":"789.apps.googleusercontent.com","client_secret":"secret-val"}"#;
        let parsed = parse_client_json(flat, None, false).unwrap();
        assert_eq!(parsed.client_type, "flat");
    }

    #[test]
    fn rejects_invalid_uris_and_missing_fields() {
        for bad in [
            br#"{"installed":{"client_id":"123"}}"#.as_slice(),
            br#"{"installed":{"client_id":"123","client_secret":"s","token_uri":"http://insecure.example/token"}}"#,
            br#"{"unknown":{"client_id":"123","client_secret":"s"}}"#,
            br#"{"installed":{"client_id":"123","client_secret":"s"},"web":{}}"#,
        ] {
            assert!(parse_client_json(bad, None, false).is_err());
        }
    }
}
