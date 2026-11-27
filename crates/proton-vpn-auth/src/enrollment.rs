//! Interactive document creation; the consuming secret manager owns encryption.
use super::{Account, Failure, MAX_BYTES, Result, decode_seed};
use clap::Args;
use data_encoding::BASE32_NOPAD;
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{IsTerminal, Read, Write};
use zeroize::Zeroizing;

const MAX_RBW_JSON_BYTES: usize = 1024 * 1024;

#[derive(Args)]
pub(super) struct EnrollArgs {
    /// Read a bounded credential JSON document from a private stdin pipe.
    #[arg(long)]
    pub stdin: bool,
    /// Write the validated canonical document to a private stdout pipe.
    /// Without --stdin, prompt on the controlling terminal.
    #[arg(long, required = true)]
    pub stdout: bool,
    /// Explicitly enroll an account without TOTP; the default requires its existing seed.
    #[arg(long)]
    pub password_only: bool,
    /// Project Proton credentials from an `rbw get --raw` JSON item (up to 1 MiB).
    #[arg(long, requires = "stdin")]
    pub rbw_json: bool,
    /// Override a projected field's vault source (`OUTPUT=FIELD`, for `username`, `password`, or `totpSecret`).
    #[arg(long, requires = "rbw_json", value_name = "OUTPUT=FIELD")]
    pub rbw_map: Vec<String>,
}

#[derive(Args)]
pub(super) struct ValidateArgs {
    /// Read a bounded Proton enrollment JSON document from stdin.
    #[arg(long, required = true)]
    pub stdin: bool,
    /// Require an account without TOTP (`totpSecret` absent).
    #[arg(long)]
    pub password_only: bool,
    /// Emit structured JSON validation output (never echoes password or totpSecret).
    #[arg(long)]
    pub json: bool,
}

fn prompt(label: &str) -> Result<Zeroizing<String>> {
    rpassword::prompt_password(label)
        .map(Zeroizing::new)
        .map_err(|_| {
            Failure::permanent("Credential enrollment requires an interactive controlling terminal")
        })
}

fn write_document(account: &Account) -> Result<()> {
    account.validate()?;
    let bytes = Zeroizing::new(
        serde_json::to_vec(account)
            .map_err(|_| Failure::permanent("Cannot encode Proton credential document"))?,
    );
    std::io::stdout()
        .write_all(&bytes)
        .map_err(|_| Failure::permanent("Cannot write Proton credential output"))
}

fn decode_parameter(input: &str) -> Result<Zeroizing<String>> {
    let invalid = || Failure::permanent("Invalid Proton authenticator URI encoding");
    let mut bytes = Zeroizing::new(Vec::with_capacity(input.len()));
    let mut source = input.bytes();
    while let Some(byte) = source.next() {
        bytes.push(match byte {
            b'%' => {
                let high = char::from(source.next().ok_or_else(invalid)?).to_digit(16);
                let low = char::from(source.next().ok_or_else(invalid)?).to_digit(16);
                ((high.ok_or_else(invalid)? << 4) | low.ok_or_else(invalid)?) as u8
            }
            b'+' => b' ',
            byte => byte,
        });
    }
    let value = std::str::from_utf8(&bytes).map_err(|_| invalid())?;
    Ok(Zeroizing::new(value.to_owned()))
}

fn normalize_seed(input: &str) -> Result<String> {
    let invalid = || Failure::permanent("Invalid or unsupported Proton authenticator URI");
    let mut uri_seed = None;
    if input.starts_with("otpauth:") {
        if input.contains('#') || input.chars().any(char::is_control) {
            return Err(invalid());
        }
        let (label, query) = input
            .strip_prefix("otpauth://totp/")
            .and_then(|path| path.split_once('?'))
            .ok_or_else(invalid)?;
        let label = decode_parameter(label)?;
        if label.trim().is_empty() || label.chars().any(char::is_control) {
            return Err(invalid());
        }
        let mut seen = BTreeSet::new();
        for parameter in query.split('&') {
            let (key, value) = parameter.split_once('=').ok_or_else(invalid)?;
            let key = decode_parameter(key)?;
            let value = decode_parameter(value)?;
            let key = match key.as_str() {
                "secret" => "secret",
                "issuer" => "issuer",
                "algorithm" if value.eq_ignore_ascii_case("SHA1") => "algorithm",
                "digits" if value.as_str() == "6" => "digits",
                "period" if value.as_str() == "30" => "period",
                _ => return Err(invalid()),
            };
            if !seen.insert(key) {
                return Err(invalid());
            }
            if key == "secret" {
                uri_seed = Some(value);
            }
        }
        if uri_seed.is_none() {
            return Err(invalid());
        }
    }
    let seed = uri_seed.as_deref().map_or(input, String::as_str);
    let canonical = Zeroizing::new(BASE32_NOPAD.encode(&decode_seed(seed)?));
    if matches!(canonical.len(), 6 | 8) && canonical.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(Failure::permanent(
            "Enroll the authenticator seed, not a one-time code",
        ));
    }
    Ok(canonical.to_string())
}

fn prepare_account(mut account: Account, password_only: bool) -> Result<Account> {
    match (account.totp_secret.take(), password_only) {
        (Some(seed), false) => {
            let seed = Zeroizing::new(seed);
            account.totp_secret = Some(normalize_seed(&seed)?);
        }
        (None, true) => {}
        (seed, _) => {
            let _seed = seed.map(Zeroizing::new);
            return Err(Failure::permanent(
                "Enrollment requires a TOTP seed, or explicit --password-only without a seed",
            ));
        }
    }
    account.validate()?;
    Ok(account)
}

fn read_bounded_stdin(limit: usize) -> Result<Zeroizing<Vec<u8>>> {
    let mut input = Zeroizing::new(Vec::with_capacity(limit + 1));
    std::io::stdin()
        .take((limit + 1) as u64)
        .read_to_end(&mut input)
        .map_err(|_| Failure::permanent("Cannot read Proton credential input"))?;
    if input.len() > limit {
        return Err(Failure::permanent("Proton credential input is too large"));
    }
    Ok(input)
}

fn resolve_rbw_mapping(
    rbw_map: &[String],
    password_only: bool,
) -> Result<BTreeMap<&'static str, String>> {
    let mut mapping: BTreeMap<&'static str, String> = BTreeMap::from([
        ("username", "username".into()),
        ("password", "password".into()),
    ]);
    if !password_only {
        mapping.insert("totpSecret", "totp".into());
    }
    let mut overridden = BTreeSet::new();
    for entry in rbw_map {
        let Some((output, field)) = entry.split_once('=') else {
            return Err(Failure::permanent("rbw mappings require OUTPUT=FIELD"));
        };
        if field.trim().is_empty() {
            return Err(Failure::permanent("rbw field name must not be empty"));
        }
        let key: &'static str = match output {
            "username" => "username",
            "password" => "password",
            "totpSecret" if !password_only => "totpSecret",
            _ => {
                return Err(Failure::permanent(
                    "rbw mappings must select username, password, or an enabled totpSecret",
                ));
            }
        };
        if !overridden.insert(key) {
            return Err(Failure::permanent("Duplicate rbw output mapping"));
        }
        mapping.insert(key, field.to_owned());
    }
    Ok(mapping)
}

fn secret<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Option<Zeroizing<String>>, D::Error> {
    Ok(Option::<String>::deserialize(deserializer)?.map(Zeroizing::new))
}

#[derive(Deserialize)]
struct RbwLogin {
    #[serde(default, deserialize_with = "secret")]
    username: Option<Zeroizing<String>>,
    #[serde(default, deserialize_with = "secret")]
    password: Option<Zeroizing<String>>,
    #[serde(default, deserialize_with = "secret")]
    totp: Option<Zeroizing<String>>,
}

#[derive(Deserialize)]
struct RbwCustomField {
    #[serde(default, deserialize_with = "secret")]
    name: Option<Zeroizing<String>>,
    #[serde(default, deserialize_with = "secret")]
    value: Option<Zeroizing<String>>,
}

#[derive(Deserialize)]
struct RbwItem {
    data: Option<RbwLogin>,
    #[serde(default, deserialize_with = "secret")]
    notes: Option<Zeroizing<String>>,
    #[serde(default)]
    fields: Vec<RbwCustomField>,
}

fn lookup_rbw_field<'a>(item: &'a RbwItem, field: &str) -> Result<Option<&'a str>> {
    let data = item.data.as_ref();
    let value = match field {
        "username" => data.and_then(|data| data.username.as_deref()),
        "password" => data.and_then(|data| data.password.as_deref()),
        "totp" => data.and_then(|data| data.totp.as_deref()),
        "notes" => item.notes.as_deref(),
        field => {
            let name = field.strip_prefix("custom:").ok_or_else(|| {
                Failure::permanent("Custom rbw fields require the custom: prefix")
            })?;
            let mut matches = item
                .fields
                .iter()
                .filter(|entry| entry.name.as_deref().is_some_and(|value| value == name));
            let first = matches.next();
            if matches.next().is_some() {
                return Err(Failure::permanent(
                    "Ambiguous duplicate custom field in rbw item",
                ));
            }
            first.and_then(|entry| entry.value.as_deref())
        }
    };
    Ok(value.map(String::as_str))
}

fn parse_rbw_account(input: &[u8], rbw_map: &[String], password_only: bool) -> Result<Account> {
    let mapping = resolve_rbw_mapping(rbw_map, password_only)?;
    if !input.trim_ascii_start().starts_with(b"{") {
        return Err(Failure::permanent("Invalid rbw JSON item"));
    }
    let item: RbwItem =
        serde_json::from_slice(input).map_err(|_| Failure::permanent("Invalid rbw JSON item"))?;
    let username = lookup_rbw_field(&item, &mapping["username"])?
        .ok_or_else(|| Failure::permanent("Missing username field in rbw item"))?;
    let password = lookup_rbw_field(&item, &mapping["password"])?
        .ok_or_else(|| Failure::permanent("Missing password field in rbw item"))?;
    let totp_secret = if password_only {
        None
    } else {
        lookup_rbw_field(&item, &mapping["totpSecret"])?.map(str::to_owned)
    };
    Ok(Account {
        username: username.to_owned(),
        password: password.to_owned(),
        totp_secret,
    })
}

fn pipe_document(args: &EnrollArgs) -> Result<()> {
    if std::io::stdin().is_terminal() || std::io::stdout().is_terminal() {
        return Err(Failure::permanent(
            "Credential document mode requires private stdin/stdout pipes",
        ));
    }
    let input = read_bounded_stdin(if args.rbw_json {
        MAX_RBW_JSON_BYTES
    } else {
        MAX_BYTES
    })?;
    let account = if args.rbw_json {
        parse_rbw_account(&input, &args.rbw_map, args.password_only)?
    } else {
        serde_json::from_slice(&input).map_err(|_| {
            Failure::permanent(
                "Invalid Proton credential JSON; expected username, password, and optional totpSecret",
            )
        })?
    };
    let account = prepare_account(account, args.password_only)?;
    write_document(&account)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ValidateReport {
    valid: bool,
    username: Option<String>,
    has_totp: bool,
    totp_normalized: bool,
    error: Option<&'static str>,
}

pub(super) fn validate(args: &ValidateArgs) -> Result<()> {
    if std::io::stdin().is_terminal() {
        return Err(Failure::permanent(
            "Validation requires a piped Proton credential JSON document on stdin",
        ));
    }
    let input = read_bounded_stdin(MAX_BYTES)?;
    let account: Account = serde_json::from_slice(&input).map_err(|_| {
        Failure::permanent(
            "Invalid Proton credential JSON; expected username, password, and optional totpSecret",
        )
    })?;
    let account = prepare_account(account, args.password_only)?;
    let has_totp = account.totp_secret.is_some();
    if args.json {
        return print_validation_report(&ValidateReport {
            valid: true,
            username: Some(account.username.clone()),
            has_totp,
            totp_normalized: has_totp,
            error: None,
        });
    }
    println!(
        "Valid Proton credential document for {} (totp: {})",
        account.username,
        if has_totp { "present" } else { "password-only" }
    );
    Ok(())
}

pub(super) fn report_validation_error(error: &Failure) {
    let _ = print_validation_report(&ValidateReport {
        valid: false,
        username: None,
        has_totp: false,
        totp_normalized: false,
        error: Some(error.message),
    });
}

fn print_validation_report(report: &ValidateReport) -> Result<()> {
    let text = serde_json::to_string_pretty(report)
        .map_err(|_| Failure::permanent("Cannot encode validation report"))?;
    writeln!(std::io::stdout().lock(), "{text}")
        .map_err(|_| Failure::permanent("Cannot write validation report"))
}

pub(super) fn run(args: &EnrollArgs) -> Result<()> {
    let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: fstat writes a complete stat on success to this valid allocation.
    let inspected = unsafe { libc::fstat(libc::STDOUT_FILENO, metadata.as_mut_ptr()) } == 0;
    if !inspected {
        return Err(Failure::permanent(
            "Cannot inspect the credential output pipe",
        ));
    }
    // SAFETY: successful fstat initialized the complete stat above.
    let kind = unsafe { metadata.assume_init() }.st_mode & libc::S_IFMT;
    if !matches!(kind, libc::S_IFIFO | libc::S_IFSOCK) {
        return Err(Failure::permanent(
            "Credential enrollment requires a private stdout pipe",
        ));
    }
    if args.stdin && args.stdout {
        return pipe_document(args);
    }
    let username = prompt("Proton account username: ")?;
    let password = prompt("Proton account password: ")?;
    let confirmation = prompt("Repeat password: ")?;
    if password != confirmation {
        return Err(Failure::permanent(
            "Password confirmation did not match; no document was created",
        ));
    }
    let seed = if args.password_only {
        None
    } else {
        let seed = prompt("Existing Proton authenticator seed (base32, not the six-digit code): ")?;
        let confirmation = prompt("Repeat authenticator seed: ")?;
        if seed != confirmation {
            return Err(Failure::permanent(
                "Authenticator seed confirmation did not match; no document was created",
            ));
        }
        Some(seed)
    };
    let account = prepare_account(
        Account {
            username: username.to_string(),
            password: password.to_string(),
            totp_secret: seed.as_ref().map(|value| value.to_string()),
        },
        args.password_only,
    )?;
    write_document(&account)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_only_document_preserves_credentials() {
        let account = Account {
            username: "fixture".into(),
            password: "private fixture".into(),
            totp_secret: None,
        };
        let account = prepare_account(account, true).unwrap_or_else(|_| panic!("valid account"));
        assert_eq!(account.username, "fixture");
        assert_eq!(account.password, "private fixture");
        assert!(account.totp_secret.is_none());
    }

    #[test]
    fn invalid_credentials_are_rejected_before_output() {
        let account = Account {
            username: "fixture".into(),
            password: "private fixture".into(),
            totp_secret: Some("invalid!".into()),
        };
        assert!(prepare_account(account, false).is_err());
    }
}
