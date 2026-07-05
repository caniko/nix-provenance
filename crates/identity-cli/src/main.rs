use std::process::ExitCode;

use anyhow::Result;
#[cfg(any(feature = "kanidm", feature = "bitwarden", feature = "rauthy"))]
use clap::Args;
use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(
    name = "identity-cli",
    about = "Identity administration CLI for Kanidm and Bitwarden-backed workflows",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Kanidm provisioning commands.
    #[cfg(feature = "kanidm")]
    Kanidm(KanidmArgs),

    /// Bitwarden export commands.
    #[cfg(feature = "bitwarden")]
    Bitwarden {
        #[command(subcommand)]
        command: BitwardenCommand,
    },

    /// Rauthy email-credential helpers (list / resend set-password links).
    #[cfg(feature = "rauthy")]
    Rauthy(RauthyArgs),

    /// Placeholder used only when all feature-gated commands are disabled.
    #[cfg(not(any(feature = "kanidm", feature = "bitwarden", feature = "rauthy")))]
    #[command(hide = true)]
    Noop,
}

#[derive(Args, Debug)]
#[cfg(feature = "rauthy")]
struct RauthyArgs {
    /// Rauthy base URL (the `/auth/v1` API path is appended automatically).
    #[arg(long, env = "RAUTHY_URL", default_value = "https://id.tartanoglu.com")]
    url: String,

    /// Path to the rauthy-provision JSON state file — the source of truth for
    /// which users are email-derived and where their set-password link lands.
    #[arg(long, env = "RAUTHY_PROVISION_STATE")]
    state: std::path::PathBuf,

    #[command(subcommand)]
    command: RauthyCommand,
}

#[derive(Subcommand, Debug)]
#[cfg(feature = "rauthy")]
enum RauthyCommand {
    /// List every email-derived user (provisioned with an emailed set-password
    /// link), as defined in the state file.
    ListEmailUsers,

    /// Resend a user a fresh set-password / reset email. The user may be given
    /// by email, email local-part, or display/given name.
    ResetPassword {
        /// User identifier (email, local-part, or name).
        username: String,
    },
}

#[derive(Args, Debug)]
#[cfg(feature = "kanidm")]
struct KanidmArgs {
    /// Kanidm base URL.
    #[arg(long, env = "KANIDM_URL")]
    url: String,

    /// File containing the idm_admin password.
    #[arg(long, env = "KANIDM_IDM_ADMIN_PASSWORD_FILE")]
    idm_admin_password_file: String,

    /// File containing the `admin` password. Required only for domain-level
    /// operations (e.g. `set-ldap-unix-bind`) that `idm_admin` cannot perform.
    #[arg(long, env = "KANIDM_ADMIN_PASSWORD_FILE")]
    admin_password_file: Option<String>,

    #[command(subcommand)]
    command: KanidmCommand,
}

#[derive(Subcommand, Debug)]
#[cfg(feature = "kanidm")]
enum KanidmCommand {
    /// Provision primary, optional TOTP, backup-code, and POSIX credentials.
    Provision(KanidmProvisionArgs),

    /// Toggle LDAP binds against Kanidm POSIX passwords (authenticates as
    /// `admin`; requires --admin-password-file).
    SetLdapUnixBind {
        /// Enable or disable POSIX-password LDAP binds.
        #[arg(required = true, action = clap::ArgAction::Set)]
        enabled: bool,
    },

    /// Set only the POSIX/unix password for a person (no primary credential
    /// update, so it bypasses MFA-required commit gating).
    SetPosixPassword {
        /// Target Kanidm account name.
        account: String,

        /// File containing the POSIX/LDAP password to set.
        #[arg(long)]
        posix_from: String,
    },

    /// Set the primary password only when the person has no primary credential.
    SetInitialPrimaryPassword {
        /// Target Kanidm account name.
        account: String,

        /// File containing the initial primary Kanidm password to set.
        #[arg(long)]
        primary_from: String,
    },

    /// Reconcile person SSH public keys by tag.
    SshPublicKey {
        #[command(subcommand)]
        command: SshPublicKeyCommand,
    },

    /// Extend a person with POSIX/unix account attributes.
    PosixExtend {
        /// Target Kanidm account name.
        account: String,

        /// POSIX gidNumber.
        #[arg(long)]
        gid_number: Option<u32>,

        /// POSIX login shell.
        #[arg(long)]
        login_shell: Option<String>,
    },

    /// Service-account operations (idiomatic LDAP search-bind identity).
    ServiceAccount {
        #[command(subcommand)]
        command: ServiceAccountCommand,
    },

    /// Add members to a Kanidm group (e.g. grant a service account mail read
    /// via `idm_people_pii_read`).
    GroupAddMembers {
        /// Group name.
        group: String,

        /// One or more member names to add.
        #[arg(required = true)]
        members: Vec<String>,
    },

    /// Remove members from a Kanidm group.
    GroupRemoveMembers {
        /// Group name.
        group: String,

        /// One or more member names to remove.
        #[arg(required = true)]
        members: Vec<String>,
    },

    /// Return whether a Kanidm person account exists.
    PersonExists {
        /// Target Kanidm account name.
        account: String,
    },

    /// Delete a Kanidm person account.
    DeletePerson {
        /// Target Kanidm account name.
        account: String,
    },

    /// Delete a person's POSIX/unix credential.
    DeletePosixPassword {
        /// Target Kanidm account name.
        account: String,
    },
}

#[derive(Subcommand, Debug)]
#[cfg(feature = "kanidm")]
enum ServiceAccountCommand {
    /// Idempotently create a service account.
    Create {
        /// Service account name.
        name: String,

        /// Display name.
        #[arg(long)]
        display_name: String,

        /// Group or account that manages this service account afterwards.
        #[arg(long, default_value = "idm_admins")]
        managed_by: String,
    },

    /// Generate a fresh API token for a service account. The token is a secret;
    /// write it to a file with --out (mode 0600) rather than echoing it.
    ApiToken {
        /// Service account name.
        name: String,

        /// Token label.
        #[arg(long, default_value = "identity-cli")]
        label: String,

        /// Issue a read-write token (default: read-only).
        #[arg(long)]
        read_write: bool,

        /// Write the token to this file (0600) instead of stdout.
        #[arg(long)]
        out: Option<String>,
    },

    /// Delete a service account (and its API tokens).
    Delete {
        /// Service account name.
        name: String,
    },
}

#[derive(Subcommand, Debug)]
#[cfg(feature = "kanidm")]
enum SshPublicKeyCommand {
    /// Ensure a tagged SSH public key exists with the declared value.
    Ensure {
        /// Target Kanidm account name.
        account: String,

        /// Kanidm SSH key tag.
        tag: String,

        /// OpenSSH public key text.
        public_key: String,
    },

    /// Delete a tagged SSH public key if present.
    Delete {
        /// Target Kanidm account name.
        account: String,

        /// Kanidm SSH key tag.
        tag: String,
    },
}

#[derive(Args, Debug)]
#[cfg(feature = "kanidm")]
struct KanidmProvisionArgs {
    /// Target Kanidm account name.
    account: String,

    /// Enroll TOTP and generate backup codes.
    #[arg(long)]
    with_totp: bool,

    /// File containing the POSIX/LDAP password to set.
    #[arg(long)]
    posix_from: Option<String>,

    /// File containing the primary Kanidm password to set.
    #[arg(long)]
    primary_from: Option<String>,

    /// Emit machine-readable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Args, Debug)]
#[cfg(feature = "bitwarden")]
struct BitwardenArgs {
    /// Bitwarden item name.
    #[arg(long)]
    name: Option<String>,

    /// Login username/service principal name.
    #[arg(long)]
    username: Option<String>,

    /// Password source: a file path or `-` for stdin.
    #[arg(long)]
    password_from: Option<String>,

    /// TOTP otpauth:// URI to store in login.totp.
    #[arg(long)]
    totp: Option<String>,

    /// Bitwarden folder name.
    #[arg(long)]
    folder: Option<String>,

    /// Bitwarden session key. Defaults to BW_SESSION.
    #[arg(long, env = "BW_SESSION", hide_env_values = true)]
    session: Option<String>,

    /// Read Phase-02 provision JSON from a file path or `-` for stdin.
    #[arg(long)]
    from_json: Option<String>,

    /// Use primary_password from --from-json instead of posix_password.
    #[arg(long)]
    use_primary: bool,
}

#[derive(Subcommand, Debug)]
#[cfg(feature = "bitwarden")]
enum BitwardenCommand {
    /// Create or update a Bitwarden login item.
    Upsert(BitwardenArgs),
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();

    let result: Result<()> = match cli.command {
        #[cfg(feature = "kanidm")]
        Commands::Kanidm(args) => run_kanidm(args).await,

        #[cfg(feature = "bitwarden")]
        Commands::Bitwarden { command } => run_bitwarden(command),

        #[cfg(feature = "rauthy")]
        Commands::Rauthy(args) => run_rauthy(args).await,

        #[cfg(not(any(feature = "kanidm", feature = "bitwarden", feature = "rauthy")))]
        Commands::Noop => Ok(()),
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("{err}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(feature = "kanidm")]
async fn run_kanidm(args: KanidmArgs) -> Result<()> {
    let config = identity_cli::kanidm::ClientConfig {
        url: args.url,
        idm_admin_password_file: args.idm_admin_password_file,
        admin_password_file: args.admin_password_file,
    };

    match args.command {
        KanidmCommand::Provision(provision_args) => {
            let json = provision_args.json;
            let result = identity_cli::kanidm::provision(
                &config,
                identity_cli::kanidm::ProvisionRequest {
                    account: provision_args.account,
                    with_totp: provision_args.with_totp,
                    posix_password_file: provision_args.posix_from,
                    primary_password_file: provision_args.primary_from,
                },
            )
            .await?;
            print_provision_result(&result, json)?;
        }
        KanidmCommand::SetLdapUnixBind { enabled } => {
            identity_cli::kanidm::set_ldap_unix_bind(&config, enabled).await?;
            println!("ldap_unix_bind={enabled}");
        }
        KanidmCommand::SetPosixPassword {
            account,
            posix_from,
        } => {
            identity_cli::kanidm::set_posix_password(&config, &account, &posix_from).await?;
            println!("posix_password_set={account}");
        }
        KanidmCommand::SetInitialPrimaryPassword {
            account,
            primary_from,
        } => {
            let set = identity_cli::kanidm::set_initial_primary_password(
                &config,
                &account,
                &primary_from,
            )
            .await?;
            println!(
                "initial_primary_password_{}={account}",
                if set { "set" } else { "present" }
            );
        }
        KanidmCommand::SshPublicKey { command } => match command {
            SshPublicKeyCommand::Ensure {
                account,
                tag,
                public_key,
            } => {
                let changed = identity_cli::kanidm::ensure_ssh_public_key(
                    &config,
                    &account,
                    &tag,
                    &public_key,
                )
                .await?;
                println!(
                    "ssh_public_key_{}={account}:{tag}",
                    if changed { "changed" } else { "ok" }
                );
            }
            SshPublicKeyCommand::Delete { account, tag } => {
                identity_cli::kanidm::delete_ssh_public_key(&config, &account, &tag).await?;
                println!("ssh_public_key_deleted={account}:{tag}");
            }
        },
        KanidmCommand::PosixExtend {
            account,
            gid_number,
            login_shell,
        } => {
            identity_cli::kanidm::extend_posix_account(
                &config,
                &account,
                gid_number,
                login_shell.as_deref(),
            )
            .await?;
            println!("posix_extended={account}");
        }
        KanidmCommand::ServiceAccount { command } => match command {
            ServiceAccountCommand::Create {
                name,
                display_name,
                managed_by,
            } => {
                let created = identity_cli::kanidm::ensure_service_account(
                    &config,
                    &name,
                    &display_name,
                    &managed_by,
                )
                .await?;
                println!(
                    "service_account={name} {}",
                    if created { "created" } else { "exists" }
                );
            }
            ServiceAccountCommand::ApiToken {
                name,
                label,
                read_write,
                out,
            } => {
                let token =
                    identity_cli::kanidm::generate_api_token(&config, &name, &label, read_write)
                        .await?;
                match out {
                    Some(path) => {
                        write_secret_file(&path, &token)?;
                        println!("api_token_written={path}");
                    }
                    None => println!("{token}"),
                }
            }
            ServiceAccountCommand::Delete { name } => {
                identity_cli::kanidm::delete_service_account(&config, &name).await?;
                println!("service_account_deleted={name}");
            }
        },
        KanidmCommand::GroupAddMembers { group, members } => {
            identity_cli::kanidm::group_add_members(&config, &group, &members).await?;
            println!("group_members_added={group}");
        }
        KanidmCommand::GroupRemoveMembers { group, members } => {
            identity_cli::kanidm::group_remove_members(&config, &group, &members).await?;
            println!("group_members_removed={group}");
        }
        KanidmCommand::PersonExists { account } => {
            let exists = identity_cli::kanidm::person_exists(&config, &account).await?;
            println!(
                "person={account} {}",
                if exists { "exists" } else { "missing" }
            );
        }
        KanidmCommand::DeletePerson { account } => {
            identity_cli::kanidm::delete_person(&config, &account).await?;
            println!("person_deleted={account}");
        }
        KanidmCommand::DeletePosixPassword { account } => {
            identity_cli::kanidm::delete_posix_password(&config, &account).await?;
            println!("posix_password_deleted={account}");
        }
    }

    Ok(())
}

/// Write a secret to a file with `0600` permissions and no trailing newline so
/// downstream consumers read the exact token bytes.
#[cfg(feature = "kanidm")]
fn write_secret_file(path: &str, secret: &str) -> Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(|err| anyhow::anyhow!("opening {path} for token write: {err}"))?;
    file.write_all(secret.as_bytes())
        .map_err(|err| anyhow::anyhow!("writing token to {path}: {err}"))?;
    Ok(())
}

#[cfg(feature = "bitwarden")]
fn run_bitwarden(command: BitwardenCommand) -> Result<()> {
    match command {
        BitwardenCommand::Upsert(args) => {
            if let Some(path) = args.password_from.as_deref() {
                identity_cli::bitwarden::validate_password_source(path)?;
            }
            let item =
                identity_cli::bitwarden::resolve_input(identity_cli::bitwarden::UpsertInput {
                    name: args.name,
                    username: args.username,
                    password_from: args.password_from,
                    totp: args.totp,
                    folder: args.folder,
                    session: args.session,
                    from_json: args.from_json,
                    use_primary: args.use_primary,
                })?;
            identity_cli::bitwarden::upsert_login(item)
        }
    }
}

#[cfg(feature = "rauthy")]
async fn run_rauthy(args: RauthyArgs) -> Result<()> {
    match args.command {
        RauthyCommand::ListEmailUsers => {
            let users = identity_cli::rauthy::email_users(&args.state)?;
            if users.is_empty() {
                println!("(no email-derived users in {})", args.state.display());
            }
            for user in users {
                match user.name {
                    Some(name) => println!("{}\t{name}", user.email),
                    None => println!("{}", user.email),
                }
            }
        }
        RauthyCommand::ResetPassword { username } => {
            let user = identity_cli::rauthy::find_user(&args.state, &username)?;
            identity_cli::rauthy::reset_password(&args.url, &user).await?;
            println!("reset_email_sent={}", user.email);
        }
    }
    Ok(())
}

#[cfg(feature = "kanidm")]
fn print_provision_result(
    result: &identity_cli::kanidm::ProvisionResult,
    json: bool,
) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(result)?);
        return Ok(());
    }

    println!("account: {}", result.account);
    println!("primary_password: {}", result.primary_password);
    println!("posix_password: {}", result.posix_password);
    if let Some(uri) = &result.totp_uri {
        println!("totp_uri: {uri}");
    }
    if !result.backup_codes.is_empty() {
        println!("backup_codes:");
        for code in &result.backup_codes {
            println!("  {code}");
        }
    }

    Ok(())
}
