//! `veil` command-line client.

mod approval;
mod client;
mod commands;
mod diagnostic;
mod exec;
mod kdf;
mod keystore;
mod project;
mod redact;
mod settings;
mod state;
mod ui;
mod vaults;

use std::{
    process::ExitCode,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::Context;
use clap::{ArgAction, CommandFactory, FromArgMatches, Parser};
use tracing_subscriber::EnvFilter;

const HELP: &str = "{about}\n\n{usage-heading} {usage}\n\nDaily use:\n  run         Run a command with project secrets; redact its output\n  list        List names and references, never values\n  get         Reveal or copy one value\n  set         Create or update one value\n  inject      Render a template containing references\n  export      Export text fields, never hidden fields\n\nSetup and access:\n  login       Register a personal device or renew its management session\n  init        Import .env and configure this project\n  vault       Manage Vaults and approval policies\n  device      Enroll and manage devices\n  workload    Manage CI identities\n  bitwarden   Configure Bitwarden client access\n  recover     Recover access with a recovery code\n  mcp         Serve scoped tools to an agent\n\nDiagnostics:\n  doctor      Check configuration, identity, connectivity and references\n  config      Show configuration and its sources\n  audit       Inspect deliveries\n  version     Show version and build information\n  upgrade     Check or install a signed CLI release\n  help        Show command help\n\n{options}\nExamples:\n  veil login --server <URL> --email <EMAIL>\n  veil init\n  veil run -- npm test\n  veil get DATABASE_URL --copy\n\nRun veil <command> --help for details.\n";

/// Veil command-line client.
#[derive(Debug, Parser)]
#[command(name = "veil", version, about = "Deliver secrets to programs without putting values in your repository.", help_template = HELP)]
struct Cli {
    /// Emit JSON results and diagnostics; run preserves the child's output.
    #[arg(long, global = true)]
    json: bool,

    /// Never prompt; missing input or approval fails instead.
    #[arg(long, global = true)]
    no_input: bool,

    /// Control diagnostic colors. Auto respects NO_COLOR and terminal detection.
    #[arg(long, global = true, value_enum, default_value = "auto")]
    color: ui::Color,

    /// Increase diagnostic verbosity: `-v` info, `-vv` debug, `-vvv` trace.
    ///
    /// Default level is `warn`; `VEIL_LOG` overrides it with a full filter expression.
    #[arg(short, long, global = true, action = ArgAction::Count)]
    verbose: u8,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, clap::Subcommand)]
enum Command {
    /// Register a personal device with all-Vault reads, or renew its management session.
    #[command(
        after_help = "Examples:\n  veil login --server <URL> --email <EMAIL>\n  veil login --create\n\nUse veil device add for a restricted host. Login does not promote an existing restricted device."
    )]
    Login {
        /// Service URL.
        #[arg(long)]
        server: Option<String>,

        /// Sign-in address.
        #[arg(long)]
        email: Option<String>,

        /// Create the account instead of signing in.
        #[arg(long)]
        create: bool,
    },

    /// Import this directory's .env into a Vault and write references to veil.toml.
    #[command(
        after_help = "Examples:\n  veil init --dry-run\n  veil init --vault api\n\nThe original .env remains on disk. Existing values require confirmation before replacement."
    )]
    Init {
        /// Vault name; defaults to the directory name.
        #[arg(long)]
        vault: Option<String>,

        /// Preview names and changes without writing or delivering values.
        #[arg(long)]
        dry_run: bool,

        /// Confirm replacing existing values; never bypass Vault approval.
        #[arg(long)]
        yes: bool,
    },

    /// Create or update one value; prefer stdin or a file over a command-line value.
    #[command(
        after_help = "Examples:\n  veil set DATABASE_URL\n  veil set TLS_KEY --file private-key.pem\n  secret-provider | veil set API_TOKEN --stdin\n\nFile and stdin input preserve trailing newlines. --value may appear in shell history and process arguments."
    )]
    Set {
        /// A veil://vault/item/field reference, or a variable name from veil.toml.
        target: String,

        /// Value; prompted when absent. May start with `-`, as PEM keys do.
        #[arg(long, allow_hyphen_values = true, conflicts_with_all = ["stdin", "file"])]
        value: Option<String>,

        /// Read the value from stdin, preserving newlines.
        #[arg(long, conflicts_with = "file")]
        stdin: bool,

        /// Read a UTF-8 value from this file, preserving newlines.
        #[arg(long)]
        file: Option<std::path::PathBuf>,
    },

    /// Show names, never values: a Vault's Items, this directory's references, or the Vaults.
    #[command(
        after_help = "Examples:\n  veil list\n  veil list api --json\n\nWithout a Vault argument, list shows project references when veil.toml exists here, otherwise readable Vaults."
    )]
    List {
        /// List the Items and fields of this Vault.
        vault: Option<String>,
    },

    /// Reveal or copy one value after approval.
    #[command(
        after_help = "Examples:\n  veil get DATABASE_URL\n  veil get DATABASE_URL --copy\n  veil get veil://api/database/password --yes --json\n\n--yes confirms this reveal, not a Vault's presence approval. Clipboard contents are not cleared automatically."
    )]
    Get {
        /// A veil://vault/item/field reference, or a variable name from veil.toml.
        target: String,

        /// Confirm revealing or copying; never bypass Vault approval.
        #[arg(long)]
        yes: bool,

        /// Put the value on the clipboard instead of printing it.
        #[arg(long)]
        copy: bool,
    },

    /// Render a template containing veil:// references.
    Inject {
        /// Template file.
        file: String,

        /// Write the result here instead of stdout.
        #[arg(long)]
        out: Option<String>,

        /// Encrypt the result with sops to the age recipients `.sops.yaml` names for --out.
        #[arg(long, requires = "out")]
        sops: bool,
    },

    /// Print text fields as shell exports, dotenv, or JSON; hidden fields are never exported.
    Export {
        /// `shell`, `dotenv`, or `json`.
        #[arg(long, default_value = "shell", value_parser = ["shell", "dotenv", "json"])]
        format: String,
    },

    /// Serve a scoped MCP front end on stdio, for an agent.
    Mcp {
        /// References the agent may use; `*` matches the rest of a segment. Repeatable.
        #[arg(long = "allow", required = true)]
        allow: Vec<String>,

        /// Also offer a tool that returns values to the agent.
        #[arg(long)]
        allow_reveal: bool,
    },

    /// Report what this machine knows and what is broken.
    Doctor,

    /// Who delivered what, and when.
    Audit {
        /// How many rows.
        #[arg(long, default_value_t = 50)]
        limit: usize,

        /// Only deliveries of this Item: a reference or a veil.toml name.
        #[arg(long)]
        item: Option<String>,
    },

    /// Run a command with the values veil.toml references; its output is redacted.
    #[command(
        after_help = "Examples:\n  veil run -- npm test\n  veil run --only DATABASE_URL -- ./server\n  veil run --mount .env -- ./file-reader\n\nUse -- before the child command. --json affects Veil diagnostics, not child output.\nA mount is a FIFO, not a regular file; it is removed on exit and has a read limit."
    )]
    Run {
        /// Mount the values as a named pipe at this path.
        #[arg(long)]
        mount: Option<String>,

        /// How many times the mounted pipe may be read before it disappears.
        #[arg(long, default_value_t = 1, requires = "mount")]
        mount_max_reads: usize,

        /// Deliver only these veil.toml names or references. Repeatable.
        #[arg(long = "only")]
        only: Vec<String>,

        /// Show delivered values in the child's output instead of redacting them.
        #[arg(long)]
        no_redact: bool,

        /// The command and its arguments.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, required = true)]
        command: Vec<String>,
    },

    /// Rebuild access from the recovery code, including the data.
    Recover {
        /// Service URL.
        #[arg(long)]
        server: Option<String>,

        /// Sign-in address.
        #[arg(long)]
        email: Option<String>,
    },

    /// Create, list, or revoke CI identities.
    Workload {
        #[command(subcommand)]
        action: WorkloadCommand,
    },

    /// Let the official Bitwarden clients see one Vault.
    Bitwarden {
        #[command(subcommand)]
        action: BitwardenCommand,
    },

    /// List or create Vaults.
    Vault {
        #[command(subcommand)]
        action: VaultCommand,
    },

    /// Enroll, approve, list, or revoke machines.
    Device {
        #[command(subcommand)]
        action: DeviceCommand,
    },

    /// Show the configuration file and the effective value of each setting.
    Config,

    /// Check or install a signed release of an installer-managed Linux CLI.
    #[command(
        after_help = "Examples:\n  veil upgrade --check\n  veil upgrade\n  veil upgrade --version 0.3.1\n\nOnly the CLI is updated. Package-manager installations and macOS source builds must use their original installation method. Public GitHub Releases supply artifacts without a token."
    )]
    Upgrade {
        /// Verify release metadata without downloading or installing the executable.
        #[arg(long)]
        check: bool,
        /// Select an exact release version rather than the latest stable release.
        #[arg(long, value_parser = veil_cli::update::parse_version)]
        version: Option<semver::Version>,
        /// Permit an explicitly selected older version.
        #[arg(long, requires = "version")]
        allow_downgrade: bool,
    },

    /// Print build information.
    Version,
}

#[derive(Debug, clap::Subcommand)]
enum BitwardenCommand {
    /// Serve one Vault to the browser extension, the mobile apps, and `bw`.
    Enable {
        /// The Vault the clients see.
        #[arg(long)]
        vault: String,
    },
    /// Show which Vault Bitwarden clients see.
    Status,
    /// Sign Bitwarden clients out and stop serving them.
    Disable,
    /// Require a code from an authenticator app at every Bitwarden login.
    #[command(name = "two-step", subcommand)]
    TwoStep(TwoStepCommand),
}

#[derive(Debug, clap::Subcommand)]
enum TwoStepCommand {
    /// Create an authenticator secret, show it as a QR code, and turn two-step login on once a
    /// code from the app is entered.
    Enable {
        /// Use this base32 secret instead of a new one, for example one already in an app.
        #[arg(long, value_name = "BASE32")]
        secret: Option<String>,
        /// The current code, instead of asking for it.
        #[arg(long, value_name = "CODE", requires = "secret")]
        code: Option<String>,
    },
    /// Turn two-step login off; Bitwarden logins then need only the master password.
    Disable,
}

#[derive(Debug, clap::Subcommand)]
enum VaultCommand {
    /// List the Vaults this machine can open.
    List,
    /// Create an empty Vault.
    Create {
        /// Vault name.
        name: String,
    },
    /// Set the approval every delivery from this Vault needs.
    Policy {
        /// Vault name.
        name: String,
        /// `none`, or `presence` (Touch ID on this machine for every delivery).
        #[arg(long, value_parser = ["none", "presence"])]
        approval: String,
    },
}

#[derive(Debug, clap::Subcommand)]
enum WorkloadCommand {
    /// Create a workload that reads some Vaults.
    Add {
        /// Workload name.
        #[arg(long)]
        name: String,

        /// OIDC issuer URL.
        #[arg(long)]
        issuer: String,

        /// Expected audience.
        #[arg(long)]
        audience: String,

        /// Claims that must match, as key=value. Repeatable.
        #[arg(long = "claim")]
        claims: Vec<String>,

        /// A Vault to grant. Repeatable; defaults to those veil.toml references.
        #[arg(long = "vault")]
        vaults: Vec<String>,
    },

    /// List workloads.
    List,

    /// Revoke a workload.
    Remove {
        /// Workload id, from `veil workload list`.
        id: uuid::Uuid,
    },
}

#[derive(Debug, clap::Subcommand)]
enum DeviceCommand {
    /// Start enrolling this machine and wait for approval.
    Add {
        /// Service URL, when this machine has no state yet.
        #[arg(long)]
        server: Option<String>,

        /// Sign-in address.
        #[arg(long)]
        email: Option<String>,

        /// Code to show; generated when absent.
        #[arg(long)]
        code: Option<String>,

        /// Device name; defaults to the hostname.
        #[arg(long)]
        name: Option<String>,
    },

    /// Approve a waiting machine from a trusted one.
    Approve {
        /// Code the waiting machine shows.
        code: String,

        /// A Vault to grant. Repeatable; defaults to those veil.toml references.
        #[arg(long = "vault")]
        vaults: Vec<String>,
    },

    /// Upgrade this machine to a personal device using the master password.
    Promote,

    /// List machines.
    List,

    /// Revoke a machine at once; the Vaults it could read get a new key on the next write.
    #[command(visible_alias = "rm")]
    Remove {
        /// Device name or id, from `veil device list`.
        target: String,
    },
}

/// Seconds since the Unix epoch.
pub(crate) fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("the clock is after 1970")
        .as_secs()
}

fn main() -> ExitCode {
    let args: Vec<_> = std::env::args_os().collect();
    let cli = match Cli::command().try_get_matches_from(&args) {
        Ok(matches) => Cli::from_arg_matches(&matches).expect("validated arguments"),
        Err(error) => {
            if !error.use_stderr() {
                let _ = error.print();
                return ExitCode::SUCCESS;
            }
            if args.len() == 1 {
                let _ = error.print();
                return ExitCode::from(2);
            }
            ui::init(ui::Output {
                json: args
                    .iter()
                    .take_while(|arg| *arg != "--")
                    .any(|arg| arg == "--json"),
                ..Default::default()
            });
            // Parser messages can contain supplied passwords or values. Never echo argv.
            let message = match error.kind() {
                clap::error::ErrorKind::InvalidValue => {
                    "Invalid option value. Check the allowed values in command help."
                }
                clap::error::ErrorKind::MissingRequiredArgument => {
                    "Required arguments are missing."
                }
                clap::error::ErrorKind::ArgumentConflict => {
                    "These options cannot be used together."
                }
                clap::error::ErrorKind::InvalidSubcommand
                | clap::error::ErrorKind::UnknownArgument => "Unknown command or option.",
                _ => "A command and valid arguments are required.",
            };
            let failure = diagnostic::Failure::new(
                "usage",
                2,
                message,
                "Usage: veil [OPTIONS] <COMMAND>. Run: veil <command> --help",
            );
            return ExitCode::from(diagnostic::report(&failure.into(), false));
        }
    };
    ui::init(ui::Output {
        json: cli.json,
        no_input: cli.no_input,
        color: cli.color,
    });
    let result = (|| {
        if cli.json
            && matches!(
                cli.command,
                Command::Inject { .. } | Command::Export { .. } | Command::Mcp { .. }
            )
        {
            return Err(diagnostic::Failure::new("usage", 2,
                "This command produces a raw stream, not a JSON result.",
                "Omit --json. Use export --format json for JSON exports; MCP already uses JSON-RPC.").into());
        }
        if !matches!(
            cli.command,
            Command::Version | Command::Doctor | Command::Upgrade { .. }
        ) {
            settings::load()?;
            init_logging(cli.verbose)?;
        }
        run(&cli)
    })();
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => ExitCode::from(diagnostic::report(
            &error,
            matches!(cli.command, Command::Run { .. })
                && error.downcast_ref::<exec::Started>().is_none(),
        )),
    }
}

fn run(cli: &Cli) -> anyhow::Result<()> {
    match &cli.command {
        Command::Login {
            server,
            email,
            create,
        } => commands::login::run(commands::login::Options {
            server: server.clone(),
            email: email.clone(),
            create: *create,
            json: cli.json,
        }),
        Command::Init {
            vault,
            dry_run,
            yes,
        } => commands::init::run(commands::init::Options {
            vault: vault.clone(),
            json: cli.json,
            dry_run: *dry_run,
            yes: *yes,
        }),
        Command::Set {
            target,
            value,
            stdin,
            file,
        } => commands::set::run(commands::set::Options {
            target: target.clone(),
            value: value.clone(),
            stdin: *stdin,
            file: file.clone(),
            json: cli.json,
        }),
        Command::List { vault } => commands::list::run(commands::list::Options {
            vault: vault.clone(),
            json: cli.json,
        }),
        Command::Get { target, yes, copy } => commands::get::run(commands::get::Options {
            target: target.clone(),
            yes: *yes,
            copy: *copy,
            json: cli.json,
        }),
        Command::Inject { file, out, sops } => commands::inject::run(commands::inject::Options {
            file: file.clone(),
            out: out.clone(),
            sops: *sops,
        }),
        Command::Export { format } => commands::export::run(commands::export::Options {
            format: format.clone(),
        }),
        Command::Mcp {
            allow,
            allow_reveal,
        } => commands::mcp::run(commands::mcp::Options {
            allow: allow.clone(),
            allow_reveal: *allow_reveal,
        }),
        Command::Doctor => commands::doctor::run(cli.json),
        Command::Audit { limit, item } => commands::audit::run(commands::audit::Options {
            limit: *limit,
            item: item.clone(),
            json: cli.json,
        }),
        Command::Run {
            command,
            mount,
            mount_max_reads,
            only,
            no_redact,
        } => commands::run::run(commands::run::Options {
            command: command.clone(),
            mount: mount.clone(),
            mount_max_reads: *mount_max_reads,
            only: only.clone(),
            no_redact: *no_redact,
        }),
        Command::Recover { server, email } => commands::recover::run(commands::recover::Options {
            server: server.clone(),
            email: email.clone(),
            json: cli.json,
        }),
        Command::Workload { action } => {
            let action = match action {
                WorkloadCommand::Add {
                    name,
                    issuer,
                    audience,
                    claims,
                    vaults,
                } => commands::workload::Action::Add {
                    name: name.clone(),
                    issuer: issuer.clone(),
                    audience: audience.clone(),
                    claims: claims.clone(),
                    vaults: vaults.clone(),
                },
                WorkloadCommand::List => commands::workload::Action::List,
                WorkloadCommand::Remove { id } => commands::workload::Action::Remove { id: *id },
            };
            commands::workload::run(action, cli.json)
        }
        Command::Bitwarden { action } => commands::bitwarden::run(
            match action {
                BitwardenCommand::Enable { vault } => commands::bitwarden::Action::Enable {
                    vault: vault.clone(),
                },
                BitwardenCommand::Status => commands::bitwarden::Action::Status,
                BitwardenCommand::Disable => commands::bitwarden::Action::Disable,
                BitwardenCommand::TwoStep(TwoStepCommand::Enable { secret, code }) => {
                    commands::bitwarden::Action::TwoStepEnable {
                        secret: secret.clone(),
                        code: code.clone(),
                    }
                }
                BitwardenCommand::TwoStep(TwoStepCommand::Disable) => {
                    commands::bitwarden::Action::TwoStepDisable
                }
            },
            cli.json,
        ),
        Command::Vault { action } => commands::vault::run(
            match action {
                VaultCommand::List => commands::vault::Action::List,
                VaultCommand::Create { name } => {
                    commands::vault::Action::Create { name: name.clone() }
                }
                VaultCommand::Policy { name, approval } => commands::vault::Action::Policy {
                    name: name.clone(),
                    approval: approval.clone(),
                },
            },
            cli.json,
        ),
        Command::Device { action } => {
            let action = match action {
                DeviceCommand::Add {
                    server,
                    email,
                    code,
                    name,
                } => commands::device::Action::Add {
                    server: server.clone(),
                    email: email.clone(),
                    code: code.clone(),
                    name: name.clone(),
                },
                DeviceCommand::Approve { code, vaults } => commands::device::Action::Approve {
                    code: code.clone(),
                    vaults: vaults.clone(),
                },
                DeviceCommand::List => commands::device::Action::List,
                DeviceCommand::Promote => commands::device::Action::Promote,
                DeviceCommand::Remove { target } => commands::device::Action::Remove {
                    target: target.clone(),
                },
            };
            commands::device::run(action, cli.json)
        }
        Command::Config => commands::config::run(cli.json),
        Command::Version => commands::version::run(cli.json),
        Command::Upgrade {
            check,
            version,
            allow_downgrade,
        } => commands::upgrade::run(commands::upgrade::Options {
            check: *check,
            version: version.as_ref().map(ToString::to_string),
            allow_downgrade: *allow_downgrade,
            json: cli.json,
        }),
    }
}

/// Installs logging on stderr, using JSON records in JSON mode.
fn init_logging(verbose: u8) -> anyhow::Result<()> {
    let level = match verbose {
        0 => "warn",
        1 => "info",
        2 => "debug",
        _ => "trace",
    };
    let filter = settings::value(settings::Key::Log).unwrap_or_else(|| format!("veil={level}"));

    let subscriber = tracing_subscriber::fmt()
        .with_ansi(!ui::output().json && ui::color())
        .with_env_filter(
            EnvFilter::try_new(&filter)
                .context("invalid log filter (VEIL_LOG or `log` in config.toml)")?,
        )
        .with_writer(std::io::stderr)
        .without_time();
    let result = if ui::output().json {
        subscriber.json().try_init()
    } else {
        subscriber.try_init()
    };
    result.map_err(|err| anyhow::anyhow!("cannot initialize logging: {err}"))?;
    Ok(())
}
