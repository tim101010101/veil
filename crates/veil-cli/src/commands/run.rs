//! `veil run`: deliver values to a child process.

use std::collections::BTreeMap;

use anyhow::{Context, Result, bail};
use veil_core::Reference;
use veil_proto::Destination;

use crate::{
    client::Client,
    exec,
    project::{self, VeilToml},
    vaults::{self, Opened, Reader, Resolved, View},
};

/// What `veil run` was asked to do.
pub struct Options {
    /// The command and its arguments.
    pub command: Vec<String>,
    /// Mount the values as a named pipe at this path.
    pub mount: Option<String>,
    /// How many times the pipe may be read before it disappears.
    pub mount_max_reads: usize,
    /// Deliver only these: references or `veil.toml` names.
    pub only: Vec<String>,
    /// Do not redact the child's output.
    pub no_redact: bool,
}

/// Runs `veil run`.
pub fn run(options: Options) -> Result<()> {
    let (program, arguments) = options
        .command
        .split_first()
        .context("nothing to run; pass a command after --")?;
    let declaration = VeilToml::read(&project::current_dir()?)?;
    let wanted = select(declaration.as_ref(), &options.only)?;
    let destination = if options.mount.is_some() {
        Destination::Mount
    } else {
        Destination::Inject
    };
    let command_line = options.command.join(" ");

    let (resolved, released) = if let Some(workload) = Workload::from_env()? {
        // In CI there is no local state: the job presents an OIDC token and its sealing key.
        let client = Client::new(&workload.server);
        let token = client
            .workload_token(workload.id, &workload.oidc_token)
            .map_err(anyhow::Error::from)?;
        let document = client
            .sync_bearer(&token.token)
            .map_err(anyhow::Error::from)?;
        let view = View::open(&document, &Reader::workload(workload.id, workload.sealing))?;
        let resolved = resolve(&view, &wanted)?;
        let released = vaults::release(
            &resolved.iter().map(|(_, r)| r).collect::<Vec<_>>(),
            destination,
            &command_line,
            |events| {
                client
                    .report_events_bearer(&token.token, &events)
                    .context("the service refused the audit record")
            },
        )?;
        (resolved, released)
    } else {
        let mut opened = Opened::load()?;
        let resolved = resolve(&opened.view, &wanted)?;
        let released = opened.release(
            &resolved.iter().map(|(_, r)| r).collect::<Vec<_>>(),
            destination,
            &command_line,
        )?;
        (resolved, released)
    };

    let variables: Vec<(String, String)> = resolved
        .iter()
        .map(|(name, resolved)| (name.clone(), resolved.value(&released).to_owned()))
        .collect();
    let redact = (!options.no_redact).then(|| variables.iter().map(|(_, v)| v.clone()).collect());

    let mounted = match &options.mount {
        Some(path) => Some(serve(path, &variables, options.mount_max_reads.max(1))?),
        None => None,
    };
    let code = exec::run(&exec::Child {
        program,
        arguments,
        variables: if options.mount.is_some() {
            &[]
        } else {
            &variables
        },
        redact,
    })?;
    if let Some(path) = mounted {
        let _ = std::fs::remove_file(path);
    }
    std::process::exit(code);
}

/// The variables to deliver, by name: every binding of `veil.toml`, or those `--only` names. An
/// `--only` reference that `veil.toml` does not bind gets a name derived from its Item and field.
fn select(declaration: Option<&VeilToml>, only: &[String]) -> Result<BTreeMap<String, Reference>> {
    let bound = match declaration {
        Some(declaration) => declaration.references()?,
        None => BTreeMap::new(),
    };
    if only.is_empty() {
        if declaration.is_none() {
            bail!("no veil.toml here; run `veil init`, or name the values with --only");
        }
        return Ok(bound);
    }
    let mut wanted = BTreeMap::new();
    for entry in only {
        if let Some(reference) = bound.get(entry) {
            wanted.insert(entry.clone(), reference.clone());
            continue;
        }
        let reference: Reference = entry
            .parse()
            .with_context(|| format!("{entry} is neither a veil.toml name nor a reference"))?;
        let name = bound
            .iter()
            .find(|(_, candidate)| **candidate == reference)
            .map(|(name, _)| name.clone())
            .unwrap_or_else(|| derived_name(&reference));
        wanted.insert(name, reference);
    }
    Ok(wanted)
}

/// `veil://example/demo-service/password` → `DEMO_SERVICE_PASSWORD`.
fn derived_name(reference: &Reference) -> String {
    format!("{}_{}", reference.item, reference.field)
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect()
}

fn resolve(view: &View, wanted: &BTreeMap<String, Reference>) -> Result<Vec<(String, Resolved)>> {
    Ok(view.resolve_all(wanted)?.into_iter().collect())
}

/// A CI job's identity, from its environment.
struct Workload {
    id: uuid::Uuid,
    sealing: veil_core::SealingKey,
    oidc_token: String,
    server: String,
}

impl Workload {
    fn from_env() -> Result<Option<Self>> {
        let (Ok(id), Ok(key), Ok(oidc_token), Ok(server)) = (
            std::env::var("VEIL_WORKLOAD"),
            std::env::var("VEIL_WORKLOAD_KEY"),
            std::env::var("VEIL_ID_TOKEN"),
            std::env::var("VEIL_SERVER"),
        ) else {
            return Ok(None);
        };
        Ok(Some(Self {
            id: id.parse().context("VEIL_WORKLOAD is not an id")?,
            sealing: veil_core::SealingKey::from_base64(&key)
                .context("VEIL_WORKLOAD_KEY is not a workload key")?,
            oidc_token,
            server,
        }))
    }
}

/// Serves the values through a named pipe that disappears after `reads` reads. The content is
/// JSON for a `.json` path, the bare value when there is exactly one value and the path is not
/// `.env`, and `NAME=value` lines otherwise.
#[cfg(unix)]
fn serve(path: &str, variables: &[(String, String)], reads: usize) -> Result<std::path::PathBuf> {
    use std::io::Write as _;
    use std::os::unix::fs::PermissionsExt as _;

    let target = std::path::PathBuf::from(path);
    if target.exists() {
        bail!("refusing to replace {path}; remove it first");
    }
    let content = if path.ends_with(".json") {
        serde_json::to_string_pretty(
            &variables
                .iter()
                .map(|(name, value)| (name.clone(), value.clone()))
                .collect::<BTreeMap<_, _>>(),
        )
        .context("cannot encode the mounted values")?
    } else if variables.len() == 1 && !path.ends_with(".env") {
        variables[0].1.clone()
    } else {
        variables
            .iter()
            .map(|(name, value)| format!("{name}={value}\n"))
            .collect()
    };
    nix::unistd::mkfifo(&target, nix::sys::stat::Mode::from_bits_truncate(0o600))
        .with_context(|| format!("cannot create a pipe at {path}"))?;
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600))?;

    let served = target.clone();
    std::thread::spawn(move || {
        for read in 1..=reads {
            // Opening blocks until a reader opens the other end.
            let Ok(mut file) = std::fs::OpenOptions::new().write(true).open(&served) else {
                return;
            };
            // This reader holds this pipe now. Give the path a fresh pipe for the next reader,
            // or none after the last, so a reader that has not closed yet cannot take another
            // reader's payload.
            let _ = std::fs::remove_file(&served);
            if read < reads
                && nix::unistd::mkfifo(&served, nix::sys::stat::Mode::from_bits_truncate(0o600))
                    .is_err()
            {
                return;
            }
            let _ = file.write_all(content.as_bytes());
        }
    });
    Ok(target)
}

#[cfg(not(unix))]
fn serve(
    _path: &str,
    _variables: &[(String, String)],
    _reads: usize,
) -> Result<std::path::PathBuf> {
    bail!("mounting needs a Unix named pipe")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_selects_bound_names_and_references() {
        let declaration = VeilToml {
            vault: None,
            env: BTreeMap::from([
                ("DB".to_owned(), "veil://api/postgres/password".to_owned()),
                (
                    "TG".to_owned(),
                    "veil://example/demo-service/password".to_owned(),
                ),
            ]),
        };
        let all = select(Some(&declaration), &[]).expect("all");
        assert_eq!(all.len(), 2);
        let some = select(
            Some(&declaration),
            &[
                "DB".to_owned(),
                "veil://example/demo-service/password".to_owned(),
            ],
        )
        .expect("some");
        assert_eq!(some.keys().collect::<Vec<_>>(), vec!["DB", "TG"]);
        let unbound = select(None, &["veil://admin/root-key/private_key".to_owned()]).expect("one");
        assert_eq!(
            unbound.keys().collect::<Vec<_>>(),
            vec!["ROOT_KEY_PRIVATE_KEY"]
        );
        assert!(select(None, &[]).is_err());
    }
}
