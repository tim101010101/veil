//! `veil workload`: CI identities that read through OIDC.

use std::collections::BTreeMap;

use anyhow::{Context, Result, bail};
use uuid::Uuid;
use veil_core::SealingKey;
use veil_proto::{CreateWorkloadRequest, TrustPolicy};

use crate::{
    client::Client,
    project::{self, VeilToml},
    state::State,
    vaults::{self, Opened},
};

/// What `veil workload` was asked to do.
pub enum Action {
    /// Create a workload that reads some Vaults.
    Add {
        /// Workload name.
        name: String,
        /// OIDC issuer.
        issuer: String,
        /// Expected audience.
        audience: String,
        /// Claims that must match, as `key=value`.
        claims: Vec<String>,
        /// Vaults to grant; defaults to those this directory's `veil.toml` references.
        vaults: Vec<String>,
    },
    /// List workloads.
    List,
    /// Revoke a workload.
    Remove {
        /// Workload id.
        id: Uuid,
    },
}

/// Runs `veil workload`.
pub fn run(action: Action, json: bool) -> Result<()> {
    match action {
        Action::Add {
            name,
            issuer,
            audience,
            claims,
            vaults,
        } => add(&name, &issuer, &audience, &claims, vaults, json),
        Action::List => list(json),
        Action::Remove { id } => remove(id, json),
    }
}

fn add(
    name: &str,
    issuer: &str,
    audience: &str,
    claims: &[String],
    names: Vec<String>,
    json: bool,
) -> Result<()> {
    let opened = Opened::load_owner()?;
    let bearer = opened.state.require_session()?;
    let names = if names.is_empty() {
        let declaration = VeilToml::read(&project::current_dir()?)?
            .context("name the Vaults to grant with --vault, or run this where a veil.toml is")?;
        let mut names: Vec<String> = declaration
            .references()?
            .into_values()
            .map(|reference| reference.vault)
            .collect();
        names.sort();
        names.dedup();
        names
    } else {
        names
    };
    if names.is_empty() {
        bail!("no Vault to grant; pass --vault");
    }
    let chosen = names
        .iter()
        .map(|name| opened.view.vault(name))
        .collect::<Result<Vec<_>>>()?;

    let mut parsed = BTreeMap::new();
    for claim in claims {
        let (key, value) = claim
            .split_once('=')
            .with_context(|| format!("{claim:?} is not key=value"))?;
        parsed.insert(key.to_owned(), value.to_owned());
    }

    let sealing = SealingKey::generate();
    let workload = Uuid::now_v7();
    opened
        .client
        .create_workload(
            &bearer,
            &CreateWorkloadRequest {
                id: workload,
                name: name.to_owned(),
                trust_policy: TrustPolicy {
                    issuer: issuer.to_owned(),
                    audience: audience.to_owned(),
                    claims: parsed,
                },
                seal_pk: sealing.public(),
                grants: vaults::grants_for(&chosen, workload, &sealing.public())?,
            },
        )
        .map_err(anyhow::Error::from)?;

    let key = sealing.to_base64();
    if json {
        println!(
            "{}",
            serde_json::json!({ "workload": workload, "key": key, "vaults": names })
        );
    } else {
        crate::ui::success(format!(
            "workload {name} ({workload}) reads {}",
            names.join(", ")
        ));
        println!();
        println!("Set these in the CI job, the key as a masked variable:");
        println!("  VEIL_SERVER={}", crate::ui::safe(&opened.state.server));
        println!("  VEIL_WORKLOAD={workload}");
        println!("  VEIL_WORKLOAD_KEY={key}");
        println!(
            "  VEIL_ID_TOKEN is issued by the platform (audience: {})",
            crate::ui::safe(audience)
        );
        println!();
        println!(
            "The key alone is useless: the service releases ciphertext only after OIDC checks out."
        );
    }
    Ok(())
}

fn list(json: bool) -> Result<()> {
    let state = State::require()?;
    let bearer = state.require_session()?;
    let workloads = Client::new(&state.server)
        .workloads(&bearer)
        .map_err(anyhow::Error::from)?;
    if json {
        println!("{}", serde_json::to_value(&workloads).context("encode")?);
    } else {
        let rows = workloads
            .into_iter()
            .map(|workload| {
                let status = if workload.revoked_at.is_some() {
                    "revoked"
                } else {
                    "active"
                };
                vec![workload.id.to_string(), workload.name, status.into()]
            })
            .collect::<Vec<_>>();
        crate::ui::table(
            &["ID", "NAME", "STATUS"],
            &rows,
            "No workloads. Run: veil workload add --help",
        );
    }
    Ok(())
}

fn remove(id: Uuid, json: bool) -> Result<()> {
    let state = State::require()?;
    let bearer = state.require_session()?;
    Client::new(&state.server)
        .revoke_workload(&bearer, id)
        .map_err(anyhow::Error::from)?;
    if json {
        println!("{}", serde_json::json!({ "revoked": id }));
    } else {
        crate::ui::success(format!("revoked {id}"));
        crate::ui::notice(
            "warning",
            "the Vaults it could read get a new key on your next write to them",
        );
    }
    Ok(())
}
