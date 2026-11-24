//! `veil vault`: list or create Vaults, and set their approval policy.

use anyhow::{Result, bail};
use veil_proto::UpdateVaultRequest;

use crate::{
    approval::Policy,
    vaults::{Opened, Writer},
};

/// What `veil vault` was asked to do.
pub enum Action {
    /// List the Vaults this machine can open.
    List,
    /// Create an empty Vault.
    Create {
        /// Vault name.
        name: String,
    },
    /// Set a Vault's approval policy.
    Policy {
        /// Vault name.
        name: String,
        /// `none` or `presence`.
        approval: String,
    },
}

/// Runs `veil vault`.
pub fn run(action: Action, json: bool) -> Result<()> {
    let opened = if matches!(&action, Action::List) {
        Opened::load()?
    } else {
        Opened::load_owner()?
    };
    match action {
        Action::List => {
            let rows: Vec<_> = opened
                .view
                .vaults()
                .iter()
                .map(|vault| {
                    (
                        vault.name.clone(),
                        vault.policy,
                        vault.row.key_generation,
                        opened.view.items_in(vault.row.id).count(),
                    )
                })
                .collect();
            if json {
                let rows: Vec<_> = rows
                    .iter()
                    .map(|(name, policy, generation, items)| {
                        serde_json::json!({
                            "name": name,
                            "approval": policy.as_str(),
                            "key_generation": generation,
                            "items": items,
                        })
                    })
                    .collect();
                println!("{}", serde_json::json!({ "vaults": rows }));
            } else {
                crate::ui::table(
                    &["VAULT", "APPROVAL", "ITEMS"],
                    &rows
                        .into_iter()
                        .map(|(name, policy, _, items)| {
                            vec![name, policy.as_str().into(), items.to_string()]
                        })
                        .collect::<Vec<_>>(),
                    "No Vaults. Run: veil vault create <name>",
                );
            }
        }
        Action::Create { name } => {
            if opened.view.vault(&name).is_ok() {
                bail!("a Vault named {name} already exists");
            }
            let (id, _) = Writer::new(&opened)?.create_vault(&name, &[])?;
            if json {
                println!("{}", serde_json::json!({ "vault": name, "id": id }));
            } else {
                crate::ui::success(format!("created Vault {name}"));
            }
        }
        Action::Policy { name, approval } => {
            let policy = Policy::parse(&approval)?;
            if policy == Policy::Device {
                bail!(
                    "`device` approval (a split Vault key released by another Device) is not available yet"
                );
            }
            let bearer = opened.state.require_session()?;
            let vault = opened.view.vault(&name)?;
            opened
                .client
                .update_vault(
                    &bearer,
                    vault.row.id,
                    &UpdateVaultRequest {
                        expected_revision: vault.row.revision,
                        name: veil_core::seal_text(&vault.key, &vault.name)?,
                        policy: Some(veil_core::seal_text(&vault.key, policy.as_str())?),
                    },
                )
                .map_err(anyhow::Error::from)?;
            if json {
                println!(
                    "{}",
                    serde_json::json!({ "vault": name, "approval": policy.as_str() })
                );
            } else {
                match policy {
                    Policy::Presence => crate::ui::success(format!(
                        "{name} requires presence approval for every delivery"
                    )),
                    _ => crate::ui::success(format!("{name} needs no approval")),
                }
            }
        }
    }
    Ok(())
}
