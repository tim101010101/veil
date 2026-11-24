//! The one enforced policy: approval per Vault.

use anyhow::Result;

use crate::vaults::Resolved;

/// A delivery a person had to confirm and did not. Exits with code `4`.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct Refused(pub String);

/// A Vault's approval policy, sealed by its key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Policy {
    /// No approval.
    None,
    /// Touch ID at this machine for every delivery.
    Presence,
    /// Approval on another Device (planned, not implemented).
    Device,
}

impl Policy {
    /// Parses a policy name.
    pub fn parse(name: &str) -> Result<Self> {
        match name {
            "none" => Ok(Self::None),
            "presence" => Ok(Self::Presence),
            "device" => Ok(Self::Device),
            other => {
                anyhow::bail!("{other:?} is not an approval policy: none, presence, or device")
            }
        }
    }

    /// The policy's name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Presence => "presence",
            Self::Device => "device",
        }
    }
}

/// Asks for the approvals the Vaults of `values` require before `command` receives them. The
/// prompt shows the full command; nothing is released when a person does not confirm.
pub fn require(values: &[&Resolved], command: &str) -> Result<()> {
    let mut vaults: Vec<&str> = Vec::new();
    for value in values {
        match value.policy {
            Policy::None => {}
            Policy::Presence => {
                if !vaults.contains(&value.vault_name.as_str()) {
                    vaults.push(&value.vault_name);
                }
            }
            Policy::Device => {
                return Err(Refused(format!(
                    "{} requires approval on another Device, which this version cannot ask for",
                    value.vault_name
                ))
                .into());
            }
        }
    }
    if vaults.is_empty() {
        return Ok(());
    }
    let names = vaults.join(", ");
    let reason = format!("release values from {names} to: {command}");
    crate::ui::notice(
        "approval",
        format!("Approve releasing values from {names} to `{command}`"),
    );
    match veil_presence::confirm(&reason) {
        veil_presence::Presence::Approved => Ok(()),
        veil_presence::Presence::Denied => {
            Err(Refused(format!("{names}: delivery not approved; nothing was released")).into())
        }
        veil_presence::Presence::Unavailable(why) => Err(Refused(format!(
            "{names} requires Touch ID for every delivery, and it is unavailable here ({why}); nothing was released"
        ))
        .into()),
    }
}
