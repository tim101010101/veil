//! `veil device`: enroll, approve, list, and revoke machines.

use std::collections::BTreeSet;

use anyhow::{Context, Result, bail};
use uuid::Uuid;
use veil_core::DeviceKeys;
use veil_proto::{ApproveDeviceRequest, BeginDeviceEnrollmentRequest};

use crate::{
    client::Client,
    commands::login::hostname,
    project::{self, VeilToml},
    state::State,
    vaults::{self, Opened},
};

/// What `veil device` was asked to do.
pub enum Action {
    /// Start enrolling this machine and wait for approval.
    Add {
        /// Service URL, when this machine has no state yet.
        server: Option<String>,
        /// Sign-in address.
        email: Option<String>,
        /// Code to show; generated when absent.
        code: Option<String>,
        /// Device name; defaults to the hostname.
        name: Option<String>,
    },
    /// Approve a waiting machine from a trusted one.
    Approve {
        /// Code the waiting machine shows.
        code: String,
        /// Vaults to grant; defaults to those this directory's `veil.toml` references.
        vaults: Vec<String>,
    },
    /// Upgrade this machine to account-wide reads using the master password.
    Promote,
    /// List machines.
    List,
    /// Revoke a machine.
    Remove {
        /// Device name or id.
        target: String,
    },
}

/// Runs `veil device`.
pub fn run(action: Action, json: bool) -> Result<()> {
    match action {
        Action::Add {
            server,
            email,
            code,
            name,
        } => add(server, email, code, name, json),
        Action::Approve { code, vaults } => approve(&code, vaults, json),
        Action::List => list(json),
        Action::Promote => crate::commands::login::promote(json),
        Action::Remove { target } => remove(&target, json),
    }
}

fn add(
    server: Option<String>,
    email: Option<String>,
    code: Option<String>,
    name: Option<String>,
    json: bool,
) -> Result<()> {
    if State::load()?.is_some() {
        bail!("this machine is already enrolled");
    }
    let server = server
        .or_else(|| crate::settings::value(crate::settings::Key::Server))
        .context("no service URL; pass --server")?;
    let email = veil_core::normalize_email(
        &email
            .or_else(|| crate::settings::value(crate::settings::Key::Email))
            .context("no email; pass --email")?,
    );
    let code = code.unwrap_or_else(random_code);
    let keys = DeviceKeys::generate();
    let device_id = Uuid::now_v7();
    let client = Client::new(&server);

    client
        .begin_device(&BeginDeviceEnrollmentRequest {
            email: email.clone(),
            code: code.clone(),
            device: veil_proto::DeviceKeys {
                id: device_id,
                name: name.unwrap_or_else(hostname),
                seal_pk: keys.sealing().public(),
                auth_pk: keys.auth_public(),
            },
        })
        .map_err(anyhow::Error::from)?;

    if json {
        eprintln!(
            "{}",
            serde_json::json!({"type": "enrollment", "code": code, "device_id": device_id, "timeout_seconds": 600})
        );
    } else {
        crate::ui::notice(
            "enrollment",
            format!("On a trusted device run: veil device approve {code} --vault <vault>"),
        );
        crate::ui::notice(
            "waiting",
            "Waiting up to ten minutes for approval; Ctrl-C cancels this client. The request expires on the service.",
        );
    }

    let response = poll(&client, &keys, device_id, &code)?;
    State::new(
        &server,
        response.account_id,
        &response.email,
        device_id,
        &keys,
    )
    .save()?;

    if json {
        println!(
            "{}",
            serde_json::json!({ "device_id": device_id, "account_id": response.account_id })
        );
    } else {
        crate::ui::success(format!(
            "approved — this device holds Grants for {} Vaults",
            response.grants.len()
        ));
    }
    Ok(())
}

fn poll(
    client: &Client,
    keys: &DeviceKeys,
    device_id: Uuid,
    code: &str,
) -> Result<veil_proto::EnrollmentResponse> {
    let attempts: u32 = std::env::var("VEIL_ENROLL_ATTEMPTS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(300);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(600);
    for attempt in 0..attempts {
        match client.enrollment(keys, device_id, code) {
            Ok(response) => return Ok(response),
            Err(crate::client::Error::Status { code: 404, .. }) => {}
            Err(error) => return Err(error).context("Enrollment could not continue"),
        }
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() || attempt + 1 == attempts {
            break;
        }
        std::thread::sleep(remaining.min(std::time::Duration::from_secs(2)));
    }
    Err(crate::diagnostic::Failure::new(
        "enrollment_timeout",
        1,
        "Timed out waiting for approval; this machine was not enrolled locally.",
        "Check pending devices from a trusted device before starting a new enrollment.",
    )
    .into())
}

fn approve(code: &str, names: Vec<String>, json: bool) -> Result<()> {
    let opened = Opened::load_owner()?;
    let bearer = opened.state.require_session()?;
    let pending = opened
        .client
        .pending_devices(&bearer)
        .map_err(anyhow::Error::from)?;
    let pending = pending
        .iter()
        .find(|pending| pending.code == code)
        .context("no pending device with that code")?;

    let names = if names.is_empty() {
        declared_vaults()?
    } else {
        names.into_iter().collect()
    };
    let chosen = names
        .iter()
        .map(|name| opened.view.vault(name))
        .collect::<Result<Vec<_>>>()?;
    let grants = vaults::grants_for(&chosen, pending.device.id, &pending.device.seal_pk)?;

    opened
        .client
        .approve_device(&bearer, code, &ApproveDeviceRequest { grants })
        .map_err(anyhow::Error::from)?;

    if json {
        println!(
            "{}",
            serde_json::json!({ "approved": pending.device.id, "vaults": names })
        );
    } else {
        crate::ui::success(format!("approved {}", pending.device.name));
        crate::ui::success(format!(
            "granted {}",
            names.iter().cloned().collect::<Vec<_>>().join(", ")
        ));
    }
    Ok(())
}

/// The Vaults this directory's `veil.toml` references.
fn declared_vaults() -> Result<BTreeSet<String>> {
    let declaration = VeilToml::read(&project::current_dir()?)?
        .context("name the Vaults to grant with --vault, or run this where a veil.toml is")?;
    let names: BTreeSet<String> = declaration
        .references()?
        .into_values()
        .map(|reference| reference.vault)
        .chain(declaration.vault.clone())
        .collect();
    if names.is_empty() {
        bail!("veil.toml references no Vault; name the Vaults to grant with --vault");
    }
    Ok(names)
}

fn list(json: bool) -> Result<()> {
    let state = State::require()?;
    let bearer = state.require_session()?;
    let devices = Client::new(&state.server)
        .devices(&bearer)
        .map_err(anyhow::Error::from)?;

    if json {
        println!("{}", serde_json::to_value(&devices).context("encode")?);
    } else {
        let rows = devices
            .into_iter()
            .map(|device| {
                let status = if device.revoked_at.is_some() {
                    "revoked"
                } else if device.id == state.device_id {
                    "this device"
                } else {
                    "active"
                };
                let scope = if device.owner {
                    "all Vaults"
                } else {
                    "granted Vaults"
                };
                vec![
                    device.id.to_string(),
                    device.name,
                    status.into(),
                    scope.into(),
                ]
            })
            .collect::<Vec<_>>();
        crate::ui::table(
            &["ID", "NAME", "STATUS", "READ SCOPE"],
            &rows,
            "No devices.",
        );
    }
    Ok(())
}

fn remove(target: &str, json: bool) -> Result<()> {
    let state = State::require()?;
    let bearer = state.require_session()?;
    let client = Client::new(&state.server);
    let id = match target.parse::<Uuid>() {
        Ok(id) => id,
        Err(_) => {
            let devices = client.devices(&bearer).map_err(anyhow::Error::from)?;
            let mut matches = devices
                .iter()
                .filter(|device| device.name == target && device.revoked_at.is_none());
            let device = matches
                .next()
                .with_context(|| format!("no active device named {target}"))?;
            if matches.next().is_some() {
                bail!("several devices are named {target}; pass the id from `veil device list`");
            }
            device.id
        }
    };
    if id == state.device_id {
        bail!("this is the machine you are on; revoke it from another one");
    }
    client
        .revoke_device(&bearer, id)
        .map_err(anyhow::Error::from)?;
    if json {
        println!("{}", serde_json::json!({ "revoked": id }));
    } else {
        crate::ui::success(format!("revoked {id}"));
        crate::ui::notice(
            "warning",
            "it keeps any values it already cached; new reads are refused",
        );
        crate::ui::notice(
            "warning",
            "the Vaults it could read get a new key on your next write to them",
        );
    }
    Ok(())
}

fn random_code() -> String {
    use rand_core::RngCore;
    let mut bytes = [0u8; 4];
    rand_core::OsRng.fill_bytes(&mut bytes);
    let value = u32::from_be_bytes(bytes) % 1_000_000;
    format!("{value:06}")
}
