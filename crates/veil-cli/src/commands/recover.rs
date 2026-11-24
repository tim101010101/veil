//! `veil recover`: rebuild access from the recovery code on a machine with no device.
//!
//! The code unwraps the account key, so every Vault opens again through it; nothing is
//! re-keyed. Revoke the machines you lost afterwards.

use anyhow::{Context, Result, bail};
use uuid::Uuid;
use veil_core::{DeviceKeys, MasterPassword, RecoveryCode};
use veil_proto::{CreateRecoveryRequest, UpdateAccountRequest};

use crate::{
    client::Client,
    commands::login::hostname,
    kdf,
    state::{State, StoredSession},
};

/// What `veil recover` was asked to do.
pub struct Options {
    /// Service URL.
    pub server: Option<String>,
    /// Sign-in address.
    pub email: Option<String>,
    pub json: bool,
}

/// Runs `veil recover`.
pub fn run(options: Options) -> Result<()> {
    if State::load()?.is_some() {
        bail!("this machine already has a device; use `veil login` instead");
    }
    let server = options
        .server
        .or_else(|| crate::settings::value(crate::settings::Key::Server))
        .context("no service URL; pass --server")?;
    let email = veil_core::normalize_email(
        &options
            .email
            .or_else(|| crate::settings::value(crate::settings::Key::Email))
            .context("no email; pass --email")?,
    );
    let code = recovery_code()?;
    let password = new_password()?;
    let client = Client::new(&server);

    let keys = DeviceKeys::generate();
    let response = client
        .recover(&CreateRecoveryRequest {
            email: email.clone(),
            recovery_proof: code.verifier(&email)?,
            device: veil_proto::DeviceKeys {
                id: Uuid::now_v7(),
                name: hostname(),
                seal_pk: keys.sealing().public(),
                auth_pk: keys.auth_public(),
            },
        })
        .map_err(anyhow::Error::from)?;
    let account_key = code
        .unwrap(&email, &response.recovery_wrap)
        .context("the recovery code does not open the account key")?;

    let kdf = veil_core::Kdf::default();
    let master = MasterPassword::derive(&password, &email, &kdf)?;
    let mut state = State::new(
        &server,
        response.account_id,
        &email,
        response.device.id,
        &keys,
    );
    state.set_account_key(&account_key);
    state.session = Some(StoredSession {
        token: response.session.token.clone(),
        expires_at: response.session.expires_at,
    });

    // The Bitwarden login wraps its Vault key with the master key: follow the new password.
    let bitwarden_protected_key = match client
        .bitwarden(&response.session.token)
        .map_err(anyhow::Error::from)?
    {
        Some(status) => {
            let document = client
                .sync_bearer(&response.session.token)
                .map_err(anyhow::Error::from)?;
            let wrap = document
                .vaults
                .iter()
                .find(|vault| vault.id == status.vault_id)
                .and_then(|vault| vault.account_key_wrap.clone())
                .context("the Vault Bitwarden clients see is missing")?;
            Some(master.protect(&veil_core::unwrap_key(&account_key, &wrap)?)?)
        }
        None => None,
    };
    client
        .update_account(
            &response.session.token,
            &UpdateAccountRequest {
                kdf: kdf::to_wire(kdf),
                auth_hash: master.auth_hash().to_owned(),
                protected_account_key: master.protect(&account_key)?,
                bitwarden_protected_key,
            },
        )
        .map_err(anyhow::Error::from)?;
    state.save()?;

    if options.json {
        println!(
            "{}",
            serde_json::json!({"recovered": true, "device_id": state.device_id})
        );
    } else {
        crate::ui::success(format!(
            "Account recovered on {server}; new master password set"
        ));
    }
    crate::ui::notice(
        "warning",
        "Revoke lost devices: veil device list, then veil device remove <id>",
    );
    Ok(())
}

fn recovery_code() -> Result<RecoveryCode> {
    let raw = match std::env::var("VEIL_RECOVERY_CODE") {
        Ok(value) if !value.trim().is_empty() => value,
        _ => crate::ui::secret(
            "Recovery code",
            "Provide VEIL_RECOVERY_CODE through a protected environment, or use an interactive terminal.",
        )?,
    };
    RecoveryCode::parse(&raw).context("that is not a recovery code")
}

fn new_password() -> Result<String> {
    if let Ok(value) = std::env::var("VEIL_PASSWORD")
        && !value.is_empty()
    {
        return Ok(value);
    }
    let first = crate::ui::secret(
        "New master password",
        "Provide VEIL_PASSWORD through a protected environment, or use an interactive terminal.",
    )?;
    let second = crate::ui::secret(
        "Repeat",
        "Repeat the new password in an interactive terminal.",
    )?;
    if first != second {
        bail!("the passwords differ");
    }
    Ok(first)
}
