//! `veil login`: create the account, or start a session on this machine.

use anyhow::{Context, Result, bail};
use uuid::Uuid;
use veil_core::{DeviceKeys, MasterPassword, NewAccount};
use veil_proto::CreateAccountRequest;

use crate::{
    client::Client,
    kdf,
    state::{State, StoredSession},
};

/// What `veil login` was asked to do.
pub struct Options {
    /// Service URL.
    pub server: Option<String>,
    /// Sign-in address.
    pub email: Option<String>,
    /// Create the account instead of signing in.
    pub create: bool,
    /// Machine-readable output.
    pub json: bool,
}

/// Runs `veil login`.
pub fn run(options: Options) -> Result<()> {
    let existing = State::load()?;
    let (server, email) = target(options.server, options.email, existing.as_ref())?;
    if !options.create
        && existing
            .as_ref()
            .is_none_or(|state| state.pending_registration)
    {
        crate::ui::notice(
            "warning",
            "Registering a personal device: access to all existing and future Vaults.",
        );
    }
    let password = password()?;
    let client = Client::new(&server);

    if options.create {
        if existing
            .as_ref()
            .is_some_and(|state| !state.pending_registration)
        {
            bail!("this machine already has a device; use `veil login` without --create");
        }
        create(&client, &server, &email, &password, options.json)
    } else {
        let state = match existing {
            Some(state) => state,
            None => {
                let mut state = State::new(
                    &server,
                    Uuid::nil(),
                    &email,
                    Uuid::now_v7(),
                    &DeviceKeys::generate(),
                );
                state.pending_registration = true;
                state.save()?;
                state
            }
        };
        sign_in(&client, &email, &password, state, false, options.json)
    }
}

fn target(
    server: Option<String>,
    email: Option<String>,
    existing: Option<&State>,
) -> Result<(String, String)> {
    let server = server
        .or_else(|| crate::settings::value(crate::settings::Key::Server))
        .or_else(|| existing.map(|state| state.server.clone()))
        .context("no service URL; set server in config.toml or pass --server")?;
    let email = veil_core::normalize_email(
        &email
            .or_else(|| crate::settings::value(crate::settings::Key::Email))
            .or_else(|| existing.map(|state| state.email.clone()))
            .context("no email; set email in config.toml or pass --email")?,
    );
    if let Some(state) = existing {
        anyhow::ensure!(
            server.trim_end_matches('/') == state.server.trim_end_matches('/')
                && email == veil_core::normalize_email(&state.email),
            "login target conflicts with this device's account; use a separate VEIL_HOME"
        );
    }
    Ok((server, email))
}

pub fn promote(json: bool) -> Result<()> {
    let state = State::require()?;
    let (server, email) = target(None, None, Some(&state))?;
    crate::ui::notice(
        "warning",
        "Promoting this device: access to all existing and future Vaults.",
    );
    sign_in(
        &Client::new(&server),
        &email,
        &password()?,
        state,
        true,
        json,
    )
}

fn create(client: &Client, server: &str, email: &str, password: &str, json: bool) -> Result<()> {
    let kdf = veil_core::Kdf::default();
    let account = NewAccount::create(email, password, &kdf)?;
    let keys = DeviceKeys::generate();
    let device_id = Uuid::now_v7();
    let response = client
        .create_account(&CreateAccountRequest {
            id: Uuid::now_v7(),
            email: email.to_owned(),
            kdf: kdf::to_wire(kdf),
            auth_hash: account.auth_hash.clone(),
            protected_account_key: account.protected_account_key.clone(),
            account_keys: account.account_keys.clone(),
            recovery_wrap: account.recovery_wrap.clone(),
            recovery_verifier: account.recovery_verifier.clone(),
            device: veil_proto::DeviceKeys {
                id: device_id,
                name: hostname(),
                seal_pk: keys.sealing().public(),
                auth_pk: keys.auth_public(),
            },
        })
        .map_err(anyhow::Error::from)?;

    let mut state = State::new(
        server,
        response.account.id,
        &response.account.email,
        response.device.id,
        &keys,
    );
    state.set_account_key(&account.account_key);
    state.session = Some(StoredSession {
        token: response.session.token,
        expires_at: response.session.expires_at,
    });
    state.save()?;

    if json {
        println!(
            "{}",
            serde_json::json!({
                "account_id": state.account_id,
                "device_id": state.device_id,
                "recovery_code": account.recovery_code.as_str(),
            })
        );
    } else {
        crate::ui::success(format!("account created on {server}"));
        crate::ui::success(format!("device registered: {}", hostname()));
        println!();
        println!("Recovery code (shown once):");
        println!("  {}", account.recovery_code.as_str());
        println!();
        println!("Save it offline. Losing it and every device loses the account.");
    }
    Ok(())
}

fn sign_in(
    client: &Client,
    email: &str,
    password: &str,
    mut state: State,
    promote: bool,
    json: bool,
) -> Result<()> {
    let kdf = kdf::from_wire(client.prelogin(email).map_err(anyhow::Error::from)?);
    let master = MasterPassword::derive(password, email, &kdf)?;
    let response = client
        .login_device(&state, master.auth_hash(), promote)
        .map_err(anyhow::Error::from)?;
    let account_key = master
        .unlock(&response.protected_account_key)
        .context("cannot unlock the account key; wrong master password?")?;
    veil_core::verify_account_keys(&account_key, &response.account_keys)
        .context("the service returned an account key state this password does not open")?;
    state.set_account_key(&account_key);
    anyhow::ensure!(
        state.pending_registration || state.account_id == response.account.id,
        "the service returned a different account for this device"
    );
    state.account_id = response.account.id;
    state.email = response.account.email;
    state.pending_registration = false;
    state.cache = None;
    state.sync_revision = None;
    state.session = Some(StoredSession {
        token: response.session.token,
        expires_at: response.session.expires_at,
    });
    state.save()?;

    if !response.device.owner {
        crate::ui::notice(
            "warning",
            "this is still a restricted device; ordinary reads use its Grants. Use `veil device promote` for persistent all-Vault access",
        );
    }
    if json {
        println!(
            "{}",
            serde_json::json!({
                "account_id": state.account_id, "email": state.email,
                "device_id": state.device_id, "owner": response.device.owner,
            })
        );
    } else {
        crate::ui::success(format!("Signed in as {}", state.email));
    }
    Ok(())
}

/// The master password, from `VEIL_PASSWORD` or a prompt.
pub fn password() -> Result<String> {
    if let Ok(value) = std::env::var("VEIL_PASSWORD")
        && !value.is_empty()
    {
        return Ok(value);
    }
    crate::ui::secret(
        "Master password",
        "Use an interactive terminal, or provide VEIL_PASSWORD through a protected environment.",
    )
}

/// This machine's name.
pub fn hostname() -> String {
    std::env::var("HOSTNAME")
        .ok()
        .filter(|name| !name.trim().is_empty())
        .or_else(|| std::fs::read_to_string("/etc/hostname").ok())
        .map(|name| name.trim().to_owned())
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| "this machine".to_owned())
}
