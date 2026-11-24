//! `veil bitwarden`: let the official Bitwarden clients see one Vault.

use anyhow::{Context, Result};
use uuid::Uuid;
use veil_core::{Key, MasterPassword};
use veil_proto::EnableBitwardenRequest;

use crate::{client::Client, commands::login::password, kdf, vaults::Opened};

/// What `veil bitwarden` was asked to do.
pub enum Action {
    /// Serve one Vault to Bitwarden clients.
    Enable {
        /// The Vault.
        vault: String,
    },
    /// Show which Vault Bitwarden clients see.
    Status,
    /// Stop serving Bitwarden clients.
    Disable,
    /// Require an authenticator code at every Bitwarden login.
    TwoStepEnable {
        /// A base32 secret to use instead of a new one.
        secret: Option<String>,
        /// The current code, instead of a prompt.
        code: Option<String>,
    },
    /// Stop requiring an authenticator code.
    TwoStepDisable,
}

/// Runs `veil bitwarden`.
pub fn run(action: Action, json: bool) -> Result<()> {
    let opened = Opened::load_owner()?;
    let bearer = opened.state.require_session()?;
    match action {
        Action::Enable { vault } => {
            let account_key = opened.reader.account_key()?.clone();
            let target = opened.view.vault(&vault)?;
            let (master, account_keys) =
                confirm_password(&opened.client, &opened.state.email, &account_key)?;
            let request = request(
                &master,
                &account_key,
                &account_keys,
                target.row.id,
                &target.key,
            )?;
            opened
                .client
                .enable_bitwarden(&bearer, &request)
                .map_err(anyhow::Error::from)?;
            if json {
                println!(
                    "{}",
                    serde_json::json!({ "vault": vault, "server": opened.state.server })
                );
            } else {
                crate::ui::success(format!(
                    "Bitwarden clients now see the Vault {vault}, and only it"
                ));
                crate::ui::notice(
                    "info",
                    "in the extension or app, choose a self-hosted server and use your email and master password",
                );
                crate::ui::notice(
                    "warning",
                    "the clients require HTTPS; serve veild behind TLS",
                );
            }
        }
        Action::Status => {
            let status = opened
                .client
                .bitwarden(&bearer)
                .map_err(anyhow::Error::from)?;
            let name = status.as_ref().and_then(|status| {
                opened
                    .view
                    .vaults()
                    .iter()
                    .find(|vault| vault.row.id == status.vault_id)
                    .map(|vault| vault.name.clone())
            });
            let two_step = status.as_ref().is_some_and(|status| status.two_step);
            if json {
                println!(
                    "{}",
                    serde_json::json!({ "vault": name, "two_step": two_step })
                );
            } else {
                match name {
                    Some(name) => {
                        println!("Bitwarden clients see the Vault {}", crate::ui::safe(&name));
                        if two_step {
                            println!("Two-step login: on (authenticator app)");
                        } else {
                            println!(
                                "Two-step login: off; turn it on with `veil bitwarden two-step enable`"
                            );
                        }
                    }
                    None => println!("Bitwarden clients are not enabled"),
                }
            }
        }
        Action::TwoStepEnable { secret, code } => {
            let secret = secret.unwrap_or_else(new_secret);
            let code = match code {
                Some(code) => code,
                None => {
                    // Refuse before showing a secret that could then never be confirmed.
                    crate::ui::require_input(
                        "Supply --secret and --code, or use an interactive terminal to set up the authenticator.",
                    )?;
                    show_secret(&opened.state.email, &secret)?;
                    prompt_code()?
                }
            };
            opened
                .client
                .enable_two_step(
                    &bearer,
                    &veil_proto::EnableTwoStepRequest {
                        secret,
                        code: code.trim().to_owned(),
                    },
                )
                .map_err(anyhow::Error::from)
                .context("two-step login was not turned on")?;
            if json {
                println!("{}", serde_json::json!({ "two_step": true }));
            } else {
                crate::ui::success("Bitwarden logins now need a code from the authenticator app");
                crate::ui::notice(
                    "warning",
                    "keep the secret somewhere safe: losing the app means `veil bitwarden two-step disable` from a signed-in machine",
                );
            }
        }
        Action::TwoStepDisable => {
            opened
                .client
                .disable_two_step(&bearer)
                .map_err(anyhow::Error::from)?;
            if json {
                println!("{}", serde_json::json!({ "two_step": false }));
            } else {
                crate::ui::success("Bitwarden logins need only the master password again");
            }
        }
        Action::Disable => {
            opened
                .client
                .disable_bitwarden(&bearer)
                .map_err(anyhow::Error::from)?;
            if json {
                println!("{}", serde_json::json!({ "disabled": true }));
            } else {
                crate::ui::success("Bitwarden clients are signed out and can no longer log in");
            }
        }
    }
    Ok(())
}

/// A new 160-bit secret, base32 without padding, the size RFC 4226 recommends.
fn new_secret() -> String {
    use rand_core::{OsRng, RngCore as _};
    let mut bytes = [0u8; 20];
    OsRng.fill_bytes(&mut bytes);
    data_encoding::BASE32_NOPAD.encode(&bytes)
}

/// Shows the secret as an `otpauth://` QR code for the authenticator app, and as text.
fn show_secret(email: &str, secret: &str) -> Result<()> {
    let label = format!("Veil:{email}")
        .replace(' ', "%20")
        .replace('@', "%40");
    let uri = format!("otpauth://totp/{label}?secret={secret}&issuer=Veil&digits=6&period=30");
    let code = qrcode::QrCode::new(uri.as_bytes()).context("cannot encode the QR code")?;
    let image = code
        .render::<qrcode::render::unicode::Dense1x2>()
        .quiet_zone(true)
        .build();
    // The secret goes to the terminal only; it is never logged or stored on this machine.
    eprintln!("Scan this with the authenticator app:\n\n{image}\n");
    eprintln!("or enter the secret by hand: {secret}\n");
    Ok(())
}

fn prompt_code() -> Result<String> {
    use std::io::{BufRead as _, Write as _};
    crate::ui::require_input("Pass --code when input cannot be prompted.")?;
    eprint!("Code from the app: ");
    std::io::stderr().flush()?;
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line)?;
    Ok(line)
}

/// Derives the master key from the password and checks it against the service, returning the
/// account's v2 key state.
pub fn confirm_password(
    client: &Client,
    email: &str,
    account_key: &Key,
) -> Result<(MasterPassword, String)> {
    let kdf = kdf::from_wire(client.prelogin(email).map_err(anyhow::Error::from)?);
    let master = MasterPassword::derive(&password()?, email, &kdf)?;
    let response = client
        .login_device(&crate::state::State::require()?, master.auth_hash(), false)
        .map_err(anyhow::Error::from)
        .context("the master password was not accepted")?;
    let unlocked = master
        .unlock(&response.protected_account_key)
        .context("the master password does not open the account key")?;
    if &unlocked != account_key {
        anyhow::bail!("this machine holds a different account key; run `veil login` again");
    }
    Ok((master, response.account_keys))
}

/// The login keys for a Vault whose key is `vault_key`.
pub fn request(
    master: &MasterPassword,
    account_key: &Key,
    account_keys: &str,
    vault_id: Uuid,
    vault_key: &Key,
) -> Result<EnableBitwardenRequest> {
    let keys = veil_core::bitwarden_keys(master, account_key, account_keys, vault_key)?;
    Ok(EnableBitwardenRequest {
        vault_id,
        protected_key: keys.protected_key,
        private_key: keys.private_key,
        public_key: keys.public_key,
        account_keys: keys.account_keys.to_string(),
    })
}
