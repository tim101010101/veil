//! Where the keys live between invocations: the login keychain on macOS, a `0600` file
//! elsewhere (no resident process holds them).
//!
//! `VEIL_KEYSTORE=keychain` or `VEIL_KEYSTORE=file` picks one explicitly; a headless host or a
//! test uses the file.

use std::{fs, path::PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

/// The secrets of one machine.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Secrets {
    /// Ed25519 seed that signs this device's requests, base64url.
    pub device_signing_key: String,
    /// RSA sealing key that Vault keys are shared to, PKCS#8 base64.
    pub device_sealing_key: String,
    /// The unwrapped account key, on Owner machines.
    #[serde(default)]
    pub account_key: Option<String>,
}

/// A place to keep [`Secrets`].
#[derive(Debug, Clone)]
pub enum Keystore {
    /// `$VEIL_HOME/keys.json`, mode `0600`.
    File(PathBuf),
    /// A generic password in the login keychain, one per `$VEIL_HOME`.
    #[cfg(target_os = "macos")]
    Keychain {
        /// Always `veil`.
        service: String,
        /// The `$VEIL_HOME` path, so separate homes keep separate keys.
        account: String,
    },
}

/// Records which build last saved the keychain, beside the state (macOS only).
#[cfg(target_os = "macos")]
const BUILD_MARKER: &str = "keychain-build";

/// This binary's version and, when the build recorded it, its commit.
#[cfg(target_os = "macos")]
fn build_id() -> String {
    match option_env!("VEIL_BUILD_COMMIT") {
        Some(commit) => format!("{}+{commit}", env!("CARGO_PKG_VERSION")),
        None => env!("CARGO_PKG_VERSION").to_owned(),
    }
}

impl Keystore {
    /// The keystore for a `$VEIL_HOME`.
    pub fn for_home(home: &std::path::Path) -> Result<Self> {
        let choice = crate::settings::value(crate::settings::Key::Keystore).unwrap_or_default();
        match choice.as_str() {
            "file" => Ok(Self::File(home.join("keys.json"))),
            #[cfg(target_os = "macos")]
            "" | "keychain" => Ok(Self::Keychain {
                service: "veil".to_owned(),
                account: home.display().to_string(),
            }),
            #[cfg(not(target_os = "macos"))]
            "" => Ok(Self::File(home.join("keys.json"))),
            other => bail!(
                "keystore {other:?} (VEIL_KEYSTORE or `keystore` in config.toml) is not `keychain` or `file`"
            ),
        }
    }

    /// Where the keys are, for messages.
    pub fn describe(&self) -> String {
        match self {
            Self::File(path) => format!("{} (0600)", path.display()),
            #[cfg(target_os = "macos")]
            Self::Keychain { .. } => "the login keychain".to_owned(),
        }
    }

    /// Reads the secrets, or `None` when there are none.
    pub fn load(&self) -> Result<Option<Secrets>> {
        let raw = match self {
            Self::File(path) => match fs::read(path) {
                Ok(raw) => raw,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                Err(error) => {
                    return Err(error).with_context(|| format!("cannot read {}", path.display()));
                }
            },
            #[cfg(target_os = "macos")]
            Self::Keychain { service, account } => {
                let _interaction = if crate::ui::interactive() {
                    None
                } else {
                    Some(security_framework::os::macos::keychain::SecKeychain::disable_user_interaction()
                        .context("cannot disable keychain prompts")?)
                };
                let marker = std::path::Path::new(account).join(BUILD_MARKER);
                let first_read = fs::read_to_string(&marker).ok() != Some(build_id());
                if first_read && crate::ui::interactive() {
                    // macOS ties keychain access to the exact build of an unsigned binary, so a
                    // new build asks once. Saying so keeps the prompt from looking like an attack.
                    crate::ui::notice(
                        "keychain",
                        "This build is new to the keychain. If macOS asks, approve access only if you trust this build.",
                    );
                }
                match security_framework::passwords::get_generic_password(service, account) {
                    Ok(raw) => raw,
                    Err(error) if error.code() == -25300 => return Ok(None),
                    Err(error) if error.code() == -25308 => return Err(crate::diagnostic::Failure::new(
                        "keychain_interaction_required", 4, "The login keychain requires interactive authorization.",
                        "Unlock the keychain and authorize this trusted build from an interactive terminal before retrying.").into()),
                    Err(error) => {
                        return Err(anyhow::anyhow!("{error}"))
                            .context("cannot read the keys from the login keychain");
                    }
                }
            }
        };
        serde_json::from_slice(&raw)
            .map(Some)
            .context("the stored keys are damaged")
    }

    /// Writes the secrets.
    pub fn save(&self, secrets: &Secrets) -> Result<()> {
        let raw = serde_json::to_vec(secrets).context("cannot encode the keys")?;
        match self {
            Self::File(path) => {
                if let Some(parent) = path.parent() {
                    fs::create_dir_all(parent)
                        .with_context(|| format!("cannot create {}", parent.display()))?;
                }
                crate::state::write_private(path, &raw)
            }
            #[cfg(target_os = "macos")]
            Self::Keychain { service, account } => {
                let _interaction = if crate::ui::interactive() {
                    None
                } else {
                    Some(security_framework::os::macos::keychain::SecKeychain::disable_user_interaction()
                        .context("cannot disable keychain prompts")?)
                };
                security_framework::passwords::set_generic_password(service, account, &raw)
                    .map_err(|error| {
                        if error.code() == -25308 {
                            anyhow::Error::from(crate::diagnostic::Failure::new("keychain_interaction_required", 4,
                                "The login keychain requires interactive authorization.",
                                "Authorize this trusted build from an interactive terminal before retrying."))
                        } else { anyhow::anyhow!("{error}") }
                    })
                    .context("cannot write the keys to the login keychain")?;
                let _ = fs::write(std::path::Path::new(account).join(BUILD_MARKER), build_id());
                Ok(())
            }
        }
    }
}
