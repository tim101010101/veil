//! Local state: the session, the sync cache, and (through the keystore) the keys.
//!
//! `$VEIL_HOME/state.json` (mode 0600) holds everything but the keys, which live in the
//! [`Keystore`]: the login keychain on macOS, `keys.json` (0600) on a headless host.

use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use veil_core::{DeviceKeys, Key};
use veil_proto::SyncDocument;

use crate::keystore::{Keystore, Secrets};

/// How long a cached document may authorise a read while offline.
pub const OFFLINE_TTL_SECONDS: u64 = 15 * 60;

/// Everything the CLI remembers between invocations.
#[derive(Debug, Serialize, Deserialize)]
pub struct State {
    /// Base URL of the service.
    pub server: String,
    /// Account the device belongs to.
    pub account_id: Uuid,
    /// Sign-in address.
    pub email: String,
    /// This machine's device id.
    pub device_id: Uuid,
    #[serde(default)]
    pub pending_registration: bool,
    /// Ed25519 seed that signs this device's requests, base64url. Kept in the keystore.
    #[serde(skip)]
    pub device_signing_key: String,
    /// RSA sealing key that Vault keys are shared to, PKCS#8 base64. Kept in the keystore.
    #[serde(skip)]
    pub device_sealing_key: String,
    /// The unwrapped account key (SDK base64), kept in the keystore. Present on Owner devices;
    /// an approved Device holds Grants only, until someone signs in on it with the master
    /// password.
    #[serde(skip)]
    pub account_key: Option<String>,
    /// The owner's session, when one is live.
    pub session: Option<StoredSession>,
    /// The last sync document and when it was fetched.
    pub cache: Option<Cache>,
    #[serde(default)]
    pub sync_revision: Option<u64>,
    /// Delivery events that could not be reported yet.
    #[serde(default)]
    pub pending_audit: Vec<veil_proto::AuditEventInput>,
}

/// A session token and its expiry.
#[derive(Debug, Serialize, Deserialize)]
pub struct StoredSession {
    /// Bearer token.
    pub token: String,
    /// Unix seconds.
    pub expires_at: u64,
}

/// A cached sync document.
#[derive(Debug, Serialize, Deserialize)]
pub struct Cache {
    /// Unix seconds.
    pub at: u64,
    /// The document.
    pub document: SyncDocument,
    #[serde(default)]
    pub device_scoped: bool,
}

impl State {
    /// Reads the state file, or `None` when this machine has never signed in.
    pub fn load() -> Result<Option<Self>> {
        let path = state_path()?;
        let mut state: Self = match fs::read_to_string(&path) {
            Ok(raw) => serde_json::from_str(&raw).map_err(|error| {
                crate::diagnostic::Failure::new(
                    "state_invalid",
                    1,
                    format!(
                        "Cannot parse {} at line {}, column {}.",
                        path.display(),
                        error.line(),
                        error.column()
                    ),
                    "Preserve this state and its keys before attempting recovery. Run: veil doctor",
                )
            })?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(error).with_context(|| format!("cannot read {}", path.display()));
            }
        };
        let keystore = Keystore::for_home(&home()?)?;
        let secrets = keystore.load()?.with_context(|| {
            format!(
                "{} exists but {} holds no keys for it; enroll this machine again",
                path.display(),
                keystore.describe()
            )
        })?;
        state.device_signing_key = secrets.device_signing_key;
        state.device_sealing_key = secrets.device_sealing_key;
        state.account_key = secrets.account_key;
        Ok(Some(state))
    }

    /// Reads the state file, failing with the next command when there is none.
    pub fn require() -> Result<Self> {
        let state = Self::load()?.ok_or_else(|| crate::diagnostic::Failure::new(
            "not_signed_in", 3, "This machine is not signed in.",
            "Run: veil login --server <URL> --email <EMAIL>. For a restricted host, use veil device add.",
        ))?;
        if state.pending_registration {
            return Err(crate::diagnostic::Failure::new(
                "registration_pending",
                3,
                "Device registration is unfinished.",
                "Run: veil login",
            )
            .into());
        }
        Ok(state)
    }

    /// Writes the state file with mode 0600.
    pub fn save(&self) -> Result<()> {
        let path = state_path()?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("cannot create {}", parent.display()))?;
        }
        Keystore::for_home(&home()?)?.save(&Secrets {
            device_signing_key: self.device_signing_key.clone(),
            device_sealing_key: self.device_sealing_key.clone(),
            account_key: self.account_key.clone(),
        })?;
        let raw = serde_json::to_string_pretty(self).context("cannot encode state")?;
        write_private(&path, raw.as_bytes())?;
        Ok(())
    }

    /// Builds the state of a device that just joined an account.
    pub fn new(
        server: &str,
        account_id: Uuid,
        email: &str,
        device_id: Uuid,
        keys: &DeviceKeys,
    ) -> Self {
        Self {
            server: server.to_owned(),
            account_id,
            email: email.to_owned(),
            device_id,
            pending_registration: false,
            device_signing_key: keys.signing_secret(),
            device_sealing_key: keys.sealing().to_base64(),
            account_key: None,
            session: None,
            cache: None,
            sync_revision: None,
            pending_audit: Vec::new(),
        }
    }

    /// The device keys.
    pub fn device_keys(&self) -> Result<DeviceKeys> {
        DeviceKeys::from_parts(&self.device_signing_key, &self.device_sealing_key)
            .context("the device keys in the state file are damaged")
    }

    /// The account key, when this machine holds it.
    pub fn account_key(&self) -> Result<Option<Key>> {
        self.account_key
            .as_deref()
            .map(|encoded| Key::from_base64(encoded).context("the account key is damaged"))
            .transpose()
    }

    /// Stores the account key.
    pub fn set_account_key(&mut self, key: &Key) {
        self.account_key = Some(key.to_base64());
    }

    /// A live session token, if one has not expired.
    pub fn live_session(&self) -> Option<String> {
        let now = crate::now();
        self.session
            .as_ref()
            .filter(|session| session.expires_at > now)
            .map(|session| session.token.clone())
    }

    /// A live session token, or the command that gets one.
    pub fn require_session(&self) -> Result<String> {
        self.live_session().ok_or_else(|| {
            crate::diagnostic::Failure::new(
                "session_required",
                3,
                "Writes need a live management session; device read access is unchanged.",
                "Run: veil login",
            )
            .into()
        })
    }

    /// The cached document, if it is still within the offline window.
    pub fn fresh_cache(&self) -> Option<&SyncDocument> {
        let cache = self.cache.as_ref()?;
        (cache.device_scoped
            && self
                .sync_revision
                .is_none_or(|revision| cache.document.revision >= revision)
            && crate::now().saturating_sub(cache.at) <= OFFLINE_TTL_SECONDS)
            .then_some(&cache.document)
    }
}

pub(crate) fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    write_atomic(path, bytes, 0o600)
}

/// Atomically replaces a project file (`veil.toml`, `.gitignore`), keeping the existing file's
/// mode and writing through a symlink to its target. New files get 0644, less the umask.
pub(crate) fn write_project(path: &Path, bytes: &[u8]) -> Result<()> {
    let target = fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    #[cfg(unix)]
    let mode = {
        use std::os::unix::fs::PermissionsExt as _;
        fs::metadata(&target).map_or(0o644, |meta| meta.permissions().mode() & 0o7777)
    };
    #[cfg(not(unix))]
    let mode = 0o644;
    write_atomic(&target, bytes, mode)
}

fn write_atomic(path: &Path, bytes: &[u8], #[allow(unused)] mode: u32) -> Result<()> {
    use std::io::Write as _;
    let temporary = path.with_extension(format!("{}.tmp", Uuid::now_v7()));
    let result = (|| {
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(mode);
        }
        let mut file = options.open(&temporary)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            file.set_permissions(fs::Permissions::from_mode(mode))?;
        }
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        #[cfg(unix)]
        if let Some(parent) = path.parent() {
            fs::File::open(parent)?.sync_all()?;
        }
        Ok::<_, std::io::Error>(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result.with_context(|| format!("cannot write {}", path.display()))
}

/// `$VEIL_HOME`, falling back to the XDG configuration directory.
pub fn home() -> Result<PathBuf> {
    if let Some(value) = std::env::var_os("VEIL_HOME").filter(|value| !value.is_empty()) {
        return Ok(PathBuf::from(value));
    }
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))
        .context("neither VEIL_HOME nor HOME is set")?;
    Ok(base.join("veil"))
}

fn state_path() -> Result<PathBuf> {
    Ok(home()?.join("state.json"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_round_trip_through_the_state() {
        let keys = DeviceKeys::generate();
        let mut state = State::new(
            "http://localhost",
            Uuid::now_v7(),
            "me@example.com",
            Uuid::now_v7(),
            &keys,
        );
        let account_key = Key::generate();
        state.set_account_key(&account_key);
        let restored = state.device_keys().expect("device keys");
        assert_eq!(restored.auth_public(), keys.auth_public());
        assert_eq!(state.account_key().expect("key"), Some(account_key));
    }

    #[test]
    fn private_writes_replace_atomically_and_leave_no_temporary_file() {
        let dir = std::env::temp_dir().join(format!("veil-private-{}", Uuid::now_v7()));
        fs::create_dir_all(&dir).expect("dir");
        let path = dir.join("state.json");
        write_private(&path, b"first").expect("write");
        write_private(&path, b"second").expect("replace");
        assert_eq!(fs::read(&path).expect("read"), b"second");
        assert_eq!(fs::read_dir(&dir).expect("dir").count(), 1);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                fs::metadata(&path).expect("stat").permissions().mode() & 0o777,
                0o600
            );
        }
        let blocked = dir.join("directory");
        fs::create_dir(&blocked).expect("blocked");
        assert!(write_private(&blocked, b"cannot rename onto directory").is_err());
        assert_eq!(fs::read_dir(&dir).expect("dir").count(), 2);
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn only_fresh_device_scoped_caches_authorize_offline_reads() {
        let mut state = State::new(
            "http://localhost",
            Uuid::now_v7(),
            "me@example.com",
            Uuid::now_v7(),
            &DeviceKeys::generate(),
        );
        let document: SyncDocument = serde_json::from_value(serde_json::json!({
            "revision": 1, "full": true, "vaults": [], "items": [],
            "grants": [], "deleted": [], "rotations": [],
        }))
        .expect("document");
        state.cache = Some(Cache {
            at: crate::now(),
            document,
            device_scoped: false,
        });
        assert!(state.fresh_cache().is_none());
        state.cache.as_mut().expect("cache").device_scoped = true;
        assert!(state.fresh_cache().is_some());
        state.sync_revision = Some(2);
        assert!(state.fresh_cache().is_none());
        state.sync_revision = Some(1);
        assert!(state.fresh_cache().is_some());
        state.cache.as_mut().expect("cache").at = 0;
        assert!(state.fresh_cache().is_none());
    }

    #[test]
    fn an_expired_session_is_not_live() {
        let mut state = State::new(
            "http://localhost",
            Uuid::now_v7(),
            "me@example.com",
            Uuid::now_v7(),
            &DeviceKeys::generate(),
        );
        state.session = Some(StoredSession {
            token: "t".to_owned(),
            expires_at: 1,
        });
        assert!(state.live_session().is_none());
        state.session = Some(StoredSession {
            token: "t".to_owned(),
            expires_at: crate::now() + 60,
        });
        assert_eq!(state.live_session(), Some("t".to_owned()));
    }
}
