//! Account, session, and recovery shapes.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::{Device, DeviceKeys};

/// The unit one owner controls.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct Account {
    /// Account id.
    pub id: Uuid,
    /// Address used to sign in, trimmed and lowercased.
    pub email: String,
}

/// Key derivation parameters for the master password, as the SDK's `Kdf`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Kdf {
    /// PBKDF2-SHA256.
    Pbkdf2 {
        /// Iterations.
        iterations: u32,
    },
    /// Argon2id.
    Argon2id {
        /// Iterations.
        iterations: u32,
        /// Memory in MiB.
        memory_mib: u32,
        /// Lanes.
        parallelism: u32,
    },
}

/// Ask for the KDF parameters before deriving the master key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct PreloginRequest {
    /// Address used to sign in.
    pub email: String,
}

/// The KDF parameters for an address. Unknown addresses get the default, so the answer does
/// not reveal whether an account exists.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct PreloginResponse {
    /// Parameters to derive the master key with.
    pub kdf: Kdf,
}

/// An owner's authenticated, expiring access.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct Session {
    /// Bearer token.
    pub token: String,
    /// Unix seconds after which the token is refused.
    pub expires_at: u64,
}

/// Create the account and its first device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct CreateAccountRequest {
    /// Client-generated id, so retries are safe.
    pub id: Uuid,
    /// Address used to sign in.
    pub email: String,
    /// Parameters the master key was derived with.
    pub kdf: Kdf,
    /// The SDK's server authorization hash of the master password.
    pub auth_hash: String,
    /// Account key wrapped by the master key (an `EncString`).
    pub protected_account_key: String,
    /// The SDK's v2 account key state, wrapped by the account key, as opaque JSON.
    pub account_keys: String,
    /// Account key wrapped by the recovery code.
    pub recovery_wrap: String,
    /// Proof derived from the recovery code, so a recovery can be authorized.
    pub recovery_verifier: String,
    /// The first device.
    pub device: DeviceKeys,
}

/// The account, the first device, and a session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct CreateAccountResponse {
    /// The new account.
    pub account: Account,
    /// The first device.
    pub device: Device,
    /// A session for the owner.
    pub session: Session,
}

/// Exchange credentials for a session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct CreateSessionRequest {
    /// Address used to sign in.
    pub email: String,
    /// The SDK's server authorization hash of the master password.
    pub auth_hash: String,
    /// Signed device identity. Older password-only clients must upgrade.
    #[serde(default)]
    pub device: Option<DeviceLogin>,
}

/// A device proving possession of its signing key during password authentication.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct DeviceLogin {
    /// Device identity and public keys.
    pub keys: DeviceKeys,
    /// Explicitly upgrade an existing restricted device to account-wide reads.
    pub promote: bool,
    /// Unix seconds, within the server's signature window.
    pub timestamp: u64,
    /// Single-use nonce.
    pub nonce: String,
    /// Ed25519 signature over `session_input`.
    pub signature: String,
}

/// A session plus the wrapped account key, so the client can decrypt after signing in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct CreateSessionResponse {
    /// Authenticated device and its persistent read scope.
    pub device: Device,
    /// The account.
    pub account: Account,
    /// The new session.
    pub session: Session,
    /// Account key wrapped by the master key.
    pub protected_account_key: String,
    /// The v2 account key state, wrapped by the account key.
    pub account_keys: String,
}

/// Change the master password.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct UpdateAccountRequest {
    /// Parameters the new master key was derived with.
    pub kdf: Kdf,
    /// New server authorization hash.
    pub auth_hash: String,
    /// Account key, wrapped by the new master key.
    pub protected_account_key: String,
    /// The Bitwarden Vault's key wrapped by the new master key. Required while Bitwarden clients
    /// are enabled, so their login follows the new password.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bitwarden_protected_key: Option<String>,
}

/// Rebuild access from the recovery code.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct CreateRecoveryRequest {
    /// Address used to sign in.
    pub email: String,
    /// The recovery verifier, proving possession of the code.
    pub recovery_proof: String,
    /// The device being registered.
    pub device: DeviceKeys,
}

/// The device registered by a recovery and a session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct CreateRecoveryResponse {
    /// Account that was recovered.
    pub account_id: Uuid,
    /// The registered device.
    pub device: Device,
    /// A session for the owner.
    pub session: Session,
    /// Account key wrapped by the recovery code.
    pub recovery_wrap: String,
}
