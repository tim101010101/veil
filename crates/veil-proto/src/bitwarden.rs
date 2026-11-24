//! Letting Bitwarden clients see one Vault.
//!
//! A Bitwarden login uses the master password and sees exactly one Vault: its user key is that
//! Vault's key. The Owner's client prepares everything the clients need, all sealed, and the
//! service only stores it and maps fields.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

/// What a Bitwarden login needs, prepared by `veil bitwarden enable`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct EnableBitwardenRequest {
    /// The Vault Bitwarden clients see.
    pub vault_id: Uuid,
    /// The Vault key wrapped by the master key: the Bitwarden `Key`.
    pub protected_key: String,
    /// The account's RSA private key, wrapped by the Vault key: the Bitwarden `PrivateKey`.
    pub private_key: String,
    /// The account's RSA public key, SPKI DER base64.
    pub public_key: String,
    /// The Bitwarden `AccountKeys` object (v2 key pairs and signed security state, wrapped by
    /// the Vault key), as JSON text. Stored and returned unchanged.
    pub account_keys: String,
}

/// Which Vault Bitwarden clients see.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct BitwardenStatus {
    /// The Vault.
    pub vault_id: Uuid,
    /// Unix seconds.
    pub enabled_at: u64,
    /// Whether a Bitwarden login also needs a code from an authenticator app.
    #[serde(default)]
    pub two_step: bool,
}

/// Turns on two-step login for Bitwarden clients: the authenticator secret, and a current code
/// from the app that holds it, which proves the app was set up before logins depend on it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct EnableTwoStepRequest {
    /// The TOTP secret, base32 without padding (RFC 6238: SHA-1, six digits, 30 seconds).
    pub secret: String,
    /// A current six-digit code.
    pub code: String,
}
