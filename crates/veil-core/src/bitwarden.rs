//! The keys a Bitwarden login needs to see one Vault.
//!
//! A Bitwarden account has one user key. For the Vault the Owner chose, that user key is the
//! Vault key: the master key wraps it, and the account's v2 key state (RSA key, ML-DSA-44 signing
//! key, signed security state) is re-wrapped under it with the SDK's own state rotation. The
//! Bitwarden clients then decrypt the Vault's Items exactly as they decrypt their own.

use bitwarden_core::key_management::account_cryptographic_state::WrappedAccountCryptographicState;
use serde_json::{Value, json};

use crate::{Error, Key, MasterPassword, key::with_context};

/// Everything the service stores so Bitwarden clients can log in and open one Vault.
#[derive(Debug, Clone, PartialEq)]
pub struct BitwardenKeys {
    /// The Vault key wrapped by the master key (Bitwarden's `Key`).
    pub protected_key: String,
    /// The RSA private key wrapped by the Vault key (Bitwarden's `PrivateKey`).
    pub private_key: String,
    /// The RSA public key, SPKI DER base64.
    pub public_key: String,
    /// Bitwarden's `AccountKeys` object.
    pub account_keys: Value,
}

/// Prepares the Bitwarden login for the Vault whose key is `vault_key`.
pub fn bitwarden_keys(
    master: &MasterPassword,
    account_key: &Key,
    account_keys: &str,
    vault_key: &Key,
) -> Result<BitwardenKeys, Error> {
    let state: WrappedAccountCryptographicState =
        serde_json::from_str(account_keys).map_err(|_| Error::Encoding)?;
    let model = with_context(|ctx| {
        let account = ctx.add_local_symmetric_key(account_key.sdk().clone());
        let vault = ctx.add_local_symmetric_key(vault_key.sdk().clone());
        let rotated = state
            .rotate(&account, &vault, ctx)
            .map_err(|_| Error::Decryption)?;
        rotated
            .to_wrapped_request_model(&vault, ctx)
            .map_err(|_| Error::Crypto)
    })?;
    let pair = &model.public_key_encryption_key_pair;
    let signature = &model.signature_key_pair;
    let private_key = pair.wrapped_private_key.clone().ok_or(Error::Crypto)?;
    let public_key = pair.public_key.clone().ok_or(Error::Crypto)?;
    Ok(BitwardenKeys {
        protected_key: master.protect(vault_key)?,
        account_keys: json!({
            "object": "privateKeys",
            "publicKeyEncryptionKeyPair": {
                "object": "publicKeyEncryptionKeyPair",
                "wrappedPrivateKey": private_key,
                "publicKey": public_key,
                "signedPublicKey": pair.signed_public_key,
            },
            "signatureKeyPair": {
                "object": "signatureKeyPair",
                "wrappedSigningKey": signature.wrapped_signing_key,
                "verifyingKey": signature.verifying_key,
            },
            "securityState": {
                "securityState": model.security_state.security_state,
                "securityVersion": model.security_state.security_version,
            },
        }),
        private_key,
        public_key,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Kdf, NewAccount};

    #[test]
    fn the_login_opens_the_vault_key_and_the_same_key_pair() {
        let account = NewAccount::create("me@example.com", "pw", &Kdf::MINIMUM).expect("create");
        let master = MasterPassword::derive("pw", "me@example.com", &Kdf::MINIMUM).expect("derive");
        let vault_key = Key::generate();
        let keys = bitwarden_keys(
            &master,
            &account.account_key,
            &account.account_keys,
            &vault_key,
        )
        .expect("keys");

        // The master password opens the Vault key, as a Bitwarden client opens its user key.
        assert_eq!(
            master.unlock(&keys.protected_key).expect("unlock"),
            vault_key
        );
        // The key pair is the account's own, now wrapped by the Vault key.
        let original = bitwarden_keys(
            &master,
            &account.account_key,
            &account.account_keys,
            &account.account_key,
        )
        .expect("same key");
        assert_eq!(keys.public_key, original.public_key);
        assert!(keys.account_keys["signatureKeyPair"]["verifyingKey"].is_string());
        assert!(keys.account_keys["securityState"]["securityState"].is_string());
    }

    #[test]
    fn a_wrong_account_key_is_refused() {
        let account = NewAccount::create("me@example.com", "pw", &Kdf::MINIMUM).expect("create");
        let master = MasterPassword::derive("pw", "me@example.com", &Kdf::MINIMUM).expect("derive");
        assert!(
            bitwarden_keys(
                &master,
                &Key::generate(),
                &account.account_keys,
                &Key::generate()
            )
            .is_err()
        );
    }
}
