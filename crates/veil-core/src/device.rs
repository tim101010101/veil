//! Principal keys: a sealing key that Vault keys are shared to, and a key that signs requests.
//!
//! Sharing a Vault key with a Device or a Workload uses the SDK's `UnsignedSharedKey`, the same
//! RSA-OAEP encapsulation Bitwarden uses to share organization keys. Request signing stays
//! Ed25519, because `veild` verifies signatures and must not link the SDK.

use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use bitwarden_crypto::{
    Pkcs8PrivateKeyBytes, PrivateKey, PublicKey, PublicKeyEncryptionAlgorithm, SpkiPublicKeyBytes,
    UnsignedSharedKey,
};
use ed25519_dalek::{Signer, SigningKey};

use crate::{
    Error, Key,
    key::{take, with_context},
};

/// The private half of a sealing key pair. Vault keys are shared to its public half.
#[derive(Clone)]
pub struct SealingKey(PrivateKey);

impl SealingKey {
    /// Draws a new RSA-2048 key pair.
    pub fn generate() -> Self {
        Self(PrivateKey::make(PublicKeyEncryptionAlgorithm::RsaOaepSha1))
    }

    /// PKCS#8 DER, base64. This is the secret a Workload keeps in CI.
    pub fn to_base64(&self) -> String {
        let der = self.0.to_der().expect("an SDK key encodes as PKCS#8");
        STANDARD.encode(der.as_ref())
    }

    /// Parses [`SealingKey::to_base64`].
    pub fn from_base64(encoded: &str) -> Result<Self, Error> {
        let der = STANDARD
            .decode(encoded.trim())
            .map_err(|_| Error::Encoding)?;
        PrivateKey::from_der(&Pkcs8PrivateKeyBytes::from(der))
            .map(Self)
            .map_err(|_| Error::Encoding)
    }

    /// The public half: SPKI DER, base64, as published to the service.
    pub fn public(&self) -> String {
        let der = self
            .0
            .to_public_key()
            .to_der()
            .expect("an SDK key encodes as SPKI");
        STANDARD.encode(der.as_ref())
    }

    /// Opens a Vault key shared with [`share_key`].
    pub fn open_shared_key(&self, shared: &str) -> Result<Key, Error> {
        let shared: UnsignedSharedKey = shared.parse().map_err(|_| Error::Encoding)?;
        with_context(|ctx| {
            let private = ctx.add_local_private_key(self.0.clone());
            let key = shared
                .decapsulate(private, ctx)
                .map_err(|_| Error::Decryption)?;
            Ok(take(ctx, key))
        })
    }
}

/// Shares `key` with the holder of `recipient` (a [`SealingKey::public`] value).
pub fn share_key(key: &Key, recipient: &str) -> Result<String, Error> {
    let der = STANDARD
        .decode(recipient.trim())
        .map_err(|_| Error::Encoding)?;
    let public =
        PublicKey::from_der(&SpkiPublicKeyBytes::from(der)).map_err(|_| Error::Encoding)?;
    with_context(|ctx| {
        let slot = ctx.add_local_symmetric_key(key.sdk().clone());
        UnsignedSharedKey::encapsulate(slot, &public, ctx)
            .map(|shared| shared.to_string())
            .map_err(|_| Error::Crypto)
    })
}

/// A Device's two keys.
#[derive(Clone)]
pub struct DeviceKeys {
    signing: SigningKey,
    sealing: SealingKey,
}

impl DeviceKeys {
    /// Draws both keys from the operating system.
    pub fn generate() -> Self {
        Self {
            signing: SigningKey::generate(&mut rand_core::OsRng),
            sealing: SealingKey::generate(),
        }
    }

    /// Rebuilds the keys from [`DeviceKeys::signing_secret`] and [`SealingKey::to_base64`].
    pub fn from_parts(signing: &str, sealing: &str) -> Result<Self, Error> {
        let bytes = URL_SAFE_NO_PAD
            .decode(signing)
            .map_err(|_| Error::Encoding)?;
        let seed: [u8; 32] = bytes.try_into().map_err(|_| Error::Encoding)?;
        Ok(Self {
            signing: SigningKey::from_bytes(&seed),
            sealing: SealingKey::from_base64(sealing)?,
        })
    }

    /// The Ed25519 seed, base64url, for local storage only.
    pub fn signing_secret(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.signing.to_bytes())
    }

    /// The sealing key.
    pub fn sealing(&self) -> &SealingKey {
        &self.sealing
    }

    /// The Ed25519 verifying key, base64url, as published to the service.
    pub fn auth_public(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.signing.verifying_key().to_bytes())
    }

    /// Signs a request with the authentication key; base64url.
    pub fn sign(&self, message: &[u8]) -> String {
        URL_SAFE_NO_PAD.encode(self.signing.sign(message).to_bytes())
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    use super::*;

    #[test]
    fn a_shared_key_opens_with_the_recipient_only() {
        let recipient = SealingKey::generate();
        let key = Key::generate();
        let shared = share_key(&key, &recipient.public()).expect("share");
        assert_eq!(recipient.open_shared_key(&shared).expect("open"), key);
        assert_eq!(
            SealingKey::generate().open_shared_key(&shared).err(),
            Some(Error::Decryption)
        );
    }

    #[test]
    fn device_keys_survive_storage() {
        let keys = DeviceKeys::generate();
        let restored = DeviceKeys::from_parts(&keys.signing_secret(), &keys.sealing().to_base64())
            .expect("restore");
        assert_eq!(restored.auth_public(), keys.auth_public());
        assert_eq!(restored.sealing().public(), keys.sealing().public());
    }

    #[test]
    fn signatures_verify_with_plain_ed25519() {
        let keys = DeviceKeys::generate();
        let public: [u8; 32] = URL_SAFE_NO_PAD
            .decode(keys.auth_public())
            .expect("b64")
            .try_into()
            .expect("32 bytes");
        let signature: [u8; 64] = URL_SAFE_NO_PAD
            .decode(keys.sign(b"request"))
            .expect("b64")
            .try_into()
            .expect("64 bytes");
        VerifyingKey::from_bytes(&public)
            .expect("key")
            .verify(b"request", &Signature::from_bytes(&signature))
            .expect("verifies");
    }
}
