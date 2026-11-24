//! Symmetric keys and the SDK key store they pass through.
//!
//! The SDK performs every operation inside a [`KeyStoreContext`]. `veil` keeps keys between
//! invocations (in the system keychain or a `0600` file), so this module moves a key into a
//! short-lived context for one operation and takes it back out afterwards.

use bitwarden_core::key_management::{KeySlotIds, SymmetricKeySlotId};
use bitwarden_crypto::{
    EncString, KeyStore, KeyStoreContext, SymmetricCryptoKey, SymmetricKeyAlgorithm,
};
use bitwarden_encoding::B64;

use crate::Error;

/// A symmetric key: an account key, a Vault key, or an Item key.
///
/// New keys are XAES-256-GCM, the algorithm the SDK uses for v2 user keys. Wrapping with such a
/// key produces COSE (type 7) `EncString`s.
#[derive(Clone)]
pub struct Key(SymmetricCryptoKey);

impl Key {
    /// Draws a fresh XAES-256-GCM key.
    pub fn generate() -> Self {
        Self(SymmetricCryptoKey::make(SymmetricKeyAlgorithm::XAes256Gcm))
    }

    /// The SDK's base64 encoding of the key, for local storage only.
    pub fn to_base64(&self) -> String {
        self.0.to_base64().to_string()
    }

    /// Parses the SDK's base64 encoding of a key.
    pub fn from_base64(encoded: &str) -> Result<Self, Error> {
        let bytes = B64::try_from(encoded).map_err(|_| Error::Encoding)?;
        SymmetricCryptoKey::try_from(bytes)
            .map(Self)
            .map_err(|_| Error::Encoding)
    }

    pub(crate) fn from_sdk(key: SymmetricCryptoKey) -> Self {
        Self(key)
    }

    pub(crate) fn sdk(&self) -> &SymmetricCryptoKey {
        &self.0
    }
}

impl std::fmt::Debug for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Key(…)")
    }
}

impl PartialEq for Key {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

/// Wraps `key` with `wrapping` (an SDK `EncString`).
pub fn wrap_key(wrapping: &Key, key: &Key) -> Result<String, Error> {
    with_context(|ctx| {
        let wrapping = ctx.add_local_symmetric_key(wrapping.0.clone());
        let key = ctx.add_local_symmetric_key(key.0.clone());
        ctx.wrap_symmetric_key(wrapping, key)
            .map(|wrapped| wrapped.to_string())
            .map_err(|_| Error::Crypto)
    })
}

/// Unwraps a key produced by [`wrap_key`] or by a Bitwarden client.
pub fn unwrap_key(wrapping: &Key, wrapped: &str) -> Result<Key, Error> {
    let wrapped: EncString = wrapped.parse().map_err(|_| Error::Encoding)?;
    with_context(|ctx| {
        let wrapping = ctx.add_local_symmetric_key(wrapping.0.clone());
        let key = ctx
            .unwrap_symmetric_key(wrapping, &wrapped)
            .map_err(|_| Error::Decryption)?;
        Ok(take(ctx, key))
    })
}

/// Runs `f` with a fresh, empty key store context.
pub(crate) fn with_context<T>(
    f: impl FnOnce(&mut KeyStoreContext<'_, KeySlotIds>) -> Result<T, Error>,
) -> Result<T, Error> {
    let store: KeyStore<KeySlotIds> = KeyStore::default();
    let mut ctx = store.context_mut();
    f(&mut ctx)
}

/// Takes a key out of the context so `veil` can keep it.
///
/// This is the one place `veil-core` reads raw key material from the SDK. The SDK marks the call
/// deprecated because its own clients keep keys inside the store; `veil` has no resident process,
/// so it must hand the key to the system keychain between invocations.
pub(crate) fn take(ctx: &KeyStoreContext<'_, KeySlotIds>, slot: SymmetricKeySlotId) -> Key {
    #[allow(deprecated)]
    let key = ctx
        .dangerous_get_symmetric_key(slot)
        .expect("a slot just filled by the SDK holds a key")
        .clone();
    Key(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_key_survives_base64() {
        let key = Key::generate();
        assert_eq!(Key::from_base64(&key.to_base64()).expect("parse"), key);
    }

    #[test]
    fn a_wrapped_key_unwraps_with_the_same_key_only() {
        let (outer, inner) = (Key::generate(), Key::generate());
        let wrapped = wrap_key(&outer, &inner).expect("wrap");
        assert!(
            wrapped.starts_with("7."),
            "XAES wrapping is a COSE EncString: {wrapped}"
        );
        assert_eq!(unwrap_key(&outer, &wrapped).expect("unwrap"), inner);
        assert_eq!(
            unwrap_key(&Key::generate(), &wrapped),
            Err(Error::Decryption)
        );
    }

    #[test]
    fn garbage_is_an_encoding_error() {
        assert_eq!(Key::from_base64("not a key").err(), Some(Error::Encoding));
        // The SDK reads a string without a type prefix as a legacy EncString, so garbage fails
        // at decryption rather than at parsing; either way it is refused.
        assert!(unwrap_key(&Key::generate(), "nonsense").is_err());
    }
}
