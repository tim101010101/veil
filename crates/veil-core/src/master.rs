//! The master password: one SDK derivation for both Veil and Bitwarden logins.

use std::num::NonZeroU32;

use bitwarden_crypto::{EncString, HashPurpose, MasterKey};
use serde::{Deserialize, Serialize};

use crate::{Error, Key};

/// Key derivation parameters, stored by the service and returned before login.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Kdf {
    /// PBKDF2-SHA256.
    Pbkdf2 {
        /// Iterations, at least 5000.
        iterations: u32,
    },
    /// Argon2id.
    Argon2id {
        /// Iterations, at least 2.
        iterations: u32,
        /// Memory in MiB, at least 16.
        memory_mib: u32,
        /// Lanes, at least 1.
        parallelism: u32,
    },
}

impl Default for Kdf {
    /// The SDK's default for new v2 accounts.
    fn default() -> Self {
        match bitwarden_crypto::Kdf::default_argon2() {
            bitwarden_crypto::Kdf::Argon2id {
                iterations,
                memory,
                parallelism,
            } => Self::Argon2id {
                iterations: iterations.get(),
                memory_mib: memory.get(),
                parallelism: parallelism.get(),
            },
            bitwarden_crypto::Kdf::PBKDF2 { iterations } => Self::Pbkdf2 {
                iterations: iterations.get(),
            },
        }
    }
}

impl Kdf {
    /// The cheapest parameters the SDK accepts. Only for secrets with full entropy, such as the
    /// recovery code, and for tests.
    pub const MINIMUM: Self = Self::Pbkdf2 { iterations: 5000 };

    fn to_sdk(self) -> Result<bitwarden_crypto::Kdf, Error> {
        let positive = |value: u32| NonZeroU32::new(value).ok_or(Error::Kdf);
        Ok(match self {
            Self::Pbkdf2 { iterations } => bitwarden_crypto::Kdf::PBKDF2 {
                iterations: positive(iterations)?,
            },
            Self::Argon2id {
                iterations,
                memory_mib,
                parallelism,
            } => bitwarden_crypto::Kdf::Argon2id {
                iterations: positive(iterations)?,
                memory: positive(memory_mib)?,
                parallelism: positive(parallelism)?,
            },
        })
    }
}

/// What a master password (or a recovery code) derives through the SDK's `MasterKey`.
pub struct MasterPassword {
    key: MasterKey,
    auth_hash: String,
}

impl MasterPassword {
    /// Derives the master key. The email is the salt, trimmed and lowercased as Bitwarden
    /// clients do, so both logins derive the same key.
    pub fn derive(password: &str, email: &str, kdf: &Kdf) -> Result<Self, Error> {
        let email = normalize_email(email);
        let key = MasterKey::derive(password, &email, &kdf.to_sdk()?).map_err(|_| Error::Kdf)?;
        let auth_hash = key
            .derive_master_key_hash(password.as_bytes(), HashPurpose::ServerAuthorization)
            .to_string();
        Ok(Self { key, auth_hash })
    }

    /// The hash sent to the service to authenticate; the service hashes it again at rest.
    pub fn auth_hash(&self) -> &str {
        &self.auth_hash
    }

    /// Wraps the account key, as Bitwarden protects a user key.
    pub fn protect(&self, account_key: &Key) -> Result<String, Error> {
        self.key
            .encrypt_user_key(account_key.sdk())
            .map(|wrapped| wrapped.to_string())
            .map_err(|_| Error::Crypto)
    }

    /// Unwraps an account key protected by [`MasterPassword::protect`].
    pub fn unlock(&self, protected: &str) -> Result<Key, Error> {
        let protected: EncString = protected.parse().map_err(|_| Error::Encoding)?;
        self.key
            .decrypt_user_key(protected)
            .map(Key::from_sdk)
            .map_err(|_| Error::Decryption)
    }
}

/// The form of an email address the service and the salt use.
pub fn normalize_email(email: &str) -> String {
    email.trim().to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_same_password_and_email_unlock_the_same_key() {
        let account_key = Key::generate();
        let first = MasterPassword::derive("correct horse", "me@example.com", &Kdf::MINIMUM)
            .expect("first");
        let protected = first.protect(&account_key).expect("protect");
        let second = MasterPassword::derive("correct horse", " ME@example.com ", &Kdf::MINIMUM)
            .expect("second");
        assert_eq!(first.auth_hash(), second.auth_hash());
        assert_eq!(second.unlock(&protected).expect("unlock"), account_key);
    }

    #[test]
    fn a_wrong_password_does_not_unlock() {
        let protected = MasterPassword::derive("right", "me@example.com", &Kdf::MINIMUM)
            .expect("derive")
            .protect(&Key::generate())
            .expect("protect");
        let wrong =
            MasterPassword::derive("wrong", "me@example.com", &Kdf::MINIMUM).expect("wrong");
        assert_eq!(wrong.unlock(&protected).err(), Some(Error::Decryption));
    }

    #[test]
    fn parameters_below_the_floor_are_rejected() {
        let weak = Kdf::Pbkdf2 { iterations: 10 };
        assert_eq!(
            MasterPassword::derive("pw", "me@example.com", &weak).err(),
            Some(Error::Kdf)
        );
        let zero = Kdf::Argon2id {
            iterations: 0,
            memory_mib: 64,
            parallelism: 1,
        };
        assert_eq!(
            MasterPassword::derive("pw", "me@example.com", &zero).err(),
            Some(Error::Kdf)
        );
    }

    #[test]
    fn the_default_is_argon2id() {
        assert!(matches!(Kdf::default(), Kdf::Argon2id { .. }));
    }
}
