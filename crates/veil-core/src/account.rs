//! Creating an account: the account key, its v2 key state, and its two wraps.

use bitwarden_core::key_management::account_cryptographic_state::WrappedAccountCryptographicState;

use crate::{
    Error, Kdf, Key, MasterPassword, RecoveryCode,
    key::{take, with_context},
};

/// Everything a new account needs, generated on the client.
pub struct NewAccount {
    /// The account key (the SDK's v2 user key). It wraps every Vault key.
    pub account_key: Key,
    /// Hash sent to the service for authentication.
    pub auth_hash: String,
    /// The account key wrapped by the master password.
    pub protected_account_key: String,
    /// The SDK's v2 account key state (RSA key, ML-DSA-44 signing key, signed security state),
    /// wrapped by the account key, as JSON.
    pub account_keys: String,
    /// Shown to the user once.
    pub recovery_code: RecoveryCode,
    /// The account key wrapped by the recovery code.
    pub recovery_wrap: String,
    /// Proof the service stores so a recovery can be authorized.
    pub recovery_verifier: String,
}

impl NewAccount {
    /// Generates the account key state and wraps it for `password`.
    pub fn create(email: &str, password: &str, kdf: &Kdf) -> Result<Self, Error> {
        let (account_key, state) = with_context(|ctx| {
            let (user_key, state) =
                WrappedAccountCryptographicState::make(ctx).map_err(|_| Error::Crypto)?;
            Ok((take(ctx, user_key), state))
        })?;
        let account_keys = serde_json::to_string(&state).map_err(|_| Error::Crypto)?;
        let master = MasterPassword::derive(password, email, kdf)?;
        let recovery_code = RecoveryCode::generate();
        Ok(Self {
            auth_hash: master.auth_hash().to_owned(),
            protected_account_key: master.protect(&account_key)?,
            account_keys,
            recovery_wrap: recovery_code.wrap(email, &account_key)?,
            recovery_verifier: recovery_code.verifier(email)?,
            recovery_code,
            account_key,
        })
    }
}

/// Checks that a stored key state belongs to `account_key` and that its signatures verify.
pub fn verify_account_keys(account_key: &Key, account_keys: &str) -> Result<(), Error> {
    let state: WrappedAccountCryptographicState =
        serde_json::from_str(account_keys).map_err(|_| Error::Encoding)?;
    with_context(|ctx| {
        let user_key = ctx.add_local_symmetric_key(account_key.sdk().clone());
        state
            .to_wrapped_request_model(&user_key, ctx)
            .map(|_| ())
            .map_err(|_| Error::Decryption)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_new_account_unlocks_with_the_password_and_the_recovery_code() {
        let account =
            NewAccount::create("me@example.com", "correct horse", &Kdf::MINIMUM).expect("create");
        let master = MasterPassword::derive("correct horse", "me@example.com", &Kdf::MINIMUM)
            .expect("derive");
        assert_eq!(master.auth_hash(), account.auth_hash);
        assert_eq!(
            master
                .unlock(&account.protected_account_key)
                .expect("unlock"),
            account.account_key
        );
        assert_eq!(
            account
                .recovery_code
                .unwrap("me@example.com", &account.recovery_wrap)
                .expect("recover"),
            account.account_key
        );
        verify_account_keys(&account.account_key, &account.account_keys).expect("verify");
    }

    #[test]
    fn a_key_state_does_not_verify_under_another_key() {
        let account = NewAccount::create("me@example.com", "pw", &Kdf::MINIMUM).expect("create");
        assert_eq!(
            verify_account_keys(&Key::generate(), &account.account_keys),
            Err(Error::Decryption)
        );
    }
}
