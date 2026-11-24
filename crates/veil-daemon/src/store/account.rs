//! Accounts, sign-in, recovery, and Owner sessions.

use super::*;

impl Store {
    /// Inserts the account and its first device, an Owner Device.
    pub fn create_account(
        &self,
        request: &CreateAccountRequest,
        at: u64,
    ) -> Result<(), StoreError> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        insert(
            &tx,
            "INSERT INTO accounts (id, email, kdf, auth_hash, protected_account_key, account_keys,
                recovery_wrap, recovery_verifier, revision, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 0, ?9)",
            params![
                request.id.to_string(),
                normalize_email(&request.email),
                kdf_json(&request.kdf)?,
                hash(&request.auth_hash),
                request.protected_account_key,
                request.account_keys,
                request.recovery_wrap,
                hash(&request.recovery_verifier),
                at as i64,
            ],
        )?;
        insert_device(&tx, request.id, &request.device, true, None, at)?;
        tx.commit()?;
        Ok(())
    }

    /// The KDF stored for an address, when the account exists.
    pub fn prelogin_kdf(&self, email: &str) -> Result<Option<Kdf>, StoreError> {
        Ok(self
            .conn()
            .query_row(
                "SELECT kdf FROM accounts WHERE email = ?1",
                params![normalize_email(email)],
                |row| kdf_at(row, 0),
            )
            .optional()?)
    }

    /// Finds an account by sign-in address.
    pub fn account_by_email(&self, email: &str) -> Result<AccountRecord, StoreError> {
        self.conn()
            .query_row(
                "SELECT id, email, kdf, auth_hash, protected_account_key, account_keys,
                    recovery_wrap, recovery_verifier
                 FROM accounts WHERE email = ?1",
                params![normalize_email(email)],
                |row| {
                    Ok(AccountRecord {
                        id: parse_id(row.get(0)?),
                        email: row.get(1)?,
                        kdf: kdf_at(row, 2)?,
                        auth_hash: row.get(3)?,
                        protected_account_key: row.get(4)?,
                        account_keys: row.get(5)?,
                        recovery_wrap: row.get(6)?,
                        recovery_verifier: row.get(7)?,
                    })
                },
            )
            .optional()?
            .ok_or(StoreError::NotFound)
    }

    /// Checks the authentication hash, in constant time, and returns the account.
    pub fn authenticate(&self, email: &str, auth_hash: &str) -> Result<AccountRecord, StoreError> {
        let account = self.account_by_email(email)?;
        if constant_time_eq(&hash(auth_hash), &account.auth_hash) {
            Ok(account)
        } else {
            Err(StoreError::NotFound)
        }
    }

    /// Checks a recovery proof, in constant time, and returns the account.
    pub fn authenticate_recovery(
        &self,
        email: &str,
        proof: &str,
    ) -> Result<AccountRecord, StoreError> {
        let account = self.account_by_email(email)?;
        if constant_time_eq(&hash(proof), &account.recovery_verifier) {
            Ok(account)
        } else {
            Err(StoreError::NotFound)
        }
    }

    /// Replaces the KDF, the authentication hash, and the wrapped account key.
    pub fn update_account(
        &self,
        account_id: Uuid,
        request: &UpdateAccountRequest,
        at_ms: u64,
    ) -> Result<(), StoreError> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        if bound_vault(&tx, account_id)?.is_some() {
            // The Bitwarden login derives from the same master password, so it must follow.
            let Some(protected_key) = &request.bitwarden_protected_key else {
                return Err(StoreError::Invalid(
                    "Bitwarden clients are enabled: the change must carry bitwarden_protected_key",
                ));
            };
            insert(
                &tx,
                "UPDATE bitwarden_bindings SET protected_key = ?2, security_stamp = ?3,
                    changed_ms = ?4 WHERE account_id = ?1",
                params![
                    account_id.to_string(),
                    protected_key,
                    Uuid::now_v7().to_string(),
                    at_ms as i64,
                ],
            )?;
            revoke_bitwarden_sessions(&tx, account_id)?;
        }
        let changed = insert(
            &tx,
            "UPDATE accounts SET kdf = ?2, auth_hash = ?3, protected_account_key = ?4
             WHERE id = ?1",
            params![
                account_id.to_string(),
                kdf_json(&request.kdf)?,
                hash(&request.auth_hash),
                request.protected_account_key,
            ],
        )?;
        if changed == 0 {
            return Err(StoreError::NotFound);
        }
        tx.commit()?;
        Ok(())
    }

    /// Stores a session by the hash of its token.
    pub fn create_session(
        &self,
        account_id: Uuid,
        device_id: Uuid,
        token: &str,
        expires_at: u64,
    ) -> Result<(), StoreError> {
        let changed = insert(
            &self.conn(),
            "INSERT INTO sessions (token_hash, account_id, device_id, expires_at)
             SELECT ?1, ?2, id, ?4 FROM devices
             WHERE id = ?3 AND account_id = ?2 AND revoked_at IS NULL",
            params![
                hash(token),
                account_id.to_string(),
                device_id.to_string(),
                expires_at as i64
            ],
        )?;
        if changed == 0 {
            return Err(StoreError::Forbidden);
        }
        Ok(())
    }

    /// Resolves a live session to its account.
    pub fn session_account(&self, token: &str, at: u64) -> Result<Option<Uuid>, StoreError> {
        Ok(self
            .conn()
            .query_row(
                "SELECT s.account_id FROM sessions s JOIN devices d
                 ON d.id = s.device_id AND d.account_id = s.account_id
                 WHERE s.token_hash = ?1 AND s.expires_at > ?2 AND d.revoked_at IS NULL",
                params![hash(token), at as i64],
                |row| Ok(parse_id(row.get(0)?)),
            )
            .optional()?)
    }

    /// Drops a session.
    pub fn delete_session(&self, token: &str) -> Result<(), StoreError> {
        insert(
            &self.conn(),
            "DELETE FROM sessions WHERE token_hash = ?1",
            params![hash(token)],
        )?;
        Ok(())
    }

    // ----- devices -----
}
