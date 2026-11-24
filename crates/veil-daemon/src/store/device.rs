//! Devices: Owner devices, enrollment by approval, revocation, and request nonces.

use super::*;

impl Store {
    /// Registers an Owner Device, as a recovery does.
    pub fn add_owner_device(
        &self,
        account_id: Uuid,
        device: &DeviceKeys,
        at: u64,
    ) -> Result<Device, StoreError> {
        insert_device(&self.conn(), account_id, device, true, None, at)?;
        Ok(new_device(device, true, at))
    }

    /// Loads a device together with the account it belongs to and its owner flag.
    pub fn device_with_account(&self, id: Uuid) -> Result<DeviceRecord, StoreError> {
        self.conn()
            .query_row(
                "SELECT account_id, id, name, seal_pk, auth_pk, created_at, revoked_at, owner
                 FROM devices WHERE id = ?1",
                params![id.to_string()],
                |row| {
                    Ok(DeviceRecord {
                        account_id: parse_id(row.get(0)?),
                        device: device_row_at(row, 1)?,
                    })
                },
            )
            .optional()?
            .ok_or(StoreError::NotFound)
    }

    /// Loads a device by id.
    pub fn device(&self, id: Uuid) -> Result<Device, StoreError> {
        self.device_with_account(id).map(|record| record.device)
    }

    /// Records a pending enrollment. Pending enrollments expire after ten minutes.
    pub fn put_pending_device(
        &self,
        account_id: Uuid,
        code: &str,
        device: &DeviceKeys,
        at: u64,
    ) -> Result<(), StoreError> {
        insert(
            &self.conn(),
            "INSERT OR REPLACE INTO pending_devices (account_id, code, id, name, seal_pk, auth_pk,
                created_at, expires_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                account_id.to_string(),
                code,
                device.id.to_string(),
                device.name,
                device.seal_pk,
                device.auth_pk,
                at as i64,
                (at + 600) as i64,
            ],
        )?;
        Ok(())
    }

    /// Lists devices waiting for approval.
    pub fn pending_devices(&self, account_id: Uuid) -> Result<Vec<PendingDevice>, StoreError> {
        query(
            &self.conn(),
            "SELECT id, name, seal_pk, auth_pk, code, created_at, expires_at
             FROM pending_devices WHERE account_id = ?1 ORDER BY created_at",
            &[account_id.to_string().into()],
            |row| {
                Ok(PendingDevice {
                    device: DeviceKeys {
                        id: parse_id(row.get(0)?),
                        name: row.get(1)?,
                        seal_pk: row.get(2)?,
                        auth_pk: row.get(3)?,
                    },
                    code: row.get(4)?,
                    created_at: row.get::<_, i64>(5)? as u64,
                    expires_at: row.get::<_, i64>(6)? as u64,
                })
            },
        )
    }

    /// Lists approved and revoked devices.
    pub fn devices(&self, account_id: Uuid) -> Result<Vec<Device>, StoreError> {
        query(
            &self.conn(),
            "SELECT id, name, seal_pk, auth_pk, created_at, revoked_at, owner FROM devices
             WHERE account_id = ?1 ORDER BY created_at",
            &[account_id.to_string().into()],
            |row| device_row_at(row, 0),
        )
    }

    /// Approves a pending device and attaches its Grants. The device is not an Owner Device.
    pub fn approve_device(
        &self,
        account_id: Uuid,
        code: &str,
        grants: &[GrantWrite],
        at: u64,
    ) -> Result<Device, StoreError> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        let device = take_pending(&tx, account_id, code, at)?;
        insert_device(&tx, account_id, &device, false, Some(code), at)?;
        let seq = next_revision(&tx, account_id)?;
        for grant in grants {
            if grant.principal_id != device.id {
                return Err(StoreError::Forbidden);
            }
            insert_grant(&tx, account_id, grant, at, seq)?;
        }
        tx.commit()?;
        Ok(new_device(&device, false, at))
    }

    /// Registers a personal device or authenticates an existing device with matching keys.
    pub fn login_device(
        &self,
        account_id: Uuid,
        proof: &veil_proto::DeviceLogin,
        at: u64,
    ) -> Result<Device, StoreError> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        let device = &proof.keys;
        let existing: Option<(String, String, String, Option<i64>)> = tx
            .query_row(
                "SELECT account_id, seal_pk, auth_pk, revoked_at FROM devices WHERE id = ?1",
                params![device.id.to_string()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()?;
        match existing {
            Some((account, seal, auth, revoked)) => {
                if account != account_id.to_string()
                    || seal != device.seal_pk
                    || auth != device.auth_pk
                    || revoked.is_some()
                {
                    return Err(StoreError::Forbidden);
                }
                if proof.promote {
                    insert(
                        &tx,
                        "UPDATE devices SET owner = 1 WHERE id = ?1",
                        params![device.id.to_string()],
                    )?;
                }
            }
            None => insert_device(&tx, account_id, device, true, None, at)?,
        }
        tx.execute(
            "DELETE FROM request_nonces WHERE expires_at <= ?1",
            params![at as i64],
        )?;
        let inserted = tx.execute(
            "INSERT OR IGNORE INTO request_nonces (device_id, nonce, expires_at) VALUES (?1, ?2, ?3)",
            params![device.id.to_string(), proof.nonce, (at + 600) as i64],
        )?;
        if inserted == 0 {
            return Err(StoreError::Conflict);
        }
        tx.commit()?;
        drop(conn);
        self.device(device.id)
    }

    /// The code an approved device enrolled with.
    pub fn device_code(&self, device_id: Uuid) -> Result<String, StoreError> {
        self.conn()
            .query_row(
                "SELECT code FROM devices WHERE id = ?1",
                params![device_id.to_string()],
                |row| row.get::<_, Option<String>>(0),
            )
            .optional()?
            .flatten()
            .ok_or(StoreError::NotFound)
    }

    /// The sign-in address and Grants an approved device collects.
    pub fn enrollment(&self, device_id: Uuid) -> Result<(String, Vec<Grant>), StoreError> {
        let conn = self.conn();
        let (account_id, email): (String, String) = conn
            .query_row(
                "SELECT a.id, a.email FROM devices d JOIN accounts a ON a.id = d.account_id
                 WHERE d.id = ?1",
                params![device_id.to_string()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?
            .ok_or(StoreError::NotFound)?;
        let grants = load_grants(&conn, parse_id(account_id), Scope::Granted(device_id))?;
        Ok((email, grants))
    }

    /// Revokes a device: its Grants go at once and every Vault it could read is due a rotation.
    /// Revoking an absent or already revoked device succeeds.
    pub fn revoke_device(&self, account_id: Uuid, id: Uuid, at: u64) -> Result<(), StoreError> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        let changed = insert(
            &tx,
            "UPDATE devices SET revoked_at = ?3
             WHERE id = ?1 AND account_id = ?2 AND revoked_at IS NULL",
            params![id.to_string(), account_id.to_string(), at as i64],
        )?;
        if changed > 0 {
            insert(
                &tx,
                "DELETE FROM sessions WHERE device_id = ?1",
                params![id.to_string()],
            )?;
            insert(
                &tx,
                "UPDATE vaults SET rotation_due = 1 WHERE account_id = ?1
                 AND EXISTS (SELECT 1 FROM devices WHERE id = ?2 AND owner = 1)",
                params![account_id.to_string(), id.to_string()],
            )?;
            drop_principal_grants(&tx, account_id, id)?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Records a nonce so a signed request cannot be replayed.
    pub fn use_nonce(&self, device: Uuid, nonce: &str, at: u64) -> Result<(), StoreError> {
        let conn = self.conn();
        conn.execute(
            "DELETE FROM request_nonces WHERE expires_at <= ?1",
            params![at as i64],
        )?;
        let inserted = conn.execute(
            "INSERT OR IGNORE INTO request_nonces (device_id, nonce, expires_at) VALUES (?1, ?2, ?3)",
            params![device.to_string(), nonce, (at + 300) as i64],
        )?;
        if inserted == 0 {
            return Err(StoreError::Conflict);
        }
        Ok(())
    }

    // ----- vaults and items -----
}

fn take_pending(
    conn: &Connection,
    account_id: Uuid,
    code: &str,
    at: u64,
) -> Result<DeviceKeys, StoreError> {
    let device = conn
        .query_row(
            "SELECT id, name, seal_pk, auth_pk FROM pending_devices
             WHERE account_id = ?1 AND code = ?2 AND expires_at > ?3",
            params![account_id.to_string(), code, at as i64],
            |row| {
                Ok(DeviceKeys {
                    id: parse_id(row.get(0)?),
                    name: row.get(1)?,
                    seal_pk: row.get(2)?,
                    auth_pk: row.get(3)?,
                })
            },
        )
        .optional()?
        .ok_or(StoreError::NotFound)?;
    insert(
        conn,
        "DELETE FROM pending_devices WHERE account_id = ?1 AND code = ?2",
        params![account_id.to_string(), code],
    )?;
    Ok(device)
}

pub(super) fn insert_device(
    conn: &Connection,
    account_id: Uuid,
    device: &DeviceKeys,
    owner: bool,
    code: Option<&str>,
    at: u64,
) -> Result<(), StoreError> {
    insert(
        conn,
        "INSERT INTO devices (id, account_id, name, seal_pk, auth_pk, owner, code, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            device.id.to_string(),
            account_id.to_string(),
            device.name,
            device.seal_pk,
            device.auth_pk,
            owner,
            code,
            at as i64,
        ],
    )?;
    Ok(())
}

fn new_device(device: &DeviceKeys, owner: bool, at: u64) -> Device {
    Device {
        id: device.id,
        name: device.name.clone(),
        seal_pk: device.seal_pk.clone(),
        auth_pk: device.auth_pk.clone(),
        created_at: at,
        revoked_at: None,
        owner,
    }
}

fn device_row_at(row: &Row<'_>, offset: usize) -> rusqlite::Result<Device> {
    Ok(Device {
        id: parse_id(row.get(offset)?),
        name: row.get(offset + 1)?,
        seal_pk: row.get(offset + 2)?,
        auth_pk: row.get(offset + 3)?,
        created_at: row.get::<_, i64>(offset + 4)? as u64,
        revoked_at: row
            .get::<_, Option<i64>>(offset + 5)?
            .map(|value| value as u64),
        owner: row.get(offset + 6)?,
    })
}
