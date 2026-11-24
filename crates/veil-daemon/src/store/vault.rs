//! Vaults and the Grants that open them, including key rotation.

use super::*;

impl Store {
    /// Creates a Vault with its first Items and Grants. Replaying the same create returns the
    /// existing Vault; the flag says whether this call created it.
    pub fn create_vault(
        &self,
        account_id: Uuid,
        request: &CreateVaultRequest,
        at_ms: u64,
    ) -> Result<(Vault, bool), StoreError> {
        let at = at_ms / 1000;
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        if let Some((owner, vault)) = find_vault(&tx, request.id)? {
            if owner == account_id
                && vault.name == request.name
                && vault.account_key_wrap.as_deref() == Some(request.account_key_wrap.as_str())
            {
                return Ok((vault, false));
            }
            return Err(StoreError::Conflict);
        }

        let seq = next_revision(&tx, account_id)?;
        insert(
            &tx,
            "INSERT INTO vaults (id, account_id, name, account_key_wrap, revision, key_generation,
                rotation_due, created_at, changed_ms) VALUES (?1, ?2, ?3, ?4, 1, 1, 0, ?5, ?6)",
            params![
                request.id.to_string(),
                account_id.to_string(),
                request.name,
                request.account_key_wrap,
                at as i64,
                at_ms as i64,
            ],
        )?;
        for item in &request.items {
            insert(
                &tx,
                "INSERT INTO items (id, vault_id, item_type, key, data, revision, favorite,
                    folder_id, deleted_ms, created_ms, revised_ms, seq)
                 VALUES (?1, ?2, ?3, ?4, ?5, 1, ?6, ?7, NULL, ?8, ?8, ?9)",
                params![
                    item.id.to_string(),
                    request.id.to_string(),
                    item.item_type,
                    item.key,
                    item.data,
                    item.favorite,
                    item.folder_id.map(|id| id.to_string()),
                    at_ms as i64,
                    seq as i64,
                ],
            )?;
        }
        for grant in &request.grants {
            if grant.vault_id != request.id {
                return Err(StoreError::Invalid("a grant names a different vault"));
            }
            insert_grant(&tx, account_id, grant, at, seq)?;
        }
        let vault = load_vault(&tx, account_id, request.id)?;
        tx.commit()?;
        Ok((vault, true))
    }

    /// Renames a Vault.
    pub fn update_vault(
        &self,
        account_id: Uuid,
        id: Uuid,
        request: &UpdateVaultRequest,
        at_ms: u64,
    ) -> Result<Vault, StoreError> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        let vault = load_vault(&tx, account_id, id)?;
        if vault.revision != request.expected_revision {
            return Err(StoreError::Conflict);
        }
        next_revision(&tx, account_id)?;
        insert(
            &tx,
            "UPDATE vaults SET name = ?2, policy = COALESCE(?4, policy), revision = revision + 1,
                changed_ms = ?3 WHERE id = ?1",
            params![id.to_string(), request.name, at_ms as i64, request.policy],
        )?;
        let vault = load_vault(&tx, account_id, id)?;
        tx.commit()?;
        Ok(vault)
    }

    /// Removes a Vault, its Items, and its Grants. Audit rows stay. Absent Vaults succeed.
    pub fn delete_vault(&self, account_id: Uuid, id: Uuid) -> Result<(), StoreError> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        match find_vault(&tx, id)? {
            Some((owner, _)) if owner == account_id => {}
            _ => return Ok(()),
        }
        let seq = next_revision(&tx, account_id)?;
        let items = query(
            &tx,
            "SELECT id FROM items WHERE vault_id = ?1",
            &[id.to_string().into()],
            |row| Ok(parse_id(row.get(0)?)),
        )?;
        for item in items {
            record_change(&tx, account_id, seq, CHANGE_DELETED, item, id, None)?;
        }
        delete_vault_grants(&tx, account_id, id, seq)?;
        record_change(&tx, account_id, seq, CHANGE_DELETED, id, id, None)?;
        insert(
            &tx,
            "DELETE FROM items WHERE vault_id = ?1",
            params![id.to_string()],
        )?;
        insert(
            &tx,
            "DELETE FROM vaults WHERE id = ?1",
            params![id.to_string()],
        )?;
        insert(
            &tx,
            "DELETE FROM folders WHERE vault_id = ?1",
            params![id.to_string()],
        )?;
        if bound_vault(&tx, account_id)? == Some(id) {
            unbind(&tx, account_id)?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Moves a Vault to a new key generation, atomically: every Item key is replaced, the
    /// Grants are replaced, and `rotation_due` is cleared. Item data is untouched.
    pub fn rotate_vault(
        &self,
        account_id: Uuid,
        id: Uuid,
        request: &RotateVaultRequest,
        at_ms: u64,
    ) -> Result<Vault, StoreError> {
        let at = at_ms / 1000;
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        let vault = load_vault(&tx, account_id, id)?;
        if vault.revision != request.expected_revision
            || vault.key_generation != request.expected_key_generation
        {
            return Err(StoreError::Conflict);
        }

        let current: BTreeSet<Uuid> = query(
            &tx,
            "SELECT id FROM items WHERE vault_id = ?1",
            &[id.to_string().into()],
            |row| Ok(parse_id(row.get(0)?)),
        )?
        .into_iter()
        .collect();
        let offered: BTreeSet<Uuid> = request.items.iter().map(|item| item.id).collect();
        if offered.len() != request.items.len() {
            return Err(StoreError::Invalid("an item key appears twice"));
        }
        if offered != current {
            return Err(StoreError::Invalid(
                "the rotation must carry a key for every item in the vault and no other",
            ));
        }

        let bound = bound_vault(&tx, account_id)? == Some(id);
        match (&request.bitwarden, bound) {
            (None, true) => {
                return Err(StoreError::Invalid(
                    "this vault is the one Bitwarden clients see: the rotation must carry their new keys",
                ));
            }
            (Some(_), false) => {
                return Err(StoreError::Invalid(
                    "bitwarden keys are only for the vault Bitwarden clients see",
                ));
            }
            (Some(keys), true) => {
                if keys.vault_id != id {
                    return Err(StoreError::Invalid(
                        "the bitwarden keys name a different vault",
                    ));
                }
                bind(&tx, account_id, keys, at_ms)?;
            }
            (None, false) => {}
        }

        let generation = vault.key_generation + 1;
        let seq = next_revision(&tx, account_id)?;
        delete_vault_grants(&tx, account_id, id, seq)?;
        insert(
            &tx,
            "UPDATE vaults SET name = ?2, account_key_wrap = ?3, key_generation = ?4,
                policy = ?6, rotation_due = 0, revision = revision + 1, changed_ms = ?5 WHERE id = ?1",
            params![
                id.to_string(),
                request.name,
                request.account_key_wrap,
                generation as i64,
                at_ms as i64,
                request.policy,
            ],
        )?;
        let revision = vault.revision + 1;
        for item in &request.items {
            insert(
                &tx,
                "UPDATE items SET key = ?2, revision = ?3, revised_ms = ?4, seq = ?5
                 WHERE id = ?1",
                params![
                    item.id.to_string(),
                    item.key,
                    revision as i64,
                    at_ms as i64,
                    seq as i64,
                ],
            )?;
        }
        for grant in &request.grants {
            if grant.vault_id != id {
                return Err(StoreError::Invalid("a grant names a different vault"));
            }
            insert_grant(&tx, account_id, grant, at, seq)?;
        }
        record_change(&tx, account_id, seq, CHANGE_ROTATED, id, id, None)?;
        let vault = load_vault(&tx, account_id, id)?;
        tx.commit()?;
        Ok(vault)
    }

    // ----- sync -----
}

/// Inserts one Grant after checking its Vault, key generation, and principal.
pub(super) fn insert_grant(
    conn: &Connection,
    account_id: Uuid,
    grant: &GrantWrite,
    at: u64,
    seq: u64,
) -> Result<(), StoreError> {
    let vault = load_vault(conn, account_id, grant.vault_id)?;
    if grant.key_generation != vault.key_generation {
        return Err(StoreError::Invalid(
            "a grant's key generation is not the vault's",
        ));
    }
    let principal = principal_live(conn, account_id, grant.principal_id)?;
    if !principal {
        return Err(StoreError::Invalid(
            "a grant names an unknown or revoked principal",
        ));
    }
    insert(
        conn,
        "INSERT INTO grants (id, vault_id, principal_id, key_generation, wrapped_key, created_at,
            seq) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            Uuid::now_v7().to_string(),
            grant.vault_id.to_string(),
            grant.principal_id.to_string(),
            grant.key_generation as i64,
            grant.wrapped_key,
            at as i64,
            seq as i64,
        ],
    )?;
    Ok(())
}

/// Whether a Device or Workload of this Account exists and is not revoked.
fn principal_live(conn: &Connection, account_id: Uuid, id: Uuid) -> Result<bool, StoreError> {
    let count: i64 = conn.query_row(
        "SELECT (SELECT COUNT(*) FROM devices
                 WHERE id = ?1 AND account_id = ?2 AND revoked_at IS NULL)
              + (SELECT COUNT(*) FROM workloads
                 WHERE id = ?1 AND account_id = ?2 AND revoked_at IS NULL)",
        params![id.to_string(), account_id.to_string()],
        |row| row.get(0),
    )?;
    Ok(count > 0)
}

/// Deletes every Grant on a Vault and records each deletion for the principal that held it.
fn delete_vault_grants(
    conn: &Connection,
    account_id: Uuid,
    vault_id: Uuid,
    seq: u64,
) -> Result<(), StoreError> {
    let grants = query(
        conn,
        "SELECT id, principal_id FROM grants WHERE vault_id = ?1",
        &[vault_id.to_string().into()],
        |row| Ok((parse_id(row.get(0)?), parse_id(row.get(1)?))),
    )?;
    for (grant, principal) in grants {
        record_change(
            conn,
            account_id,
            seq,
            CHANGE_DELETED,
            grant,
            vault_id,
            Some(principal),
        )?;
    }
    insert(
        conn,
        "DELETE FROM grants WHERE vault_id = ?1",
        params![vault_id.to_string()],
    )?;
    Ok(())
}

/// Deletes a revoked principal's Grants and marks every Vault they opened as due a rotation.
pub(super) fn drop_principal_grants(
    conn: &Connection,
    account_id: Uuid,
    principal_id: Uuid,
) -> Result<(), StoreError> {
    let grants = query(
        conn,
        "SELECT g.id, g.vault_id FROM grants g JOIN vaults v ON v.id = g.vault_id
         WHERE g.principal_id = ?1 AND v.account_id = ?2",
        &[
            principal_id.to_string().into(),
            account_id.to_string().into(),
        ],
        |row| Ok((parse_id(row.get(0)?), parse_id(row.get(1)?))),
    )?;
    if grants.is_empty() {
        return Ok(());
    }
    let seq = next_revision(conn, account_id)?;
    for (grant, vault) in grants {
        record_change(
            conn,
            account_id,
            seq,
            CHANGE_DELETED,
            grant,
            vault,
            Some(principal_id),
        )?;
        insert(
            conn,
            "UPDATE vaults SET rotation_due = 1 WHERE id = ?1",
            params![vault.to_string()],
        )?;
        insert(
            conn,
            "DELETE FROM grants WHERE id = ?1",
            params![grant.to_string()],
        )?;
    }
    Ok(())
}

const VAULT_COLUMNS: &str =
    "v.id, v.name, v.revision, v.key_generation, v.rotation_due, v.account_key_wrap, v.policy";

fn vault_row(row: &Row<'_>, with_wrap: bool) -> rusqlite::Result<Vault> {
    Ok(Vault {
        id: parse_id(row.get(0)?),
        name: row.get(1)?,
        revision: row.get::<_, i64>(2)? as u64,
        key_generation: row.get::<_, i64>(3)? as u32,
        rotation_due: row.get(4)?,
        account_key_wrap: if with_wrap { Some(row.get(5)?) } else { None },
        policy: row.get(6)?,
    })
}

/// A Vault by id in any Account, with the Account that owns it.
pub(super) fn find_vault(conn: &Connection, id: Uuid) -> Result<Option<(Uuid, Vault)>, StoreError> {
    Ok(conn
        .query_row(
            &format!("SELECT {VAULT_COLUMNS}, v.account_id FROM vaults v WHERE v.id = ?1"),
            params![id.to_string()],
            |row| Ok((parse_id(row.get(7)?), vault_row(row, true)?)),
        )
        .optional()?)
}

/// A Vault of this Account, as the Owner sees it.
pub(super) fn load_vault(
    conn: &Connection,
    account_id: Uuid,
    id: Uuid,
) -> Result<Vault, StoreError> {
    match find_vault(conn, id)? {
        Some((owner, vault)) if owner == account_id => Ok(vault),
        _ => Err(StoreError::NotFound),
    }
}

pub(super) fn load_vaults(
    conn: &Connection,
    account_id: Uuid,
    scope: Scope,
) -> Result<Vec<Vault>, StoreError> {
    match scope {
        Scope::Owner => query(
            conn,
            &format!(
                "SELECT {VAULT_COLUMNS} FROM vaults v WHERE v.account_id = ?1 ORDER BY v.created_at"
            ),
            &[account_id.to_string().into()],
            |row| vault_row(row, true),
        ),
        Scope::Granted(principal) => query(
            conn,
            &format!(
                "SELECT {VAULT_COLUMNS} FROM vaults v JOIN grants g ON g.vault_id = v.id
                 WHERE v.account_id = ?1 AND g.principal_id = ?2 ORDER BY v.created_at"
            ),
            &[account_id.to_string().into(), principal.to_string().into()],
            |row| vault_row(row, false),
        ),
    }
}

pub(super) fn vault_readable(
    conn: &Connection,
    account_id: Uuid,
    scope: Scope,
    vault_id: Uuid,
) -> Result<bool, StoreError> {
    let count: i64 = match scope {
        Scope::Owner => conn.query_row(
            "SELECT COUNT(*) FROM vaults WHERE id = ?1 AND account_id = ?2",
            params![vault_id.to_string(), account_id.to_string()],
            |row| row.get(0),
        )?,
        Scope::Granted(principal) => conn.query_row(
            "SELECT COUNT(*) FROM vaults v JOIN grants g ON g.vault_id = v.id
             WHERE v.id = ?1 AND v.account_id = ?2 AND g.principal_id = ?3",
            params![
                vault_id.to_string(),
                account_id.to_string(),
                principal.to_string()
            ],
            |row| row.get(0),
        )?,
    };
    Ok(count > 0)
}
