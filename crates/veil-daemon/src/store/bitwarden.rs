//! What Bitwarden clients need stored: the binding of an Account to one Vault, their login
//! sessions, and folders. Cipher writes go through the same Item write path as the Veil API.
//!
//! Every key in the binding is sealed by the Owner's client and stored verbatim.

use rusqlite::{Connection, OptionalExtension, params};
use uuid::Uuid;
use veil_proto::{BitwardenStatus, EnableBitwardenRequest, Kdf};

use super::{
    ITEM_COLUMNS, ItemRecord, ItemState, Store, StoreError, find_item_record, hash, insert,
    item_record_row, kdf_at, load_vault, parse_id, query, remove_item, write_item,
};

/// The keys a Bitwarden login unlocks with, as the Owner's client prepared them.
#[derive(Debug, Clone)]
pub struct Binding {
    /// The one Vault the login sees.
    pub vault_id: Uuid,
    /// The Vault key wrapped by the master key.
    pub protected_key: String,
    /// The account's RSA private key wrapped by the Vault key.
    pub private_key: String,
    /// The account's RSA public key.
    pub public_key: String,
    /// The Bitwarden `AccountKeys` object, as JSON text.
    pub account_keys: String,
    /// The id the clients assigned to the user key, once they report it.
    pub user_key_id: Option<String>,
    /// Changes whenever the login's keys change, so clients drop stale state.
    pub security_stamp: String,
    /// Unix seconds.
    pub enabled_at: u64,
    /// Milliseconds of the last change to the binding.
    pub changed_ms: u64,
}

/// An Account as a Bitwarden login sees it.
#[derive(Debug, Clone)]
pub struct BitwardenAccount {
    /// Account id.
    pub id: Uuid,
    /// Sign-in address, normalized.
    pub email: String,
    /// Master key derivation.
    pub kdf: Kdf,
    /// Unix seconds.
    pub created_at: u64,
    /// The binding.
    pub binding: Binding,
}

/// A folder of the bound Vault. The name is sealed.
#[derive(Debug, Clone)]
pub struct Folder {
    /// Folder id.
    pub id: Uuid,
    /// Sealed name.
    pub name: String,
    /// Milliseconds of the last write.
    pub revised_ms: u64,
}

const BINDING_COLUMNS: &str = "b.vault_id, b.protected_key, b.private_key, b.public_key,
    b.account_keys, b.user_key_id, b.security_stamp, b.enabled_at, b.changed_ms";

fn binding_row(row: &rusqlite::Row<'_>, offset: usize) -> rusqlite::Result<Binding> {
    Ok(Binding {
        vault_id: parse_id(row.get(offset)?),
        protected_key: row.get(offset + 1)?,
        private_key: row.get(offset + 2)?,
        public_key: row.get(offset + 3)?,
        account_keys: row.get(offset + 4)?,
        user_key_id: row.get(offset + 5)?,
        security_stamp: row.get(offset + 6)?,
        enabled_at: row.get::<_, i64>(offset + 7)? as u64,
        changed_ms: row.get::<_, i64>(offset + 8)? as u64,
    })
}

fn load_binding(conn: &Connection, account_id: Uuid) -> Result<Option<Binding>, StoreError> {
    Ok(conn
        .query_row(
            &format!("SELECT {BINDING_COLUMNS} FROM bitwarden_bindings b WHERE b.account_id = ?1"),
            params![account_id.to_string()],
            |row| binding_row(row, 0),
        )
        .optional()?)
}

/// The Vault Bitwarden clients of this Account see, if any.
pub(super) fn bound_vault(conn: &Connection, account_id: Uuid) -> Result<Option<Uuid>, StoreError> {
    Ok(conn
        .query_row(
            "SELECT vault_id FROM bitwarden_bindings WHERE account_id = ?1",
            params![account_id.to_string()],
            |row| Ok(parse_id(row.get(0)?)),
        )
        .optional()?)
}

/// The bound Vault, or `NotFound` when Bitwarden clients are not enabled.
fn require_bound(conn: &Connection, account_id: Uuid) -> Result<Uuid, StoreError> {
    bound_vault(conn, account_id)?.ok_or(StoreError::NotFound)
}

/// Creates or replaces the binding and signs every Bitwarden client out.
pub(super) fn bind(
    conn: &Connection,
    account_id: Uuid,
    keys: &EnableBitwardenRequest,
    at_ms: u64,
) -> Result<(), StoreError> {
    // The client copies `AccountKeys` into its state as JSON; refuse what it could not read.
    if serde_json::from_str::<serde_json::Value>(&keys.account_keys).is_err() {
        return Err(StoreError::Invalid("account_keys must be JSON text"));
    }
    insert(
        conn,
        "INSERT INTO bitwarden_bindings (account_id, vault_id, protected_key, private_key,
            public_key, account_keys, user_key_id, security_stamp, enabled_at, changed_ms)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL, ?7, ?8, ?9)
         ON CONFLICT (account_id) DO UPDATE SET vault_id = excluded.vault_id,
            protected_key = excluded.protected_key, private_key = excluded.private_key,
            public_key = excluded.public_key, account_keys = excluded.account_keys,
            user_key_id = NULL, security_stamp = excluded.security_stamp,
            enabled_at = CASE WHEN bitwarden_bindings.vault_id = excluded.vault_id
                THEN bitwarden_bindings.enabled_at ELSE excluded.enabled_at END,
            changed_ms = excluded.changed_ms",
        params![
            account_id.to_string(),
            keys.vault_id.to_string(),
            keys.protected_key,
            keys.private_key,
            keys.public_key,
            keys.account_keys,
            Uuid::now_v7().to_string(),
            (at_ms / 1000) as i64,
            at_ms as i64,
        ],
    )?;
    revoke_bitwarden_sessions(conn, account_id)
}

/// Removes the binding and signs every Bitwarden client out.
pub(super) fn unbind(conn: &Connection, account_id: Uuid) -> Result<(), StoreError> {
    insert(
        conn,
        "DELETE FROM bitwarden_bindings WHERE account_id = ?1",
        params![account_id.to_string()],
    )?;
    revoke_bitwarden_sessions(conn, account_id)
}

/// Ends every Bitwarden login of the Account: access and refresh tokens alike.
pub(super) fn revoke_bitwarden_sessions(
    conn: &Connection,
    account_id: Uuid,
) -> Result<(), StoreError> {
    insert(
        conn,
        "DELETE FROM bitwarden_sessions WHERE account_id = ?1",
        params![account_id.to_string()],
    )?;
    Ok(())
}

/// Moves the bound Vault's change time, which the clients poll as the revision date.
fn touch_vault(conn: &Connection, vault_id: Uuid, at_ms: u64) -> Result<(), StoreError> {
    insert(
        conn,
        "UPDATE vaults SET changed_ms = MAX(changed_ms, ?2) WHERE id = ?1",
        params![vault_id.to_string(), at_ms as i64],
    )?;
    Ok(())
}

/// An Item of the bound Vault; any other Item is `NotFound`.
fn bound_item(conn: &Connection, vault_id: Uuid, id: Uuid) -> Result<ItemRecord, StoreError> {
    match find_item_record(conn, id)? {
        Some(record) if record.item.vault_id == vault_id => Ok(record),
        _ => Err(StoreError::NotFound),
    }
}

fn status(
    conn: &Connection,
    account_id: Uuid,
    binding: &Binding,
) -> Result<BitwardenStatus, StoreError> {
    let two_step = conn
        .query_row(
            "SELECT 1 FROM bitwarden_two_step WHERE account_id = ?1",
            params![account_id.to_string()],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    Ok(BitwardenStatus {
        vault_id: binding.vault_id,
        enabled_at: binding.enabled_at,
        two_step,
    })
}

impl Store {
    // ----- binding -----

    /// Lets Bitwarden clients see one Vault of the Account, replacing any previous binding.
    pub fn enable_bitwarden(
        &self,
        account_id: Uuid,
        keys: &EnableBitwardenRequest,
        at_ms: u64,
    ) -> Result<BitwardenStatus, StoreError> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        load_vault(&tx, account_id, keys.vault_id)?;
        bind(&tx, account_id, keys, at_ms)?;
        let binding = load_binding(&tx, account_id)?.ok_or(StoreError::NotFound)?;
        let status = status(&tx, account_id, &binding)?;
        tx.commit()?;
        Ok(status)
    }

    /// Which Vault Bitwarden clients see, if any.
    pub fn bitwarden_status(
        &self,
        account_id: Uuid,
    ) -> Result<Option<BitwardenStatus>, StoreError> {
        let conn = self.conn();
        load_binding(&conn, account_id)?
            .map(|binding| status(&conn, account_id, &binding))
            .transpose()
    }

    // ----- two-step login -----

    /// Turns on two-step login with `secret`. `step` is the time step of the code that proved
    /// the authenticator holds it, so that code cannot also log in.
    pub fn enable_two_step(
        &self,
        account_id: Uuid,
        secret: &str,
        step: u64,
        at: u64,
    ) -> Result<(), StoreError> {
        self.conn().execute(
            "INSERT INTO bitwarden_two_step (account_id, secret, last_step, enabled_at)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT (account_id) DO UPDATE SET
                secret = excluded.secret, last_step = excluded.last_step,
                enabled_at = excluded.enabled_at",
            params![account_id.to_string(), secret, step as i64, at as i64],
        )?;
        Ok(())
    }

    /// Turns two-step login off. Turning it off twice succeeds.
    pub fn disable_two_step(&self, account_id: Uuid) -> Result<(), StoreError> {
        self.conn().execute(
            "DELETE FROM bitwarden_two_step WHERE account_id = ?1",
            params![account_id.to_string()],
        )?;
        Ok(())
    }

    /// The authenticator secret, when two-step login is on.
    pub fn two_step_secret(&self, account_id: Uuid) -> Result<Option<String>, StoreError> {
        Ok(self
            .conn()
            .query_row(
                "SELECT secret FROM bitwarden_two_step WHERE account_id = ?1",
                params![account_id.to_string()],
                |row| row.get(0),
            )
            .optional()?)
    }

    /// Spends the code of time step `step`: true only for a step later than every step spent
    /// before, so a code works once.
    pub fn spend_two_step(&self, account_id: Uuid, step: u64) -> Result<bool, StoreError> {
        let changed = self.conn().execute(
            "UPDATE bitwarden_two_step SET last_step = ?2
             WHERE account_id = ?1 AND last_step < ?2",
            params![account_id.to_string(), step as i64],
        )?;
        Ok(changed == 1)
    }

    /// Stops serving Bitwarden clients. Disabling twice succeeds.
    pub fn disable_bitwarden(&self, account_id: Uuid) -> Result<(), StoreError> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        unbind(&tx, account_id)?;
        tx.commit()?;
        Ok(())
    }

    /// The Account with its binding; `NotFound` without one.
    pub fn bitwarden_account(&self, account_id: Uuid) -> Result<BitwardenAccount, StoreError> {
        self.conn()
            .query_row(
                &format!(
                    "SELECT a.id, a.email, a.kdf, a.created_at, {BINDING_COLUMNS}
                     FROM accounts a JOIN bitwarden_bindings b ON b.account_id = a.id
                     WHERE a.id = ?1"
                ),
                params![account_id.to_string()],
                |row| {
                    Ok(BitwardenAccount {
                        id: parse_id(row.get(0)?),
                        email: row.get(1)?,
                        kdf: kdf_at(row, 2)?,
                        created_at: row.get::<_, i64>(3)? as u64,
                        binding: binding_row(row, 4)?,
                    })
                },
            )
            .optional()?
            .ok_or(StoreError::NotFound)
    }

    /// Records the id the clients gave the user key.
    pub fn set_user_key_id(
        &self,
        account_id: Uuid,
        user_key_id: &str,
        at_ms: u64,
    ) -> Result<(), StoreError> {
        let changed = insert(
            &self.conn(),
            "UPDATE bitwarden_bindings SET user_key_id = ?2, changed_ms = ?3 WHERE account_id = ?1",
            params![account_id.to_string(), user_key_id, at_ms as i64],
        )?;
        if changed == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    /// Milliseconds of the last change the clients would see: the bound Vault, its Items and
    /// folders, or the binding.
    pub fn bitwarden_revision_ms(&self, account_id: Uuid) -> Result<u64, StoreError> {
        self.conn()
            .query_row(
                "SELECT MAX(v.changed_ms, b.changed_ms) FROM bitwarden_bindings b
                 JOIN vaults v ON v.id = b.vault_id WHERE b.account_id = ?1",
                params![account_id.to_string()],
                |row| Ok(row.get::<_, i64>(0)? as u64),
            )
            .optional()?
            .ok_or(StoreError::NotFound)
    }

    // ----- sessions -----

    /// Starts a Bitwarden login; returns its session id, the access token's `jti`.
    pub fn create_bitwarden_session(
        &self,
        account_id: Uuid,
        refresh_token: &str,
        expires_at: u64,
    ) -> Result<Uuid, StoreError> {
        let id = Uuid::now_v7();
        insert(
            &self.conn(),
            "INSERT INTO bitwarden_sessions (id, account_id, refresh_hash, expires_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                id.to_string(),
                account_id.to_string(),
                hash(refresh_token),
                expires_at as i64,
            ],
        )?;
        Ok(id)
    }

    /// Swaps a live refresh token for a new one; the old one stops working. Returns the
    /// session and its Account.
    pub fn refresh_bitwarden_session(
        &self,
        refresh_token: &str,
        next_refresh_token: &str,
        at: u64,
        expires_at: u64,
    ) -> Result<Option<(Uuid, Uuid)>, StoreError> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        let Some((session, account)) = tx
            .query_row(
                "SELECT id, account_id FROM bitwarden_sessions
                 WHERE refresh_hash = ?1 AND expires_at > ?2",
                params![hash(refresh_token), at as i64],
                |row| Ok((parse_id(row.get(0)?), parse_id(row.get(1)?))),
            )
            .optional()?
        else {
            return Ok(None);
        };
        insert(
            &tx,
            "UPDATE bitwarden_sessions SET refresh_hash = ?2, expires_at = ?3 WHERE id = ?1",
            params![
                session.to_string(),
                hash(next_refresh_token),
                expires_at as i64,
            ],
        )?;
        tx.commit()?;
        Ok(Some((session, account)))
    }

    /// Whether a Bitwarden session is live and still has a binding behind it.
    pub fn bitwarden_session_live(
        &self,
        session: Uuid,
        account_id: Uuid,
        at: u64,
    ) -> Result<bool, StoreError> {
        let count: i64 = self.conn().query_row(
            "SELECT COUNT(*) FROM bitwarden_sessions s
             JOIN bitwarden_bindings b ON b.account_id = s.account_id
             WHERE s.id = ?1 AND s.account_id = ?2 AND s.expires_at > ?3",
            params![session.to_string(), account_id.to_string(), at as i64],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }

    // ----- ciphers -----

    /// Every Item of the bound Vault, trashed ones included.
    pub fn bitwarden_items(&self, account_id: Uuid) -> Result<Vec<ItemRecord>, StoreError> {
        let conn = self.conn();
        let vault_id = require_bound(&conn, account_id)?;
        query(
            &conn,
            &format!("SELECT {ITEM_COLUMNS} FROM items i WHERE i.vault_id = ?1 ORDER BY i.id"),
            &[vault_id.to_string().into()],
            item_record_row,
        )
    }

    /// One Item of the bound Vault.
    pub fn bitwarden_item(&self, account_id: Uuid, id: Uuid) -> Result<ItemRecord, StoreError> {
        let conn = self.conn();
        let vault_id = require_bound(&conn, account_id)?;
        bound_item(&conn, vault_id, id)
    }

    /// Creates an Item in the bound Vault with a service-assigned id.
    pub fn bitwarden_create_item(
        &self,
        account_id: Uuid,
        state: &ItemState,
        at_ms: u64,
    ) -> Result<ItemRecord, StoreError> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        let vault_id = require_bound(&tx, account_id)?;
        let record = write_item(&tx, account_id, vault_id, Uuid::now_v7(), state, at_ms)?;
        tx.commit()?;
        Ok(record)
    }

    /// Imports Items and folders into the bound Vault in one transaction: all or none. A folder
    /// keeps its id when that id names a folder of this Vault; otherwise it is created. Each
    /// Item names its folder by index into `folders`.
    pub fn bitwarden_import(
        &self,
        account_id: Uuid,
        folders: &[(Option<Uuid>, String)],
        items: &[(ItemState, Option<usize>)],
        at_ms: u64,
    ) -> Result<usize, StoreError> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        let vault_id = require_bound(&tx, account_id)?;
        let mut folder_ids = Vec::with_capacity(folders.len());
        for (id, name) in folders {
            let existing = match id {
                Some(id) => tx
                    .query_row(
                        "SELECT 1 FROM folders WHERE id = ?1 AND vault_id = ?2",
                        params![id.to_string(), vault_id.to_string()],
                        |_| Ok(()),
                    )
                    .optional()?
                    .map(|()| *id),
                None => None,
            };
            let folder_id = match existing {
                Some(id) => id,
                None => {
                    let id = Uuid::now_v7();
                    insert(
                        &tx,
                        "INSERT INTO folders (id, vault_id, name, revised_ms) VALUES (?1, ?2, ?3, ?4)",
                        params![id.to_string(), vault_id.to_string(), name, at_ms as i64],
                    )?;
                    id
                }
            };
            folder_ids.push(folder_id);
        }
        for (state, folder) in items {
            let mut state = state.clone();
            state.folder_id = match folder {
                Some(index) => Some(
                    *folder_ids
                        .get(*index)
                        .ok_or(StoreError::Invalid("a folder relationship names no folder"))?,
                ),
                None => None,
            };
            write_item(&tx, account_id, vault_id, Uuid::now_v7(), &state, at_ms)?;
        }
        touch_vault(&tx, vault_id, at_ms)?;
        tx.commit()?;
        Ok(items.len())
    }

    /// Rewrites one Item of the bound Vault from its current state.
    pub fn bitwarden_update_item(
        &self,
        account_id: Uuid,
        id: Uuid,
        at_ms: u64,
        change: impl FnOnce(&ItemRecord) -> Result<ItemState, StoreError>,
    ) -> Result<ItemRecord, StoreError> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        let vault_id = require_bound(&tx, account_id)?;
        let current = bound_item(&tx, vault_id, id)?;
        let state = change(&current)?;
        let record = write_item(
            &tx,
            account_id,
            vault_id,
            id,
            &state,
            next_revision(&current, at_ms),
        )?;
        tx.commit()?;
        Ok(record)
    }

    /// Rewrites several Items of the bound Vault at once. Ids outside it are skipped, as the
    /// Bitwarden service does.
    pub fn bitwarden_update_items(
        &self,
        account_id: Uuid,
        ids: &[Uuid],
        at_ms: u64,
        change: impl Fn(&ItemRecord) -> ItemState,
    ) -> Result<Vec<ItemRecord>, StoreError> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        let vault_id = require_bound(&tx, account_id)?;
        let mut out = Vec::with_capacity(ids.len());
        for id in ids {
            let Ok(current) = bound_item(&tx, vault_id, *id) else {
                continue;
            };
            let state = change(&current);
            let at = next_revision(&current, at_ms);
            out.push(write_item(&tx, account_id, vault_id, *id, &state, at)?);
        }
        tx.commit()?;
        Ok(out)
    }

    /// Removes one Item of the bound Vault for good.
    pub fn bitwarden_delete_item(
        &self,
        account_id: Uuid,
        id: Uuid,
        at_ms: u64,
    ) -> Result<(), StoreError> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        let vault_id = require_bound(&tx, account_id)?;
        bound_item(&tx, vault_id, id)?;
        remove_item(&tx, account_id, vault_id, id, at_ms)?;
        tx.commit()?;
        Ok(())
    }

    // ----- folders -----

    /// The folders of the bound Vault.
    pub fn bitwarden_folders(&self, account_id: Uuid) -> Result<Vec<Folder>, StoreError> {
        let conn = self.conn();
        let vault_id = require_bound(&conn, account_id)?;
        query(
            &conn,
            "SELECT id, name, revised_ms FROM folders WHERE vault_id = ?1 ORDER BY id",
            &[vault_id.to_string().into()],
            |row| {
                Ok(Folder {
                    id: parse_id(row.get(0)?),
                    name: row.get(1)?,
                    revised_ms: row.get::<_, i64>(2)? as u64,
                })
            },
        )
    }

    /// Creates a folder in the bound Vault.
    pub fn bitwarden_create_folder(
        &self,
        account_id: Uuid,
        name: &str,
        at_ms: u64,
    ) -> Result<Folder, StoreError> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        let vault_id = require_bound(&tx, account_id)?;
        let id = Uuid::now_v7();
        insert(
            &tx,
            "INSERT INTO folders (id, vault_id, name, revised_ms) VALUES (?1, ?2, ?3, ?4)",
            params![id.to_string(), vault_id.to_string(), name, at_ms as i64],
        )?;
        touch_vault(&tx, vault_id, at_ms)?;
        tx.commit()?;
        Ok(Folder {
            id,
            name: name.to_owned(),
            revised_ms: at_ms,
        })
    }

    /// Renames a folder of the bound Vault.
    pub fn bitwarden_rename_folder(
        &self,
        account_id: Uuid,
        id: Uuid,
        name: &str,
        at_ms: u64,
    ) -> Result<Folder, StoreError> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        let vault_id = require_bound(&tx, account_id)?;
        let changed = insert(
            &tx,
            "UPDATE folders SET name = ?3, revised_ms = ?4 WHERE id = ?1 AND vault_id = ?2",
            params![id.to_string(), vault_id.to_string(), name, at_ms as i64],
        )?;
        if changed == 0 {
            return Err(StoreError::NotFound);
        }
        touch_vault(&tx, vault_id, at_ms)?;
        tx.commit()?;
        Ok(Folder {
            id,
            name: name.to_owned(),
            revised_ms: at_ms,
        })
    }

    /// Deletes a folder of the bound Vault; its Items leave it through the Item write path.
    pub fn bitwarden_delete_folder(
        &self,
        account_id: Uuid,
        id: Uuid,
        at_ms: u64,
    ) -> Result<(), StoreError> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        let vault_id = require_bound(&tx, account_id)?;
        let changed = insert(
            &tx,
            "DELETE FROM folders WHERE id = ?1 AND vault_id = ?2",
            params![id.to_string(), vault_id.to_string()],
        )?;
        if changed == 0 {
            return Err(StoreError::NotFound);
        }
        let filed = query(
            &tx,
            &format!(
                "SELECT {ITEM_COLUMNS} FROM items i WHERE i.vault_id = ?1 AND i.folder_id = ?2"
            ),
            &[vault_id.to_string().into(), id.to_string().into()],
            item_record_row,
        )?;
        for record in filed {
            let item = record.item;
            let state = ItemState {
                item_type: item.item_type,
                key: item.key,
                data: item.data,
                favorite: item.favorite,
                folder_id: None,
                deleted_ms: record.deleted_ms,
            };
            write_item(&tx, account_id, vault_id, item.id, &state, at_ms)?;
        }
        touch_vault(&tx, vault_id, at_ms)?;
        tx.commit()?;
        Ok(())
    }
}

/// A write's revision date: now, but always later than the stored one. Clients detect stale
/// copies by comparing millisecond revision dates, so two writes in the same millisecond must
/// not share one.
fn next_revision(current: &ItemRecord, at_ms: u64) -> u64 {
    at_ms.max(current.revised_ms + 1)
}
