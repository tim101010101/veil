//! Item writes, shared by the Veil API and the Bitwarden client API.

use super::*;

impl Store {
    /// Creates or replaces one Item. The flag says whether this call created it.
    ///
    /// `expected_revision: 0` creates; replaying an identical create returns the existing Item.
    pub fn put_item(
        &self,
        account_id: Uuid,
        vault_id: Uuid,
        item_id: Uuid,
        request: &PutItemRequest,
        at_ms: u64,
    ) -> Result<(Item, bool), StoreError> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        load_vault(&tx, account_id, vault_id)?;
        let existing = find_item_record(&tx, item_id)?;
        if existing
            .as_ref()
            .is_some_and(|record| record.item.vault_id != vault_id)
        {
            return Err(StoreError::NotFound);
        }
        let deleted_ms = existing.as_ref().and_then(|record| record.deleted_ms);
        let created = match existing.as_ref().map(|record| &record.item) {
            None if request.expected_revision == 0 => true,
            None => return Err(StoreError::Conflict),
            Some(item) if request.expected_revision == 0 => {
                if same_content(item, request) {
                    return Ok((item.clone(), false));
                }
                return Err(StoreError::Conflict);
            }
            Some(item) if item.revision != request.expected_revision => {
                return Err(StoreError::Conflict);
            }
            Some(_) => false,
        };

        // The Veil API never sets the trash date; a write keeps the one Bitwarden clients set.
        let record = write_item(
            &tx,
            account_id,
            vault_id,
            item_id,
            &ItemState {
                item_type: request.item_type,
                key: request.key.clone(),
                data: request.data.clone(),
                favorite: request.favorite,
                folder_id: request.folder_id,
                deleted_ms,
            },
            at_ms,
        )?;
        tx.commit()?;
        Ok((record.item, created))
    }

    /// Removes one Item. An absent Item, or an absent Vault, succeeds.
    pub fn delete_item(
        &self,
        account_id: Uuid,
        vault_id: Uuid,
        item_id: Uuid,
        at_ms: u64,
    ) -> Result<(), StoreError> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        match find_vault(&tx, vault_id)? {
            Some((owner, _)) if owner == account_id => {}
            _ => return Ok(()),
        }
        let Some(item) = find_item(&tx, item_id)? else {
            return Ok(());
        };
        if item.vault_id != vault_id {
            return Err(StoreError::NotFound);
        }
        remove_item(&tx, account_id, vault_id, item_id, at_ms)?;
        tx.commit()?;
        Ok(())
    }
}

pub(super) const ITEM_COLUMNS: &str =
    "i.id, i.vault_id, i.item_type, i.key, i.data, i.revision, i.favorite,
    i.folder_id, i.deleted_ms, i.revised_ms, i.created_ms";

fn item_row(row: &Row<'_>) -> rusqlite::Result<Item> {
    item_record_row(row).map(|record| record.item)
}

pub(super) fn item_record_row(row: &Row<'_>) -> rusqlite::Result<ItemRecord> {
    let deleted_ms = row.get::<_, Option<i64>>(8)?.map(|value| value as u64);
    let revised_ms = row.get::<_, i64>(9)? as u64;
    Ok(ItemRecord {
        item: Item {
            id: parse_id(row.get(0)?),
            vault_id: parse_id(row.get(1)?),
            item_type: row.get(2)?,
            key: row.get(3)?,
            data: row.get(4)?,
            revision: row.get::<_, i64>(5)? as u64,
            favorite: row.get(6)?,
            folder_id: row.get::<_, Option<String>>(7)?.map(parse_id),
            deleted_at: deleted_ms.map(|ms| ms / 1000),
            revised_at: revised_ms / 1000,
        },
        deleted_ms,
        revised_ms,
        created_ms: row.get::<_, i64>(10)? as u64,
    })
}

pub(super) fn find_item(conn: &Connection, id: Uuid) -> Result<Option<Item>, StoreError> {
    Ok(find_item_record(conn, id)?.map(|record| record.item))
}

pub(super) fn find_item_record(
    conn: &Connection,
    id: Uuid,
) -> Result<Option<ItemRecord>, StoreError> {
    Ok(conn
        .query_row(
            &format!("SELECT {ITEM_COLUMNS} FROM items i WHERE i.id = ?1"),
            params![id.to_string()],
            item_record_row,
        )
        .optional()?)
}

/// Everything one Item write stores.
#[derive(Debug, Clone)]
pub struct ItemState {
    /// Bitwarden `CipherType`.
    pub item_type: u8,
    /// Item key wrapped by the Vault key, opaque.
    pub key: String,
    /// The sealed record container, opaque.
    pub data: String,
    /// Favorite flag.
    pub favorite: bool,
    /// Folder, when filed in one.
    pub folder_id: Option<Uuid>,
    /// Milliseconds, when moved to the trash.
    pub deleted_ms: Option<u64>,
}

/// The one Item write path, for the Veil and Bitwarden APIs alike: the Account cursor, the Vault
/// revision and change time, and the Item's revision and write time all move together. The
/// creation time is kept from the first write.
pub(super) fn write_item(
    conn: &Connection,
    account_id: Uuid,
    vault_id: Uuid,
    item_id: Uuid,
    state: &ItemState,
    at_ms: u64,
) -> Result<ItemRecord, StoreError> {
    let seq = next_revision(conn, account_id)?;
    let revision = bump_vault(conn, vault_id, at_ms)?;
    insert(
        conn,
        "INSERT INTO items (id, vault_id, item_type, key, data, revision, favorite, folder_id,
            deleted_ms, created_ms, revised_ms, seq)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?10, ?11)
         ON CONFLICT (id) DO UPDATE SET item_type = excluded.item_type, key = excluded.key,
            data = excluded.data, revision = excluded.revision, favorite = excluded.favorite,
            folder_id = excluded.folder_id, deleted_ms = excluded.deleted_ms,
            revised_ms = excluded.revised_ms, seq = excluded.seq",
        params![
            item_id.to_string(),
            vault_id.to_string(),
            state.item_type,
            state.key,
            state.data,
            revision as i64,
            state.favorite,
            state.folder_id.map(|id| id.to_string()),
            state.deleted_ms.map(|ms| ms as i64),
            at_ms as i64,
            seq as i64,
        ],
    )?;
    find_item_record(conn, item_id)?.ok_or(StoreError::NotFound)
}

/// The one Item removal path: the deletion enters the change feed.
pub(super) fn remove_item(
    conn: &Connection,
    account_id: Uuid,
    vault_id: Uuid,
    item_id: Uuid,
    at_ms: u64,
) -> Result<(), StoreError> {
    let seq = next_revision(conn, account_id)?;
    bump_vault(conn, vault_id, at_ms)?;
    insert(
        conn,
        "DELETE FROM items WHERE id = ?1",
        params![item_id.to_string()],
    )?;
    record_change(
        conn,
        account_id,
        seq,
        CHANGE_DELETED,
        item_id,
        vault_id,
        None,
    )
}

fn same_content(item: &Item, request: &PutItemRequest) -> bool {
    item.item_type == request.item_type
        && item.key == request.key
        && item.data == request.data
        && item.favorite == request.favorite
        && item.folder_id == request.folder_id
}

/// Items readable by `scope` written after `from`, plus every Item of a Vault whose Grant to
/// the caller arrived after `from`.
pub(super) fn load_items(
    conn: &Connection,
    account_id: Uuid,
    scope: Scope,
    from: i64,
) -> Result<Vec<Item>, StoreError> {
    match scope {
        Scope::Owner => query(
            conn,
            &format!(
                "SELECT {ITEM_COLUMNS} FROM items i JOIN vaults v ON v.id = i.vault_id
                 WHERE v.account_id = ?1 AND i.seq > ?2 ORDER BY i.vault_id, i.id"
            ),
            &[account_id.to_string().into(), from.into()],
            item_row,
        ),
        Scope::Granted(principal) => query(
            conn,
            &format!(
                "SELECT {ITEM_COLUMNS} FROM items i JOIN vaults v ON v.id = i.vault_id
                 JOIN grants g ON g.vault_id = v.id
                 WHERE v.account_id = ?1 AND g.principal_id = ?2 AND (i.seq > ?3 OR g.seq > ?3)
                 ORDER BY i.vault_id, i.id"
            ),
            &[
                account_id.to_string().into(),
                principal.to_string().into(),
                from.into(),
            ],
            item_row,
        ),
    }
}
