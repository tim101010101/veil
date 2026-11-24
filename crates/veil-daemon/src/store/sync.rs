//! The sync document: everything a reader may see, scoped by its Grants.

use super::*;

impl Store {
    /// What `scope` may read that changed since the cursor.
    ///
    /// Without a cursor, or with one from the future, the document is full.
    pub fn sync(
        &self,
        account_id: Uuid,
        scope: Scope,
        since: Option<u64>,
    ) -> Result<SyncDocument, StoreError> {
        let conn = self.conn();
        let revision: u64 = conn
            .query_row(
                "SELECT revision FROM accounts WHERE id = ?1",
                params![account_id.to_string()],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
            .ok_or(StoreError::NotFound)? as u64;
        let cursor = since.filter(|since| *since <= revision);
        let from = cursor.unwrap_or(0) as i64;

        let vaults = load_vaults(&conn, account_id, scope)?;
        let generations: HashMap<Uuid, u32> = vaults
            .iter()
            .map(|vault| (vault.id, vault.key_generation))
            .collect();
        let items = load_items(&conn, account_id, scope, from)?;
        let grants = load_grants(&conn, account_id, scope)?;

        let mut deleted = BTreeSet::new();
        let mut rotations = Vec::new();
        if cursor.is_some() {
            let changes = query(
                &conn,
                "SELECT kind, entity_id, vault_id, principal_id FROM changes
                 WHERE account_id = ?1 AND revision > ?2 ORDER BY revision",
                &[account_id.to_string().into(), from.into()],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        parse_id(row.get(1)?),
                        parse_id(row.get(2)?),
                        row.get::<_, Option<String>>(3)?.map(parse_id),
                    ))
                },
            )?;
            let mut rotated = BTreeSet::new();
            for (kind, entity, vault, principal) in changes {
                let readable = generations.contains_key(&vault);
                match kind.as_str() {
                    CHANGE_DELETED => match scope {
                        Scope::Owner => {
                            deleted.insert(entity);
                        }
                        Scope::Granted(caller) => {
                            if readable {
                                deleted.insert(entity);
                            } else if principal == Some(caller) {
                                // The caller lost its Grant: the Vault is gone for it too.
                                deleted.insert(entity);
                                deleted.insert(vault);
                            }
                        }
                    },
                    CHANGE_ROTATED if readable => {
                        rotated.insert(vault);
                    }
                    _ => {}
                }
            }
            rotations = rotated
                .into_iter()
                .filter_map(|vault_id| {
                    generations.get(&vault_id).map(|key_generation| Rotation {
                        vault_id,
                        key_generation: *key_generation,
                    })
                })
                .collect();
        }

        Ok(SyncDocument {
            revision,
            full: cursor.is_none(),
            vaults,
            items,
            grants,
            deleted: deleted.into_iter().collect(),
            rotations,
        })
    }

    // ----- audit -----
}

pub(super) fn load_grants(
    conn: &Connection,
    account_id: Uuid,
    scope: Scope,
) -> Result<Vec<Grant>, StoreError> {
    let map = |row: &Row<'_>| {
        Ok(Grant {
            id: parse_id(row.get(0)?),
            vault_id: parse_id(row.get(1)?),
            principal_id: parse_id(row.get(2)?),
            key_generation: row.get::<_, i64>(3)? as u32,
            wrapped_key: row.get(4)?,
            created_at: row.get::<_, i64>(5)? as u64,
        })
    };
    match scope {
        Scope::Owner => query(
            conn,
            "SELECT g.id, g.vault_id, g.principal_id, g.key_generation, g.wrapped_key, g.created_at
             FROM grants g JOIN vaults v ON v.id = g.vault_id
             WHERE v.account_id = ?1 ORDER BY g.created_at, g.id",
            &[account_id.to_string().into()],
            map,
        ),
        Scope::Granted(principal) => query(
            conn,
            "SELECT g.id, g.vault_id, g.principal_id, g.key_generation, g.wrapped_key, g.created_at
             FROM grants g JOIN vaults v ON v.id = g.vault_id
             WHERE v.account_id = ?1 AND g.principal_id = ?2 ORDER BY g.created_at, g.id",
            &[account_id.to_string().into(), principal.to_string().into()],
            map,
        ),
    }
}
