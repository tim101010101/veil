//! CI Workloads and their short-lived tokens.

use super::*;

impl Store {
    /// Creates a workload and attaches its Grants. Replaying the same create returns the
    /// existing workload; the flag says whether this call created it.
    pub fn create_workload(
        &self,
        account_id: Uuid,
        request: &CreateWorkloadRequest,
        at: u64,
    ) -> Result<(Workload, bool), StoreError> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        if let Some((owner, workload)) = find_workload(&tx, request.id)? {
            if owner == account_id
                && workload.name == request.name
                && workload.seal_pk == request.seal_pk
                && workload.trust_policy == request.trust_policy
            {
                return Ok((workload, false));
            }
            return Err(StoreError::Conflict);
        }
        insert(
            &tx,
            "INSERT INTO workloads (id, account_id, name, issuer, audience, claims, seal_pk,
                created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                request.id.to_string(),
                account_id.to_string(),
                request.name,
                request.trust_policy.issuer,
                request.trust_policy.audience,
                serde_json::to_string(&request.trust_policy.claims)
                    .map_err(|_| StoreError::Invalid("claims cannot be stored"))?,
                request.seal_pk,
                at as i64,
            ],
        )?;
        let seq = next_revision(&tx, account_id)?;
        for grant in &request.grants {
            if grant.principal_id != request.id {
                return Err(StoreError::Forbidden);
            }
            insert_grant(&tx, account_id, grant, at, seq)?;
        }
        tx.commit()?;
        Ok((
            Workload {
                id: request.id,
                name: request.name.clone(),
                trust_policy: request.trust_policy.clone(),
                seal_pk: request.seal_pk.clone(),
                created_at: at,
                revoked_at: None,
            },
            true,
        ))
    }

    /// Loads a workload and its account.
    pub fn workload(&self, id: Uuid) -> Result<(Uuid, Workload), StoreError> {
        find_workload(&self.conn(), id)?.ok_or(StoreError::NotFound)
    }

    /// Lists workloads.
    pub fn workloads(&self, account_id: Uuid) -> Result<Vec<Workload>, StoreError> {
        query(
            &self.conn(),
            "SELECT id, name, issuer, audience, claims, seal_pk, created_at, revoked_at
             FROM workloads WHERE account_id = ?1 ORDER BY created_at",
            &[account_id.to_string().into()],
            |row| workload_row(row, 0),
        )
    }

    /// Revokes a workload: its tokens and Grants go at once and every Vault it could read is
    /// due a rotation. Revoking an absent or already revoked workload succeeds.
    pub fn revoke_workload(&self, account_id: Uuid, id: Uuid, at: u64) -> Result<(), StoreError> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        let changed = insert(
            &tx,
            "UPDATE workloads SET revoked_at = ?3
             WHERE id = ?1 AND account_id = ?2 AND revoked_at IS NULL",
            params![id.to_string(), account_id.to_string(), at as i64],
        )?;
        if changed > 0 {
            insert(
                &tx,
                "DELETE FROM workload_tokens WHERE workload_id = ?1",
                params![id.to_string()],
            )?;
            drop_principal_grants(&tx, account_id, id)?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Stores a short-lived workload token by its hash.
    pub fn create_workload_token(
        &self,
        workload_id: Uuid,
        token: &str,
        expires_at: u64,
    ) -> Result<(), StoreError> {
        insert(
            &self.conn(),
            "INSERT INTO workload_tokens (token_hash, workload_id, expires_at)
             VALUES (?1, ?2, ?3)",
            params![hash(token), workload_id.to_string(), expires_at as i64],
        )?;
        Ok(())
    }

    /// Resolves a live workload token to its account and workload.
    pub fn workload_token(&self, token: &str, at: u64) -> Result<Option<(Uuid, Uuid)>, StoreError> {
        Ok(self
            .conn()
            .query_row(
                "SELECT w.account_id, t.workload_id FROM workload_tokens t
                 JOIN workloads w ON w.id = t.workload_id
                 WHERE t.token_hash = ?1 AND t.expires_at > ?2 AND w.revoked_at IS NULL",
                params![hash(token), at as i64],
                |row| Ok((parse_id(row.get(0)?), parse_id(row.get(1)?))),
            )
            .optional()?)
    }
}

fn find_workload(conn: &Connection, id: Uuid) -> Result<Option<(Uuid, Workload)>, StoreError> {
    Ok(conn
        .query_row(
            "SELECT account_id, id, name, issuer, audience, claims, seal_pk, created_at, revoked_at
             FROM workloads WHERE id = ?1",
            params![id.to_string()],
            |row| Ok((parse_id(row.get(0)?), workload_row(row, 1)?)),
        )
        .optional()?)
}

fn workload_row(row: &Row<'_>, offset: usize) -> rusqlite::Result<Workload> {
    let claims: String = row.get(offset + 4)?;
    Ok(Workload {
        id: parse_id(row.get(offset)?),
        name: row.get(offset + 1)?,
        trust_policy: TrustPolicy {
            issuer: row.get(offset + 2)?,
            audience: row.get(offset + 3)?,
            claims: serde_json::from_str(&claims).map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    offset + 4,
                    rusqlite::types::Type::Text,
                    Box::new(error),
                )
            })?,
        },
        seal_pk: row.get(offset + 5)?,
        created_at: row.get::<_, i64>(offset + 6)? as u64,
        revoked_at: row
            .get::<_, Option<i64>>(offset + 7)?
            .map(|value| value as u64),
    })
}
