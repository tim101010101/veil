//! Delivery records and their queries.

use super::*;

impl Store {
    /// Records delivery events, after checking that `scope` may read every reported Vault and
    /// that each reported Item, when it still exists, lives in that Vault.
    pub fn record_audit(
        &self,
        account_id: Uuid,
        principal_id: Uuid,
        kind: PrincipalKind,
        scope: Scope,
        events: &[AuditEventInput],
        at: u64,
    ) -> Result<(), StoreError> {
        if events.len() > MAX_AUDIT_BATCH {
            return Err(StoreError::Invalid("a batch holds at most 100 events"));
        }
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        for event in events {
            if !vault_readable(&tx, account_id, scope, event.vault_id)? {
                return Err(StoreError::Forbidden);
            }
            if let Some(item) = find_item(&tx, event.item_id)?
                && item.vault_id != event.vault_id
            {
                return Err(StoreError::Forbidden);
            }
            insert(
                &tx,
                "INSERT INTO audit (id, account_id, at, principal_id, principal_kind, vault_id,
                    item_id, destination, result)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    Uuid::now_v7().to_string(),
                    account_id.to_string(),
                    at as i64,
                    principal_id.to_string(),
                    kind_name(kind),
                    event.vault_id.to_string(),
                    event.item_id.to_string(),
                    destination_name(event.destination),
                    result_name(event.result),
                ],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Lists delivery events, newest first.
    pub fn audit_events(
        &self,
        account_id: Uuid,
        filter: &AuditFilter,
    ) -> Result<Vec<AuditEvent>, StoreError> {
        let mut sql = String::from(
            "SELECT id, at, principal_id, principal_kind, vault_id, item_id, destination, result
             FROM audit WHERE account_id = ?1 AND at < ?2",
        );
        let mut args: Vec<SqlValue> = vec![
            account_id.to_string().into(),
            (filter
                .before
                .unwrap_or(i64::MAX as u64)
                .min(i64::MAX as u64) as i64)
                .into(),
        ];
        if let Some(vault_id) = filter.vault_id {
            args.push(vault_id.to_string().into());
            let _ = write!(sql, " AND vault_id = ?{}", args.len());
        }
        if let Some(item_id) = filter.item_id {
            args.push(item_id.to_string().into());
            let _ = write!(sql, " AND item_id = ?{}", args.len());
        }
        args.push((filter.limit.clamp(1, 200) as i64).into());
        let _ = write!(sql, " ORDER BY at DESC, id DESC LIMIT ?{}", args.len());
        query(&self.conn(), &sql, &args, |row| {
            Ok(AuditEvent {
                id: parse_id(row.get(0)?),
                at: row.get::<_, i64>(1)? as u64,
                principal_id: parse_id(row.get(2)?),
                principal_kind: parse_kind(row.get(3)?),
                vault_id: parse_id(row.get(4)?),
                item_id: parse_id(row.get(5)?),
                destination: parse_destination(row.get(6)?),
                result: parse_result(row.get(7)?),
            })
        })
    }

    // ----- workloads -----
}

fn destination_name(destination: Destination) -> &'static str {
    match destination {
        Destination::Inject => "inject",
        Destination::Mount => "mount",
        Destination::Render => "render",
        Destination::Print => "print",
        Destination::Export => "export",
        Destination::Browser => "browser",
    }
}

fn parse_destination(value: String) -> Destination {
    match value.as_str() {
        "mount" => Destination::Mount,
        "render" => Destination::Render,
        "print" => Destination::Print,
        "export" => Destination::Export,
        "browser" => Destination::Browser,
        _ => Destination::Inject,
    }
}

fn result_name(result: DeliveryResult) -> &'static str {
    match result {
        DeliveryResult::Ok => "ok",
        DeliveryResult::Denied => "denied",
        DeliveryResult::Failed => "failed",
    }
}

fn parse_result(value: String) -> DeliveryResult {
    match value.as_str() {
        "denied" => DeliveryResult::Denied,
        "failed" => DeliveryResult::Failed,
        _ => DeliveryResult::Ok,
    }
}
