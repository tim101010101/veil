//! Embedded storage.
//!
//! The service stores sealed strings, identifiers, revisions, and public keys. It never parses
//! a sealed field, so it never sees a name, a value, or a key.
//!
//! The schema is the Vault/Item model. It replaced the 0.1.0 Project/Environment tables
//! outright; the service refuses to open a database that still holds them.

use std::{
    collections::{BTreeSet, HashMap},
    fmt::Write as _,
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};

use rand_core::RngCore;
use rusqlite::{Connection, OptionalExtension, Row, params, types::Value as SqlValue};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use veil_proto::{
    AuditEvent, AuditEventInput, CreateAccountRequest, CreateVaultRequest, CreateWorkloadRequest,
    DeliveryResult, Destination, Device, DeviceKeys, Grant, GrantWrite, Item, Kdf, PendingDevice,
    PrincipalKind, PutItemRequest, RotateVaultRequest, Rotation, SyncDocument, TrustPolicy,
    UpdateAccountRequest, UpdateVaultRequest, Vault, Workload,
};

/// `PRAGMA user_version` of the schema below. 0.1.0 databases carry `0` and an `accounts` table.
/// Version 2 never shipped; 3 adds millisecond Item times and the Bitwarden tables.
const SCHEMA_VERSION: i64 = 4;

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS accounts (
    id TEXT PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    kdf TEXT NOT NULL,
    auth_hash TEXT NOT NULL,
    protected_account_key TEXT NOT NULL,
    account_keys TEXT NOT NULL,
    recovery_wrap TEXT NOT NULL,
    recovery_verifier TEXT NOT NULL,
    revision INTEGER NOT NULL,
    created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    account_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS devices (
    id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL,
    name TEXT NOT NULL,
    seal_pk TEXT NOT NULL,
    auth_pk TEXT NOT NULL,
    owner INTEGER NOT NULL,
    code TEXT,
    created_at INTEGER NOT NULL,
    revoked_at INTEGER
);
CREATE TABLE IF NOT EXISTS pending_devices (
    account_id TEXT NOT NULL,
    code TEXT NOT NULL,
    id TEXT NOT NULL,
    name TEXT NOT NULL,
    seal_pk TEXT NOT NULL,
    auth_pk TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    PRIMARY KEY (account_id, code)
);
CREATE TABLE IF NOT EXISTS vaults (
    id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL,
    name TEXT NOT NULL,
    account_key_wrap TEXT NOT NULL,
    revision INTEGER NOT NULL,
    key_generation INTEGER NOT NULL,
    rotation_due INTEGER NOT NULL,
    policy TEXT,
    created_at INTEGER NOT NULL,
    changed_ms INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS vaults_account ON vaults (account_id);
CREATE TABLE IF NOT EXISTS items (
    id TEXT PRIMARY KEY,
    vault_id TEXT NOT NULL,
    item_type INTEGER NOT NULL,
    key TEXT NOT NULL,
    data TEXT NOT NULL,
    revision INTEGER NOT NULL,
    favorite INTEGER NOT NULL,
    folder_id TEXT,
    deleted_ms INTEGER,
    created_ms INTEGER NOT NULL,
    revised_ms INTEGER NOT NULL,
    seq INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS items_vault ON items (vault_id);
CREATE TABLE IF NOT EXISTS grants (
    id TEXT PRIMARY KEY,
    vault_id TEXT NOT NULL,
    principal_id TEXT NOT NULL,
    key_generation INTEGER NOT NULL,
    wrapped_key TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    seq INTEGER NOT NULL,
    UNIQUE (vault_id, principal_id)
);
CREATE INDEX IF NOT EXISTS grants_principal ON grants (principal_id);
CREATE TABLE IF NOT EXISTS changes (
    account_id TEXT NOT NULL,
    revision INTEGER NOT NULL,
    kind TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    vault_id TEXT NOT NULL,
    principal_id TEXT
);
CREATE INDEX IF NOT EXISTS changes_account ON changes (account_id, revision);
CREATE TABLE IF NOT EXISTS workloads (
    id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL,
    name TEXT NOT NULL,
    issuer TEXT NOT NULL,
    audience TEXT NOT NULL,
    claims TEXT NOT NULL,
    seal_pk TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    revoked_at INTEGER
);
CREATE TABLE IF NOT EXISTS workload_tokens (
    token_hash TEXT PRIMARY KEY,
    workload_id TEXT NOT NULL,
    expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS audit (
    id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL,
    at INTEGER NOT NULL,
    principal_id TEXT NOT NULL,
    principal_kind TEXT NOT NULL,
    vault_id TEXT NOT NULL,
    item_id TEXT NOT NULL,
    destination TEXT NOT NULL,
    result TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS audit_account ON audit (account_id, at);
CREATE TABLE IF NOT EXISTS request_nonces (
    device_id TEXT NOT NULL,
    nonce TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    PRIMARY KEY (device_id, nonce)
);
CREATE TABLE IF NOT EXISTS service_secrets (
    name TEXT PRIMARY KEY,
    value BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS bitwarden_bindings (
    account_id TEXT PRIMARY KEY,
    vault_id TEXT NOT NULL,
    protected_key TEXT NOT NULL,
    private_key TEXT NOT NULL,
    public_key TEXT NOT NULL,
    account_keys TEXT NOT NULL,
    user_key_id TEXT,
    security_stamp TEXT NOT NULL,
    enabled_at INTEGER NOT NULL,
    changed_ms INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS bitwarden_sessions (
    id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL,
    refresh_hash TEXT NOT NULL UNIQUE,
    expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS bitwarden_sessions_account ON bitwarden_sessions (account_id);
CREATE TABLE IF NOT EXISTS folders (
    id TEXT PRIMARY KEY,
    vault_id TEXT NOT NULL,
    name TEXT NOT NULL,
    revised_ms INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS folders_vault ON folders (vault_id);
CREATE TABLE IF NOT EXISTS bitwarden_two_step (
    account_id TEXT PRIMARY KEY,
    secret TEXT NOT NULL,
    last_step INTEGER NOT NULL,
    enabled_at INTEGER NOT NULL
);
"#;

/// `service_secrets.name` of the Bitwarden access token signing key.
const TOKEN_SECRET: &str = "bitwarden_token";

/// `changes.kind` for an Item, Vault, or Grant that was removed.
const CHANGE_DELETED: &str = "deleted";
/// `changes.kind` for a Vault whose key generation moved.
const CHANGE_ROTATED: &str = "rotated";

/// The most events one batch may carry.
pub const MAX_AUDIT_BATCH: usize = 100;

/// A failure the API layer turns into a status code.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// The object does not exist or is not visible to the caller.
    #[error("not found")]
    NotFound,
    /// The write conflicts with an existing object or a stale revision.
    #[error("conflict")]
    Conflict,
    /// The caller may not perform this action.
    #[error("forbidden")]
    Forbidden,
    /// The request is well formed JSON but cannot be applied as written.
    #[error("invalid: {0}")]
    Invalid(&'static str),
    /// The database file was written by an incompatible version.
    #[error("the database holds schema version {0}; this veild needs a fresh database")]
    IncompatibleSchema(i64),
    /// Anything the operator must see in the log.
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),
}

/// Which Vaults a reader may open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// Every Vault in the Account, with its account key wrap: the Owner and Owner Devices.
    Owner,
    /// Only the Vaults this Device or Workload holds a Grant for.
    Granted(Uuid),
}

/// An account as stored.
pub struct AccountRecord {
    /// Account id.
    pub id: Uuid,
    /// Sign-in address.
    pub email: String,
    /// Parameters the master key is derived with.
    pub kdf: Kdf,
    /// SHA-256 of the authentication hash.
    pub auth_hash: String,
    /// Account key wrapped by the master key.
    pub protected_account_key: String,
    /// The SDK's v2 account key state, opaque.
    pub account_keys: String,
    /// Account key wrapped by the recovery code.
    pub recovery_wrap: String,
    /// SHA-256 of the recovery verifier.
    pub recovery_verifier: String,
}

/// A device as stored, with what the wire shape leaves out.
pub struct DeviceRecord {
    /// Account the device belongs to.
    pub account_id: Uuid,
    /// The device.
    pub device: Device,
}

/// An Item as stored, with the write times the wire shape rounds to seconds.
#[derive(Debug, Clone)]
pub struct ItemRecord {
    /// The Item.
    pub item: Item,
    /// Milliseconds, when moved to the trash.
    pub deleted_ms: Option<u64>,
    /// Milliseconds of the last write.
    pub revised_ms: u64,
    /// Milliseconds of the first write.
    pub created_ms: u64,
}

/// Filters for the audit list.
#[derive(Debug, Clone, Default)]
pub struct AuditFilter {
    /// Page size, clamped to 1..=200.
    pub limit: usize,
    /// Only events strictly older than this Unix time.
    pub before: Option<u64>,
    /// Only events for this Vault.
    pub vault_id: Option<Uuid>,
    /// Only events for this Item.
    pub item_id: Option<Uuid>,
}

/// The embedded database.
pub struct Store {
    conn: Mutex<Connection>,
    /// Signs Bitwarden access tokens; generated on first start and kept in the database.
    token_secret: Vec<u8>,
}

/// Seconds since the Unix epoch.
pub fn now() -> u64 {
    now_ms() / 1000
}

/// Milliseconds since the Unix epoch: the resolution Item and folder write times are kept at.
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("the clock is after 1970")
        .as_millis() as u64
}

impl Store {
    /// Opens or creates a database file.
    pub fn open(path: &std::path::Path) -> Result<Self, StoreError> {
        let conn = Connection::open(path)?;
        Self::from_connection(conn)
    }

    /// Opens a database that lives only for the process.
    pub fn in_memory() -> Result<Self, StoreError> {
        Self::from_connection(Connection::open_in_memory()?)
    }

    fn from_connection(conn: Connection) -> Result<Self, StoreError> {
        conn.execute_batch("PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL;")?;
        let version: i64 = conn.query_row("PRAGMA user_version", [], |row| row.get(0))?;
        if version == 0 {
            let tables: i64 = conn.query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table'",
                [],
                |row| row.get(0),
            )?;
            if tables > 0 {
                // A 0.1.0 database: never written over in place.
                return Err(StoreError::IncompatibleSchema(version));
            }
        } else if version == 3 {
            conn.execute_batch(
                "BEGIN IMMEDIATE;
                 ALTER TABLE sessions ADD COLUMN device_id TEXT;
                 DELETE FROM sessions;
                 PRAGMA user_version = 4;
                 COMMIT;",
            )?;
        } else if version != SCHEMA_VERSION {
            return Err(StoreError::IncompatibleSchema(version));
        }
        conn.execute_batch(SCHEMA)?;
        conn.execute_batch(&format!("PRAGMA user_version = {SCHEMA_VERSION};"))?;
        let token_secret = service_secret(&conn, TOKEN_SECRET)?;
        Ok(Self {
            conn: Mutex::new(conn),
            token_secret,
        })
    }

    /// Writes a consistent snapshot of the whole database to a new file at `to`, while the
    /// service keeps serving. The snapshot holds what the database holds: ciphertext, hashes,
    /// public keys, and the service's token-signing secret. Restoring it is copying it back over
    /// the database path while `veild` is stopped.
    pub fn backup(&self, to: &std::path::Path) -> Result<(), StoreError> {
        // Created empty and owner-only before SQLite fills it: the snapshot holds the
        // token-signing secret, and `create_new` refuses a file that already exists.
        let mut file = std::fs::OpenOptions::new();
        file.write(true).create_new(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut file, 0o600);
        file.open(to).map_err(|error| match error.kind() {
            std::io::ErrorKind::AlreadyExists => {
                StoreError::Invalid("the backup target already exists")
            }
            _ => StoreError::Invalid("cannot create the backup file"),
        })?;
        let written = match to.to_str() {
            Some(path) => self
                .conn()
                .execute("VACUUM INTO ?1", params![path])
                .map(drop)
                .map_err(StoreError::from),
            None => Err(StoreError::Invalid("the backup path is not UTF-8")),
        };
        if written.is_err() {
            // Leave no empty file behind to block the next attempt.
            let _ = std::fs::remove_file(to);
        }
        written
    }

    /// The key Bitwarden access tokens are signed with.
    pub fn token_secret(&self) -> &[u8] {
        &self.token_secret
    }

    fn conn(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.conn.lock().expect("store mutex is not poisoned")
    }

    // ----- accounts and sessions -----
}

mod bitwarden;
pub use bitwarden::{Binding, BitwardenAccount, Folder};
use bitwarden::{bind, bound_vault, revoke_bitwarden_sessions, unbind};

mod account;
mod device;
use device::insert_device;
mod vault;
use vault::{
    drop_principal_grants, find_vault, insert_grant, load_vault, load_vaults, vault_readable,
};
mod item;
pub use item::ItemState;
use item::{
    ITEM_COLUMNS, find_item, find_item_record, item_record_row, load_items, remove_item, write_item,
};
mod sync;
use sync::load_grants;
mod audit;
mod workload;

// ----- helpers -----

/// Loads a random service secret, generating it on first use.
fn service_secret(conn: &Connection, name: &str) -> Result<Vec<u8>, StoreError> {
    let mut fresh = [0u8; 32];
    rand_core::OsRng.fill_bytes(&mut fresh);
    conn.execute(
        "INSERT OR IGNORE INTO service_secrets (name, value) VALUES (?1, ?2)",
        params![name, fresh.as_slice()],
    )?;
    Ok(conn.query_row(
        "SELECT value FROM service_secrets WHERE name = ?1",
        params![name],
        |row| row.get(0),
    )?)
}

fn insert(
    conn: &Connection,
    sql: &str,
    params: impl rusqlite::Params,
) -> Result<usize, StoreError> {
    match conn.execute(sql, params) {
        Ok(changed) => Ok(changed),
        Err(rusqlite::Error::SqliteFailure(error, _))
            if error.code == rusqlite::ErrorCode::ConstraintViolation =>
        {
            Err(StoreError::Conflict)
        }
        Err(error) => Err(StoreError::Database(error)),
    }
}

fn query<T>(
    conn: &Connection,
    sql: &str,
    args: &[SqlValue],
    map: impl Fn(&Row<'_>) -> rusqlite::Result<T>,
) -> Result<Vec<T>, StoreError> {
    let mut statement = conn.prepare(sql)?;
    let mut rows = statement.query(rusqlite::params_from_iter(args.iter()))?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        out.push(map(row)?);
    }
    Ok(out)
}

/// Advances the Account's sync cursor once for a write and returns the new value.
fn next_revision(conn: &Connection, account_id: Uuid) -> Result<u64, StoreError> {
    let changed = conn.execute(
        "UPDATE accounts SET revision = revision + 1 WHERE id = ?1",
        params![account_id.to_string()],
    )?;
    if changed == 0 {
        return Err(StoreError::NotFound);
    }
    let revision: i64 = conn.query_row(
        "SELECT revision FROM accounts WHERE id = ?1",
        params![account_id.to_string()],
        |row| row.get(0),
    )?;
    Ok(revision as u64)
}

/// Advances a Vault's revision and change time and returns the new revision.
fn bump_vault(conn: &Connection, vault_id: Uuid, at_ms: u64) -> Result<u64, StoreError> {
    conn.execute(
        "UPDATE vaults SET revision = revision + 1, changed_ms = MAX(changed_ms, ?2) WHERE id = ?1",
        params![vault_id.to_string(), at_ms as i64],
    )?;
    let revision: i64 = conn.query_row(
        "SELECT revision FROM vaults WHERE id = ?1",
        params![vault_id.to_string()],
        |row| row.get(0),
    )?;
    Ok(revision as u64)
}

fn record_change(
    conn: &Connection,
    account_id: Uuid,
    revision: u64,
    kind: &str,
    entity_id: Uuid,
    vault_id: Uuid,
    principal_id: Option<Uuid>,
) -> Result<(), StoreError> {
    insert(
        conn,
        "INSERT INTO changes (account_id, revision, kind, entity_id, vault_id, principal_id)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            account_id.to_string(),
            revision as i64,
            kind,
            entity_id.to_string(),
            vault_id.to_string(),
            principal_id.map(|id| id.to_string()),
        ],
    )?;
    Ok(())
}

fn kdf_json(kdf: &Kdf) -> Result<String, StoreError> {
    serde_json::to_string(kdf).map_err(|_| StoreError::Invalid("kdf cannot be stored"))
}

fn kdf_at(row: &Row<'_>, index: usize) -> rusqlite::Result<Kdf> {
    let text: String = row.get(index)?;
    serde_json::from_str(&text).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            index,
            rusqlite::types::Type::Text,
            Box::new(error),
        )
    })
}

fn normalize_email(email: &str) -> String {
    email.trim().to_lowercase()
}

fn kind_name(kind: PrincipalKind) -> &'static str {
    match kind {
        PrincipalKind::Owner => "owner",
        PrincipalKind::Device => "device",
        PrincipalKind::Workload => "workload",
    }
}

fn parse_kind(value: String) -> PrincipalKind {
    match value.as_str() {
        "owner" => PrincipalKind::Owner,
        "workload" => PrincipalKind::Workload,
        _ => PrincipalKind::Device,
    }
}

fn parse_id(value: String) -> Uuid {
    Uuid::parse_str(&value).unwrap_or_default()
}

fn constant_time_eq(left: &str, right: &str) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.bytes()
        .zip(right.bytes())
        .fold(0u8, |acc, (a, b)| acc | (a ^ b))
        == 0
}

fn hash(value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    let mut out = String::with_capacity(64);
    for byte in digest {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refuses_a_database_with_old_tables() {
        let conn = Connection::open_in_memory().expect("memory");
        conn.execute_batch("CREATE TABLE environments (id TEXT PRIMARY KEY);")
            .expect("old table");

        let result = Store::from_connection(conn);

        assert!(matches!(result, Err(StoreError::IncompatibleSchema(0))));
    }

    #[test]
    fn version_three_migration_invalidates_unbound_sessions() {
        let conn = Connection::open_in_memory().expect("memory");
        conn.execute_batch(&SCHEMA.replacen("    device_id TEXT NOT NULL,\n", "", 1))
            .expect("old schema");
        conn.execute_batch(
            "PRAGMA user_version = 3;
             INSERT INTO sessions VALUES ('old-hash', 'account', 9999999999);
             INSERT INTO bitwarden_sessions VALUES ('bw-id', 'account', 'refresh-hash', 9999999999);"
        ).expect("old sessions");
        let store = Store::from_connection(conn).expect("migration");
        let conn = store.conn();
        let count: i64 = conn
            .query_row("SELECT count(*) FROM sessions", [], |r| r.get(0))
            .expect("sessions");
        assert_eq!(count, 0);
        let count: i64 = conn
            .query_row("SELECT count(*) FROM bitwarden_sessions", [], |r| r.get(0))
            .expect("bw sessions");
        assert_eq!(count, 1);
        let version: i64 = conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .expect("version");
        assert_eq!(version, SCHEMA_VERSION);
    }

    #[test]
    fn a_backup_reopens_as_the_same_service() {
        let dir = std::env::temp_dir().join(format!("veil-backup-{}", Uuid::now_v7()));
        std::fs::create_dir_all(&dir).expect("dir");
        let live = Store::open(&dir.join("veil.db")).expect("open");
        let snapshot = dir.join("snapshot.db");

        live.backup(&snapshot).expect("backup");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&snapshot)
                .expect("meta")
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "the snapshot is the owner's only");
        }
        assert!(matches!(
            live.backup(&snapshot),
            Err(StoreError::Invalid(_))
        ));

        // The restored database is the same service: tokens it signed stay valid.
        let restored = Store::open(&snapshot).expect("restored");
        assert_eq!(restored.token_secret(), live.token_secret());
        std::fs::remove_dir_all(&dir).expect("cleanup");
    }
}
