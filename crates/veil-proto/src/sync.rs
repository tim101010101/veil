//! The change feed clients sync from.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::{Grant, Item, Vault};

/// Everything the caller may read that changed since its cursor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct SyncDocument {
    /// Cursor this document represents; monotonic per Account.
    pub revision: u64,
    /// True when the service could not serve an increment.
    pub full: bool,
    /// Vaults the caller may read, with their current revision.
    pub vaults: Vec<Vault>,
    /// Items in those Vaults that changed since the cursor, including trashed ones.
    pub items: Vec<Item>,
    /// Grants held by the caller, or every Grant for the Owner.
    pub grants: Vec<Grant>,
    /// Ids removed since the cursor.
    pub deleted: Vec<Uuid>,
    /// Vaults whose key generation moved since the cursor.
    pub rotations: Vec<Rotation>,
}

/// A key generation change the client must notice.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct Rotation {
    /// Vault that was rotated.
    pub vault_id: Uuid,
    /// The new generation.
    pub key_generation: u32,
}
