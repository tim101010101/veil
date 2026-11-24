//! Vaults, Items, and Grants.
//!
//! Sealed fields are SDK strings the service stores and returns unchanged: `EncString`s for
//! names and wrapped keys, `UnsignedSharedKey`s for Grants, and the sealed record container for
//! Item data. The service never interprets them.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

/// The unit of encryption and authorization: one key, many Items.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct Vault {
    /// Vault id.
    pub id: Uuid,
    /// Name, sealed by the Vault key, so every holder of a Grant can read it.
    pub name: String,
    /// Bumped by every change to the Vault or its Items; writes carry the expected value.
    pub revision: u64,
    /// Which Vault key the Item keys and Grants are wrapped with.
    pub key_generation: u32,
    /// A principal that held a Grant was revoked; the Owner rotates the key on the next write.
    pub rotation_due: bool,
    /// Approval policy (`none`, `presence`, or `device`), sealed by the Vault key. Absent means
    /// `none`. Clients enforce it; sealing keeps the service from reading or forging it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<String>,
    /// Vault key wrapped by the account key. Owner only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_key_wrap: Option<String>,
}

/// One sealed record and its plaintext metadata.
///
/// The metadata is exactly: id, Vault, type,
/// revision, favorite flag, folder, and deletion date, plus the service's own write time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct Item {
    /// Item id.
    pub id: Uuid,
    /// Owning Vault.
    pub vault_id: Uuid,
    /// Bitwarden `CipherType`: 1 login, 2 secure note, 3 card, 4 identity, 5 SSH key.
    pub item_type: u8,
    /// Item key wrapped by the Vault key.
    pub key: String,
    /// The sealed record container.
    pub data: String,
    /// The Vault revision of the last write to this Item.
    pub revision: u64,
    /// Favorite flag.
    pub favorite: bool,
    /// Folder, when filed in one.
    pub folder_id: Option<Uuid>,
    /// Unix seconds, when moved to the trash.
    pub deleted_at: Option<u64>,
    /// Unix seconds of the last write, stamped by the service.
    pub revised_at: u64,
}

/// An Item as written by the Owner.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ItemWrite {
    /// Client-generated id, so retries are safe.
    pub id: Uuid,
    /// Bitwarden `CipherType`.
    pub item_type: u8,
    /// Item key wrapped by the Vault key.
    pub key: String,
    /// The sealed record container.
    pub data: String,
    /// Favorite flag.
    #[serde(default)]
    pub favorite: bool,
    /// Folder, when filed in one.
    #[serde(default)]
    pub folder_id: Option<Uuid>,
}

/// A Vault key shared with one principal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct Grant {
    /// Grant id.
    pub id: Uuid,
    /// Vault whose key is shared.
    pub vault_id: Uuid,
    /// Device or Workload that can open it.
    pub principal_id: Uuid,
    /// Vault key generation this Grant belongs to.
    pub key_generation: u32,
    /// The Vault key, encapsulated to the principal's sealing key.
    pub wrapped_key: String,
    /// Unix seconds.
    pub created_at: u64,
}

/// A Grant as written by the Owner.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct GrantWrite {
    /// Vault whose key is shared.
    pub vault_id: Uuid,
    /// Device or Workload that can open it.
    pub principal_id: Uuid,
    /// Vault key generation this Grant belongs to.
    pub key_generation: u32,
    /// The Vault key, encapsulated to the principal's sealing key.
    pub wrapped_key: String,
}

/// Create a Vault with its first key generation, Items, and Grants.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct CreateVaultRequest {
    /// Client-generated id, so retries are safe.
    pub id: Uuid,
    /// Name, sealed by the Vault key.
    pub name: String,
    /// Vault key wrapped by the account key.
    pub account_key_wrap: String,
    /// Initial Items.
    #[serde(default)]
    pub items: Vec<ItemWrite>,
    /// Grants for Devices and Workloads; the Owner reads through `account_key_wrap`.
    #[serde(default)]
    pub grants: Vec<GrantWrite>,
}

/// Rename a Vault or change its approval policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct UpdateVaultRequest {
    /// Revision the client last saw.
    pub expected_revision: u64,
    /// Name, sealed by the Vault key.
    pub name: String,
    /// Approval policy, sealed by the Vault key; absent leaves it unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<String>,
}

/// Create or replace one Item.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct PutItemRequest {
    /// Item revision the client last saw; `0` creates.
    pub expected_revision: u64,
    /// Bitwarden `CipherType`.
    pub item_type: u8,
    /// Item key wrapped by the Vault key.
    pub key: String,
    /// The sealed record container.
    pub data: String,
    /// Favorite flag.
    #[serde(default)]
    pub favorite: bool,
    /// Folder, when filed in one.
    #[serde(default)]
    pub folder_id: Option<Uuid>,
}

/// One Item key re-wrapped under a new Vault key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ItemKeyWrite {
    /// Item id.
    pub id: Uuid,
    /// Item key wrapped by the new Vault key.
    pub key: String,
}

/// Move a Vault to a new key: re-wrap every Item key and replace the Grants, atomically.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct RotateVaultRequest {
    /// Revision the client last saw.
    pub expected_revision: u64,
    /// Key generation the client last saw.
    pub expected_key_generation: u32,
    /// Name, sealed by the new Vault key.
    pub name: String,
    /// Approval policy, re-sealed by the new Vault key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<String>,
    /// Every Item key, re-wrapped. Item data does not change.
    pub items: Vec<ItemKeyWrite>,
    /// The new Grant set.
    pub grants: Vec<GrantWrite>,
    /// New Vault key wrapped by the account key.
    pub account_key_wrap: String,
    /// New Bitwarden login keys. Required when this Vault is the one Bitwarden clients see.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bitwarden: Option<crate::EnableBitwardenRequest>,
}
