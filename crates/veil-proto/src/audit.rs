//! Delivery and authentication records.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::PrincipalKind;

/// Where a value was delivered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum Destination {
    /// A child process environment.
    Inject,
    /// A named pipe read as a file.
    Mount,
    /// A rendered file or template.
    Render,
    /// A terminal.
    Print,
    /// Shell or tool output.
    Export,
    /// A browser session handed to a helper.
    Browser,
}

/// How a delivery ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryResult {
    /// The value reached its destination.
    Ok,
    /// Policy or approval refused it.
    Denied,
    /// Delivery was attempted and failed.
    Failed,
}

/// One delivery, as reported by a client.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct AuditEventInput {
    /// Vault the value came from.
    pub vault_id: Uuid,
    /// Item that was delivered.
    pub item_id: Uuid,
    /// Where it went.
    pub destination: Destination,
    /// How it ended.
    pub result: DeliveryResult,
}

/// A client batch of delivery events.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct AuditEventBatch {
    /// At most 100 events.
    pub events: Vec<AuditEventInput>,
}

/// A recorded event, stamped by the service.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct AuditEvent {
    /// Event id.
    pub id: Uuid,
    /// Unix seconds, set by the service.
    pub at: u64,
    /// Who acted.
    pub principal_id: Uuid,
    /// What kind of principal acted.
    pub principal_kind: PrincipalKind,
    /// Vault the value came from.
    pub vault_id: Uuid,
    /// Item that was delivered.
    pub item_id: Uuid,
    /// Where it went.
    pub destination: Destination,
    /// How it ended.
    pub result: DeliveryResult,
}
