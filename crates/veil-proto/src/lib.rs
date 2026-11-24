//! Wire contract shared by `veild` and `veil`.
//!
//! Types here describe what crosses the network. They contain no secrets and no logic
//! beyond serialization, so the CLI never links daemon internals and the OpenAPI document is
//! generated from a single definition.
//!
//! The contract is frozen by `tests/contract.rs`: adding a type without registering it in
//! [`Contract`] fails the build.

mod account;
mod audit;
mod bitwarden;
mod principal;
mod request;
mod sync;
mod vault;

pub use account::{
    Account, CreateAccountRequest, CreateAccountResponse, CreateRecoveryRequest,
    CreateRecoveryResponse, CreateSessionRequest, CreateSessionResponse, DeviceLogin, Kdf,
    PreloginRequest, PreloginResponse, Session, UpdateAccountRequest,
};
pub use audit::{AuditEvent, AuditEventBatch, AuditEventInput, DeliveryResult, Destination};
pub use bitwarden::{BitwardenStatus, EnableBitwardenRequest, EnableTwoStepRequest};
pub use principal::{
    ApproveDeviceRequest, BeginDeviceEnrollmentRequest, CreateWorkloadRequest, Device, DeviceKeys,
    EnrollmentProof, EnrollmentResponse, ExchangeWorkloadTokenRequest, PendingDevice,
    PrincipalKind, TrustPolicy, Workload, WorkloadToken,
};
pub use request::{RequestToSign, body_hash, enrollment_input, session_input, signing_input};
pub use sync::{Rotation, SyncDocument};
pub use vault::{
    CreateVaultRequest, Grant, GrantWrite, Item, ItemKeyWrite, ItemWrite, PutItemRequest,
    RotateVaultRequest, UpdateVaultRequest, Vault,
};

use serde::{Deserialize, Serialize};
use utoipa::{OpenApi, ToSchema};

/// Prefix for all versioned API routes.
///
/// Liveness and readiness probes stay unversioned on purpose, so orchestration never
/// depends on an API version.
pub const API_PREFIX: &str = "/api/v1";

/// The protocol version carried in `X-Veil-Protocol`.
pub const PROTOCOL_VERSION: u32 = 1;

/// Builds unambiguous context bytes: each part is length-prefixed.
///
/// Used for signing inputs, so nothing can be reordered or concatenated ambiguously.
pub fn binding(parts: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    for part in parts {
        out.extend_from_slice(&(part.len() as u32).to_be_bytes());
        out.extend_from_slice(part);
    }
    out
}

/// Service health, as reported by `GET /healthz` and `GET /readyz`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct HealthReport {
    /// Current status.
    pub status: ServiceStatus,
    /// Service name, matching the OpenTelemetry `service.name` resource attribute.
    pub service: String,
    /// Product version, matching the OpenTelemetry `service.version` resource attribute.
    pub version: String,
    /// Source commit the running artifact was built from, when the build recorded one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commit: Option<String>,
}

/// Status of a service instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ServiceStatus {
    /// Serving traffic and ready to answer requests.
    Ok,
    /// Alive but not ready to serve, for example while a dependency is unavailable.
    Degraded,
}

/// Error envelope, serialized as `application/problem+json` ([RFC 9457]).
///
/// [RFC 9457]: https://www.rfc-editor.org/rfc/rfc9457
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ProblemDetails {
    /// Stable URI identifying the problem type.
    #[serde(rename = "type")]
    pub kind: String,
    /// Short, human-readable summary, stable across occurrences of the same type.
    pub title: String,
    /// HTTP status code.
    pub status: u16,
    /// Human-readable explanation for this occurrence.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl ProblemDetails {
    /// Builds a problem document for `status` with the given type URI and title.
    pub fn new(kind: impl Into<String>, title: impl Into<String>, status: u16) -> Self {
        Self {
            kind: kind.into(),
            title: title.into(),
            status,
            detail: None,
        }
    }

    /// Attaches an occurrence-specific explanation.
    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }
}

/// Compile-time OpenAPI components for the wire contract.
///
/// Paths are added by `veild` as handlers land; this document is the single source for
/// every schema both sides exchange.
#[derive(OpenApi)]
#[openapi(components(schemas(
    Account,
    Kdf,
    PreloginRequest,
    PreloginResponse,
    Session,
    DeviceKeys,
    Device,
    CreateAccountRequest,
    CreateAccountResponse,
    CreateSessionRequest,
    DeviceLogin,
    CreateSessionResponse,
    UpdateAccountRequest,
    CreateRecoveryRequest,
    CreateRecoveryResponse,
    BeginDeviceEnrollmentRequest,
    ApproveDeviceRequest,
    PendingDevice,
    EnrollmentResponse,
    EnrollmentProof,
    PrincipalKind,
    TrustPolicy,
    CreateWorkloadRequest,
    Workload,
    ExchangeWorkloadTokenRequest,
    WorkloadToken,
    Vault,
    CreateVaultRequest,
    UpdateVaultRequest,
    Item,
    ItemWrite,
    PutItemRequest,
    ItemKeyWrite,
    Grant,
    GrantWrite,
    RotateVaultRequest,
    EnableBitwardenRequest,
    BitwardenStatus,
    SyncDocument,
    Rotation,
    Destination,
    DeliveryResult,
    AuditEventInput,
    AuditEventBatch,
    AuditEvent,
    HealthReport,
    ServiceStatus,
    ProblemDetails
)))]
pub struct Contract;
