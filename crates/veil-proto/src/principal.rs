//! Principals: devices, workloads, and what identifies them.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::{Grant, GrantWrite};

/// What a device or workload is called.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum PrincipalKind {
    /// The owner's own session.
    Owner,
    /// An approved machine.
    Device,
    /// A short-lived CI principal.
    Workload,
}

/// Public keys a device presents when it enrolls.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct DeviceKeys {
    /// Client-generated id, so retries are safe.
    pub id: Uuid,
    /// Human-readable name, shown when approving.
    pub name: String,
    /// Sealing public key that Vault keys are shared to: SPKI DER, base64.
    pub seal_pk: String,
    /// Ed25519 key that verifies this device's signed requests, base64url.
    pub auth_pk: String,
}

/// An approved machine that reads without further interaction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct Device {
    /// Device id.
    pub id: Uuid,
    /// Human-readable name.
    pub name: String,
    /// Sealing public key: SPKI DER, base64.
    pub seal_pk: String,
    /// Ed25519 authentication key, base64url.
    pub auth_pk: String,
    /// Unix seconds.
    pub created_at: u64,
    /// Unix seconds, when revoked.
    pub revoked_at: Option<u64>,
    /// Reads all current and future Vaults when true, otherwise only granted Vaults.
    #[serde(default)]
    pub owner: bool,
}

/// Start enrolling a device: the new machine picks a code and shows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct BeginDeviceEnrollmentRequest {
    /// Address of the account the device joins.
    pub email: String,
    /// Six-digit code shown on the new machine.
    pub code: String,
    /// The new machine's public keys.
    pub device: DeviceKeys,
}

/// A device waiting for approval.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct PendingDevice {
    /// The machine that wants to join.
    pub device: DeviceKeys,
    /// Code the machine is showing.
    pub code: String,
    /// Unix seconds.
    pub created_at: u64,
    /// Unix seconds.
    pub expires_at: u64,
}

/// Approve a pending device by attaching its Grants. A Device never receives the account key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ApproveDeviceRequest {
    /// Vault keys shared with the new device.
    pub grants: Vec<GrantWrite>,
}

/// What an approved device needs to finish enrolling.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct EnrollmentResponse {
    /// Account the device joined.
    pub account_id: Uuid,
    /// Sign-in address.
    pub email: String,
    /// The approved device.
    pub device: Device,
    /// Vault keys shared with this device.
    pub grants: Vec<Grant>,
}

/// Query a pending device polls with.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct EnrollmentProof {
    /// The device that is polling.
    pub device_id: Uuid,
    /// Code it registered.
    pub code: String,
    /// Unix seconds.
    pub timestamp: u64,
    /// Single-use nonce.
    pub nonce: String,
    /// Signature over the enrollment input.
    pub signature: String,
}

/// What an OIDC token must prove.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct TrustPolicy {
    /// Expected `iss`.
    pub issuer: String,
    /// Expected `aud`.
    pub audience: String,
    /// Claims that must match exactly.
    pub claims: BTreeMap<String, String>,
}

/// Create a workload and attach its grants.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct CreateWorkloadRequest {
    /// Client-generated id, so retries are safe.
    pub id: Uuid,
    /// Human-readable name.
    pub name: String,
    /// What the issuer must prove.
    pub trust_policy: TrustPolicy,
    /// Sealing public key that Vault keys are shared to: SPKI DER, base64.
    pub seal_pk: String,
    /// Vault keys shared with the workload.
    pub grants: Vec<GrantWrite>,
}

/// A short-lived CI principal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct Workload {
    /// Workload id.
    pub id: Uuid,
    /// Human-readable name.
    pub name: String,
    /// What the issuer must prove.
    pub trust_policy: TrustPolicy,
    /// Sealing public key: SPKI DER, base64.
    pub seal_pk: String,
    /// Unix seconds.
    pub created_at: u64,
    /// Unix seconds, when revoked.
    pub revoked_at: Option<u64>,
}

/// Exchange an OIDC token for a short-lived workload token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ExchangeWorkloadTokenRequest {
    /// The token issued by the CI platform.
    pub oidc_token: String,
}

/// A short-lived token and its expiry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct WorkloadToken {
    /// Bearer token.
    pub token: String,
    /// Unix seconds after which the token is refused.
    pub expires_at: u64,
}
