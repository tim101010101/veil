//! Who is calling: the owner's session, a device signing each request, or a workload token.
//!
//! Only a device-bound Owner session writes. A personal Owner Device reads the whole Account; a Device enrolled by approval and a Workload read only the Vaults
//! they hold a Grant for.

use axum::{
    extract::{FromRequest, FromRequestParts, Request},
    http::{HeaderMap, Method, header::AUTHORIZATION, request::Parts},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, VerifyingKey};
use uuid::Uuid;
use veil_proto::{AuditEventBatch, PrincipalKind};
use veil_proto::{RequestToSign, body_hash, signing_input};

use crate::{
    app::AppState,
    error::ApiError,
    store::{Scope, now},
};

/// How far a device's clock may be from the service's.
const MAX_SKEW_SECONDS: u64 = 300;

/// The owner, holding a session token and allowed to write.
///
/// Any other authenticated principal (a signed Device request, a Workload token) is refused
/// with `403`; a request with no credential is `401`.
#[derive(Debug, Clone, Copy)]
pub struct Owner(pub Uuid);

/// A caller allowed to read.
#[derive(Debug, Clone, Copy)]
pub enum Reader {
    /// The owner's session.
    Owner {
        /// Account the session belongs to.
        account_id: Uuid,
    },
    /// A device signing its request.
    Device {
        /// Account the device belongs to.
        account_id: Uuid,
        /// Device id, for scoping the sync document.
        device_id: Uuid,
        /// An Owner Device reads the whole Account.
        owner: bool,
    },
    /// A CI workload holding a short-lived token.
    Workload {
        /// Account the workload belongs to.
        account_id: Uuid,
        /// Workload id, for scoping the sync document.
        workload_id: Uuid,
    },
}

impl Reader {
    /// The account behind the caller.
    pub fn account_id(&self) -> Uuid {
        match self {
            Self::Owner { account_id }
            | Self::Device { account_id, .. }
            | Self::Workload { account_id, .. } => *account_id,
        }
    }

    /// Which Vaults the caller may read.
    pub fn scope(&self) -> Scope {
        match *self {
            Self::Owner { .. } | Self::Device { owner: true, .. } => Scope::Owner,
            Self::Device { device_id, .. } => Scope::Granted(device_id),
            Self::Workload { workload_id, .. } => Scope::Granted(workload_id),
        }
    }
}

impl FromRequestParts<AppState> for Owner {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let Some(token) = bearer(parts) else {
            // A signed request is a Device, which never writes.
            return Err(if parts.headers.contains_key("x-veil-device") {
                ApiError::forbidden()
            } else {
                ApiError::unauthorized()
            });
        };
        let at = now();
        if let Some(account_id) = state
            .store
            .session_account(&token, at)
            .map_err(ApiError::from)?
        {
            return Ok(Self(account_id));
        }
        if state
            .store
            .workload_token(&token, at)
            .map_err(ApiError::from)?
            .is_some()
        {
            return Err(ApiError::forbidden());
        }
        Err(ApiError::unauthorized())
    }
}

impl FromRequestParts<AppState> for Reader {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        if let Some(token) = bearer(parts) {
            if let Some(account_id) = state
                .store
                .session_account(&token, now())
                .map_err(ApiError::from)?
            {
                return Ok(Self::Owner { account_id });
            }
            if let Some((account_id, workload_id)) = state
                .store
                .workload_token(&token, now())
                .map_err(ApiError::from)?
            {
                return Ok(Self::Workload {
                    account_id,
                    workload_id,
                });
            }
            return Err(ApiError::unauthorized());
        }

        let device = verify_device(parts, state)?;
        Ok(Self::Device {
            account_id: device.account_id,
            device_id: device.device_id,
            owner: device.owner,
        })
    }
}

/// A device whose signature checked out.
#[derive(Debug, Clone, Copy)]
pub(crate) struct SignedDevice {
    account_id: Uuid,
    device_id: Uuid,
    owner: bool,
}

fn bearer(parts: &Parts) -> Option<String> {
    parts
        .headers
        .get(AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
        .map(str::to_owned)
}

fn verify_device(parts: &Parts, state: &AppState) -> Result<SignedDevice, ApiError> {
    // Reads carry no body, so the signature covers the empty hash.
    if !matches!(parts.method.as_str(), "GET" | "HEAD") {
        return Err(ApiError::forbidden());
    }
    authenticate_device(
        &parts.headers,
        &parts.method,
        parts.uri.path(),
        &body_hash(b""),
        state,
    )
}

/// Checks a device signature over an optional body.
pub(crate) fn authenticate_device(
    headers: &HeaderMap,
    method: &Method,
    path: &str,
    digest: &[u8],
    state: &AppState,
) -> Result<SignedDevice, ApiError> {
    let device_id = header_value(headers, "x-veil-device")?
        .parse::<Uuid>()
        .map_err(|_| ApiError::unauthorized())?;
    let record = state
        .store
        .device_with_account(device_id)
        .map_err(|_| ApiError::unauthorized())?;
    let (account_id, device) = (record.account_id, record.device);
    if device.revoked_at.is_some() {
        return Err(ApiError::unauthorized());
    }

    let timestamp: u64 = header_value(headers, "x-veil-timestamp")?
        .parse()
        .map_err(|_| ApiError::unauthorized())?;
    let at = now();
    if at.abs_diff(timestamp) > MAX_SKEW_SECONDS {
        return Err(ApiError::unauthorized());
    }

    let nonce = header_value(headers, "x-veil-nonce")?;
    let signature = header_value(headers, "x-veil-signature")?;
    let account = account_id.to_string();
    let request = RequestToSign {
        account_id: &account,
        method: method.as_str(),
        path,
        body_hash: digest,
        timestamp,
        nonce: nonce.as_bytes(),
    };

    verify_signature(&device.auth_pk, &signing_input(&request), &signature)?;
    state
        .store
        .use_nonce(device_id, &nonce, at)
        .map_err(|_| ApiError::unauthorized())?;

    Ok(SignedDevice {
        account_id,
        device_id,
        owner: device.owner,
    })
}

/// Checks an Ed25519 signature against a base64url public key.
pub(crate) fn verify_signature(
    auth_pk: &str,
    message: &[u8],
    signature: &str,
) -> Result<(), ApiError> {
    let key: [u8; 32] = URL_SAFE_NO_PAD
        .decode(auth_pk)
        .map_err(|_| ApiError::unauthorized())?
        .try_into()
        .map_err(|_| ApiError::unauthorized())?;
    let key = VerifyingKey::from_bytes(&key).map_err(|_| ApiError::unauthorized())?;
    let signature = URL_SAFE_NO_PAD
        .decode(signature)
        .map_err(|_| ApiError::unauthorized())?;
    let signature = Signature::from_slice(&signature).map_err(|_| ApiError::unauthorized())?;
    key.verify_strict(message, &signature)
        .map_err(|_| ApiError::unauthorized())
}

fn header_value(headers: &HeaderMap, name: &'static str) -> Result<String, ApiError> {
    headers
        .get(name)
        .ok_or_else(ApiError::unauthorized)?
        .to_str()
        .map(str::to_owned)
        .map_err(|_| ApiError::unauthorized())
}

/// A batch of delivery events, with the principal that reported it.
pub struct DeliveryBatch {
    /// Account the principal belongs to.
    pub account_id: Uuid,
    /// Device or workload that delivered.
    pub principal_id: Uuid,
    /// What kind of principal it was.
    pub kind: PrincipalKind,
    /// Which Vaults the principal may read, and so report on.
    pub scope: Scope,
    /// The events.
    pub events: Vec<veil_proto::AuditEventInput>,
}

impl FromRequest<AppState> for DeliveryBatch {
    type Rejection = ApiError;

    async fn from_request(request: Request, state: &AppState) -> Result<Self, Self::Rejection> {
        let (parts, body) = request.into_parts();
        let bytes = axum::body::to_bytes(body, 256 * 1024)
            .await
            .map_err(|_| ApiError::bad_request("body is too large or unreadable"))?;

        let (account_id, principal_id, kind, scope) = match bearer(&parts) {
            Some(token) => {
                if let Some(account_id) = state
                    .store
                    .session_account(&token, now())
                    .map_err(ApiError::from)?
                {
                    (account_id, account_id, PrincipalKind::Owner, Scope::Owner)
                } else if let Some((account_id, workload_id)) = state
                    .store
                    .workload_token(&token, now())
                    .map_err(ApiError::from)?
                {
                    (
                        account_id,
                        workload_id,
                        PrincipalKind::Workload,
                        Scope::Granted(workload_id),
                    )
                } else {
                    return Err(ApiError::unauthorized());
                }
            }
            None => {
                let device = authenticate_device(
                    &parts.headers,
                    &parts.method,
                    parts.uri.path(),
                    &body_hash(&bytes),
                    state,
                )?;
                let scope = if device.owner {
                    Scope::Owner
                } else {
                    Scope::Granted(device.device_id)
                };
                (
                    device.account_id,
                    device.device_id,
                    PrincipalKind::Device,
                    scope,
                )
            }
        };

        let batch: AuditEventBatch = serde_json::from_slice(&bytes)
            .map_err(|_| ApiError::bad_request("events are not valid JSON"))?;
        Ok(Self {
            account_id,
            principal_id,
            kind,
            scope,
            events: batch.events,
        })
    }
}
