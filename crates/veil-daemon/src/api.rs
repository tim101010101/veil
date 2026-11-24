//! HTTP handlers. They parse, authorize, and delegate; all storage work lives in `store`.

use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode, header::AUTHORIZATION},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rand_core::RngCore;
use serde::Deserialize;
use uuid::Uuid;
use veil_proto::{
    Account, ApproveDeviceRequest, BeginDeviceEnrollmentRequest, BitwardenStatus,
    CreateAccountRequest, CreateAccountResponse, CreateRecoveryRequest, CreateRecoveryResponse,
    CreateSessionRequest, CreateSessionResponse, CreateVaultRequest, CreateWorkloadRequest, Device,
    EnableBitwardenRequest, EnableTwoStepRequest, EnrollmentProof, EnrollmentResponse,
    ExchangeWorkloadTokenRequest, Item, Kdf, PendingDevice, PreloginRequest, PreloginResponse,
    PutItemRequest, RotateVaultRequest, Session, SyncDocument, UpdateAccountRequest,
    UpdateVaultRequest, Vault, Workload, WorkloadToken,
};

use crate::{
    app::AppState,
    auth::{DeliveryBatch, Owner, Reader},
    error::ApiError,
    store::{AuditFilter, StoreError, now, now_ms},
    throttle::ClientIp,
};

/// How long a session token stays usable.
const SESSION_SECONDS: u64 = 12 * 60 * 60;

/// KDF answered for an address with no account, so prelogin does not reveal existence.
pub const DEFAULT_KDF: Kdf = Kdf::Argon2id {
    iterations: 6,
    memory_mib: 32,
    parallelism: 4,
};

/// Query for the audit list.
#[derive(Debug, Deserialize)]
pub struct AuditQuery {
    limit: Option<usize>,
    before: Option<u64>,
    vault_id: Option<Uuid>,
    item_id: Option<Uuid>,
}

/// Query for an incremental sync.
#[derive(Debug, Deserialize)]
pub struct SyncQuery {
    since: Option<u64>,
}

pub(crate) fn new_token() -> String {
    let mut bytes = [0u8; 32];
    rand_core::OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn issue(
    state: &AppState,
    account_id: Uuid,
    device_id: Uuid,
    at: u64,
) -> Result<Session, ApiError> {
    let token = new_token();
    let expires_at = at + SESSION_SECONDS;
    state
        .store
        .create_session(account_id, device_id, &token, expires_at)?;
    Ok(Session { token, expires_at })
}

fn created_or_ok(created: bool) -> StatusCode {
    if created {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    }
}

/// The KDF parameters for an address; unknown addresses get [`DEFAULT_KDF`].
pub async fn prelogin(
    State(state): State<AppState>,
    Json(request): Json<PreloginRequest>,
) -> Result<Json<PreloginResponse>, ApiError> {
    let kdf = state.store.prelogin_kdf(&request.email)?;
    Ok(Json(PreloginResponse {
        kdf: kdf.unwrap_or(DEFAULT_KDF),
    }))
}

/// Creates the account and its first device, an Owner Device.
pub async fn create_account(
    State(state): State<AppState>,
    Json(request): Json<CreateAccountRequest>,
) -> Result<(StatusCode, Json<CreateAccountResponse>), ApiError> {
    if request.email.trim().is_empty() {
        return Err(ApiError::bad_request("email is required"));
    }
    let at = now();
    state
        .store
        .create_account(&request, at)
        .map_err(|error| match error {
            StoreError::Conflict => ApiError::conflict("an account with this email already exists"),
            other => ApiError::from(other),
        })?;
    let device = state.store.device(request.device.id)?;
    let session = issue(&state, request.id, request.device.id, at)?;

    Ok((
        StatusCode::CREATED,
        Json(CreateAccountResponse {
            account: Account {
                id: request.id,
                email: request.email.trim().to_lowercase(),
            },
            device,
            session,
        }),
    ))
}

/// Exchanges the authentication hash for a session and the wrapped account key.
pub async fn create_session(
    State(state): State<AppState>,
    client: ClientIp,
    Json(request): Json<CreateSessionRequest>,
) -> Result<Json<CreateSessionResponse>, ApiError> {
    let at = now();
    state
        .throttle
        .admit(client, &request.email, at, "session")
        .map_err(|limited| ApiError::too_many_requests(limited.retry_after))?;
    let Ok(account) = state.store.authenticate(&request.email, &request.auth_hash) else {
        state
            .throttle
            .record_failure(client, &request.email, at, "session");
        return Err(ApiError::unauthorized());
    };
    state.throttle.succeed(&request.email);
    let proof = request.device.as_ref().ok_or_else(|| {
        ApiError::bad_request("device proof required; upgrade veil and run veil login again")
    })?;
    if at.abs_diff(proof.timestamp) > 300 || proof.nonce.is_empty() {
        return Err(ApiError::unauthorized());
    }
    crate::auth::verify_signature(
        &proof.keys.auth_pk,
        &veil_proto::session_input(&request.email, &request.auth_hash, proof),
        &proof.signature,
    )?;
    let device = state.store.login_device(account.id, proof, at)?;
    let session = issue(&state, account.id, proof.keys.id, at)?;
    Ok(Json(CreateSessionResponse {
        device,
        account: Account {
            id: account.id,
            email: account.email,
        },
        session,
        protected_account_key: account.protected_account_key,
        account_keys: account.account_keys,
    }))
}

/// Ends the current session.
pub async fn delete_session(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    if let Some(token) = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
    {
        state.store.delete_session(token)?;
    }
    Ok(StatusCode::NO_CONTENT)
}

/// Replaces the master password or KDF: new authentication hash and new account key wrap.
pub async fn update_account(
    State(state): State<AppState>,
    Owner(account_id): Owner,
    Json(request): Json<UpdateAccountRequest>,
) -> Result<StatusCode, ApiError> {
    state.store.update_account(account_id, &request, now_ms())?;
    Ok(StatusCode::NO_CONTENT)
}

/// Rebuilds access from the recovery code and registers a new Owner Device.
pub async fn create_recovery(
    State(state): State<AppState>,
    client: ClientIp,
    Json(request): Json<CreateRecoveryRequest>,
) -> Result<Json<CreateRecoveryResponse>, ApiError> {
    let at = now();
    state
        .throttle
        .admit(client, &request.email, at, "recovery")
        .map_err(|limited| ApiError::too_many_requests(limited.retry_after))?;
    let Ok(account) = state
        .store
        .authenticate_recovery(&request.email, &request.recovery_proof)
    else {
        state
            .throttle
            .record_failure(client, &request.email, at, "recovery");
        return Err(ApiError::unauthorized());
    };
    state.throttle.succeed(&request.email);
    let device = state
        .store
        .add_owner_device(account.id, &request.device, at)?;
    let session = issue(&state, account.id, device.id, at)?;

    Ok(Json(CreateRecoveryResponse {
        account_id: account.id,
        device,
        session,
        recovery_wrap: account.recovery_wrap,
    }))
}

/// The incremental document a client caches.
pub async fn sync(
    State(state): State<AppState>,
    reader: Reader,
    Query(query): Query<SyncQuery>,
) -> Result<Json<SyncDocument>, ApiError> {
    Ok(Json(state.store.sync(
        reader.account_id(),
        reader.scope(),
        query.since,
    )?))
}

/// Creates a Vault with its key wrap, first Items, and Grants.
pub async fn create_vault(
    State(state): State<AppState>,
    Owner(account_id): Owner,
    Json(request): Json<CreateVaultRequest>,
) -> Result<(StatusCode, Json<Vault>), ApiError> {
    let (vault, created) = state.store.create_vault(account_id, &request, now_ms())?;
    Ok((created_or_ok(created), Json(vault)))
}

/// Renames a Vault.
pub async fn update_vault(
    State(state): State<AppState>,
    Owner(account_id): Owner,
    Path(id): Path<Uuid>,
    Json(request): Json<UpdateVaultRequest>,
) -> Result<Json<Vault>, ApiError> {
    Ok(Json(state.store.update_vault(
        account_id,
        id,
        &request,
        now_ms(),
    )?))
}

/// Removes a Vault, its Items, and its Grants.
pub async fn delete_vault(
    State(state): State<AppState>,
    Owner(account_id): Owner,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    state.store.delete_vault(account_id, id)?;
    Ok(StatusCode::NO_CONTENT)
}

/// Creates or replaces one Item.
pub async fn put_item(
    State(state): State<AppState>,
    Owner(account_id): Owner,
    Path((vault_id, item_id)): Path<(Uuid, Uuid)>,
    Json(request): Json<PutItemRequest>,
) -> Result<(StatusCode, Json<Item>), ApiError> {
    let (item, created) =
        state
            .store
            .put_item(account_id, vault_id, item_id, &request, now_ms())?;
    Ok((created_or_ok(created), Json(item)))
}

/// Removes one Item.
pub async fn delete_item(
    State(state): State<AppState>,
    Owner(account_id): Owner,
    Path((vault_id, item_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, ApiError> {
    state
        .store
        .delete_item(account_id, vault_id, item_id, now_ms())?;
    Ok(StatusCode::NO_CONTENT)
}

/// Moves a Vault to a new key generation.
pub async fn rotate_vault(
    State(state): State<AppState>,
    Owner(account_id): Owner,
    Path(id): Path<Uuid>,
    Json(request): Json<RotateVaultRequest>,
) -> Result<Json<Vault>, ApiError> {
    Ok(Json(state.store.rotate_vault(
        account_id,
        id,
        &request,
        now_ms(),
    )?))
}

/// Records a device that wants to enroll. The answer never reveals whether the account exists.
pub async fn begin_device(
    State(state): State<AppState>,
    Json(request): Json<BeginDeviceEnrollmentRequest>,
) -> Result<StatusCode, ApiError> {
    if let Ok(account) = state.store.account_by_email(&request.email) {
        state
            .store
            .put_pending_device(account.id, &request.code, &request.device, now())?;
    }
    Ok(StatusCode::ACCEPTED)
}

/// Approves a pending device by attaching its Grants.
pub async fn approve_device(
    State(state): State<AppState>,
    Owner(account_id): Owner,
    Path(code): Path<String>,
    Json(request): Json<ApproveDeviceRequest>,
) -> Result<(StatusCode, Json<Device>), ApiError> {
    let device = state
        .store
        .approve_device(account_id, &code, &request.grants, now())?;
    Ok((StatusCode::CREATED, Json(device)))
}

/// Lists devices waiting for approval.
pub async fn pending_devices(
    State(state): State<AppState>,
    Owner(account_id): Owner,
) -> Result<Json<Vec<PendingDevice>>, ApiError> {
    Ok(Json(state.store.pending_devices(account_id)?))
}

/// Lists approved and revoked devices.
pub async fn list_devices(
    State(state): State<AppState>,
    Owner(account_id): Owner,
) -> Result<Json<Vec<Device>>, ApiError> {
    Ok(Json(state.store.devices(account_id)?))
}

/// Finishes enrollment for an approved device, proving possession of its key.
pub async fn device_enrollment(
    State(state): State<AppState>,
    Query(proof): Query<EnrollmentProof>,
) -> Result<Json<EnrollmentResponse>, ApiError> {
    let record = state
        .store
        .device_with_account(proof.device_id)
        .map_err(ApiError::from)?;
    let (account_id, device) = (record.account_id, record.device);
    if device.revoked_at.is_some() {
        return Err(ApiError::unauthorized());
    }
    let at = now();
    if at.abs_diff(proof.timestamp) > 300 {
        return Err(ApiError::unauthorized());
    }
    let code = state.store.device_code(proof.device_id)?;
    if code != proof.code {
        return Err(ApiError::unauthorized());
    }
    crate::auth::verify_signature(
        &device.auth_pk,
        &veil_proto::enrollment_input(proof.device_id, &proof.code, proof.timestamp),
        &proof.signature,
    )?;
    state
        .store
        .use_nonce(proof.device_id, &proof.nonce, at)
        .map_err(|_| ApiError::unauthorized())?;

    let (email, grants) = state.store.enrollment(proof.device_id)?;
    Ok(Json(EnrollmentResponse {
        account_id,
        email,
        device,
        grants,
    }))
}

/// Revokes a device: its Grants go at once and its Vaults become due a rotation.
pub async fn revoke_device(
    State(state): State<AppState>,
    Owner(account_id): Owner,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    state.store.revoke_device(account_id, id, now())?;
    Ok(StatusCode::NO_CONTENT)
}

/// Records delivery events reported by a device or workload.
pub async fn report_events(
    State(state): State<AppState>,
    batch: DeliveryBatch,
) -> Result<StatusCode, ApiError> {
    state.store.record_audit(
        batch.account_id,
        batch.principal_id,
        batch.kind,
        batch.scope,
        &batch.events,
        now(),
    )?;
    Ok(StatusCode::ACCEPTED)
}

/// Lists delivery events, newest first.
pub async fn audit_events(
    State(state): State<AppState>,
    Owner(account_id): Owner,
    Query(query): Query<AuditQuery>,
) -> Result<Json<Vec<veil_proto::AuditEvent>>, ApiError> {
    Ok(Json(state.store.audit_events(
        account_id,
        &AuditFilter {
            limit: query.limit.unwrap_or(50),
            before: query.before,
            vault_id: query.vault_id,
            item_id: query.item_id,
        },
    )?))
}

/// Creates a CI workload with its trust policy and Grants.
pub async fn create_workload(
    State(state): State<AppState>,
    Owner(account_id): Owner,
    Json(request): Json<CreateWorkloadRequest>,
) -> Result<(StatusCode, Json<Workload>), ApiError> {
    let (workload, created) = state.store.create_workload(account_id, &request, now())?;
    Ok((created_or_ok(created), Json(workload)))
}

/// Lists CI workloads.
pub async fn list_workloads(
    State(state): State<AppState>,
    Owner(account_id): Owner,
) -> Result<Json<Vec<Workload>>, ApiError> {
    Ok(Json(state.store.workloads(account_id)?))
}

/// Revokes a CI workload: its Grants go at once and its Vaults become due a rotation.
pub async fn revoke_workload(
    State(state): State<AppState>,
    Owner(account_id): Owner,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    state.store.revoke_workload(account_id, id, now())?;
    Ok(StatusCode::NO_CONTENT)
}

/// Exchanges a CI platform's OIDC token for a short-lived workload token.
pub async fn exchange_workload_token(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(request): Json<ExchangeWorkloadTokenRequest>,
) -> Result<Json<WorkloadToken>, ApiError> {
    let (_, workload) = state
        .store
        .workload(id)
        .map_err(|_| ApiError::unauthorized())?;
    if workload.revoked_at.is_some() {
        return Err(ApiError::unauthorized());
    }

    let policy = workload.trust_policy.clone();
    let presented = request.oidc_token;
    let outcome = tokio::task::spawn_blocking(move || crate::oidc::verify(&policy, &presented))
        .await
        .map_err(|error| {
            tracing::error!(error = %error, "oidc verification task failed");
            ApiError::internal("identity verification unavailable")
        })?;
    if let Err(reason) = outcome {
        tracing::warn!(workload = %id, reason = %reason.0, "oidc token rejected");
        return Err(ApiError::unauthorized());
    }

    let token = new_token();
    let expires_at = now() + 600;
    state.store.create_workload_token(id, &token, expires_at)?;
    Ok(Json(WorkloadToken { token, expires_at }))
}

/// Lets Bitwarden clients see one Vault; replaces any previous choice and signs them all out.
pub async fn enable_bitwarden(
    State(state): State<AppState>,
    Owner(account_id): Owner,
    Json(request): Json<EnableBitwardenRequest>,
) -> Result<Json<BitwardenStatus>, ApiError> {
    Ok(Json(state.store.enable_bitwarden(
        account_id,
        &request,
        now_ms(),
    )?))
}

/// Which Vault Bitwarden clients see.
pub async fn bitwarden_status(
    State(state): State<AppState>,
    Owner(account_id): Owner,
) -> Result<Json<BitwardenStatus>, ApiError> {
    state
        .store
        .bitwarden_status(account_id)?
        .map(Json)
        .ok_or_else(ApiError::not_found)
}

/// Turns on two-step login for Bitwarden clients once a current code proves the authenticator
/// holds the secret.
pub async fn enable_two_step(
    State(state): State<AppState>,
    Owner(account_id): Owner,
    Json(request): Json<EnableTwoStepRequest>,
) -> Result<StatusCode, ApiError> {
    if !crate::totp::valid_secret(&request.secret) {
        return Err(ApiError::bad_request(
            "the secret must be base32 and at least 128 bits",
        ));
    }
    let at = now();
    let step = crate::totp::verify(&request.secret, &request.code, at)
        .ok_or_else(|| ApiError::bad_request("the code does not match the secret"))?;
    state
        .store
        .enable_two_step(account_id, &request.secret, step, at)?;
    tracing::info!(
        event = "two-step-enabled",
        "Bitwarden two-step login turned on"
    );
    Ok(StatusCode::NO_CONTENT)
}

/// Turns two-step login for Bitwarden clients off.
pub async fn disable_two_step(
    State(state): State<AppState>,
    Owner(account_id): Owner,
) -> Result<StatusCode, ApiError> {
    state.store.disable_two_step(account_id)?;
    tracing::warn!(
        event = "two-step-disabled",
        "Bitwarden two-step login turned off"
    );
    Ok(StatusCode::NO_CONTENT)
}

/// Stops serving Bitwarden clients and signs them all out.
pub async fn disable_bitwarden(
    State(state): State<AppState>,
    Owner(account_id): Owner,
) -> Result<StatusCode, ApiError> {
    state.store.disable_bitwarden(account_id)?;
    Ok(StatusCode::NO_CONTENT)
}
