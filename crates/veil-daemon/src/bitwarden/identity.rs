//! Prelogin and `connect/token`: a Bitwarden login with the same server authorization hash a
//! Veil Session uses, granted only while the Account has a binding.

use std::collections::HashMap;

use axum::{
    Form, Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use bitwarden_api_identity::models as idm;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uuid::Uuid;
use veil_proto::Kdf;

use super::{BwError, BwJson};
use crate::{
    api::{DEFAULT_KDF, new_token},
    app::AppState,
    store::{BitwardenAccount, StoreError, now},
    throttle::{ClientIp, Limited},
};

/// How long an access token is valid.
const ACCESS_SECONDS: u64 = 60 * 60;
/// How long a refresh token is valid; each refresh starts a new period.
const REFRESH_SECONDS: u64 = 30 * 24 * 60 * 60;
/// `iss` of the access tokens.
const ISSUER: &str = "veil|login";
/// The scopes a password login receives.
const SCOPES: [&str; 2] = ["api", "offline_access"];

/// `{email}`, as the clients send it to the prelogin endpoints.
#[derive(Debug, Deserialize)]
pub struct PreloginBody {
    #[serde(alias = "Email")]
    email: String,
}

/// The claims of an access token. The clients read `sub`, `email`, `name`, and `premium`.
#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    nbf: u64,
    exp: u64,
    iss: String,
    sub: String,
    email: String,
    email_verified: bool,
    name: String,
    premium: bool,
    amr: Vec<String>,
    sstamp: String,
    device: String,
    scope: Vec<String>,
    jti: String,
}

/// The KDF in the numbers Bitwarden uses: type, iterations, memory (MiB), parallelism.
fn kdf_numbers(kdf: &Kdf) -> (idm::KdfType, i32, Option<i32>, Option<i32>) {
    let clamp = |value: u32| i32::try_from(value).unwrap_or(i32::MAX);
    match *kdf {
        Kdf::Pbkdf2 { iterations } => (idm::KdfType::PBKDF2_SHA256, clamp(iterations), None, None),
        Kdf::Argon2id {
            iterations,
            memory_mib,
            parallelism,
        } => (
            idm::KdfType::Argon2id,
            clamp(iterations),
            Some(clamp(memory_mib)),
            Some(clamp(parallelism)),
        ),
    }
}

/// `MasterPasswordUnlock`, as both the token response and sync carry it.
pub(super) fn master_password_unlock(account: &BitwardenAccount) -> Value {
    let (kind, iterations, memory, parallelism) = kdf_numbers(&account.kdf);
    json!({
        "Kdf": {
            "KdfType": kind.as_i64(),
            "Iterations": iterations,
            "Memory": memory,
            "Parallelism": parallelism,
        },
        "MasterKeyEncryptedUserKey": account.binding.protected_key,
        "Salt": account.email,
    })
}

/// The stored `AccountKeys` JSON text as a JSON value. It was checked to be JSON when stored.
pub(super) fn account_keys(account: &BitwardenAccount) -> Value {
    serde_json::from_str(&account.binding.account_keys).unwrap_or(Value::Null)
}

/// The KDF for an address and the salt: the normalized address. Unknown addresses get the
/// same default as the Veil prelogin, so the answer does not reveal whether an account exists.
pub async fn prelogin(
    State(state): State<AppState>,
    BwJson(body): BwJson<PreloginBody>,
) -> Result<Json<idm::PasswordPreloginResponseModel>, BwError> {
    let kdf = state
        .store
        .prelogin_kdf(&body.email)?
        .unwrap_or(DEFAULT_KDF);
    let (kind, iterations, memory, parallelism) = kdf_numbers(&kdf);
    Ok(Json(idm::PasswordPreloginResponseModel {
        kdf: Some(kind),
        kdf_iterations: Some(iterations),
        kdf_memory: memory,
        kdf_parallelism: parallelism,
        kdf_settings: Some(Box::new(idm::KdfSettings {
            kdf_type: kind,
            iterations,
            memory,
            parallelism,
        })),
        salt: Some(body.email.trim().to_lowercase()),
    }))
}

/// `connect/token`: OAuth, so not in the Bitwarden OpenAPI document; the shape is the one the
/// clients were proven against.
pub async fn token(
    State(state): State<AppState>,
    client: ClientIp,
    Form(form): Form<HashMap<String, String>>,
) -> Result<Response, BwError> {
    let field = |name: &str| form.get(name).map(String::as_str);
    let at = now();
    let refresh_token = new_token();
    let expires_at = at + REFRESH_SECONDS;

    let session = match field("grant_type") {
        Some("password") => {
            let (Some(username), Some(password)) = (field("username"), field("password")) else {
                return Ok(invalid_grant());
            };
            if let Err(limited) = state.throttle.admit(client, username, at, "bitwarden") {
                return Ok(throttled(limited));
            }
            let account = match state.store.authenticate(username, password) {
                Ok(account) => account,
                Err(StoreError::NotFound) => {
                    state
                        .throttle
                        .record_failure(client, username, at, "bitwarden");
                    return Ok(invalid_grant());
                }
                Err(error) => return Err(error.into()),
            };
            // Only an Account that chose a Vault for Bitwarden clients may log in with them.
            if state.store.bitwarden_status(account.id)?.is_none() {
                state
                    .throttle
                    .record_failure(client, username, at, "bitwarden");
                return Ok(invalid_grant());
            }
            if let Some(secret) = state.store.two_step_secret(account.id)? {
                let code = field("twoFactorToken").filter(|code| !code.trim().is_empty());
                let Some(code) = code.filter(|_| field("twoFactorProvider") == Some(AUTHENTICATOR))
                else {
                    return Ok(two_step_required());
                };
                let spent = match crate::totp::verify(&secret, code, at) {
                    Some(step) => state.store.spend_two_step(account.id, step)?,
                    None => false,
                };
                if !spent {
                    state
                        .throttle
                        .record_failure(client, username, at, "bitwarden-two-step");
                    return Ok(invalid_two_step());
                }
            }
            state.throttle.succeed(username);
            let session =
                state
                    .store
                    .create_bitwarden_session(account.id, &refresh_token, expires_at)?;
            (session, account.id)
        }
        Some("refresh_token") => {
            let Some(presented) = field("refresh_token") else {
                return Ok(invalid_grant());
            };
            match state.store.refresh_bitwarden_session(
                presented,
                &refresh_token,
                at,
                expires_at,
            )? {
                Some(found) => found,
                None => return Ok(invalid_grant()),
            }
        }
        _ => {
            return Ok((
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "unsupported_grant_type" })),
            )
                .into_response());
        }
    };

    let (session, account_id) = session;
    let account = match state.store.bitwarden_account(account_id) {
        Ok(account) => account,
        Err(StoreError::NotFound) => return Ok(invalid_grant()),
        Err(error) => return Err(error.into()),
    };
    let device = field("deviceIdentifier").unwrap_or("unknown");
    let access_token = sign(state.store.token_secret(), &account, session, device, at)?;
    let (kind, iterations, memory, parallelism) = kdf_numbers(&account.kdf);

    Ok(Json(json!({
        "access_token": access_token,
        "expires_in": ACCESS_SECONDS,
        "token_type": "Bearer",
        "refresh_token": refresh_token,
        "scope": SCOPES.join(" "),
        "Key": account.binding.protected_key,
        "PrivateKey": account.binding.private_key,
        "Kdf": kind.as_i64(),
        "KdfIterations": iterations,
        "KdfMemory": memory,
        "KdfParallelism": parallelism,
        "ResetMasterPassword": false,
        "ForcePasswordReset": false,
        "MasterPasswordPolicy": { "Object": "masterPasswordPolicy" },
        "UserDecryptionOptions": {
            "HasMasterPassword": true,
            "Object": "userDecryptionOptions",
            "MasterPasswordUnlock": master_password_unlock(&account),
        },
        "AccountKeys": account_keys(&account),
        "unofficialServer": true,
    }))
    .into_response())
}

/// The refusal for any failed grant; it never says which part was wrong.
fn invalid_grant() -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({
            "error": "invalid_grant",
            "error_description": "invalid_username_or_password",
            "ErrorModel": {
                "Message": "Username or password is incorrect. Try again.",
                "Object": "error",
            },
        })),
    )
        .into_response()
}

/// The Bitwarden two-step provider for authenticator apps (TOTP).
const AUTHENTICATOR: &str = "0";

/// The answer to a correct password when a code is still needed: the clients then ask for one
/// and send it with the password again.
fn two_step_required() -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({
            "error": "invalid_grant",
            "error_description": "Two factor required.",
            "TwoFactorProviders": [AUTHENTICATOR],
            "TwoFactorProviders2": { AUTHENTICATOR: null },
            "MasterPasswordPolicy": { "Object": "masterPasswordPolicy" },
        })),
    )
        .into_response()
}

/// A wrong, expired, or already used code.
fn invalid_two_step() -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({
            "error": "invalid_grant",
            "error_description": "invalid_two_step_token",
            "ErrorModel": {
                "Message": "Two-step token is invalid. Try again.",
                "Object": "error",
            },
        })),
    )
        .into_response()
}

/// The refusal while a source is over its failure limit, in the shape the clients display.
fn throttled(limited: Limited) -> Response {
    let minutes = limited.retry_after.div_ceil(60);
    let mut response = (
        StatusCode::TOO_MANY_REQUESTS,
        Json(json!({
            "error": "invalid_grant",
            "error_description": "too_many_failed_sign_ins",
            "ErrorModel": {
                "Message": format!("Too many failed sign-ins. Try again in {minutes} minutes."),
                "Object": "error",
            },
        })),
    )
        .into_response();
    response
        .headers_mut()
        .insert(axum::http::header::RETRY_AFTER, limited.retry_after.into());
    response
}

fn sign(
    secret: &[u8],
    account: &BitwardenAccount,
    session: Uuid,
    device: &str,
    at: u64,
) -> Result<String, BwError> {
    let claims = Claims {
        nbf: at,
        exp: at + ACCESS_SECONDS,
        iss: ISSUER.to_owned(),
        sub: account.id.to_string(),
        email: account.email.clone(),
        email_verified: true,
        name: account.email.clone(),
        premium: true,
        amr: vec!["Application".to_owned()],
        sstamp: account.binding.security_stamp.clone(),
        device: device.to_owned(),
        scope: SCOPES.iter().map(|scope| (*scope).to_owned()).collect(),
        jti: session.to_string(),
    };
    jsonwebtoken::encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(secret),
    )
    .map_err(|error| {
        tracing::error!(error = %error, "access token could not be signed");
        BwError::new(StatusCode::INTERNAL_SERVER_ERROR, "Token unavailable.")
    })
}

/// Checks an access token's signature, issuer, and lifetime; returns its Account and session.
/// Whether the session is still live is the caller's check.
pub(super) fn verify_access_token(secret: &[u8], token: &str) -> Option<(Uuid, Uuid)> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.leeway = 0;
    validation.validate_nbf = true;
    validation.set_issuer(&[ISSUER]);
    validation.set_required_spec_claims(&["exp", "nbf", "iss", "sub"]);
    let data =
        jsonwebtoken::decode::<Claims>(token, &DecodingKey::from_secret(secret), &validation)
            .ok()?;
    Some((data.claims.sub.parse().ok()?, data.claims.jti.parse().ok()?))
}
