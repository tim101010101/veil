//! The Bitwarden client API: the subset official clients need for one personal Vault.
//!
//! These routes map stored fields to Bitwarden's JSON shapes. They never decrypt and never parse
//! a sealed string. A Bitwarden login sees exactly the Vault in its Account's binding, whose key
//! is the login's user key. Bitwarden bearer tokens are accepted here only, and Veil
//! credentials are not.

mod identity;
mod vault;

use axum::{
    Json, Router,
    body::Bytes,
    extract::{FromRequest, FromRequestParts, Request},
    http::{StatusCode, header::AUTHORIZATION, request::Parts},
    middleware::Next,
    response::{IntoResponse, Response},
    routing::{get, post, put},
};
use serde::de::DeserializeOwned;
use serde_json::json;
use time::{OffsetDateTime, format_description::well_known::Rfc3339, macros::format_description};
use tower_http::cors::CorsLayer;
use uuid::Uuid;

use crate::{
    app::AppState,
    store::{StoreError, now},
};

/// Builds the Bitwarden routes. They live at the paths the clients call, outside `/api/v1`.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/identity/accounts/prelogin", post(identity::prelogin))
        .route(
            "/identity/accounts/prelogin/password",
            post(identity::prelogin),
        )
        .route("/api/accounts/prelogin", post(identity::prelogin))
        .route("/identity/connect/token", post(identity::token))
        .route("/api/config", get(vault::config))
        .route("/api/sync", get(vault::sync))
        .route("/api/accounts/profile", get(vault::profile))
        .route("/api/accounts/revision-date", get(vault::revision_date))
        .route(
            "/api/accounts/key-management/user-key-id",
            post(vault::set_user_key_id),
        )
        .route("/api/devices/knowndevice", get(vault::known_device))
        .route("/api/ciphers", post(vault::create_cipher))
        .route("/api/ciphers/create", post(vault::create_cipher))
        .route("/api/ciphers/import", post(vault::import_ciphers))
        .route("/api/ciphers/delete", put(vault::trash_ciphers))
        .route("/api/ciphers/restore", put(vault::restore_ciphers))
        .route(
            "/api/ciphers/{id}",
            get(vault::get_cipher)
                .put(vault::update_cipher)
                .post(vault::update_cipher)
                .delete(vault::delete_cipher),
        )
        .route("/api/ciphers/{id}/partial", put(vault::partial_cipher))
        .route(
            "/api/ciphers/{id}/delete",
            put(vault::trash_cipher).post(vault::delete_cipher),
        )
        .route("/api/ciphers/{id}/restore", put(vault::restore_cipher))
        .route(
            "/api/folders",
            get(vault::folders).post(vault::create_folder),
        )
        .route(
            "/api/folders/{id}",
            put(vault::rename_folder).delete(vault::delete_folder),
        )
        // The clients call from extension and web origins with bearer tokens, never cookies,
        // so answering any origin exposes nothing a direct request would not.
        .layer(CorsLayer::permissive())
}

/// Whether a path belongs to the Bitwarden surface, matched or not.
fn is_bitwarden_path(path: &str) -> bool {
    if path.starts_with("/api/v1/") || path == "/api/v1" {
        return false;
    }
    ["/api/", "/identity/", "/icons/", "/notifications/"]
        .iter()
        .any(|prefix| path.starts_with(prefix))
}

/// Logs every Bitwarden request at debug level, so endpoints a new client release needs show
/// up as `404`s in the log.
pub async fn log_requests(request: Request, next: Next) -> Response {
    if !is_bitwarden_path(request.uri().path()) {
        return next.run(request).await;
    }
    let method = request.method().clone();
    let path = request.uri().path().to_owned();
    let response = next.run(request).await;
    tracing::debug!(%method, %path, status = response.status().as_u16(), "bitwarden request");
    response
}

/// An error in the shape Bitwarden clients display: `{message, validationErrors, object}`.
#[derive(Debug)]
pub struct BwError {
    status: StatusCode,
    message: String,
}

impl BwError {
    fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }

    fn bad_request(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, message)
    }

    fn unauthorized() -> Self {
        Self::new(StatusCode::UNAUTHORIZED, "Unauthorized.")
    }

    fn not_found() -> Self {
        Self::new(StatusCode::NOT_FOUND, "Resource not found.")
    }
}

impl From<StoreError> for BwError {
    fn from(error: StoreError) -> Self {
        match error {
            StoreError::NotFound => Self::not_found(),
            StoreError::Invalid(message) => Self::bad_request(message),
            StoreError::Conflict => Self::new(StatusCode::CONFLICT, "The object changed."),
            StoreError::Forbidden => Self::new(StatusCode::FORBIDDEN, "Not permitted."),
            StoreError::IncompatibleSchema(_) | StoreError::Database(_) => {
                tracing::error!(error = %error, "storage failure");
                Self::new(StatusCode::INTERNAL_SERVER_ERROR, "Storage unavailable.")
            }
        }
    }
}

impl IntoResponse for BwError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(json!({
                "message": self.message,
                "validationErrors": null,
                "object": "error",
            })),
        )
            .into_response()
    }
}

/// A JSON body read regardless of `Content-Type`, refused in the Bitwarden error shape.
pub struct BwJson<T>(pub T);

impl<T: DeserializeOwned, S: Send + Sync> FromRequest<S> for BwJson<T> {
    type Rejection = BwError;

    async fn from_request(request: Request, state: &S) -> Result<Self, Self::Rejection> {
        let bytes = Bytes::from_request(request, state)
            .await
            .map_err(|_| BwError::bad_request("The request body could not be read."))?;
        serde_json::from_slice(&bytes)
            .map(Self)
            .map_err(|error| BwError::bad_request(format!("The request body is invalid: {error}")))
    }
}

/// A caller holding a live Bitwarden access token.
#[derive(Debug, Clone, Copy)]
pub struct BitwardenLogin {
    /// The Account behind the login.
    pub account_id: Uuid,
}

impl FromRequestParts<AppState> for BitwardenLogin {
    type Rejection = BwError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let token = parts
            .headers
            .get(AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "))
            .ok_or_else(BwError::unauthorized)?;
        let (account_id, session) =
            identity::verify_access_token(state.store.token_secret(), token)
                .ok_or_else(BwError::unauthorized)?;
        if !state
            .store
            .bitwarden_session_live(session, account_id, now())?
        {
            return Err(BwError::unauthorized());
        }
        Ok(Self { account_id })
    }
}

/// RFC 3339 with milliseconds and `Z`, as the clients send it back.
fn format_ms(ms: u64) -> String {
    let format =
        format_description!("[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:3]Z");
    OffsetDateTime::from_unix_timestamp_nanos(i128::from(ms) * 1_000_000)
        .ok()
        .and_then(|at| at.format(&format).ok())
        .unwrap_or_default()
}

/// Milliseconds since the epoch of an RFC 3339 date.
fn parse_ms(text: &str) -> Option<u64> {
    let at = OffsetDateTime::parse(text, &Rfc3339).ok()?;
    u64::try_from(at.unix_timestamp_nanos() / 1_000_000).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates_round_trip_at_millisecond_resolution() {
        let text = format_ms(1_762_862_400_123);

        assert_eq!(text, "2025-11-11T12:00:00.123Z");
        assert_eq!(parse_ms(&text), Some(1_762_862_400_123));
        assert_eq!(
            parse_ms("2025-11-11T13:00:00.123+01:00"),
            Some(1_762_862_400_123)
        );
        assert_eq!(parse_ms("yesterday"), None);
    }

    #[test]
    fn the_veil_api_is_not_a_bitwarden_path() {
        assert!(is_bitwarden_path("/api/sync"));
        assert!(is_bitwarden_path("/identity/connect/token"));
        assert!(is_bitwarden_path("/notifications/hub"));
        assert!(!is_bitwarden_path("/api/v1/sync"));
        assert!(!is_bitwarden_path("/healthz"));
    }
}
