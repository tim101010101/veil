//! HTTP application: router, middleware, and the OpenAPI document.

use std::sync::Arc;

use axum::{
    Json, Router,
    extract::Request,
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{delete, get, post, put},
};
use tower_http::trace::{DefaultOnResponse, TraceLayer};
use tracing::Level;
use utoipa::OpenApi;
use veil_proto::{HealthReport, ServiceStatus};

use crate::{
    api, bitwarden,
    error::ApiError,
    store::Store,
    throttle::{Network, Throttle},
};

/// Value of the OpenTelemetry `service.name` resource attribute.
pub const SERVICE_NAME: &str = "veild";

/// Product version, recorded in the `service.version` resource attribute and in probes.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Source commit, when the build recorded one (`VEIL_BUILD_COMMIT` at compile time).
pub const COMMIT: Option<&str> = option_env!("VEIL_BUILD_COMMIT");

/// Everything a handler needs.
#[derive(Clone)]
pub struct AppState {
    /// The embedded database.
    pub store: Arc<Store>,
    /// Failed sign-ins per client address and account.
    pub throttle: Arc<Throttle>,
    /// Address ranges of the proxies trusted to append the client to `X-Forwarded-For`.
    pub trusted_proxies: Vec<Network>,
}

impl AppState {
    /// State for a service reached directly, with no trusted proxy in front.
    pub fn new(store: Store) -> Self {
        Self {
            store: Arc::new(store),
            throttle: Arc::new(Throttle::default()),
            trusted_proxies: Vec::new(),
        }
    }
}

/// Builds the router.
///
/// Liveness and readiness are separate routes so that orchestration can restart an
/// unresponsive instance without depending on a downstream service. Feature routes mount
/// under [`veil_proto::API_PREFIX`].
pub fn router(state: AppState) -> Router {
    let api = Router::new()
        .route("/api/v1/prelogin", post(api::prelogin))
        .route("/api/v1/accounts", post(api::create_account))
        .route("/api/v1/accounts/current", put(api::update_account))
        .route("/api/v1/sessions", post(api::create_session))
        .route("/api/v1/sessions/current", delete(api::delete_session))
        .route("/api/v1/recoveries", post(api::create_recovery))
        .route("/api/v1/sync", get(api::sync))
        .route("/api/v1/vaults", post(api::create_vault))
        .route(
            "/api/v1/vaults/{id}",
            put(api::update_vault).delete(api::delete_vault),
        )
        .route(
            "/api/v1/vaults/{id}/items/{item_id}",
            put(api::put_item).delete(api::delete_item),
        )
        .route("/api/v1/vaults/{id}/rotate", post(api::rotate_vault))
        .route(
            "/api/v1/bitwarden",
            put(api::enable_bitwarden)
                .get(api::bitwarden_status)
                .delete(api::disable_bitwarden),
        )
        .route(
            "/api/v1/bitwarden/two-step",
            put(api::enable_two_step).delete(api::disable_two_step),
        )
        .route(
            "/api/v1/audit/events",
            post(api::report_events).get(api::audit_events),
        )
        .route(
            "/api/v1/workloads",
            post(api::create_workload).get(api::list_workloads),
        )
        .route("/api/v1/workloads/{id}", delete(api::revoke_workload))
        .route(
            "/api/v1/workloads/{id}/token",
            post(api::exchange_workload_token),
        )
        .route(
            "/api/v1/devices",
            post(api::begin_device).get(api::list_devices),
        )
        .route("/api/v1/devices/pending", get(api::pending_devices))
        .route("/api/v1/devices/enrollment", get(api::device_enrollment))
        .route("/api/v1/devices/{code}/approve", post(api::approve_device))
        .route("/api/v1/devices/{id}", delete(api::revoke_device))
        .layer(middleware::from_fn(check_protocol));

    Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/openapi.json", get(openapi))
        .merge(api)
        .merge(bitwarden::router())
        .with_state(state)
        .layer(middleware::from_fn(bitwarden::log_requests))
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(request_span)
                .on_response(DefaultOnResponse::new().level(Level::INFO)),
        )
}

/// The span of one request: method and path only. A query string can carry a bearer token
/// (Bitwarden clients put one on `/notifications/hub`), so it is never logged.
fn request_span(request: &axum::http::Request<axum::body::Body>) -> tracing::Span {
    tracing::info_span!(
        "request",
        method = %request.method(),
        path = %request.uri().path(),
        version = ?request.version(),
    )
}

/// Header that names the protocol version a client speaks.
pub const PROTOCOL_HEADER: &str = "x-veil-protocol";

/// Refuses a request whose `X-Veil-Protocol` names another version with `426`.
///
/// An absent header is accepted, so probes and simple tools still work.
async fn check_protocol(request: Request, next: Next) -> Response {
    if let Some(value) = request.headers().get(PROTOCOL_HEADER) {
        let speaks = value
            .to_str()
            .ok()
            .and_then(|value| value.trim().parse::<u32>().ok());
        if speaks != Some(veil_proto::PROTOCOL_VERSION) {
            return ApiError::protocol_mismatch();
        }
    }
    next.run(request).await
}

/// `GET /healthz`: the process can answer requests.
#[utoipa::path(
    get,
    path = "/healthz",
    tag = "health",
    responses((status = 200, description = "Service is alive", body = HealthReport))
)]
async fn healthz() -> Json<HealthReport> {
    Json(report(ServiceStatus::Ok))
}

/// `GET /readyz`: the process can serve traffic.
#[utoipa::path(
    get,
    path = "/readyz",
    tag = "health",
    responses((status = 200, description = "Service is ready", body = HealthReport))
)]
async fn readyz() -> Json<HealthReport> {
    // No downstream dependencies exist yet. When storage arrives, this handler reports
    // `ServiceStatus::Degraded` (and 503) while the dependency is unavailable.
    Json(report(ServiceStatus::Ok))
}

/// `GET /openapi.json`: the API contract, generated at compile time.
#[utoipa::path(
    get,
    path = "/openapi.json",
    tag = "meta",
    responses((status = 200, description = "OpenAPI document", body = serde_json::Value))
)]
async fn openapi() -> axum::response::Response {
    let mut doc = ApiDoc::openapi();
    doc.info.version = VERSION.to_owned();
    doc.merge(veil_proto::Contract::openapi());
    match serde_json::to_value(&doc) {
        Ok(value) => Json(value).into_response(),
        Err(err) => {
            tracing::error!(error = %err, "OpenAPI document could not be serialized");
            ApiError::internal("OpenAPI document unavailable").into_response()
        }
    }
}

fn report(status: ServiceStatus) -> HealthReport {
    HealthReport {
        status,
        service: SERVICE_NAME.to_owned(),
        version: VERSION.to_owned(),
        commit: COMMIT.map(str::to_owned),
    }
}

/// Compile-time OpenAPI document.
///
/// Feature resources add their paths here; every schema comes from
/// [`veil_proto::Contract`], so the wire shapes are defined once.
#[derive(OpenApi)]
#[openapi(
    info(
        title = "Veil API",
        license(name = "AGPL-3.0-only"),
    ),
    paths(healthz, readyz, openapi),
    tags(
        (name = "health", description = "Liveness and readiness"),
        (name = "meta", description = "Machine-readable API description"),
    ),
)]
pub struct ApiDoc;
