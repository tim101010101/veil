//! HTTP surface tests: the router is exercised without binding a socket.

use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};

use tower::ServiceExt;
use veil_daemon::{
    app::{AppState, router},
    store::Store,
};
use veil_proto::{HealthReport, ServiceStatus};

fn state() -> AppState {
    AppState::new(Store::in_memory().expect("in-memory store"))
}

fn request(path: &str) -> Request<Body> {
    Request::builder()
        .uri(path)
        .body(Body::empty())
        .expect("request is well formed")
}

async fn body_json<T: serde::de::DeserializeOwned>(path: &str) -> (StatusCode, T) {
    let response = router(state())
        .oneshot(request(path))
        .await
        .expect("router responds");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("body is readable");
    let value = serde_json::from_slice(&bytes).unwrap_or_else(|err| {
        panic!(
            "{path} did not return JSON: {err}\n{}",
            String::from_utf8_lossy(&bytes)
        )
    });
    (status, value)
}

#[tokio::test]
async fn healthz_reports_service_identity() {
    let (status, report) = body_json::<HealthReport>("/healthz").await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(report.status, ServiceStatus::Ok);
    assert_eq!(report.service, veil_daemon::app::SERVICE_NAME);
    assert_eq!(report.version, veil_daemon::app::VERSION);
}

#[tokio::test]
async fn readyz_reports_ready() {
    let (status, report) = body_json::<HealthReport>("/readyz").await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(report.status, ServiceStatus::Ok);
}

#[tokio::test]
async fn openapi_describes_health_routes() {
    let (status, doc) = body_json::<serde_json::Value>("/openapi.json").await;

    assert_eq!(status, StatusCode::OK);
    let paths = doc["paths"]
        .as_object()
        .unwrap_or_else(|| panic!("openapi document has no paths: {doc}"));
    assert!(paths.contains_key("/healthz"), "paths: {paths:?}");
    assert!(paths.contains_key("/readyz"), "paths: {paths:?}");
    assert_eq!(doc["info"]["version"], veil_daemon::app::VERSION);
}

#[tokio::test]
async fn openapi_includes_the_wire_contract() {
    let (status, doc) = body_json::<serde_json::Value>("/openapi.json").await;

    assert_eq!(status, StatusCode::OK);
    let schemas = doc["components"]["schemas"]
        .as_object()
        .unwrap_or_else(|| panic!("openapi document has no schemas: {doc}"));
    for name in ["Vault", "Item", "Grant", "SyncDocument", "AuditEvent"] {
        assert!(schemas.contains_key(name), "missing {name}: {schemas:?}");
    }
}

#[tokio::test]
async fn unknown_route_is_not_found() {
    let response = router(state())
        .oneshot(request("/api/v1/nothing-here"))
        .await
        .expect("router responds");

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}
