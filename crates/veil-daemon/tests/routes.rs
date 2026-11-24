//! Every route declares who may call it, and nothing but the public ones answers a request that
//! carries no credential.
//!
//! The table below is the one place to read the service's access surface. A route added to the
//! router without a row here fails `every_route_is_declared`.

use std::collections::BTreeSet;

use axum::{
    Router,
    body::Body,
    http::{Method, Request, StatusCode, header::CONTENT_TYPE},
};
use tower::ServiceExt;
use veil_daemon::{
    app::{AppState, router},
    store::Store,
};

/// Who may call a route.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Access {
    /// No credential: health, the API contract, sign-up, sign-in, and recovery.
    Public,
    /// The Owner's Veil session token.
    Owner,
    /// The Owner's session, a signed Device request, or a Workload token.
    Reader,
    /// A proof carried in the request itself: a CI job's OIDC token, or a Device's signed
    /// enrollment proof. Without it the request is malformed.
    Proof,
    /// A Bitwarden client's access token.
    Bitwarden,
}

use Access::*;

const ROUTES: &[(&str, &str, Access)] = &[
    ("GET", "/healthz", Public),
    ("GET", "/readyz", Public),
    ("GET", "/openapi.json", Public),
    // Veil API.
    ("POST", "/api/v1/prelogin", Public),
    ("POST", "/api/v1/accounts", Public),
    ("PUT", "/api/v1/accounts/current", Owner),
    ("POST", "/api/v1/sessions", Public),
    // Sign-out deletes whatever token it is given; holding the token is the only right needed.
    ("DELETE", "/api/v1/sessions/current", Public),
    ("POST", "/api/v1/recoveries", Public),
    ("GET", "/api/v1/sync", Reader),
    ("POST", "/api/v1/vaults", Owner),
    ("PUT", "/api/v1/vaults/{id}", Owner),
    ("DELETE", "/api/v1/vaults/{id}", Owner),
    ("PUT", "/api/v1/vaults/{id}/items/{item_id}", Owner),
    ("DELETE", "/api/v1/vaults/{id}/items/{item_id}", Owner),
    ("POST", "/api/v1/vaults/{id}/rotate", Owner),
    ("PUT", "/api/v1/bitwarden", Owner),
    ("GET", "/api/v1/bitwarden", Owner),
    ("DELETE", "/api/v1/bitwarden", Owner),
    ("PUT", "/api/v1/bitwarden/two-step", Owner),
    ("DELETE", "/api/v1/bitwarden/two-step", Owner),
    ("POST", "/api/v1/audit/events", Reader),
    ("GET", "/api/v1/audit/events", Owner),
    ("POST", "/api/v1/workloads", Owner),
    ("GET", "/api/v1/workloads", Owner),
    ("DELETE", "/api/v1/workloads/{id}", Owner),
    ("POST", "/api/v1/workloads/{id}/token", Proof),
    ("POST", "/api/v1/devices", Public),
    ("GET", "/api/v1/devices", Owner),
    ("GET", "/api/v1/devices/pending", Owner),
    ("GET", "/api/v1/devices/enrollment", Proof),
    ("POST", "/api/v1/devices/{code}/approve", Owner),
    ("DELETE", "/api/v1/devices/{id}", Owner),
    // Bitwarden client API.
    ("POST", "/identity/accounts/prelogin", Public),
    ("POST", "/identity/accounts/prelogin/password", Public),
    ("POST", "/api/accounts/prelogin", Public),
    ("POST", "/identity/connect/token", Public),
    ("GET", "/api/config", Public),
    ("GET", "/api/sync", Bitwarden),
    ("GET", "/api/accounts/profile", Bitwarden),
    ("GET", "/api/accounts/revision-date", Bitwarden),
    (
        "POST",
        "/api/accounts/key-management/user-key-id",
        Bitwarden,
    ),
    ("GET", "/api/devices/knowndevice", Public),
    ("POST", "/api/ciphers", Bitwarden),
    ("POST", "/api/ciphers/create", Bitwarden),
    ("POST", "/api/ciphers/import", Bitwarden),
    ("PUT", "/api/ciphers/delete", Bitwarden),
    ("PUT", "/api/ciphers/restore", Bitwarden),
    ("GET", "/api/ciphers/{id}", Bitwarden),
    ("PUT", "/api/ciphers/{id}", Bitwarden),
    ("POST", "/api/ciphers/{id}", Bitwarden),
    ("DELETE", "/api/ciphers/{id}", Bitwarden),
    ("PUT", "/api/ciphers/{id}/partial", Bitwarden),
    ("PUT", "/api/ciphers/{id}/delete", Bitwarden),
    ("POST", "/api/ciphers/{id}/delete", Bitwarden),
    ("PUT", "/api/ciphers/{id}/restore", Bitwarden),
    ("GET", "/api/folders", Bitwarden),
    ("POST", "/api/folders", Bitwarden),
    ("PUT", "/api/folders/{id}", Bitwarden),
    ("DELETE", "/api/folders/{id}", Bitwarden),
];

/// The `(method, path)` pairs the router source registers, read from the source itself.
fn registered() -> BTreeSet<(String, String)> {
    let sources = [
        include_str!("../src/app.rs"),
        include_str!("../src/bitwarden.rs"),
    ];
    let mut routes = BTreeSet::new();
    for source in sources {
        for chunk in source.split(".route(").skip(1) {
            let path = chunk.split('"').nth(1).expect("a route path literal");
            // The method calls of this route end where the next builder call starts.
            let end = [".route(", ".layer(", ".merge(", ".with_state("]
                .iter()
                .filter_map(|next| chunk.find(next))
                .min()
                .unwrap_or(chunk.len());
            let calls = &chunk[..end];
            for method in ["get", "post", "put", "delete", "patch"] {
                // `get(` or `.get(`, but not the tail of a longer name such as `budget(`.
                let called = calls.match_indices(&format!("{method}(")).any(|(at, _)| {
                    calls[..at]
                        .chars()
                        .next_back()
                        .is_none_or(|before| !before.is_alphanumeric() && before != '_')
                });
                if called {
                    routes.insert((method.to_uppercase(), path.to_owned()));
                }
            }
        }
    }
    routes
}

#[test]
fn every_route_is_declared() {
    let declared: BTreeSet<(String, String)> = ROUTES
        .iter()
        .map(|(method, path, _)| ((*method).to_owned(), (*path).to_owned()))
        .collect();
    assert_eq!(declared.len(), ROUTES.len(), "a route is declared twice");
    let registered = registered();
    let undeclared: Vec<_> = registered.difference(&declared).collect();
    let stale: Vec<_> = declared.difference(&registered).collect();
    assert!(
        undeclared.is_empty() && stale.is_empty(),
        "routes without an access row: {undeclared:?}; rows without a route: {stale:?}"
    );
}

#[tokio::test]
async fn only_public_routes_answer_without_a_credential() {
    let app: Router = router(AppState::new(Store::in_memory().expect("in-memory store")));
    for (method, path, access) in ROUTES {
        let uri = path
            .replace("{id}", "01890000-0000-7000-8000-000000000001")
            .replace("{item_id}", "01890000-0000-7000-8000-000000000002")
            .replace("{code}", "424242");
        let request = Request::builder()
            .method(Method::from_bytes(method.as_bytes()).expect("method"))
            .uri(&uri)
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from("{}"))
            .expect("request");
        let status = app
            .clone()
            .oneshot(request)
            .await
            .expect("response")
            .status();
        match access {
            Public => assert_ne!(
                status,
                StatusCode::UNAUTHORIZED,
                "{method} {path} is declared public"
            ),
            Proof => assert!(
                status.is_client_error(),
                "{method} {path} answered {status} without its proof"
            ),
            Owner | Reader | Bitwarden => assert_eq!(
                status,
                StatusCode::UNAUTHORIZED,
                "{method} {path} needs a {access:?} credential"
            ),
        }
    }
}
