//! The Bitwarden client API through the router: the binding, login, sync, ciphers, and folders,
//! and how they meet the Veil API.
//!
//! Sealed fields are dummy strings: the service stores them unchanged and never parses them.

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Method, Request, StatusCode, header::CONTENT_TYPE},
};
use serde_json::{Value, json};
use tower::ServiceExt;
use uuid::Uuid;
use veil_daemon::{
    app::{AppState, router},
    store::Store,
};

const EMAIL: &str = "me@example.com";
const AUTH_HASH: &str = "auth-hash";
const ACCOUNT_KEYS: &str = r#"{"object":"privateKeys","opaque":true}"#;

fn app() -> Router {
    router(AppState::new(Store::in_memory().expect("in-memory store")))
}

async fn send(app: &Router, request: Request<Body>) -> (StatusCode, Value) {
    let response = app.clone().oneshot(request).await.expect("router responds");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("body");
    let value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    };
    (status, value)
}

async fn call(
    app: &Router,
    method: Method,
    path: &str,
    bearer: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut builder = Request::builder().method(method).uri(path);
    if let Some(token) = bearer {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    let request = match body {
        Some(value) => builder
            .header(CONTENT_TYPE, "application/json; charset=utf-8")
            .body(Body::from(value.to_string()))
            .expect("request"),
        None => builder.body(Body::empty()).expect("request"),
    };
    send(app, request).await
}

/// Calls and expects a status, returning the body.
async fn expect(
    app: &Router,
    method: Method,
    path: &str,
    bearer: Option<&str>,
    body: Option<Value>,
    status: StatusCode,
) -> Value {
    let (got, body) = call(app, method.clone(), path, bearer, body).await;
    assert_eq!(got, status, "{method} {path}: {body}");
    body
}

async fn token_request(app: &Router, form: &[(&str, &str)]) -> (StatusCode, Value) {
    let body = form
        .iter()
        .map(|(key, value)| format!("{key}={}", value.replace('@', "%40").replace(' ', "+")))
        .collect::<Vec<_>>()
        .join("&");
    let request = Request::builder()
        .method(Method::POST)
        .uri("/identity/connect/token")
        .header(
            CONTENT_TYPE,
            "application/x-www-form-urlencoded; charset=utf-8",
        )
        .body(Body::from(body))
        .expect("request");
    send(app, request).await
}

async fn password_login(app: &Router, username: &str, password: &str) -> (StatusCode, Value) {
    token_request(
        app,
        &[
            ("grant_type", "password"),
            ("username", username),
            ("password", password),
            ("scope", "api offline_access"),
            ("client_id", "cli"),
            ("deviceType", "8"),
            ("deviceIdentifier", "device-1"),
            ("deviceName", "linux"),
        ],
    )
    .await
}

/// Logs in with Bitwarden; returns the access and refresh tokens.
async fn login(app: &Router) -> (String, String) {
    let (status, body) = password_login(app, EMAIL, AUTH_HASH).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    (
        body["access_token"].as_str().expect("access").to_owned(),
        body["refresh_token"].as_str().expect("refresh").to_owned(),
    )
}

/// Creates the account; returns an Owner session.
async fn create_account(app: &Router) -> String {
    let body = expect(
        app,
        Method::POST,
        "/api/v1/accounts",
        None,
        Some(json!({
            "id": Uuid::now_v7(),
            "email": EMAIL,
            "kdf": { "kind": "pbkdf2", "iterations": 600000 },
            "auth_hash": AUTH_HASH,
            "protected_account_key": "2.protected|account|key",
            "account_keys": "{\"opaque\":true}",
            "recovery_wrap": "2.recovery|wrap|x",
            "recovery_verifier": "recovery-verifier",
            "device": {
                "id": Uuid::now_v7(),
                "name": "laptop",
                "seal_pk": "c3BraS1kZXI=",
                "auth_pk": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            },
        })),
        StatusCode::CREATED,
    )
    .await;
    body["session"]["token"].as_str().expect("token").to_owned()
}

fn item(id: Uuid, data: &str) -> Value {
    json!({ "id": id, "item_type": 1, "key": format!("2.key-{id}"), "data": data })
}

async fn create_vault(app: &Router, token: &str, vault: Uuid, items: Value) {
    expect(
        app,
        Method::POST,
        "/api/v1/vaults",
        Some(token),
        Some(json!({
            "id": vault,
            "name": "2.vault-name",
            "account_key_wrap": "2.account-key-wrap",
            "items": items,
            "grants": [],
        })),
        StatusCode::CREATED,
    )
    .await;
}

fn enable_body(vault: Uuid, generation: &str) -> Value {
    json!({
        "vault_id": vault,
        "protected_key": format!("2.protected-{generation}"),
        "private_key": format!("2.private-{generation}"),
        "public_key": "cHVibGljLWtleQ==",
        "account_keys": ACCOUNT_KEYS,
    })
}

async fn enable(app: &Router, token: &str, vault: Uuid) -> Value {
    expect(
        app,
        Method::PUT,
        "/api/v1/bitwarden",
        Some(token),
        Some(enable_body(vault, "1")),
        StatusCode::OK,
    )
    .await
}

/// An account with one Vault holding `items`, bound for Bitwarden; returns the Owner session.
async fn bound_account(app: &Router, vault: Uuid, items: Value) -> String {
    let token = create_account(app).await;
    create_vault(app, &token, vault, items).await;
    enable(app, &token, vault).await;
    token
}

async fn two_step_login(app: &Router, code: &str) -> (StatusCode, Value) {
    token_request(
        app,
        &[
            ("grant_type", "password"),
            ("username", EMAIL),
            ("password", AUTH_HASH),
            ("scope", "api offline_access"),
            ("client_id", "cli"),
            ("deviceType", "8"),
            ("deviceIdentifier", "device-1"),
            ("deviceName", "linux"),
            ("twoFactorProvider", "0"),
            ("twoFactorToken", code),
            ("twoFactorRemember", "0"),
        ],
    )
    .await
}

async fn veil_sync(app: &Router, token: &str, since: Option<u64>) -> Value {
    let path = match since {
        Some(since) => format!("/api/v1/sync?since={since}"),
        None => "/api/v1/sync".to_owned(),
    };
    expect(app, Method::GET, &path, Some(token), None, StatusCode::OK).await
}

async fn bw_sync(app: &Router, access: &str) -> Value {
    expect(
        app,
        Method::GET,
        "/api/sync",
        Some(access),
        None,
        StatusCode::OK,
    )
    .await
}

fn cipher_body(data: &str) -> Value {
    json!({
        "type": 1,
        "key": "2.cipher-key",
        "data": data,
        "favorite": false,
        "folderId": null,
        "reprompt": 0,
        "name": null,
    })
}

fn find<'a>(list: &'a Value, id: &str) -> Option<&'a Value> {
    list.as_array()
        .expect("array")
        .iter()
        .find(|entry| entry["id"] == id)
}

fn sorted_ids(list: &Value) -> Vec<String> {
    let mut out: Vec<String> = list
        .as_array()
        .expect("array")
        .iter()
        .map(|entry| entry["id"].as_str().expect("id").to_owned())
        .collect();
    out.sort();
    out
}

// ----- binding -----

#[tokio::test]
async fn the_binding_is_enabled_read_replaced_and_disabled() {
    let app = app();
    let token = create_account(&app).await;
    let (first, second) = (Uuid::now_v7(), Uuid::now_v7());
    create_vault(&app, &token, first, json!([])).await;
    create_vault(&app, &token, second, json!([])).await;

    expect(
        &app,
        Method::GET,
        "/api/v1/bitwarden",
        Some(&token),
        None,
        StatusCode::NOT_FOUND,
    )
    .await;
    expect(
        &app,
        Method::PUT,
        "/api/v1/bitwarden",
        Some(&token),
        Some(enable_body(Uuid::now_v7(), "1")),
        StatusCode::NOT_FOUND,
    )
    .await;
    let mut not_json = enable_body(first, "1");
    not_json["account_keys"] = json!("not json");
    expect(
        &app,
        Method::PUT,
        "/api/v1/bitwarden",
        Some(&token),
        Some(not_json),
        StatusCode::BAD_REQUEST,
    )
    .await;

    let status = enable(&app, &token, first).await;
    assert_eq!(status["vault_id"], first.to_string());
    assert!(status["enabled_at"].as_u64().expect("enabled_at") > 0);
    let read = expect(
        &app,
        Method::GET,
        "/api/v1/bitwarden",
        Some(&token),
        None,
        StatusCode::OK,
    )
    .await;
    assert_eq!(read, status);

    // Replacing the binding signs Bitwarden clients out.
    let (access, _) = login(&app).await;
    let replaced = enable(&app, &token, second).await;
    assert_eq!(replaced["vault_id"], second.to_string());
    expect(
        &app,
        Method::GET,
        "/api/sync",
        Some(&access),
        None,
        StatusCode::UNAUTHORIZED,
    )
    .await;

    let (access, _) = login(&app).await;
    expect(
        &app,
        Method::DELETE,
        "/api/v1/bitwarden",
        Some(&token),
        None,
        StatusCode::NO_CONTENT,
    )
    .await;
    expect(
        &app,
        Method::GET,
        "/api/v1/bitwarden",
        Some(&token),
        None,
        StatusCode::NOT_FOUND,
    )
    .await;
    expect(
        &app,
        Method::GET,
        "/api/sync",
        Some(&access),
        None,
        StatusCode::UNAUTHORIZED,
    )
    .await;
    let (status, _) = password_login(&app, EMAIL, AUTH_HASH).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "no binding, no login");
}

#[tokio::test]
async fn another_accounts_vault_cannot_be_bound() {
    let app = app();
    let token = create_account(&app).await;
    let vault = Uuid::now_v7();
    create_vault(&app, &token, vault, json!([])).await;

    // A second account on the same service.
    let body = expect(
        &app,
        Method::POST,
        "/api/v1/accounts",
        None,
        Some(json!({
            "id": Uuid::now_v7(),
            "email": "other@example.com",
            "kdf": { "kind": "pbkdf2", "iterations": 600000 },
            "auth_hash": "other-hash",
            "protected_account_key": "2.other",
            "account_keys": "{}",
            "recovery_wrap": "2.other",
            "recovery_verifier": "other",
            "device": {
                "id": Uuid::now_v7(),
                "name": "other",
                "seal_pk": "c3BraS1kZXI=",
                "auth_pk": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            },
        })),
        StatusCode::CREATED,
    )
    .await;
    let other = body["session"]["token"].as_str().expect("token");
    expect(
        &app,
        Method::PUT,
        "/api/v1/bitwarden",
        Some(other),
        Some(enable_body(vault, "1")),
        StatusCode::NOT_FOUND,
    )
    .await;
}

// ----- identity -----

#[tokio::test]
async fn prelogin_answers_the_kdf_and_salt_without_revealing_accounts() {
    let app = app();
    create_account(&app).await;

    for path in [
        "/identity/accounts/prelogin",
        "/identity/accounts/prelogin/password",
        "/api/accounts/prelogin",
    ] {
        let known = expect(
            &app,
            Method::POST,
            path,
            None,
            Some(json!({ "email": " Me@Example.com " })),
            StatusCode::OK,
        )
        .await;
        assert_eq!(known["kdf"], 0, "{path}");
        assert_eq!(known["kdfIterations"], 600000);
        assert_eq!(known["kdfSettings"]["kdfType"], 0);
        assert_eq!(known["salt"], EMAIL);

        let unknown = expect(
            &app,
            Method::POST,
            path,
            None,
            Some(json!({ "email": "Nobody@Example.com" })),
            StatusCode::OK,
        )
        .await;
        assert_eq!(unknown["kdf"], 1);
        assert_eq!(unknown["kdfIterations"], 6);
        assert_eq!(unknown["kdfMemory"], 32);
        assert_eq!(unknown["kdfParallelism"], 4);
        assert_eq!(unknown["salt"], "nobody@example.com");
    }
}

#[tokio::test]
async fn a_password_login_needs_the_right_hash_and_a_binding() {
    let app = app();
    let token = create_account(&app).await;
    let vault = Uuid::now_v7();
    create_vault(&app, &token, vault, json!([])).await;

    let (status, body) = password_login(&app, EMAIL, AUTH_HASH).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "no binding yet");
    assert_eq!(body["error"], "invalid_grant");

    enable(&app, &token, vault).await;
    let (status, body) = password_login(&app, EMAIL, "wrong-hash").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_grant");
    assert_eq!(body["error_description"], "invalid_username_or_password");
    assert_eq!(
        body["ErrorModel"]["Message"],
        "Username or password is incorrect. Try again."
    );
    let (status, _) = password_login(&app, "nobody@example.com", AUTH_HASH).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let (status, body) = password_login(&app, " ME@example.com ", AUTH_HASH).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["token_type"], "Bearer");
    assert_eq!(body["expires_in"], 3600);
    assert_eq!(body["scope"], "api offline_access");
    assert_eq!(body["Key"], "2.protected-1");
    assert_eq!(body["PrivateKey"], "2.private-1");
    assert_eq!(body["Kdf"], 0);
    assert_eq!(body["KdfIterations"], 600000);
    assert_eq!(body["KdfMemory"], Value::Null);
    assert_eq!(body["AccountKeys"]["object"], "privateKeys");
    assert_eq!(body["AccountKeys"]["opaque"], true);
    assert_eq!(body["ForcePasswordReset"], false);
    assert_eq!(body["unofficialServer"], true);
    let unlock = &body["UserDecryptionOptions"]["MasterPasswordUnlock"];
    assert_eq!(unlock["Kdf"]["KdfType"], 0);
    assert_eq!(unlock["Kdf"]["Iterations"], 600000);
    assert_eq!(unlock["MasterKeyEncryptedUserKey"], "2.protected-1");
    assert_eq!(unlock["Salt"], EMAIL);

    // The access token is a JWT whose claims the clients read.
    let access = body["access_token"].as_str().expect("access");
    let payload = access.split('.').nth(1).expect("payload");
    let claims: Value = serde_json::from_slice(
        &base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, payload)
            .expect("base64url"),
    )
    .expect("claims");
    assert_eq!(claims["email"], EMAIL);
    assert_eq!(claims["premium"], true);
    assert_eq!(claims["device"], "device-1");
    assert!(claims["jti"].is_string());
    assert_eq!(
        claims["exp"].as_u64().expect("exp") - claims["nbf"].as_u64().expect("nbf"),
        3600
    );
}

#[tokio::test]
async fn a_refresh_issues_new_tokens_and_retires_the_old_refresh_token() {
    let app = app();
    bound_account(&app, Uuid::now_v7(), json!([])).await;
    let (_, refresh) = login(&app).await;

    let (status, body) = token_request(
        &app,
        &[("grant_type", "refresh_token"), ("refresh_token", &refresh)],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let access = body["access_token"].as_str().expect("access");
    let next = body["refresh_token"].as_str().expect("refresh");
    assert_ne!(next, refresh);
    bw_sync(&app, access).await;

    let (status, body) = token_request(
        &app,
        &[("grant_type", "refresh_token"), ("refresh_token", &refresh)],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_grant");
    let (status, _) = token_request(
        &app,
        &[("grant_type", "refresh_token"), ("refresh_token", next)],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = token_request(&app, &[("grant_type", "client_credentials")]).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn veil_and_bitwarden_credentials_do_not_cross() {
    let app = app();
    let token = bound_account(&app, Uuid::now_v7(), json!([])).await;
    let (access, refresh) = login(&app).await;

    for path in ["/api/sync", "/api/accounts/profile", "/api/folders"] {
        expect(
            &app,
            Method::GET,
            path,
            Some(&token),
            None,
            StatusCode::UNAUTHORIZED,
        )
        .await;
    }
    for bearer in [&access, &refresh] {
        expect(
            &app,
            Method::GET,
            "/api/v1/sync",
            Some(bearer),
            None,
            StatusCode::UNAUTHORIZED,
        )
        .await;
    }
    expect(
        &app,
        Method::GET,
        "/api/sync",
        None,
        None,
        StatusCode::UNAUTHORIZED,
    )
    .await;
    // A token whose claims were changed no longer matches its signature.
    let parts: Vec<&str> = access.split('.').collect();
    let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let mut claims: Value =
        serde_json::from_slice(&base64::Engine::decode(&engine, parts[1]).expect("payload"))
            .expect("claims");
    claims["sub"] = json!(Uuid::now_v7());
    let forged = format!(
        "{}.{}.{}",
        parts[0],
        base64::Engine::encode(&engine, claims.to_string()),
        parts[2]
    );
    expect(
        &app,
        Method::GET,
        "/api/sync",
        Some(&forged),
        None,
        StatusCode::UNAUTHORIZED,
    )
    .await;
}

#[tokio::test]
async fn config_needs_no_login_and_unknown_endpoints_are_not_found() {
    let app = app();
    let config = expect(&app, Method::GET, "/api/config", None, None, StatusCode::OK).await;
    assert_eq!(config["server"]["name"], "Veil");
    assert_eq!(config["version"], "2026.10.0");
    assert_eq!(config["object"], "config");

    for path in [
        "/api/organizations",
        "/identity/sso/prevalidate",
        "/icons/example.com/icon.png",
        "/notifications/hub",
    ] {
        expect(&app, Method::GET, path, None, None, StatusCode::NOT_FOUND).await;
    }
    // The protocol check stays on the Veil API.
    let request = Request::builder()
        .uri("/api/config")
        .header("x-veil-protocol", "99")
        .body(Body::empty())
        .expect("request");
    assert_eq!(send(&app, request).await.0, StatusCode::OK);
}

// ----- sync -----

#[tokio::test]
async fn sync_shows_only_the_bound_vault() {
    let app = app();
    let token = create_account(&app).await;
    let (bound, other) = (Uuid::now_v7(), Uuid::now_v7());
    let (a, b, c) = (Uuid::now_v7(), Uuid::now_v7(), Uuid::now_v7());
    create_vault(
        &app,
        &token,
        bound,
        json!([item(a, "data-a"), item(b, "data-b")]),
    )
    .await;
    create_vault(&app, &token, other, json!([item(c, "data-c")])).await;
    enable(&app, &token, bound).await;
    let (access, _) = login(&app).await;

    let sync = bw_sync(&app, &access).await;
    let mut expected = vec![a.to_string(), b.to_string()];
    expected.sort();
    assert_eq!(sorted_ids(&sync["ciphers"]), expected);
    let cipher = find(&sync["ciphers"], &a.to_string()).expect("a");
    assert_eq!(cipher["key"], format!("2.key-{a}"));
    assert_eq!(cipher["data"], "data-a");
    assert_eq!(cipher["type"], 1);
    assert_eq!(cipher["reprompt"], 0);
    assert_eq!(cipher["edit"], true);
    assert_eq!(cipher["permissions"]["delete"], true);
    assert_eq!(cipher["collectionIds"], json!([]));
    assert!(
        cipher["revisionDate"]
            .as_str()
            .expect("date")
            .ends_with('Z')
    );

    assert_eq!(sync["object"], "sync");
    assert_eq!(sync["domains"], Value::Null);
    assert_eq!(sync["collections"], json!([]));
    assert_eq!(sync["folders"], json!([]));
    assert_eq!(sync["profile"]["email"], EMAIL);
    assert_eq!(sync["profile"]["key"], "2.protected-1");
    assert_eq!(sync["profile"]["privateKey"], "2.private-1");
    assert_eq!(sync["profile"]["premium"], true);
    assert_eq!(sync["profile"]["accountKeys"]["opaque"], true);
    assert_eq!(
        sync["userDecryption"]["masterPasswordUnlock"]["MasterKeyEncryptedUserKey"],
        "2.protected-1"
    );
    assert_eq!(sync["userDecryption"]["userKeyId"], Value::Null);

    // An Item of another Vault is not there.
    expect(
        &app,
        Method::GET,
        &format!("/api/ciphers/{c}"),
        Some(&access),
        None,
        StatusCode::NOT_FOUND,
    )
    .await;
    expect(
        &app,
        Method::PUT,
        &format!("/api/ciphers/{c}"),
        Some(&access),
        Some(cipher_body("stolen")),
        StatusCode::NOT_FOUND,
    )
    .await;
    expect(
        &app,
        Method::DELETE,
        &format!("/api/ciphers/{c}"),
        Some(&access),
        None,
        StatusCode::NOT_FOUND,
    )
    .await;
}

#[tokio::test]
async fn profile_user_key_id_and_revision_date() {
    let app = app();
    bound_account(&app, Uuid::now_v7(), json!([])).await;
    let (access, _) = login(&app).await;

    let profile = expect(
        &app,
        Method::GET,
        "/api/accounts/profile",
        Some(&access),
        None,
        StatusCode::OK,
    )
    .await;
    assert_eq!(profile["object"], "profile");
    assert_eq!(profile["accountKeys"]["object"], "privateKeys");
    let known = expect(
        &app,
        Method::GET,
        "/api/devices/knowndevice",
        Some(&access),
        None,
        StatusCode::OK,
    )
    .await;
    assert_eq!(known, true);

    let before = expect(
        &app,
        Method::GET,
        "/api/accounts/revision-date",
        Some(&access),
        None,
        StatusCode::OK,
    )
    .await
    .as_u64()
    .expect("ms");
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    expect(
        &app,
        Method::POST,
        "/api/accounts/key-management/user-key-id",
        Some(&access),
        Some(json!({ "userKeyId": "key-id-1" })),
        StatusCode::OK,
    )
    .await;
    let sync = bw_sync(&app, &access).await;
    assert_eq!(sync["userDecryption"]["userKeyId"], "key-id-1");
    let after = expect(
        &app,
        Method::GET,
        "/api/accounts/revision-date",
        Some(&access),
        None,
        StatusCode::OK,
    )
    .await
    .as_u64()
    .expect("ms");
    assert!(after > before, "{after} > {before}");

    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    expect(
        &app,
        Method::POST,
        "/api/ciphers",
        Some(&access),
        Some(cipher_body("data")),
        StatusCode::OK,
    )
    .await;
    let written = expect(
        &app,
        Method::GET,
        "/api/accounts/revision-date",
        Some(&access),
        None,
        StatusCode::OK,
    )
    .await
    .as_u64()
    .expect("ms");
    assert!(written > after, "{written} > {after}");
}

// ----- ciphers -----

#[tokio::test]
async fn cipher_writes_move_the_veil_change_feed() {
    let app = app();
    let vault = Uuid::now_v7();
    let token = bound_account(&app, vault, json!([])).await;
    let (access, _) = login(&app).await;
    let cursor = veil_sync(&app, &token, None).await["revision"]
        .as_u64()
        .expect("revision");

    // Create, bare and wrapped.
    let created = expect(
        &app,
        Method::POST,
        "/api/ciphers",
        Some(&access),
        Some(cipher_body("data-1")),
        StatusCode::OK,
    )
    .await;
    let id = created["id"].as_str().expect("id").to_owned();
    assert_eq!(created["data"], "data-1");
    assert_eq!(created["key"], "2.cipher-key");
    assert_eq!(created["revisionDate"], created["creationDate"]);
    assert!(created.get("deletedDate").is_none_or(Value::is_null));
    let wrapped = expect(
        &app,
        Method::POST,
        "/api/ciphers/create",
        Some(&access),
        Some(json!({ "cipher": cipher_body("data-w"), "collectionIds": [] })),
        StatusCode::OK,
    )
    .await;
    assert_eq!(wrapped["data"], "data-w");

    let feed = veil_sync(&app, &token, Some(cursor)).await;
    let veil_item = find(&feed["items"], &id).expect("the Veil feed sees the create");
    assert_eq!(veil_item["vault_id"], vault.to_string());
    assert_eq!(veil_item["item_type"], 1);
    assert_eq!(veil_item["data"], "data-1");
    let cursor = feed["revision"].as_u64().expect("revision");

    // Update, with and without the client's last known revision date.
    let mut update = cipher_body("data-2");
    update["lastKnownRevisionDate"] = created["revisionDate"].clone();
    update["favorite"] = json!(true);
    let updated = expect(
        &app,
        Method::PUT,
        &format!("/api/ciphers/{id}"),
        Some(&access),
        Some(update.clone()),
        StatusCode::OK,
    )
    .await;
    assert_eq!(updated["data"], "data-2");
    assert_eq!(updated["favorite"], true);
    assert_eq!(updated["creationDate"], created["creationDate"]);
    let stale = expect(
        &app,
        Method::PUT,
        &format!("/api/ciphers/{id}"),
        Some(&access),
        Some(update),
        StatusCode::BAD_REQUEST,
    )
    .await;
    assert_eq!(
        stale["message"],
        "The client copy of this cipher is out of date. Sync the client and try again."
    );
    expect(
        &app,
        Method::POST,
        &format!("/api/ciphers/{id}"),
        Some(&access),
        Some(cipher_body("data-3")),
        StatusCode::OK,
    )
    .await;
    let feed = veil_sync(&app, &token, Some(cursor)).await;
    assert_eq!(find(&feed["items"], &id).expect("update")["data"], "data-3");
    let cursor = feed["revision"].as_u64().expect("revision");

    // Partial: folder and favorite only.
    let folder = Uuid::now_v7();
    let partial = expect(
        &app,
        Method::PUT,
        &format!("/api/ciphers/{id}/partial"),
        Some(&access),
        Some(json!({ "folderId": folder, "favorite": true })),
        StatusCode::OK,
    )
    .await;
    assert_eq!(partial["folderId"], folder.to_string());
    assert_eq!(partial["data"], "data-3");
    let feed = veil_sync(&app, &token, Some(cursor)).await;
    let veil_item = find(&feed["items"], &id).expect("partial");
    assert_eq!(veil_item["folder_id"], folder.to_string());
    assert_eq!(veil_item["favorite"], true);
    let cursor = feed["revision"].as_u64().expect("revision");

    // Trash and restore.
    expect(
        &app,
        Method::PUT,
        &format!("/api/ciphers/{id}/delete"),
        Some(&access),
        None,
        StatusCode::OK,
    )
    .await;
    let feed = veil_sync(&app, &token, Some(cursor)).await;
    assert!(
        find(&feed["items"], &id).expect("trash")["deleted_at"].is_u64(),
        "{feed}"
    );
    let cursor = feed["revision"].as_u64().expect("revision");
    let trashed = find(&bw_sync(&app, &access).await["ciphers"], &id)
        .expect("trashed ciphers are synced")
        .clone();
    assert!(trashed["deletedDate"].is_string());
    // A Veil write keeps the trash date.
    let veil_put = expect(
        &app,
        Method::PUT,
        &format!("/api/v1/vaults/{vault}/items/{id}"),
        Some(&token),
        Some(json!({
            "expected_revision": find(&veil_sync(&app, &token, None).await["items"], &id)
                .expect("item")["revision"],
            "item_type": 1,
            "key": "2.cipher-key",
            "data": "data-veil",
        })),
        StatusCode::OK,
    )
    .await;
    assert!(veil_put["deleted_at"].is_u64());
    let cursor_after_veil = veil_sync(&app, &token, None).await["revision"]
        .as_u64()
        .expect("revision");
    assert!(cursor_after_veil > cursor);

    let restored = expect(
        &app,
        Method::PUT,
        &format!("/api/ciphers/{id}/restore"),
        Some(&access),
        None,
        StatusCode::OK,
    )
    .await;
    assert!(restored.get("deletedDate").is_none_or(Value::is_null));
    assert_eq!(restored["data"], "data-veil");
    let feed = veil_sync(&app, &token, Some(cursor_after_veil)).await;
    assert!(find(&feed["items"], &id).expect("restore")["deleted_at"].is_null());
    let cursor = feed["revision"].as_u64().expect("revision");

    // Bulk trash and restore; unknown ids are skipped.
    let other = wrapped["id"].as_str().expect("id").to_owned();
    let ids = json!({ "ids": [id, other, Uuid::now_v7()] });
    expect(
        &app,
        Method::PUT,
        "/api/ciphers/delete",
        Some(&access),
        Some(ids.clone()),
        StatusCode::OK,
    )
    .await;
    let feed = veil_sync(&app, &token, Some(cursor)).await;
    for each in [&id, &other] {
        assert!(find(&feed["items"], each).expect("bulk trash")["deleted_at"].is_u64());
    }
    let cursor = feed["revision"].as_u64().expect("revision");
    let restored = expect(
        &app,
        Method::PUT,
        "/api/ciphers/restore",
        Some(&access),
        Some(ids),
        StatusCode::OK,
    )
    .await;
    assert_eq!(restored["object"], "list");
    assert_eq!(restored["data"].as_array().expect("list").len(), 2);
    let feed = veil_sync(&app, &token, Some(cursor)).await;
    for each in [&id, &other] {
        assert!(find(&feed["items"], each).expect("bulk restore")["deleted_at"].is_null());
    }
    let cursor = feed["revision"].as_u64().expect("revision");

    // Permanent deletion, both forms.
    expect(
        &app,
        Method::DELETE,
        &format!("/api/ciphers/{id}"),
        Some(&access),
        None,
        StatusCode::OK,
    )
    .await;
    expect(
        &app,
        Method::POST,
        &format!("/api/ciphers/{other}/delete"),
        Some(&access),
        None,
        StatusCode::OK,
    )
    .await;
    let feed = veil_sync(&app, &token, Some(cursor)).await;
    let deleted: Vec<&str> = feed["deleted"]
        .as_array()
        .expect("deleted")
        .iter()
        .map(|entry| entry.as_str().expect("id"))
        .collect();
    assert!(deleted.contains(&id.as_str()) && deleted.contains(&other.as_str()));
    assert_eq!(bw_sync(&app, &access).await["ciphers"], json!([]));
    expect(
        &app,
        Method::GET,
        &format!("/api/ciphers/{id}"),
        Some(&access),
        None,
        StatusCode::NOT_FOUND,
    )
    .await;
}

#[tokio::test]
async fn a_field_encrypted_cipher_is_refused() {
    let app = app();
    let a = Uuid::now_v7();
    bound_account(&app, Uuid::now_v7(), json!([item(a, "data-a")])).await;
    let (access, _) = login(&app).await;

    let v1 = json!({
        "type": 1,
        "name": "2.name|enc|x",
        "login": { "username": "2.user|enc|x", "password": "2.pass|enc|x" },
    });
    for (method, path) in [
        (Method::POST, "/api/ciphers".to_owned()),
        (Method::PUT, format!("/api/ciphers/{a}")),
    ] {
        let body = expect(
            &app,
            method,
            &path,
            Some(&access),
            Some(v1.clone()),
            StatusCode::BAD_REQUEST,
        )
        .await;
        assert_eq!(body["object"], "error");
    }
    let mut key_only = cipher_body("data");
    key_only["data"] = Value::Null;
    expect(
        &app,
        Method::POST,
        "/api/ciphers",
        Some(&access),
        Some(key_only),
        StatusCode::BAD_REQUEST,
    )
    .await;
    let sync = bw_sync(&app, &access).await;
    assert_eq!(sync["ciphers"].as_array().expect("ciphers").len(), 1);
}

// ----- folders -----

#[tokio::test]
async fn folders_are_created_renamed_and_deleted_and_deletion_unfiles_items() {
    let app = app();
    let vault = Uuid::now_v7();
    let token = bound_account(&app, vault, json!([])).await;
    let (access, _) = login(&app).await;

    let folder = expect(
        &app,
        Method::POST,
        "/api/folders",
        Some(&access),
        Some(json!({ "name": "2.folder|name|x" })),
        StatusCode::OK,
    )
    .await;
    assert_eq!(folder["object"], "folder");
    assert_eq!(folder["name"], "2.folder|name|x");
    let folder_id = folder["id"].as_str().expect("id").to_owned();

    let renamed = expect(
        &app,
        Method::PUT,
        &format!("/api/folders/{folder_id}"),
        Some(&access),
        Some(json!({ "name": "2.renamed|x" })),
        StatusCode::OK,
    )
    .await;
    assert_eq!(renamed["name"], "2.renamed|x");
    let listed = expect(
        &app,
        Method::GET,
        "/api/folders",
        Some(&access),
        None,
        StatusCode::OK,
    )
    .await;
    assert_eq!(listed["data"][0]["name"], "2.renamed|x");
    assert_eq!(bw_sync(&app, &access).await["folders"][0]["id"], folder_id);
    expect(
        &app,
        Method::PUT,
        &format!("/api/folders/{}", Uuid::now_v7()),
        Some(&access),
        Some(json!({ "name": "x" })),
        StatusCode::NOT_FOUND,
    )
    .await;

    let mut filed = cipher_body("filed");
    filed["folderId"] = json!(folder_id);
    let cipher = expect(
        &app,
        Method::POST,
        "/api/ciphers",
        Some(&access),
        Some(filed),
        StatusCode::OK,
    )
    .await;
    assert_eq!(cipher["folderId"], folder_id);
    let id = cipher["id"].as_str().expect("id").to_owned();
    let cursor = veil_sync(&app, &token, None).await["revision"]
        .as_u64()
        .expect("revision");

    expect(
        &app,
        Method::DELETE,
        &format!("/api/folders/{folder_id}"),
        Some(&access),
        None,
        StatusCode::OK,
    )
    .await;
    let sync = bw_sync(&app, &access).await;
    assert_eq!(sync["folders"], json!([]));
    let unfiled = find(&sync["ciphers"], &id).expect("cipher stays");
    assert!(unfiled.get("folderId").is_none_or(Value::is_null));
    let feed = veil_sync(&app, &token, Some(cursor)).await;
    assert!(find(&feed["items"], &id).expect("unfiling is a write")["folder_id"].is_null());
    expect(
        &app,
        Method::DELETE,
        &format!("/api/folders/{folder_id}"),
        Some(&access),
        None,
        StatusCode::NOT_FOUND,
    )
    .await;
}

// ----- the Veil API around the binding -----

#[tokio::test]
async fn rotating_the_bound_vault_requires_new_bitwarden_keys_and_signs_clients_out() {
    let app = app();
    let token = create_account(&app).await;
    let (bound, other) = (Uuid::now_v7(), Uuid::now_v7());
    let a = Uuid::now_v7();
    create_vault(&app, &token, bound, json!([item(a, "data-a")])).await;
    create_vault(&app, &token, other, json!([])).await;
    enable(&app, &token, bound).await;
    let (access, refresh) = login(&app).await;

    let rotate = |items: Value, bitwarden: Option<Value>| {
        let mut body = json!({
            "expected_revision": 1,
            "expected_key_generation": 1,
            "name": "2.rotated-name",
            "items": items,
            "grants": [],
            "account_key_wrap": "2.new-account-wrap",
        });
        if let Some(keys) = bitwarden {
            body["bitwarden"] = keys;
        }
        body
    };
    let path = format!("/api/v1/vaults/{bound}/rotate");
    let items = json!([{ "id": a, "key": "2.new-a" }]);

    expect(
        &app,
        Method::POST,
        &path,
        Some(&token),
        Some(rotate(items.clone(), None)),
        StatusCode::BAD_REQUEST,
    )
    .await;
    expect(
        &app,
        Method::POST,
        &path,
        Some(&token),
        Some(rotate(items.clone(), Some(enable_body(other, "2")))),
        StatusCode::BAD_REQUEST,
    )
    .await;
    expect(
        &app,
        Method::POST,
        &format!("/api/v1/vaults/{other}/rotate"),
        Some(&token),
        Some(rotate(json!([]), Some(enable_body(other, "2")))),
        StatusCode::BAD_REQUEST,
    )
    .await;
    // Nothing moved: the old login still works.
    bw_sync(&app, &access).await;

    expect(
        &app,
        Method::POST,
        &path,
        Some(&token),
        Some(rotate(items, Some(enable_body(bound, "2")))),
        StatusCode::OK,
    )
    .await;
    expect(
        &app,
        Method::GET,
        "/api/sync",
        Some(&access),
        None,
        StatusCode::UNAUTHORIZED,
    )
    .await;
    let (status, _) = token_request(
        &app,
        &[("grant_type", "refresh_token"), ("refresh_token", &refresh)],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let (status, body) = password_login(&app, EMAIL, AUTH_HASH).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["Key"], "2.protected-2");
    assert_eq!(body["PrivateKey"], "2.private-2");
    let sync = bw_sync(&app, body["access_token"].as_str().expect("access")).await;
    assert_eq!(sync["ciphers"][0]["key"], "2.new-a");
    // Rotating another Vault without Bitwarden keys is unaffected.
    expect(
        &app,
        Method::POST,
        &format!("/api/v1/vaults/{other}/rotate"),
        Some(&token),
        Some(rotate(json!([]), None)),
        StatusCode::OK,
    )
    .await;
}

#[tokio::test]
async fn a_password_change_must_rewrap_the_bitwarden_key() {
    let app = app();
    let token = bound_account(&app, Uuid::now_v7(), json!([])).await;
    let (access, _) = login(&app).await;
    let change = |bitwarden: Option<&str>| {
        let mut body = json!({
            "kdf": { "kind": "argon2id", "iterations": 3, "memory_mib": 64, "parallelism": 4 },
            "auth_hash": "new-hash",
            "protected_account_key": "2.new|wrap|x",
        });
        if let Some(key) = bitwarden {
            body["bitwarden_protected_key"] = json!(key);
        }
        body
    };

    expect(
        &app,
        Method::PUT,
        "/api/v1/accounts/current",
        Some(&token),
        Some(change(None)),
        StatusCode::BAD_REQUEST,
    )
    .await;
    bw_sync(&app, &access).await;
    let (status, _) = password_login(&app, EMAIL, AUTH_HASH).await;
    assert_eq!(status, StatusCode::OK, "nothing changed");

    expect(
        &app,
        Method::PUT,
        "/api/v1/accounts/current",
        Some(&token),
        Some(change(Some("2.bitwarden|new|x"))),
        StatusCode::NO_CONTENT,
    )
    .await;
    expect(
        &app,
        Method::GET,
        "/api/sync",
        Some(&access),
        None,
        StatusCode::UNAUTHORIZED,
    )
    .await;
    let (status, _) = password_login(&app, EMAIL, AUTH_HASH).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, body) = password_login(&app, EMAIL, "new-hash").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["Key"], "2.bitwarden|new|x");
    assert_eq!(body["Kdf"], 1);
    assert_eq!(body["KdfMemory"], 64);
    assert_eq!(body["KdfParallelism"], 4);
}

#[tokio::test]
async fn deleting_the_bound_vault_removes_the_binding() {
    let app = app();
    let vault = Uuid::now_v7();
    let token = bound_account(&app, vault, json!([])).await;
    let (access, _) = login(&app).await;

    expect(
        &app,
        Method::DELETE,
        &format!("/api/v1/vaults/{vault}"),
        Some(&token),
        None,
        StatusCode::NO_CONTENT,
    )
    .await;
    expect(
        &app,
        Method::GET,
        "/api/v1/bitwarden",
        Some(&token),
        None,
        StatusCode::NOT_FOUND,
    )
    .await;
    expect(
        &app,
        Method::GET,
        "/api/sync",
        Some(&access),
        None,
        StatusCode::UNAUTHORIZED,
    )
    .await;
    let (status, _) = password_login(&app, EMAIL, AUTH_HASH).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn repeated_failed_logins_lock_the_account_out_for_a_while() {
    let app = app();
    bound_account(&app, Uuid::now_v7(), json!([])).await;
    for _ in 0..veil_daemon::throttle::ACCOUNT_LIMIT {
        let (status, _) = password_login(&app, EMAIL, "wrong-hash").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    // Over the limit even the right password is refused, before it is checked.
    let body = "grant_type=password&username=me%40example.com&password=auth-hash&scope=api+offline_access&client_id=cli&deviceType=8&deviceIdentifier=device-1&deviceName=linux";
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/identity/connect/token")
                .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(body))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    let retry_after: u64 = response.headers()["retry-after"]
        .to_str()
        .expect("header")
        .parse()
        .expect("seconds");
    assert!(retry_after > 0 && retry_after <= veil_daemon::throttle::WINDOW_SECONDS);
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    let refused: Value = serde_json::from_slice(&bytes).expect("json");
    assert_eq!(refused["error"], "invalid_grant");
    assert!(
        refused["ErrorModel"]["Message"]
            .as_str()
            .expect("message")
            .starts_with("Too many failed sign-ins")
    );
}

#[tokio::test]
async fn two_step_login_needs_a_fresh_authenticator_code() {
    use veil_daemon::totp;
    const SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    let app = app();
    let vault = Uuid::now_v7();
    let token = bound_account(&app, vault, json!([])).await;
    let step = veil_daemon::store::now() / totp::STEP_SECONDS;
    let current = totp::code(SECRET, step).expect("code");

    let (status, _) = call(
        &app,
        Method::PUT,
        "/api/v1/bitwarden/two-step",
        Some(&token),
        Some(json!({ "secret": "GEZDGNBV", "code": current })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "a short secret is refused");
    let (status, _) = call(
        &app,
        Method::PUT,
        "/api/v1/bitwarden/two-step",
        Some(&token),
        Some(json!({ "secret": SECRET, "code": "000000" })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "a wrong code is refused");
    let (status, _) = call(
        &app,
        Method::PUT,
        "/api/v1/bitwarden/two-step",
        Some(&token),
        Some(json!({ "secret": SECRET, "code": current })),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let status_body = expect(
        &app,
        Method::GET,
        "/api/v1/bitwarden",
        Some(&token),
        None,
        StatusCode::OK,
    )
    .await;
    assert_eq!(status_body["two_step"], true);

    // The right password alone now asks for the second step, in the clients' shape.
    let (status, body) = password_login(&app, EMAIL, AUTH_HASH).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error_description"], "Two factor required.");
    assert_eq!(body["TwoFactorProviders"], json!(["0"]));
    assert!(body["TwoFactorProviders2"].get("0").is_some());

    let (status, body) = two_step_login(&app, "123456").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error_description"], "invalid_two_step_token");
    // The code that enabled two-step is spent; the next one is within the drift allowance.
    let (status, _) = two_step_login(&app, &current).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "the enabling code is spent"
    );
    let next = totp::code(SECRET, step + 1).expect("code");
    let (status, body) = two_step_login(&app, &next).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, _) = two_step_login(&app, &next).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "a code works once");

    let (status, _) = call(
        &app,
        Method::DELETE,
        "/api/v1/bitwarden/two-step",
        Some(&token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, body) = password_login(&app, EMAIL, AUTH_HASH).await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test]
async fn an_import_lands_whole_with_its_folders_or_not_at_all() {
    let app = app();
    bound_account(&app, Uuid::now_v7(), json!([])).await;
    let (access, _) = login(&app).await;
    let existing = expect(
        &app,
        Method::POST,
        "/api/folders",
        Some(&access),
        Some(json!({ "name": "2.existing-folder" })),
        StatusCode::OK,
    )
    .await;
    let existing_id = existing["id"].as_str().expect("folder id").to_owned();

    // One invalid Item (not sealed by the client) refuses the whole import.
    let mut unsealed = cipher_body("2.data-c");
    unsealed["key"] = Value::Null;
    let (status, _) = call(
        &app,
        Method::POST,
        "/api/ciphers/import",
        Some(&access),
        Some(json!({
            "ciphers": [cipher_body("2.data-a"), unsealed],
            "folders": [],
            "folderRelationships": [],
        })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = call(
        &app,
        Method::POST,
        "/api/ciphers/import",
        Some(&access),
        Some(json!({
            "ciphers": [cipher_body("2.data-a")],
            "folders": [],
            "folderRelationships": [{ "key": 0, "value": 3 }],
        })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a relationship to no folder"
    );
    assert_eq!(
        bw_sync(&app, &access).await["ciphers"]
            .as_array()
            .expect("ciphers")
            .len(),
        0,
        "refused imports wrote nothing"
    );

    // A good import: a new folder, the existing one by id, and a foreign id that is not trusted.
    let (status, _) = call(
        &app,
        Method::POST,
        "/api/ciphers/import",
        Some(&access),
        Some(json!({
            "ciphers": [cipher_body("2.data-a"), cipher_body("2.data-b"), cipher_body("2.data-c")],
            "folders": [
                { "name": "2.new-folder" },
                { "name": "2.ignored-name", "id": existing_id },
                { "name": "2.foreign", "id": Uuid::now_v7() },
            ],
            "folderRelationships": [
                { "key": 0, "value": 0 },
                { "key": 1, "value": 1 },
                { "key": 2, "value": 2 },
            ],
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let synced = bw_sync(&app, &access).await;
    let ciphers = synced["ciphers"].as_array().expect("ciphers");
    assert_eq!(ciphers.len(), 3);
    let folders = synced["folders"].as_array().expect("folders");
    assert_eq!(folders.len(), 3, "one existing, two created: {folders:?}");
    let folder_named = |name: &str| {
        folders
            .iter()
            .find(|folder| folder["name"] == name)
            .and_then(|folder| folder["id"].as_str())
            .unwrap_or_else(|| panic!("no folder {name}"))
            .to_owned()
    };
    let in_folder = |data: &str| {
        ciphers
            .iter()
            .find(|cipher| cipher["data"] == data)
            .and_then(|cipher| cipher["folderId"].as_str())
            .unwrap_or_else(|| panic!("{data} has no folder"))
            .to_owned()
    };
    assert_eq!(in_folder("2.data-a"), folder_named("2.new-folder"));
    assert_eq!(
        in_folder("2.data-b"),
        existing_id,
        "an existing folder is reused"
    );
    assert_eq!(
        in_folder("2.data-c"),
        folder_named("2.foreign"),
        "a foreign id gets a new folder"
    );
}
