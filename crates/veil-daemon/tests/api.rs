//! Account, Vault, Item, device, workload, sync, and audit flows through the router.
//!
//! Sealed fields are dummy strings: the service stores them unchanged and never parses them.

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Method, Request, StatusCode, header::CONTENT_TYPE},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{Value, json};
use tower::ServiceExt;
use uuid::Uuid;
use veil_daemon::{
    app::{AppState, router},
    store::Store,
};
use veil_proto::RequestToSign;

const EMAIL: &str = "me@example.com";
const AUTH_HASH: &str = "auth-hash";
const RECOVERY_VERIFIER: &str = "recovery-verifier";

fn state() -> AppState {
    AppState::new(Store::in_memory().expect("in-memory store"))
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs()
}

/// A device whose auth key signs test requests. The sealing key is never parsed by veild.
struct TestDevice {
    id: Uuid,
    signing: SigningKey,
}

impl TestDevice {
    fn new(seed: u8) -> Self {
        Self {
            id: Uuid::now_v7(),
            signing: SigningKey::from_bytes(&[seed; 32]),
        }
    }

    fn keys(&self) -> Value {
        json!({
            "id": self.id,
            "name": format!("test-device-{}", self.id),
            "seal_pk": "c3BraS1kZXI=",
            "auth_pk": URL_SAFE_NO_PAD.encode(self.signing.verifying_key().to_bytes()),
        })
    }

    /// A signed request. `uri` may carry a query; the signature covers the path only.
    fn signed(
        &self,
        account: Uuid,
        method: Method,
        uri: &str,
        body: Option<&Value>,
    ) -> Request<Body> {
        let timestamp = unix_now();
        let nonce = URL_SAFE_NO_PAD.encode(Uuid::now_v7().as_bytes());
        let bytes = body.map(Value::to_string).unwrap_or_default();
        let account = account.to_string();
        let path = uri.split('?').next().expect("path");
        let digest = veil_proto::body_hash(bytes.as_bytes());
        let input = veil_proto::signing_input(&RequestToSign {
            account_id: &account,
            method: method.as_str(),
            path,
            body_hash: &digest,
            timestamp,
            nonce: nonce.as_bytes(),
        });
        let signature = URL_SAFE_NO_PAD.encode(self.signing.sign(&input).to_bytes());

        let mut builder = Request::builder()
            .method(method)
            .uri(uri)
            .header("x-veil-device", self.id.to_string())
            .header("x-veil-timestamp", timestamp.to_string())
            .header("x-veil-nonce", nonce)
            .header("x-veil-signature", signature);
        if body.is_some() {
            builder = builder.header(CONTENT_TYPE, "application/json");
        }
        builder.body(Body::from(bytes)).expect("request")
    }
}

fn login_body(device: &TestDevice, email: &str, auth_hash: &str, promote: bool) -> Value {
    let mut proof = veil_proto::DeviceLogin {
        keys: serde_json::from_value(device.keys()).expect("device keys"),
        promote,
        timestamp: unix_now(),
        nonce: Uuid::now_v7().to_string(),
        signature: String::new(),
    };
    proof.signature = URL_SAFE_NO_PAD.encode(
        device
            .signing
            .sign(&veil_proto::session_input(email, auth_hash, &proof))
            .to_bytes(),
    );
    json!({ "email": email, "auth_hash": auth_hash, "device": proof })
}

async fn send(app: Router, request: Request<Body>) -> (StatusCode, Value) {
    let response = app.oneshot(request).await.expect("router responds");
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
    app: Router,
    method: Method,
    path: &str,
    bearer: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header("x-veil-protocol", "1");
    if let Some(token) = bearer {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    let request = match body {
        Some(value) => builder
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(value.to_string()))
            .expect("request"),
        None => builder.body(Body::empty()).expect("request"),
    };
    send(app, request).await
}

fn account_body(device: &TestDevice) -> Value {
    json!({
        "id": Uuid::now_v7(),
        "email": EMAIL,
        "kdf": { "kind": "pbkdf2", "iterations": 600000 },
        "auth_hash": AUTH_HASH,
        "protected_account_key": "2.protected|account|key",
        "account_keys": "{\"opaque\":true}",
        "recovery_wrap": "2.recovery|wrap|x",
        "recovery_verifier": RECOVERY_VERIFIER,
        "device": device.keys(),
    })
}

/// Creates the account; returns its id and an Owner session.
async fn create_account(app: Router, device: &TestDevice) -> (Uuid, String) {
    let (status, body) = call(
        app,
        Method::POST,
        "/api/v1/accounts",
        None,
        Some(account_body(device)),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    (
        id(&body["account"]["id"]),
        body["session"]["token"].as_str().expect("token").to_owned(),
    )
}

fn id(value: &Value) -> Uuid {
    value.as_str().expect("id string").parse().expect("uuid")
}

fn item(id: Uuid, data: &str) -> Value {
    json!({ "id": id, "item_type": 2, "key": format!("2.key-{id}"), "data": data })
}

/// Creates a Vault with the given Items and Grants; returns the response body.
async fn create_vault(app: Router, token: &str, vault: Uuid, items: Value, grants: Value) -> Value {
    let (status, body) = call(
        app,
        Method::POST,
        "/api/v1/vaults",
        Some(token),
        Some(json!({
            "id": vault,
            "name": "2.vault-name",
            "account_key_wrap": "2.account-key-wrap",
            "items": items,
            "grants": grants,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    body
}

fn grant(vault: Uuid, principal: Uuid, generation: u32) -> Value {
    json!({
        "vault_id": vault,
        "principal_id": principal,
        "key_generation": generation,
        "wrapped_key": format!("shared-{vault}-{principal}"),
    })
}

/// Enrolls `device` by approval with the given Grants (each built for `device`).
async fn approve(app: Router, token: &str, device: &TestDevice, code: &str, grants: Value) {
    let (status, _) = call(
        app.clone(),
        Method::POST,
        "/api/v1/devices",
        None,
        Some(json!({ "email": EMAIL, "code": code, "device": device.keys() })),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let (status, body) = call(
        app,
        Method::POST,
        &format!("/api/v1/devices/{code}/approve"),
        Some(token),
        Some(json!({ "grants": grants })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
}

async fn enroll(app: Router, device: &TestDevice, code: &str) -> (StatusCode, Value) {
    let timestamp = unix_now();
    let nonce = URL_SAFE_NO_PAD.encode(Uuid::now_v7().as_bytes());
    let input = veil_proto::enrollment_input(device.id, code, timestamp);
    let signature = URL_SAFE_NO_PAD.encode(device.signing.sign(&input).to_bytes());
    let path = format!(
        "/api/v1/devices/enrollment?device_id={}&code={code}&timestamp={timestamp}&nonce={nonce}&signature={signature}",
        device.id
    );
    call(app, Method::GET, &path, None, None).await
}

async fn sync_as(
    app: Router,
    account: Uuid,
    device: &TestDevice,
    since: Option<u64>,
) -> (StatusCode, Value) {
    let uri = match since {
        Some(since) => format!("/api/v1/sync?since={since}"),
        None => "/api/v1/sync".to_owned(),
    };
    send(app, device.signed(account, Method::GET, &uri, None)).await
}

async fn owner_sync(app: Router, token: &str, since: Option<u64>) -> Value {
    let uri = match since {
        Some(since) => format!("/api/v1/sync?since={since}"),
        None => "/api/v1/sync".to_owned(),
    };
    let (status, body) = call(app, Method::GET, &uri, Some(token), None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body
}

fn ids(list: &Value) -> Vec<Uuid> {
    let mut out: Vec<Uuid> = list
        .as_array()
        .expect("array")
        .iter()
        .map(|entry| {
            id(if entry.is_string() {
                entry
            } else {
                &entry["id"]
            })
        })
        .collect();
    out.sort_unstable();
    out
}

fn vault_in(sync: &Value, vault: Uuid) -> &Value {
    sync["vaults"]
        .as_array()
        .expect("vaults")
        .iter()
        .find(|entry| id(&entry["id"]) == vault)
        .expect("vault is listed")
}

// ----- protocol -----

#[tokio::test]
async fn another_protocol_version_is_upgrade_required() {
    let app = router(state());
    let body = json!({ "email": EMAIL });
    let request = |version: Option<&str>| {
        let mut builder = Request::builder()
            .method(Method::POST)
            .uri("/api/v1/prelogin")
            .header(CONTENT_TYPE, "application/json");
        if let Some(version) = version {
            builder = builder.header("x-veil-protocol", version);
        }
        builder.body(Body::from(body.to_string())).expect("request")
    };

    let (status, problem) = send(app.clone(), request(Some("2"))).await;
    assert_eq!(status, StatusCode::UPGRADE_REQUIRED);
    assert!(
        problem["type"]
            .as_str()
            .expect("type")
            .ends_with("/protocol"),
        "{problem}"
    );
    assert_eq!(problem["status"], 426);
    assert_eq!(problem["supported"], json!([1]));

    let (status, _) = send(app.clone(), request(Some("1"))).await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = send(app, request(None)).await;
    assert_eq!(status, StatusCode::OK);
}

// ----- accounts -----

#[tokio::test]
async fn prelogin_answers_unknown_addresses_with_the_default() {
    let app = router(state());
    let default =
        json!({ "kind": "argon2id", "iterations": 6, "memory_mib": 32, "parallelism": 4 });

    let (status, body) = call(
        app.clone(),
        Method::POST,
        "/api/v1/prelogin",
        None,
        Some(json!({ "email": "nobody@example.com" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["kdf"], default);

    create_account(app.clone(), &TestDevice::new(1)).await;
    let (_, body) = call(
        app,
        Method::POST,
        "/api/v1/prelogin",
        None,
        Some(json!({ "email": " ME@example.com " })),
    )
    .await;
    assert_eq!(
        body["kdf"],
        json!({ "kind": "pbkdf2", "iterations": 600000 })
    );
}

#[tokio::test]
async fn sessions_return_the_wrapped_account_key_and_refuse_wrong_hashes() {
    let app = router(state());
    let device = TestDevice::new(1);
    let (account, token) = create_account(app.clone(), &device).await;

    let (status, _) = call(
        app.clone(),
        Method::POST,
        "/api/v1/accounts",
        None,
        Some(account_body(&TestDevice::new(2))),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);

    let (status, _) = call(
        app.clone(),
        Method::POST,
        "/api/v1/sessions",
        None,
        Some(json!({ "email": EMAIL, "auth_hash": "wrong" })),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = call(
        app.clone(),
        Method::POST,
        "/api/v1/sessions",
        None,
        Some(json!({ "email": "nobody@example.com", "auth_hash": AUTH_HASH })),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let (status, body) = call(
        app.clone(),
        Method::POST,
        "/api/v1/sessions",
        None,
        Some(login_body(&device, EMAIL, AUTH_HASH, false)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(id(&body["account"]["id"]), account);
    assert_eq!(body["account"]["email"], EMAIL);
    assert_eq!(body["protected_account_key"], "2.protected|account|key");
    assert_eq!(body["account_keys"], "{\"opaque\":true}");

    let (status, _) = call(
        app.clone(),
        Method::DELETE,
        "/api/v1/sessions/current",
        Some(&token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = call(app, Method::GET, "/api/v1/sync", Some(&token), None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_password_change_replaces_the_hash_kdf_and_wrap() {
    let app = router(state());
    let (_, token) = create_account(app.clone(), &TestDevice::new(1)).await;

    let (status, _) = call(
        app.clone(),
        Method::PUT,
        "/api/v1/accounts/current",
        Some(&token),
        Some(json!({
            "kdf": { "kind": "argon2id", "iterations": 3, "memory_mib": 64, "parallelism": 4 },
            "auth_hash": "new-hash",
            "protected_account_key": "2.new|wrap|x",
        })),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (status, _) = call(
        app.clone(),
        Method::POST,
        "/api/v1/sessions",
        None,
        Some(json!({ "email": EMAIL, "auth_hash": AUTH_HASH })),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, body) = call(
        app.clone(),
        Method::POST,
        "/api/v1/sessions",
        None,
        Some(login_body(&TestDevice::new(2), EMAIL, "new-hash", false)),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["protected_account_key"], "2.new|wrap|x");
    let (_, body) = call(
        app,
        Method::POST,
        "/api/v1/prelogin",
        None,
        Some(json!({ "email": EMAIL })),
    )
    .await;
    assert_eq!(body["kdf"]["memory_mib"], 64);
}

#[tokio::test]
async fn a_recovery_registers_an_owner_device() {
    let app = router(state());
    let (account, token) = create_account(app.clone(), &TestDevice::new(1)).await;
    let vault = Uuid::now_v7();
    create_vault(app.clone(), &token, vault, json!([]), json!([])).await;

    let recovered = TestDevice::new(9);
    let (status, _) = call(
        app.clone(),
        Method::POST,
        "/api/v1/recoveries",
        None,
        Some(json!({ "email": EMAIL, "recovery_proof": "wrong", "device": recovered.keys() })),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let (status, body) = call(
        app.clone(),
        Method::POST,
        "/api/v1/recoveries",
        None,
        Some(json!({
            "email": EMAIL,
            "recovery_proof": RECOVERY_VERIFIER,
            "device": recovered.keys(),
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(id(&body["account_id"]), account);
    assert_eq!(id(&body["device"]["id"]), recovered.id);
    assert_eq!(body["recovery_wrap"], "2.recovery|wrap|x");

    let (status, sync) = sync_as(app, account, &recovered, None).await;
    assert_eq!(status, StatusCode::OK, "{sync}");
    assert_eq!(
        vault_in(&sync, vault)["account_key_wrap"],
        "2.account-key-wrap"
    );
}

// ----- vaults and items -----

#[tokio::test]
async fn items_are_created_replaced_and_deleted_with_revisions() {
    let app = router(state());
    let (_, token) = create_account(app.clone(), &TestDevice::new(1)).await;
    let vault = Uuid::now_v7();
    let first = Uuid::now_v7();
    let created = create_vault(
        app.clone(),
        &token,
        vault,
        json!([item(first, "data-1")]),
        json!([]),
    )
    .await;
    assert_eq!(created["revision"], 1);
    assert_eq!(created["key_generation"], 1);
    assert_eq!(created["rotation_due"], false);
    assert_eq!(created["account_key_wrap"], "2.account-key-wrap");

    // Replaying the same create returns the existing Vault.
    let (status, replay) = call(
        app.clone(),
        Method::POST,
        "/api/v1/vaults",
        Some(&token),
        Some(json!({
            "id": vault,
            "name": "2.vault-name",
            "account_key_wrap": "2.account-key-wrap",
            "items": [item(first, "data-1")],
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{replay}");
    assert_eq!(replay, created);

    let second = Uuid::now_v7();
    let path = format!("/api/v1/vaults/{vault}/items/{second}");
    let put = |expected: u64, data: &str| json!({ "expected_revision": expected, "item_type": 1, "key": "2.item-key", "data": data, "favorite": true });

    let (status, body) = call(
        app.clone(),
        Method::PUT,
        &path,
        Some(&token),
        Some(put(0, "a")),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(body["revision"], 2);
    assert_eq!(id(&body["vault_id"]), vault);
    assert_eq!(body["data"], "a");
    assert_eq!(body["favorite"], true);
    assert!(body["revised_at"].as_u64().expect("revised_at") > 0);

    // An identical create replay is idempotent; a different one conflicts.
    let (status, replay) = call(
        app.clone(),
        Method::PUT,
        &path,
        Some(&token),
        Some(put(0, "a")),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(replay, body);
    let (status, _) = call(
        app.clone(),
        Method::PUT,
        &path,
        Some(&token),
        Some(put(0, "b")),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);

    // Replacing needs the Item's current revision.
    let (status, _) = call(
        app.clone(),
        Method::PUT,
        &path,
        Some(&token),
        Some(put(1, "b")),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    let (status, body) = call(
        app.clone(),
        Method::PUT,
        &path,
        Some(&token),
        Some(put(2, "b")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["revision"], 3);
    assert_eq!(body["data"], "b");

    // The first Item kept its revision; the Vault moved with every write.
    let sync = owner_sync(app.clone(), &token, None).await;
    assert_eq!(vault_in(&sync, vault)["revision"], 3);
    let first_item = sync["items"]
        .as_array()
        .expect("items")
        .iter()
        .find(|entry| id(&entry["id"]) == first)
        .expect("first item");
    assert_eq!(first_item["revision"], 1);

    // An Item addressed through another Vault is not found.
    let other = Uuid::now_v7();
    create_vault(app.clone(), &token, other, json!([]), json!([])).await;
    let (status, _) = call(
        app.clone(),
        Method::PUT,
        &format!("/api/v1/vaults/{other}/items/{second}"),
        Some(&token),
        Some(put(3, "c")),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = call(
        app.clone(),
        Method::DELETE,
        &format!("/api/v1/vaults/{other}/items/{second}"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = call(
        app.clone(),
        Method::PUT,
        &format!("/api/v1/vaults/{}/items/{}", Uuid::now_v7(), Uuid::now_v7()),
        Some(&token),
        Some(put(0, "c")),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let (status, _) = call(app.clone(), Method::DELETE, &path, Some(&token), None).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = call(app.clone(), Method::DELETE, &path, Some(&token), None).await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // Rename needs the Vault revision: create, two puts, delete = 4.
    let rename = |expected: u64| json!({ "expected_revision": expected, "name": "2.renamed" });
    let vault_path = format!("/api/v1/vaults/{vault}");
    let (status, _) = call(
        app.clone(),
        Method::PUT,
        &vault_path,
        Some(&token),
        Some(rename(3)),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    let (status, body) = call(
        app.clone(),
        Method::PUT,
        &vault_path,
        Some(&token),
        Some(rename(4)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["name"], "2.renamed");
    assert_eq!(body["revision"], 5);

    let (status, _) = call(app.clone(), Method::DELETE, &vault_path, Some(&token), None).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = call(app.clone(), Method::DELETE, &vault_path, Some(&token), None).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let sync = owner_sync(app, &token, None).await;
    assert_eq!(ids(&sync["vaults"]), vec![other]);
    assert!(sync["items"].as_array().expect("items").is_empty());
}

#[tokio::test]
async fn rotation_replaces_keys_and_grants_but_not_data() {
    let app = router(state());
    let (account, token) = create_account(app.clone(), &TestDevice::new(1)).await;
    let vault = Uuid::now_v7();
    let (a, b) = (Uuid::now_v7(), Uuid::now_v7());
    create_vault(
        app.clone(),
        &token,
        vault,
        json!([item(a, "data-a"), item(b, "data-b")]),
        json!([]),
    )
    .await;
    let device = TestDevice::new(2);
    approve(
        app.clone(),
        &token,
        &device,
        "111111",
        json!([grant(vault, device.id, 1)]),
    )
    .await;

    let rotate = |revision: u64, generation: u32, items: Value, grants: Value| {
        json!({
            "expected_revision": revision,
            "expected_key_generation": generation,
            "name": "2.rotated-name",
            "items": items,
            "grants": grants,
            "account_key_wrap": "2.new-account-wrap",
        })
    };
    let path = format!("/api/v1/vaults/{vault}/rotate");
    let both = json!([{ "id": a, "key": "2.new-a" }, { "id": b, "key": "2.new-b" }]);

    let (status, _) = call(
        app.clone(),
        Method::POST,
        &path,
        Some(&token),
        Some(rotate(1, 2, both.clone(), json!([]))),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "stale key generation");
    let (status, _) = call(
        app.clone(),
        Method::POST,
        &path,
        Some(&token),
        Some(rotate(9, 1, both.clone(), json!([]))),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "stale revision");
    let (status, _) = call(
        app.clone(),
        Method::POST,
        &path,
        Some(&token),
        Some(rotate(
            1,
            1,
            json!([{ "id": a, "key": "2.new-a" }]),
            json!([]),
        )),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "missing item key");
    let (status, _) = call(
        app.clone(),
        Method::POST,
        &path,
        Some(&token),
        Some(rotate(
            1,
            1,
            both.clone(),
            json!([grant(vault, device.id, 1)]),
        )),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "grant for the old generation"
    );

    let before = owner_sync(app.clone(), &token, None).await;
    let cursor = before["revision"].as_u64().expect("revision");
    let (status, body) = call(
        app.clone(),
        Method::POST,
        &path,
        Some(&token),
        Some(rotate(1, 1, both, json!([grant(vault, device.id, 2)]))),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["key_generation"], 2);
    assert_eq!(body["revision"], 2);
    assert_eq!(body["rotation_due"], false);
    assert_eq!(body["name"], "2.rotated-name");
    assert_eq!(body["account_key_wrap"], "2.new-account-wrap");

    let sync = owner_sync(app.clone(), &token, Some(cursor)).await;
    assert_eq!(sync["full"], false);
    assert_eq!(
        sync["rotations"],
        json!([{ "vault_id": vault, "key_generation": 2 }])
    );
    let items = sync["items"].as_array().expect("items");
    assert_eq!(items.len(), 2);
    for entry in items {
        let data = if id(&entry["id"]) == a {
            "data-a"
        } else {
            "data-b"
        };
        assert_eq!(entry["data"], data, "data is untouched");
        assert!(entry["key"].as_str().expect("key").starts_with("2.new-"));
    }
    let grants = sync["grants"].as_array().expect("grants");
    assert_eq!(grants.len(), 1);
    assert_eq!(grants[0]["key_generation"], 2);
    // The old Grant id is reported deleted.
    assert_eq!(sync["deleted"].as_array().expect("deleted").len(), 1);

    let (status, device_sync) = sync_as(app, account, &device, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(device_sync["grants"][0]["key_generation"], 2);
}

// ----- principals -----

#[tokio::test]
async fn an_owner_device_reads_everything_but_cannot_write() {
    let app = router(state());
    let owner_device = TestDevice::new(1);
    let (account, token) = create_account(app.clone(), &owner_device).await;
    let vault = Uuid::now_v7();
    let entry = Uuid::now_v7();
    create_vault(
        app.clone(),
        &token,
        vault,
        json!([item(entry, "d")]),
        json!([]),
    )
    .await;

    let (status, sync) = sync_as(app.clone(), account, &owner_device, None).await;
    assert_eq!(status, StatusCode::OK, "{sync}");
    assert_eq!(
        vault_in(&sync, vault)["account_key_wrap"],
        "2.account-key-wrap"
    );
    assert_eq!(ids(&sync["items"]), vec![entry]);

    let body = json!({ "id": Uuid::now_v7(), "name": "n", "account_key_wrap": "w" });
    let (status, _) = send(
        app.clone(),
        owner_device.signed(account, Method::POST, "/api/v1/vaults", Some(&body)),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let put = json!({ "expected_revision": 1, "item_type": 1, "key": "k", "data": "x" });
    let (status, _) = send(
        app.clone(),
        owner_device.signed(
            account,
            Method::PUT,
            &format!("/api/v1/vaults/{vault}/items/{entry}"),
            Some(&put),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // No credential at all is a 401, not a 403.
    let (status, _) = call(app, Method::POST, "/api/v1/vaults", None, Some(body)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn an_approved_device_reads_only_its_granted_vaults_and_loses_them_on_revoke() {
    let app = router(state());
    let (account, token) = create_account(app.clone(), &TestDevice::new(1)).await;
    let (granted, hidden) = (Uuid::now_v7(), Uuid::now_v7());
    let (seen, unseen) = (Uuid::now_v7(), Uuid::now_v7());
    create_vault(
        app.clone(),
        &token,
        granted,
        json!([item(seen, "s")]),
        json!([]),
    )
    .await;
    create_vault(
        app.clone(),
        &token,
        hidden,
        json!([item(unseen, "u")]),
        json!([]),
    )
    .await;

    let device = TestDevice::new(2);
    let (status, _) = call(
        app.clone(),
        Method::POST,
        "/api/v1/devices",
        None,
        Some(json!({ "email": EMAIL, "code": "123456", "device": device.keys() })),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    // An unknown address answers the same way.
    let (status, _) = call(
        app.clone(),
        Method::POST,
        "/api/v1/devices",
        None,
        Some(json!({ "email": "nobody@example.com", "code": "654321", "device": TestDevice::new(3).keys() })),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED);

    let (status, pending) = call(
        app.clone(),
        Method::GET,
        "/api/v1/devices/pending",
        Some(&token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(pending.as_array().expect("pending").len(), 1);
    assert_eq!(pending[0]["code"], "123456");

    // Not enrolled yet: polling fails.
    let (status, _) = enroll(app.clone(), &device, "123456").await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let (status, approved) = call(
        app.clone(),
        Method::POST,
        "/api/v1/devices/123456/approve",
        Some(&token),
        Some(json!({ "grants": [grant(granted, device.id, 1)] })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{approved}");
    assert_eq!(id(&approved["id"]), device.id);

    let (status, _) = enroll(app.clone(), &device, "000000").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, enrollment) = enroll(app.clone(), &device, "123456").await;
    assert_eq!(status, StatusCode::OK, "{enrollment}");
    assert_eq!(id(&enrollment["account_id"]), account);
    assert_eq!(enrollment["email"], EMAIL);
    assert!(enrollment.get("wrapped_account_key").is_none());
    assert_eq!(enrollment["grants"].as_array().expect("grants").len(), 1);
    assert_eq!(id(&enrollment["grants"][0]["vault_id"]), granted);

    let (status, sync) = sync_as(app.clone(), account, &device, None).await;
    assert_eq!(status, StatusCode::OK, "{sync}");
    assert_eq!(ids(&sync["vaults"]), vec![granted]);
    assert!(vault_in(&sync, granted).get("account_key_wrap").is_none());
    assert_eq!(ids(&sync["items"]), vec![seen]);
    assert_eq!(sync["grants"].as_array().expect("grants").len(), 1);
    let cursor = sync["revision"].as_u64().expect("revision");

    // An approved device cannot write either.
    let body = json!({ "expected_revision": 1, "name": "x" });
    let (status, _) = send(
        app.clone(),
        device.signed(
            account,
            Method::PUT,
            &format!("/api/v1/vaults/{granted}"),
            Some(&body),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // A replayed signature is refused.
    let request = device.signed(account, Method::GET, "/api/v1/sync", None);
    let replay = Request::builder()
        .method(Method::GET)
        .uri("/api/v1/sync")
        .header("x-veil-device", request.headers()["x-veil-device"].clone())
        .header(
            "x-veil-timestamp",
            request.headers()["x-veil-timestamp"].clone(),
        )
        .header("x-veil-nonce", request.headers()["x-veil-nonce"].clone())
        .header(
            "x-veil-signature",
            request.headers()["x-veil-signature"].clone(),
        )
        .body(Body::empty())
        .expect("request");
    assert_eq!(send(app.clone(), request).await.0, StatusCode::OK);
    assert_eq!(send(app.clone(), replay).await.0, StatusCode::UNAUTHORIZED);

    let owner_before = owner_sync(app.clone(), &token, None).await;
    let owner_cursor = owner_before["revision"].as_u64().expect("revision");
    let (status, _) = call(
        app.clone(),
        Method::DELETE,
        &format!("/api/v1/devices/{}", device.id),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = call(
        app.clone(),
        Method::DELETE,
        &format!("/api/v1/devices/{}", device.id),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "revoking twice is fine");

    let owner_after = owner_sync(app.clone(), &token, Some(owner_cursor)).await;
    assert!(owner_after["grants"].as_array().expect("grants").is_empty());
    assert_eq!(vault_in(&owner_after, granted)["rotation_due"], true);
    assert_eq!(vault_in(&owner_after, hidden)["rotation_due"], false);
    assert_eq!(owner_after["deleted"].as_array().expect("deleted").len(), 1);

    let (status, _) = sync_as(app.clone(), account, &device, Some(cursor)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let (_, devices) = call(app, Method::GET, "/api/v1/devices", Some(&token), None).await;
    let revoked = devices
        .as_array()
        .expect("devices")
        .iter()
        .find(|entry| id(&entry["id"]) == device.id)
        .expect("device listed");
    assert!(revoked["revoked_at"].is_u64());
}

#[tokio::test]
async fn sync_cursors_carry_changes_deletions_and_lost_grants() {
    let app = router(state());
    let (account, token) = create_account(app.clone(), &TestDevice::new(1)).await;
    let (shared, private) = (Uuid::now_v7(), Uuid::now_v7());
    let (kept, dropped) = (Uuid::now_v7(), Uuid::now_v7());
    create_vault(
        app.clone(),
        &token,
        shared,
        json!([item(kept, "k"), item(dropped, "d")]),
        json!([]),
    )
    .await;
    create_vault(app.clone(), &token, private, json!([]), json!([])).await;
    let device = TestDevice::new(2);
    approve(
        app.clone(),
        &token,
        &device,
        "222222",
        json!([grant(shared, device.id, 1)]),
    )
    .await;

    let full = owner_sync(app.clone(), &token, None).await;
    assert_eq!(full["full"], true);
    assert_eq!(full["items"].as_array().expect("items").len(), 2);
    assert!(full["deleted"].as_array().expect("deleted").is_empty());
    let cursor = full["revision"].as_u64().expect("revision");
    let (_, device_full) = sync_as(app.clone(), account, &device, None).await;
    let device_cursor = device_full["revision"].as_u64().expect("revision");

    // Nothing changed: an empty increment at the same cursor.
    let same = owner_sync(app.clone(), &token, Some(cursor)).await;
    assert_eq!(same["full"], false);
    assert_eq!(same["revision"], cursor);
    assert!(same["items"].as_array().expect("items").is_empty());
    assert_eq!(
        same["vaults"].as_array().expect("vaults").len(),
        2,
        "vaults are always listed"
    );

    let (status, _) = call(
        app.clone(),
        Method::PUT,
        &format!("/api/v1/vaults/{shared}/items/{kept}"),
        Some(&token),
        Some(json!({ "expected_revision": 1, "item_type": 2, "key": "k2", "data": "k2" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = call(
        app.clone(),
        Method::DELETE,
        &format!("/api/v1/vaults/{shared}/items/{dropped}"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let increment = owner_sync(app.clone(), &token, Some(cursor)).await;
    assert_eq!(increment["full"], false);
    assert!(increment["revision"].as_u64().expect("revision") > cursor);
    assert_eq!(ids(&increment["items"]), vec![kept]);
    assert_eq!(ids(&increment["deleted"]), vec![dropped]);
    assert!(
        increment["rotations"]
            .as_array()
            .expect("rotations")
            .is_empty()
    );

    let (_, device_increment) = sync_as(app.clone(), account, &device, Some(device_cursor)).await;
    assert_eq!(ids(&device_increment["items"]), vec![kept]);
    assert_eq!(ids(&device_increment["deleted"]), vec![dropped]);

    // A cursor from the future gets a full document.
    let future = owner_sync(app.clone(), &token, Some(u64::MAX >> 1)).await;
    assert_eq!(future["full"], true);

    // Rotating the shared Vault without the device: it loses the Vault.
    let device_cursor = device_increment["revision"].as_u64().expect("revision");
    let (status, body) = call(
        app.clone(),
        Method::POST,
        &format!("/api/v1/vaults/{shared}/rotate"),
        Some(&token),
        Some(json!({
            "expected_revision": 3,
            "expected_key_generation": 1,
            "name": "n2",
            "items": [{ "id": kept, "key": "k3" }],
            "grants": [],
            "account_key_wrap": "w2",
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (_, device_after) = sync_as(app, account, &device, Some(device_cursor)).await;
    assert!(
        device_after["vaults"]
            .as_array()
            .expect("vaults")
            .is_empty()
    );
    assert!(device_after["items"].as_array().expect("items").is_empty());
    assert!(
        device_after["rotations"]
            .as_array()
            .expect("rotations")
            .is_empty()
    );
    let deleted = ids(&device_after["deleted"]);
    assert!(deleted.contains(&shared), "{device_after}");
    assert!(!deleted.contains(&private));
}

#[tokio::test]
async fn a_workload_reads_its_grants_and_revocation_marks_rotation_due() {
    let state = state();
    let app = router(state.clone());
    let (_, token) = create_account(app.clone(), &TestDevice::new(1)).await;
    let (granted, hidden) = (Uuid::now_v7(), Uuid::now_v7());
    let entry = Uuid::now_v7();
    create_vault(
        app.clone(),
        &token,
        granted,
        json!([item(entry, "x")]),
        json!([]),
    )
    .await;
    create_vault(
        app.clone(),
        &token,
        hidden,
        json!([item(Uuid::now_v7(), "y")]),
        json!([]),
    )
    .await;

    let workload = Uuid::now_v7();
    let body = json!({
        "id": workload,
        "name": "ci",
        "trust_policy": { "issuer": "https://issuer.example", "audience": "veil", "claims": { "ref": "main" } },
        "seal_pk": "c3BraS1kZXI=",
        "grants": [grant(granted, workload, 1)],
    });
    let (status, created) = call(
        app.clone(),
        Method::POST,
        "/api/v1/workloads",
        Some(&token),
        Some(body.clone()),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let (status, replay) = call(
        app.clone(),
        Method::POST,
        "/api/v1/workloads",
        Some(&token),
        Some(body),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(replay, created);

    let (_, list) = call(
        app.clone(),
        Method::GET,
        "/api/v1/workloads",
        Some(&token),
        None,
    )
    .await;
    assert_eq!(ids(&list), vec![workload]);

    state
        .store
        .create_workload_token(workload, "workload-token", unix_now() + 600)
        .expect("token");
    let (status, sync) = call(
        app.clone(),
        Method::GET,
        "/api/v1/sync",
        Some("workload-token"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{sync}");
    assert_eq!(ids(&sync["vaults"]), vec![granted]);
    assert!(vault_in(&sync, granted).get("account_key_wrap").is_none());
    assert_eq!(ids(&sync["items"]), vec![entry]);

    // A Workload never writes.
    let (status, _) = call(
        app.clone(),
        Method::POST,
        "/api/v1/vaults",
        Some("workload-token"),
        Some(json!({ "id": Uuid::now_v7(), "name": "n", "account_key_wrap": "w" })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let (status, _) = call(
        app.clone(),
        Method::DELETE,
        &format!("/api/v1/workloads/{workload}"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = call(
        app.clone(),
        Method::GET,
        "/api/v1/sync",
        Some("workload-token"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let owner = owner_sync(app.clone(), &token, None).await;
    assert!(owner["grants"].as_array().expect("grants").is_empty());
    assert_eq!(vault_in(&owner, granted)["rotation_due"], true);
    assert_eq!(vault_in(&owner, hidden)["rotation_due"], false);
    let (_, list) = call(app, Method::GET, "/api/v1/workloads", Some(&token), None).await;
    assert!(list[0]["revoked_at"].is_u64());
}

// ----- audit -----

#[tokio::test]
async fn audit_reports_are_scoped_to_readable_vaults_and_filterable() {
    let app = router(state());
    let (account, token) = create_account(app.clone(), &TestDevice::new(1)).await;
    let (granted, hidden) = (Uuid::now_v7(), Uuid::now_v7());
    let (a, b, secret) = (Uuid::now_v7(), Uuid::now_v7(), Uuid::now_v7());
    create_vault(
        app.clone(),
        &token,
        granted,
        json!([item(a, "a"), item(b, "b")]),
        json!([]),
    )
    .await;
    create_vault(
        app.clone(),
        &token,
        hidden,
        json!([item(secret, "s")]),
        json!([]),
    )
    .await;
    let device = TestDevice::new(2);
    approve(
        app.clone(),
        &token,
        &device,
        "333333",
        json!([grant(granted, device.id, 1)]),
    )
    .await;

    let event = |vault: Uuid, item: Uuid| json!({ "vault_id": vault, "item_id": item, "destination": "inject", "result": "ok" });
    let report = |events: Value| {
        let body = json!({ "events": events });
        device.signed(account, Method::POST, "/api/v1/audit/events", Some(&body))
    };

    let (status, _) = send(
        app.clone(),
        report(json!([
            event(granted, a),
            event(granted, b),
            event(granted, a)
        ])),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let (status, _) = send(app.clone(), report(json!([event(hidden, secret)]))).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "vault without a grant");
    let (status, _) = send(app.clone(), report(json!([event(granted, secret)]))).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "item from another vault");
    let too_many: Vec<Value> = (0..101).map(|_| event(granted, a)).collect();
    let (status, _) = send(app.clone(), report(json!(too_many))).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let (status, all) = call(
        app.clone(),
        Method::GET,
        "/api/v1/audit/events",
        Some(&token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(all.as_array().expect("events").len(), 3);
    assert_eq!(id(&all[0]["principal_id"]), device.id);
    assert_eq!(all[0]["principal_kind"], "device");

    let (_, by_item) = call(
        app.clone(),
        Method::GET,
        &format!("/api/v1/audit/events?item_id={a}"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(by_item.as_array().expect("events").len(), 2);
    let (_, by_vault) = call(
        app.clone(),
        Method::GET,
        &format!("/api/v1/audit/events?vault_id={hidden}"),
        Some(&token),
        None,
    )
    .await;
    assert!(by_vault.as_array().expect("events").is_empty());
    let (_, limited) = call(
        app.clone(),
        Method::GET,
        &format!("/api/v1/audit/events?vault_id={granted}&limit=1"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(limited.as_array().expect("events").len(), 1);

    // Only the Owner lists events.
    let (status, _) = send(
        app,
        device.signed(account, Method::GET, "/api/v1/audit/events", None),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn a_workload_exchanges_a_real_oidc_token() {
    use jsonwebtoken::{Algorithm, EncodingKey, Header};
    use rsa::traits::PublicKeyParts;

    let key = rsa::RsaPrivateKey::new(&mut rand_core::OsRng, 2048).expect("rsa key");
    let encoding = EncodingKey::from_rsa_der(
        rsa::pkcs1::EncodeRsaPrivateKey::to_pkcs1_der(&key)
            .expect("der")
            .as_bytes(),
    );

    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let issuer = format!("http://{}", listener.local_addr().expect("addr"));
    let jwks = json!({
        "keys": [{
            "kty": "RSA",
            "kid": "test",
            "alg": "RS256",
            "use": "sig",
            "n": URL_SAFE_NO_PAD.encode(key.n().to_bytes_be()),
            "e": URL_SAFE_NO_PAD.encode(key.e().to_bytes_be()),
        }]
    });
    let served = issuer.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming().take(6).flatten() {
            let mut buffer = [0u8; 4096];
            let mut stream = stream;
            let _ = std::io::Read::read(&mut stream, &mut buffer);
            let request = String::from_utf8_lossy(&buffer);
            let body = if request.starts_with("GET /.well-known/openid-configuration") {
                format!(r#"{{"issuer":"{served}","jwks_uri":"{served}/jwks"}}"#)
            } else {
                jwks.to_string()
            };
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = std::io::Write::write_all(&mut stream, response.as_bytes());
        }
    });

    let app = router(state());
    let device = TestDevice::new(1);
    let (_, token) = create_account(app.clone(), &device).await;
    let vault = Uuid::now_v7();
    create_vault(app.clone(), &token, vault, json!([]), json!([])).await;

    let workload = Uuid::now_v7();
    let (status, body) = call(
        app.clone(),
        Method::POST,
        "/api/v1/workloads",
        Some(&token),
        Some(json!({
            "id": workload,
            "name": "oidc-ci",
            "trust_policy": {
                "issuer": issuer,
                "audience": "veil",
                "claims": { "ref": "refs/heads/main" },
            },
            "seal_pk": "c3BraS1kZXI=",
            "grants": [grant(vault, workload, 1)],
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");

    let claims = json!({
        "iss": issuer,
        "aud": "veil",
        "exp": std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_secs()
            + 600,
        "ref": "refs/heads/main",
    });
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("test".to_owned());
    let jwt = jsonwebtoken::encode(&header, &claims, &encoding).expect("jwt");

    let (status, body) = call(
        app.clone(),
        Method::POST,
        &format!("/api/v1/workloads/{workload}/token"),
        None,
        Some(json!({ "oidc_token": jwt })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let workload_token = body["token"].as_str().expect("token").to_owned();

    let (status, sync) = call(
        app.clone(),
        Method::GET,
        "/api/v1/sync",
        Some(&workload_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{sync}");
    assert_eq!(ids(&sync["vaults"]), vec![vault]);

    let mut wrong = claims.clone();
    wrong["aud"] = json!("other");
    let jwt = jsonwebtoken::encode(&header, &wrong, &encoding).expect("jwt");
    let (status, _) = call(
        app,
        Method::POST,
        &format!("/api/v1/workloads/{workload}/token"),
        None,
        Some(json!({ "oidc_token": jwt })),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn personal_login_reads_future_vaults_and_revocation_ends_its_sessions() {
    let state = state();
    let app = router(state.clone());
    let owner = TestDevice::new(41);
    let (account, token) = create_account(app.clone(), &owner).await;
    let personal = TestDevice::new(42);
    let request = login_body(&personal, EMAIL, AUTH_HASH, false);
    let (status, login) = call(
        app.clone(),
        Method::POST,
        "/api/v1/sessions",
        None,
        Some(request.clone()),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{login}");
    let personal_token = login["session"]["token"].as_str().expect("session");
    let (status, _) = call(
        app.clone(),
        Method::POST,
        "/api/v1/sessions",
        None,
        Some(request),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "proofs are single-use");
    let (status, login2) = call(
        app.clone(),
        Method::POST,
        "/api/v1/sessions",
        None,
        Some(login_body(&personal, EMAIL, AUTH_HASH, false)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{login2}");

    state
        .store
        .create_session(account, personal.id, "expired", 1)
        .expect("expired session");
    let (status, _) = call(
        app.clone(),
        Method::GET,
        "/api/v1/sync",
        Some("expired"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let vault = Uuid::now_v7();
    create_vault(app.clone(), &token, vault, json!([]), json!([])).await;
    let (status, sync) = send(
        app.clone(),
        personal.signed(account, Method::GET, "/api/v1/sync", None),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{sync}");
    assert_eq!(ids(&sync["vaults"]), vec![vault]);
    assert!(sync["vaults"][0]["account_key_wrap"].is_string());
    let (status, _) = send(
        app.clone(),
        personal.signed(account, Method::POST, "/api/v1/vaults", Some(&json!({}))),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let (status, devices) = call(
        app.clone(),
        Method::GET,
        "/api/v1/devices",
        Some(&token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(devices.as_array().expect("devices").len(), 2);
    assert!(
        devices
            .as_array()
            .expect("devices")
            .iter()
            .all(|d| d["owner"] == true)
    );

    let (status, _) = call(
        app.clone(),
        Method::DELETE,
        &format!("/api/v1/devices/{}", personal.id),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    for bearer in [
        personal_token,
        login2["session"]["token"].as_str().expect("session"),
    ] {
        let (status, _) = call(app.clone(), Method::GET, "/api/v1/sync", Some(bearer), None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
    let (status, _) = send(
        app.clone(),
        personal.signed(account, Method::GET, "/api/v1/sync", None),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (_, sync) = call(app.clone(), Method::GET, "/api/v1/sync", Some(&token), None).await;
    assert_eq!(vault_in(&sync, vault)["rotation_due"], true);
    let (status, _) = call(
        app,
        Method::POST,
        "/api/v1/sessions",
        None,
        Some(login_body(&personal, EMAIL, AUTH_HASH, false)),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn restricted_login_requires_explicit_signed_promotion() {
    let app = router(state());
    let owner = TestDevice::new(43);
    let (account, token) = create_account(app.clone(), &owner).await;
    let restricted = TestDevice::new(44);
    let vault = Uuid::now_v7();
    create_vault(app.clone(), &token, vault, json!([]), json!([])).await;
    approve(app.clone(), &token, &restricted, "444444", json!([])).await;
    let (status, _) = call(
        app.clone(),
        Method::POST,
        "/api/v1/sessions",
        None,
        Some(login_body(&restricted, EMAIL, AUTH_HASH, false)),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (_, sync) = send(
        app.clone(),
        restricted.signed(account, Method::GET, "/api/v1/sync", None),
    )
    .await;
    assert!(sync["vaults"].as_array().expect("vaults").is_empty());

    let mut tampered = login_body(&restricted, EMAIL, AUTH_HASH, false);
    tampered["device"]["promote"] = json!(true);
    let (status, _) = call(
        app.clone(),
        Method::POST,
        "/api/v1/sessions",
        None,
        Some(tampered),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = call(
        app.clone(),
        Method::POST,
        "/api/v1/sessions",
        None,
        Some(login_body(&restricted, EMAIL, AUTH_HASH, true)),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (_, sync) = send(
        app,
        restricted.signed(account, Method::GET, "/api/v1/sync", None),
    )
    .await;
    assert_eq!(ids(&sync["vaults"]), vec![vault]);
}

#[tokio::test]
async fn device_login_refuses_legacy_tampered_stale_and_mismatched_identities() {
    let app = router(state());
    let owner = TestDevice::new(45);
    create_account(app.clone(), &owner).await;
    let (status, _) = call(
        app.clone(),
        Method::POST,
        "/api/v1/sessions",
        None,
        Some(json!({"email": EMAIL, "auth_hash": AUTH_HASH})),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let other = TestDevice::new(46);
    let mut changed = login_body(&other, EMAIL, AUTH_HASH, false);
    changed["device"]["keys"]["seal_pk"] = json!("different");
    let (status, _) = call(
        app.clone(),
        Method::POST,
        "/api/v1/sessions",
        None,
        Some(changed),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let mut stale = login_body(&other, EMAIL, AUTH_HASH, false);
    stale["device"]["timestamp"] = json!(1);
    let (status, _) = call(
        app.clone(),
        Method::POST,
        "/api/v1/sessions",
        None,
        Some(stale),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let collision = TestDevice {
        id: owner.id,
        signing: other.signing,
    };
    let (status, _) = call(
        app.clone(),
        Method::POST,
        "/api/v1/sessions",
        None,
        Some(login_body(&collision, EMAIL, AUTH_HASH, false)),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let mut second = account_body(&TestDevice::new(47));
    second["email"] = json!("second@example.com");
    let (status, _) = call(
        app.clone(),
        Method::POST,
        "/api/v1/accounts",
        None,
        Some(second),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, _) = call(
        app,
        Method::POST,
        "/api/v1/sessions",
        None,
        Some(login_body(&owner, "second@example.com", AUTH_HASH, false)),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn repeated_failed_sign_ins_are_refused_with_retry_after() {
    let app = router(state());
    create_account(app.clone(), &TestDevice::new(1)).await;
    for _ in 0..veil_daemon::throttle::ACCOUNT_LIMIT {
        let (status, _) = call(
            app.clone(),
            Method::POST,
            "/api/v1/sessions",
            None,
            Some(json!({ "email": EMAIL, "auth_hash": "wrong" })),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
    let (status, body) = call(
        app.clone(),
        Method::POST,
        "/api/v1/sessions",
        None,
        Some(json!({ "email": EMAIL, "auth_hash": AUTH_HASH })),
    )
    .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
    assert_eq!(body["status"], 429);
}
