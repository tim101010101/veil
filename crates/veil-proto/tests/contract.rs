//! The wire contract.
//!
//! These tests fail when a type is added without being registered in the OpenAPI
//! document, when a sealed record changes shape, or when an id stops being a UUID.

use utoipa::OpenApi;
use uuid::Uuid;
use veil_proto::{Contract, DeliveryResult, Destination, Item, Kdf};

/// Every schema the contract promises. Adding a type means adding it here and in
/// [`Contract`]; the exact-match assertion is the tripwire.
const DOCUMENTED: &[&str] = &[
    "Account",
    "ApproveDeviceRequest",
    "AuditEvent",
    "AuditEventBatch",
    "AuditEventInput",
    "BeginDeviceEnrollmentRequest",
    "BitwardenStatus",
    "CreateAccountRequest",
    "CreateAccountResponse",
    "CreateRecoveryRequest",
    "CreateRecoveryResponse",
    "CreateSessionRequest",
    "CreateSessionResponse",
    "CreateVaultRequest",
    "CreateWorkloadRequest",
    "DeliveryResult",
    "Destination",
    "Device",
    "DeviceKeys",
    "DeviceLogin",
    "EnableBitwardenRequest",
    "EnrollmentProof",
    "EnrollmentResponse",
    "ExchangeWorkloadTokenRequest",
    "Grant",
    "GrantWrite",
    "HealthReport",
    "Item",
    "ItemKeyWrite",
    "ItemWrite",
    "Kdf",
    "PendingDevice",
    "PreloginRequest",
    "PreloginResponse",
    "PrincipalKind",
    "ProblemDetails",
    "PutItemRequest",
    "RotateVaultRequest",
    "Rotation",
    "ServiceStatus",
    "Session",
    "SyncDocument",
    "TrustPolicy",
    "UpdateAccountRequest",
    "UpdateVaultRequest",
    "Vault",
    "Workload",
    "WorkloadToken",
];

#[test]
fn the_contract_documents_exactly_the_v1_schemas() {
    let document = Contract::openapi();
    let components = document.components.expect("components");
    let mut actual: Vec<&str> = components.schemas.keys().map(String::as_str).collect();
    actual.sort_unstable();

    let mut expected = DOCUMENTED.to_vec();
    expected.sort_unstable();

    assert_eq!(actual, expected);
}

#[test]
fn sealed_fields_are_opaque_strings() {
    let item = Item {
        id: Uuid::from_u128(1),
        vault_id: Uuid::from_u128(2),
        item_type: 1,
        key: "7.wrapped".to_owned(),
        data: r#"{"format_version":1}"#.to_owned(),
        revision: 3,
        favorite: false,
        folder_id: None,
        deleted_at: None,
        revised_at: 4,
    };
    let json = serde_json::to_value(&item).expect("serialize");
    assert_eq!(json["key"], "7.wrapped");
    assert_eq!(json["data"], r#"{"format_version":1}"#);
    assert_eq!(serde_json::from_value::<Item>(json).expect("parse"), item);
}

#[test]
fn ids_are_uuid_strings_and_garbage_is_rejected() {
    let json = serde_json::json!({
        "id": "not-a-uuid", "vault_id": Uuid::from_u128(2), "item_type": 1, "key": "k",
        "data": "d", "revision": 1, "favorite": false, "folder_id": null, "deleted_at": null,
        "revised_at": 1,
    });
    assert!(
        serde_json::from_value::<Item>(json).is_err(),
        "a malformed id must not parse"
    );
}

#[test]
fn the_kdf_is_tagged_by_kind() {
    let kdf = Kdf::Argon2id {
        iterations: 6,
        memory_mib: 32,
        parallelism: 4,
    };
    assert_eq!(
        serde_json::to_value(kdf).expect("serialize"),
        serde_json::json!({ "kind": "argon2id", "iterations": 6, "memory_mib": 32, "parallelism": 4 })
    );
}

#[test]
fn destinations_use_their_wire_names() {
    assert_eq!(
        serde_json::to_value(Destination::Inject).expect("serialize"),
        "inject"
    );
    assert_eq!(
        serde_json::to_value(Destination::Browser).expect("serialize"),
        "browser"
    );
    assert_eq!(
        serde_json::to_value(DeliveryResult::Ok).expect("serialize"),
        "ok"
    );
}
