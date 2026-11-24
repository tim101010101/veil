//! The format gate (compatibility suite): golden fixtures sealed by the pinned SDK, checked both ways.
//!
//! - The SDK, called directly, opens every fixture. This pins the stored bytes to the SDK.
//! - `veil-core` opens every fixture and the SDK's own recorded `CipherBlobV1` test vectors.
//! - Records written by `veil-core` open with the SDK directly.
//!
//! The fixtures come from `examples/golden.rs` (`scripts/regenerate-golden.sh`), which never
//! calls `veil-core`.

use std::{fs, path::PathBuf, str::FromStr};

use base64::{Engine, engine::general_purpose::STANDARD};
use bitwarden_core::key_management::{
    KeySlotIds, account_cryptographic_state::WrappedAccountCryptographicState,
};
use bitwarden_crypto::{
    EncString, HashPurpose, Kdf, KeyDecryptable, KeyStore, MasterKey, Pkcs8PrivateKeyBytes,
    PrivateKey, SymmetricCryptoKey, UnsignedSharedKey,
    safe::{DataEnvelope, DataEnvelopeNamespace, SealableData, SealableVersionedData},
};
use bitwarden_encoding::B64;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Serialize, Deserialize, Debug, PartialEq)]
#[serde(transparent)]
struct RecordV1(Value);
impl SealableData for RecordV1 {}
bitwarden_crypto::generate_versioned_sealable!(Record, DataEnvelopeNamespace::VaultItem, [RecordV1 => "1"]);

fn fixture(name: &str) -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name);
    serde_json::from_str(&fs::read_to_string(&path).expect("fixture")).expect("fixture json")
}

fn text<'a>(value: &'a Value, key: &str) -> &'a str {
    value[key]
        .as_str()
        .unwrap_or_else(|| panic!("{key} is a string"))
}

fn items() -> Vec<Value> {
    ["login-token", "login-full", "secure-note", "ssh-key"]
        .iter()
        .map(|name| fixture(&format!("items/{name}.json")))
        .collect()
}

fn sdk_kdf(account: &Value) -> Kdf {
    let kdf = &account["kdf"];
    assert_eq!(kdf["kind"], "argon2id");
    let field = |name: &str| {
        u32::try_from(kdf[name].as_u64().expect("number"))
            .expect("u32")
            .try_into()
            .expect("non-zero")
    };
    Kdf::Argon2id {
        iterations: field("iterations"),
        memory: field("memory_mib"),
        parallelism: field("parallelism"),
    }
}

/// Opens one stored Item with the SDK alone.
fn sdk_open_item(
    ctx: &mut bitwarden_crypto::KeyStoreContext<'_, KeySlotIds>,
    vault: bitwarden_core::key_management::SymmetricKeySlotId,
    key: &str,
    data: &str,
) -> Value {
    let item = ctx
        .unwrap_symmetric_key(vault, &EncString::from_str(key).expect("key"))
        .expect("item key unwraps");
    let container: Value = serde_json::from_str(data).expect("container");
    assert_eq!(container["format_version"], 1);
    let envelope = DataEnvelope::from_str(text(&container, "envelope")).expect("envelope");
    let cek = EncString::from_str(text(&container, "wrapped_cek")).expect("cek");
    let Record::RecordV1(RecordV1(record)) = envelope
        .unseal_with_wrapping_key(&item, &cek, ctx)
        .expect("record unseals");
    record
}

// ---- The SDK opens the fixtures -------------------------------------------------------------

#[test]
fn the_sdk_opens_the_account_fixture() {
    let account = fixture("account.json");
    let (email, password) = (text(&account, "email"), text(&account, "password"));
    let master = MasterKey::derive(password, email, &sdk_kdf(&account)).expect("derive");
    assert_eq!(
        master
            .derive_master_key_hash(password.as_bytes(), HashPurpose::ServerAuthorization)
            .to_string(),
        text(&account, "auth_hash")
    );
    let account_key = master
        .decrypt_user_key(
            text(&account, "protected_account_key")
                .parse()
                .expect("enc"),
        )
        .expect("account key");

    let state: WrappedAccountCryptographicState =
        serde_json::from_str(text(&account, "account_keys")).expect("state");
    let store: KeyStore<KeySlotIds> = KeyStore::default();
    let mut ctx = store.context_mut();
    let user = ctx.add_local_symmetric_key(account_key.clone());
    state
        .to_wrapped_request_model(&user, &mut ctx)
        .expect("v2 key state verifies under the account key");

    let code = text(&account, "recovery_code");
    let recovery = MasterKey::derive(
        code,
        email,
        &Kdf::PBKDF2 {
            iterations: 5000.try_into().expect("non-zero"),
        },
    )
    .expect("recovery");
    assert_eq!(
        recovery
            .decrypt_user_key(text(&account, "recovery_wrap").parse().expect("enc"))
            .expect("recovery unwraps"),
        account_key
    );
}

#[test]
fn the_sdk_opens_the_vault_and_item_fixtures() {
    let account = fixture("account.json");
    let vault = fixture("vault.json");
    let master = MasterKey::derive(
        text(&account, "password"),
        text(&account, "email"),
        &sdk_kdf(&account),
    )
    .expect("derive");
    let account_key = master
        .decrypt_user_key(
            text(&account, "protected_account_key")
                .parse()
                .expect("enc"),
        )
        .expect("account key");

    let store: KeyStore<KeySlotIds> = KeyStore::default();
    let mut ctx = store.context_mut();
    let user = ctx.add_local_symmetric_key(account_key);
    let vault_slot = ctx
        .unwrap_symmetric_key(
            user,
            &text(&vault, "account_key_wrap").parse().expect("enc"),
        )
        .expect("vault key");
    #[allow(deprecated)]
    let vault_key: SymmetricCryptoKey = ctx
        .dangerous_get_symmetric_key(vault_slot)
        .expect("key")
        .clone();
    let name: String = EncString::from_str(text(&vault, "sealed_name"))
        .expect("enc")
        .decrypt_with_key(&vault_key)
        .expect("name");
    assert_eq!(name, text(&vault, "name"));

    let device = PrivateKey::from_der(&Pkcs8PrivateKeyBytes::from(
        STANDARD
            .decode(text(&vault["grant"], "sealing_key"))
            .expect("b64"),
    ))
    .expect("device key");
    let device = ctx.add_local_private_key(device);
    let shared = UnsignedSharedKey::from_str(text(&vault["grant"], "wrapped_key")).expect("grant");
    let granted = shared.decapsulate(device, &mut ctx).expect("grant opens");
    #[allow(deprecated)]
    let granted = ctx
        .dangerous_get_symmetric_key(granted)
        .expect("key")
        .clone();
    assert_eq!(granted, vault_key);

    for item in items() {
        let record = sdk_open_item(
            &mut ctx,
            vault_slot,
            text(&item, "key"),
            text(&item, "data"),
        );
        assert_eq!(record, item["record"]);
    }
}

// ---- veil-core opens the fixtures and the SDK's own vectors ---------------------------------

fn core_kdf(account: &Value) -> veil_core::Kdf {
    serde_json::from_value(account["kdf"].clone()).expect("kdf")
}

fn core_vault_key() -> veil_core::Key {
    let account = fixture("account.json");
    let master = veil_core::MasterPassword::derive(
        text(&account, "password"),
        text(&account, "email"),
        &core_kdf(&account),
    )
    .expect("derive");
    let account_key = master
        .unlock(text(&account, "protected_account_key"))
        .expect("unlock");
    veil_core::unwrap_key(
        &account_key,
        text(&fixture("vault.json"), "account_key_wrap"),
    )
    .expect("vault key")
}

#[test]
fn veil_core_opens_the_account_fixture() {
    let account = fixture("account.json");
    let email = text(&account, "email");
    let master =
        veil_core::MasterPassword::derive(text(&account, "password"), email, &core_kdf(&account))
            .expect("derive");
    assert_eq!(master.auth_hash(), text(&account, "auth_hash"));
    let account_key = master
        .unlock(text(&account, "protected_account_key"))
        .expect("unlock");
    veil_core::verify_account_keys(&account_key, text(&account, "account_keys"))
        .expect("key state verifies");

    let code = veil_core::RecoveryCode::parse(text(&account, "recovery_code")).expect("code");
    assert_eq!(
        code.verifier(email).expect("verifier"),
        text(&account, "recovery_verifier")
    );
    assert_eq!(
        code.unwrap(email, text(&account, "recovery_wrap"))
            .expect("recover"),
        account_key
    );
}

#[test]
fn veil_core_opens_the_vault_and_item_fixtures() {
    let vault = fixture("vault.json");
    let vault_key = core_vault_key();
    assert_eq!(
        veil_core::open_text(&vault_key, text(&vault, "sealed_name")).expect("name"),
        text(&vault, "name")
    );
    let device = veil_core::SealingKey::from_base64(text(&vault["grant"], "sealing_key"))
        .expect("device key");
    assert_eq!(
        device
            .open_shared_key(text(&vault["grant"], "wrapped_key"))
            .expect("grant"),
        vault_key
    );

    for fixture in items() {
        let sealed = veil_core::SealedItem {
            key: text(&fixture, "key").to_owned(),
            data: text(&fixture, "data").to_owned(),
        };
        let item = veil_core::open_item(&vault_key, &sealed).expect("item opens");
        assert_eq!(item.to_json(), fixture["record"]);
        assert_eq!(
            item.item_type().code(),
            fixture["type"].as_u64().map(|code| code as u8)
        );
    }
}

#[test]
fn veil_core_reads_the_fields_it_resolves_from_the_fixtures() {
    let vault_key = core_vault_key();
    let open = |name: &str| {
        let fixture = fixture(&format!("items/{name}.json"));
        veil_core::open_item(
            &vault_key,
            &veil_core::SealedItem {
                key: text(&fixture, "key").to_owned(),
                data: text(&fixture, "data").to_owned(),
            },
        )
        .expect("item")
    };
    let example_app = open("login-full");
    assert_eq!(example_app.field("username").as_deref(), Some("admin"));
    assert_eq!(example_app.field("password").as_deref(), Some("example-pw"));
    assert_eq!(
        example_app.field("uri").as_deref(),
        Some("https://app.example.com")
    );
    assert_eq!(
        example_app.field("client_secret").as_deref(),
        Some("oidc-s3cret")
    );
    assert!(example_app.is_hidden("client_secret") && !example_app.is_hidden("client_id"));
    assert_eq!(
        open("login-token").field("password").as_deref(),
        Some("demo-123:ABC")
    );
    assert_eq!(
        open("secure-note").field("TLS_KEY_PASSPHRASE").as_deref(),
        Some("hunter2")
    );
    assert!(
        open("ssh-key")
            .field("private_key")
            .is_some_and(|key| key.contains("OPENSSH"))
    );
}

#[test]
fn veil_core_reads_records_the_bitwarden_sdk_sealed() {
    let vectors = fixture("upstream-vectors.json");
    for (name, vector) in vectors["vectors"].as_object().expect("vectors") {
        // The SDK sealed each vector with a bare content key. Wrap that key the way a v2 cipher
        // stores it (content key under an Item key, Item key under the Vault key), leaving the
        // SDK's envelope bytes untouched.
        let store: KeyStore<KeySlotIds> = KeyStore::default();
        let mut ctx = store.context_mut();
        let cek = SymmetricCryptoKey::try_from(B64::try_from(text(vector, "cek")).expect("b64"))
            .expect("cek");
        let cek = ctx.add_local_symmetric_key(cek);
        let item = ctx.make_symmetric_key(bitwarden_crypto::SymmetricKeyAlgorithm::XAes256Gcm);
        let vault = ctx.make_symmetric_key(bitwarden_crypto::SymmetricKeyAlgorithm::XAes256Gcm);
        let wrapped_cek = ctx.wrap_symmetric_key(item, cek).expect("wrap cek");
        let key = ctx.wrap_symmetric_key(vault, item).expect("wrap item key");
        #[allow(deprecated)]
        let vault_key = ctx
            .dangerous_get_symmetric_key(vault)
            .expect("key")
            .to_base64();
        let sealed = veil_core::SealedItem {
            key: key.to_string(),
            data: serde_json::json!({
                "format_version": 1,
                "wrapped_cek": wrapped_cek.to_string(),
                "envelope": text(vector, "envelope"),
            })
            .to_string(),
        };

        let vault_key = veil_core::Key::from_base64(&vault_key.to_string()).expect("vault key");
        let opened = veil_core::open_item(&vault_key, &sealed)
            .unwrap_or_else(|error| panic!("{name}: {error}"));
        let expect = &vector["expect"];
        assert_eq!(opened.name(), text(expect, "name"), "{name}");
        assert_eq!(
            opened.to_json()["typeData"]["type"],
            expect["type"],
            "{name}"
        );
        for (field, value) in expect["fields"].as_object().expect("fields") {
            assert_eq!(
                opened.field(field).as_deref(),
                value.as_str(),
                "{name}.{field}"
            );
        }
    }
}

// ---- The SDK opens what veil-core writes ----------------------------------------------------

#[test]
fn the_sdk_opens_an_account_created_by_veil_core() {
    let account = veil_core::NewAccount::create(
        "writer@example.com",
        "correct horse",
        &veil_core::Kdf::MINIMUM,
    )
    .expect("create");
    let kdf = Kdf::PBKDF2 {
        iterations: 5000.try_into().expect("non-zero"),
    };
    let master = MasterKey::derive("correct horse", "writer@example.com", &kdf).expect("derive");
    assert_eq!(
        master
            .derive_master_key_hash(b"correct horse", HashPurpose::ServerAuthorization)
            .to_string(),
        account.auth_hash
    );
    let account_key = master
        .decrypt_user_key(account.protected_account_key.parse().expect("enc"))
        .expect("account key");
    assert_eq!(
        account_key.to_base64().to_string(),
        account.account_key.to_base64()
    );

    let state: WrappedAccountCryptographicState =
        serde_json::from_str(&account.account_keys).expect("state");
    let store: KeyStore<KeySlotIds> = KeyStore::default();
    let mut ctx = store.context_mut();
    let user = ctx.add_local_symmetric_key(account_key);
    state
        .to_wrapped_request_model(&user, &mut ctx)
        .expect("v2 key state verifies");
}

#[test]
fn the_sdk_opens_vaults_and_items_written_by_veil_core() {
    let account_key = veil_core::Key::generate();
    let vault_key = veil_core::Key::generate();
    let account_key_wrap = veil_core::wrap_key(&account_key, &vault_key).expect("wrap");
    let sealed_name = veil_core::seal_text(&vault_key, "example").expect("name");
    let device = veil_core::SealingKey::generate();
    let grant = veil_core::share_key(&vault_key, &device.public()).expect("share");

    let mut example_app = veil_core::Item::login("example_app");
    example_app.set_field("username", "admin");
    example_app.set_field("password", "example-pw");
    example_app.set_field("uri", "https://app.example.com");
    example_app.set_field("client_secret", "oidc-s3cret");
    let mut note = veil_core::Item::secure_note("tls");
    note.set_field("notes", "certificate");
    note.set_field("TLS_KEY_PASSPHRASE", "hunter2");

    let store: KeyStore<KeySlotIds> = KeyStore::default();
    let mut ctx = store.context_mut();
    let user = ctx.add_local_symmetric_key(
        SymmetricCryptoKey::try_from(B64::try_from(account_key.to_base64()).expect("b64"))
            .expect("key"),
    );
    let vault = ctx
        .unwrap_symmetric_key(user, &account_key_wrap.parse().expect("enc"))
        .expect("vault key");
    #[allow(deprecated)]
    let sdk_vault_key = ctx.dangerous_get_symmetric_key(vault).expect("key").clone();
    let name: String = EncString::from_str(&sealed_name)
        .expect("enc")
        .decrypt_with_key(&sdk_vault_key)
        .expect("name");
    assert_eq!(name, "example");

    let private = PrivateKey::from_der(&Pkcs8PrivateKeyBytes::from(
        STANDARD.decode(device.to_base64()).expect("b64"),
    ))
    .expect("device");
    let private = ctx.add_local_private_key(private);
    let granted = UnsignedSharedKey::from_str(&grant)
        .expect("grant")
        .decapsulate(private, &mut ctx)
        .expect("grant opens");
    #[allow(deprecated)]
    let granted = ctx
        .dangerous_get_symmetric_key(granted)
        .expect("key")
        .clone();
    assert_eq!(granted, sdk_vault_key);

    for item in [example_app, note] {
        let sealed = veil_core::seal_item(&vault_key, &item, None).expect("seal");
        let record = sdk_open_item(&mut ctx, vault, &sealed.key, &sealed.data);
        assert_eq!(record, item.to_json());
        assert!(
            sealed.key.starts_with("7."),
            "Item keys are wrapped with COSE: {}",
            sealed.key
        );
    }
}
