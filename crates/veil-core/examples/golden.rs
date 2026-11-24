//! Writes the golden fixtures in `crates/veil-core/tests/fixtures/` with the pinned SDK.
//!
//! Run `scripts/regenerate-golden.sh`. This program calls `bitwarden-crypto` and
//! `bitwarden-core` directly and never `veil-core`, so the fixtures are an independent record of
//! the format: `veil-core` must open them, and the SDK must open what `veil-core` writes. A merge
//! request that changes them states why in a `Fixtures:` line of its description.

use std::{fs, path::Path};

use base64::{Engine, engine::general_purpose::STANDARD};
use bitwarden_core::key_management::{
    KeySlotIds, account_cryptographic_state::WrappedAccountCryptographicState,
};
use bitwarden_crypto::{
    HashPurpose, Kdf, KeyEncryptable, KeyStore, MasterKey, PrivateKey,
    PublicKeyEncryptionAlgorithm, SymmetricKeyAlgorithm, UnsignedSharedKey,
    safe::{DataEnvelope, DataEnvelopeNamespace, SealableData, SealableVersionedData},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

#[derive(Serialize, Deserialize, Debug, PartialEq)]
#[serde(transparent)]
struct RecordV1(Value);
impl SealableData for RecordV1 {}
bitwarden_crypto::generate_versioned_sealable!(Record, DataEnvelopeNamespace::VaultItem, [RecordV1 => "1"]);

const EMAIL: &str = "golden@example.com";
const PASSWORD: &str = "correct horse battery staple";
/// A recovery code in canonical form. Fixtures only.
const RECOVERY_CODE: &str = "ABCDE-FGHIJ-KLMNO-PQRST-UVWXY-Z2345-67ABC-DEFGH-IJKLM-NOPQR-ST";

fn records() -> Vec<(&'static str, u8, Value)> {
    vec![
        (
            "login-token",
            1,
            json!({
                "name": "demo-service", "notes": null,
                "typeData": { "type": "login", "username": null, "password": "demo-123:ABC",
                    "passwordRevisionDate": null, "totp": null, "autofillOnPageLoad": null },
            }),
        ),
        (
            "login-full",
            1,
            json!({
                "name": "example_app", "notes": "admin account",
                "typeData": { "type": "login", "username": "admin", "password": "example-pw",
                    "passwordRevisionDate": null, "uris": [{ "uri": "https://app.example.com", "match": null }],
                    "totp": null, "autofillOnPageLoad": null },
                "fields": [
                    { "name": "client_secret", "value": "oidc-s3cret", "type": 1, "linkedId": null },
                    { "name": "client_id", "value": "example_app", "type": 0, "linkedId": null },
                ],
            }),
        ),
        (
            "secure-note",
            2,
            json!({
                "name": "tls", "notes": "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----",
                "typeData": { "type": "secureNote", "secureNoteType": 0 },
                "fields": [{ "name": "TLS_KEY_PASSPHRASE", "value": "hunter2", "type": 1, "linkedId": null }],
            }),
        ),
        (
            "ssh-key",
            5,
            json!({
                "name": "deploy-key", "notes": null,
                "typeData": { "type": "sshKey",
                    "privateKey": "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEA\n-----END OPENSSH PRIVATE KEY-----",
                    "publicKey": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI deploy@veil",
                    "fingerprint": "SHA256:deploydeploydeploydeploydeploydeploydeploy" },
            }),
        ),
    ]
}

fn main() {
    let dir = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "crates/veil-core/tests/fixtures".to_owned());
    let dir = Path::new(&dir);
    fs::create_dir_all(dir.join("items")).expect("fixture directory");

    let store: KeyStore<KeySlotIds> = KeyStore::default();
    let mut ctx = store.context_mut();

    // Account: v2 key state, wrapped by the master password and by the recovery code.
    let kdf = Kdf::default_argon2();
    let master = MasterKey::derive(PASSWORD, EMAIL, &kdf).expect("derive");
    let (account_slot, state) = WrappedAccountCryptographicState::make(&mut ctx).expect("make");
    #[allow(deprecated)]
    let account_key = ctx
        .dangerous_get_symmetric_key(account_slot)
        .expect("key")
        .clone();
    let recovery_kdf = Kdf::PBKDF2 {
        iterations: 5000.try_into().expect("non-zero"),
    };
    let recovery = MasterKey::derive(RECOVERY_CODE, EMAIL, &recovery_kdf).expect("recovery");
    let Kdf::Argon2id {
        iterations,
        memory,
        parallelism,
    } = kdf
    else {
        unreachable!("the SDK default is Argon2id")
    };
    write(
        &dir.join("account.json"),
        &json!({
            "email": EMAIL,
            "password": PASSWORD,
            "kdf": { "kind": "argon2id", "iterations": iterations.get(), "memory_mib": memory.get(),
                     "parallelism": parallelism.get() },
            "auth_hash": master
                .derive_master_key_hash(PASSWORD.as_bytes(), HashPurpose::ServerAuthorization)
                .to_string(),
            "protected_account_key": master.encrypt_user_key(&account_key).expect("protect").to_string(),
            "account_keys": serde_json::to_string(&state).expect("state"),
            "recovery_code": RECOVERY_CODE,
            "recovery_verifier": recovery
                .derive_master_key_hash(RECOVERY_CODE.as_bytes(), HashPurpose::ServerAuthorization)
                .to_string(),
            "recovery_wrap": recovery.encrypt_user_key(&account_key).expect("recovery wrap").to_string(),
        }),
    );

    // Vault: its key wrapped by the account key, its name sealed by itself, one Grant.
    let vault_slot = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XAes256Gcm);
    #[allow(deprecated)]
    let vault_key = ctx
        .dangerous_get_symmetric_key(vault_slot)
        .expect("key")
        .clone();
    let device = PrivateKey::make(PublicKeyEncryptionAlgorithm::RsaOaepSha1);
    write(
        &dir.join("vault.json"),
        &json!({
            "name": "example",
            "sealed_name": "example".encrypt_with_key(&vault_key).expect("name").to_string(),
            "account_key_wrap": ctx.wrap_symmetric_key(account_slot, vault_slot).expect("wrap").to_string(),
            "grant": {
                "sealing_key": STANDARD.encode(device.to_der().expect("der").as_ref()),
                "wrapped_key": UnsignedSharedKey::encapsulate(vault_slot, &device.to_public_key(), &ctx)
                    .expect("share").to_string(),
            },
        }),
    );

    // Items: one per type Veil uses, each with its own Item key and a fresh content key.
    for (file, item_type, record) in records() {
        let item_slot = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XAes256Gcm);
        let key = ctx
            .wrap_symmetric_key(vault_slot, item_slot)
            .expect("item key");
        let (envelope, wrapped_cek) = DataEnvelope::seal_with_wrapping_key(
            Record::from(RecordV1(record.clone())),
            &item_slot,
            &mut ctx,
        )
        .expect("seal");
        let data = json!({
            "format_version": 1,
            "wrapped_cek": wrapped_cek.to_string(),
            "envelope": String::from(envelope),
        });
        write(
            &dir.join("items").join(format!("{file}.json")),
            &json!({ "type": item_type, "key": key.to_string(), "data": data.to_string(), "record": record }),
        );
    }
    println!("wrote fixtures to {}", dir.display());
}

fn write(path: &Path, value: &Value) {
    let mut text = serde_json::to_string_pretty(value).expect("json");
    text.push('\n');
    fs::write(path, text).expect("write fixture");
}
