//! Items: one sealed record per Item, in the SDK's v2 format.
//!
//! On the wire an Item is two strings, exactly as a Bitwarden v2 client stores a cipher:
//!
//! - `key`: the Item key, wrapped by the Vault key (an `EncString`).
//! - `data`: `{"format_version":1,"wrapped_cek":…,"envelope":…}`, where `envelope` is a
//!   `DataEnvelope` (COSE_Encrypt0, namespace `VaultItem`) sealed with a fresh content key, and
//!   `wrapped_cek` is that content key wrapped by the Item key.
//!
//! The plaintext is the SDK's `CipherBlobV1` record. `veil-core` keeps it as JSON and reads and
//! writes only the fields `veil` uses, so fields a Bitwarden client wrote and `veil` does not
//! know survive a `veil` write unchanged.

use bitwarden_crypto::{
    EncString,
    safe::{DataEnvelope, DataEnvelopeNamespace, SealableData, SealableVersionedData},
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::{Error, Key, key::with_context};

const FORMAT_VERSION: u64 = 1;

#[derive(Serialize, Deserialize, Debug, PartialEq)]
#[serde(transparent)]
struct RecordV1(Value);

impl SealableData for RecordV1 {}

bitwarden_crypto::generate_versioned_sealable!(
    Record,
    DataEnvelopeNamespace::VaultItem,
    [RecordV1 => "1"]
);

/// The kind of Item, from the `typeData.type` tag of the record.
///
/// The numeric code is the plaintext type Bitwarden stores beside the record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ItemType {
    /// A website or service account.
    Login,
    /// Free text plus custom fields.
    SecureNote,
    /// A payment card.
    Card,
    /// A personal identity.
    Identity,
    /// An SSH key pair.
    SshKey,
    /// A type this version of `veil` does not know; its record is kept as is.
    Other(String),
}

impl ItemType {
    /// Bitwarden's `CipherType` number, for the types `veil` can create.
    pub fn code(&self) -> Option<u8> {
        match self {
            Self::Login => Some(1),
            Self::SecureNote => Some(2),
            Self::Card => Some(3),
            Self::Identity => Some(4),
            Self::SshKey => Some(5),
            Self::Other(_) => None,
        }
    }

    fn from_tag(tag: &str) -> Self {
        match tag {
            "login" => Self::Login,
            "secureNote" => Self::SecureNote,
            "card" => Self::Card,
            "identity" => Self::Identity,
            "sshKey" => Self::SshKey,
            other => Self::Other(other.to_owned()),
        }
    }
}

/// The fields of a login that references can name, mapped to their record keys.
const LOGIN_FIELDS: [(&str, &str); 3] = [
    ("username", "username"),
    ("password", "password"),
    ("totp", "totp"),
];

/// The fields of an SSH key that references can name.
const SSH_FIELDS: [(&str, &str); 3] = [
    ("private_key", "privateKey"),
    ("public_key", "publicKey"),
    ("fingerprint", "fingerprint"),
];

/// Custom field types (`FieldType` in the SDK).
const FIELD_TEXT: u64 = 0;
const FIELD_HIDDEN: u64 = 1;
const FIELD_BOOLEAN: u64 = 2;

/// One Item's plaintext record.
#[derive(Debug, Clone, PartialEq)]
pub struct Item(Map<String, Value>);

impl Item {
    /// A login with only a name. Tokens are logins with only a password.
    pub fn login(name: &str) -> Self {
        Self::with_type_data(
            name,
            json!({
                "type": "login",
                "username": null,
                "password": null,
                "passwordRevisionDate": null,
                "totp": null,
                "autofillOnPageLoad": null,
            }),
        )
    }

    /// A secure note: notes plus custom fields.
    pub fn secure_note(name: &str) -> Self {
        Self::with_type_data(name, json!({ "type": "secureNote", "secureNoteType": 0 }))
    }

    fn with_type_data(name: &str, type_data: Value) -> Self {
        let mut record = Map::new();
        record.insert("name".to_owned(), Value::String(name.to_owned()));
        record.insert("notes".to_owned(), Value::Null);
        record.insert("typeData".to_owned(), type_data);
        Self(record)
    }

    /// Validates a plaintext record: a `name` string and a tagged `typeData` object.
    pub fn from_json(value: Value) -> Result<Self, Error> {
        let Value::Object(record) = value else {
            return Err(Error::Item);
        };
        let valid = record.get("name").is_some_and(Value::is_string)
            && record
                .get("typeData")
                .and_then(|data| data.get("type"))
                .is_some_and(Value::is_string);
        if !valid {
            return Err(Error::Item);
        }
        Ok(Self(record))
    }

    /// The plaintext record.
    pub fn to_json(&self) -> Value {
        Value::Object(self.0.clone())
    }

    /// The Item name.
    pub fn name(&self) -> &str {
        self.0
            .get("name")
            .and_then(Value::as_str)
            .expect("validated on construction")
    }

    /// Renames the Item.
    pub fn set_name(&mut self, name: &str) {
        self.0
            .insert("name".to_owned(), Value::String(name.to_owned()));
    }

    /// The kind of Item.
    pub fn item_type(&self) -> ItemType {
        ItemType::from_tag(
            self.type_data()
                .get("type")
                .and_then(Value::as_str)
                .expect("validated on construction"),
        )
    }

    /// Reads one field: `username`, `password`, `totp`, `uri`, `notes`, an SSH key part, or a
    /// custom field by name. Built-in names win over custom fields of the same name.
    pub fn field(&self, name: &str) -> Option<String> {
        if name == "notes" {
            return self
                .0
                .get("notes")
                .and_then(Value::as_str)
                .map(str::to_owned);
        }
        if let Some(key) = self.builtin_key(name) {
            return self
                .type_data()
                .get(key)
                .and_then(Value::as_str)
                .map(str::to_owned);
        }
        if name == "uri" && self.item_type() == ItemType::Login {
            return self
                .type_data()
                .get("uris")
                .and_then(Value::as_array)
                .and_then(|uris| uris.first())
                .and_then(|uri| uri.get("uri"))
                .and_then(Value::as_str)
                .map(str::to_owned);
        }
        self.custom_fields()
            .iter()
            .find(|field| field.get("name").and_then(Value::as_str) == Some(name))
            .and_then(|field| match field.get("value") {
                Some(Value::String(value)) => Some(value.clone()),
                Some(Value::Bool(value)) => Some(value.to_string()),
                _ => None,
            })
    }

    /// Whether a field holds a secret: built-in secrets and hidden custom fields.
    pub fn is_hidden(&self, name: &str) -> bool {
        match name {
            "password" | "totp" | "private_key" => true,
            "username" | "uri" | "notes" | "public_key" | "fingerprint" => false,
            _ => self
                .custom_fields()
                .iter()
                .find(|field| field.get("name").and_then(Value::as_str) == Some(name))
                .and_then(|field| field.get("type"))
                .and_then(Value::as_u64)
                .is_none_or(|kind| kind == FIELD_HIDDEN),
        }
    }

    /// Writes one field. Unknown names become hidden custom fields.
    pub fn set_field(&mut self, name: &str, value: &str) {
        if name == "notes" {
            self.0
                .insert("notes".to_owned(), Value::String(value.to_owned()));
            return;
        }
        if let Some(key) = self.builtin_key(name) {
            self.type_data_mut()
                .insert(key.to_owned(), Value::String(value.to_owned()));
            return;
        }
        if name == "uri" && self.item_type() == ItemType::Login {
            let data = self.type_data_mut();
            let uris = data
                .entry("uris")
                .or_insert_with(|| Value::Array(Vec::new()));
            if !uris.is_array() {
                *uris = Value::Array(Vec::new());
            }
            let uris = uris.as_array_mut().expect("just made an array");
            match uris.first_mut().and_then(Value::as_object_mut) {
                Some(first) => {
                    first.insert("uri".to_owned(), Value::String(value.to_owned()));
                }
                None => uris.insert(0, json!({ "uri": value, "match": null })),
            }
            return;
        }
        let fields = self
            .0
            .entry("fields")
            .or_insert_with(|| Value::Array(Vec::new()));
        if !fields.is_array() {
            *fields = Value::Array(Vec::new());
        }
        let fields = fields.as_array_mut().expect("just made an array");
        if let Some(field) = fields
            .iter_mut()
            .find(|field| field.get("name").and_then(Value::as_str) == Some(name))
            .and_then(Value::as_object_mut)
        {
            let boolean = field.get("type").and_then(Value::as_u64) == Some(FIELD_BOOLEAN);
            let value = match (boolean, value) {
                (true, "true") => Value::Bool(true),
                (true, "false") => Value::Bool(false),
                _ => Value::String(value.to_owned()),
            };
            field.insert("value".to_owned(), value);
            return;
        }
        fields.push(json!({
            "name": name,
            "value": value,
            "type": FIELD_HIDDEN,
            "linkedId": null,
        }));
    }

    /// Names of the fields that hold a value, built-in first, in record order.
    pub fn field_names(&self) -> Vec<String> {
        let mut names = Vec::new();
        let builtins: &[(&str, &str)] = match self.item_type() {
            ItemType::Login => &LOGIN_FIELDS,
            ItemType::SshKey => &SSH_FIELDS,
            _ => &[],
        };
        for (name, _) in builtins {
            if self.field(name).is_some() {
                names.push((*name).to_owned());
            }
        }
        if self.field("uri").is_some() {
            names.push("uri".to_owned());
        }
        if self.field("notes").is_some() {
            names.push("notes".to_owned());
        }
        for field in self.custom_fields() {
            let kind = field.get("type").and_then(Value::as_u64);
            if let Some(name) = field.get("name").and_then(Value::as_str)
                && matches!(kind, Some(FIELD_TEXT | FIELD_HIDDEN | FIELD_BOOLEAN))
                && !names.iter().any(|known| known == name)
            {
                names.push(name.to_owned());
            }
        }
        names
    }

    fn builtin_key(&self, name: &str) -> Option<&'static str> {
        let table: &[(&str, &'static str)] = match self.item_type() {
            ItemType::Login => &LOGIN_FIELDS,
            ItemType::SshKey => &SSH_FIELDS,
            _ => return None,
        };
        table
            .iter()
            .find(|(field, _)| *field == name)
            .map(|(_, key)| *key)
    }

    fn type_data(&self) -> &Map<String, Value> {
        self.0
            .get("typeData")
            .and_then(Value::as_object)
            .expect("validated on construction")
    }

    fn type_data_mut(&mut self) -> &mut Map<String, Value> {
        self.0
            .get_mut("typeData")
            .and_then(Value::as_object_mut)
            .expect("validated on construction")
    }

    fn custom_fields(&self) -> &[Value] {
        self.0
            .get("fields")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or_default()
    }
}

/// An Item as stored: what `veild` and Bitwarden clients see.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedItem {
    /// The Item key wrapped by the Vault key.
    pub key: String,
    /// The sealed record container.
    pub data: String,
}

/// Seals an Item. Pass the stored `key` of an existing Item to keep its Item key; every write
/// draws a fresh content key either way.
pub fn seal_item(
    vault_key: &Key,
    item: &Item,
    item_key: Option<&str>,
) -> Result<SealedItem, Error> {
    let item_key = match item_key {
        Some(wrapped) => crate::unwrap_key(vault_key, wrapped)?,
        None => Key::generate(),
    };
    let key = crate::wrap_key(vault_key, &item_key)?;
    with_context(|ctx| {
        let slot = ctx.add_local_symmetric_key(item_key.sdk().clone());
        let record = Record::from(RecordV1(item.to_json()));
        let (envelope, wrapped_cek) =
            DataEnvelope::seal_with_wrapping_key(record, &slot, ctx).map_err(|_| Error::Crypto)?;
        let data = json!({
            "format_version": FORMAT_VERSION,
            "wrapped_cek": wrapped_cek.to_string(),
            "envelope": String::from(envelope),
        });
        Ok(SealedItem {
            key,
            data: data.to_string(),
        })
    })
}

/// Opens a stored Item with its Vault key.
pub fn open_item(vault_key: &Key, sealed: &SealedItem) -> Result<Item, Error> {
    let container: Value = serde_json::from_str(&sealed.data).map_err(|_| Error::Encoding)?;
    if container.get("format_version").and_then(Value::as_u64) != Some(FORMAT_VERSION) {
        return Err(Error::Item);
    }
    let text = |name: &str| {
        container
            .get(name)
            .and_then(Value::as_str)
            .ok_or(Error::Encoding)
    };
    let envelope: DataEnvelope = text("envelope")?.parse().map_err(|_| Error::Encoding)?;
    let wrapped_cek: EncString = text("wrapped_cek")?.parse().map_err(|_| Error::Encoding)?;
    let item_key: EncString = sealed.key.parse().map_err(|_| Error::Encoding)?;
    let record = with_context(|ctx| {
        let vault = ctx.add_local_symmetric_key(vault_key.sdk().clone());
        let item = ctx
            .unwrap_symmetric_key(vault, &item_key)
            .map_err(|_| Error::Decryption)?;
        let Record::RecordV1(RecordV1(record)) = envelope
            .unseal_with_wrapping_key(&item, &wrapped_cek, ctx)
            .map_err(|_| Error::Decryption)?;
        Ok(record)
    })?;
    Item::from_json(record)
}

/// Re-wraps an Item key for a rotated Vault key. The sealed record does not change.
pub fn rewrap_item_key(
    old_vault_key: &Key,
    new_vault_key: &Key,
    key: &str,
) -> Result<String, Error> {
    let item_key = crate::unwrap_key(old_vault_key, key)?;
    crate::wrap_key(new_vault_key, &item_key)
}

/// Seals a short text, such as a Vault or folder name, as an SDK `EncString`.
pub fn seal_text(key: &Key, text: &str) -> Result<String, Error> {
    use bitwarden_crypto::KeyEncryptable;
    text.encrypt_with_key(key.sdk())
        .map(|sealed| sealed.to_string())
        .map_err(|_| Error::Crypto)
}

/// Opens a text sealed with [`seal_text`] or by a Bitwarden client.
pub fn open_text(key: &Key, sealed: &str) -> Result<String, Error> {
    use bitwarden_crypto::KeyDecryptable;
    let sealed: EncString = sealed.parse().map_err(|_| Error::Encoding)?;
    sealed
        .decrypt_with_key(key.sdk())
        .map_err(|_| Error::Decryption)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn token() -> Item {
        let mut item = Item::login("demo-service");
        item.set_field("password", "demo-123:ABC");
        item
    }

    #[test]
    fn an_item_round_trips_and_keeps_its_key() {
        let vault = Key::generate();
        let sealed = seal_item(&vault, &token(), None).expect("seal");
        assert_eq!(open_item(&vault, &sealed).expect("open"), token());

        let mut changed = token();
        changed.set_field("password", "rotated");
        let resealed = seal_item(&vault, &changed, Some(&sealed.key)).expect("reseal");
        assert_eq!(
            crate::unwrap_key(&vault, &resealed.key).expect("new"),
            crate::unwrap_key(&vault, &sealed.key).expect("old"),
            "the Item key survives a write"
        );
        assert_ne!(
            resealed.data, sealed.data,
            "every write draws a content key"
        );
        assert_eq!(
            open_item(&vault, &resealed)
                .expect("open")
                .field("password")
                .as_deref(),
            Some("rotated")
        );
    }

    #[test]
    fn another_vault_key_cannot_open_an_item() {
        let sealed = seal_item(&Key::generate(), &token(), None).expect("seal");
        assert_eq!(open_item(&Key::generate(), &sealed), Err(Error::Decryption));
    }

    #[test]
    fn rotation_rewraps_without_touching_the_record() {
        let (old, new) = (Key::generate(), Key::generate());
        let sealed = seal_item(&old, &token(), None).expect("seal");
        let rotated = SealedItem {
            key: rewrap_item_key(&old, &new, &sealed.key).expect("rewrap"),
            data: sealed.data.clone(),
        };
        assert_eq!(open_item(&new, &rotated).expect("open"), token());
    }

    #[test]
    fn fields_resolve_by_name() {
        let mut item = Item::login("example_app");
        item.set_field("username", "admin");
        item.set_field("uri", "https://app.example.com");
        item.set_field("client_secret", "s3cret");
        assert_eq!(item.field("username").as_deref(), Some("admin"));
        assert_eq!(
            item.field("uri").as_deref(),
            Some("https://app.example.com")
        );
        assert_eq!(item.field("client_secret").as_deref(), Some("s3cret"));
        assert_eq!(item.field("password"), None);
        assert_eq!(item.field_names(), vec!["username", "uri", "client_secret"]);
        assert!(item.is_hidden("client_secret"));
        assert!(!item.is_hidden("username"));
    }

    #[test]
    fn unknown_record_fields_survive_a_write() {
        let mut record = token().to_json();
        record["typeData"]["httpAuthenticationEnabled"] = json!(true);
        record["passwordHistory"] =
            json!([{ "password": "old", "lastUsedDate": "2026-01-01T00:00:00Z" }]);
        let mut item = Item::from_json(record.clone()).expect("valid");
        item.set_field("password", "new");
        let written = item.to_json();
        assert_eq!(
            written["typeData"]["httpAuthenticationEnabled"],
            json!(true)
        );
        assert_eq!(written["passwordHistory"], record["passwordHistory"]);
    }

    #[test]
    fn records_without_a_name_or_type_are_refused() {
        assert_eq!(
            Item::from_json(json!({ "typeData": { "type": "login" } })),
            Err(Error::Item)
        );
        assert_eq!(
            Item::from_json(json!({ "name": "x", "typeData": {} })),
            Err(Error::Item)
        );
        assert_eq!(Item::from_json(json!([])), Err(Error::Item));
    }

    #[test]
    fn texts_round_trip() {
        let key = Key::generate();
        let sealed = seal_text(&key, "example").expect("seal");
        assert_eq!(open_text(&key, &sealed).expect("open"), "example");
        assert_eq!(open_text(&Key::generate(), &sealed), Err(Error::Decryption));
    }
}
