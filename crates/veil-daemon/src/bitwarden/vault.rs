//! Config, sync, profile, ciphers, and folders: stored fields mapped to Bitwarden shapes.
//!
//! A cipher is an Item of the bound Vault. Only whole sealed records are stored: `type`, `key`,
//! `data`, `favorite`, `folderId`, and the trash date. Writes go through the store's Item write
//! path, so the Veil change feed sees them exactly as Owner writes.

use std::collections::HashMap;

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use bitwarden_api_api::models as api;
use serde_json::{Value, json};
use uuid::Uuid;

use super::{BitwardenLogin, BwError, BwJson, format_ms, identity, parse_ms};
use crate::{
    app::AppState,
    store::{BitwardenAccount, Folder, ItemRecord, ItemState, StoreError, now_ms},
};

/// The version the clients compare against their minimum server version.
const SERVER_VERSION: &str = "2026.10.0";

/// What the clients see when the client copy of a cipher is older than the stored one.
const OUT_OF_DATE: &str =
    "The client copy of this cipher is out of date. Sync the client and try again.";

/// What a field-encrypted (v1) cipher is told.
const NOT_SEALED: &str = "This server stores only whole sealed ciphers: key and data are required. \
    Update the client and try again.";

/// `{ids}` of a bulk trash or restore.
#[derive(Debug, serde::Deserialize)]
pub struct BulkIds {
    #[serde(alias = "Ids")]
    ids: Vec<String>,
}

// ----- account -----

/// `GET /api/config`: no authentication; names this server, not Bitwarden.
pub async fn config() -> Json<api::ConfigResponseModel> {
    Json(api::ConfigResponseModel {
        object: Some("config".into()),
        version: Some(SERVER_VERSION.into()),
        git_hash: crate::app::COMMIT.map(Into::into),
        server: Some(Box::new(api::ServerConfigResponseModel {
            name: Some("Veil".into()),
            url: None,
        })),
        environment: Some(Box::new(api::EnvironmentConfigResponseModel {
            cloud_region: Some("self-hosted".into()),
            vault: Some(String::new()),
            api: Some(String::new()),
            identity: Some(String::new()),
            notifications: Some(String::new()),
            sso: Some(String::new()),
            ..Default::default()
        })),
        feature_states: Some(HashMap::new()),
        ..Default::default()
    })
}

fn profile_model(account: &BitwardenAccount) -> api::ProfileResponseModel {
    api::ProfileResponseModel {
        object: Some("profile".into()),
        id: Some(account.id),
        name: Some(account.email.clone()),
        email: Some(account.email.clone()),
        email_verified: Some(true),
        premium: Some(true),
        premium_from_organization: Some(false),
        culture: Some("en-US".into()),
        two_factor_enabled: Some(false),
        key: Some(account.binding.protected_key.clone()),
        private_key: Some(account.binding.private_key.clone()),
        security_stamp: Some(account.binding.security_stamp.clone()),
        force_password_reset: Some(false),
        uses_key_connector: Some(false),
        creation_date: Some(format_ms(account.created_at * 1000)),
        verify_devices: Some(false),
        organizations: Some(vec![]),
        providers: Some(vec![]),
        provider_organizations: Some(vec![]),
        ..Default::default()
    }
}

/// The profile with `accountKeys` as the raw object the Owner's client stored.
fn profile_value(account: &BitwardenAccount) -> Result<Value, BwError> {
    let mut profile = to_value(profile_model(account))?;
    profile["accountKeys"] = identity::account_keys(account);
    Ok(profile)
}

fn to_value(model: impl serde::Serialize) -> Result<Value, BwError> {
    serde_json::to_value(model).map_err(|error| {
        tracing::error!(error = %error, "response could not be serialized");
        BwError::new(StatusCode::INTERNAL_SERVER_ERROR, "Response unavailable.")
    })
}

/// `GET /api/sync`: the profile, the bound Vault's folders, and every Item in it.
pub async fn sync(
    State(state): State<AppState>,
    login: BitwardenLogin,
) -> Result<Json<Value>, BwError> {
    let account = state.store.bitwarden_account(login.account_id)?;
    let folders = state.store.bitwarden_folders(login.account_id)?;
    let items = state.store.bitwarden_items(login.account_id)?;
    let body = api::SyncResponseModel {
        object: Some("sync".into()),
        folders: Some(folders.iter().map(folder).collect()),
        collections: Some(vec![]),
        ciphers: Some(items.iter().map(cipher).collect()),
        policies: Some(vec![]),
        sends: Some(vec![]),
        ..Default::default()
    };
    let mut body = to_value(body)?;
    body["profile"] = profile_value(&account)?;
    body["domains"] = Value::Null;
    body["userDecryption"] = json!({
        "masterPasswordUnlock": identity::master_password_unlock(&account),
        "userKeyId": account.binding.user_key_id,
    });
    Ok(Json(body))
}

/// `GET /api/accounts/profile`.
pub async fn profile(
    State(state): State<AppState>,
    login: BitwardenLogin,
) -> Result<Json<Value>, BwError> {
    let account = state.store.bitwarden_account(login.account_id)?;
    Ok(Json(profile_value(&account)?))
}

/// `GET /api/accounts/revision-date`: milliseconds of the last change the clients would see.
pub async fn revision_date(
    State(state): State<AppState>,
    login: BitwardenLogin,
) -> Result<Json<u64>, BwError> {
    Ok(Json(state.store.bitwarden_revision_ms(login.account_id)?))
}

/// `POST /api/accounts/key-management/user-key-id`: the clients name the user key once.
pub async fn set_user_key_id(
    State(state): State<AppState>,
    login: BitwardenLogin,
    BwJson(body): BwJson<api::SetUserKeyIdRequestModel>,
) -> Result<StatusCode, BwError> {
    state
        .store
        .set_user_key_id(login.account_id, &body.user_key_id, now_ms())?;
    Ok(StatusCode::OK)
}

/// `GET /api/devices/knowndevice`: every device is known, so no new-device email is expected.
pub async fn known_device() -> Json<bool> {
    Json(true)
}

// ----- ciphers -----

fn cipher(record: &ItemRecord) -> api::CipherDetailsResponseModel {
    let item = &record.item;
    api::CipherDetailsResponseModel {
        object: Some("cipherDetails".into()),
        id: Some(item.id),
        r#type: Some(api::CipherType::from_i64(i64::from(item.item_type))),
        key: Some(item.key.clone()),
        data: Some(item.data.clone()),
        favorite: Some(item.favorite),
        folder_id: item.folder_id,
        reprompt: Some(api::CipherRepromptType::None),
        edit: Some(true),
        view_password: Some(true),
        organization_use_totp: Some(false),
        permissions: Some(Box::new(api::CipherPermissionsResponseModel {
            delete: Some(true),
            restore: Some(true),
        })),
        collection_ids: Some(vec![]),
        revision_date: Some(format_ms(record.revised_ms)),
        creation_date: Some(format_ms(record.created_ms)),
        deleted_date: record.deleted_ms.map(format_ms),
        ..Default::default()
    }
}

fn list(data: Vec<Value>) -> Json<Value> {
    Json(json!({ "data": data, "object": "list", "continuationToken": null }))
}

/// Clients post either a bare cipher or `{cipher, collectionIds}`.
#[derive(serde::Deserialize)]
#[serde(untagged)]
pub enum CipherBody {
    /// `{cipher, collectionIds}`.
    Wrapped(api::CipherCreateRequestModel),
    /// A bare cipher.
    Bare(Box<api::CipherRequestModel>),
}

impl CipherBody {
    fn into_cipher(self) -> api::CipherRequestModel {
        match self {
            Self::Wrapped(wrapped) => *wrapped.cipher,
            Self::Bare(cipher) => *cipher,
        }
    }
}

/// A folder id as the clients send it: absent, empty, or a UUID.
fn folder_id(value: Option<&str>) -> Result<Option<Uuid>, BwError> {
    match value.map(str::trim) {
        None | Some("") => Ok(None),
        Some(text) => text
            .parse()
            .map(Some)
            .map_err(|_| BwError::bad_request("folderId is not a valid id.")),
    }
}

/// The stored fields of a cipher write. A cipher without `key` and `data` is field-encrypted
/// (v1), which this server does not store.
fn sealed(cipher: &api::CipherRequestModel, deleted_ms: Option<u64>) -> Result<ItemState, BwError> {
    let (Some(key), Some(data)) = (&cipher.key, &cipher.data) else {
        return Err(BwError::bad_request(NOT_SEALED));
    };
    if key.is_empty() || data.is_empty() {
        return Err(BwError::bad_request(NOT_SEALED));
    }
    let item_type = cipher
        .r#type
        .and_then(|kind| u8::try_from(kind.as_i64()).ok())
        .filter(|kind| *kind > 0)
        .ok_or_else(|| BwError::bad_request("type is required."))?;
    Ok(ItemState {
        item_type,
        key: key.clone(),
        data: data.clone(),
        favorite: cipher.favorite.unwrap_or(false),
        folder_id: folder_id(cipher.folder_id.as_deref())?,
        deleted_ms,
    })
}

fn state_of(record: &ItemRecord) -> ItemState {
    ItemState {
        item_type: record.item.item_type,
        key: record.item.key.clone(),
        data: record.item.data.clone(),
        favorite: record.item.favorite,
        folder_id: record.item.folder_id,
        deleted_ms: record.deleted_ms,
    }
}

/// `POST /api/ciphers` and `/api/ciphers/create`.
pub async fn create_cipher(
    State(state): State<AppState>,
    login: BitwardenLogin,
    BwJson(body): BwJson<CipherBody>,
) -> Result<Json<api::CipherDetailsResponseModel>, BwError> {
    let item = sealed(&body.into_cipher(), None)?;
    let record = state
        .store
        .bitwarden_create_item(login.account_id, &item, now_ms())?;
    Ok(Json(cipher(&record)))
}

/// The most one import may carry, as the official server limits it.
const IMPORT_MAX_CIPHERS: usize = 7000;
const IMPORT_MAX_FOLDERS: usize = 2000;

/// `POST /api/ciphers/import`: Items sealed by the client, with folders and which Item goes in
/// which folder (by index). The clients use it for file imports (`bw import`) and for the
/// Credential Exchange import on iOS. Every Item is checked before any is written, and the
/// write is one transaction: an import lands whole or not at all.
pub async fn import_ciphers(
    State(state): State<AppState>,
    login: BitwardenLogin,
    BwJson(body): BwJson<api::ImportCiphersRequestModel>,
) -> Result<StatusCode, BwError> {
    let ciphers = body.ciphers.unwrap_or_default();
    let folders = body.folders.unwrap_or_default();
    let relationships = body.folder_relationships.unwrap_or_default();
    if ciphers.is_empty() {
        return Err(BwError::bad_request("There are no ciphers to import."));
    }
    if ciphers.len() > IMPORT_MAX_CIPHERS
        || folders.len() > IMPORT_MAX_FOLDERS
        || relationships.len() > IMPORT_MAX_CIPHERS
    {
        return Err(BwError::bad_request(
            "You cannot import this much data at once.",
        ));
    }
    let mut folder_of = vec![None; ciphers.len()];
    for relationship in &relationships {
        let (Some(cipher), Some(folder)) = (relationship.key, relationship.value) else {
            return Err(BwError::bad_request("A folder relationship is incomplete."));
        };
        let (Ok(cipher), Ok(folder)) = (usize::try_from(cipher), usize::try_from(folder)) else {
            return Err(BwError::bad_request(
                "A folder relationship is out of range.",
            ));
        };
        if cipher >= ciphers.len() || folder >= folders.len() {
            return Err(BwError::bad_request(
                "A folder relationship is out of range.",
            ));
        }
        folder_of[cipher] = Some(folder);
    }
    let items = ciphers
        .iter()
        .zip(folder_of)
        .map(|(cipher, folder)| sealed(cipher, None).map(|item| (item, folder)))
        .collect::<Result<Vec<_>, _>>()?;
    let folders: Vec<(Option<Uuid>, String)> = folders
        .into_iter()
        .map(|folder| (folder.id, folder.name))
        .collect();
    let imported = state
        .store
        .bitwarden_import(login.account_id, &folders, &items, now_ms())?;
    tracing::info!(
        event = "bitwarden-import",
        items = imported,
        folders = folders.len(),
        "Bitwarden import stored"
    );
    Ok(StatusCode::OK)
}

/// `GET /api/ciphers/{id}`.
pub async fn get_cipher(
    State(state): State<AppState>,
    login: BitwardenLogin,
    Path(id): Path<Uuid>,
) -> Result<Json<api::CipherDetailsResponseModel>, BwError> {
    let record = state.store.bitwarden_item(login.account_id, id)?;
    Ok(Json(cipher(&record)))
}

/// `PUT`/`POST /api/ciphers/{id}`: a whole new sealed record, refused when the client's copy
/// is older than the stored one.
pub async fn update_cipher(
    State(state): State<AppState>,
    login: BitwardenLogin,
    Path(id): Path<Uuid>,
    BwJson(body): BwJson<CipherBody>,
) -> Result<Json<api::CipherDetailsResponseModel>, BwError> {
    let request = body.into_cipher();
    let last_known = match request.last_known_revision_date.as_deref() {
        None => None,
        Some(text) => Some(parse_ms(text).ok_or_else(|| BwError::bad_request(OUT_OF_DATE))?),
    };
    let item = sealed(&request, None)?;
    let record = state
        .store
        .bitwarden_update_item(login.account_id, id, now_ms(), |current| {
            if last_known.is_some_and(|known| known != current.revised_ms) {
                return Err(StoreError::Invalid(OUT_OF_DATE));
            }
            Ok(ItemState {
                deleted_ms: current.deleted_ms,
                ..item
            })
        })?;
    Ok(Json(cipher(&record)))
}

/// `PUT /api/ciphers/{id}/partial`: folder and favorite only.
pub async fn partial_cipher(
    State(state): State<AppState>,
    login: BitwardenLogin,
    Path(id): Path<Uuid>,
    BwJson(body): BwJson<api::CipherPartialRequestModel>,
) -> Result<Json<api::CipherDetailsResponseModel>, BwError> {
    let folder = folder_id(body.folder_id.as_deref())?;
    let favorite = body.favorite.unwrap_or(false);
    let record = state
        .store
        .bitwarden_update_item(login.account_id, id, now_ms(), |current| {
            Ok(ItemState {
                folder_id: folder,
                favorite,
                ..state_of(current)
            })
        })?;
    Ok(Json(cipher(&record)))
}

/// `PUT /api/ciphers/{id}/delete`: move to the trash.
pub async fn trash_cipher(
    State(state): State<AppState>,
    login: BitwardenLogin,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, BwError> {
    let at = now_ms();
    state
        .store
        .bitwarden_update_item(login.account_id, id, at, |current| {
            Ok(ItemState {
                deleted_ms: Some(at),
                ..state_of(current)
            })
        })?;
    Ok(StatusCode::OK)
}

/// `PUT /api/ciphers/{id}/restore`: take out of the trash.
pub async fn restore_cipher(
    State(state): State<AppState>,
    login: BitwardenLogin,
    Path(id): Path<Uuid>,
) -> Result<Json<api::CipherDetailsResponseModel>, BwError> {
    let record = state
        .store
        .bitwarden_update_item(login.account_id, id, now_ms(), |current| {
            Ok(ItemState {
                deleted_ms: None,
                ..state_of(current)
            })
        })?;
    Ok(Json(cipher(&record)))
}

/// `DELETE /api/ciphers/{id}` and `POST /api/ciphers/{id}/delete`: remove for good.
pub async fn delete_cipher(
    State(state): State<AppState>,
    login: BitwardenLogin,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, BwError> {
    state
        .store
        .bitwarden_delete_item(login.account_id, id, now_ms())?;
    Ok(StatusCode::OK)
}

fn bulk_ids(body: &BulkIds) -> Vec<Uuid> {
    body.ids.iter().filter_map(|id| id.parse().ok()).collect()
}

/// `PUT /api/ciphers/delete`: move several to the trash.
pub async fn trash_ciphers(
    State(state): State<AppState>,
    login: BitwardenLogin,
    BwJson(body): BwJson<BulkIds>,
) -> Result<StatusCode, BwError> {
    let at = now_ms();
    state
        .store
        .bitwarden_update_items(login.account_id, &bulk_ids(&body), at, |current| {
            ItemState {
                deleted_ms: Some(at),
                ..state_of(current)
            }
        })?;
    Ok(StatusCode::OK)
}

/// `PUT /api/ciphers/restore`: take several out of the trash.
pub async fn restore_ciphers(
    State(state): State<AppState>,
    login: BitwardenLogin,
    BwJson(body): BwJson<BulkIds>,
) -> Result<Json<Value>, BwError> {
    let records = state.store.bitwarden_update_items(
        login.account_id,
        &bulk_ids(&body),
        now_ms(),
        |current| ItemState {
            deleted_ms: None,
            ..state_of(current)
        },
    )?;
    let data = records
        .iter()
        .map(|record| to_value(cipher(record)))
        .collect::<Result<_, _>>()?;
    Ok(list(data))
}

// ----- folders -----

fn folder(folder: &Folder) -> api::FolderResponseModel {
    api::FolderResponseModel {
        object: Some("folder".into()),
        id: Some(folder.id),
        name: Some(folder.name.clone()),
        revision_date: Some(format_ms(folder.revised_ms)),
    }
}

/// `GET /api/folders`.
pub async fn folders(
    State(state): State<AppState>,
    login: BitwardenLogin,
) -> Result<Json<Value>, BwError> {
    let data = state
        .store
        .bitwarden_folders(login.account_id)?
        .iter()
        .map(|found| to_value(folder(found)))
        .collect::<Result<_, _>>()?;
    Ok(list(data))
}

/// `POST /api/folders`. The name is sealed.
pub async fn create_folder(
    State(state): State<AppState>,
    login: BitwardenLogin,
    BwJson(body): BwJson<api::FolderRequestModel>,
) -> Result<Json<api::FolderResponseModel>, BwError> {
    let created = state
        .store
        .bitwarden_create_folder(login.account_id, &body.name, now_ms())?;
    Ok(Json(folder(&created)))
}

/// `PUT /api/folders/{id}`.
pub async fn rename_folder(
    State(state): State<AppState>,
    login: BitwardenLogin,
    Path(id): Path<Uuid>,
    BwJson(body): BwJson<api::FolderRequestModel>,
) -> Result<Json<api::FolderResponseModel>, BwError> {
    let renamed =
        state
            .store
            .bitwarden_rename_folder(login.account_id, id, &body.name, now_ms())?;
    Ok(Json(folder(&renamed)))
}

/// `DELETE /api/folders/{id}`: its Items stay, filed in no folder.
pub async fn delete_folder(
    State(state): State<AppState>,
    login: BitwardenLogin,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, BwError> {
    state
        .store
        .bitwarden_delete_folder(login.account_id, id, now_ms())?;
    Ok(StatusCode::OK)
}
