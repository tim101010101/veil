//! The HTTP client for `veild`.

use std::time::Duration;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::Value;
use uuid::Uuid;
use veil_core::DeviceKeys;
use veil_proto::{
    ApproveDeviceRequest, AuditEvent, AuditEventBatch, AuditEventInput,
    BeginDeviceEnrollmentRequest, CreateAccountRequest, CreateAccountResponse,
    CreateRecoveryRequest, CreateRecoveryResponse, CreateSessionRequest, CreateSessionResponse,
    CreateVaultRequest, CreateWorkloadRequest, Device, EnrollmentResponse, Item, Kdf,
    PendingDevice, PreloginRequest, PreloginResponse, PutItemRequest, RequestToSign,
    RotateVaultRequest, SyncDocument, UpdateAccountRequest, Vault, Workload, WorkloadToken,
    body_hash, enrollment_input, signing_input,
};

use crate::state::State;

/// A failed call.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The service answered with an error status.
    #[error("{message}")]
    Status {
        /// HTTP status.
        code: u16,
        /// Title and detail from the problem document.
        message: String,
    },
    /// The service could not be reached.
    #[error("cannot reach the service: {0}")]
    Transport(String),
    /// Anything else.
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl Error {
    /// True when a cached copy may stand in: unreachable or a server error, never a refusal.
    pub fn is_offline(&self) -> bool {
        match self {
            Self::Transport(_) => true,
            Self::Status { code, .. } => *code >= 500,
            Self::Other(_) => false,
        }
    }

    /// True for a revision conflict.
    pub fn is_conflict(&self) -> bool {
        matches!(self, Self::Status { code: 409, .. })
    }
}

/// Talks to one `veild`.
#[derive(Debug, Clone)]
pub struct Client {
    base: String,
}

impl Client {
    /// A client for the service at `base`.
    pub fn new(base: &str) -> Self {
        Self {
            base: base.trim_end_matches('/').to_owned(),
        }
    }

    /// The KDF parameters for an address.
    pub fn prelogin(&self, email: &str) -> Result<Kdf, Error> {
        let response: PreloginResponse = self.post(
            "/api/v1/prelogin",
            None,
            &PreloginRequest {
                email: email.to_owned(),
            },
        )?;
        Ok(response.kdf)
    }

    /// Creates the account and its first device.
    pub fn create_account(
        &self,
        request: &CreateAccountRequest,
    ) -> Result<CreateAccountResponse, Error> {
        self.post("/api/v1/accounts", None, request)
    }

    /// Starts an owner session.
    pub fn login(&self, request: &CreateSessionRequest) -> Result<CreateSessionResponse, Error> {
        self.post("/api/v1/sessions", None, request)
    }

    /// Authenticates this device, registering a personal device if its identity is new.
    pub fn login_device(
        &self,
        state: &State,
        auth_hash: &str,
        promote: bool,
    ) -> Result<CreateSessionResponse, Error> {
        let keys = state.device_keys().map_err(Error::Other)?;
        let mut proof = veil_proto::DeviceLogin {
            keys: veil_proto::DeviceKeys {
                id: state.device_id,
                name: crate::commands::login::hostname(),
                seal_pk: keys.sealing().public(),
                auth_pk: keys.auth_public(),
            },
            promote,
            timestamp: crate::now(),
            nonce: Uuid::now_v7().to_string(),
            signature: String::new(),
        };
        proof.signature = keys.sign(&veil_proto::session_input(&state.email, auth_hash, &proof));
        self.login(&CreateSessionRequest {
            email: state.email.clone(),
            auth_hash: auth_hash.to_owned(),
            device: Some(proof),
        })
    }

    /// Proves possession of the recovery code.
    pub fn recover(
        &self,
        request: &CreateRecoveryRequest,
    ) -> Result<CreateRecoveryResponse, Error> {
        self.post("/api/v1/recoveries", None, request)
    }

    /// Replaces the master password.
    pub fn update_account(
        &self,
        bearer: &str,
        request: &UpdateAccountRequest,
    ) -> Result<(), Error> {
        self.send(
            "PUT",
            "/api/v1/accounts/current",
            Some(bearer),
            Some(json(request)?),
            &[],
        )
        .map(|_| ())
    }

    /// Creates a Vault.
    pub fn create_vault(&self, bearer: &str, request: &CreateVaultRequest) -> Result<Vault, Error> {
        self.post("/api/v1/vaults", Some(bearer), request)
    }

    /// Renames a Vault or changes its policy.
    pub fn update_vault(
        &self,
        bearer: &str,
        vault_id: Uuid,
        request: &veil_proto::UpdateVaultRequest,
    ) -> Result<Vault, Error> {
        self.send(
            "PUT",
            &format!("/api/v1/vaults/{vault_id}"),
            Some(bearer),
            Some(json(request)?),
            &[],
        )
        .and_then(decode)
    }

    /// Creates or replaces one Item.
    pub fn put_item(
        &self,
        bearer: &str,
        vault_id: Uuid,
        item_id: Uuid,
        request: &PutItemRequest,
    ) -> Result<Item, Error> {
        self.send(
            "PUT",
            &format!("/api/v1/vaults/{vault_id}/items/{item_id}"),
            Some(bearer),
            Some(json(request)?),
            &[],
        )
        .and_then(decode)
    }

    /// Moves a Vault to a new key.
    pub fn rotate_vault(
        &self,
        bearer: &str,
        vault_id: Uuid,
        request: &RotateVaultRequest,
    ) -> Result<Vault, Error> {
        self.send(
            "POST",
            &format!("/api/v1/vaults/{vault_id}/rotate"),
            Some(bearer),
            Some(json(request)?),
            &[],
        )
        .and_then(decode)
    }

    /// Lets Bitwarden clients see one Vault.
    pub fn enable_bitwarden(
        &self,
        bearer: &str,
        request: &veil_proto::EnableBitwardenRequest,
    ) -> Result<veil_proto::BitwardenStatus, Error> {
        self.send(
            "PUT",
            "/api/v1/bitwarden",
            Some(bearer),
            Some(json(request)?),
            &[],
        )
        .and_then(decode)
    }

    /// Which Vault Bitwarden clients see, if any.
    pub fn bitwarden(&self, bearer: &str) -> Result<Option<veil_proto::BitwardenStatus>, Error> {
        match self.send("GET", "/api/v1/bitwarden", Some(bearer), None, &[]) {
            Ok(value) => decode(value).map(Some),
            Err(Error::Status { code: 404, .. }) => Ok(None),
            Err(error) => Err(error),
        }
    }

    /// Stops serving Bitwarden clients.
    pub fn disable_bitwarden(&self, bearer: &str) -> Result<(), Error> {
        self.send("DELETE", "/api/v1/bitwarden", Some(bearer), None, &[])
            .map(|_| ())
    }

    /// Turns on two-step login for Bitwarden clients.
    pub fn enable_two_step(
        &self,
        bearer: &str,
        request: &veil_proto::EnableTwoStepRequest,
    ) -> Result<(), Error> {
        self.send(
            "PUT",
            "/api/v1/bitwarden/two-step",
            Some(bearer),
            Some(json(request)?),
            &[],
        )
        .map(|_| ())
    }

    /// Turns two-step login for Bitwarden clients off.
    pub fn disable_two_step(&self, bearer: &str) -> Result<(), Error> {
        self.send(
            "DELETE",
            "/api/v1/bitwarden/two-step",
            Some(bearer),
            None,
            &[],
        )
        .map(|_| ())
    }

    /// Exchanges an OIDC token for a workload token.
    pub fn workload_token(&self, workload: Uuid, oidc_token: &str) -> Result<WorkloadToken, Error> {
        self.post(
            &format!("/api/v1/workloads/{workload}/token"),
            None,
            &serde_json::json!({ "oidc_token": oidc_token }),
        )
    }

    /// Reports deliveries with this device's signature.
    pub fn report_events_signed(
        &self,
        state: &State,
        events: &[AuditEventInput],
    ) -> Result<(), Error> {
        let bytes = serde_json::to_vec(&AuditEventBatch {
            events: events.to_vec(),
        })
        .map_err(anyhow::Error::from)?;
        let headers = sign(state, "POST", "/api/v1/audit/events", &bytes)?;
        self.send_bytes("/api/v1/audit/events", None, &bytes, &headers)
            .map(|_| ())
    }

    /// Reports deliveries with a workload token.
    pub fn report_events_bearer(
        &self,
        bearer: &str,
        events: &[AuditEventInput],
    ) -> Result<(), Error> {
        let value = json(&AuditEventBatch {
            events: events.to_vec(),
        })?;
        self.send(
            "POST",
            "/api/v1/audit/events",
            Some(bearer),
            Some(value),
            &[],
        )
        .map(|_| ())
    }

    /// Recent deliveries, newest first, optionally for one Vault or Item.
    pub fn audit(
        &self,
        bearer: &str,
        limit: usize,
        vault_id: Option<Uuid>,
        item_id: Option<Uuid>,
    ) -> Result<Vec<AuditEvent>, Error> {
        let mut path = format!("/api/v1/audit/events?limit={limit}");
        if let Some(vault_id) = vault_id {
            path.push_str(&format!("&vault_id={vault_id}"));
        }
        if let Some(item_id) = item_id {
            path.push_str(&format!("&item_id={item_id}"));
        }
        self.send("GET", &path, Some(bearer), None, &[])
            .and_then(decode)
    }

    /// Creates a workload.
    pub fn create_workload(
        &self,
        bearer: &str,
        request: &CreateWorkloadRequest,
    ) -> Result<Workload, Error> {
        self.post("/api/v1/workloads", Some(bearer), request)
    }

    /// Lists workloads.
    pub fn workloads(&self, bearer: &str) -> Result<Vec<Workload>, Error> {
        self.send("GET", "/api/v1/workloads", Some(bearer), None, &[])
            .and_then(decode)
    }

    /// Revokes a workload.
    pub fn revoke_workload(&self, bearer: &str, id: Uuid) -> Result<(), Error> {
        self.send(
            "DELETE",
            &format!("/api/v1/workloads/{id}"),
            Some(bearer),
            None,
            &[],
        )
        .map(|_| ())
    }

    /// Syncs with a bearer token: an Owner session or a workload token.
    pub fn sync_bearer(&self, bearer: &str) -> Result<SyncDocument, Error> {
        self.send("GET", "/api/v1/sync", Some(bearer), None, &[])
            .and_then(decode)
    }

    /// Syncs with this device's signature.
    pub fn sync(&self, state: &State) -> Result<SyncDocument, Error> {
        let headers = sign(state, "GET", "/api/v1/sync", b"")?;
        self.send("GET", "/api/v1/sync", None, None, &headers)
            .and_then(decode)
    }

    /// Starts enrolling this machine.
    pub fn begin_device(&self, request: &BeginDeviceEnrollmentRequest) -> Result<(), Error> {
        self.send("POST", "/api/v1/devices", None, Some(json(request)?), &[])
            .map(|_| ())
    }

    /// Machines waiting for approval.
    pub fn pending_devices(&self, bearer: &str) -> Result<Vec<PendingDevice>, Error> {
        self.send("GET", "/api/v1/devices/pending", Some(bearer), None, &[])
            .and_then(decode)
    }

    /// Every machine in the account.
    pub fn devices(&self, bearer: &str) -> Result<Vec<Device>, Error> {
        self.send("GET", "/api/v1/devices", Some(bearer), None, &[])
            .and_then(decode)
    }

    /// Approves a pending machine.
    pub fn approve_device(
        &self,
        bearer: &str,
        code: &str,
        request: &ApproveDeviceRequest,
    ) -> Result<Device, Error> {
        self.send(
            "POST",
            &format!("/api/v1/devices/{code}/approve"),
            Some(bearer),
            Some(json(request)?),
            &[],
        )
        .and_then(decode)
    }

    /// Revokes a machine.
    pub fn revoke_device(&self, bearer: &str, device_id: Uuid) -> Result<(), Error> {
        self.send(
            "DELETE",
            &format!("/api/v1/devices/{device_id}"),
            Some(bearer),
            None,
            &[],
        )
        .map(|_| ())
    }

    /// Polls for the Grants an approved machine receives.
    pub fn enrollment(
        &self,
        keys: &DeviceKeys,
        device_id: Uuid,
        code: &str,
    ) -> Result<EnrollmentResponse, Error> {
        let timestamp = crate::now();
        let nonce = URL_SAFE_NO_PAD.encode(Uuid::now_v7().as_bytes());
        let signature = keys.sign(&enrollment_input(device_id, code, timestamp));
        let path = format!(
            "/api/v1/devices/enrollment?device_id={device_id}&code={code}&timestamp={timestamp}&nonce={nonce}&signature={signature}"
        );
        self.send("GET", &path, None, None, &[]).and_then(decode)
    }

    fn send_bytes(
        &self,
        path: &str,
        bearer: Option<&str>,
        body: &[u8],
        headers: &[(&str, String)],
    ) -> Result<Value, Error> {
        let url = format!("{}{path}", self.base);
        let mut request = ureq::request("POST", &url)
            .timeout(Duration::from_secs(15))
            .set("Content-Type", "application/json")
            .set("X-Veil-Protocol", &veil_proto::PROTOCOL_VERSION.to_string());
        if let Some(token) = bearer {
            request = request.set("Authorization", &format!("Bearer {token}"));
        }
        for (name, value) in headers {
            request = request.set(name, value);
        }
        let (code, text) = match request.send_bytes(body) {
            Ok(response) => (response.status(), read(response)),
            Err(ureq::Error::Status(code, response)) => (code, read(response)),
            Err(error) => return Err(Error::Transport(error.to_string())),
        };
        let value: Value = if text.trim().is_empty() {
            Value::Null
        } else {
            serde_json::from_str(&text).unwrap_or(Value::Null)
        };
        if (200..300).contains(&code) {
            Ok(value)
        } else {
            Err(Error::Status {
                code,
                message: problem(&value, code),
            })
        }
    }

    fn post<T: Serialize, R: DeserializeOwned>(
        &self,
        path: &str,
        bearer: Option<&str>,
        body: &T,
    ) -> Result<R, Error> {
        let value = serde_json::to_value(body).map_err(anyhow::Error::from)?;
        self.send("POST", path, bearer, Some(value), &[])
            .and_then(decode)
    }

    fn send(
        &self,
        method: &str,
        path: &str,
        bearer: Option<&str>,
        body: Option<Value>,
        headers: &[(&str, String)],
    ) -> Result<Value, Error> {
        let url = format!("{}{path}", self.base);
        let mut request = ureq::request(method, &url)
            .timeout(Duration::from_secs(15))
            .set("X-Veil-Protocol", &veil_proto::PROTOCOL_VERSION.to_string());
        if let Some(token) = bearer {
            request = request.set("Authorization", &format!("Bearer {token}"));
        }
        for (name, value) in headers {
            request = request.set(name, value);
        }
        let response = match body {
            Some(value) => request
                .set("Content-Type", "application/json")
                .send_json(value),
            None => request.call(),
        };
        let (code, text) = match response {
            Ok(response) => (response.status(), read(response)),
            Err(ureq::Error::Status(code, response)) => (code, read(response)),
            Err(error) => return Err(Error::Transport(error.to_string())),
        };
        let value: Value = if text.trim().is_empty() {
            Value::Null
        } else {
            serde_json::from_str(&text).unwrap_or(Value::Null)
        };
        if (200..300).contains(&code) {
            Ok(value)
        } else {
            Err(Error::Status {
                code,
                message: problem(&value, code),
            })
        }
    }
}

fn read(response: ureq::Response) -> String {
    response.into_string().unwrap_or_default()
}

fn problem(value: &Value, code: u16) -> String {
    let title = value["title"].as_str();
    let detail = value["detail"].as_str();
    match (title, detail) {
        (Some(title), Some(detail)) => format!("{title}: {detail}"),
        (Some(title), None) => title.to_owned(),
        _ => format!("the service answered {code}"),
    }
}

fn decode<R: DeserializeOwned>(value: Value) -> Result<R, Error> {
    serde_json::from_value(value).map_err(|error| Error::Other(error.into()))
}

fn json<T: Serialize>(body: &T) -> Result<Value, Error> {
    serde_json::to_value(body).map_err(|error| Error::Other(error.into()))
}

/// The headers of a request signed by this device.
fn sign(
    state: &State,
    method: &str,
    path: &str,
    body: &[u8],
) -> Result<Vec<(&'static str, String)>, Error> {
    let timestamp = crate::now();
    let nonce = URL_SAFE_NO_PAD.encode(Uuid::now_v7().as_bytes());
    let digest = body_hash(body);
    let account = state.account_id.to_string();
    let input = signing_input(&RequestToSign {
        account_id: &account,
        method,
        path,
        body_hash: &digest,
        timestamp,
        nonce: nonce.as_bytes(),
    });
    let signature = state.device_keys().map_err(Error::Other)?.sign(&input);
    Ok(vec![
        ("x-veil-device", state.device_id.to_string()),
        ("x-veil-timestamp", timestamp.to_string()),
        ("x-veil-nonce", nonce),
        ("x-veil-signature", signature),
    ])
}
