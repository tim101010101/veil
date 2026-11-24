//! Opening a sync document: Vault keys, names, Items, and reference resolution.
//!
//! A Vault opens through the account key (the Owner) or through a Grant (a Device or a
//! Workload). A Vault the reader cannot open is invisible, name included, because its name is
//! sealed by its own key: a reference into it fails exactly like a reference to a Vault that
//! does not exist.

use std::collections::BTreeMap;

use anyhow::{Context, Result, bail};
use uuid::Uuid;
use veil_core::{Item, Key, Reference, SealedItem, SealingKey};
use veil_proto::{
    AuditEventInput, CreateVaultRequest, DeliveryResult, Destination, GrantWrite, ItemKeyWrite,
    PutItemRequest, RotateVaultRequest, SyncDocument, Vault,
};

use crate::{
    approval::{self, Policy},
    client::Client,
    state::State,
};

/// Who is opening the document: the account key, a Grant holder, or both.
pub struct Reader {
    account_key: Option<Key>,
    principal: Option<(Uuid, SealingKey)>,
}

impl Reader {
    /// The reader this machine's state allows.
    pub fn from_state(state: &State) -> Result<Self> {
        Ok(Self {
            account_key: state.account_key()?,
            principal: Some((state.device_id, state.device_keys()?.sealing().clone())),
        })
    }

    /// A Workload: Grants only.
    pub fn workload(id: Uuid, sealing: SealingKey) -> Self {
        Self {
            account_key: None,
            principal: Some((id, sealing)),
        }
    }

    /// The account key, for writes.
    pub fn account_key(&self) -> Result<&Key> {
        self.account_key
            .as_ref()
            .context("this device holds Grants only; sign in with `veil login` to write")
    }

    fn vault_key(&self, document: &SyncDocument, row: &Vault) -> Result<Option<Key>> {
        if let (Some(account_key), Some(wrap)) = (&self.account_key, &row.account_key_wrap) {
            return veil_core::unwrap_key(account_key, wrap)
                .map(Some)
                .with_context(|| format!("cannot open the key of Vault {}", row.id));
        }
        let Some((id, sealing)) = &self.principal else {
            return Ok(None);
        };
        let Some(grant) = document.grants.iter().find(|grant| {
            grant.vault_id == row.id
                && grant.principal_id == *id
                && grant.key_generation == row.key_generation
        }) else {
            return Ok(None);
        };
        sealing
            .open_shared_key(&grant.wrapped_key)
            .map(Some)
            .with_context(|| format!("cannot open the Grant for Vault {}", row.id))
    }
}

/// A Vault this reader can open.
pub struct OpenVault {
    /// The stored row.
    pub row: Vault,
    /// Its plaintext name.
    pub name: String,
    /// Its key.
    pub key: Key,
    /// Its approval policy.
    pub policy: Policy,
}

/// An Item in an open Vault.
pub struct OpenItem {
    /// Item id.
    pub id: Uuid,
    /// Owning Vault.
    pub vault_id: Uuid,
    /// The stored row.
    pub row: veil_proto::Item,
    /// The plaintext record.
    pub item: Item,
}

/// One resolved reference.
#[derive(Debug, Clone)]
pub struct Resolved {
    /// The Vault's name, for prompts.
    pub vault_name: String,
    /// The Vault's approval policy.
    pub policy: Policy,
    /// Whether the field is hidden (a secret) rather than text.
    pub hidden: bool,
    /// The value; readable only through [`Resolved::value`] once [`release`] let it out.
    value: String,
    /// Vault it came from.
    pub vault_id: Uuid,
    /// Item it came from.
    pub item_id: Uuid,
}

impl Resolved {
    /// The value, for a delivery that passed the gate.
    pub fn value(&self, _released: &Released) -> &str {
        &self.value
    }

    /// The audit event for delivering this value.
    fn event(&self, destination: Destination) -> AuditEventInput {
        AuditEventInput {
            vault_id: self.vault_id,
            item_id: self.item_id,
            destination,
            result: DeliveryResult::Ok,
        }
    }
}

/// Proof that values passed the delivery gate. Only [`release`] makes one, and a [`Resolved`]
/// value cannot be read without it.
pub struct Released(());

/// The one gate every delivered value passes: the approval its Vaults require, then
/// the audit record, in that order. `audit` sends the record; it fails rather than drop it, so
/// nothing leaves unaudited.
pub fn release(
    values: &[&Resolved],
    destination: Destination,
    command: &str,
    audit: impl FnOnce(Vec<AuditEventInput>) -> Result<()>,
) -> Result<Released> {
    approval::require(values, command)?;
    audit(
        values
            .iter()
            .map(|value| value.event(destination))
            .collect(),
    )?;
    Ok(Released(()))
}

/// A template with its references resolved, rendered only once released.
pub struct Template {
    /// The literal text around each placeholder: one more piece than there are values.
    pieces: Vec<String>,
    /// The values, in placeholder order.
    pub used: Vec<Resolved>,
}

impl Template {
    /// The rendered text.
    pub fn render(&self, released: &Released) -> String {
        let mut out = String::new();
        for (piece, value) in self.pieces.iter().zip(&self.used) {
            out.push_str(piece);
            out.push_str(value.value(released));
        }
        out.push_str(self.pieces.last().map_or("", String::as_str));
        out
    }
}

/// Everything a reader can open in one document.
pub struct View {
    vaults: Vec<OpenVault>,
    items: Vec<OpenItem>,
}

impl View {
    /// Opens every Vault and live Item the reader can. A record that fails to open is an error:
    /// it means tampering or a format this client does not understand.
    pub fn open(document: &SyncDocument, reader: &Reader) -> Result<Self> {
        let mut vaults = Vec::new();
        for row in &document.vaults {
            let Some(key) = reader.vault_key(document, row)? else {
                continue;
            };
            let name = veil_core::open_text(&key, &row.name)
                .with_context(|| format!("cannot open the name of Vault {}", row.id))?;
            let policy = match &row.policy {
                Some(sealed) => Policy::parse(
                    &veil_core::open_text(&key, sealed)
                        .with_context(|| format!("cannot open the policy of Vault {name}"))?,
                )?,
                None => Policy::None,
            };
            vaults.push(OpenVault {
                row: row.clone(),
                name,
                key,
                policy,
            });
        }

        let mut items = Vec::new();
        for row in document.items.iter().filter(|row| row.deleted_at.is_none()) {
            let Some(vault) = vaults.iter().find(|vault| vault.row.id == row.vault_id) else {
                continue;
            };
            let item = veil_core::open_item(
                &vault.key,
                &SealedItem {
                    key: row.key.clone(),
                    data: row.data.clone(),
                },
            )
            .with_context(|| format!("cannot open Item {} in Vault {}", row.id, vault.name))?;
            items.push(OpenItem {
                id: row.id,
                vault_id: row.vault_id,
                row: row.clone(),
                item,
            });
        }
        vaults.sort_by(|left, right| left.name.cmp(&right.name));
        items.sort_by(|left, right| left.item.name().cmp(right.item.name()));
        Ok(Self { vaults, items })
    }

    /// Every open Vault, by name.
    pub fn vaults(&self) -> &[OpenVault] {
        &self.vaults
    }

    /// The Vault with this name.
    pub fn vault(&self, name: &str) -> Result<&OpenVault> {
        let mut matches = self.vaults.iter().filter(|vault| vault.name == name);
        let vault = matches
            .next()
            .with_context(|| format!("no Vault named {name:?} that this machine can open"))?;
        if matches.next().is_some() {
            bail!("two Vaults are named {name:?}; rename one");
        }
        Ok(vault)
    }

    /// The live Items of one Vault, by name.
    pub fn items_in(&self, vault_id: Uuid) -> impl Iterator<Item = &OpenItem> {
        self.items
            .iter()
            .filter(move |item| item.vault_id == vault_id)
    }

    /// The Item with this name in this Vault, if there is one.
    pub fn find_item(&self, vault: &OpenVault, name: &str) -> Result<Option<&OpenItem>> {
        let mut matches = self
            .items_in(vault.row.id)
            .filter(|item| item.item.name() == name);
        let first = matches.next();
        if first.is_some() && matches.next().is_some() {
            bail!("two Items are named {name:?} in {}; rename one", vault.name);
        }
        Ok(first)
    }

    /// Resolves one reference.
    pub fn resolve(&self, reference: &Reference) -> Result<Resolved> {
        let vault = self.vault(&reference.vault)?;
        let item = self
            .find_item(vault, &reference.item)?
            .with_context(|| format!("no Item {:?} in Vault {}", reference.item, vault.name))?;
        let value = item.item.field(&reference.field).with_context(|| {
            format!(
                "Item {} in {} has no field {:?}",
                reference.item, vault.name, reference.field
            )
        })?;
        Ok(Resolved {
            vault_name: vault.name.clone(),
            policy: vault.policy,
            hidden: item.item.is_hidden(&reference.field),
            value,
            vault_id: vault.row.id,
            item_id: item.id,
        })
    }

    /// Resolves every reference of a `veil.toml`, by variable name.
    pub fn resolve_all(
        &self,
        references: &BTreeMap<String, Reference>,
    ) -> Result<BTreeMap<String, Resolved>> {
        references
            .iter()
            .map(|(name, reference)| {
                self.resolve(reference)
                    .with_context(|| format!("cannot resolve {name} = {reference}"))
                    .map(|resolved| (name.clone(), resolved))
            })
            .collect()
    }

    /// Resolves every `{{ veil://… }}` in a template.
    pub fn template(&self, template: &str) -> Result<Template> {
        let mut pieces = Vec::new();
        let mut used = Vec::new();
        let mut rest = template;
        while let Some(start) = rest.find("{{") {
            pieces.push(rest[..start].to_owned());
            let after = &rest[start + 2..];
            let end = after
                .find("}}")
                .context("unterminated {{ in the template")?;
            let inner = after[..end].trim();
            let reference: Reference = inner
                .parse()
                .with_context(|| format!("{inner:?} is not a reference"))?;
            used.push(self.resolve(&reference)?);
            rest = &after[end + 2..];
        }
        pieces.push(rest.to_owned());
        Ok(Template { pieces, used })
    }
}

/// Fetches the current document for this machine, falling back to a fresh cache when the
/// service is unreachable. Refusals (`401`, `403`, `410`) are never served from cache, and a
/// document older than the last one seen is refused.
pub fn fetch(state: &mut State, client: &Client) -> Result<SyncDocument> {
    let fetched = client.sync(state);
    match fetched {
        Ok(document) => {
            accept_revision(state, &document)?;
            state.cache = Some(crate::state::Cache {
                at: crate::now(),
                document: document.clone(),
                device_scoped: true,
            });
            state.save()?;
            Ok(document)
        }
        Err(error) if error.is_offline() => {
            let cached = state
                .fresh_cache()
                .cloned()
                .context("the service is unreachable and the cached copy is too old")?;
            crate::ui::notice(
                "warning",
                "Service unreachable; using the cached copy within the device-scoped offline window.",
            );
            Ok(cached)
        }
        Err(error) => Err(error.into()),
    }
}

fn accept_revision(state: &mut State, document: &SyncDocument) -> Result<()> {
    let watermark = state
        .sync_revision
        .max(state.cache.as_ref().map(|cache| cache.document.revision));
    if let Some(watermark) = watermark
        && document.revision < watermark
    {
        bail!(
            "the service returned an older state (revision {} after {}); refusing it",
            document.revision,
            watermark
        );
    }
    state.sync_revision = Some(document.revision);
    Ok(())
}

/// A machine's state, its client, and what it can open right now.
pub struct Opened {
    /// Local state.
    pub state: State,
    /// The service.
    pub client: Client,
    /// The document the view was opened from.
    pub document: SyncDocument,
    /// Who opened it.
    pub reader: Reader,
    /// What it opened.
    pub view: View,
    management: bool,
}

impl Opened {
    /// Loads the state, syncs, and opens the document.
    pub fn load() -> Result<Self> {
        let mut state = State::require()?;
        let client = Client::new(&state.server);
        let document = fetch(&mut state, &client)?;
        let reader = Reader::from_state(&state)?;
        let view = View::open(&document, &reader)?;
        Ok(Self {
            state,
            client,
            document,
            reader,
            view,
            management: false,
        })
    }

    /// Opens an uncached account-wide view for management, never for secret delivery.
    pub fn load_owner() -> Result<Self> {
        Self::owner_view(true)
    }

    pub fn preview_owner() -> Result<Self> {
        Self::owner_view(false)
    }

    fn owner_view(save_revision: bool) -> Result<Self> {
        let mut state = State::require()?;
        let client = Client::new(&state.server);
        let document = client
            .sync_bearer(&state.require_session()?)
            .map_err(anyhow::Error::from)?;
        accept_revision(&mut state, &document)?;
        if save_revision {
            state.save()?;
        }
        let reader = Reader::from_state(&state)?;
        let view = View::open(&document, &reader)?;
        Ok(Self {
            state,
            client,
            document,
            reader,
            view,
            management: true,
        })
    }

    /// Syncs again after a write.
    pub fn refresh(&mut self) -> Result<()> {
        self.document = if self.management {
            let document = self
                .client
                .sync_bearer(&self.state.require_session()?)
                .map_err(anyhow::Error::from)?;
            accept_revision(&mut self.state, &document)?;
            self.state.save()?;
            document
        } else {
            fetch(&mut self.state, &self.client)?
        };
        self.view = View::open(&self.document, &self.reader)?;
        Ok(())
    }

    /// Passes `values` through the delivery gate, recording them with this machine's signature.
    pub fn release(
        &mut self,
        values: &[&Resolved],
        destination: Destination,
        command: &str,
    ) -> Result<Released> {
        anyhow::ensure!(!self.management, "management views cannot deliver secrets");
        release(values, destination, command, |events| self.report(events))
    }

    /// Records deliveries before they happen. Events that cannot be reported are kept and sent
    /// before the next delivery; a refusal is an error, so nothing is released unaudited.
    fn report(&mut self, events: Vec<AuditEventInput>) -> Result<()> {
        let mut pending = std::mem::take(&mut self.state.pending_audit);
        pending.extend(events);
        if pending.is_empty() {
            return Ok(());
        }
        match self.client.report_events_signed(&self.state, &pending) {
            Ok(()) => {}
            Err(error) if error.is_offline() => {
                crate::ui::notice("warning", "Audit buffered until the service is reachable.");
                self.state.pending_audit = pending;
            }
            Err(error) => return Err(error).context("the service refused the audit record"),
        }
        self.state.save()
    }
}

/// Owner writes against one Vault.
pub struct Writer {
    client: Client,
    bearer: String,
    account_key: Key,
    email: String,
}

impl Writer {
    /// A writer for this machine: needs a live Owner session and the account key.
    pub fn new(opened: &Opened) -> Result<Self> {
        Ok(Self {
            client: opened.client.clone(),
            bearer: opened.state.require_session()?,
            account_key: opened.reader.account_key()?.clone(),
            email: opened.state.email.clone(),
        })
    }

    /// Creates a Vault with its first Items. Returns its id.
    pub fn create_vault(&self, name: &str, items: &[Item]) -> Result<(Uuid, Key)> {
        let key = Key::generate();
        let id = Uuid::now_v7();
        let items = items
            .iter()
            .map(|item| {
                let sealed = veil_core::seal_item(&key, item, None)?;
                Ok(veil_proto::ItemWrite {
                    id: Uuid::now_v7(),
                    item_type: item_type(item)?,
                    key: sealed.key,
                    data: sealed.data,
                    favorite: false,
                    folder_id: None,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        self.client
            .create_vault(
                &self.bearer,
                &CreateVaultRequest {
                    id,
                    name: veil_core::seal_text(&key, name)?,
                    account_key_wrap: veil_core::wrap_key(&self.account_key, &key)?,
                    items,
                    grants: Vec::new(),
                },
            )
            .map_err(anyhow::Error::from)?;
        Ok((id, key))
    }

    /// Writes one Item: replaces `existing`, or creates a new Item.
    pub fn put_item(
        &self,
        vault: &OpenVault,
        existing: Option<&OpenItem>,
        item: &Item,
    ) -> Result<veil_proto::Item> {
        let sealed = veil_core::seal_item(
            &vault.key,
            item,
            existing.map(|existing| existing.row.key.as_str()),
        )?;
        let id = existing.map_or_else(Uuid::now_v7, |existing| existing.id);
        self.client
            .put_item(
                &self.bearer,
                vault.row.id,
                id,
                &PutItemRequest {
                    expected_revision: existing.map_or(0, |existing| existing.row.revision),
                    item_type: item_type(item)?,
                    key: sealed.key,
                    data: sealed.data,
                    favorite: existing.is_some_and(|existing| existing.row.favorite),
                    folder_id: existing.and_then(|existing| existing.row.folder_id),
                },
            )
            .map_err(|error| {
                if error.is_conflict() {
                    crate::diagnostic::Failure::new("revision_conflict", 5,
                        format!("{} changed on another machine.", item.name()),
                        "Inspect the current state before retrying; no conflicting value was overwritten.").into()
                } else {
                    error.into()
                }
            })
    }

    /// Rotates a Vault whose key a revoked principal held: a new key, re-wrapped Item keys, and
    /// fresh Grants for every principal that still holds one. Item data does not change.
    pub fn rotate(&self, document: &SyncDocument, vault: &OpenVault) -> Result<Key> {
        let new_key = Key::generate();
        let items = document
            .items
            .iter()
            .filter(|item| item.vault_id == vault.row.id)
            .map(|item| {
                Ok(ItemKeyWrite {
                    id: item.id,
                    key: veil_core::rewrap_item_key(&vault.key, &new_key, &item.key)?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        // The Vault Bitwarden clients see has their login keys wrapped by its key: renew them,
        // which needs the master password.
        let bitwarden = match self
            .client
            .bitwarden(&self.bearer)
            .map_err(anyhow::Error::from)?
        {
            Some(status) if status.vault_id == vault.row.id => {
                crate::ui::notice(
                    "input",
                    format!(
                        "{} is the Vault Bitwarden clients see; its new key needs the master password",
                        vault.name
                    ),
                );
                let (master, account_keys) = crate::commands::bitwarden::confirm_password(
                    &self.client,
                    &self.email,
                    &self.account_key,
                )?;
                Some(crate::commands::bitwarden::request(
                    &master,
                    &self.account_key,
                    &account_keys,
                    vault.row.id,
                    &new_key,
                )?)
            }
            _ => None,
        };
        let devices = self
            .client
            .devices(&self.bearer)
            .map_err(anyhow::Error::from)?;
        let workloads = self
            .client
            .workloads(&self.bearer)
            .map_err(anyhow::Error::from)?;
        let mut grants = Vec::new();
        for grant in document
            .grants
            .iter()
            .filter(|grant| grant.vault_id == vault.row.id)
        {
            let recipient = devices
                .iter()
                .filter(|device| device.revoked_at.is_none())
                .find(|device| device.id == grant.principal_id)
                .map(|device| device.seal_pk.as_str())
                .or_else(|| {
                    workloads
                        .iter()
                        .filter(|workload| workload.revoked_at.is_none())
                        .find(|workload| workload.id == grant.principal_id)
                        .map(|workload| workload.seal_pk.as_str())
                });
            let Some(recipient) = recipient else {
                continue;
            };
            grants.push(GrantWrite {
                vault_id: vault.row.id,
                principal_id: grant.principal_id,
                key_generation: vault.row.key_generation + 1,
                wrapped_key: veil_core::share_key(&new_key, recipient)?,
            });
        }
        self.client
            .rotate_vault(
                &self.bearer,
                vault.row.id,
                &RotateVaultRequest {
                    expected_revision: vault.row.revision,
                    expected_key_generation: vault.row.key_generation,
                    name: veil_core::seal_text(&new_key, &vault.name)?,
                    policy: match vault.policy {
                        Policy::None => None,
                        policy => Some(veil_core::seal_text(&new_key, policy.as_str())?),
                    },
                    items,
                    grants,
                    account_key_wrap: veil_core::wrap_key(&self.account_key, &new_key)?,
                    bitwarden,
                },
            )
            .map_err(anyhow::Error::from)?;
        Ok(new_key)
    }
}

/// Shares the keys of `vaults` with a principal's sealing key.
pub fn grants_for(
    vaults: &[&OpenVault],
    principal_id: Uuid,
    seal_pk: &str,
) -> Result<Vec<GrantWrite>> {
    vaults
        .iter()
        .map(|vault| {
            Ok(GrantWrite {
                vault_id: vault.row.id,
                principal_id,
                key_generation: vault.row.key_generation,
                wrapped_key: veil_core::share_key(&vault.key, seal_pk)?,
            })
        })
        .collect()
}

fn item_type(item: &Item) -> Result<u8> {
    item.item_type()
        .code()
        .with_context(|| format!("{} has an Item type this version cannot write", item.name()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn document(account_key: &Key) -> (SyncDocument, Uuid) {
        let vault_key = Key::generate();
        let vault_id = Uuid::now_v7();
        let mut token = Item::login("demo-service");
        token.set_field("password", "demo-123:ABC");
        let sealed = veil_core::seal_item(&vault_key, &token, None).expect("seal");
        let document = SyncDocument {
            revision: 1,
            full: true,
            vaults: vec![Vault {
                id: vault_id,
                name: veil_core::seal_text(&vault_key, "example").expect("name"),
                revision: 1,
                key_generation: 1,
                rotation_due: false,
                policy: None,
                account_key_wrap: Some(veil_core::wrap_key(account_key, &vault_key).expect("wrap")),
            }],
            items: vec![veil_proto::Item {
                id: Uuid::now_v7(),
                vault_id,
                item_type: 1,
                key: sealed.key,
                data: sealed.data,
                revision: 1,
                favorite: false,
                folder_id: None,
                deleted_at: None,
                revised_at: 1,
            }],
            grants: Vec::new(),
            deleted: Vec::new(),
            rotations: Vec::new(),
        };
        (document, vault_id)
    }

    fn owner(account_key: Key) -> Reader {
        Reader {
            account_key: Some(account_key),
            principal: None,
        }
    }

    #[test]
    fn management_and_device_views_share_a_persistent_rollback_watermark() {
        let mut state = State::new(
            "http://localhost",
            Uuid::now_v7(),
            "me@example.com",
            Uuid::now_v7(),
            &veil_core::DeviceKeys::generate(),
        );
        let (mut document, _) = document(&Key::generate());
        document.revision = 8;
        state.cache = Some(crate::state::Cache {
            at: crate::now(),
            document: document.clone(),
            device_scoped: false,
        });
        document.revision = 7;
        assert!(accept_revision(&mut state, &document).is_err());
        document.revision = 9;
        accept_revision(&mut state, &document).expect("advance");
        let mut restored: State =
            serde_json::from_str(&serde_json::to_string(&state).expect("serialize"))
                .expect("deserialize");
        document.revision = 8;
        assert!(accept_revision(&mut restored, &document).is_err());
        assert_eq!(restored.sync_revision, Some(9));
        document.revision = 9;
        accept_revision(&mut restored, &document).expect("same revision");
        assert_eq!(
            restored.cache.expect("cache").document.revision,
            8,
            "management observation does not replace the ordinary cache"
        );
    }

    #[test]
    fn references_resolve_and_templates_render() {
        let account_key = Key::generate();
        let (document, vault_id) = document(&account_key);
        let view = View::open(&document, &owner(account_key)).expect("open");
        let template = view
            .template("token={{ veil://example/demo-service/password }};")
            .expect("template");
        assert_eq!(template.used[0].vault_id, vault_id);
        let mut events = Vec::new();
        let released = release(
            &template.used.iter().collect::<Vec<_>>(),
            Destination::Render,
            "test",
            |sent| {
                events = sent;
                Ok(())
            },
        )
        .expect("release");
        assert_eq!(template.render(&released), "token=demo-123:ABC;");
        assert_eq!(events.len(), 1, "one audit record per value");
    }

    #[test]
    fn a_refused_approval_neither_audits_nor_releases() {
        let account_key = Key::generate();
        let (document, _) = document(&account_key);
        let view = View::open(&document, &owner(account_key)).expect("open");
        let mut resolved = view
            .resolve(&"veil://example/demo-service/password".parse().expect("ref"))
            .expect("resolve");
        // `device` refuses on every machine this version runs on, without prompting.
        resolved.policy = Policy::Device;
        let mut audited = false;
        let refused = release(&[&resolved], Destination::Print, "test", |_| {
            audited = true;
            Ok(())
        });
        assert!(refused.is_err());
        assert!(!audited, "a refused delivery must not be recorded as made");
    }

    #[test]
    fn a_vault_without_a_grant_is_invisible() {
        let (document, _) = document(&Key::generate());
        let reader = Reader::workload(Uuid::now_v7(), SealingKey::generate());
        let view = View::open(&document, &reader).expect("open");
        let error = view
            .resolve(&"veil://example/demo-service/password".parse().expect("ref"))
            .expect_err("no grant");
        assert!(error.to_string().contains("can open"), "{error}");
    }

    #[test]
    fn missing_items_and_fields_name_what_is_missing() {
        let account_key = Key::generate();
        let (document, _) = document(&account_key);
        let view = View::open(&document, &owner(account_key)).expect("open");
        let missing = view
            .resolve(&"veil://example/other/password".parse().expect("ref"))
            .expect_err("item");
        assert!(missing.to_string().contains("other"), "{missing}");
        let field = view
            .resolve(&"veil://example/demo-service/username".parse().expect("ref"))
            .expect_err("field");
        assert!(field.to_string().contains("username"), "{field}");
    }

    #[test]
    fn an_unterminated_placeholder_fails() {
        let account_key = Key::generate();
        let (document, _) = document(&account_key);
        let view = View::open(&document, &owner(account_key)).expect("open");
        assert!(
            view.template("{{ veil://example/demo-service/password")
                .is_err()
        );
    }
}
