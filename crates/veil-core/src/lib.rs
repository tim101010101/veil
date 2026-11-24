//! Account, Vault, and Item cryptography for `veil`, on the official Bitwarden SDK.
//!
//! # Trust boundary
//!
//! This crate is the only place in Veil that holds plaintext key material, and it owns no
//! cipher code: every key derivation, wrap, and seal is a call into `bitwarden-crypto` or
//! `bitwarden-core`. It performs no I/O, so the CLI can use it without a server.
//! `veild` must never link it; `cargo deny` enforces that (`crates/veil-daemon/deny.toml`).
//!
//! # Key hierarchy
//!
//! ```text
//! master password ──SDK MasterKey──┬─→ authentication hash
//!                                  └─→ wraps the account key (the SDK's v2 user key)
//! recovery code ──same derivation──→ a second wrap of the account key
//! account key ──→ wraps the v2 account key state, and every Vault key (Owner access)
//! Vault key ──→ shared to a Device or Workload sealing key (RSA-OAEP, a Grant)
//!   └ Item key (one per Item) ──→ content key (one per write) ──→ DataEnvelope
//! ```
//!
//! Additions here are security-relevant and need explicit review.
//!

mod account;
mod bitwarden;
mod device;
mod error;
mod item;
mod key;
mod master;
mod recovery;
mod reference;

pub use account::{NewAccount, verify_account_keys};
pub use bitwarden::{BitwardenKeys, bitwarden_keys};
pub use device::{DeviceKeys, SealingKey, share_key};
pub use error::Error;
pub use item::{
    Item, ItemType, SealedItem, open_item, open_text, rewrap_item_key, seal_item, seal_text,
};
pub use key::{Key, unwrap_key, wrap_key};
pub use master::{Kdf, MasterPassword, normalize_email};
pub use recovery::RecoveryCode;
pub use reference::Reference;
