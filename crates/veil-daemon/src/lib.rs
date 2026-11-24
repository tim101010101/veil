//! `veild`: the self-hosted HTTP service.
//!
//! Responsibilities kept deliberately narrow at skeleton stage: configuration resolution,
//! structured logging, the HTTP surface, and the error envelope. Storage, authentication,
//! and ciphertext handling are added per feature, behind this boundary.
//!
//! The server never decrypts. Plaintext key material lives in `veil-core` on the client.

pub mod api;
pub mod app;
pub mod auth;
pub mod bitwarden;
pub mod config;
pub mod error;
pub mod oidc;
pub mod store;
pub mod telemetry;
pub mod throttle;
pub mod totp;
