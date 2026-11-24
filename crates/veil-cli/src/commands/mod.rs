//! Subcommands. One module per command family; each exposes `run(...)`.

pub mod audit;
pub mod bitwarden;
pub mod config;
pub mod device;
pub mod doctor;
pub mod export;
pub mod get;
pub mod init;
pub mod inject;
pub mod list;
pub mod login;
pub mod mcp;
pub mod recover;
pub mod run;
pub mod set;
pub mod upgrade;
pub mod vault;
pub mod version;
pub mod workload;
