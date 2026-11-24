//! Configuration resolution.
//!
//! Precedence, highest first: command-line arguments, `VEIL_*` environment variables, the
//! TOML configuration file, built-in defaults. Every layer is optional, so an empty
//! environment starts a working server on the loopback interface.

use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    str::FromStr,
};

use serde::Deserialize;

use crate::throttle::Network;
use thiserror::Error;

/// Listen address used when no layer supplies one.
pub const DEFAULT_BIND: &str = "127.0.0.1:8080";

/// Log filter used when no layer supplies one.
pub const DEFAULT_LOG: &str = "info";

/// Database file used when no layer supplies one.
pub const DEFAULT_DB: &str = "veil.db";

const ENV_BIND: &str = "VEIL_BIND";
const ENV_LOG: &str = "VEIL_LOG";
const ENV_DB: &str = "VEIL_DB";
const ENV_TRUSTED_PROXIES: &str = "VEIL_TRUSTED_PROXIES";

/// Effective configuration for a server instance.
#[derive(Debug, Clone)]
pub struct Config {
    /// Address the HTTP listener binds to.
    pub bind: SocketAddr,
    /// Filter passed to the tracing subscriber.
    pub log: String,
    /// Configuration file that contributed values, if any.
    pub source_file: Option<PathBuf>,
    /// Path to the embedded database.
    pub db: PathBuf,
    /// Address ranges of the proxies in front of the service. `X-Forwarded-For` counts only
    /// from them; empty ignores the header, which a client can forge.
    pub trusted_proxies: Vec<Network>,
}

/// Values supplied by command-line arguments.
#[derive(Debug, Default, Clone)]
pub struct Overrides {
    /// `--config`: path to a TOML configuration file.
    pub config_file: Option<PathBuf>,
    /// `--bind`: listen address.
    pub bind: Option<String>,
    /// `--log`: tracing filter.
    pub log: Option<String>,
    /// `--db`: database path.
    pub db: Option<PathBuf>,
}

/// Why a configuration could not be resolved.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// The configuration file could not be read.
    #[error("cannot read config file {path}: {source}")]
    Io {
        /// Path that failed.
        path: PathBuf,
        /// Underlying I/O error.
        source: std::io::Error,
    },
    /// The configuration file is not valid TOML for the expected schema.
    #[error("cannot parse config file {path}: {source}")]
    Parse {
        /// Path that failed.
        path: PathBuf,
        /// Underlying TOML error.
        source: toml::de::Error,
    },
    /// A value was supplied but cannot be interpreted.
    #[error("invalid value for {field}: {detail}")]
    Invalid {
        /// Configuration field name, as written by the operator.
        field: &'static str,
        /// Why the value was rejected.
        detail: String,
    },
}

/// Configuration file schema. Unknown keys are rejected so typos fail loudly.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct FileConfig {
    bind: Option<String>,
    log: Option<String>,
    db: Option<String>,
    trusted_proxies: Option<Vec<String>>,
}

impl FileConfig {
    fn load(path: &Path) -> Result<Self, ConfigError> {
        let raw = std::fs::read_to_string(path).map_err(|source| ConfigError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        toml::from_str(&raw).map_err(|source| ConfigError::Parse {
            path: path.to_path_buf(),
            source,
        })
    }
}

impl Config {
    /// Resolves the effective configuration from all layers.
    pub fn resolve(overrides: &Overrides) -> Result<Self, ConfigError> {
        let file = match &overrides.config_file {
            Some(path) => FileConfig::load(path)?,
            None => FileConfig::default(),
        };

        let bind_raw = overrides
            .bind
            .clone()
            .or_else(|| env(ENV_BIND))
            .or(file.bind)
            .unwrap_or_else(|| DEFAULT_BIND.to_owned());
        let bind = SocketAddr::from_str(&bind_raw).map_err(|err| ConfigError::Invalid {
            field: "bind",
            detail: format!("{bind_raw:?}: {err}"),
        })?;

        let log = overrides
            .log
            .clone()
            .or_else(|| env(ENV_LOG))
            .or(file.log)
            .unwrap_or_else(|| DEFAULT_LOG.to_owned());
        // Validate eagerly so a bad filter fails at startup, not on the first log record.
        if let Err(err) = tracing_subscriber::EnvFilter::try_new(&log) {
            return Err(ConfigError::Invalid {
                field: "log",
                detail: format!("{log:?}: {err}"),
            });
        }

        let db = overrides
            .db
            .clone()
            .or_else(|| env(ENV_DB).map(PathBuf::from))
            .or_else(|| file.db.map(PathBuf::from))
            .unwrap_or_else(|| PathBuf::from(DEFAULT_DB));

        let ranges: Vec<String> = match env(ENV_TRUSTED_PROXIES) {
            Some(raw) => raw.split(',').map(str::to_owned).collect(),
            None => file.trusted_proxies.unwrap_or_default(),
        };
        let trusted_proxies = ranges
            .iter()
            .filter(|range| !range.trim().is_empty())
            .map(|range| range.parse())
            .collect::<Result<Vec<Network>, String>>()
            .map_err(|detail| ConfigError::Invalid {
                field: "trusted-proxies",
                detail,
            })?;

        Ok(Self {
            bind,
            log,
            source_file: overrides.config_file.clone(),
            db,
            trusted_proxies,
        })
    }
}

/// Reads an environment variable, treating blank values as unset.
fn env(name: &str) -> Option<String> {
    match std::env::var(name) {
        Ok(value) if !value.trim().is_empty() => Some(value),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn overrides() -> Overrides {
        Overrides {
            config_file: None,
            bind: None,
            log: None,
            db: None,
        }
    }

    #[test]
    fn defaults_apply_without_layers() {
        let config = Config::resolve(&overrides()).expect("defaults are valid");
        assert_eq!(
            config.bind,
            DEFAULT_BIND.parse().expect("default bind parses")
        );
        assert_eq!(config.log, DEFAULT_LOG);
        assert_eq!(config.db, PathBuf::from(DEFAULT_DB));
        assert!(config.source_file.is_none());
    }

    #[test]
    fn arguments_win_over_file_values() {
        let dir = tempdir();
        let path = dir.join("veil.toml");
        std::fs::write(
            &path,
            "bind = \"127.0.0.1:9001\"\nlog = \"debug\"\ndb = \"/tmp/veil-test.db\"\n",
        )
        .expect("write file");

        let config = Config::resolve(&Overrides {
            config_file: Some(path),
            bind: Some("127.0.0.1:9999".to_owned()),
            log: None,
            db: None,
        })
        .expect("config resolves");

        assert_eq!(config.bind.port(), 9999);
        // File value survives where the argument layer is absent.
        assert_eq!(config.log, "debug");
        assert_eq!(config.db, PathBuf::from("/tmp/veil-test.db"));
    }

    #[test]
    fn invalid_bind_is_reported_with_field_name() {
        let err = Config::resolve(&Overrides {
            bind: Some("not-an-address".to_owned()),
            ..overrides()
        })
        .expect_err("invalid bind must fail");

        assert!(err.to_string().contains("bind"), "{err}");
    }

    #[test]
    fn unknown_file_keys_are_rejected() {
        let dir = tempdir();
        let path = dir.join("veil.toml");
        std::fs::write(&path, "bnd = \"127.0.0.1:8080\"\n").expect("write file");

        let err = Config::resolve(&Overrides {
            config_file: Some(path),
            ..overrides()
        })
        .expect_err("typo must fail");

        assert!(matches!(err, ConfigError::Parse { .. }), "{err}");
    }

    /// Minimal temporary directory, removed on drop. Avoids a `tempfile` dependency for
    /// four tests.
    struct TempDir(PathBuf);

    impl TempDir {
        fn join(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn tempdir() -> TempDir {
        let base = std::env::temp_dir().join(format!(
            "veil-config-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&base).expect("create temp dir");
        TempDir(base)
    }
}
