//! `config.toml`: the one place for `veil`'s settings.
//!
//! The file lives beside the state, at `$VEIL_HOME/config.toml` (`~/.config/veil/config.toml`
//! by default), or wherever `VEIL_CONFIG` points. Precedence, highest first: command-line flags,
//! `VEIL_*` environment variables, this file, built-in defaults. A missing file means defaults;
//! an unreadable or unknown key fails every command, so a typo is never silently ignored. The
//! file holds settings only: never a password, a recovery code, or a key.

use std::{path::PathBuf, sync::OnceLock};

use anyhow::{Context, Result};
use serde::Deserialize;

/// Settings the file may hold. New settings are added here and nowhere else.
#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Settings {
    /// Service URL (`VEIL_SERVER`); login rejects conflicts with an existing device binding.
    pub server: Option<String>,
    /// Sign-in address (`VEIL_EMAIL`); login rejects conflicts with an existing device binding.
    pub email: Option<String>,
    /// Where the account key is kept: `keychain` (macOS) or `file` (`VEIL_KEYSTORE`).
    pub keystore: Option<String>,
    /// Command that reads a value on stdin for `veil get --copy` (`VEIL_CLIPBOARD_COMMAND`).
    pub clipboard_command: Option<String>,
    /// Tracing filter, for example `veil=debug` (`VEIL_LOG`).
    pub log: Option<String>,
}

/// One setting: its file key and environment variable.
#[derive(Debug, Clone, Copy)]
pub enum Key {
    /// `server` / `VEIL_SERVER`.
    Server,
    /// `email` / `VEIL_EMAIL`.
    Email,
    /// `keystore` / `VEIL_KEYSTORE`.
    Keystore,
    /// `clipboard-command` / `VEIL_CLIPBOARD_COMMAND`.
    ClipboardCommand,
    /// `log` / `VEIL_LOG`.
    Log,
}

impl Key {
    /// Every setting, in the order `veil config` shows them.
    pub const ALL: [Self; 5] = [
        Self::Server,
        Self::Email,
        Self::Keystore,
        Self::ClipboardCommand,
        Self::Log,
    ];

    /// The key in `config.toml`.
    pub fn name(self) -> &'static str {
        match self {
            Self::Server => "server",
            Self::Email => "email",
            Self::Keystore => "keystore",
            Self::ClipboardCommand => "clipboard-command",
            Self::Log => "log",
        }
    }

    /// The environment variable that overrides the file.
    pub fn env(self) -> &'static str {
        match self {
            Self::Server => "VEIL_SERVER",
            Self::Email => "VEIL_EMAIL",
            Self::Keystore => "VEIL_KEYSTORE",
            Self::ClipboardCommand => "VEIL_CLIPBOARD_COMMAND",
            Self::Log => "VEIL_LOG",
        }
    }

    fn in_file(self, settings: &Settings) -> Option<&String> {
        match self {
            Self::Server => settings.server.as_ref(),
            Self::Email => settings.email.as_ref(),
            Self::Keystore => settings.keystore.as_ref(),
            Self::ClipboardCommand => settings.clipboard_command.as_ref(),
            Self::Log => settings.log.as_ref(),
        }
    }
}

/// Where a value came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// A `VEIL_*` environment variable.
    Environment,
    /// `config.toml`.
    File,
}

static LOADED: OnceLock<Settings> = OnceLock::new();

/// The file `veil` reads: `VEIL_CONFIG`, else `$VEIL_HOME/config.toml`.
pub fn path() -> Result<PathBuf> {
    match std::env::var_os("VEIL_CONFIG").filter(|value| !value.is_empty()) {
        Some(path) => Ok(PathBuf::from(path)),
        None => Ok(crate::state::home()?.join("config.toml")),
    }
}

/// Reads the file once, before any command runs.
pub fn load() -> Result<()> {
    // Without VEIL_CONFIG, VEIL_HOME, or HOME there is no file to read: defaults apply.
    let Ok(path) = path() else {
        let _ = LOADED.set(Settings::default());
        return Ok(());
    };
    let settings = match std::fs::read_to_string(&path) {
        Ok(text) => parse(&text).map_err(|error| {
            crate::diagnostic::Failure::new(
                "config_invalid",
                2,
                format!("cannot parse {}: {error}", path.display()),
                "Fix the configuration file. Run: veil doctor",
            )
        })?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Settings::default(),
        Err(error) => {
            return Err(error).with_context(|| format!("cannot read {}", path.display()));
        }
    };
    let _ = LOADED.set(settings);
    Ok(())
}

/// The value of `key` and where it came from: the environment, else the file.
pub fn get(key: Key) -> Option<(String, Source)> {
    let from_env = std::env::var(key.env()).ok();
    resolve(
        from_env,
        LOADED.get().and_then(|settings| key.in_file(settings)),
    )
}

/// The value of `key`, without its source.
pub fn value(key: Key) -> Option<String> {
    get(key).map(|(value, _)| value)
}

fn parse(text: &str) -> Result<Settings> {
    toml::from_str(text).map_err(|error: toml::de::Error| {
        let line = text[..error.span().map_or(0, |span| span.start)]
            .bytes()
            .filter(|b| *b == b'\n')
            .count()
            + 1;
        let detail = if error.message().starts_with("unknown field") {
            error.message().split(',').next().unwrap_or("unknown field")
        } else {
            "invalid TOML or setting type"
        };
        anyhow::anyhow!("{detail} at line {line}; configuration values are not shown")
    })
}

/// The environment wins over the file; blank values count as unset.
fn resolve(from_env: Option<String>, in_file: Option<&String>) -> Option<(String, Source)> {
    let set = |value: &str| !value.trim().is_empty();
    match from_env.filter(|value| set(value)) {
        Some(value) => Some((value, Source::Environment)),
        None => in_file
            .filter(|value| set(value))
            .map(|value| (value.clone(), Source::File)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_setting_parses_by_its_file_key() {
        let settings = parse(
            "server = \"https://veil.example\"\nemail = \"me@example.com\"\nkeystore = \"file\"\n\
             clipboard-command = \"xclip -selection clipboard\"\nlog = \"veil=debug\"\n",
        )
        .expect("parse");
        for key in Key::ALL {
            assert!(
                key.in_file(&settings).is_some(),
                "{} is not read",
                key.name()
            );
        }
    }

    #[test]
    fn an_unknown_key_is_an_error() {
        let error = parse("sever = \"https://veil.example\"\n").expect_err("typo");
        assert!(error.to_string().contains("sever"), "{error}");
    }

    #[test]
    fn the_environment_wins_over_the_file_and_blanks_are_unset() {
        let file = "https://from-file".to_owned();
        assert_eq!(
            resolve(Some("https://from-env".to_owned()), Some(&file)),
            Some(("https://from-env".to_owned(), Source::Environment))
        );
        assert_eq!(
            resolve(Some("  ".to_owned()), Some(&file)),
            Some((file.clone(), Source::File))
        );
        assert_eq!(resolve(None, None), None);
    }
}
