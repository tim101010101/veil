//! What a project directory declares: `veil.toml`, its `.env`, and `.gitignore`.

use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use veil_core::Reference;

/// The name of the declaration file.
pub const FILE: &str = "veil.toml";

/// What `veil.toml` contains: the references a project needs, never values or permissions.
///
/// ```toml
/// vault = "api"
///
/// [env]
/// DATABASE_URL = "veil://api/DATABASE_URL/password"
/// DEMO_TOKEN = "veil://example/demo-service/password"
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VeilToml {
    /// The Vault `veil set NAME` creates new Items in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vault: Option<String>,
    /// Environment variable name to reference.
    #[serde(default)]
    pub env: BTreeMap<String, String>,
}

impl VeilToml {
    /// Reads `veil.toml` from a directory.
    pub fn read(dir: &Path) -> Result<Option<Self>> {
        let path = dir.join(FILE);
        let raw = match fs::read_to_string(&path) {
            Ok(raw) => raw,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(error).with_context(|| format!("cannot read {}", path.display()));
            }
        };
        let declaration: Self = toml::from_str(&raw).map_err(|error: toml::de::Error| {
            let line = raw[..error.span().map_or(0, |span| span.start)]
                .bytes()
                .filter(|b| *b == b'\n')
                .count()
                + 1;
            crate::diagnostic::Failure::new(
                "project_invalid",
                2,
                format!(
                    "Cannot parse {} at line {line}; values are not shown.",
                    path.display()
                ),
                "Fix veil.toml syntax and setting types, then run veil doctor.",
            )
        })?;
        for (name, reference) in &declaration.env {
            if !valid_env_name(name) {
                return Err(crate::diagnostic::Failure::new(
                    "project_invalid",
                    2,
                    "veil.toml contains an invalid environment variable name.",
                    "Use letters, digits and underscores; the first character must not be a digit.",
                )
                .into());
            }
            reference.parse::<Reference>().with_context(|| {
                format!("{name} in {} is not a veil:// reference", path.display())
            })?;
        }
        Ok(Some(declaration))
    }

    /// Reads `veil.toml`, failing with the next command when there is none.
    pub fn require(dir: &Path) -> Result<Self> {
        Self::read(dir)?.ok_or_else(|| {
            crate::diagnostic::Failure::new(
                "project_missing",
                2,
                "No veil.toml in this directory.",
                "Run veil init in the project directory, or use a full veil:// reference.",
            )
            .into()
        })
    }

    /// Writes `veil.toml` into a directory.
    pub fn write(&self, dir: &Path) -> Result<()> {
        let path = dir.join(FILE);
        let raw = toml::to_string_pretty(self).context("cannot encode veil.toml")?;
        crate::state::write_project(&path, raw.as_bytes())?;
        Ok(())
    }

    pub fn write_new(&self, dir: &Path) -> Result<()> {
        let path = dir.join(FILE);
        let temporary = dir.join(format!(".veil-{}.tmp", uuid::Uuid::now_v7()));
        let raw = toml::to_string_pretty(self).context("cannot encode veil.toml")?;
        crate::state::write_project(&temporary, raw.as_bytes())?;
        let result = fs::hard_link(&temporary, &path);
        let _ = fs::remove_file(&temporary);
        result.with_context(|| {
            format!(
                "cannot create {}; an existing file will not be replaced",
                path.display()
            )
        })
    }

    /// Every reference, by variable name.
    pub fn references(&self) -> Result<BTreeMap<String, Reference>> {
        self.env
            .iter()
            .map(|(name, reference)| Ok((name.clone(), reference.parse()?)))
            .collect::<Result<_, veil_core::Error>>()
            .context("veil.toml holds a malformed reference")
    }
}

/// A variable name and value read from `.env`.
pub type Variables = BTreeMap<String, String>;

pub fn valid_env_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .enumerate()
            .all(|(i, b)| b == b'_' || b.is_ascii_alphabetic() || (i > 0 && b.is_ascii_digit()))
}

/// Parses a `.env` file, ignoring comments, blank lines, and an `export` prefix.
pub fn parse_env(text: &str) -> Result<Variables> {
    let mut variables = Variables::new();
    for (index, line) in text.lines().enumerate() {
        let invalid = |reason: &str| {
            crate::diagnostic::Failure::new(
                "env_invalid",
                2,
                format!(
                    "Invalid .env at line {}: {reason}; values are not shown.",
                    index + 1
                ),
                "Use one literal NAME=value assignment per line; shell expansion and multiline values are not supported by init.",
            )
        };
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line);
        let (name, value) = line
            .split_once('=')
            .ok_or_else(|| invalid("expected NAME=value"))?;
        let name = name.trim();
        if !valid_env_name(name) {
            return Err(invalid("invalid variable name").into());
        }
        if variables.contains_key(name) {
            return Err(invalid("duplicate variable name").into());
        }
        let value = value.trim();
        let value = if value.starts_with(['\'', '"']) {
            let quote = value.as_bytes()[0] as char;
            let end = value[1..]
                .find(quote)
                .ok_or_else(|| invalid("unclosed quote"))?
                + 1;
            let rest = value[end + 1..].trim();
            if !rest.is_empty() && !rest.starts_with('#') {
                return Err(invalid("unexpected text after quoted value").into());
            }
            let value = &value[1..end];
            if quote == '"' && value.contains('\\') {
                return Err(
                    invalid("escape sequences need explicit conversion before import").into(),
                );
            }
            value
        } else {
            // Dotenv tools disagree on whether ` #` starts a comment here; refuse to guess
            // which part of a secret to keep.
            if value.contains(" #") || value.contains("\t#") {
                return Err(invalid(
                    "quote a value containing ' #', or move the comment to its own line",
                )
                .into());
            }
            value.trim_end()
        };
        variables.insert(name.to_owned(), value.to_owned());
    }
    Ok(variables)
}

/// Adds `.env` to `.gitignore` when it is missing.
pub fn ignore_env(dir: &Path) -> Result<bool> {
    let path = dir.join(".gitignore");
    let current = match fs::read_to_string(&path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(error) => return Err(error).with_context(|| format!("cannot read {}", path.display())),
    };
    if current.lines().any(|line| line.trim() == ".env") {
        return Ok(false);
    }
    let mut updated = current;
    if !updated.is_empty() && !updated.ends_with('\n') {
        updated.push('\n');
    }
    updated.push_str(".env\n");
    crate::state::write_project(&path, updated.as_bytes())?;
    Ok(true)
}

/// The working directory.
pub fn current_dir() -> Result<PathBuf> {
    std::env::current_dir().context("cannot determine the working directory")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_parsing_handles_quotes_comments_and_export() {
        let variables = parse_env(
            "# comment\nDATABASE_URL=postgres://localhost\nEMPTY=\nexport QUOTED=\"a b\"\nSINGLE='c'\n",
        ).expect("valid env");
        assert_eq!(
            variables.get("DATABASE_URL").map(String::as_str),
            Some("postgres://localhost")
        );
        assert_eq!(variables.get("EMPTY").map(String::as_str), Some(""));
        assert_eq!(variables.get("QUOTED").map(String::as_str), Some("a b"));
        assert_eq!(variables.get("SINGLE").map(String::as_str), Some("c"));
    }

    #[test]
    fn veil_toml_round_trips() {
        let dir = tempdir();
        let declaration = VeilToml {
            vault: Some("api".to_owned()),
            env: BTreeMap::from([(
                "DATABASE_URL".to_owned(),
                "veil://api/DATABASE_URL/password".to_owned(),
            )]),
        };
        declaration.write(&dir).expect("write");
        assert_eq!(VeilToml::read(&dir).expect("read"), Some(declaration));
    }

    #[test]
    fn a_malformed_reference_is_refused() {
        let dir = tempdir();
        fs::write(dir.join(FILE), "[env]\nDB = \"veil://api/DB\"\n").expect("write");
        assert!(VeilToml::read(&dir).is_err());
    }

    #[test]
    fn an_unquoted_value_with_an_inline_hash_is_refused_not_truncated() {
        assert!(parse_env("DB_PASS=abc #xyz\n").is_err());
        assert!(parse_env("DB_PASS=abc\t#xyz\n").is_err());
        let variables = parse_env("DB_PASS=\"abc #xyz\" # note\nHASH=a#b\n").expect("valid env");
        assert_eq!(
            variables.get("DB_PASS").map(String::as_str),
            Some("abc #xyz")
        );
        assert_eq!(variables.get("HASH").map(String::as_str), Some("a#b"));
    }

    #[cfg(unix)]
    #[test]
    fn project_files_keep_their_mode_and_symlinks() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempdir();
        fs::write(dir.join("shared-ignore"), "target\n").expect("write");
        fs::set_permissions(dir.join("shared-ignore"), fs::Permissions::from_mode(0o664))
            .expect("chmod");
        std::os::unix::fs::symlink("shared-ignore", dir.join(".gitignore")).expect("link");
        assert!(ignore_env(&dir).expect("update"));
        assert!(
            fs::symlink_metadata(dir.join(".gitignore"))
                .expect("meta")
                .file_type()
                .is_symlink()
        );
        let target = dir.join("shared-ignore");
        assert_eq!(fs::read_to_string(&target).expect("read"), "target\n.env\n");
        assert_eq!(
            fs::metadata(&target).expect("meta").permissions().mode() & 0o777,
            0o664
        );
    }

    #[test]
    fn gitignore_is_updated_once() {
        let dir = tempdir();
        assert!(ignore_env(&dir).expect("first"));
        assert!(!ignore_env(&dir).expect("second"));
        let content = fs::read_to_string(dir.join(".gitignore")).expect("read");
        assert_eq!(content.matches(".env").count(), 1);
    }

    struct TempDir(PathBuf);

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn tempdir() -> TempDir {
        let base = std::env::temp_dir().join(format!(
            "veil-project-{}-{}",
            std::process::id(),
            uuid::Uuid::now_v7()
        ));
        fs::create_dir_all(&base).expect("create");
        TempDir(base)
    }

    impl std::ops::Deref for TempDir {
        type Target = PathBuf;

        fn deref(&self) -> &Self::Target {
            &self.0
        }
    }
}
