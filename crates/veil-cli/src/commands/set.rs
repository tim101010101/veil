//! `veil set`: write one value.

use anyhow::{Context, Result};
use veil_core::{Item, Reference};

use crate::{
    project::{self, VeilToml},
    vaults::{Opened, Writer},
};

/// What `veil set` was asked to do.
pub struct Options {
    /// A `veil://` reference, or a variable name from `veil.toml`.
    pub target: String,
    /// Value; prompted when absent.
    pub value: Option<String>,
    pub stdin: bool,
    pub file: Option<std::path::PathBuf>,
    /// Machine-readable output.
    pub json: bool,
}

/// Runs `veil set`.
pub fn run(options: Options) -> Result<()> {
    let dir = project::current_dir()?;
    let mut declaration = VeilToml::read(&dir)?;
    let (reference, new_binding) = target(&options.target, declaration.as_ref())?;

    let value = match (options.value, options.stdin, options.file) {
        (Some(value), _, _) => value,
        (_, true, _) => {
            use std::io::Read as _;
            let mut value = String::new();
            std::io::stdin()
                .read_to_string(&mut value)
                .context("cannot read a UTF-8 value from stdin")?;
            value
        }
        (_, _, Some(path)) => std::fs::read_to_string(&path)
            .with_context(|| format!("cannot read a UTF-8 value from {}", path.display()))?,
        _ => crate::ui::secret(
            &format!("Value for {reference}"),
            "Supply set --stdin or --file when input cannot be prompted.",
        )?,
    };
    let mut opened = Opened::load_owner()?;
    let writer = Writer::new(&opened)?;

    // A revoked principal still holds the old key: rotate before writing anything new.
    let vault = opened.view.vault(&reference.vault)?;
    if vault.row.rotation_due {
        writer.rotate(&opened.document, vault)?;
        crate::ui::notice(
            "info",
            format!("Rotated the key of {} after a revocation", reference.vault),
        );
        opened.refresh()?;
    }

    let vault = opened.view.vault(&reference.vault)?;
    let existing = opened.view.find_item(vault, &reference.item)?;
    let mut item =
        existing.map_or_else(|| Item::login(&reference.item), |found| found.item.clone());
    item.set_field(&reference.field, &value);
    let written = writer.put_item(vault, existing, &item)?;

    if let (Some(name), Some(declaration)) = (new_binding, declaration.as_mut()) {
        declaration.env.insert(name, reference.to_string());
        declaration.write(&dir)?;
    }

    if options.json {
        println!(
            "{}",
            serde_json::json!({ "reference": reference.to_string(), "revision": written.revision })
        );
    } else {
        crate::ui::success(format!("{reference} updated"));
        crate::ui::notice(
            "warning",
            "Running processes still hold the old value; restart them.",
        );
    }
    Ok(())
}

/// What to write: a reference given outright, a variable bound in `veil.toml`, or a new
/// variable in the declared Vault (returned so the binding can be added).
fn target(target: &str, declaration: Option<&VeilToml>) -> Result<(Reference, Option<String>)> {
    if target.starts_with("veil://") {
        return Ok((
            target
                .parse()
                .context("not a well-formed veil:// reference")?,
            None,
        ));
    }
    if !project::valid_env_name(target) {
        return Err(crate::diagnostic::Failure::new("variable_name_invalid", 2,
            "The target is not a valid environment variable name.",
            "Use letters, digits and underscores without a leading digit, or use a full veil:// reference.").into());
    }
    let declaration = declaration
        .with_context(|| format!("{target} is not a reference and there is no veil.toml here"))?;
    if let Some(bound) = declaration.env.get(target) {
        return Ok((bound.parse()?, None));
    }
    let vault = declaration
        .vault
        .as_deref()
        .with_context(|| format!("{target} is not in veil.toml and it names no default vault"))?;
    Ok((
        Reference::new(vault, target, "password")?,
        Some(target.to_owned()),
    ))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    fn declaration() -> VeilToml {
        VeilToml {
            vault: Some("api".to_owned()),
            env: BTreeMap::from([(
                "DB".to_owned(),
                "veil://shared/postgres/password".to_owned(),
            )]),
        }
    }

    #[test]
    fn targets_resolve_in_order() {
        let (reference, binding) = target("veil://example/bot/password", None).expect("reference");
        assert_eq!(reference.vault, "example");
        assert!(binding.is_none());

        let (reference, binding) = target("DB", Some(&declaration())).expect("bound");
        assert_eq!(reference.to_string(), "veil://shared/postgres/password");
        assert!(binding.is_none());

        let (reference, binding) = target("NEW", Some(&declaration())).expect("new");
        assert_eq!(reference.to_string(), "veil://api/NEW/password");
        assert_eq!(binding.as_deref(), Some("NEW"));
    }

    #[test]
    fn a_bare_name_needs_a_veil_toml() {
        assert!(target("DB", None).is_err());
    }
}
