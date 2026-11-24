//! `veil export`: print text fields for a shell or a file, never hidden ones.

use anyhow::{Result, bail};
use veil_proto::Destination;

use crate::{
    project::{self, VeilToml},
    vaults::Opened,
};

/// What `veil export` was asked to do.
pub struct Options {
    /// `shell`, `dotenv`, or `json`.
    pub format: String,
}

/// Runs `veil export`.
pub fn run(options: Options) -> Result<()> {
    let declaration = VeilToml::require(&project::current_dir()?)?;
    let mut opened = Opened::load()?;
    let resolved = opened.view.resolve_all(&declaration.references()?)?;
    let (text, hidden): (Vec<_>, Vec<_>) = resolved.into_iter().partition(|(_, r)| !r.hidden);
    for (name, _) in &hidden {
        crate::ui::notice(
            "warning",
            format!("{name} is a hidden field and is not exported; use veil run"),
        );
    }
    let released = opened.release(
        &text.iter().map(|(_, r)| r).collect::<Vec<_>>(),
        Destination::Export,
        "veil export",
    )?;

    match options.format.as_str() {
        "shell" => {
            for (name, resolved) in &text {
                println!(
                    "export {name}='{}'",
                    resolved.value(&released).replace('\'', r"'\''")
                );
            }
        }
        "dotenv" => {
            for (name, resolved) in &text {
                println!("{name}={}", resolved.value(&released));
            }
        }
        "json" => {
            let map: serde_json::Map<String, serde_json::Value> = text
                .iter()
                .map(|(name, r)| {
                    (
                        name.clone(),
                        serde_json::Value::String(r.value(&released).to_owned()),
                    )
                })
                .collect();
            println!("{}", serde_json::Value::Object(map));
        }
        other => bail!("{other} is not a format: shell, dotenv, or json"),
    }
    Ok(())
}
