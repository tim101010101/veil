//! `veil list`: names, never values.

use anyhow::Result;

use crate::{
    project::{self, VeilToml},
    vaults::Opened,
};

/// What `veil list` was asked to do.
pub struct Options {
    /// A Vault to list the Items and fields of.
    pub vault: Option<String>,
    /// Machine-readable output.
    pub json: bool,
}

/// Runs `veil list`: the Items of a Vault, the bindings of `veil.toml`, or the Vaults.
pub fn run(options: Options) -> Result<()> {
    let opened = Opened::load()?;
    if let Some(name) = &options.vault {
        let vault = opened.view.vault(name)?;
        let items: Vec<_> = opened
            .view
            .items_in(vault.row.id)
            .map(|item| (item.item.name().to_owned(), item.item.field_names()))
            .collect();
        if options.json {
            let items: Vec<_> = items
                .iter()
                .map(|(name, fields)| serde_json::json!({ "item": name, "fields": fields }))
                .collect();
            println!("{}", serde_json::json!({ "vault": name, "items": items }));
        } else {
            crate::ui::table(
                &["ITEM", "FIELDS"],
                &items
                    .into_iter()
                    .map(|(name, fields)| vec![name, fields.join(", ")])
                    .collect::<Vec<_>>(),
                "No items. Use veil set veil://<vault>/<item>/<field> to add one.",
            );
        }
        return Ok(());
    }

    if let Some(declaration) = VeilToml::read(&project::current_dir()?)? {
        let mut rows = Vec::new();
        for (name, reference) in declaration.references()? {
            let status = match opened.view.resolve(&reference) {
                Ok(_) => "ok",
                Err(_) => "missing",
            };
            rows.push((name, reference.to_string(), status));
        }
        if options.json {
            let rows: Vec<_> = rows
                .iter()
                .map(|(name, reference, status)| {
                    serde_json::json!({ "name": name, "reference": reference, "status": status })
                })
                .collect();
            println!("{}", serde_json::json!({ "env": rows }));
        } else {
            crate::ui::table(
                &["NAME", "REFERENCE", "STATUS"],
                &rows
                    .into_iter()
                    .map(|(name, reference, status)| vec![name, reference, status.into()])
                    .collect::<Vec<_>>(),
                "No project references. Use veil set NAME to add one.",
            );
        }
        return Ok(());
    }

    let vaults: Vec<_> = opened
        .view
        .vaults()
        .iter()
        .map(|vault| {
            (
                vault.name.clone(),
                opened.view.items_in(vault.row.id).count(),
            )
        })
        .collect();
    if options.json {
        let vaults: Vec<_> = vaults
            .iter()
            .map(|(name, items)| serde_json::json!({ "vault": name, "items": items }))
            .collect();
        println!("{}", serde_json::json!({ "vaults": vaults }));
    } else {
        crate::ui::table(
            &["VAULT", "ITEMS"],
            &vaults
                .into_iter()
                .map(|(name, items)| vec![name, items.to_string()])
                .collect::<Vec<_>>(),
            "No readable Vaults. Use veil vault create <name>, or ask a trusted device for a grant.",
        );
    }
    Ok(())
}
