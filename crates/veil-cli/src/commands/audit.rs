//! `veil audit`: who delivered what, and when.

use anyhow::{Context, Result};

use crate::vaults::Opened;

/// What `veil audit` was asked to do.
pub struct Options {
    /// How many rows.
    pub limit: usize,
    /// Only deliveries of this Item: a reference, or a `veil.toml` name.
    pub item: Option<String>,
    /// Machine-readable output.
    pub json: bool,
}

/// Runs `veil audit`.
pub fn run(options: Options) -> Result<()> {
    let opened = Opened::load()?;
    let bearer = opened.state.require_session()?;
    let filter = match &options.item {
        Some(target) => {
            let reference = crate::commands::get::target(target)?;
            let resolved = opened.view.resolve(&reference)?;
            Some((resolved.vault_id, resolved.item_id))
        }
        None => None,
    };
    let events = opened
        .client
        .audit(
            &bearer,
            options.limit,
            filter.map(|(vault, _)| vault),
            filter.map(|(_, item)| item),
        )
        .map_err(anyhow::Error::from)?;

    if options.json {
        println!("{}", serde_json::to_value(&events).context("encode")?);
        return Ok(());
    }
    let mut rows = Vec::new();
    for event in events {
        // Names are sealed; show them only where this machine can open them.
        let vault = opened
            .view
            .vaults()
            .iter()
            .find(|vault| vault.row.id == event.vault_id);
        let item = vault.and_then(|vault| {
            opened
                .view
                .items_in(vault.row.id)
                .find(|item| item.id == event.item_id)
                .map(|item| item.item.name().to_owned())
        });
        rows.push(vec![
            event.at.to_string(),
            event.principal_id.to_string(),
            format!(
                "{}/{}",
                vault.map_or_else(|| event.vault_id.to_string(), |vault| vault.name.clone()),
                item.unwrap_or_else(|| event.item_id.to_string())
            ),
            format!("{:?}", event.destination),
            format!("{:?}", event.result),
        ]);
    }
    crate::ui::table(
        &["TIME", "PRINCIPAL", "ITEM", "DESTINATION", "RESULT"],
        &rows,
        "No deliveries recorded.",
    );
    Ok(())
}
