use std::collections::BTreeMap;

use anyhow::{Context, Result, bail};
use veil_core::{Item, Reference};

use crate::{
    diagnostic::Failure,
    project::{self, VeilToml},
    ui,
    vaults::{Opened, Writer},
};

pub struct Options {
    pub vault: Option<String>,
    pub json: bool,
    pub dry_run: bool,
    pub yes: bool,
}

pub fn run(options: Options) -> Result<()> {
    let dir = project::current_dir()?;
    if dir.join(project::FILE).try_exists()? {
        bail!("This directory already has veil.toml; inspect it instead of importing again.");
    }
    let text = match std::fs::read_to_string(dir.join(".env")) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(Failure::new("env_missing", 2, "No .env file in this directory.",
                "Create .env to import values, or configure veil.toml with references to existing values.").into());
        }
        Err(error) => return Err(error).context("Cannot read .env; nothing was imported"),
    };
    let values = project::parse_env(&text)?;
    if values.is_empty() {
        return Err(Failure::new(
            "env_empty",
            2,
            ".env contains no assignments; nothing was imported.",
            "Add literal NAME=value assignments before importing.",
        )
        .into());
    }
    let ignore = dir.join(".gitignore");
    if ignore.try_exists()? {
        std::fs::read_to_string(&ignore).context("Cannot read .gitignore; nothing was imported")?;
    }
    let vault_name = options
        .vault
        .or_else(|| {
            dir.file_name()
                .map(|name| name.to_string_lossy().into_owned())
        })
        .context("Cannot infer a Vault name; pass --vault")?;
    let env: BTreeMap<_, _> = values
        .keys()
        .map(|name| {
            Ok((
                name.clone(),
                Reference::new(&vault_name, name, "password")?.to_string(),
            ))
        })
        .collect::<Result<_>>()?;

    let opened = Opened::preview_owner()?;
    let writer = Writer::new(&opened)?;
    let created = !opened
        .view
        .vaults()
        .iter()
        .any(|vault| vault.name == vault_name);
    let vault = if created {
        None
    } else {
        Some(opened.view.vault(&vault_name)?)
    };
    if vault.is_some_and(|vault| vault.row.rotation_due) {
        return Err(Failure::new(
            "rotation_required",
            1,
            "This Vault needs key rotation before import.",
            "Use veil set to perform the required rotation, then preview the import again.",
        )
        .into());
    }
    let mut changes = Vec::new();
    for name in values.keys() {
        let existing = match vault {
            Some(vault) => opened.view.find_item(vault, name)?,
            None => None,
        };
        changes.push(serde_json::json!({"name": name, "action": if existing.is_some() { "replace" } else { "create" }}));
    }
    let replaced = changes
        .iter()
        .filter(|change| change["action"] == "replace")
        .count();
    if options.dry_run {
        if options.json {
            println!(
                "{}",
                serde_json::json!({"dry_run": true, "vault": vault_name, "create_vault": created, "changes": changes, "files": ["veil.toml", ".gitignore"], "source_retained": true})
            );
        } else {
            ui::table(
                &["ACTION", "NAME"],
                &changes
                    .iter()
                    .map(|c| {
                        vec![
                            c["action"].as_str().unwrap().into(),
                            c["name"].as_str().unwrap().into(),
                        ]
                    })
                    .collect::<Vec<_>>(),
                "No changes",
            );
            println!(
                "Vault: {}. Would write veil.toml and ignore .env; .env remains on disk. No changes made.",
                ui::safe(&vault_name)
            );
        }
        return Ok(());
    }
    ui::notice(
        "plan",
        format!(
            "Import {} names into {vault_name}: {} new, {replaced} replacements. Write veil.toml and ignore .env; retain the original .env.",
            values.len(),
            values.len() - replaced
        ),
    );
    if replaced > 0 {
        for change in &changes {
            if change["action"] == "replace" {
                ui::notice("replace", change["name"].as_str().unwrap());
            }
        }
        ui::confirm(
            "Replace these existing values?",
            options.yes,
            "Inspect veil init --dry-run, then pass init --yes to authorize replacements.",
        )?;
    }
    let mut completed = 0;
    let mut remote_attempted = false;
    let result = (|| {
        opened.state.save()?;
        if let Some(vault) = vault {
            for (name, value) in &values {
                let existing = opened.view.find_item(vault, name)?;
                let mut item =
                    existing.map_or_else(|| Item::login(name), |found| found.item.clone());
                item.set_field("password", value);
                remote_attempted = true;
                writer.put_item(vault, existing, &item)?;
                completed += 1;
            }
        } else {
            let items = values
                .iter()
                .map(|(name, value)| {
                    let mut item = Item::login(name);
                    item.set_field("password", value);
                    item
                })
                .collect::<Vec<_>>();
            remote_attempted = true;
            writer.create_vault(&vault_name, &items)?;
            completed = values.len();
        }
        if dir.join(project::FILE).try_exists()? {
            bail!("veil.toml appeared during import; refusing to replace it");
        }
        VeilToml {
            vault: Some(vault_name.clone()),
            env,
        }
        .write_new(&dir)?;
        project::ignore_env(&dir)?;
        Ok(())
    })();
    if let Err(error) = result {
        let failure = Failure::from_error(&error);
        return Err(Failure::new(failure.code, failure.exit_code,
            format!("Import did not finish: {}. {completed}/{} writes confirmed; {} No rollback was attempted.", failure.message, values.len(),
                if !remote_attempted { "No remote write was attempted." } else if completed == values.len() { "All requested writes were acknowledged." } else { "An unacknowledged request may also have committed." }),
            "Inspect the Vault and local files before retrying: veil list <VAULT>. The original .env remains on disk.").into());
    }
    if options.json {
        println!(
            "{}",
            serde_json::json!({"vault": vault_name, "created": created, "items": completed, "replaced": replaced})
        );
    } else {
        ui::success(format!("Imported {completed} values and wrote veil.toml"));
    }
    ui::notice(
        "warning",
        "The original .env remains on disk. Verify veil run -- <command> before removing it; .gitignore does not untrack committed files.",
    );
    Ok(())
}
