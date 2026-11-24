//! `veil config`: where the configuration file is, and where each setting's value comes from.

use anyhow::Result;

use crate::settings::{self, Key, Source};

/// Prints the file path and every setting with its effective value and source.
pub fn run(json: bool) -> Result<()> {
    let path = settings::path()?;
    let rows: Vec<(Key, Option<(String, Source)>)> = Key::ALL
        .iter()
        .map(|key| (*key, settings::get(*key)))
        .collect();
    if json {
        let values: serde_json::Map<String, serde_json::Value> = rows
            .iter()
            .map(|(key, found)| {
                let entry = match found {
                    Some((value, source)) => serde_json::json!({
                        "value": value,
                        "source": source_name(*source, *key),
                    }),
                    None => serde_json::Value::Null,
                };
                (key.name().to_owned(), entry)
            })
            .collect();
        println!(
            "{}",
            serde_json::json!({ "file": path, "exists": path.exists(), "settings": values })
        );
        return Ok(());
    }
    let presence = if path.exists() {
        ""
    } else {
        " (not created; defaults apply)"
    };
    println!("{}{presence}", crate::ui::safe(&path.display().to_string()));
    for (key, found) in rows {
        match found {
            Some((value, source)) => {
                println!(
                    "  {:<18} {}  ({})",
                    key.name(),
                    crate::ui::safe(&value),
                    source_name(source, key)
                );
            }
            None => println!("  {:<18} -", key.name()),
        }
    }
    Ok(())
}

fn source_name(source: Source, key: Key) -> String {
    match source {
        Source::Environment => key.env().to_owned(),
        Source::File => "config.toml".to_owned(),
    }
}
