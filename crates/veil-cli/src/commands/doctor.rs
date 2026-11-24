use anyhow::Result;
use serde::Serialize;

use crate::{client::Client, diagnostic::Failure, project, settings, state::State, ui, vaults};

#[derive(Serialize)]
struct Check {
    name: String,
    status: &'static str,
    message: String,
    hint: String,
}

fn check(
    checks: &mut Vec<Check>,
    name: &str,
    status: &'static str,
    message: impl Into<String>,
    hint: &str,
) {
    checks.push(Check {
        name: name.into(),
        status,
        message: message.into(),
        hint: hint.into(),
    });
}

fn failed(checks: &mut Vec<Check>, name: &str, error: anyhow::Error) {
    let failure = Failure::from_error(&error);
    check(checks, name, "error", failure.message, &failure.hint);
}

pub fn run(json: bool) -> Result<()> {
    let mut checks = Vec::new();
    let configured = match settings::load() {
        Ok(()) => {
            check(&mut checks, "config", "ok", "Configuration loaded", "");
            true
        }
        Err(error) => {
            failed(&mut checks, "config", error);
            false
        }
    };
    let declaration = match project::current_dir().and_then(|dir| project::VeilToml::read(&dir)) {
        Ok(Some(value)) => {
            check(
                &mut checks,
                "project",
                "ok",
                format!("veil.toml binds {} references", value.env.len()),
                "",
            );
            Some(value)
        }
        Ok(None) => {
            check(
                &mut checks,
                "project",
                "warning",
                "No veil.toml in this directory",
                "Run veil init only if this directory is a project that needs secrets.",
            );
            None
        }
        Err(error) => {
            failed(&mut checks, "project", error);
            None
        }
    };
    if configured {
        match State::load() {
            Ok(Some(state)) => {
                check(
                    &mut checks,
                    "device",
                    if state.pending_registration {
                        "error"
                    } else {
                        "ok"
                    },
                    format!(
                        "{} ({}){}",
                        state.device_id,
                        state.email,
                        if state.pending_registration {
                            "; registration unfinished"
                        } else {
                            ""
                        }
                    ),
                    if state.pending_registration {
                        "Run: veil login"
                    } else {
                        ""
                    },
                );
                check(
                    &mut checks,
                    "session",
                    if state.live_session().is_some() {
                        "ok"
                    } else {
                        "warning"
                    },
                    if state.live_session().is_some() {
                        "Management session is live"
                    } else {
                        "No live management session; device read scope is unchanged"
                    },
                    if state.live_session().is_none() {
                        "Run veil login when you need to write."
                    } else {
                        ""
                    },
                );
                let client = Client::new(&state.server);
                match client.sync(&state) {
                    Ok(document) => {
                        check(
                            &mut checks,
                            "service",
                            "ok",
                            format!(
                                "Reachable; revision {}, {} readable Vaults",
                                document.revision,
                                document.vaults.len()
                            ),
                            "",
                        );
                        match vaults::Reader::from_state(&state)
                            .and_then(|reader| vaults::View::open(&document, &reader))
                        {
                            Ok(view) => {
                                if let Some(declaration) = declaration {
                                    for (name, reference) in declaration.references()? {
                                        match view.resolve(&reference) {
                                            Ok(_) => check(
                                                &mut checks,
                                                &name,
                                                "ok",
                                                reference.to_string(),
                                                "",
                                            ),
                                            Err(error) => failed(&mut checks, &name, error),
                                        }
                                    }
                                }
                            }
                            Err(error) => failed(&mut checks, "keys", error),
                        }
                    }
                    Err(error) => {
                        if error.is_offline() && state.fresh_cache().is_some() {
                            check(
                                &mut checks,
                                "cache",
                                "warning",
                                "A fresh device-scoped cache is available; doctor did not deliver any values",
                                "Restore connectivity before the cache expires.",
                            );
                        }
                        failed(&mut checks, "service", error.into());
                    }
                }
            }
            Ok(None) => check(
                &mut checks,
                "device",
                "error",
                "No device registered on this machine",
                "Run: veil login --server <URL> --email <EMAIL>",
            ),
            Err(error) => failed(&mut checks, "device", error),
        }
    } else {
        check(
            &mut checks,
            "device",
            "skipped",
            "Fix configuration before inspecting the configured keystore",
            "",
        );
    }
    let problems = checks
        .iter()
        .filter(|check| check.status == "error")
        .count();
    if json {
        println!(
            "{}",
            serde_json::json!({"ok": problems == 0, "checks": checks})
        );
    } else {
        let rows = checks
            .iter()
            .map(|c| vec![c.status.into(), c.name.clone(), c.message.clone()])
            .collect::<Vec<_>>();
        ui::table(&["STATUS", "CHECK", "RESULT"], &rows, "No checks performed");
        for c in &checks {
            if !c.hint.is_empty() {
                println!("  {}: {}", ui::safe(&c.name), ui::safe(&c.hint));
            }
        }
    }
    if problems > 0 {
        return Err(Failure::new(
            "checks_failed",
            1,
            format!("{problems} diagnostic check(s) failed."),
            "Follow the checks above; doctor did not modify your configuration or deliver secrets.",
        )
        .into());
    }
    Ok(())
}
