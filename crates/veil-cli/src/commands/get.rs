//! `veil get`: reveal one value on purpose.

use anyhow::{Context, Result, bail};
use veil_core::Reference;
use veil_proto::Destination;

use crate::{
    project::{self, VeilToml},
    vaults::Opened,
};

/// What `veil get` was asked to do.
pub struct Options {
    /// A `veil://` reference, or a variable name from `veil.toml`.
    pub target: String,
    /// Skip the prompt.
    pub yes: bool,
    /// Put the value on the clipboard instead of printing it.
    pub copy: bool,
    pub json: bool,
}

/// Runs `veil get`.
pub fn run(options: Options) -> Result<()> {
    let reference = target(&options.target)?;
    let mut opened = Opened::load()?;
    let resolved = opened.view.resolve(&reference)?;

    // Ask here first: a Touch ID press spent on a value that then cannot be shown is wasted.
    crate::ui::confirm(
        &format!(
            "{} {reference}?",
            if options.copy { "Copy" } else { "Reveal" }
        ),
        options.yes,
        "Pass get --yes to authorize revealing or copying this value; Vault approval still applies.",
    )?;
    let released = opened.release(
        &[&resolved],
        Destination::Print,
        &format!("veil get {reference}"),
    )?;
    if options.copy {
        copy(resolved.value(&released))?;
        if options.json {
            println!(
                "{}",
                serde_json::json!({"reference": reference.to_string(), "copied": true})
            );
        } else {
            crate::ui::notice(
                "warning",
                format!("Copied {reference}; clear the clipboard when finished."),
            );
        }
    } else if options.json {
        println!(
            "{}",
            serde_json::json!({"reference": reference.to_string(), "value": resolved.value(&released)})
        );
    } else {
        println!("{}", resolved.value(&released));
    }
    Ok(())
}

/// Puts a value on the clipboard: `VEIL_CLIPBOARD_COMMAND`, else the platform's tool.
fn copy(value: &str) -> Result<()> {
    use std::io::Write as _;
    let command =
        crate::settings::value(crate::settings::Key::ClipboardCommand).unwrap_or_else(|| {
            if cfg!(target_os = "macos") {
                "pbcopy".to_owned()
            } else if std::env::var_os("WAYLAND_DISPLAY").is_some() {
                "wl-copy".to_owned()
            } else {
                "xclip -selection clipboard".to_owned()
            }
        });
    let mut child = std::process::Command::new("sh")
        .args(["-c", &command])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .spawn()
        .with_context(|| format!("cannot run the clipboard command {command:?}"))?;
    child
        .stdin
        .take()
        .context("clipboard stdin")?
        .write_all(value.as_bytes())?;
    let status = child.wait()?;
    if !status.success() {
        bail!("the clipboard command {command:?} failed");
    }
    Ok(())
}

/// A reference given outright, or a variable bound in `veil.toml`.
pub fn target(target: &str) -> Result<Reference> {
    if target.starts_with("veil://") {
        return target
            .parse()
            .context("not a well-formed veil:// reference");
    }
    let declaration = VeilToml::require(&project::current_dir()?)?;
    declaration
        .env
        .get(target)
        .with_context(|| format!("{target} is not bound in veil.toml"))?
        .parse()
        .context("veil.toml holds a malformed reference")
}
