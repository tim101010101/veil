//! `veil inject`: render a template containing references.

use std::io::Write as _;

use anyhow::{Context, Result};
use veil_proto::Destination;

use crate::vaults::Opened;

/// What `veil inject` was asked to do.
pub struct Options {
    /// Template file.
    pub file: String,
    /// Write the result here instead of stdout.
    pub out: Option<String>,
    /// Encrypt the result to the age recipients in `.sops.yaml` with sops.
    pub sops: bool,
}

/// Runs `veil inject`.
pub fn run(options: Options) -> Result<()> {
    let template = std::fs::read_to_string(&options.file)
        .with_context(|| format!("cannot read {}", options.file))?;
    let mut opened = Opened::load()?;
    let template = opened.view.template(&template)?;
    let released = opened.release(
        &template.used.iter().collect::<Vec<_>>(),
        Destination::Render,
        &format!("veil inject {}", options.file),
    )?;
    let rendered = template.render(&released);

    if options.sops {
        let path = options
            .out
            .context("--sops needs --out: sops picks the recipients by the output path")?;
        let sealed = sops(&path, rendered.as_bytes())?;
        std::fs::write(&path, sealed).with_context(|| format!("cannot write {path}"))?;
        crate::ui::success(format!("wrote {path} (encrypted with sops)"));
        return Ok(());
    }
    match options.out {
        Some(path) => {
            write_private(&path, rendered.as_bytes())?;
            crate::ui::success(format!("wrote {path} (0600)"));
        }
        None => print!("{rendered}"),
    }
    Ok(())
}

/// Encrypts `plaintext` with sops for `path`: sops reads the creation rule for that path from
/// `.sops.yaml` and needs only the recipients' public keys. The plaintext goes through a pipe and
/// never touches the disk.
fn sops(path: &str, plaintext: &[u8]) -> Result<Vec<u8>> {
    use std::io::Write as _;
    let kind = if path.ends_with(".json") {
        "json"
    } else if path.ends_with(".env") {
        "dotenv"
    } else if path.ends_with(".yaml") || path.ends_with(".yml") {
        "yaml"
    } else {
        "binary"
    };
    let mut child = std::process::Command::new("sops")
        .args([
            "--encrypt",
            "--input-type",
            kind,
            "--output-type",
            kind,
            "--filename-override",
            path,
            "/dev/stdin",
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .context("cannot run sops; install it to use --sops")?;
    let mut stdin = child.stdin.take().context("sops stdin")?;
    stdin
        .write_all(plaintext)
        .context("cannot hand the rendering to sops")?;
    drop(stdin);
    let output = child.wait_with_output().context("sops did not finish")?;
    if !output.status.success() {
        anyhow::bail!(
            "sops refused: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(output.stdout)
}

/// Writes a file only its owner can read.
pub fn write_private(path: &str, content: &[u8]) -> Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("cannot write {path}"))?;
    file.write_all(content)
        .with_context(|| format!("cannot write {path}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("cannot restrict {path}"))?;
    }
    Ok(())
}
