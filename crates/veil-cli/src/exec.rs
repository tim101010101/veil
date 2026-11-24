//! Running a child with delivered values, its output redacted by default.
//!
//! - Redaction off: the child inherits stdin, stdout, and stderr.
//! - Output to a pipe or file: stdout and stderr are relayed through a redactor each.
//! - Output to a terminal: the child runs on a pseudo-terminal, so colors and interactive
//!   programs keep working, and everything it prints is relayed through a redactor.

use std::{
    io::{IsTerminal as _, Read, Write},
    process::{Command, Stdio},
};

use anyhow::{Context, Result};

use crate::redact::Redactor;

#[derive(Debug, thiserror::Error)]
#[error("The child started, but Veil could not finish supervising it")]
pub struct Started;

fn exit_code(status: std::process::ExitStatus) -> i32 {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt as _;
        if let Some(signal) = status.signal() {
            return 128 + signal;
        }
    }
    status.code().unwrap_or(1)
}

/// What to run.
pub struct Child<'a> {
    /// Program.
    pub program: &'a str,
    /// Its arguments.
    pub arguments: &'a [String],
    /// Environment variables to add.
    pub variables: &'a [(String, String)],
    /// Values to redact from its output; `None` turns redaction off.
    pub redact: Option<Vec<String>>,
}

/// Runs the child and returns its exit code.
pub fn run(child: &Child<'_>) -> Result<i32> {
    match &child.redact {
        None => inherit(child),
        Some(values) if std::io::stdout().is_terminal() => terminal(child, values),
        Some(values) => piped(child, values),
    }
}

/// Runs the child with its output captured and redacted; returns the exit code, stdout, and
/// stderr. Used where the output goes back to a caller rather than to a stream.
pub fn capture(child: &Child<'_>) -> Result<(i32, Vec<u8>, Vec<u8>)> {
    let output = command(child)
        .stdin(Stdio::null())
        .output()
        .with_context(|| format!("cannot run {}", child.program))?;
    let values = child.redact.clone().unwrap_or_default();
    Ok((
        output.status.code().unwrap_or(1),
        crate::redact::redact_all(&values, &output.stdout),
        crate::redact::redact_all(&values, &output.stderr),
    ))
}

fn command(child: &Child<'_>) -> Command {
    let mut command = Command::new(child.program);
    command.args(child.arguments);
    for (name, value) in child.variables {
        command.env(name, value);
    }
    command
}

fn inherit(child: &Child<'_>) -> Result<i32> {
    let mut process = command(child)
        .spawn()
        .with_context(|| format!("cannot run {}", child.program))?;
    let status = process.wait().context(Started)?;
    Ok(exit_code(status))
}

fn piped(child: &Child<'_>, values: &[String]) -> Result<i32> {
    let mut process = command(child)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("cannot run {}", child.program))?;
    let stdout = process
        .stdout
        .take()
        .context("child stdout")
        .context(Started)?;
    let stderr = process
        .stderr
        .take()
        .context("child stderr")
        .context(Started)?;
    let out = relay(stdout, std::io::stdout(), Redactor::new(values));
    let err = relay(stderr, std::io::stderr(), Redactor::new(values));
    let status = process
        .wait()
        .context("cannot wait for the child")
        .context(Started)?;
    let _ = out.join();
    let _ = err.join();
    Ok(exit_code(status))
}

/// Copies `from` to `to` through `redactor` until end of file.
fn relay<R, W>(mut from: R, mut to: W, mut redactor: Redactor) -> std::thread::JoinHandle<()>
where
    R: Read + Send + 'static,
    W: Write + Send + 'static,
{
    std::thread::spawn(move || {
        let mut buffer = [0u8; 8192];
        loop {
            match from.read(&mut buffer) {
                Ok(0) | Err(_) => break,
                Ok(read) => {
                    let _ = to.write_all(&redactor.feed(&buffer[..read]));
                    let _ = to.flush();
                }
            }
        }
        let _ = to.write_all(&redactor.finish());
        let _ = to.flush();
    })
}

fn terminal(child: &Child<'_>, values: &[String]) -> Result<i32> {
    use portable_pty::{CommandBuilder, PtySize, native_pty_system};

    let (cols, rows) = terminal_size::terminal_size()
        .map(|(width, height)| (width.0, height.0))
        .unwrap_or((80, 24));
    let pair = native_pty_system()
        .openpty(PtySize {
            rows,
            cols,
            pixel_width: 0,
            pixel_height: 0,
        })
        .context("cannot open a pseudo-terminal")?;
    let mut builder = CommandBuilder::new(child.program);
    builder.args(child.arguments);
    builder.cwd(std::env::current_dir().context("cannot read the working directory")?);
    for (name, value) in child.variables {
        builder.env(name, value);
    }
    let mut process = pair
        .slave
        .spawn_command(builder)
        .with_context(|| format!("cannot run {}", child.program))?;
    drop(pair.slave);

    let reader = pair
        .master
        .try_clone_reader()
        .context("cannot read the pseudo-terminal")
        .context(Started)?;
    let mut writer = pair
        .master
        .take_writer()
        .context("cannot write the pseudo-terminal")
        .context(Started)?;
    let output = relay(reader, std::io::stdout(), Redactor::new(values));

    // Keystrokes go to the child unchanged; its own terminal settings decide what they mean.
    let raw = RawMode::enable();
    std::thread::spawn(move || {
        let mut buffer = [0u8; 1024];
        let mut stdin = std::io::stdin();
        while let Ok(read) = stdin.read(&mut buffer) {
            if read == 0 || writer.write_all(&buffer[..read]).is_err() {
                break;
            }
            let _ = writer.flush();
        }
    });

    let status = process
        .wait()
        .context("cannot wait for the child")
        .context(Started)?;
    drop(pair.master);
    let _ = output.join();
    drop(raw);
    Ok(status.exit_code() as i32)
}

/// Puts this process's terminal in raw mode while the child owns the screen.
struct RawMode(Option<nix::sys::termios::Termios>);

impl RawMode {
    fn enable() -> Self {
        use nix::sys::termios::{SetArg, cfmakeraw, tcgetattr, tcsetattr};
        let stdin = std::io::stdin();
        if !stdin.is_terminal() {
            return Self(None);
        }
        let Ok(saved) = tcgetattr(&stdin) else {
            return Self(None);
        };
        let mut raw = saved.clone();
        cfmakeraw(&mut raw);
        if tcsetattr(&stdin, SetArg::TCSANOW, &raw).is_err() {
            return Self(None);
        }
        Self(Some(saved))
    }
}

impl Drop for RawMode {
    fn drop(&mut self) {
        if let Some(saved) = &self.0 {
            let _ = nix::sys::termios::tcsetattr(
                std::io::stdin(),
                nix::sys::termios::SetArg::TCSANOW,
                saved,
            );
        }
    }
}
