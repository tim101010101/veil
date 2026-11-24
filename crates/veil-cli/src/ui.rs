use std::io::{self, IsTerminal, Write};
use std::sync::OnceLock;

use anyhow::{Context, Result};
use clap::ValueEnum;

#[derive(Clone, Copy, Debug, Default, ValueEnum)]
pub enum Color {
    #[default]
    Auto,
    Always,
    Never,
}

#[derive(Default)]
pub struct Output {
    pub json: bool,
    pub no_input: bool,
    pub color: Color,
}

static OUTPUT: OnceLock<Output> = OnceLock::new();

pub fn init(output: Output) {
    let _ = OUTPUT.set(output);
}

pub fn output() -> &'static Output {
    OUTPUT.get_or_init(Output::default)
}

pub fn color() -> bool {
    match output().color {
        Color::Always => true,
        Color::Never => false,
        Color::Auto => {
            io::stderr().is_terminal()
                && std::env::var_os("NO_COLOR").is_none()
                && std::env::var("TERM").as_deref() != Ok("dumb")
        }
    }
}

pub fn safe(text: &str) -> String {
    text.chars()
        .flat_map(|c| {
            if c.is_control() || matches!(c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}') {
                c.escape_default().collect::<Vec<_>>()
            } else {
                vec![c]
            }
        })
        .collect()
}

pub fn notice(level: &str, message: impl AsRef<str>) {
    if output().json {
        eprintln!(
            "{}",
            serde_json::json!({"type": level, "message": message.as_ref()})
        );
    } else {
        eprintln!("{level}: {}", safe(message.as_ref()));
    }
}

pub fn success(message: impl AsRef<str>) {
    if !output().json && io::stderr().is_terminal() {
        notice("done", message);
    }
}

pub fn interactive() -> bool {
    !output().no_input && !output().json && io::stdin().is_terminal() && io::stderr().is_terminal()
}

pub fn require_input(hint: &str) -> Result<()> {
    if !interactive() {
        return Err(crate::diagnostic::Failure::new(
            "input_required",
            4,
            "Interactive input is unavailable.",
            hint,
        )
        .into());
    }
    Ok(())
}

pub fn secret(prompt: &str, hint: &str) -> Result<String> {
    require_input(hint)?;
    rpassword::prompt_password(format!("{}: ", safe(prompt)))
        .context("cannot read the secret input")
}

pub fn confirm(prompt: &str, yes: bool, hint: &str) -> Result<()> {
    if yes {
        return Ok(());
    }
    require_input(hint)?;
    eprint!("{} [y/N] ", safe(prompt));
    io::stderr().flush()?;
    let mut answer = String::new();
    io::stdin().read_line(&mut answer)?;
    if matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
        Ok(())
    } else {
        Err(crate::diagnostic::Failure::new(
            "confirmation_declined",
            4,
            "Operation cancelled; no change was authorized.",
            "",
        )
        .into())
    }
}

pub fn table(headers: &[&str], rows: &[Vec<String>], empty: &str) {
    if rows.is_empty() {
        if io::stdout().is_terminal() {
            println!("{}", safe(empty));
        }
        return;
    }
    let rows: Vec<Vec<String>> = rows
        .iter()
        .map(|row| row.iter().map(|v| safe(v)).collect())
        .collect();
    if !io::stdout().is_terminal() {
        for row in rows {
            println!("{}", row.join("\t"));
        }
        return;
    }
    let columns = terminal_size::terminal_size().map_or(80, |(width, _)| usize::from(width.0));
    let max_width =
        (columns.saturating_sub(headers.len().saturating_sub(1) * 2) / headers.len()).clamp(4, 48);
    let widths: Vec<usize> = headers
        .iter()
        .enumerate()
        .map(|(i, h)| {
            rows.iter()
                .map(|row| row[i].chars().count())
                .max()
                .unwrap_or(0)
                .max(h.len())
                .min(max_width)
        })
        .collect();
    let print_row = |row: &[String]| {
        let fields: Vec<String> = row
            .iter()
            .zip(&widths)
            .map(|(cell, width)| {
                let cell = if cell.chars().count() > *width {
                    format!(
                        "{}…",
                        cell.chars()
                            .take(width.saturating_sub(1))
                            .collect::<String>()
                    )
                } else {
                    cell.clone()
                };
                let padding = width.saturating_sub(cell.chars().count());
                format!("{cell}{}", " ".repeat(padding))
            })
            .collect();
        println!("{}", fields.join("  ").trim_end());
    };
    print_row(&headers.iter().map(|v| (*v).to_owned()).collect::<Vec<_>>());
    for row in rows {
        print_row(&row);
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn terminal_controls_are_data_not_instructions() {
        assert_eq!(
            super::safe("ok\n\x1b[31m\u{202e}"),
            "ok\\n\\u{1b}[31m\\u{202e}"
        );
    }
}
