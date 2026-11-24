//! `veil mcp`: a scoped MCP front end for an agent, on stdio.
//!
//! The agent's host starts it with the scope written in the agent's configuration:
//!
//! - `veil_list` returns the references in scope, never values.
//! - `veil_exec` runs a command with references delivered as environment variables and returns
//!   its output, redacted, so values do not enter the agent's context.
//! - `veil_reveal` returns a value; it exists only with `--allow-reveal`.
//!
//! Veil does not decide whether its caller is an agent: this is one more way to compose
//! commands. A Vault's approval policy still applies to every delivery.

use std::{
    collections::BTreeMap,
    io::{BufRead, Write},
};

use anyhow::{Context, Result, bail};
use serde_json::{Value, json};
use veil_core::Reference;
use veil_proto::Destination;

use crate::{exec, vaults::Opened};

/// What `veil mcp` was asked to do.
pub struct Options {
    /// Reference patterns the agent may use.
    pub allow: Vec<String>,
    /// Offer `veil_reveal`.
    pub allow_reveal: bool,
}

/// The latest MCP revision this server speaks.
const PROTOCOL: &str = "2025-06-18";

/// Runs `veil mcp` until stdin closes.
pub fn run(options: Options) -> Result<()> {
    let scope = Scope::new(&options.allow)?;
    // Fail at start, not on the first call, when this machine cannot read anything.
    Opened::load()?;
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    for line in stdin.lock().lines() {
        let line = line.context("cannot read from the MCP client")?;
        if line.trim().is_empty() {
            continue;
        }
        let Ok(request) = serde_json::from_str::<Value>(&line) else {
            write(&mut stdout, &error(Value::Null, -32700, "parse error"))?;
            continue;
        };
        let Some(id) = request.get("id").cloned() else {
            continue; // a notification: nothing to answer
        };
        let method = request["method"].as_str().unwrap_or_default();
        let response = match method {
            "initialize" => result(
                id,
                json!({
                    "protocolVersion": request["params"]["protocolVersion"].as_str().unwrap_or(PROTOCOL),
                    "capabilities": { "tools": {} },
                    "serverInfo": { "name": "veil", "version": env!("CARGO_PKG_VERSION") },
                }),
            ),
            "ping" => result(id, json!({})),
            "tools/list" => result(id, json!({ "tools": tools(options.allow_reveal) })),
            "tools/call" => {
                let name = request["params"]["name"].as_str().unwrap_or_default();
                let arguments = &request["params"]["arguments"];
                let outcome = match name {
                    "veil_list" => list(&scope),
                    "veil_exec" => execute(&scope, arguments),
                    "veil_reveal" if options.allow_reveal => reveal(&scope, arguments),
                    other => Err(anyhow::anyhow!("no tool named {other}")),
                };
                result(
                    id,
                    match outcome {
                        Ok(text) => {
                            json!({ "content": [{ "type": "text", "text": text }], "isError": false })
                        }
                        Err(error) => json!({
                            "content": [{ "type": "text", "text": format!("{error:#}") }],
                            "isError": true,
                        }),
                    },
                )
            }
            other => error(id, -32601, &format!("no method {other}")),
        };
        write(&mut stdout, &response)?;
    }
    Ok(())
}

fn tools(reveal: bool) -> Vec<Value> {
    let mut tools = vec![
        json!({
            "name": "veil_list",
            "description": "List the veil:// references you may use. Returns names, never values.",
            "inputSchema": { "type": "object", "properties": {} },
        }),
        json!({
            "name": "veil_exec",
            "description": "Run a command with secrets delivered as environment variables. \
                The output comes back with every delivered value replaced by [redacted].",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "command": { "type": "array", "items": { "type": "string" },
                        "description": "Program and arguments, e.g. [\"curl\", \"-H\", \"Authorization: Bearer $TOKEN\", \"…\"] run through sh -c if you need expansion" },
                    "env": { "type": "object", "additionalProperties": { "type": "string" },
                        "description": "Variable name to veil:// reference" },
                },
                "required": ["command"],
            },
        }),
    ];
    if reveal {
        tools.push(json!({
            "name": "veil_reveal",
            "description": "Return the value of one veil:// reference.",
            "inputSchema": {
                "type": "object",
                "properties": { "reference": { "type": "string" } },
                "required": ["reference"],
            },
        }));
    }
    tools
}

fn list(scope: &Scope) -> Result<String> {
    let opened = Opened::load()?;
    let mut references = Vec::new();
    for vault in opened.view.vaults() {
        for item in opened.view.items_in(vault.row.id) {
            for field in item.item.field_names() {
                let reference = Reference::new(&vault.name, item.item.name(), &field)?;
                if scope.allows(&reference) {
                    references.push(reference.to_string());
                }
            }
        }
    }
    Ok(references.join("\n"))
}

fn execute(scope: &Scope, arguments: &Value) -> Result<String> {
    let command: Vec<String> = serde_json::from_value(arguments["command"].clone())
        .context("command must be an array of strings")?;
    let (program, rest) = command.split_first().context("command is empty")?;
    let env: BTreeMap<String, String> = match arguments.get("env") {
        Some(env) if !env.is_null() => {
            serde_json::from_value(env.clone()).context("env must map names to references")?
        }
        _ => BTreeMap::new(),
    };
    let mut wanted = BTreeMap::new();
    for (name, reference) in env {
        let reference: Reference = reference
            .parse()
            .with_context(|| format!("{name}: not a veil:// reference"))?;
        if !scope.allows(&reference) {
            bail!("{reference} is outside the scope this agent was given");
        }
        wanted.insert(name, reference);
    }

    let mut opened = Opened::load()?;
    let resolved = opened.view.resolve_all(&wanted)?;
    let released = opened.release(
        &resolved.values().collect::<Vec<_>>(),
        Destination::Inject,
        &command.join(" "),
    )?;
    let variables: Vec<(String, String)> = resolved
        .iter()
        .map(|(name, resolved)| (name.clone(), resolved.value(&released).to_owned()))
        .collect();
    let (code, stdout, stderr) = exec::capture(&exec::Child {
        program,
        arguments: rest,
        variables: &variables,
        redact: Some(variables.iter().map(|(_, value)| value.clone()).collect()),
    })?;
    Ok(format!(
        "exit code {code}\n--- stdout\n{}\n--- stderr\n{}",
        String::from_utf8_lossy(&stdout),
        String::from_utf8_lossy(&stderr)
    ))
}

fn reveal(scope: &Scope, arguments: &Value) -> Result<String> {
    let reference: Reference = arguments["reference"]
        .as_str()
        .context("reference is required")?
        .parse()
        .context("not a veil:// reference")?;
    if !scope.allows(&reference) {
        bail!("{reference} is outside the scope this agent was given");
    }
    let mut opened = Opened::load()?;
    let resolved = opened.view.resolve(&reference)?;
    let released = opened.release(
        &[&resolved],
        Destination::Print,
        &format!("veil_reveal {reference}"),
    )?;
    Ok(resolved.value(&released).to_owned())
}

/// The references an agent may use: `veil://vault/item/field` patterns where `*` matches any
/// part of one segment, and a final `*` segment matches everything below it.
struct Scope(Vec<Vec<String>>);

impl Scope {
    fn new(patterns: &[String]) -> Result<Self> {
        let mut parsed = Vec::new();
        for pattern in patterns {
            let rest = pattern
                .strip_prefix("veil://")
                .with_context(|| format!("{pattern} is not a veil:// pattern"))?;
            let segments: Vec<String> = rest.split('/').map(str::to_owned).collect();
            if segments.is_empty() || segments.len() > 3 || segments.iter().any(String::is_empty) {
                bail!(
                    "{pattern} must look like veil://vault/item/field, with * where any part goes"
                );
            }
            parsed.push(segments);
        }
        Ok(Self(parsed))
    }

    fn allows(&self, reference: &Reference) -> bool {
        let parts = [&reference.vault, &reference.item, &reference.field];
        self.0.iter().any(|pattern| {
            parts
                .iter()
                .enumerate()
                .all(|(index, part)| match pattern.get(index) {
                    Some(segment) => glob(segment, part),
                    None => pattern.last().is_some_and(|last| last == "*"),
                })
        })
    }
}

/// `*` matches any run of characters.
fn glob(pattern: &str, text: &str) -> bool {
    match pattern.split_once('*') {
        None => pattern == text,
        Some((prefix, rest)) => {
            let Some(remaining) = text.strip_prefix(prefix) else {
                return false;
            };
            (0..=remaining.len())
                .filter(|cut| remaining.is_char_boundary(*cut))
                .any(|cut| glob(rest, &remaining[cut..]))
        }
    }
}

fn result(id: Value, result: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

fn error(id: Value, code: i64, message: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
}

fn write(stdout: &mut std::io::Stdout, message: &Value) -> Result<()> {
    writeln!(stdout, "{message}").context("cannot write to the MCP client")?;
    stdout.flush().context("cannot write to the MCP client")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reference(text: &str) -> Reference {
        text.parse().expect("reference")
    }

    #[test]
    fn a_vault_wildcard_covers_everything_in_it() {
        let scope = Scope::new(&["veil://example/*".to_owned()]).expect("scope");
        assert!(scope.allows(&reference("veil://example/demo-service/password")));
        assert!(!scope.allows(&reference("veil://admin/root/password")));
    }

    #[test]
    fn segments_match_exactly_or_by_glob() {
        let scope = Scope::new(&["veil://example/*-service/password".to_owned()]).expect("scope");
        assert!(scope.allows(&reference("veil://example/demo-service/password")));
        assert!(!scope.allows(&reference("veil://example/demo-service/username")));
        assert!(!scope.allows(&reference("veil://example/example_app/password")));
        let exact = Scope::new(&["veil://a/b/c".to_owned()]).expect("scope");
        assert!(exact.allows(&reference("veil://a/b/c")));
        assert!(!exact.allows(&reference("veil://a/b/cd")));
    }

    #[test]
    fn malformed_patterns_are_refused() {
        assert!(Scope::new(&["example/*".to_owned()]).is_err());
        assert!(Scope::new(&["veil://a//b".to_owned()]).is_err());
        assert!(Scope::new(&["veil://a/b/c/d".to_owned()]).is_err());
    }
}
