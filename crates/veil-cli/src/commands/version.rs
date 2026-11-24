//! `veil version`: build information for this binary.
//!
//! The version is the release unit version, shared with the server and every crate in the
//! workspace. `commit` is present only when the build recorded `VEIL_BUILD_COMMIT`.

use anyhow::Context;
use serde::Serialize;

const NAME: &str = "veil";
const VERSION: &str = env!("CARGO_PKG_VERSION");
const COMMIT: Option<&str> = option_env!("VEIL_BUILD_COMMIT");

#[derive(Debug, Serialize)]
struct BuildInfo {
    name: &'static str,
    version: &'static str,
    commit: Option<&'static str>,
}

/// Prints the build information.
pub fn run(json: bool) -> anyhow::Result<()> {
    let info = BuildInfo {
        name: NAME,
        version: VERSION,
        commit: COMMIT,
    };

    if json {
        let encoded = serde_json::to_string_pretty(&info).context("cannot encode build info")?;
        println!("{encoded}");
    } else {
        println!("{} {VERSION}", info.name);
        if let Some(commit) = info.commit {
            println!("commit {commit}");
        }
    }
    Ok(())
}
