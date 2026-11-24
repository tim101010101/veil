use anyhow::Result;
use veil_cli::{
    github::ReleaseSource,
    update::{self, Installation},
};

use crate::{diagnostic::Failure, ui};

pub struct Options {
    pub check: bool,
    pub version: Option<String>,
    pub allow_downgrade: bool,
    pub json: bool,
}

pub fn run(options: Options) -> Result<()> {
    execute(options).map_err(|error| {
        if error.downcast_ref::<Failure>().is_some() { error } else {
            Failure::new("upgrade_failed", 1, format!("{error:#}"),
                "No update was activated. Use the original installation method or check the release configuration; never bypass signature verification.").into()
        }
    })
}

fn execute(options: Options) -> Result<()> {
    let target = update::platform()?;
    let current = env!("CARGO_PKG_VERSION");
    if let Some(version) = &options.version {
        update::select_version(current, version, true, options.allow_downgrade)?;
    }
    let installation = Installation::inspect(&std::env::current_exe()?, current, &target)?;
    let trust = update::trust()?;
    let source = ReleaseSource::configured()?;
    let explicit = options.version.is_some();
    let requested = match options.version {
        Some(version) => version,
        None => source.latest_tag()?,
    };
    let version =
        update::select_version(current, &requested, explicit, options.allow_downgrade)?.to_string();
    let delegation = source.asset(&version, "release-key.json", 4096)?;
    let delegation_signature = source.asset(&version, "release-key.sig", 1024)?;
    let (key, _) = trust.release_key(&delegation, &delegation_signature, jiff::Timestamp::now())?;
    let manifest_bytes = source.asset(&version, "manifest.json", update::MAX_MANIFEST)?;
    let signature = source.asset(&version, "manifest.sig", 1024)?;
    let manifest = update::verify_manifest(&manifest_bytes, &signature, &key, &version)?;
    let artifact = update::artifact(&manifest, &target)?;
    let available = version != current;
    let protocol_changed = manifest.protocol != veil_proto::PROTOCOL_VERSION;
    if options.json && (options.check || !available) {
        println!(
            "{}",
            serde_json::json!({"current": current, "version": version, "available": available, "target": target, "launcher": installation.launcher, "checked": true, "protocol_changed": protocol_changed})
        );
    } else if !options.json {
        println!(
            "Current  {current}\nTarget   {version} ({target})\nPath     {}\nSource   Veil installer",
            ui::safe(&installation.launcher.display().to_string())
        );
    }
    if protocol_changed {
        ui::notice(
            "warning",
            format!(
                "Release protocol {} differs from this build's {}. Verify service compatibility; the service will not be updated.",
                manifest.protocol,
                veil_proto::PROTOCOL_VERSION
            ),
        );
    }
    if options.check || !available {
        if !options.json {
            println!(
                "{}",
                if available {
                    "Update available. Run veil upgrade to install."
                } else {
                    "Already at the requested version."
                }
            );
        }
        return Ok(());
    }
    let lock = installation.lock()?;
    installation.check_launcher()?;
    ui::notice(
        "progress",
        "Downloading and verifying the signed release archive",
    );
    let archive = source.asset(&version, &artifact.file, artifact.size)?;
    let release = update::verify_release(
        &manifest_bytes,
        &signature,
        &key,
        &version,
        &target,
        &archive,
    )?;
    let activation = installation.activate(&release, &lock)?;
    if !activation.durable {
        ui::notice(
            "warning",
            "The new version is active, but syncing the launcher directory failed. Power-loss durability is not confirmed; the previous version directory is retained.",
        );
    }
    if options.json {
        println!(
            "{}",
            serde_json::json!({"updated": true, "previous": current, "version": version, "launcher": installation.launcher, "executable": activation.executable, "previous_executable": installation.executable, "durable": activation.durable})
        );
    } else {
        ui::success(format!("Veil {version} is active"));
        println!(
            "Updated {current} to {version}. Previous binary retained at {}",
            ui::safe(&installation.executable.display().to_string())
        );
    }
    Ok(())
}
