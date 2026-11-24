//! `veild` entry point.
//!
//! Startup order is fixed: parse arguments, resolve configuration, install logging, bind,
//! serve. Failures before logging is installed are reported on stderr; after that they are
//! reported as structured log records.

use std::{path::PathBuf, process::ExitCode};

use anyhow::Context;
use clap::Parser;

use veil_daemon::{
    app,
    config::{Config, Overrides},
    store::Store,
    telemetry,
};

/// Exit code for an unusable configuration (`EX_CONFIG` from `sysexits.h`).
const EXIT_CONFIG: u8 = 78;

/// Veil daemon.
#[derive(Debug, Parser)]
#[command(name = "veild", version, about = "Veil daemon", long_about = None)]
struct Args {
    /// Path to a TOML configuration file.
    #[arg(long, global = true, env = "VEIL_CONFIG", value_name = "PATH")]
    config: Option<PathBuf>,

    /// Listen address, for example `0.0.0.0:8080`. Overrides `VEIL_BIND` and the file.
    #[arg(long, value_name = "ADDR")]
    bind: Option<String>,

    /// Tracing filter, for example `info` or `veil_daemon=debug`. Overrides `VEIL_LOG`.
    #[arg(long, value_name = "FILTER")]
    log: Option<String>,

    /// Database path. Overrides `VEIL_DB`.
    #[arg(long, global = true, value_name = "PATH")]
    db: Option<PathBuf>,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, clap::Subcommand)]
enum Command {
    /// Write a consistent snapshot of the database to a new file, while the service runs.
    ///
    /// To restore, stop veild, replace the database file with the snapshot (and remove its
    /// `-wal` and `-shm` files), and start veild again.
    Backup {
        /// The snapshot file to create; it must not exist.
        to: PathBuf,
    },
}

#[tokio::main]
async fn main() -> ExitCode {
    let args = Args::parse();
    let overrides = Overrides {
        config_file: args.config.clone(),
        bind: args.bind.clone(),
        log: args.log.clone(),
        db: args.db.clone(),
    };

    let config = match Config::resolve(&overrides) {
        Ok(config) => config,
        Err(err) => {
            eprintln!("veild: {err}");
            return ExitCode::from(EXIT_CONFIG);
        }
    };

    if let Some(Command::Backup { to }) = args.command {
        return match backup(&config.db, &to) {
            Ok(()) => {
                println!("wrote {}", to.display());
                ExitCode::SUCCESS
            }
            Err(err) => {
                eprintln!("veild: {err:#}");
                ExitCode::FAILURE
            }
        };
    }

    match serve(config).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            tracing::error!(error = format!("{err:#}"), "server stopped with an error");
            ExitCode::FAILURE
        }
    }
}

/// Snapshots the database at `db` into `to`. A missing database is an error rather than a new,
/// empty one, so a wrong path cannot produce a backup of nothing.
fn backup(db: &std::path::Path, to: &std::path::Path) -> anyhow::Result<()> {
    anyhow::ensure!(db.exists(), "no database at {}", db.display());
    let store = Store::open(db).with_context(|| format!("cannot open {}", db.display()))?;
    store
        .backup(to)
        .with_context(|| format!("cannot write {}", to.display()))
}

async fn serve(config: Config) -> anyhow::Result<()> {
    telemetry::init(&config.log).context("cannot initialize logging")?;

    let store =
        Store::open(&config.db).with_context(|| format!("cannot open {}", config.db.display()))?;
    let state = app::AppState {
        trusted_proxies: config.trusted_proxies,
        ..app::AppState::new(store)
    };

    tracing::info!(
        service = app::SERVICE_NAME,
        version = app::VERSION,
        commit = app::COMMIT,
        bind = %config.bind,
        config_file = config.source_file.as_ref().map(tracing::field::debug),
        db = %config.db.display(),
        "starting",
    );

    let listener = tokio::net::TcpListener::bind(config.bind)
        .await
        .with_context(|| format!("cannot bind {}", config.bind))?;
    tracing::info!(addr = %listener.local_addr()?, "listening on http");

    axum::serve(
        listener,
        app::router(state).into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
    .context("HTTP server failed")?;

    tracing::info!("shutdown complete");
    Ok(())
}

/// Resolves on `SIGINT` or `SIGTERM`, so container stop and `Ctrl-C` drain identically.
async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(err) = tokio::signal::ctrl_c().await {
            tracing::error!(error = %err, "cannot listen for SIGINT");
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(err) => tracing::error!(error = %err, "cannot listen for SIGTERM"),
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => tracing::info!("SIGINT received, draining"),
        () = terminate => tracing::info!("SIGTERM received, draining"),
    }
}
