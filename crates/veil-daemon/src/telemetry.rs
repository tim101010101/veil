//! Logging setup.
//!
//! One subscriber, structured JSON on stderr. stdout stays free so the process can be used
//! in pipelines and so log collection is not mixed with program output.
//!
//! OpenTelemetry export (traces, metrics) is the next infrastructure step; when it lands,
//! this module owns the provider setup and shutdown flush, and log records carry
//! `trace_id`/`span_id`.

use thiserror::Error;
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

/// Why logging could not be initialized.
#[derive(Debug, Error)]
pub enum TelemetryError {
    /// The filter expression is invalid.
    #[error("invalid log filter: {0}")]
    Filter(#[from] tracing_subscriber::filter::ParseError),
    /// A global subscriber is already installed.
    #[error("logging already initialized: {0}")]
    Init(#[from] tracing_subscriber::util::TryInitError),
}

/// Installs the process-wide tracing subscriber.
pub fn init(filter: &str) -> Result<(), TelemetryError> {
    let filter = EnvFilter::try_new(filter)?;
    let layer = fmt::layer()
        .json()
        .with_writer(std::io::stderr)
        .with_current_span(true)
        .with_span_list(true);

    tracing_subscriber::registry()
        .with(filter)
        .with(layer)
        .try_init()?;
    Ok(())
}
