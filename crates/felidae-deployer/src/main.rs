use clap::Parser as _;
use std::io::IsTerminal as _;
use tracing_subscriber::{EnvFilter, layer::SubscriberExt as _, util::SubscriberInitExt as _};

use crate::cli::Run as _;

mod cli;

#[tokio::main]
async fn main() -> color_eyre::Result<()> {
    color_eyre::install()?;
    // Instantiate tracing layers.
    // The `FmtLayer` is used to print to the console,
    // colorizing only if we're in a tty.
    let fmt_layer = tracing_subscriber::fmt::layer()
        .with_ansi(std::io::stdout().is_terminal())
        .with_writer(std::io::stderr)
        .with_target(true);
    // The `EnvFilter` layer is used to filter events based on `RUST_LOG`.
    let filter_layer = EnvFilter::try_from_default_env().or_else(|_| EnvFilter::try_new("info"))?;
    // Register the tracing subscribers.
    let registry = tracing_subscriber::registry()
        .with(filter_layer)
        .with(fmt_layer);
    registry.init();
    cli::Options::parse().run().await
}
