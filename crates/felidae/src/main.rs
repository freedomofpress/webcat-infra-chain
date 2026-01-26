#[macro_use]
extern crate tracing;

use clap::Parser as _;
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt as _, util::SubscriberInitExt as _};

use crate::cli::Run as _;

mod cli;

#[tokio::main]
async fn main() -> color_eyre::Result<()> {
    color_eyre::install()?;
    // The `EnvFilter` layer is used to filter events based on `RUST_LOG`.
    let filter_layer: EnvFilter =
        EnvFilter::try_from_default_env().or_else(|_| EnvFilter::try_new("info"))?;
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .with(filter_layer)
        .init();
    cli::Options::parse().run().await
}
