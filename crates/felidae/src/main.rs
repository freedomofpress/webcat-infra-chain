#[macro_use]
extern crate tracing;

use clap::Parser as _;

use crate::cli::Run as _;

mod cli;

#[tokio::main]
async fn main() -> color_eyre::Result<()> {
    tracing_subscriber::fmt().init();
    color_eyre::install()?;
    tracing::debug!("Starting application");
    cli::Options::parse().run().await
}
