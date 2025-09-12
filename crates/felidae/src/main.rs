use clap::Parser as _;

use crate::cli::Run as _;

mod cli;

#[tokio::main]
async fn main() -> color_eyre::Result<()> {
    tracing_subscriber::fmt().init();
    cli::Options::parse().run().await
}
