use clap::Parser;

#[derive(Parser)]
pub enum Options {
    Start(start::Start),
}

// One module per top-level subcommand
mod start;

pub trait Run {
    fn run(self) -> impl Future<Output = color_eyre::Result<()>> + Send;
}

impl Run for Options {
    async fn run(self) -> color_eyre::Result<()> {
        match self {
            Self::Start(start) => start.run().await,
        }
    }
}
