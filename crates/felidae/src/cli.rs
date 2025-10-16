use clap::Parser;

#[derive(Parser)]
pub enum Options {
    Start(start::Start),
    Reset(reset::Reset),
}

// One module per top-level subcommand
mod reset;
mod start;

pub trait Run {
    fn run(self) -> impl Future<Output = color_eyre::Result<()>> + Send;
}

impl Run for Options {
    async fn run(self) -> color_eyre::Result<()> {
        match self {
            Self::Start(start) => start.run().await,
            Self::Reset(reset) => reset.run().await,
        }
    }
}
