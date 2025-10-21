use clap::Parser;

#[derive(Parser)]
pub enum Options {
    /// Start this Felidae node.
    Start(start::Start),
    /// Reset this Felidae node.
    Reset(reset::Reset),
    /// Administer the Felidae network.
    #[command(subcommand)]
    Admin(admin::Admin),
}

// One module per top-level subcommand
mod admin;
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
            Self::Admin(admin) => admin.run().await,
        }
    }
}
