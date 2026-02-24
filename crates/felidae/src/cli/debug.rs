use super::Run;

mod compare_state;

#[derive(clap::Subcommand)]
pub enum Debug {
    /// Compare felidae JMT state between two storage directories (e.g. after a halt).
    CompareState(compare_state::CompareState),
}

impl Run for Debug {
    async fn run(self) -> color_eyre::Result<()> {
        match self {
            Self::CompareState(cmd) => cmd.run().await,
        }
    }
}
