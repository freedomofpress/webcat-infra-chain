use super::Run;

mod compare_state;
mod key_convert;

#[derive(clap::Subcommand)]
pub enum Debug {
    /// Compare felidae JMT state between two storage directories (e.g. after a halt).
    CompareState(compare_state::CompareState),
    /// Convert an Ed25519 public key between CometBFT (base64) and felidae (hex) formats.
    ConvertKey(key_convert::ConvertKey),
}

impl Run for Debug {
    async fn run(self) -> color_eyre::Result<()> {
        match self {
            Self::CompareState(cmd) => cmd.run().await,
            Self::ConvertKey(cmd) => cmd.run().await,
        }
    }
}
