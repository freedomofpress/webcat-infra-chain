use super::Run;

mod compare_state;
mod key_convert;
mod parse_config;

#[derive(clap::Subcommand)]
pub enum Debug {
    /// Compare felidae JMT state between two storage directories (e.g. after a halt).
    CompareState(compare_state::CompareState),
    /// Convert an Ed25519 public key between CometBFT (base64) and felidae (hex) formats.
    ConvertKey(key_convert::ConvertKey),
    /// Validate config(s) under strict domain-type parsing (upgrade pre-flight).
    ParseConfig(parse_config::ParseConfig),
}

impl Run for Debug {
    async fn run(self) -> color_eyre::Result<()> {
        match self {
            Self::CompareState(cmd) => cmd.run().await,
            Self::ConvertKey(cmd) => cmd.run().await,
            Self::ParseConfig(cmd) => cmd.run().await,
        }
    }
}
