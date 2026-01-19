//! Create network command implementation.

use std::path::PathBuf;

use clap::{Parser, ValueEnum};
use color_eyre::eyre::Context;
use tracing::info;

use super::Run;
use felidae_deployer::{Network, NetworkConfig, Platform};

/// Platform options for the CLI.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum CliPlatform {
    /// Local deployment (localhost).
    Local,
    // TODO: consider more platform support, e.g. "systemd" for generating
    // service unit files, maybe a "docker-compose" one.
}

impl From<CliPlatform> for Platform {
    fn from(p: CliPlatform) -> Self {
        match p {
            CliPlatform::Local => Platform::Local,
        }
    }
}

/// Create a new felidae network.
#[derive(Parser)]
pub struct CreateNetwork {
    /// Deployment platform.
    #[arg(long, default_value = "local")]
    pub platform: CliPlatform,

    /// Number of validator nodes.
    #[arg(long, default_value = "1")]
    pub num_validators: usize,

    /// Create sentry nodes for each validator.
    #[arg(long, default_value = "false")]
    pub use_sentries: bool,

    /// Output directory for the network.
    #[arg(long)]
    pub directory: PathBuf,

    /// Chain ID for the network.
    #[arg(long, default_value = "felidae-test")]
    pub chain_id: String,

    /// CometBFT timeout_commit setting (how long to wait after committing a block before starting on the new height).
    /// This effectively controls the block interval. Examples: "1s", "500ms", "2s".
    #[arg(long, alias = "blocks-every", default_value = "1s")]
    pub timeout_commit: String,
}

impl Run for CreateNetwork {
    async fn run(self) -> color_eyre::Result<()> {
        info!(
            "Creating network with {} validators in {:?}",
            self.num_validators, self.directory
        );

        let config = NetworkConfig {
            chain_id: self.chain_id,
            num_validators: self.num_validators,
            use_sentries: self.use_sentries,
            platform: self.platform.into(),
            directory: self.directory.clone(),
            timeout_commit: self.timeout_commit.clone(),
            ..Default::default()
        };

        let mut network = Network::new(config);

        info!("Initializing {} nodes...", network.nodes.len());
        network.initialize()?;

        // Generate process-compose.yaml for optional use with process-compose
        // Always include oracle servers for validators
        let process_compose_config = network.generate_process_compose_config("felidae", None);
        let process_compose_path = self.directory.join("process-compose.yaml");
        std::fs::write(&process_compose_path, &process_compose_config)
            .wrap_err_with(|| format!("failed to write {:?}", process_compose_path))?;
        info!(
            "Generated process-compose config at {:?}",
            process_compose_path
        );

        info!("Network created successfully!");
        info!("Output directory: {:?}", self.directory);
        info!(
            "Network metadata: {:?}",
            self.directory.join("network.json")
        );

        for node in &network.nodes {
            info!(
                "  {} ({}): P2P={}, RPC={}, ABCI={}",
                node.name,
                node.node_id.as_deref().unwrap_or("unknown"),
                node.ports.cometbft_p2p,
                node.ports.cometbft_rpc,
                node.ports.felidae_abci
            );
        }

        println!("\nTo run with process-compose:");
        println!("  cd {} && process-compose up", self.directory.display());
        println!("\nOr run directly with felidae-deployer:");
        println!(
            "  felidae-deployer run-network --directory {} --dev",
            self.directory.display()
        );

        Ok(())
    }
}
