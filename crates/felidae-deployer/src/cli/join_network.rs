//! Join network command implementation.

use std::path::PathBuf;

use clap::Parser;
use tracing::info;
use url::Url;

use super::Run;
use felidae_deployer::join::{self, GenesisSource, JoinConfig, PeerSource};

/// Join an existing felidae network by bootstrapping a new node from an
/// authoritative genesis file.
///
/// Genesis must always be provided via --genesis-file or --genesis-url to
/// ensure byte-for-byte integrity. The CometBFT RPC cannot be used as a
/// genesis source because it re-serializes the JSON, which would cause
/// AppHash mismatches.
///
/// Peers can be provided explicitly with --peer, or auto-discovered from
/// a CometBFT RPC endpoint with --cometbft-url. These options are mutually
/// exclusive.
///
/// Examples:
///   felidae-deployer join-network --genesis-file genesis.json --peer <ID@HOST:PORT> --directory <DIR>
///   felidae-deployer join-network --genesis-url <URL> --cometbft-url <RPC> --directory <DIR>
#[derive(Parser)]
pub struct JoinNetwork {
    /// Path to a local genesis.json file.
    #[arg(long, group = "genesis_source")]
    pub genesis_file: Option<PathBuf>,

    /// URL pointing to a raw genesis JSON file to fetch.
    /// The response body is used byte-for-byte.
    #[arg(long, group = "genesis_source")]
    pub genesis_url: Option<Url>,

    /// CometBFT JSON-RPC URL for auto-discovering peers (e.g. http://127.0.0.1:26657).
    /// Only used for peer discovery (via /status and /net_info), not for genesis.
    #[arg(long, group = "peer_source")]
    pub cometbft_url: Option<Url>,

    /// CometBFT persistent peer address (node_id@host:port).
    /// May be specified multiple times.
    #[arg(long, group = "peer_source")]
    pub peer: Vec<String>,

    /// Output directory for the new node's configuration.
    #[arg(long)]
    pub directory: PathBuf,

    /// Automatically find free ports instead of using defaults.
    /// Useful when joining a network running on the same host.
    #[arg(long, default_value = "false")]
    pub find_free_ports: bool,

    /// Name/moniker for the new node.
    #[arg(long, default_value = "fullnode-0")]
    pub node_name: String,

    /// Emit output as JSON.
    #[clap(long)]
    pub json: bool,
}

impl Run for JoinNetwork {
    async fn run(self) -> color_eyre::Result<()> {
        // Resolve genesis source — always required.
        let genesis_source = match (self.genesis_file, self.genesis_url) {
            (Some(path), None) => GenesisSource::File(path),
            (None, Some(url)) => GenesisSource::Url(url),
            (None, None) => {
                return Err(color_eyre::eyre::eyre!(
                    "one of --genesis-file or --genesis-url is required"
                ));
            }
            _ => {
                return Err(color_eyre::eyre::eyre!(
                    "--genesis-file and --genesis-url are mutually exclusive"
                ));
            }
        };

        // Resolve peer source — exactly one of --cometbft-url or --peer is required.
        let peer_source = match (self.cometbft_url, self.peer.is_empty()) {
            (Some(url), _) => PeerSource::CometbftRpc(url),
            (None, false) => PeerSource::Explicit(self.peer),
            (None, true) => {
                return Err(color_eyre::eyre::eyre!(
                    "one of --peer or --cometbft-url is required for peer discovery"
                ));
            }
        };

        info!(
            directory = %self.directory.display(),
            find_free_ports = self.find_free_ports,
            "joining network"
        );

        if self.directory.exists() {
            let entries = std::fs::read_dir(&self.directory)?;
            if entries.count() > 0 {
                return Err(color_eyre::eyre::eyre!(
                    "directory {:?} already exists and is not empty",
                    self.directory
                ));
            }
        }

        let config = JoinConfig {
            genesis_source,
            peer_source,
            directory: self.directory.clone(),
            find_free_ports: self.find_free_ports,
            node_name: self.node_name,
        };

        let node = join::join_network(config).await?;

        info!("node config written successfully");

        if self.json {
            println!("{}", serde_json::to_string(&node)?);
        } else {
            println!("\nNode bootstrapped at: {}", self.directory.display());
            println!(
                "  Node ID:  {}",
                node.node_id.as_deref().unwrap_or("unknown")
            );
            println!("  P2P port: {}", node.ports.cometbft_p2p);
            println!("  RPC port: {}", node.ports.cometbft_rpc);
            println!("  ABCI port: {}", node.ports.felidae_abci);
            println!();
            println!("To start CometBFT:");
            println!("  cometbft start --home {}", node.cometbft_home().display());
            println!();
            println!("To start felidae:");
            println!(
                "  felidae start --abci-bind {}:{} --query-bind {}:{} --homedir {}",
                node.bind_address,
                node.ports.felidae_abci,
                node.bind_address,
                node.ports.felidae_query,
                node.felidae_home().display(),
            );
        }

        Ok(())
    }
}
