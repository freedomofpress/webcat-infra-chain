//! Node types for webcat networks.

use std::net::IpAddr;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::ports::NodePorts;

/// The role of a node in the network.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NodeRole {
    /// A validator node that participates in consensus.
    Validator,
    /// A sentry node that shields validators from direct exposure.
    Sentry,
    /// A full node that does not participate in consensus.
    FullNode,
}

impl NodeRole {
    /// Returns true if this node is a validator.
    pub fn is_validator(&self) -> bool {
        matches!(self, Self::Validator)
    }

    /// Returns the directory prefix for this role.
    pub fn dir_prefix(&self) -> &'static str {
        match self {
            Self::Validator => "validator",
            Self::Sentry => "sentry",
            Self::FullNode => "fullnode",
        }
    }
}

/// A node in a webcat network.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebcatNode {
    /// The unique name of this node (e.g., "validator-0", "sentry-1").
    pub name: String,
    /// The role of this node.
    pub role: NodeRole,
    /// The ports allocated to this node.
    pub ports: NodePorts,
    /// The home directory for this node's data.
    pub home_dir: PathBuf,
    /// The bind address for this node's services.
    pub bind_address: IpAddr,
    /// The CometBFT node ID (populated after initialization).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node_id: Option<String>,
}

impl WebcatNode {
    /// Create a new node with the given parameters.
    pub fn new(name: String, role: NodeRole, ports: NodePorts, home_dir: PathBuf) -> Self {
        Self {
            name,
            role,
            ports,
            home_dir,
            bind_address: "127.0.0.1".parse().unwrap(),
            node_id: None,
        }
    }

    /// Get the path to the CometBFT home directory.
    pub fn cometbft_home(&self) -> PathBuf {
        self.home_dir.join("cometbft")
    }

    /// Get the path to the CometBFT config directory.
    pub fn cometbft_config_dir(&self) -> PathBuf {
        self.cometbft_home().join("config")
    }

    /// Get the path to the CometBFT data directory.
    pub fn cometbft_data_dir(&self) -> PathBuf {
        self.cometbft_home().join("data")
    }

    /// Get the path to the Felidae home directory.
    pub fn felidae_home(&self) -> PathBuf {
        self.home_dir.join("felidae")
    }

    /// Get the path to the node_key.json file.
    pub fn node_key_path(&self) -> PathBuf {
        self.cometbft_config_dir().join("node_key.json")
    }

    /// Get the path to the priv_validator_key.json file.
    pub fn priv_validator_key_path(&self) -> PathBuf {
        self.cometbft_config_dir().join("priv_validator_key.json")
    }

    /// Get the path to the priv_validator_state.json file.
    pub fn priv_validator_state_path(&self) -> PathBuf {
        self.cometbft_data_dir().join("priv_validator_state.json")
    }

    /// Get the path to the config.toml file.
    pub fn config_toml_path(&self) -> PathBuf {
        self.cometbft_config_dir().join("config.toml")
    }

    /// Get the path to the genesis.json file.
    pub fn genesis_path(&self) -> PathBuf {
        self.cometbft_config_dir().join("genesis.json")
    }

    /// Get the path to the admin key file.
    pub fn admin_key_path(&self) -> PathBuf {
        self.felidae_home().join("admin_key.pkcs8.hex")
    }

    /// Get the path to the oracle key file.
    pub fn oracle_key_path(&self) -> PathBuf {
        self.felidae_home().join("oracle_key.pkcs8.hex")
    }

    /// Get the P2P address for this node (e.g., "tcp://127.0.0.1:26656").
    pub fn p2p_listen_address(&self) -> String {
        format!("tcp://{}:{}", self.bind_address, self.ports.cometbft_p2p)
    }

    /// Get the RPC address for this node (e.g., "tcp://127.0.0.1:26657").
    pub fn rpc_listen_address(&self) -> String {
        format!("tcp://{}:{}", self.bind_address, self.ports.cometbft_rpc)
    }

    /// Get the ABCI address for this node (e.g., "127.0.0.1:26658").
    pub fn abci_address(&self) -> String {
        format!("{}:{}", self.bind_address, self.ports.felidae_abci)
    }

    /// Get the persistent peer address (node_id@host:port).
    /// Returns None if node_id is not set.
    pub fn persistent_peer_address(&self) -> Option<String> {
        self.node_id
            .as_ref()
            .map(|id| format!("{}@{}:{}", id, self.bind_address, self.ports.cometbft_p2p))
    }
}
