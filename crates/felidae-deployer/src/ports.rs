//! Port allocation strategies for webcat networks.

use serde::{Deserialize, Serialize};

/// Default base ports for CometBFT and Felidae services.
pub const DEFAULT_COMETBFT_P2P_PORT: u16 = 26656;
pub const DEFAULT_COMETBFT_RPC_PORT: u16 = 26657;
pub const DEFAULT_FELIDAE_ABCI_PORT: u16 = 26658;
pub const DEFAULT_FELIDAE_QUERY_PORT: u16 = 8080;
pub const DEFAULT_FELIDAE_ORACLE_PORT: u16 = 8081;

/// Default offset between nodes for port allocation.
pub const DEFAULT_PORT_OFFSET: u16 = 100;

/// Port allocation strategy for assigning ports to nodes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortAllocationStrategy {
    /// Base port for CometBFT P2P.
    pub cometbft_p2p_base: u16,
    /// Base port for CometBFT RPC.
    pub cometbft_rpc_base: u16,
    /// Base port for Felidae ABCI.
    pub felidae_abci_base: u16,
    /// Base port for Felidae Query service.
    pub felidae_query_base: u16,
    /// Base port for Felidae Oracle service.
    pub felidae_oracle_base: u16,
    /// Offset between consecutive nodes.
    pub node_offset: u16,
}

impl Default for PortAllocationStrategy {
    fn default() -> Self {
        Self {
            cometbft_p2p_base: DEFAULT_COMETBFT_P2P_PORT,
            cometbft_rpc_base: DEFAULT_COMETBFT_RPC_PORT,
            felidae_abci_base: DEFAULT_FELIDAE_ABCI_PORT,
            felidae_query_base: DEFAULT_FELIDAE_QUERY_PORT,
            felidae_oracle_base: DEFAULT_FELIDAE_ORACLE_PORT,
            node_offset: DEFAULT_PORT_OFFSET,
        }
    }
}

impl PortAllocationStrategy {
    /// Allocate ports for a node at the given index.
    pub fn allocate(&self, node_index: usize) -> NodePorts {
        let offset = (node_index as u16) * self.node_offset;
        NodePorts {
            cometbft_p2p: self.cometbft_p2p_base + offset,
            cometbft_rpc: self.cometbft_rpc_base + offset,
            felidae_abci: self.felidae_abci_base + offset,
            felidae_query: self.felidae_query_base + offset,
            felidae_oracle: self.felidae_oracle_base + offset,
        }
    }
}

/// All ports allocated to a single node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodePorts {
    /// CometBFT P2P port (default 26656).
    pub cometbft_p2p: u16,
    /// CometBFT RPC port (default 26657).
    pub cometbft_rpc: u16,
    /// Felidae ABCI port (default 26658).
    pub felidae_abci: u16,
    /// Felidae Query service port (default 8080).
    pub felidae_query: u16,
    /// Felidae Oracle service port (default 8081).
    pub felidae_oracle: u16,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_port_allocation() {
        let strategy = PortAllocationStrategy::default();

        let ports0 = strategy.allocate(0);
        assert_eq!(ports0.cometbft_p2p, 26656);
        assert_eq!(ports0.cometbft_rpc, 26657);
        assert_eq!(ports0.felidae_abci, 26658);
        assert_eq!(ports0.felidae_query, 8080);
        assert_eq!(ports0.felidae_oracle, 8081);

        let ports1 = strategy.allocate(1);
        assert_eq!(ports1.cometbft_p2p, 26756);
        assert_eq!(ports1.cometbft_rpc, 26757);
        assert_eq!(ports1.felidae_abci, 26758);
        assert_eq!(ports1.felidae_query, 8180);
        assert_eq!(ports1.felidae_oracle, 8181);

        let ports2 = strategy.allocate(2);
        assert_eq!(ports2.cometbft_p2p, 26856);
        assert_eq!(ports2.cometbft_rpc, 26857);
        assert_eq!(ports2.felidae_abci, 26858);
        assert_eq!(ports2.felidae_query, 8280);
        assert_eq!(ports2.felidae_oracle, 8281);
    }
}
