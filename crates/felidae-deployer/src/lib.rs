//! felidae-deployer: Orchestrate felidae and cometbft nodes for integration testing.
//!
//! This crate provides both a CLI and library interface for creating and managing
//! felidae test networks.
//!
//! # Example
//!
//! ```rust,no_run
//! use felidae_deployer::{Network, NetworkConfig};
//!
//! let config = NetworkConfig {
//!     num_validators: 3,
//!     use_sentries: true,
//!     ..Default::default()
//! };
//!
//! let mut network = Network::new(config);
//! network.initialize().expect("failed to initialize network");
//! ```

pub mod network;
pub mod node;
pub mod ports;

pub use network::{Network, NetworkConfig, Platform};
pub use node::{NodeRole, WebcatNode};
pub use ports::{NodePorts, PortAllocationStrategy};
