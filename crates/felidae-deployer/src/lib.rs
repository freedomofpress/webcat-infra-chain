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
//!
//! // The generated genesis has no app_state yet, and InitChain refuses to
//! // start without one; inject the chain config before launching nodes:
//! let felidae_config = network
//!     .generate_felidae_config(
//!         std::time::Duration::from_secs(60), // oracle voting delay
//!         std::time::Duration::from_secs(0),  // admin voting delay
//!     )
//!     .expect("failed to generate config");
//! network
//!     .inject_genesis_app_state(&felidae_config)
//!     .expect("failed to inject genesis app_state");
//! ```

pub mod join;
pub mod network;
pub mod node;
pub mod ports;

pub use network::{Network, NetworkConfig, Platform};
pub use node::{NodeRole, WebcatNode};
pub use ports::{NodePorts, PortAllocationStrategy};
