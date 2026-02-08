#![cfg(feature = "integration")]

//! Integration tests for felidae 3-validator network with oracle observations.
//!
//! # Overview
//!
//! These tests verify the core felidae ABCI application behavior through end-to-end
//! integration testing with a real 3-validator CometBFT network. The tests exercise
//! the complete transaction lifecycle from submission through consensus to state
//! finalization.
//!
//! # Architecture Under Test
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                         Test Network (3 Validators)                      │
//! │                                                                          │
//! │  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐               │
//! │  │ Validator 0  │    │ Validator 1  │    │ Validator 2  │               │
//! │  │ ┌──────────┐ │    │ ┌──────────┐ │    │ ┌──────────┐ │               │
//! │  │ │ CometBFT │◄├────┤►│ CometBFT │◄├────┤►│ CometBFT │ │  ◄── Consensus│
//! │  │ └────┬─────┘ │    │ └────┬─────┘ │    │ └────┬─────┘ │               │
//! │  │      │ABCI   │    │      │ABCI   │    │      │ABCI   │               │
//! │  │ ┌────▼─────┐ │    │ ┌────▼─────┐ │    │ ┌────▼─────┐ │               │
//! │  │ │ Felidae  │ │    │ │ Felidae  │ │    │ │ Felidae  │ │  ◄── State    │
//! │  │ └──────────┘ │    │ └──────────┘ │    │ └──────────┘ │      Machine  │
//! │  └──────────────┘    └──────────────┘    └──────────────┘               │
//! └─────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Business Logic Tested
//!
//! ## Oracle Observation Flow
//!
//! The oracle observation system implements a Byzantine fault-tolerant mechanism for
//! reaching consensus on domain-to-enrollment mappings in the WEBCAT protocol:
//!
//! 1. **Vote Submission**: Authorized oracles submit signed observations containing:
//!    - Domain name (e.g., "example.com.")
//!    - Zone (parent zone, e.g., "com.")
//!    - Enrollment hash (SHA-256 of canonical JSON enrollment) or NotFound
//!    - Blockstamp (block height + app hash for freshness verification)
//!
//! 2. **Vote Accumulation**: Votes are stored in a vote queue keyed by domain.
//!    Each oracle can have at most one active vote per domain.
//!
//! 3. **Quorum Detection**: When votes for the same (domain, hash) pair reach
//!    quorum (configured as 2/3 + 1 of total oracles), the observation moves
//!    to a "pending" state.
//!
//! 4. **Delay Period**: Pending observations wait for a configurable delay
//!    before becoming canonical. This provides a window for detecting issues.
//!
//! 5. **Canonicalization**: After the delay, observations are promoted to the
//!    canonical substore, making them queryable via the `/snapshot` endpoint.
//!
//! ## State Substores
//!
//! - **Internal**: Vote queues, pending changes, configuration, block metadata
//! - **Canonical**: Finalized domain → enrollment hash mappings (exposed to clients)
//!
//! # Test Configuration
//!
//! All tests use a 3-validator network with:
//! - Quorum: 3 (2/3 + 1 of 3 = 3)
//! - Voting timeout: 300s
//! - Promotion delay: 1s (shortened for testing; production uses longer delays)
//! - Max enrolled subdomains per registered domain: 5
//!
//! # Module Organization
//!
//! - `constants`: Test domain constants and enrollment data generation
//! - `harness`: TestNetwork struct for managing test network lifecycle
//! - `helpers`: Transaction submission and query helper functions
//! - `binaries`: Binary discovery for felidae and cometbft
//! - `oracle_tests`: Oracle observation and quorum tests
//! - `admin_tests`: Admin reconfiguration tests
//! - `cli_tests`: CLI workflow integration tests

pub mod binaries;
pub mod constants;
pub mod harness;
pub mod helpers;

mod admin_tests;
mod cli_tests;
mod oracle_tests;
mod query_tests;
