//! API response types for felidae query endpoints.
//!
//! These types are used for serializing responses from the query API and
//! deserializing them in clients and tests.

use serde::{Deserialize, Serialize};
use tendermint::Time;

use crate::transaction::{Config, Domain, HashObserved};

/// Response structure from the `/enrollment/votes` query endpoint.
///
/// This represents a single oracle's active vote in the voting queue. Votes
/// remain active until either:
/// 1. Quorum is reached and the vote is consumed into a pending change
/// 2. The vote times out (exceeds `voting.timeout` from config)
/// 3. The same oracle submits a new vote for the same domain (overwrites)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OracleVote {
    /// Hex-encoded ECDSA-P256 public key identifying the oracle
    pub oracle: String,
    /// When this vote was submitted
    pub time: Time,
    /// Fully qualified domain name (e.g., "example.com.")
    pub domain: Domain,
    /// The observed hash or NotFound indicator
    pub hash: HashObserved,
}

/// Response structure from the `/enrollment/pending` query endpoint.
///
/// Pending observations have reached quorum but are waiting for the delay
/// period to expire before being promoted to canonical state. During this
/// window:
/// - The pending value can be viewed via this endpoint
/// - A new quorum with a *different* value will overwrite (timer resets)
/// - A new quorum with the *same* value is dropped (timer preserved)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingObservation {
    /// When this pending observation was created
    pub time: Time,
    /// Fully qualified domain name (e.g., "example.com.")
    pub domain: Domain,
    /// The observed hash or NotFound indicator
    pub hash: HashObserved,
}

/// Response structure from the `/admin/votes` query endpoint.
///
/// This represents a single admin's active vote for a configuration change.
/// Unlike oracle votes which target domains, admin votes target the singleton
/// chain configuration. The voted `config` contains the proposed new settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminVote {
    /// Hex-encoded ECDSA-P256 public key identifying the admin
    pub admin: String,
    /// When this vote was submitted
    pub time: Time,
    /// The proposed new configuration
    pub config: Config,
}

/// Response structure from the `/admin/pending` query endpoint.
///
/// Pending config changes have reached quorum but are waiting for the delay
/// period to expire before being applied.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingConfig {
    /// When this pending config was created
    pub time: Time,
    /// The proposed new configuration
    pub config: Config,
}

/// Response structure from the `/chain-info` query endpoint.
///
/// Contains basic information about the running chain, derived entirely
/// from Felidae application state (no CometBFT RPC required).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainInfo {
    /// The chain identifier (e.g., "felidae-test")
    pub chain_id: String,
    /// Current block height
    pub block_height: u64,
    /// Timestamp of the latest committed block
    pub block_time: Time,
    /// The application state root hash (hex-encoded)
    pub app_hash: String,
}

/// Response structure from the `/validators` query endpoint.
///
/// Summarises a single validator's on-chain state: its identity, current
/// voting power, status, and recent signing behaviour. The `missed_blocks`,
/// `uptime_window`, `missed_blocks_max`, and `unjail_missed_max` fields
/// together let a caller render signing uptime as well as compare it against
/// the thresholds that govern jailing and unjailing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorInfo {
    /// Hex-encoded ed25519 public key identifying the validator.
    pub identity: String,
    /// Hex-encoded CometBFT address (first 20 bytes of SHA-256 over the public key).
    pub address: String,
    /// Current voting power reported to CometBFT.
    pub power: u64,
    /// Validator status: one of `"active"`, `"inactive"`, `"jailed"`, or `"tombstoned"`.
    pub status: String,
    /// Number of blocks missed within the current sliding uptime window.
    pub missed_blocks: u64,
    /// Size of the sliding uptime window in blocks.
    pub uptime_window: u64,
    /// Jail threshold: once missed blocks exceeds this, the validator is jailed.
    pub missed_blocks_max: u64,
    /// Unjail threshold: once a jailed validator's missed blocks falls to this, it unjails.
    pub unjail_missed_max: u64,
}
