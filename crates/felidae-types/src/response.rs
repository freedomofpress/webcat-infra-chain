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
