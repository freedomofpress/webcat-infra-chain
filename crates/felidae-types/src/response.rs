//! API response types for felidae query endpoints.
//!
//! These types are used for serializing responses from the query API and
//! deserializing them in clients and tests.

use serde::{Deserialize, Serialize};
use tendermint::Time;

use crate::transaction::{Config, Domain, HashObserved, Identity, ValidatorKey, ValidatorStatus};

/// Response structure from the `/enrollment/votes` query endpoint.
///
/// This represents a single oracle's active vote in the voting queue. Votes
/// remain active until either:
/// 1. Quorum is reached and the vote is consumed into a pending change
/// 2. The vote times out (exceeds `voting.timeout` from config)
/// 3. The same oracle submits a new vote for the same domain (overwrites)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OracleVote {
    /// The oracle's P-256 public key (hex on the wire).
    pub oracle: Identity,
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
    /// The admin's P-256 public key (hex on the wire).
    pub admin: Identity,
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
    /// The validator's ed25519 consensus public key (hex on the wire).
    pub identity: ValidatorKey,
    /// The CometBFT address, `SHA-256(identity)[..20]` (lowercase hex on the wire).
    #[serde(with = "lowercase_hex_id")]
    pub address: tendermint::account::Id,
    /// Current voting power reported to CometBFT.
    pub power: u64,
    /// Validator lifecycle status (a lowercase word on the wire).
    pub status: ValidatorStatus,
    /// Number of blocks missed within the current sliding uptime window.
    pub missed_blocks: u64,
    /// Size of the sliding uptime window in blocks.
    pub uptime_window: u64,
    /// Jail threshold: once missed blocks exceeds this, the validator is jailed.
    pub missed_blocks_max: u64,
    /// Unjail threshold: once a jailed validator's missed blocks falls to this, it unjails.
    pub unjail_missed_max: u64,
}

/// Response structure from the `/oracles` query endpoint: one authorized oracle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OracleInfo {
    /// The oracle's P-256 public key (hex on the wire).
    pub identity: Identity,
    /// The oracle's HTTP endpoint.
    pub endpoint: url::Url,
}

/// Serde adapter for [`tendermint::account::Id`] as lowercase hex.
///
/// The type's native serde is uppercase (CometBFT's convention); our wire has
/// always been lowercase, and clients prefix-match against it case-sensitively.
/// Decoding accepts either case.
mod lowercase_hex_id {
    use serde::{Deserialize, Deserializer, Serializer};
    use tendermint::account::Id;

    pub fn serialize<S: Serializer>(id: &Id, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex::encode(id.as_bytes()))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Id, D::Error> {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        Id::try_from(bytes).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validator_info_wire_shape_is_stable() {
        let identity = ValidatorKey::from_bytes(&[7u8; 32]).unwrap();
        let info = ValidatorInfo {
            identity,
            address: identity.address(),
            power: 1,
            status: ValidatorStatus::Jailed,
            missed_blocks: 2,
            uptime_window: 10,
            missed_blocks_max: 5,
            unjail_missed_max: 3,
        };
        let json = serde_json::to_value(&info).unwrap();
        // Bare lowercase hex for both keys, a lowercase word for status: the
        // shape the CLI and integration tests have always consumed.
        assert_eq!(json["identity"], "07".repeat(32));
        assert_eq!(json["address"], hex::encode(identity.address().as_bytes()));
        assert_eq!(json["status"], "jailed");
        let back: ValidatorInfo = serde_json::from_value(json).unwrap();
        assert_eq!(back.identity, identity);
        assert_eq!(back.address, identity.address());
        assert_eq!(back.status, ValidatorStatus::Jailed);
    }

    #[test]
    fn oracle_info_wire_shape_is_stable() {
        let identity = crate::test_util::test_identity(1);
        // The example URL is never polled, just used to exercise the parsing on structs.
        let example_url: &str = "https://oracle.example.com/";
        let info = OracleInfo {
            identity,
            endpoint: url::Url::parse(example_url).unwrap(),
        };
        let json = serde_json::to_value(&info).unwrap();
        // Bare lowercase hex of the SEC1 uncompressed point (65 bytes, "04"
        // prefix), a plain URL string: the shape the /oracles endpoint has
        // always served.
        assert_eq!(json["identity"], hex::encode(identity.to_bytes()));
        let hex_str = json["identity"].as_str().unwrap();
        assert_eq!(hex_str.len(), 130);
        assert!(hex_str.starts_with("04"));
        assert_eq!(json["endpoint"], example_url);
        let back: OracleInfo = serde_json::from_value(json).unwrap();
        assert_eq!(back.identity, identity);
        assert_eq!(back.endpoint, info.endpoint);
    }
}
