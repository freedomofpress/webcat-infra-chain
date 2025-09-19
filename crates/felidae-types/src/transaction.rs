use aws_lc_rs::digest::{Context, SHA256};
use felidae_proto::transaction::{self as proto};
use prost::bytes::Bytes;
use std::{hash::Hash, ops::Deref};
use tendermint::AppHash;

use crate::{SignError, Signer};

/// Type conversions between the protobuf-generated types and the domain types.
mod convert;

mod authenticated;
pub use authenticated::AuthenticatedTx;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Transaction {
    pub chain_id: String,
    pub actions: Vec<Action>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Unsigned {
    pub public_key: Bytes,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Action {
    Reconfigure(Reconfigure),
    Observe(Observe),
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Reconfigure {
    pub admin: Admin,
    pub config: Config,
    pub version: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Config {
    pub admin_config: AdminConfig,
    pub oracle_config: OracleConfig,
    pub onion_config: OnionConfig,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AdminConfig {
    pub admins: Vec<Admin>,
    pub voting_config: VotingConfig,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Admin {
    identity: Bytes,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OracleConfig {
    pub enabled: bool,
    pub oracles: Vec<Oracle>,
    pub voting_config: VotingConfig,
    pub max_enrolled_subdomains: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Oracle {
    identity: Bytes,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OnionConfig {
    pub enabled: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VotingConfig {
    pub total: Total,
    pub quorum: Quorum,
    pub timeout: Timeout,
    pub delay: Delay,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Total(pub u64);

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Quorum(pub u64);

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Timeout(pub u64);

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Delay(pub u64);

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Observe {
    pub oracle: Oracle,
    pub observation: Observation,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Observation {
    pub domain: fqdn::FQDN,
    pub hash_observed: HashObserved,
    pub blockstamp: Blockstamp,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HashObserved(pub [u8; 32]);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Blockstamp {
    pub app_hash: AppHash,
    pub block_number: u64,
}

impl PartialOrd for Blockstamp {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Blockstamp {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.block_number
            .cmp(&other.block_number)
            .then_with(|| self.app_hash.as_bytes().cmp(other.app_hash.as_bytes()))
    }
}

impl Hash for Blockstamp {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.app_hash.as_bytes().hash(state);
        self.block_number.hash(state);
    }
}
