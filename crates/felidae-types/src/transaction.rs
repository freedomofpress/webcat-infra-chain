use aws_lc_rs::digest::{Context, SHA256};
use felidae_proto::domain_types;
use felidae_proto::transaction::{self as proto};
use prost::bytes::Bytes;
use std::any::TypeId;
use std::fmt::Display;
use std::{hash::Hash, ops::Deref, time::Duration};
use tendermint::block::Height;
use tendermint::{AppHash, Time};

use crate::{SignError, Signer};

/// Type conversions between the protobuf-generated types and the domain types.
mod convert;

mod authenticated;
pub use authenticated::AuthenticatedTx;

// Here are all the domain types that can be stored:
domain_types!(
    Transaction: proto::Transaction,
    ChainId: String,
    Unsigned: proto::Signature,
    Action: proto::Action,
    Reconfigure: proto::action::Reconfigure,
    Config: proto::Config,
    AdminConfig: proto::config::AdminConfig,
    Admin: proto::Admin,
    OracleConfig: proto::config::OracleConfig,
    Oracle: proto::Oracle,
    OnionConfig: proto::config::OnionConfig,
    VotingConfig: proto::config::VotingConfig,
    Observe: proto::action::Observe,
    Observation: proto::action::observe::Observation,
    HashObserved: proto::action::observe::observation::HashObserved,
    Blockstamp: proto::action::observe::observation::Blockstamp,
);

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Transaction {
    pub chain_id: ChainId,
    pub actions: Vec<Action>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ChainId(pub String);

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
    pub not_before: Time,
    pub not_after: Time,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Config {
    pub version: u64,
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
    pub identity: Bytes,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OracleConfig {
    pub enabled: bool,
    pub oracles: Vec<Oracle>,
    pub voting_config: VotingConfig,
    pub max_enrolled_subdomains: u64,
    pub observation_timeout: Duration,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Oracle {
    pub identity: Bytes,
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
pub struct Timeout(pub Duration);

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Delay(pub Duration);

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Observe {
    pub oracle: Oracle,
    pub observation: Observation,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Observation {
    pub domain: Domain,
    pub zone: Domain,
    pub hash_observed: HashObserved,
    pub blockstamp: Blockstamp,
}

/// A fully qualified domain name (FQDN).
///
/// This wrapper type changes the Display implementation to order the name's components from most
/// significant to least significant (e.g. "com.example.www" instead of "www.example.com").
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Domain {
    pub name: fqdn::FQDN,
}

impl Display for Domain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let parts: Vec<&str> = self.name.labels().collect();
        write!(
            f,
            "{}",
            parts.iter().rev().cloned().collect::<Vec<&str>>().join(".")
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HashObserved {
    Hash([u8; 32]),
    NotFound,
}

impl TryFrom<proto::action::observe::observation::HashObserved> for HashObserved {
    type Error = crate::ParseError;

    fn try_from(
        value: proto::action::observe::observation::HashObserved,
    ) -> Result<Self, Self::Error> {
        if value.hash.len() == 32 {
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&value.hash);
            Ok(HashObserved::Hash(hash))
        } else if value.hash.is_empty() {
            Ok(HashObserved::NotFound)
        } else {
            Err(crate::ParseError(TypeId::of::<
                proto::action::observe::observation::HashObserved,
            >()))
        }
    }
}

impl From<HashObserved> for proto::action::observe::observation::HashObserved {
    fn from(value: HashObserved) -> Self {
        match value {
            HashObserved::Hash(hash) => proto::action::observe::observation::HashObserved {
                hash: hash.to_vec().into(),
            },
            HashObserved::NotFound => {
                proto::action::observe::observation::HashObserved { hash: Bytes::new() }
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Blockstamp {
    pub app_hash: AppHash,
    pub block_height: Height,
}

impl PartialOrd for Blockstamp {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Blockstamp {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.block_height
            .cmp(&other.block_height)
            .then_with(|| self.app_hash.as_bytes().cmp(other.app_hash.as_bytes()))
    }
}

impl Hash for Blockstamp {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.app_hash.as_bytes().hash(state);
        self.block_height.hash(state);
    }
}
