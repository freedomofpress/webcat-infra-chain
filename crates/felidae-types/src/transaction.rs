use felidae_proto::domain_types;
use felidae_proto::transaction::{self as proto};
use prost::bytes::Bytes;
use serde::{Deserialize, Serialize};
use serde_with::{DisplayFromStr, hex::Hex, serde_as};
use std::fmt::{Debug, Display};
use std::str::FromStr;
use std::{hash::Hash, ops::Deref, time::Duration};
use tendermint::block::Height;
use tendermint::{AppHash, Time};

use crate::{SignError, Signer};

/// Type conversions between the protobuf-generated types and the domain types.
mod convert;

/// Builder for transactions.
mod build;
pub use build::Builder;

mod authenticated;
pub use authenticated::AuthenticatedTx;

// Here are all the domain types that can be stored in the state, and their mapping to protobuf:
domain_types!(
    Transaction: proto::Transaction,
    Domain: String,
    Zone: String,
    PrefixOrderDomain: String,
    Empty: String,
    ChainId: String,
    Unsigned: proto::Signature,
    Action: proto::Action,
    Reconfigure: proto::action::Reconfigure,
    Config: proto::Config,
    AdminConfig: proto::config::AdminConfig,
    Admin: proto::Admin,
    OracleConfig: proto::config::OracleConfig,
    Oracle: proto::Oracle,
    OracleIdentity: proto::OracleIdentity,
    OnionConfig: proto::config::OnionConfig,
    VotingConfig: proto::config::VotingConfig,
    Observe: proto::action::Observe,
    Observation: proto::action::observe::Observation,
    HashObserved: proto::action::observe::observation::HashObserved,
    Blockstamp: proto::action::observe::observation::Blockstamp,
);

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Transaction {
    pub chain_id: ChainId,
    pub actions: Vec<Action>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ChainId(pub String);

#[serde_as]
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Unsigned {
    #[serde_as(as = "Hex")]
    pub public_key: Bytes,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Reconfigure(Reconfigure),
    /// Post a result of observing a domain.
    Observe(Observe),
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Reconfigure {
    #[serde(flatten)]
    pub config: Config,
    pub not_before: Time,
    pub not_after: Time,
    pub admin: Admin,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Config {
    pub version: u32,
    pub admins: AdminConfig,
    pub oracles: OracleConfig,
    pub onion: OnionConfig,
}

impl Config {
    pub fn template(version: u32) -> Self {
        Self {
            version,
            admins: AdminConfig {
                voting: VotingConfig {
                    total: Total(0),
                    quorum: Quorum(0),
                    timeout: Timeout(Duration::from_secs(24 * 60 * 60)),
                    delay: Delay(Duration::from_secs(0)),
                },
                authorized: vec![],
            },
            oracles: OracleConfig {
                enabled: false,
                voting: VotingConfig {
                    total: Total(0),
                    quorum: Quorum(0),
                    timeout: Timeout(Duration::from_secs(5 * 60)),
                    delay: Delay(Duration::from_secs(7 * 24 * 60 * 60)),
                },
                max_enrolled_subdomains: 1,
                observation_timeout: Duration::from_secs(5 * 60),
                authorized: vec![],
            },
            onion: OnionConfig { enabled: false },
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct AdminConfig {
    pub voting: VotingConfig,
    pub authorized: Vec<Admin>,
}

#[serde_as]
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Admin {
    #[serde_as(as = "Hex")]
    pub identity: Bytes,
}

#[serde_as]
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct OracleConfig {
    pub enabled: bool,
    pub voting: VotingConfig,
    pub max_enrolled_subdomains: u64,
    #[serde(with = "humantime_serde")]
    pub observation_timeout: Duration,
    pub authorized: Vec<Oracle>,
}

#[serde_as]
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Oracle {
    #[serde_as(as = "Hex")]
    pub identity: Bytes,
    /// Endpoint (domain name or IP address) for the oracle.
    #[serde(default = "default_oracle_endpoint")]
    pub endpoint: String,
}

fn default_oracle_endpoint() -> String {
    "127.0.0.1".to_string()
}

/// Transparent wrapper for the oracle's public key.
#[serde_as]
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct OracleIdentity {
    #[serde_as(as = "Hex")]
    pub identity: Bytes,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct OnionConfig {
    pub enabled: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct VotingConfig {
    pub total: Total,
    /// The minimum number of votes required to apply a vote result.
    pub quorum: Quorum,

    pub timeout: Timeout,
    /// Vote is not canonical until this delay expires. If there's another
    /// vote that applies in this time window, then the vote is not applied.
    pub delay: Delay,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Total(pub u64);

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Quorum(pub u64);

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Timeout(#[serde(with = "humantime_serde")] pub Duration);

#[serde_as]
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Delay(#[serde(with = "humantime_serde")] pub Duration);

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Observe {
    #[serde(flatten)]
    pub observation: Observation,
    pub oracle: OracleIdentity,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Observation {
    pub domain: Domain,
    pub zone: Zone,
    #[serde(flatten)]
    pub blockstamp: Blockstamp,
    pub hash_observed: HashObserved,
}

/// A fully qualified domain name (FQDN).
#[serde_as]
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Domain {
    #[serde_as(as = "DisplayFromStr")]
    pub name: fqdn::FQDN,
}

impl Display for Domain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name)
    }
}

/// A fully qualified domain name (FQDN) for a domain, displayed and parsed in order of its labels.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PrefixOrderDomain {
    pub name: fqdn::FQDN,
}

impl From<Domain> for PrefixOrderDomain {
    fn from(domain: Domain) -> Self {
        Self { name: domain.name }
    }
}

impl From<PrefixOrderDomain> for Domain {
    fn from(prefix_order_domain: PrefixOrderDomain) -> Self {
        Self {
            name: prefix_order_domain.name,
        }
    }
}

impl Display for PrefixOrderDomain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut labels: Vec<&str> = self.name.labels().collect();
        labels.reverse();
        write!(f, ".{}", labels.join("."))
    }
}

impl FromStr for PrefixOrderDomain {
    type Err = fqdn::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut labels: Vec<&str> = s.trim_start_matches('.').split('.').collect();
        labels.reverse();
        let mut domain_string = labels.join(".");
        domain_string.push('.');
        let fqdn = fqdn::FQDN::from_str(&domain_string)?;
        Ok(Self { name: fqdn })
    }
}

/// A unit type that serializes as an empty string.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Empty;

impl Display for Empty {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "")
    }
}

impl FromStr for Empty {
    type Err = crate::ParseError;

    fn from_str(string: &str) -> Result<Self, Self::Err> {
        if string.is_empty() {
            Ok(Empty)
        } else {
            Err(crate::ParseError::new::<Self>(string))
        }
    }
}

/// A fully qualified domain name (FQDN) that is meant to be treated as a zone.
#[serde_as]
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Zone {
    #[serde_as(as = "DisplayFromStr")]
    pub name: fqdn::FQDN,
}

impl Display for Zone {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name)
    }
}

#[serde_as]
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(untagged)]
pub enum HashObserved {
    Hash(#[serde_as(as = "Hex")] [u8; 32]),
    NotFound,
}

impl Debug for HashObserved {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HashObserved::Hash(hash) => write!(f, "{}", hex::encode(hash)),
            HashObserved::NotFound => write!(f, "NotFound"),
        }
    }
}

#[serde_as]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Blockstamp {
    pub block_height: Height,
    #[serde_as(as = "Hex")]
    pub app_hash: AppHash,
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

#[cfg(test)]
mod tests {
    use super::*;

    use insta::assert_snapshot;

    #[test]
    fn test_domain_display_and_parse() {
        let domain_str = "sub.example.com.";
        let fqdn = fqdn::FQDN::from_ascii_str(domain_str).unwrap();
        let domain = Domain { name: fqdn.clone() };
        assert_eq!(domain.to_string(), domain_str);
    }

    #[test]
    fn test_prefix_order_domain_display_and_parse() {
        let domain_str = ".com.example.sub";
        let prefix_order_domain = PrefixOrderDomain::from_str(domain_str).unwrap();
        assert_eq!(prefix_order_domain.to_string(), ".com.example.sub");
        assert_eq!(
            prefix_order_domain.name,
            fqdn::FQDN::from_ascii_str("sub.example.com.").unwrap()
        );
    }

    #[test]
    fn test_observe_serialization() {
        let observe = Observe {
            oracle: OracleIdentity {
                identity: Bytes::from_static(&[0u8; 64]),
            },
            observation: Observation {
                domain: Domain {
                    name: fqdn::FQDN::from_ascii_str("example.com.").unwrap(),
                },
                zone: Zone {
                    name: fqdn::FQDN::from_ascii_str("com.").unwrap(),
                },
                hash_observed: HashObserved::Hash([0u8; 32]),
                blockstamp: Blockstamp {
                    app_hash: AppHash::try_from([0u8; 32].to_vec()).unwrap(),
                    block_height: Height::from(0u32),
                },
            },
        };
        assert_snapshot!(serde_json::to_string(&observe).unwrap());
    }

    #[test]
    fn test_config_serialization() {
        let config = Config {
            version: 1,
            admins: AdminConfig {
                authorized: vec![Admin {
                    identity: Bytes::from_static(&[0u8; 64]),
                }],
                voting: VotingConfig {
                    total: Total(3),
                    quorum: Quorum(2),
                    timeout: Timeout(Duration::from_secs(30)),
                    delay: Delay(Duration::from_secs(5)),
                },
            },
            oracles: OracleConfig {
                enabled: true,
                authorized: vec![Oracle {
                    identity: Bytes::from_static(&[1u8; 64]),
                    endpoint: "127.0.0.1".to_string(),
                }],
                voting: VotingConfig {
                    total: Total(5),
                    quorum: Quorum(3),
                    timeout: Timeout(Duration::from_secs(60)),
                    delay: Delay(Duration::from_secs(10)),
                },
                max_enrolled_subdomains: 100,
                observation_timeout: Duration::from_secs(120),
            },
            onion: OnionConfig { enabled: false },
        };
        assert_snapshot!(serde_json::to_string(&config).unwrap());
    }

    #[test]
    fn test_transaction_serialization() {
        let tx = Transaction {
            chain_id: ChainId("test-chain".to_string()),
            actions: vec![Action::Reconfigure(Reconfigure {
                admin: Admin {
                    identity: Bytes::from_static(&[0u8; 64]),
                },
                not_before: Time::from_unix_timestamp(1_650_000_000, 0).unwrap(),
                not_after: Time::from_unix_timestamp(1_660_000_000, 0).unwrap(),
                config: Config {
                    version: 1,
                    admins: AdminConfig {
                        authorized: vec![Admin {
                            identity: Bytes::from_static(&[0u8; 64]),
                        }],
                        voting: VotingConfig {
                            total: Total(3),
                            quorum: Quorum(2),
                            timeout: Timeout(Duration::from_secs(30)),
                            delay: Delay(Duration::from_secs(5)),
                        },
                    },
                    oracles: OracleConfig {
                        enabled: true,
                        authorized: vec![Oracle {
                            identity: Bytes::from_static(&[1u8; 64]),
                            endpoint: "127.0.0.1".to_string(),
                        }],
                        voting: VotingConfig {
                            total: Total(5),
                            quorum: Quorum(3),
                            timeout: Timeout(Duration::from_secs(60)),
                            delay: Delay(Duration::from_secs(10)),
                        },
                        max_enrolled_subdomains: 100,
                        observation_timeout: Duration::from_secs(120),
                    },
                    onion: OnionConfig { enabled: false },
                },
            })],
        };
        assert_snapshot!(serde_json::to_string(&tx).unwrap());
    }
}
