use felidae_proto::domain_types;
use felidae_proto::transaction::{self as proto};
use serde::{Deserialize, Serialize};
use serde_with::{DisplayFromStr, hex::Hex, serde_as};
use std::fmt::{Debug, Display};
use std::str::FromStr;
use std::{hash::Hash, ops::Deref, time::Duration};
use tendermint::block::Height;
use tendermint::{AppHash, Time};
use url::Url;

use crate::{SignError, Signer};

/// Type conversions between the protobuf-generated types and the domain types.
mod convert;

/// Builder for transactions.
mod build;
pub use build::Builder;

mod authenticated;

mod check;
pub use authenticated::AuthenticatedTx;
pub use check::InvalidConfig;

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
    ValidatorConfig: proto::config::ValidatorConfig,
    VotingConfig: proto::config::VotingConfig,
    Validator: proto::Validator,
    Observe: proto::action::Observe,
    Observation: proto::action::observe::Observation,
    HashObserved: proto::action::observe::observation::HashObserved,
    Blockstamp: proto::action::observe::observation::Blockstamp,
    OracleVoteValue: proto::OracleVoteValue,
);

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Transaction {
    pub chain_id: ChainId,
    pub actions: Vec<Action>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ChainId(pub String);

/// The signer slot of a transaction action, with the signature stripped.
///
/// Signatures live only in the protobuf layer; this is what remains once one has
/// been verified: the (already-parsed) identity that signed.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Unsigned {
    pub identity: Identity,
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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub validators: Vec<Validator>,
    #[serde(default)]
    pub validator_config: ValidatorConfig,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ValidatorConfig {
    /// Number of blocks in the sliding uptime window.
    pub uptime_window: u64,
    /// Maximum missed blocks in the window before a validator is jailed.
    pub missed_blocks_max: u64,
    /// Maximum missed blocks in the window before a jailed validator is unjailed.
    /// Must be strictly less than `missed_blocks_max` to prevent oscillation.
    pub unjail_missed_max: u64,
}

impl Default for ValidatorConfig {
    fn default() -> Self {
        Self {
            uptime_window: 10_000,
            missed_blocks_max: 500,
            unjail_missed_max: 250,
        }
    }
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
                // Placeholder entry
                authorized: vec![Admin {
                    identity: Identity::placeholder(),
                }],
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
                // Placeholder entry so it's easier to fill out
                authorized: vec![Oracle {
                    identity: Identity::placeholder(),
                    endpoint: Url::parse("http://127.0.0.1:8081").unwrap(),
                }],
            },
            onion: OnionConfig { enabled: false },
            validators: vec![],
            validator_config: ValidatorConfig::default(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct AdminConfig {
    pub voting: VotingConfig,
    pub authorized: Vec<Admin>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Admin {
    pub identity: Identity,
}

/// A NIST P-256 ECDSA public key identifying an admin or oracle.
///
/// Parsed and validated at construction, so a held value is always a point on
/// the curve. Canonical encoding is 65-byte SEC1 uncompressed (`0x04 || x || y`),
/// matching what [`KeyPair::public_key`] produces; compressed (33-byte) input
/// is accepted and canonicalized. JSON shape is a bare lowercase hex string.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Identity(p256::ecdsa::VerifyingKey);

impl Identity {
    /// Parse an identity from SEC1-encoded bytes (compressed or uncompressed).
    pub fn from_sec1_bytes(bytes: &[u8]) -> Result<Self, crate::ParseError> {
        p256::ecdsa::VerifyingKey::from_sec1_bytes(bytes)
            .map(Identity)
            .map_err(|_| {
                crate::ParseError::new::<Identity>(format!(
                    "invalid P-256 public key: {}",
                    hex::encode(bytes)
                ))
            })
    }

    /// The canonical 65-byte SEC1 uncompressed encoding.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_encoded_point(false).as_bytes().to_vec()
    }

    /// The identity of a signing keypair.
    pub fn from_keypair(keypair: &crate::KeyPair) -> Self {
        Self::from_sec1_bytes(&keypair.public_key())
            .expect("KeyPair public key is always a valid SEC1 point")
    }

    /// A well-known placeholder identity for config templates: the P-256
    /// generator point. Valid and parseable, but rejected by config validation
    /// if left unreplaced.
    pub fn placeholder() -> Self {
        Identity(
            p256::ecdsa::VerifyingKey::from_affine(p256::AffinePoint::GENERATOR)
                .expect("generator point is not the identity point"),
        )
    }
}

impl From<p256::ecdsa::VerifyingKey> for Identity {
    fn from(key: p256::ecdsa::VerifyingKey) -> Self {
        Identity(key)
    }
}

impl From<Identity> for p256::ecdsa::VerifyingKey {
    fn from(identity: Identity) -> Self {
        identity.0
    }
}

impl Hash for Identity {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.to_bytes().hash(state);
    }
}

impl Display for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.to_bytes()))
    }
}

impl Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Identity({self})")
    }
}

impl FromStr for Identity {
    type Err = crate::ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = hex::decode(s)
            .map_err(|_| crate::ParseError::new::<Identity>(format!("invalid hex: {s}")))?;
        Self::from_sec1_bytes(&bytes)
    }
}

impl Serialize for Identity {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Identity {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Validator {
    /// Ed25519 consensus public key; hex string in JSON, parsed at construction.
    pub public_key: ValidatorKey,
}

/// An Ed25519 consensus public key identifying a validator.
///
/// The one home for every encoding of the key: lowercase hex on the wire
/// (config JSON, query API) and in state keys, the raw 32 bytes in protobuf,
/// and the CometBFT address (`SHA-256(key)[..20]`) via [`ValidatorKey::address`].
/// Only the length is checked, exactly as CometBFT does; `[0u8; 32]` remains
/// representable so config validation can reject it as a placeholder.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ValidatorKey(tendermint::public_key::Ed25519);

impl ValidatorKey {
    /// Parse a key from its raw 32-byte encoding.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, crate::ParseError> {
        tendermint::public_key::Ed25519::try_from(bytes)
            .map(ValidatorKey)
            .map_err(|_| {
                crate::ParseError::new::<ValidatorKey>(format!(
                    "invalid ed25519 public key (expected 32 bytes): {}",
                    hex::encode(bytes)
                ))
            })
    }

    /// The raw 32-byte encoding.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    /// The CometBFT validator address: the first 20 bytes of the SHA-256 of the key.
    ///
    /// This is how CometBFT refers to validators in commit votes and misbehavior
    /// evidence, so it is the join key between ABCI requests and our state.
    pub fn address(&self) -> tendermint::account::Id {
        tendermint::account::Id::from(self.0)
    }
}

impl From<ValidatorKey> for tendermint::PublicKey {
    fn from(key: ValidatorKey) -> Self {
        tendermint::PublicKey::Ed25519(key.0)
    }
}

impl TryFrom<tendermint::PublicKey> for ValidatorKey {
    type Error = crate::ParseError;

    /// Rejects any non-Ed25519 key. The `tendermint` crate's `secp256k1` feature
    /// is off in this workspace, so this cannot currently fail, but cargo
    /// features unify across the dependency graph: this is the fence that keeps
    /// a non-Ed25519 consensus key out of state should that ever change.
    fn try_from(key: tendermint::PublicKey) -> Result<Self, Self::Error> {
        key.ed25519().map(ValidatorKey).ok_or_else(|| {
            crate::ParseError::new::<ValidatorKey>(format!(
                "not an ed25519 public key: {}",
                hex::encode(key.to_bytes())
            ))
        })
    }
}

impl PartialOrd for ValidatorKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ValidatorKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.as_bytes().cmp(other.as_bytes())
    }
}

impl Hash for ValidatorKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.as_bytes().hash(state);
    }
}

impl Display for ValidatorKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.as_bytes()))
    }
}

impl Debug for ValidatorKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ValidatorKey({self})")
    }
}

impl FromStr for ValidatorKey {
    type Err = crate::ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = hex::decode(s)
            .map_err(|_| crate::ParseError::new::<ValidatorKey>(format!("invalid hex: {s}")))?;
        Self::from_bytes(&bytes)
    }
}

impl Serialize for ValidatorKey {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for ValidatorKey {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
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

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Oracle {
    pub identity: Identity,
    /// URL endpoint for the oracle (e.g. `https://oracle.example.com/oracle/`).
    #[serde(
        default = "default_oracle_endpoint",
        deserialize_with = "deserialize_endpoint"
    )]
    pub endpoint: Url,
}

impl PartialOrd for Oracle {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Oracle {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.identity
            .cmp(&other.identity)
            .then_with(|| self.endpoint.as_str().cmp(other.endpoint.as_str()))
    }
}

fn default_oracle_endpoint() -> Url {
    Url::parse("http://127.0.0.1:8081").expect("default oracle endpoint is a valid URL")
}

fn deserialize_endpoint<'de, D>(deserializer: D) -> Result<Url, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    Url::parse(&s).map_err(serde::de::Error::custom)
}

/// Transparent wrapper for the oracle's public key.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct OracleIdentity {
    pub identity: Identity,
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

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct OracleVoteValue {
    pub hash_observed: HashObserved,
    pub zone: Zone,
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

    /// Deterministic P-256 identity derived from a fixed low scalar.
    ///
    /// The scalar is 256 + n, so no `n` yields scalar 1 — whose public key is
    /// the generator point, i.e. `Identity::placeholder()`.
    fn test_identity(n: u8) -> Identity {
        let mut scalar = [0u8; 32];
        scalar[30] = 1;
        scalar[31] = n;
        let signing_key =
            p256::ecdsa::SigningKey::from_slice(&scalar).expect("low scalar is a valid key");
        Identity::from(*signing_key.verifying_key())
    }

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
    fn validator_serde_hex_round_trip() {
        let key = ValidatorKey::from_bytes(&[2u8; 32]).unwrap();
        let validator = Validator { public_key: key };
        let json = serde_json::to_string(&validator).unwrap();
        // Operator-facing shape must stay a bare hex string, not tendermint's tagged enum.
        assert_eq!(json, format!(r#"{{"public_key":"{}"}}"#, "02".repeat(32)));
        assert_eq!(serde_json::from_str::<Validator>(&json).unwrap(), validator);
        // Display and FromStr agree with the JSON shape (they back the state keys).
        assert_eq!(key.to_string(), "02".repeat(32));
        assert_eq!(key.to_string().parse::<ValidatorKey>().unwrap(), key);
    }

    #[test]
    fn validator_deserialize_rejects_invalid_keys() {
        for bad in [
            r#"{"public_key":"zz"}"#.to_string(),                 // not hex
            format!(r#"{{"public_key":"{}"}}"#, "02".repeat(31)), // too short
            format!(r#"{{"public_key":"{}"}}"#, "02".repeat(33)), // too long
        ] {
            assert!(serde_json::from_str::<Validator>(&bad).is_err());
        }
        assert!(ValidatorKey::from_bytes(&[2u8; 31]).is_err());
        assert!(ValidatorKey::from_bytes(&[2u8; 33]).is_err());
    }

    #[test]
    fn all_zeros_placeholder_key_still_parses() {
        // check_config's placeholder rejection relies on 32 zero bytes being representable;
        // pin that ValidatorKey is length-only validation.
        assert!(ValidatorKey::from_bytes(&[0u8; 32]).is_ok());
    }

    #[test]
    fn validator_key_address_is_sha256_prefix() {
        // The CometBFT address convention, pinned so state code can lean on
        // `address()` instead of hand-rolling the hash.
        use sha2::{Digest, Sha256};
        let key = ValidatorKey::from_bytes(&[7u8; 32]).unwrap();
        let expected = &Sha256::digest(key.as_bytes())[..20];
        assert_eq!(key.address().as_bytes(), expected);
    }

    #[test]
    fn validator_key_tendermint_round_trip() {
        let key = ValidatorKey::from_bytes(&[3u8; 32]).unwrap();
        let tm = tendermint::PublicKey::from(key);
        assert_eq!(tm.to_bytes(), key.as_bytes());
        assert_eq!(ValidatorKey::try_from(tm).unwrap(), key);
    }

    #[test]
    fn identity_serde_hex_round_trip() {
        let identity = test_identity(1);
        let json = serde_json::to_string(&identity).unwrap();
        // Bare lowercase hex of the 65-byte SEC1 uncompressed encoding.
        let hex = identity.to_string();
        assert_eq!(hex.len(), 130);
        assert!(hex.starts_with("04"));
        assert_eq!(json, format!(r#""{hex}""#));
        assert_eq!(serde_json::from_str::<Identity>(&json).unwrap(), identity);
    }

    #[test]
    fn identity_rejects_invalid() {
        // Off-curve: valid tag and length, but (1,1) is not on the curve.
        let mut off_curve = vec![0u8; 65];
        off_curve[0] = 0x04;
        off_curve[32] = 1;
        off_curve[64] = 1;
        for bad in [vec![], vec![1u8; 64], vec![1u8; 66], off_curve] {
            assert!(
                Identity::from_sec1_bytes(&bad).is_err(),
                "{}-byte input must be rejected",
                bad.len()
            );
            let json = format!(r#""{}""#, hex::encode(&bad));
            assert!(serde_json::from_str::<Identity>(&json).is_err());
        }
    }

    #[test]
    fn identity_accepts_compressed_and_canonicalizes() {
        let identity = test_identity(1);
        let compressed = p256::ecdsa::VerifyingKey::from(identity)
            .to_encoded_point(true)
            .as_bytes()
            .to_vec();
        assert_eq!(compressed.len(), 33);
        let parsed = Identity::from_sec1_bytes(&compressed).unwrap();
        assert_eq!(parsed, identity);
        assert_eq!(parsed.to_bytes().len(), 65);
    }

    #[test]
    fn placeholder_is_parseable() {
        // check_config rejects the placeholder by equality, so it must be
        // representable in the strictly-parsed type.
        let placeholder = Identity::placeholder();
        assert_eq!(
            Identity::from_sec1_bytes(&placeholder.to_bytes()).unwrap(),
            placeholder
        );
        // The generator point's well-known SEC1 prefix.
        assert!(placeholder.to_string().starts_with("046b17d1f2e12c4247"));
    }

    #[test]
    fn test_observe_serialization() {
        let observe = Observe {
            oracle: OracleIdentity {
                identity: test_identity(1),
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
                    identity: test_identity(1),
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
                    identity: test_identity(2),
                    endpoint: Url::parse("http://127.0.0.1:8081").unwrap(),
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
            validators: vec![],
            validator_config: ValidatorConfig::default(),
        };
        assert_snapshot!(serde_json::to_string(&config).unwrap());
    }

    #[test]
    fn test_transaction_serialization() {
        let tx = Transaction {
            chain_id: ChainId("test-chain".to_string()),
            actions: vec![Action::Reconfigure(Reconfigure {
                admin: Admin {
                    identity: test_identity(1),
                },
                not_before: Time::from_unix_timestamp(1_650_000_000, 0).unwrap(),
                not_after: Time::from_unix_timestamp(1_660_000_000, 0).unwrap(),
                config: Config {
                    version: 1,
                    admins: AdminConfig {
                        authorized: vec![Admin {
                            identity: test_identity(1),
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
                            identity: test_identity(2),
                            endpoint: Url::parse("http://127.0.0.1:8081").unwrap(),
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
                    validators: vec![],
                    validator_config: ValidatorConfig::default(),
                },
            })],
        };
        assert_snapshot!(serde_json::to_string(&tx).unwrap());
    }

    #[test]
    fn test_oracle_deserialize_accepts_valid_urls() {
        let valid_urls = [
            "http://127.0.0.1",
            "https://oracle.example.com/oracle/",
            "http://127.0.0.1:8081",
            "https://webcat-sentry-1.freedom.press/oracle/",
        ];
        for url in valid_urls {
            let json = format!(
                r#"{{"identity":"{}","endpoint":"{}"}}"#,
                test_identity(1),
                url
            );
            let oracle: Result<Oracle, _> = serde_json::from_str(&json);
            assert!(oracle.is_ok(), "expected valid URL to deserialize: {url}");
            assert_eq!(
                oracle.unwrap().endpoint.as_str().trim_end_matches('/'),
                url.trim_end_matches('/')
            );
        }
    }

    #[test]
    fn test_oracle_deserialize_rejects_invalid_urls() {
        let invalid_urls = ["127.0.0.1", "not-a-url", "127.0.0.1:8081", ""];
        for url in invalid_urls {
            let json = format!(
                r#"{{"identity":"{}","endpoint":"{}"}}"#,
                test_identity(1),
                url
            );
            let oracle: Result<Oracle, _> = serde_json::from_str(&json);
            assert!(
                oracle.is_err(),
                "expected invalid URL to fail deserialization: {url}"
            );
        }
    }
}
