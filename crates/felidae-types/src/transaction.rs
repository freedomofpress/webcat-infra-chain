use std::{any::TypeId, marker::PhantomData, rc::Rc};

use aws_lc_rs::{
    digest::{Context, Digest},
    signature::{Ed25519KeyPair, EdDSAParameters, KeyPair, ParsedPublicKey, UnparsedPublicKey},
};
use prost::Message as _;

use felidae_proto::transaction::{self as proto};

#[derive(Clone)]
pub struct Transaction {
    pub chain_id: String,
    pub actions: Vec<Action>,
}

#[derive(Clone)]
pub struct Signature<P> {
    public_key: UnparsedPublicKey<Vec<u8>>,
    signature: Vec<u8>,
    party: PhantomData<fn(&P)>,
}

impl<P> Signature<P> {
    pub fn sign(keypair: &Ed25519KeyPair, mut context: Context, message: &[u8]) -> Self {
        context.update(message);
        let hash = context.finish();
        let signature = keypair.sign(hash.as_ref());
        let public_key = keypair.public_key().as_ref().to_vec();
        Self {
            public_key: UnparsedPublicKey::new(&EdDSAParameters, public_key),
            signature: signature.as_ref().to_vec(),
            party: PhantomData,
        }
    }

    pub(crate) fn from_parts(public_key: Vec<u8>, signature: Vec<u8>) -> Self {
        Self {
            public_key: UnparsedPublicKey::new(&EdDSAParameters, public_key),
            signature,
            party: PhantomData,
        }
    }

    pub fn public_key(&self) -> &[u8] {
        self.public_key.as_ref()
    }

    pub fn verify_digest(
        &self,
        mut context: Context,
        message: &[u8],
    ) -> Result<(), aws_lc_rs::error::Unspecified> {
        context.update(message);
        let hash = context.finish();
        self.public_key.verify_digest(&hash, &self.signature)
    }
}

#[derive(Clone)]
pub enum Action {
    Reconfigure(Reconfigure),
    Observe(Observe),
}

#[derive(Clone)]
pub struct Reconfigure {
    pub signature: Signature<Reconfigure>,
    pub config: Config,
}

#[derive(Clone)]
pub struct Config {
    pub admin_config: AdminConfig,
    pub oracle_config: OracleConfig,
    pub onion_config: OnionConfig,
}

#[derive(Clone)]
pub struct AdminConfig {
    pub admins: Vec<Admin>,
    pub voting_config: VotingConfig,
}

#[derive(Clone)]
pub struct Admin {
    pub identity: Rc<ParsedPublicKey>,
}

#[derive(Clone)]
pub struct OracleConfig {
    pub enabled: bool,
    pub oracles: Vec<Oracle>,
    pub voting_config: VotingConfig,
    pub max_enrolled_subdomains: u64,
}

#[derive(Clone)]
pub struct Oracle {
    pub identity: Rc<ParsedPublicKey>,
}

#[derive(Clone)]
pub struct OnionConfig {
    pub enabled: bool,
}

#[derive(Clone)]
pub struct VotingConfig {
    pub total: u64,
    pub quorum: u64,
    pub timeout: u64,
    pub delay: u64,
}

#[derive(Clone)]
pub struct Observe {
    pub signature: Signature<Observe>,
    pub observation: Observation,
}

#[derive(Clone)]
pub struct Observation {
    pub domain: fqdn::FQDN,
    pub hash_observed: [u8; 32],
    pub blockstamp: Blockstamp,
}

#[derive(Clone)]
pub struct Blockstamp {
    pub app_hash: [u8; 32],
    pub block_number: u64,
}

impl TryFrom<proto::Transaction> for Transaction {
    type Error = crate::ParseError;

    fn try_from(tx: proto::Transaction) -> Result<Self, Self::Error> {
        let proto::Transaction { chain_id, actions } = tx;

        let actions = actions
            .into_iter()
            .map(TryInto::try_into)
            .collect::<Result<_, _>>()?;

        Ok(Transaction { chain_id, actions })
    }
}

impl From<Transaction> for proto::Transaction {
    fn from(tx: Transaction) -> Self {
        let Transaction { chain_id, actions } = tx;
        proto::Transaction {
            chain_id,
            actions: actions.into_iter().map(Into::into).collect(),
        }
    }
}

impl TryFrom<proto::Action> for Action {
    type Error = crate::ParseError;

    fn try_from(value: proto::Action) -> Result<Self, Self::Error> {
        match value.action {
            Some(proto::action::Action::Reconfigure(reconfigure)) => {
                Ok(Action::Reconfigure(reconfigure.try_into().map_err(
                    |_| crate::ParseError(TypeId::of::<Reconfigure>()),
                )?))
            }
            Some(proto::action::Action::Observe(observe)) => Ok(Action::Observe(
                observe
                    .try_into()
                    .map_err(|_| crate::ParseError(TypeId::of::<Observe>()))?,
            )),
            None => Err(crate::ParseError(TypeId::of::<Action>())),
        }
    }
}

impl From<Action> for proto::Action {
    fn from(action: Action) -> Self {
        match action {
            Action::Reconfigure(reconfigure) => proto::Action {
                action: Some(proto::action::Action::Reconfigure(
                    proto::action::Reconfigure {
                        admin_identity: todo!(),
                        admin_signature: todo!(),
                        config: todo!(),
                    },
                )),
            },
            Action::Observe(observe) => proto::Action {
                action: Some(proto::action::Action::Observe(proto::action::Observe {
                    oracle_identity: todo!(),
                    oracle_signature: todo!(),
                    observation: todo!(),
                })),
            },
        }
    }
}

impl TryFrom<proto::action::Reconfigure> for Reconfigure {
    type Error = crate::ParseError;

    fn try_from(value: proto::action::Reconfigure) -> Result<Self, Self::Error> {
        let proto::action::Reconfigure {
            admin_identity,
            admin_signature,
            config,
        } = value;

        // TODO: parse identity and signature

        let config = config
            .map(TryInto::try_into)
            .ok_or_else(|| crate::ParseError(TypeId::of::<Config>()))??;

        Ok(Reconfigure {
            admin_identity,
            admin_signature,
            config,
        })
    }
}

impl TryFrom<proto::action::Observe> for Observe {
    type Error = crate::ParseError;

    fn try_from(value: proto::action::Observe) -> Result<Self, Self::Error> {
        let proto::action::Observe {
            oracle_identity,
            oracle_signature,
            observation,
        } = value;

        // TODO: parse identity and signature

        let observation = observation
            .map(TryInto::try_into)
            .ok_or_else(|| crate::ParseError(TypeId::of::<Observation>()))??;

        Ok(Observe {
            oracle_identity,
            oracle_signature,
            observation,
        })
    }
}

impl TryFrom<proto::Config> for Config {
    type Error = crate::ParseError;

    fn try_from(value: proto::Config) -> Result<Self, Self::Error> {
        let proto::Config {
            admin_config,
            oracle_config,
            onion_config,
        } = value;

        let admin_config = admin_config
            .map(TryInto::try_into)
            .ok_or_else(|| crate::ParseError(TypeId::of::<AdminConfig>()))??;

        let oracle_config = oracle_config
            .map(TryInto::try_into)
            .ok_or_else(|| crate::ParseError(TypeId::of::<OracleConfig>()))??;

        let onion_config = onion_config
            .map(TryInto::try_into)
            .ok_or_else(|| crate::ParseError(TypeId::of::<OnionConfig>()))??;

        Ok(Config {
            admin_config,
            oracle_config,
            onion_config,
        })
    }
}

impl TryFrom<proto::config::AdminConfig> for AdminConfig {
    type Error = crate::ParseError;

    fn try_from(value: proto::config::AdminConfig) -> Result<Self, Self::Error> {
        let proto::config::AdminConfig {
            admins,
            voting_config,
        } = value;

        let admins = admins
            .into_iter()
            .map(TryInto::try_into)
            .collect::<Result<_, _>>()?;

        let voting_config = voting_config
            .map(TryInto::try_into)
            .ok_or_else(|| crate::ParseError(TypeId::of::<VotingConfig>()))??;

        Ok(AdminConfig {
            admins,
            voting_config,
        })
    }
}

impl TryFrom<proto::config::OracleConfig> for OracleConfig {
    type Error = crate::ParseError;

    fn try_from(value: proto::config::OracleConfig) -> Result<Self, Self::Error> {
        let proto::config::OracleConfig {
            enabled,
            oracles,
            voting_config,
            max_enrolled_subdomains,
        } = value;

        let oracles = oracles
            .into_iter()
            .map(TryInto::try_into)
            .collect::<Result<_, _>>()?;

        let voting_config = voting_config
            .map(TryInto::try_into)
            .ok_or_else(|| crate::ParseError(TypeId::of::<VotingConfig>()))??;

        Ok(OracleConfig {
            enabled,
            oracles,
            voting_config,
            max_enrolled_subdomains,
        })
    }
}

impl TryFrom<proto::action::observe::Observation> for Observation {
    type Error = crate::ParseError;

    fn try_from(value: proto::action::observe::Observation) -> Result<Self, Self::Error> {
        let proto::action::observe::Observation {
            domain,
            hash_observed,
            blockstamp,
        } = value;

        let domain = domain
            .parse()
            .map_err(|_| crate::ParseError(TypeId::of::<fqdn::FQDN>()))?;

        let hash_observed = hash_observed
            .ok_or_else(|| crate::ParseError(TypeId::of::<[u8; 32]>()))?
            .try_into()
            .map_err(|_| crate::ParseError(TypeId::of::<[u8; 32]>()))?;

        let blockstamp = blockstamp
            .ok_or_else(|| crate::ParseError(TypeId::of::<[u8; 32]>()))?
            .try_into()
            .map_err(|_| crate::ParseError(TypeId::of::<Blockstamp>()))?;

        Ok(Observation {
            domain,
            hash_observed,
            blockstamp,
        })
    }
}
