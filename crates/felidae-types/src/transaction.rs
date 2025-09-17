use std::{any::TypeId, marker::PhantomData, rc::Rc};

use aws_lc_rs::signature::{EdDSAParameters, ParsedPublicKey};
use prost::Message as _;

use felidae_proto::transaction::{self as proto};

#[derive(Clone)]
pub struct Transaction {
    pub signature: Signature<Transaction>,
    pub body: TransactionBody,
}

#[derive(Clone)]
pub struct TransactionBody {
    pub chain_id: String,
    pub actions: Vec<Action>,
}

#[derive(Clone)]
pub struct Signature<P> {
    public_key: Rc<ParsedPublicKey>,
    public_key_bytes: Rc<Vec<u8>>,
    signature: Vec<u8>,
    party: PhantomData<fn(&P)>,
}

#[derive(thiserror::Error, Debug)]
#[error("Invalid signature on: {0:?}")]
pub struct InvalidSignature(TypeId);

pub trait Signed: Sized + 'static {
    fn signature(&self) -> &Signature<Self>;

    fn payload(&self) -> Vec<u8>;

    fn verify(&self) -> Result<(), InvalidSignature> {
        let Signature {
            public_key,
            public_key_bytes: _,
            signature,
            party: _,
        } = self.signature();
        public_key
            .verify_sig(&self.payload(), signature)
            .map_err(|_| InvalidSignature(TypeId::of::<Self>()))
    }
}

impl Signed for Transaction {
    fn signature(&self) -> &Signature<Self> {
        &self.signature
    }

    fn payload(&self) -> Vec<u8> {
        let proto = proto::transaction::Body::from(self.body.clone());
        let mut buf = Vec::with_capacity(proto.encoded_len());
        proto.encode(&mut buf).expect("buffer is large enough");
        buf
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
        let proto::Transaction { signature, body } = tx;

        let signature = signature
            .map(TryInto::try_into)
            .ok_or_else(|| crate::ParseError(TypeId::of::<Signature<Transaction>>()))??;

        let body = body
            .map(TryInto::try_into)
            .ok_or_else(|| crate::ParseError(TypeId::of::<TransactionBody>()))??;

        Ok(Transaction { signature, body })
    }
}

impl From<Transaction> for proto::Transaction {
    fn from(tx: Transaction) -> Self {
        let Transaction { signature, body } = tx;
        proto::Transaction {
            signature: Some(signature.into()),
            body: Some(body.into()),
        }
    }
}

impl TryFrom<proto::transaction::Body> for TransactionBody {
    type Error = crate::ParseError;

    fn try_from(value: proto::transaction::Body) -> Result<Self, Self::Error> {
        let proto::transaction::Body { chain_id, actions } = value;
        let actions = actions
            .into_iter()
            .map(TryInto::try_into)
            .collect::<Result<_, _>>()?;
        Ok(TransactionBody { chain_id, actions })
    }
}

impl From<TransactionBody> for proto::transaction::Body {
    fn from(body: TransactionBody) -> Self {
        let TransactionBody { chain_id, actions } = body;
        proto::transaction::Body {
            chain_id,
            actions: actions.into_iter().map(Into::into).collect(),
        }
    }
}

impl TryFrom<proto::transaction::Signature> for Signature<Transaction> {
    type Error = crate::ParseError;

    fn try_from(value: proto::transaction::Signature) -> Result<Self, Self::Error> {
        let proto::transaction::Signature {
            ephemeral_public_key,
            signature,
        } = value;
        Ok(Signature {
            public_key_bytes: Rc::new(ephemeral_public_key.clone()),
            public_key: Rc::new(
                ParsedPublicKey::new(&EdDSAParameters, ephemeral_public_key)
                    .map_err(|_| crate::ParseError(TypeId::of::<Signature<Transaction>>()))?,
            ),
            signature,
            party: PhantomData,
        })
    }
}

impl From<Signature<Transaction>> for proto::transaction::Signature {
    fn from(sig: Signature<Transaction>) -> Self {
        let Signature {
            public_key: _,
            public_key_bytes,
            signature,
            party: _,
        } = sig;
        proto::transaction::Signature {
            ephemeral_public_key: public_key_bytes.as_ref().to_vec(),
            signature,
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
            Action::Reconfigure(_) => proto::Action {
                action: Some(proto::action::Action::Reconfigure(
                    proto::action::Reconfigure {
                        signature: todo!(),
                        config: todo!(),
                    },
                )),
            },
            Action::Observe(_) => proto::Action {
                action: Some(proto::action::Action::Observe(proto::action::Observe {
                    signature: todo!(),
                    observation: todo!(),
                })),
            },
        }
    }
}

impl TryFrom<proto::action::Reconfigure> for Reconfigure {
    type Error = crate::ParseError;

    fn try_from(value: proto::action::Reconfigure) -> Result<Self, Self::Error> {
        let proto::action::Reconfigure { signature, config } = value;

        let signature = signature
            .map(TryInto::try_into)
            .ok_or_else(|| crate::ParseError(TypeId::of::<Signature<Reconfigure>>()))??;

        let config = config
            .map(TryInto::try_into)
            .ok_or_else(|| crate::ParseError(TypeId::of::<Config>()))??;

        Ok(Reconfigure { signature, config })
    }
}

impl TryFrom<proto::action::Observe> for Observe {
    type Error = crate::ParseError;

    fn try_from(value: proto::action::Observe) -> Result<Self, Self::Error> {
        let proto::action::Observe {
            signature,
            observation,
        } = value;

        let signature = signature
            .map(TryInto::try_into)
            .ok_or_else(|| crate::ParseError(TypeId::of::<Signature<Observe>>()))??;

        let observation = observation
            .map(TryInto::try_into)
            .ok_or_else(|| crate::ParseError(TypeId::of::<Observation>()))??;

        Ok(Observe {
            signature,
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

impl TryFrom<proto::Admin> for Admin {
    type Error = crate::ParseError;

    fn try_from(value: proto::Admin) -> Result<Self, Self::Error> {
        let proto::Admin { identity } = value;
        let identity = Rc::new(
            ParsedPublicKey::new(&EdDSAParameters, identity)
                .map_err(|_| crate::ParseError(TypeId::of::<Admin>()))?,
        );
        Ok(Admin { identity })
    }
}

impl TryFrom<proto::config::OracleConfig> for OracleConfig {
    type Error = crate::ParseError;

    fn try_from(value: proto::config::OracleConfig) -> Result<Self, Self::Error> {
        let proto::config::OracleConfig {
            enabled,
            oracles,
            voting_config,
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
        })
    }
}

impl TryFrom<proto::Oracle> for Oracle {
    type Error = crate::ParseError;

    fn try_from(value: proto::Oracle) -> Result<Self, Self::Error> {
        let proto::Oracle { identity } = value;
        let identity = Rc::new(
            ParsedPublicKey::new(&EdDSAParameters, identity)
                .map_err(|_| crate::ParseError(TypeId::of::<Oracle>()))?,
        );
        Ok(Oracle { identity })
    }
}
