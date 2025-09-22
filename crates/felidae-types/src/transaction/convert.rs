use aws_lc_rs::signature::{EdDSAParameters, ParsedPublicKey};
use felidae_proto::transaction::{self as proto, KeyPair};
use std::any::TypeId;

use super::*;

impl TryFrom<proto::Transaction> for Transaction {
    type Error = crate::ParseError;

    fn try_from(tx: proto::Transaction) -> Result<Self, Self::Error> {
        let proto::Transaction { chain_id, actions } = tx;

        let chain_id = ChainId(chain_id);

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
            chain_id: chain_id.0,
            actions: actions.into_iter().map(Into::into).collect(),
        }
    }
}

impl TryFrom<String> for ChainId {
    type Error = crate::ParseError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if value.is_empty() {
            Err(crate::ParseError(TypeId::of::<ChainId>()))
        } else {
            Ok(ChainId(value))
        }
    }
}

impl From<ChainId> for String {
    fn from(value: ChainId) -> Self {
        value.0
    }
}

impl TryFrom<proto::Signature> for Unsigned {
    type Error = crate::ParseError;

    fn try_from(value: proto::Signature) -> Result<Self, Self::Error> {
        let _pk = ParsedPublicKey::new(&EdDSAParameters, &value.public_key)
            .map_err(|_| crate::ParseError(TypeId::of::<ParsedPublicKey>()))?;
        Ok(Unsigned {
            public_key: value.public_key,
        })
    }
}

impl From<Unsigned> for proto::Signature {
    fn from(unsigned: Unsigned) -> Self {
        proto::Signature::unsigned(unsigned.public_key)
    }
}

impl From<KeyPair> for Unsigned {
    fn from(value: KeyPair) -> Self {
        Unsigned {
            public_key: value.public_key().as_ref().to_vec().into(),
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
                action: Some(proto::action::Action::Reconfigure(reconfigure.into())),
            },
            Action::Observe(observe) => proto::Action {
                action: Some(proto::action::Action::Observe(observe.into())),
            },
        }
    }
}

impl TryFrom<proto::action::Reconfigure> for Reconfigure {
    type Error = crate::ParseError;

    fn try_from(value: proto::action::Reconfigure) -> Result<Self, Self::Error> {
        let proto::action::Reconfigure {
            signature,
            config,
            not_before,
            not_after,
        } = value;

        let admin: Admin = signature
            .map(Unsigned::try_from)
            .ok_or_else(|| crate::ParseError(TypeId::of::<Admin>()))??
            .try_into()?;

        let config = config
            .map(TryInto::try_into)
            .ok_or_else(|| crate::ParseError(TypeId::of::<Config>()))??;

        let not_before = not_before
            .map(TryInto::try_into)
            .ok_or_else(|| crate::ParseError(TypeId::of::<tendermint::Time>()))?
            .map_err(|_| crate::ParseError(TypeId::of::<tendermint::Time>()))?;

        let not_after = not_after
            .map(TryInto::try_into)
            .ok_or_else(|| crate::ParseError(TypeId::of::<tendermint::Time>()))?
            .map_err(|_| crate::ParseError(TypeId::of::<tendermint::Time>()))?;

        Ok(Reconfigure {
            admin,
            config,
            not_before,
            not_after,
        })
    }
}

impl From<Reconfigure> for proto::action::Reconfigure {
    fn from(reconfigure: Reconfigure) -> Self {
        let Reconfigure {
            admin,
            config,
            not_before,
            not_after,
        } = reconfigure;
        proto::action::Reconfigure {
            signature: Some(admin.into()),
            config: Some(config.into()),
            not_before: Some(not_before.into()),
            not_after: Some(not_after.into()),
        }
    }
}

impl TryFrom<proto::action::Observe> for Observe {
    type Error = crate::ParseError;

    fn try_from(value: proto::action::Observe) -> Result<Self, Self::Error> {
        let proto::action::Observe {
            signature,
            observation,
        } = value;

        let oracle = signature
            .map(Unsigned::try_from)
            .ok_or_else(|| crate::ParseError(TypeId::of::<Oracle>()))??
            .try_into()?;

        let observation = observation
            .map(TryInto::try_into)
            .ok_or_else(|| crate::ParseError(TypeId::of::<Observation>()))??;

        Ok(Observe {
            oracle,
            observation,
        })
    }
}

impl From<Observe> for proto::action::Observe {
    fn from(observe: Observe) -> Self {
        let Observe {
            oracle,
            observation,
        } = observe;
        proto::action::Observe {
            signature: Some(oracle.into()),
            observation: Some(observation.into()),
        }
    }
}

impl TryFrom<proto::Config> for Config {
    type Error = crate::ParseError;

    fn try_from(value: proto::Config) -> Result<Self, Self::Error> {
        let proto::Config {
            version,
            admin_config,
            oracle_config,
            onion_config,
        } = value;

        let version = version
            .try_into()
            .map_err(|_| crate::ParseError(TypeId::of::<u64>()))?;

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
            version,
            admin_config,
            oracle_config,
            onion_config,
        })
    }
}

impl From<Config> for proto::Config {
    fn from(config: Config) -> Self {
        let Config {
            version,
            admin_config,
            oracle_config,
            onion_config,
        } = config;
        proto::Config {
            version: version as i64,
            admin_config: Some(admin_config.into()),
            oracle_config: Some(oracle_config.into()),
            onion_config: Some(onion_config.into()),
        }
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

impl From<AdminConfig> for proto::config::AdminConfig {
    fn from(config: AdminConfig) -> Self {
        let AdminConfig {
            admins,
            voting_config,
        } = config;
        proto::config::AdminConfig {
            admins: admins.into_iter().map(Into::into).collect(),
            voting_config: Some(voting_config.into()),
        }
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
            observation_timeout,
        } = value;

        let max_enrolled_subdomains: u64 = max_enrolled_subdomains
            .try_into()
            .map_err(|_| crate::ParseError(TypeId::of::<u64>()))?;

        let oracles = oracles
            .into_iter()
            .map(TryInto::try_into)
            .collect::<Result<_, _>>()?;

        let voting_config = voting_config
            .map(TryInto::try_into)
            .ok_or_else(|| crate::ParseError(TypeId::of::<VotingConfig>()))??;

        let observation_timeout = Duration::from_secs(
            observation_timeout
                .try_into()
                .map_err(|_| crate::ParseError(TypeId::of::<Duration>()))?,
        );

        Ok(OracleConfig {
            enabled,
            oracles,
            voting_config,
            observation_timeout,
            max_enrolled_subdomains,
        })
    }
}

impl From<OracleConfig> for proto::config::OracleConfig {
    fn from(config: OracleConfig) -> Self {
        let OracleConfig {
            enabled,
            oracles,
            voting_config,
            max_enrolled_subdomains,
            observation_timeout,
        } = config;
        proto::config::OracleConfig {
            enabled,
            oracles: oracles.into_iter().map(Into::into).collect(),
            voting_config: Some(voting_config.into()),
            observation_timeout: observation_timeout.as_secs() as i64,
            max_enrolled_subdomains: max_enrolled_subdomains as i64,
        }
    }
}

impl TryFrom<proto::config::OnionConfig> for OnionConfig {
    type Error = crate::ParseError;

    fn try_from(value: proto::config::OnionConfig) -> Result<Self, Self::Error> {
        let proto::config::OnionConfig { enabled } = value;
        Ok(OnionConfig { enabled })
    }
}

impl From<OnionConfig> for proto::config::OnionConfig {
    fn from(config: OnionConfig) -> Self {
        let OnionConfig { enabled } = config;
        proto::config::OnionConfig { enabled }
    }
}

impl TryFrom<proto::config::VotingConfig> for VotingConfig {
    type Error = crate::ParseError;

    fn try_from(value: proto::config::VotingConfig) -> Result<Self, Self::Error> {
        let proto::config::VotingConfig {
            total,
            quorum,
            timeout,
            delay,
        } = value;

        let total = Total(
            total
                .try_into()
                .map_err(|_| crate::ParseError(TypeId::of::<u64>()))?,
        );
        let quorum = Quorum(
            quorum
                .try_into()
                .map_err(|_| crate::ParseError(TypeId::of::<u64>()))?,
        );
        let timeout = Timeout(Duration::from_secs(
            u64::try_from(timeout).map_err(|_| crate::ParseError(TypeId::of::<u64>()))?,
        ));
        let delay = Delay(Duration::from_secs(
            u64::try_from(delay).map_err(|_| crate::ParseError(TypeId::of::<u64>()))?,
        ));

        Ok(VotingConfig {
            total,
            quorum,
            timeout,
            delay,
        })
    }
}

impl From<VotingConfig> for proto::config::VotingConfig {
    fn from(config: VotingConfig) -> Self {
        let VotingConfig {
            total,
            quorum,
            timeout,
            delay,
        } = config;
        proto::config::VotingConfig {
            total: total.0 as i64,
            quorum: quorum.0 as i64,
            timeout: timeout.0.as_secs() as i64,
            delay: delay.0.as_secs() as i64,
        }
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

        let hash_observed = if let Some(hash) = hash_observed {
            let hash: [u8; 32] = hash
                .to_vec()
                .try_into()
                .map_err(|_| crate::ParseError(TypeId::of::<HashObserved>()))?;
            HashObserved::Hash(hash)
        } else {
            HashObserved::NotFound
        };

        let blockstamp = blockstamp
            .ok_or_else(|| crate::ParseError(TypeId::of::<Blockstamp>()))?
            .try_into()
            .map_err(|_| crate::ParseError(TypeId::of::<Blockstamp>()))?;

        Ok(Observation {
            domain,
            hash_observed,
            blockstamp,
        })
    }
}

impl From<Observation> for proto::action::observe::Observation {
    fn from(observation: Observation) -> Self {
        let Observation {
            domain,
            hash_observed,
            blockstamp,
        } = observation;
        proto::action::observe::Observation {
            domain: domain.to_string(),
            hash_observed: match hash_observed {
                HashObserved::Hash(h) => Some(h.to_vec().into()),
                HashObserved::NotFound => None,
            },
            blockstamp: Some(blockstamp.into()),
        }
    }
}

impl TryFrom<proto::action::observe::observation::Blockstamp> for Blockstamp {
    type Error = crate::ParseError;

    fn try_from(
        value: proto::action::observe::observation::Blockstamp,
    ) -> Result<Self, Self::Error> {
        let proto::action::observe::observation::Blockstamp {
            block_hash,
            block_number,
        } = value;

        let block_hash = block_hash
            .to_vec()
            .try_into()
            .map_err(|_| crate::ParseError(TypeId::of::<[u8; 32]>()))?;

        let block_height: Height = u64::try_from(block_number)
            .map_err(|_| crate::ParseError(TypeId::of::<u64>()))?
            .try_into()
            .map_err(|_| crate::ParseError(TypeId::of::<Height>()))?;

        Ok(Blockstamp {
            app_hash: block_hash,
            block_height,
        })
    }
}

impl From<Blockstamp> for proto::action::observe::observation::Blockstamp {
    fn from(blockstamp: Blockstamp) -> Self {
        let Blockstamp {
            app_hash,
            block_height,
        } = blockstamp;
        proto::action::observe::observation::Blockstamp {
            block_hash: app_hash.as_bytes().to_vec().into(),
            block_number: block_height.value() as i64,
        }
    }
}

impl TryFrom<proto::Admin> for Admin {
    type Error = crate::ParseError;

    fn try_from(value: proto::Admin) -> Result<Self, Self::Error> {
        let _pk = ParsedPublicKey::new(&EdDSAParameters, &value.public_key)
            .map_err(|_| crate::ParseError(TypeId::of::<ParsedPublicKey>()))?;
        Ok(Admin {
            identity: value.public_key,
        })
    }
}

impl TryFrom<Unsigned> for Admin {
    type Error = crate::ParseError;

    fn try_from(value: Unsigned) -> Result<Self, Self::Error> {
        let _pk = ParsedPublicKey::new(&EdDSAParameters, &value.public_key)
            .map_err(|_| crate::ParseError(TypeId::of::<ParsedPublicKey>()))?;
        Ok(Admin {
            identity: value.public_key,
        })
    }
}

impl From<Admin> for proto::Admin {
    fn from(admin: Admin) -> Self {
        proto::Admin {
            public_key: admin.identity,
        }
    }
}

impl From<Admin> for proto::Signature {
    fn from(admin: Admin) -> Self {
        proto::Signature::unsigned(admin.identity)
    }
}

impl TryFrom<proto::Oracle> for Oracle {
    type Error = crate::ParseError;

    fn try_from(value: proto::Oracle) -> Result<Self, Self::Error> {
        let _pk = ParsedPublicKey::new(&EdDSAParameters, &value.public_key)
            .map_err(|_| crate::ParseError(TypeId::of::<ParsedPublicKey>()))?;
        Ok(Oracle {
            identity: value.public_key,
        })
    }
}

impl TryFrom<Unsigned> for Oracle {
    type Error = crate::ParseError;

    fn try_from(value: Unsigned) -> Result<Self, Self::Error> {
        let _pk = ParsedPublicKey::new(&EdDSAParameters, &value.public_key)
            .map_err(|_| crate::ParseError(TypeId::of::<ParsedPublicKey>()))?;
        Ok(Oracle {
            identity: value.public_key,
        })
    }
}

impl From<Oracle> for proto::Oracle {
    fn from(oracle: Oracle) -> Self {
        proto::Oracle {
            public_key: oracle.identity,
        }
    }
}

impl From<Oracle> for proto::Signature {
    fn from(oracle: Oracle) -> Self {
        proto::Signature::unsigned(oracle.identity)
    }
}
