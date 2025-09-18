use aws_lc_rs::signature::{EdDSAParameters, ParsedPublicKey};
use felidae_proto::transaction::{self as proto};
use std::any::TypeId;

use super::*;

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
        let proto::action::Reconfigure { signature, config } = value;

        let admin = signature
            .map(TryInto::try_into)
            .ok_or_else(|| crate::ParseError(TypeId::of::<Admin>()))??;

        let config = config
            .map(TryInto::try_into)
            .ok_or_else(|| crate::ParseError(TypeId::of::<Config>()))??;

        Ok(Reconfigure { admin, config })
    }
}

impl From<Reconfigure> for proto::action::Reconfigure {
    fn from(reconfigure: Reconfigure) -> Self {
        let Reconfigure { admin, config } = reconfigure;
        proto::action::Reconfigure {
            signature: Some(admin.into()),
            config: Some(config.into()),
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
            .map(TryInto::try_into)
            .ok_or_else(|| crate::ParseError(TypeId::of::<Oracle>()))??;

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

impl From<Config> for proto::Config {
    fn from(config: Config) -> Self {
        let Config {
            admin_config,
            oracle_config,
            onion_config,
        } = config;
        proto::Config {
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

        Ok(OracleConfig {
            enabled,
            oracles,
            voting_config,
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
        } = config;
        proto::config::OracleConfig {
            enabled,
            oracles: oracles.into_iter().map(Into::into).collect(),
            voting_config: Some(voting_config.into()),
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
        let timeout = Timeout(
            timeout
                .try_into()
                .map_err(|_| crate::ParseError(TypeId::of::<u64>()))?,
        );
        let delay = Delay(
            delay
                .try_into()
                .map_err(|_| crate::ParseError(TypeId::of::<u64>()))?,
        );

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
            timeout: timeout.0 as i64,
            delay: delay.0 as i64,
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

        let hash_observed = HashObserved(
            hash_observed
                .ok_or_else(|| crate::ParseError(TypeId::of::<HashObserved>()))?
                .to_vec()
                .try_into()
                .map_err(|_| crate::ParseError(TypeId::of::<HashObserved>()))?,
        );

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

impl From<Observation> for proto::action::observe::Observation {
    fn from(observation: Observation) -> Self {
        let Observation {
            domain,
            hash_observed,
            blockstamp,
        } = observation;
        proto::action::observe::Observation {
            domain: domain.to_string(),
            hash_observed: Some(hash_observed.0.to_vec().into()),
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

        let block_number: u64 = block_number
            .try_into()
            .map_err(|_| crate::ParseError(TypeId::of::<u64>()))?;

        Ok(Blockstamp {
            app_hash: block_hash,
            block_number,
        })
    }
}

impl From<Blockstamp> for proto::action::observe::observation::Blockstamp {
    fn from(blockstamp: Blockstamp) -> Self {
        let Blockstamp {
            app_hash,
            block_number,
        } = blockstamp;
        proto::action::observe::observation::Blockstamp {
            block_hash: app_hash.as_bytes().to_vec().into(),
            block_number: block_number as i64,
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

impl TryFrom<proto::Signature> for Admin {
    type Error = crate::ParseError;

    fn try_from(value: proto::Signature) -> Result<Self, Self::Error> {
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
        proto::Signature::new(admin.identity)
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

impl TryFrom<proto::Signature> for Oracle {
    type Error = crate::ParseError;

    fn try_from(value: proto::Signature) -> Result<Self, Self::Error> {
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
        proto::Signature::new(oracle.identity)
    }
}
