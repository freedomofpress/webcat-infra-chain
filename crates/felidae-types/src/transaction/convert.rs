use felidae_proto::transaction::{self as proto, KeyPair};
use fqdn::FQDN;

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
            Err(crate::ParseError::new::<ChainId>(value))
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

impl TryFrom<String> for Domain {
    type Error = crate::ParseError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let name = FQDN::from_ascii_str(&value)
            .map_err(|_| crate::ParseError::new::<Domain>(value.clone()))?;
        Ok(Domain { name })
    }
}

impl From<Domain> for String {
    fn from(value: Domain) -> Self {
        value.name.to_string()
    }
}

impl TryFrom<String> for Zone {
    type Error = crate::ParseError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let name = FQDN::from_ascii_str(&value)
            .map_err(|_| crate::ParseError::new::<Zone>(value.clone()))?;
        Ok(Zone { name })
    }
}

impl From<Zone> for String {
    fn from(value: Zone) -> Self {
        value.name.to_string()
    }
}

impl From<PrefixOrderDomain> for String {
    fn from(value: PrefixOrderDomain) -> Self {
        value.name.to_string()
    }
}

impl TryFrom<String> for PrefixOrderDomain {
    type Error = crate::ParseError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let name = FQDN::from_ascii_str(&value)
            .map_err(|_| crate::ParseError::new::<PrefixOrderDomain>(value.clone()))?;
        Ok(PrefixOrderDomain { name })
    }
}

impl TryFrom<proto::Signature> for Unsigned {
    type Error = crate::ParseError;

    fn try_from(value: proto::Signature) -> Result<Self, Self::Error> {
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
            public_key: value.public_key().into(),
        }
    }
}

impl TryFrom<proto::Action> for Action {
    type Error = crate::ParseError;

    fn try_from(value: proto::Action) -> Result<Self, Self::Error> {
        match value.action {
            Some(proto::action::Action::Reconfigure(reconfigure)) => {
                Ok(Action::Reconfigure(reconfigure.try_into()?))
            }
            Some(proto::action::Action::Observe(observe)) => {
                Ok(Action::Observe(observe.try_into()?))
            }
            None => Err(crate::ParseError::new::<Action>("missing".to_string())),
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
            .ok_or_else(|| crate::ParseError::new::<Admin>("missing".to_string()))??
            .try_into()?;

        let config = config
            .map(TryInto::try_into)
            .ok_or_else(|| crate::ParseError::new::<Config>("missing".to_string()))??;

        let not_before = not_before
            .map(TryInto::try_into)
            .ok_or_else(|| crate::ParseError::new::<tendermint::Time>("missing".to_string()))?
            .map_err(|_| crate::ParseError::new::<tendermint::Time>("missing".to_string()))?;

        let not_after = not_after
            .map(TryInto::try_into)
            .ok_or_else(|| crate::ParseError::new::<tendermint::Time>("missing".to_string()))?
            .map_err(|_| crate::ParseError::new::<tendermint::Time>("missing".to_string()))?;

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
            .ok_or_else(|| crate::ParseError::new::<Oracle>("missing".to_string()))??
            .try_into()?;

        let observation = observation
            .map(TryInto::try_into)
            .ok_or_else(|| crate::ParseError::new::<Observation>("missing".to_string()))??;

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
            .map_err(|_| crate::ParseError::new::<u32>("missing".to_string()))?;

        let admin_config = admin_config
            .map(TryInto::try_into)
            .ok_or_else(|| crate::ParseError::new::<AdminConfig>("missing".to_string()))??;

        let oracle_config = oracle_config
            .map(TryInto::try_into)
            .ok_or_else(|| crate::ParseError::new::<OracleConfig>("missing".to_string()))??;

        let onion_config = onion_config
            .map(TryInto::try_into)
            .ok_or_else(|| crate::ParseError::new::<OnionConfig>("missing".to_string()))??;

        Ok(Config {
            version,
            admins: admin_config,
            oracles: oracle_config,
            onion: onion_config,
        })
    }
}

impl From<Config> for proto::Config {
    fn from(config: Config) -> Self {
        let Config {
            version,
            admins: admin_config,
            oracles: oracle_config,
            onion: onion_config,
        } = config;
        proto::Config {
            version: version.into(),
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
            .ok_or_else(|| crate::ParseError::new::<VotingConfig>("missing".to_string()))??;

        Ok(AdminConfig {
            authorized: admins,
            voting: voting_config,
        })
    }
}

impl From<AdminConfig> for proto::config::AdminConfig {
    fn from(config: AdminConfig) -> Self {
        let AdminConfig {
            authorized: admins,
            voting: voting_config,
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

        let max_enrolled_subdomains: u64 = u64::try_from(max_enrolled_subdomains)
            .map_err(|_| crate::ParseError::new::<u64>("missing".to_string()))?;

        let oracles = oracles
            .into_iter()
            .map(TryInto::try_into)
            .collect::<Result<_, _>>()?;

        let voting_config = voting_config
            .map(TryInto::try_into)
            .ok_or_else(|| crate::ParseError::new::<VotingConfig>("missing".to_string()))??;

        let observation_timeout = Duration::from_secs(
            u64::try_from(observation_timeout)
                .map_err(|_| crate::ParseError::new::<Duration>("missing".to_string()))?,
        );

        Ok(OracleConfig {
            enabled,
            authorized: oracles,
            voting: voting_config,
            observation_timeout,
            max_enrolled_subdomains,
        })
    }
}

impl From<OracleConfig> for proto::config::OracleConfig {
    fn from(config: OracleConfig) -> Self {
        let OracleConfig {
            enabled,
            authorized: oracles,
            voting: voting_config,
            max_enrolled_subdomains,
            observation_timeout,
        } = config;
        proto::config::OracleConfig {
            enabled,
            oracles: oracles.into_iter().map(Into::into).collect(),
            voting_config: Some(voting_config.into()),
            observation_timeout: i64::try_from(observation_timeout.as_secs()).unwrap_or(i64::MAX),
            max_enrolled_subdomains: i64::try_from(max_enrolled_subdomains).unwrap_or(i64::MAX),
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

        let total =
            Total(u64::try_from(total).map_err(|_| crate::ParseError::new::<Total>(total))?);
        let quorum =
            Quorum(u64::try_from(quorum).map_err(|_| crate::ParseError::new::<Quorum>(quorum))?);
        let timeout = Timeout(Duration::from_secs(
            u64::try_from(timeout).map_err(|_| crate::ParseError::new::<Timeout>(timeout))?,
        ));
        let delay = Delay(Duration::from_secs(
            u64::try_from(delay).map_err(|_| crate::ParseError::new::<Delay>(delay))?,
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
            total: i64::try_from(total.0).unwrap_or(i64::MAX),
            quorum: i64::try_from(quorum.0).unwrap_or(i64::MAX),
            timeout: i64::try_from(timeout.0.as_secs()).unwrap_or(i64::MAX),
            delay: i64::try_from(delay.0.as_secs()).unwrap_or(i64::MAX),
        }
    }
}

impl TryFrom<proto::action::observe::Observation> for Observation {
    type Error = crate::ParseError;

    fn try_from(value: proto::action::observe::Observation) -> Result<Self, Self::Error> {
        let proto::action::observe::Observation {
            domain,
            zone,
            hash_observed,
            blockstamp,
        } = value;

        let domain = Domain {
            name: FQDN::from_ascii_str(&domain)
                .map_err(|_| crate::ParseError::new::<Domain>(domain))?,
        };

        let zone = Zone {
            name: FQDN::from_ascii_str(&zone).map_err(|_| crate::ParseError::new::<Zone>(zone))?,
        };

        let hash_observed = hash_observed
            .map(TryInto::try_into)
            .ok_or_else(|| crate::ParseError::new::<HashObserved>("missing".to_string()))??;

        let blockstamp = blockstamp
            .ok_or_else(|| crate::ParseError::new::<Blockstamp>("missing".to_string()))?
            .try_into()
            .map_err(|_| crate::ParseError::new::<Blockstamp>("missing".to_string()))?;

        Ok(Observation {
            domain,
            zone,
            hash_observed,
            blockstamp,
        })
    }
}

impl From<Observation> for proto::action::observe::Observation {
    fn from(observation: Observation) -> Self {
        let Observation {
            domain,
            zone,
            hash_observed,
            blockstamp,
        } = observation;
        proto::action::observe::Observation {
            domain: domain.into(),
            zone: zone.into(),
            hash_observed: Some(hash_observed.into()),
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
            .map_err(|_| crate::ParseError::new::<AppHash>("missing".to_string()))?;

        let block_height: Height = u64::try_from(block_number)
            .map_err(|_| crate::ParseError::new::<Height>("missing".to_string()))?
            .try_into()
            .map_err(|_| crate::ParseError::new::<Height>("missing".to_string()))?;

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
            block_number: i64::try_from(block_height.value()).unwrap_or(i64::MAX),
        }
    }
}

impl TryFrom<proto::Admin> for Admin {
    type Error = crate::ParseError;

    fn try_from(value: proto::Admin) -> Result<Self, Self::Error> {
        Ok(Admin {
            identity: value.public_key,
        })
    }
}

impl TryFrom<Unsigned> for Admin {
    type Error = crate::ParseError;

    fn try_from(value: Unsigned) -> Result<Self, Self::Error> {
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
        Ok(Oracle {
            identity: value.public_key,
        })
    }
}

impl TryFrom<Unsigned> for Oracle {
    type Error = crate::ParseError;

    fn try_from(value: Unsigned) -> Result<Self, Self::Error> {
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

impl From<FQDN> for Domain {
    fn from(name: FQDN) -> Self {
        Domain { name }
    }
}

impl From<Domain> for FQDN {
    fn from(domain: Domain) -> Self {
        domain.name
    }
}

impl From<Empty> for String {
    fn from(_: Empty) -> Self {
        String::new()
    }
}

impl TryFrom<String> for Empty {
    type Error = crate::ParseError;

    fn try_from(string: String) -> Result<Self, crate::ParseError> {
        string
            .parse()
            .map_err(|_| crate::ParseError::new::<Empty>(string))
    }
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
            Err(crate::ParseError::new::<HashObserved>(hex::encode(
                value.hash,
            )))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_parse() {
        let domain_str = "com.";
        let domain: FQDN = domain_str.parse().unwrap();
        assert_eq!(domain.to_string(), domain_str);
    }
}
