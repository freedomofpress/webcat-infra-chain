#[macro_use]
extern crate tracing;

use std::{collections::BTreeSet, str::FromStr, time::Duration};

use color_eyre::{
    Report,
    eyre::{OptionExt, bail, eyre},
};
use felidae_types::{
    FQDN,
    transaction::{
        Action, Admin, AdminConfig, AuthenticatedTx, Blockstamp, ChainId, Config, Delay, Domain,
        Empty, HashObserved, Observation, Observe, OnionConfig, Oracle, OracleConfig,
        PrefixOrderDomain, Quorum, Reconfigure, Timeout, Total, Transaction, VotingConfig,
    },
};
use futures::{Stream, StreamExt};
use prost::Message;
use prost::bytes::Bytes;
use sha2::{Digest, Sha256};
use tendermint::{
    AppHash, Time,
    abci::{
        request, response,
        types::{BlockSignatureInfo, CommitInfo, Misbehavior, Validator, VoteInfo},
    },
    block::{BlockIdFlag, Header, Height},
    validator::Update,
    vote::Power,
};

mod store;
pub use store::Store;
use store::{
    StateReadExt, StateWriteExt,
    Substore::{Canonical, Internal},
};

mod vote_queue;
pub use vote_queue::{Vote, VoteQueue};

/// ABCI service implementation for [`State`].
mod abci;

#[derive(Debug, Clone)]
pub struct State<S> {
    store: S,
}

impl<S> State<S> {
    /// Create a new state with the given store.
    pub fn new(store: S) -> Self {
        Self { store }
    }
}

impl<S: StateReadExt + StateWriteExt + 'static> State<S> {
    /// Initialize the chain state.
    #[instrument(skip(self, request,))]
    pub async fn init_chain(
        &mut self,
        request: request::InitChain,
    ) -> Result<response::InitChain, Report> {
        // The initial app hash should be the hash of the InitChain request canonicalized as a protobuf:
        let mut hasher = Sha256::new();
        hasher.update(
            tendermint_proto::v0_34::abci::RequestInitChain::from(request.clone()).encode_to_vec(),
        );
        let app_hash = AppHash::try_from(hasher.finalize().to_vec())?;

        // Ensure that the initial height is 1:
        if request.initial_height.value() != 1 {
            bail!("initial height must be 1");
        }

        // Set the chain ID in the state:
        self.set_chain_id(ChainId(request.chain_id)).await?;

        // TODO: Set the genesis time in the state

        // Ensure that the app state is empty:
        if !request.app_state_bytes.is_empty() {
            bail!("app state must be empty");
        }

        // Set the initial config in the state:
        self.set_config(Config {
            version: 0,
            admins: AdminConfig {
                authorized: vec![], // Default admin set: the first reconfig will set this
                voting: VotingConfig {
                    total: Total(0),   // No admins required to initially reconfigure
                    quorum: Quorum(0), // No quorum required to initially reconfigure
                    timeout: Timeout(Duration::from_secs(0)), // No follow-up voting for initial reconfig
                    delay: Delay(Duration::from_secs(0)),     // No delay for initial reconfig
                },
            },
            oracles: OracleConfig {
                enabled: false,     // Oracles disabled initially
                authorized: vec![], // No oracles initially
                voting: VotingConfig {
                    total: Total(0),                                    // No oracles initially
                    quorum: Quorum(0),                                  // No voting initially
                    timeout: Timeout(Duration::from_secs(0)),           // No voting initially
                    delay: Delay(Duration::from_secs(i64::MAX as u64)), // No voting initially
                },
                max_enrolled_subdomains: 0, // No subdomains initially
                observation_timeout: Duration::from_secs(i64::MAX as u64), // No observations initially
            },
            onion: OnionConfig { enabled: false },
        })
        .await?;

        // Declare the initial validator set:
        for validator in request.validators.iter() {
            self.declare_validator(validator.clone()).await?;
        }

        Ok(response::InitChain {
            // TODO: permit changing consensus params?
            consensus_params: Some(request.consensus_params),
            // TODO: permit declaring validators in initial chain params: reflect them here
            validators: request.validators,
            app_hash,
        })
    }

    /// Helper function to pad block heights for lexicographic ordering.
    ///
    /// Uses 20 digits to accommodate the full u64 range.
    fn pad_height(height: Height) -> String {
        format!("{:020}", height.value())
    }

    /// Begin a block, without committing yet.
    pub async fn begin_block(
        &mut self,
        request::BeginBlock {
            last_commit_info: CommitInfo { round: _, votes },
            byzantine_validators,
            header:
                Header {
                    chain_id,
                    height,
                    time,
                    app_hash,
                    version: _,
                    last_block_id: _,
                    last_commit_hash: _,
                    data_hash: _,
                    validators_hash: _,
                    next_validators_hash: _,
                    consensus_hash: _,
                    last_results_hash: _,
                    evidence_hash: _,
                    proposer_address: _,
                },
            hash: _,
        }: request::BeginBlock,
    ) -> Result<response::BeginBlock, Report> {
        // Ensure chain ID matches the current chain ID:
        let current_chain_id = self.chain_id().await?;
        if chain_id.as_str() != current_chain_id.0 {
            bail!(
                "begin-block chain ID {} does not match current chain ID {}",
                chain_id.as_str(),
                current_chain_id.0,
            );
        }

        // Record validator uptime
        let mut voting_validators = BTreeSet::new();
        for VoteInfo {
            validator,
            sig_info,
        } in votes
        {
            let voted = match sig_info {
                BlockSignatureInfo::Flag(BlockIdFlag::Absent) => false,
                BlockSignatureInfo::Flag(BlockIdFlag::Commit | BlockIdFlag::Nil)
                | BlockSignatureInfo::LegacySigned => true,
            };
            if voted {
                voting_validators.insert(validator.address);
            }
        }
        self.mark_validators_voted(voting_validators).await?;

        // TODO: Tombstone inactive validators?

        // Tombstone byzantine validators
        for Misbehavior {
            validator: bad_validator,
            kind: _,
            height: _,
            time: _,
            total_voting_power: _,
        } in byzantine_validators
        {
            self.tombstone_validator(bad_validator).await?;
        }

        // Record the current block height and time:
        self.set_block_height(height).await?;
        self.set_block_time(time).await?;

        // Record the previous block's app hash:
        self.record_app_hash(app_hash).await?;

        // Timeout expired votes in the vote queues
        self.admin_voting().await?.timeout_expired_votes().await?;
        self.oracle_voting().await?.timeout_expired_votes().await?;

        Ok(response::BeginBlock { events: vec![] })
    }

    /// Deliver transaction bytes to the state.
    pub async fn deliver_tx(&mut self, tx_bytes: &[u8]) -> Result<(), Report> {
        let tx = AuthenticatedTx::from_proto(tx_bytes)?;
        self.deliver_authenticated_tx(&tx).await
    }

    /// Execute a transaction against the current state, without committing the results yet.
    async fn deliver_authenticated_tx(&mut self, tx: &AuthenticatedTx) -> Result<(), Report> {
        let Transaction { actions, .. } = &**tx;

        // First, check the chain ID to see if it matches the current chain ID.
        let current_chain_id = self.chain_id().await?;
        if tx.chain_id != current_chain_id {
            bail!(
                "transaction chain ID {} does not match current chain ID {}",
                tx.chain_id.0,
                current_chain_id.0,
            );
        }

        // Ensure the transaction is non-empty:
        if actions.is_empty() {
            bail!("transaction must contain at least one action");
        }

        // Then, apply each action in order:
        for action in actions {
            use Action::*;
            match action {
                Reconfigure(reconfig) => self.reconfigure(reconfig).await?,
                Observe(observe) => self.observe(observe).await?,
            }
        }

        Ok(())
    }

    /// End a block, without committing yet.
    pub async fn end_block(
        &mut self,
        request::EndBlock { height }: request::EndBlock,
    ) -> Result<response::EndBlock, Report> {
        // Ensure the height matches the current height:
        let current_height = self.block_height().await?;
        if Height::try_from(u64::try_from(height)?)? != current_height {
            bail!(
                "end-block height {} does not match current height {}",
                height,
                current_height
            );
        }

        // Process ripe pending config changes into current config
        for (_, new_config) in self.admin_voting().await?.promote_pending_changes().await? {
            // We want to only apply configs with a version greater than the current version, to
            // avoid replay attacks. This can only happen if there are multiple pending config
            // changes: this prevents someone from re-submitting an older but still-pending config
            // change sequenced after a newer config change, but in the same block. If this were to
            // be permitted, this would allow the older config to override the newer config, without
            // requiring interaction by admins, since this is a replay of already signed data.
            //
            // This is also prevented by a check on the version in the reconfigure action, but
            // checking it here too is defense in depth.
            let current_config = self.config().await?;
            if current_config.version >= new_config.version {
                info!(
                    version = new_config.version,
                    "skipping new config with older version than current"
                );
                continue;
            }

            info!(version = new_config.version, "applying new config",);
            self.set_config(new_config).await?;
        }

        // Process ripe pending oracle observations into canonical state
        for (subdomain, hash_observed) in self
            .oracle_voting()
            .await?
            .promote_pending_changes()
            .await?
        {
            self.update_canonical(subdomain.into(), hash_observed)
                .await?;
        }

        Ok(response::EndBlock {
            validator_updates: self.active_validators().await?,
            events: vec![],
            consensus_param_updates: None,
        })
    }

    /// Handle a reconfiguration action.
    #[instrument(skip(self, reconfig))]
    async fn reconfigure(&mut self, reconfig: &Reconfigure) -> Result<(), Report> {
        let Reconfigure {
            admin: admin @ Admin { identity },
            config,
            not_before,
            not_after,
        } = reconfig;

        // Check that the admin is a current admin (or that there are no admins yet -- i.e. this is
        // the initial configuration being set, which can be done without permission):
        let current_config = self.config().await?;

        if !current_config.admins.authorized.is_empty()
            && !current_config.admins.authorized.iter().any(|a| a == admin)
        {
            bail!("not a current admin: {}", hex::encode(identity));
        }

        // Ensure the current time is within the not_before and not_after bounds:
        let current_time = self.block_time().await?;
        if current_time < *not_before {
            bail!("current time {current_time} is before the not_before bound {not_before}");
        }
        if current_time > *not_after {
            bail!("current time {current_time} is after the not_after bound {not_after}");
        }

        // Check the config for current validity:
        self.check_config(config).await?;

        // Ensure that the version is greater than any pending config change:
        if let Some(pending_config) = self.admin_voting().await?.pending_for_key(Empty).await?
            && pending_config.version >= config.version
        {
            bail!(
                "newly proposed config version {} must be greater than pending version {}",
                config.version,
                pending_config.version
            );
        }

        // Enqueue the config change in the vote queue for admin reconfigurations
        self.admin_voting()
            .await?
            .cast(Vote {
                key: Empty,
                party: hex::encode(identity),
                time: current_time,
                value: config.clone(),
            })
            .await?;

        Ok(())
    }

    /// Handle an observation action.
    #[instrument(skip(self, observe), fields(domain = %observe.observation.domain, zone = %observe.observation.zone))]
    async fn observe(&mut self, observe: &Observe) -> Result<(), Report> {
        let Observe {
            oracle: oracle @ Oracle { identity },
            observation:
                Observation {
                    domain: subdomain,
                    zone,
                    hash_observed,
                    blockstamp:
                        Blockstamp {
                            block_height,
                            app_hash,
                        },
                },
        } = observe;

        // Check that the oracle is a current oracle:
        let current_config = self.config().await?;
        if !current_config
            .oracles
            .authorized
            .iter()
            .any(|o| o == oracle)
        {
            bail!("not a current oracle: {}", hex::encode(identity));
        }

        // Ensure the blockstamp is not in the future
        let current_block_height = self.block_height().await?;
        if *block_height > current_block_height {
            bail!("blockstamp {block_height} is in the future");
        }

        // Ensure the blockstamp is recent enough based on the configured observation timeout
        let current_time = self.block_time().await?;
        let block_time = self.time_of_block(*block_height).await?;
        let observation_age = current_time.duration_since(block_time).map_err(|_| {
            eyre!(
                "current time {} is before block time {}",
                current_time,
                block_time
            )
        })?;
        if observation_age >= current_config.oracles.observation_timeout {
            bail!("blockstamp is too old based on observation timeout");
        }

        // Ensure the blockstamp's app hash matches the app hash at the given block number
        let recorded_app_hash = self.previous_app_hash(*block_height).await?;
        if recorded_app_hash != *app_hash {
            bail!(
                "blockstamp app hash {app_hash} does not match recorded app hash {recorded_app_hash} for block {block_height}"
            );
        }

        // In the voting queue, we need to treat domains as prefix-ordered:
        let subdomain = PrefixOrderDomain::from(subdomain.clone());

        // Ensure that the domain is not equal to the zone, and instead is a strict subdomain of the zone:
        if subdomain.name == zone.name {
            bail!(
                "observed domain {} must be a strict subdomain of zone {}",
                subdomain,
                zone
            );
        }
        if !subdomain.name.is_subdomain_of(&zone.name) {
            bail!(
                "observed domain {} is not a subdomain of zone {}",
                subdomain,
                zone
            );
        }

        // Compute the registered domain (the registration zone plus one additional label)
        let registered_domain = PrefixOrderDomain::from(Domain::from(
            subdomain
                .name
                .hierarchy()
                .nth(subdomain.name.depth() - zone.name.depth() - 1)
                .ok_or_eyre("zone depths invalid (should not happen)")?
                .to_owned(),
        ));

        // Prevent unenrolling non-existent subdomains or enrolling too many new subdomains:
        if self
            .canonical_hash(subdomain.clone().into())
            .await?
            .is_none()
        {
            let pending_change = self
                .oracle_voting()
                .await?
                .pending_for_key(subdomain.clone())
                .await?;
            if let Some(HashObserved::NotFound) | None = pending_change {
                // In this case, we know the subdomain does not exist in pending or canonical state, or
                // is currently already queued for deletion:

                if let HashObserved::NotFound = hash_observed {
                    // This prevents oracles from voting to delete a subdomain that does not exist.
                    bail!(
                        "cannot vote to delete subdomain {subdomain} which is either unknown or already queued for deletion",
                    );
                } else {
                    // If the subdomain does not exist, ensure that the oracle is allowed to register a new
                    // subdomain under the registered domain.
                    let max_enrolled_subdomains = current_config.oracles.max_enrolled_subdomains;

                    // Count the number of distinct subdomains under the registered domain in both
                    // the canonical state and the pending changes, and ensure it is less than the max
                    // allowed:
                    let registered_domain_votes = self
                        .oracle_voting()
                        .await?
                        .votes_for_key(registered_domain.clone())
                        .await?;
                    let subdomain_votes = self
                        .oracle_voting()
                        .await?
                        .votes_for_key_prefix(registered_domain.clone(), Some('.'))
                        .await?;
                    let registered_domain_pending = self
                        .oracle_voting()
                        .await?
                        .pending_for_key(registered_domain.clone())
                        .await?;
                    let subdomain_pending = self
                        .oracle_voting()
                        .await?
                        .pending_for_key_prefix(registered_domain.clone(), Some('.'))
                        .await?;
                    let canonical_subdomains = self
                        .canonical_subdomains(registered_domain.clone().into())
                        .await?;

                    // We collect all the places in the pipeline, from voting to pending to canonical:
                    let unique_subdomains = registered_domain_votes
                        .into_iter()
                        .map(|v| v.key)
                        .chain(subdomain_votes.into_iter().map(|v| v.key))
                        .chain(registered_domain_pending.map({
                            let registered_domain = registered_domain.clone();
                            move |_| registered_domain
                        }))
                        .chain(subdomain_pending.into_iter().map(|(_time, k, _v)| k))
                        .chain(canonical_subdomains.into_iter().map(Into::into))
                        .collect::<BTreeSet<_>>()
                        .len();

                    // If adding this new subdomain would exceed the max, bail:
                    if unique_subdomains as u64 + 1 >= max_enrolled_subdomains {
                        bail!(
                            "cannot register new subdomain {subdomain} under {registered_domain}: would exceed max enrolled subdomains of {max_enrolled_subdomains}",
                        );
                    }
                }
            }
        }

        // Enqueue the observation in the vote queue for oracle observations
        self.oracle_voting()
            .await?
            .cast(Vote {
                key: subdomain.clone(),
                party: hex::encode(identity),
                time: current_time,
                value: hash_observed.clone(),
            })
            .await?;

        Ok(())
    }

    /// Get the current chain ID from the state.
    async fn chain_id(&self) -> Result<ChainId, Report> {
        self.store
            .get::<ChainId>(Internal, "parameters/chain_id")
            .await?
            .ok_or_eyre("chain ID not found in state; is the state initialized?")
    }

    /// Set the current chain ID in the state.
    ///
    /// This should only be called once, during initial setup.
    async fn set_chain_id(&mut self, chain_id: ChainId) -> Result<(), Report> {
        let existing = self.chain_id().await.ok();
        if existing.is_some() {
            bail!("chain ID is already set; cannot set it again");
        }

        self.store.put(Internal, "parameters/chain_id", chain_id);
        Ok(())
    }

    /// Get the current config from the state.
    pub async fn config(&self) -> Result<Config, Report> {
        self.store
            .get::<Config>(Internal, "parameters/config")
            .await?
            .ok_or_eyre("config not found in state; is the state initialized?")
    }

    /// Set the current config in the state.
    async fn set_config(&mut self, config: Config) -> Result<(), Report> {
        self.store.put(Internal, "parameters/config", config);
        Ok(())
    }

    /// Get the current block height from the state.
    pub async fn block_height(&self) -> Result<Height, Report> {
        self.store
            .get::<Height>(Internal, "current/block_height")
            .await?
            .ok_or_eyre("block height not found in state; is the state initialized?")
    }

    /// Set the current block height in the state.
    async fn set_block_height(&mut self, height: Height) -> Result<(), Report> {
        self.store.put(Internal, "current/block_height", height);
        Ok(())
    }

    /// Get the current block time from the state.
    async fn block_time(&self) -> Result<Time, Report> {
        self.store
            .get::<Time>(Internal, "current/block_time")
            .await?
            .ok_or_eyre("block time not found in state; is the state initialized?")
    }

    /// Set the current block time in the state.
    async fn set_block_time(&mut self, time: Time) -> Result<(), Report> {
        self.store.put(Internal, "current/block_time", time);
        self.record_block_time(time).await?;
        Ok(())
    }

    /// Get the time of a specific block from the state.
    async fn time_of_block(&self, height: Height) -> Result<Time, Report> {
        self.store
            .get::<Time>(Internal, &format!("blocktime/{}", Self::pad_height(height)))
            .await?
            .ok_or_eyre("block time not found in state")
    }

    /// Record the time of the current block in the state.
    async fn record_block_time(&mut self, time: Time) -> Result<(), Report> {
        let height = self.block_height().await?;
        self.store.put(
            Internal,
            &format!("blocktime/{}", Self::pad_height(height)),
            time,
        );
        Ok(())
    }

    /// Record the app hash of the previous block in the state.
    async fn record_app_hash(&mut self, app_hash: AppHash) -> Result<(), Report> {
        let height = self.block_height().await?.value() - 1;
        self.store.put(
            Internal,
            &format!("apphash/{}", Self::pad_height(height.try_into()?)),
            app_hash.clone(),
        );
        Ok(())
    }

    /// Get the app hash of a specific previous block from the state.
    async fn previous_app_hash(&self, block_height: Height) -> Result<AppHash, Report> {
        self.store
            .get::<AppHash>(
                Internal,
                &format!("apphash/{}", Self::pad_height(block_height)),
            )
            .await?
            .ok_or_eyre("app hash not found in state")
    }

    /// Declare a new validator by its address.
    async fn declare_validator(&mut self, validator: Update) -> Result<(), Report> {
        // Check to ensure the validator does not exist already (prevents redeclaring tombstoned
        // validators to set their power back to non-zero):
        let existing: Option<Power> = self
            .store
            .get(
                Internal,
                &format!(
                    "current/validators/{}",
                    hex::encode(validator.pub_key.to_bytes())
                ),
            )
            .await?;
        if let Some(existing) = existing {
            bail!(
                "Validator {} already exists with power {}",
                hex::encode(validator.pub_key.to_bytes()),
                existing,
            );
        }

        self.store.put(
            Internal,
            &format!(
                "current/validators/{}",
                hex::encode(validator.pub_key.to_bytes())
            ),
            validator.power,
        );

        Ok(())
    }

    /// Tombstone a validator by its address.
    async fn tombstone_validator(
        &mut self,
        Validator {
            address: bad_address,
            ..
        }: Validator,
    ) -> Result<(), Report> {
        // Go through the list of active validators, taking the address (first 20 bytes of the
        // SHA-256 hash of the public key) as and checking if it matches the given address:
        let active_validators = self.active_validators().await?;
        let mut bad_pub_key = None;
        for Update { pub_key, .. } in active_validators {
            // Compute the address of this validator:
            let mut context = Sha256::new();
            context.update(pub_key.to_bytes());
            let pub_key_hash: [u8; 32] = context.finalize().into();
            let validator_address = &pub_key_hash[0..20];

            // If the address matches, we've found the bad validator:
            if validator_address == bad_address {
                bad_pub_key = Some(pub_key);
                break;
            }
        }

        if let Some(bad_pub_key) = bad_pub_key {
            info!(
                pub_key = hex::encode(bad_pub_key.to_bytes()),
                "tombstoning validator",
            );
        } else {
            warn!(
                "could not find validator with address {}; it may have already been tombstoned",
                hex::encode(bad_address)
            );
        }

        Ok(())
    }

    /// Get all active validators.
    async fn active_validators(&self) -> Result<Vec<Update>, Report> {
        let mut updates = vec![];
        let mut stream = Box::pin(self.store.prefix::<Power>(Internal, "current/validators/"));
        while let Some(Ok((key, power))) = stream.next().await {
            let pub_key = hex::decode(key.trim_start_matches("current/validators/"))?;
            if power.value() > 0 {
                updates.push(Update {
                    pub_key: tendermint::PublicKey::from_raw_ed25519(&pub_key)
                        .ok_or_eyre("invalid ed25519 public key")?,
                    power,
                });
            }
        }
        Ok(updates)
    }

    /// Record validator uptime for the current block.
    async fn mark_validators_voted(&mut self, addresses: BTreeSet<[u8; 20]>) -> Result<(), Report> {
        let active_validators = self.active_validators().await?;
        let mut voting_validators = Vec::new();
        for Update { pub_key, .. } in active_validators {
            // Compute the address of this validator:
            let mut context = Sha256::new();
            context.update(pub_key.to_bytes());
            let pub_key_hash: [u8; 32] = context.finalize().into();
            let validator_address = &pub_key_hash[0..20];

            // If the address is in the list of voting addresses, mark it as having voted:
            if addresses.contains(validator_address) {
                voting_validators.push(pub_key);
            }
        }

        // TODO: Actually record the validator uptimes in the state
        debug!(
            validators = voting_validators
                .iter()
                .map(|pk| hex::encode(pk.to_bytes()))
                .collect::<Vec<_>>()
                .join(", "),
            "voting validators",
        );

        Ok(())
    }

    /// Check a config for internal consistency and validity, as well as validity against the
    /// current config.
    async fn check_config(
        &self,
        Config {
            version,
            admins:
                AdminConfig {
                    authorized: admins,
                    voting: admin_voting_config,
                },
            oracles:
                OracleConfig {
                    enabled: _, // Can be enabled or not
                    authorized: oracles,
                    voting: oracle_voting_config,
                    max_enrolled_subdomains,
                    observation_timeout: _, // Any timeout is acceptable
                },
            onion: OnionConfig {
                enabled: _, // Can be enabled or not
            },
        }: &Config,
    ) -> Result<(), Report> {
        // Ensure the version is greater than the current version:
        let current_config = self.config().await?;
        if *version <= current_config.version {
            bail!(
                "new config version {version} must be greater than current version {}",
                current_config.version
            );
        }

        // Check that the voting configs are valid:
        self.check_voting_config(Total(admins.len() as u64), admin_voting_config)?;
        self.check_voting_config(Total(oracles.len() as u64), oracle_voting_config)?;

        // Ensure that max_enrolled_subdomains is non-zero:
        if *max_enrolled_subdomains == 0 {
            bail!("max_enrolled_subdomains must be non-zero");
        }

        // Ensure that max_enrolled_subdomains does not decrease:
        if *max_enrolled_subdomains < current_config.oracles.max_enrolled_subdomains {
            bail!("max_enrolled_subdomains cannot decrease");
        }

        Ok(())
    }

    /// Ensure that a voting config is internally consistent, and valid with respect to the expected
    /// total number of voting parties.
    fn check_voting_config(
        &self,
        expected_total: Total,
        voting_config: &VotingConfig,
    ) -> Result<(), Report> {
        let VotingConfig {
            total,
            quorum,
            timeout: _, // Any timeout is acceptable
            delay: _,   // Any delay is acceptable
        } = voting_config;

        // Ensure the total matches the expected total:
        if *total != expected_total {
            bail!(
                "voting config total {} does not match expected total {}",
                total.0,
                expected_total.0
            );
        }

        // Ensure the quorum is non-zero and less than or equal to the total:
        if quorum.0 == 0 {
            bail!("voting config quorum must be non-zero");
        }
        if quorum.0 > total.0 {
            bail!(
                "voting config quorum {} cannot be greater than total {}",
                quorum.0,
                total.0
            );
        }

        Ok(())
    }

    /// Get the vote queue for oracle observations.
    pub async fn oracle_voting<'a>(
        &'a mut self,
    ) -> Result<VoteQueue<'a, S, PrefixOrderDomain, HashObserved>, Report> {
        let config = self.config().await?.oracles.voting.clone();
        Ok(VoteQueue::<S, PrefixOrderDomain, HashObserved>::new(
            self,
            "oracle_voting/",
            config,
        ))
    }

    /// Get the vote queue for admin updates.
    pub async fn admin_voting<'a>(&'a mut self) -> Result<VoteQueue<'a, S, Empty, Config>, Report> {
        let config = self.config().await?.admins.voting.clone();
        Ok(VoteQueue::<S, Empty, Config>::new(
            self,
            "admin_voting/",
            config,
        ))
    }

    /// Get the canonical hash for a given subdomain, if it exists.
    pub async fn canonical_hash(&self, subdomain: Domain) -> Result<Option<[u8; 32]>, Report> {
        let key = PrefixOrderDomain {
            name: subdomain.name.clone(),
        }
        .to_string();

        if let Some(bytes) = self.store.get::<Bytes>(Canonical, &key).await? {
            let hash = <[u8; 32]>::try_from(&bytes[..])
                .map_err(|_| eyre!("canonical hash for {} has invalid length", subdomain))?;
            Ok(Some(hash))
        } else {
            Ok(None)
        }
    }

    /// Get a stream of the canonical hashes for every subdomain under a registered domain,
    /// not including the registered domain itself.
    pub async fn canonical_strict_subdomains_hashes(
        &self,
        registered_domain: Domain,
    ) -> impl Stream<Item = Result<(Domain, [u8; 32]), Report>> + 'static {
        let mut prefix = PrefixOrderDomain {
            name: registered_domain.name.clone(),
        }
        .to_string();

        // Add a trailing dot to only get subdomains, not the registered domain itself, *UNLESS* the
        // registered domain being queried is the root domain, in which case it already ends with a
        // dot, so we shouldn't add one!
        if registered_domain.name != FQDN::default() {
            prefix.push('.'); // e.g. ".com.example."
        }

        self.store.prefix::<Bytes>(Canonical, prefix).map(|result| {
            let (key, bytes) = result?;
            let prefix_ordered = PrefixOrderDomain::from_str(&key)?;
            let domain = Domain {
                name: prefix_ordered.name,
            };
            let hash = <[u8; 32]>::try_from(&bytes[..])
                .map_err(|_| eyre!("canonical hash for {} has invalid length", domain))?;
            Ok((domain, hash))
        })
    }

    /// Get a stream of the canonical hashes for every subdomain including the registered domain
    /// itself.
    pub async fn canonical_subdomains_hashes(
        &self,
        registered_domain: Domain,
    ) -> Result<impl Stream<Item = Result<(Domain, [u8; 32]), Report>> + 'static, Report> {
        let subdomains = self
            .canonical_strict_subdomains_hashes(registered_domain.clone())
            .await;

        let domain = self.canonical_hash(registered_domain.clone()).await?;
        let domain = if let Some(domain) = domain {
            futures::stream::once(async move { Ok((registered_domain, domain)) }).boxed()
        } else {
            futures::stream::empty().boxed()
        };

        Ok(domain.chain(subdomains))
    }

    /// Returns a count of all subdomains including the registered domain itself in the canonical
    /// state.
    pub async fn canonical_subdomains(
        &self,
        registered_domain: Domain,
    ) -> Result<Vec<Domain>, Report> {
        let mut subdomains = self
            .canonical_strict_subdomains(registered_domain.clone())
            .await?;
        if self
            .canonical_hash(registered_domain.clone())
            .await?
            .is_some()
        {
            subdomains.push(registered_domain.clone());
        }
        Ok(subdomains)
    }

    /// Returns a count of all subdomains under a registered domain in the canonical state.
    ///
    /// This does not include the registered domain itself, only its subdomains.
    pub async fn canonical_strict_subdomains(
        &self,
        registered_domain: Domain,
    ) -> Result<Vec<Domain>, Report> {
        let mut prefix = PrefixOrderDomain {
            name: registered_domain.name.clone(),
        }
        .to_string();
        prefix.push('.'); // e.g. ".com.example."

        let mut subdomains = Vec::new();
        let mut stream = Box::pin(StateReadExt::prefix_keys(&self.store, Canonical, &prefix));
        while let Some(Ok(subdomain)) = stream.next().await {
            let prefix_ordered = PrefixOrderDomain::from_str(&subdomain)?;
            let subdomain = Domain {
                name: prefix_ordered.name,
            };
            subdomains.push(subdomain);
        }
        Ok(subdomains)
    }

    /// Update the canonical hash for a given subdomain.
    async fn update_canonical(
        &mut self,
        subdomain: Domain,
        hash_observed: HashObserved,
    ) -> Result<(), Report> {
        // We store subdomains in prefix order, e.g. ".com.example" instead of "example.com", to
        // allow prefix search for subdomains.
        let key = PrefixOrderDomain {
            name: subdomain.name.clone(),
        }
        .to_string(); // notice that we do not add a trailing dot here!

        if let HashObserved::Hash(hash) = hash_observed {
            info!(
                domain = %subdomain.name,
                hash = hex::encode(hash),
                "updating canonical hash"
            );
            self.store.put(Canonical, &key, Vec::from(hash));
        } else {
            info!(domain = key, "deleting canonical hash");
            StateWriteExt::delete(&mut self.store, Canonical, &key);
        }
        Ok(())
    }
}
