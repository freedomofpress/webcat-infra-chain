#[macro_use]
extern crate tracing;

#[macro_use]
extern crate color_eyre;

use std::time::Duration;

use aws_lc_rs::digest;
use cnidarium::{RootHash, Storage};
use color_eyre::{
    Report,
    eyre::{OptionExt, bail},
};
use felidae_types::transaction::{
    Action, Admin, AdminConfig, AuthenticatedTx, ChainId, Config, Delay, Observe, OnionConfig,
    Oracle, OracleConfig, Quorum, Reconfigure, Timeout, Total, Transaction, VotingConfig,
};
use tendermint::{
    AppHash, Time,
    abci::{
        request, response,
        types::{BlockSignatureInfo, CommitInfo, Misbehavior, Validator, VoteInfo},
    },
    block::{BlockIdFlag, Header, Height},
    vote::Power,
};

mod store;
use store::Store;

pub struct State {
    internal: Store,
    canonical: Store,
}

pub struct RootHashes {
    pub internal: RootHash,
    pub canonical: RootHash,
    pub app_hash: RootHash,
}

impl State {
    /// Create a new state.
    pub fn new(internal: Storage, canonical: Storage) -> Self {
        Self {
            internal: Store::new(internal),
            canonical: Store::new(canonical),
        }
    }

    /// Get the 3 root hashes: internal, canonical, and app hash (hash of internal and canonical).
    pub async fn root_hashes(&self) -> Result<RootHashes, Report> {
        let internal = self.internal.root_hash().await?;
        let canonical = self.canonical.root_hash().await?;
        Ok(RootHashes {
            internal,
            canonical,
            app_hash: {
                let mut context = digest::Context::new(&digest::SHA256);
                context.update(internal.as_ref());
                context.update(canonical.as_ref());
                RootHash(
                    context
                        .finish()
                        .as_ref()
                        .try_into()
                        .expect("SHA256 output is 32 bytes"),
                )
            },
        })
    }

    /// Commit all pending changes to the underlying storage.
    pub async fn commit(&mut self) -> Result<(), Report> {
        self.internal.commit().await?;
        self.canonical.commit().await?;
        Ok(())
    }

    /// Discard all pending changes.
    pub fn abort(&mut self) {
        self.internal.abort();
        self.canonical.abort();
    }

    /// Initialize the chain state.
    pub async fn init_chain(
        &mut self,
        request::InitChain {
            time: _,
            chain_id,
            consensus_params,
            validators,
            app_state_bytes,
            initial_height,
        }: request::InitChain,
    ) -> Result<response::InitChain, Report> {
        // Ensure that the initial height is 1:
        if initial_height.value() != 1 {
            bail!("initial height must be 1");
        }

        // Set the chain ID in the state:
        self.set_chain_id(ChainId(chain_id)).await?;

        // TODO: Set the genesis time in the state

        // Ensure that the app state is empty:
        if !app_state_bytes.is_empty() {
            bail!("app state must be empty");
        }

        // Set the initial config in the state:
        self.set_config(Config {
            version: 0,
            admin_config: AdminConfig {
                admins: vec![], // Default admin set: the first reconfig will set this
                voting_config: VotingConfig {
                    total: Total(0),   // No admins required to initially reconfigure
                    quorum: Quorum(0), // No quorum required to initially reconfigure
                    timeout: Timeout(Duration::from_secs(0)), // No follow-up voting for initial reconfig
                    delay: Delay(Duration::from_secs(0)),     // No delay for initial reconfig
                },
            },
            oracle_config: OracleConfig {
                enabled: false,  // Oracles disabled initially
                oracles: vec![], // No oracles initially
                voting_config: VotingConfig {
                    total: Total(0),                             // No oracles initially
                    quorum: Quorum(0),                           // No voting initially
                    timeout: Timeout(Duration::from_secs(0)),    // No voting initially
                    delay: Delay(Duration::from_secs(u64::MAX)), // No voting initially
                },
                max_enrolled_subdomains: 0, // No subdomains initially
            },
            onion_config: OnionConfig { enabled: false },
        })
        .await?;

        Ok(response::InitChain {
            consensus_params: Some(consensus_params),
            validators,
            app_hash: AppHash::try_from(self.root_hashes().await?.app_hash.0.to_vec())
                .expect("AppHash is 32 bytes"),
        })
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
                    version: _,
                    last_block_id: _,
                    last_commit_hash: _,
                    data_hash: _,
                    validators_hash: _,
                    next_validators_hash: _,
                    consensus_hash: _,
                    app_hash: _,
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
                // TODO: record that this validator voted in the last block
            }
        }

        // TODO: Tombstone inactive validators?

        // Tombstone byzantine validators
        for Misbehavior {
            validator,
            kind: _,
            height: _,
            time: _,
            total_voting_power: _,
        } in byzantine_validators
        {
            self.tombstone_validator(validator).await?;
        }

        // Record the current block height and time:
        self.set_block_height(height).await?;
        self.set_block_time(time).await?;

        // TODO: Process pending config changes
        // TODO: Process pending oracle observations

        Ok(response::BeginBlock { events: vec![] })
    }

    /// Execute a transaction against the current state, without committing the results yet.
    pub async fn deliver_authenticated_tx(&self, tx: &AuthenticatedTx) -> Result<(), Report> {
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

        // TODO: Pull the validator set from state, always
        let validator_updates = vec![];

        Ok(response::EndBlock {
            validator_updates,
            events: vec![],
            consensus_param_updates: None,
        })
    }

    /// Handle a reconfiguration action.
    pub async fn reconfigure(&self, reconfig: &Reconfigure) -> Result<(), Report> {
        let Reconfigure {
            admin: Admin { identity },
            config,
            not_before,
            not_after,
        } = reconfig;

        // Ensure the current time is within the not_before and not_after bounds:
        let current_time = self.block_time().await?;
        if current_time < *not_before {
            bail!("current time is before the not_before bound");
        }
        if current_time > *not_after {
            bail!("current time is after the not_after bound");
        }

        // Check the config for current validity:
        self.check_config(config).await?;

        // TODO: enqueue the config in the vote queue for config changes

        Ok(())
    }

    /// Handle an observation action.
    pub async fn observe(&self, observe: &Observe) -> Result<(), Report> {
        let Observe {
            oracle: Oracle { identity },
            observation,
        } = observe;

        // TODO: enqueue the observation in the vote queue for observations

        Ok(())
    }

    /// Get the current chain ID from the state.
    pub async fn chain_id(&self) -> Result<ChainId, Report> {
        self.internal
            .get::<ChainId>("parameters/chain_id")
            .await?
            .ok_or_eyre("chain ID not found in state; is the state initialized?")
    }

    /// Set the current chain ID in the state.
    ///
    /// This should only be called once, during initial setup.
    pub async fn set_chain_id(&mut self, chain_id: ChainId) -> Result<(), Report> {
        let existing = self.chain_id().await.ok();
        if existing.is_some() {
            bail!("chain ID is already set; cannot set it again");
        }

        self.internal.put("parameters/chain_id", chain_id).await;
        Ok(())
    }

    /// Get the current config from the state.
    pub async fn config(&self) -> Result<Config, Report> {
        self.internal
            .get::<Config>("parameters/config")
            .await?
            .ok_or_eyre("config not found in state; is the state initialized?")
    }

    /// Set the current config in the state.
    pub async fn set_config(&mut self, config: Config) -> Result<(), Report> {
        self.internal.put("parameters/config", config).await;
        Ok(())
    }

    /// Get the current block height from the state.
    pub async fn block_height(&self) -> Result<Height, Report> {
        self.internal
            .get::<Height>("current/block_height")
            .await?
            .ok_or_eyre("block height not found in state; is the state initialized?")
    }

    /// Set the current block height in the state.
    async fn set_block_height(&mut self, height: Height) -> Result<(), Report> {
        self.internal.put("current/block_height", height).await;
        Ok(())
    }

    /// Get the current block time from the state.
    pub async fn block_time(&self) -> Result<Time, Report> {
        self.internal
            .get::<Time>("current/block_time")
            .await?
            .ok_or_eyre("block time not found in state; is the state initialized?")
    }

    /// Set the current block time in the state.
    async fn set_block_time(&mut self, time: Time) -> Result<(), Report> {
        self.internal.put("current/block_time", time).await;
        Ok(())
    }

    /// Declare a new validator by its address.
    pub async fn declare_validator(&mut self, validator: Validator) -> Result<(), Report> {
        // Check to ensure the validator does not exist already (prevents redeclaring tombstoned
        // validators to set their power back to non-zero):
        let existing: Option<Power> = self
            .internal
            .get(&format!(
                "current/validators/{}",
                hex::encode(validator.address)
            ))
            .await?;
        if let Some(existing) = existing {
            bail!(
                "Validator {} already exists with power {}",
                hex::encode(validator.address),
                existing,
            );
        }

        self.internal
            .put(
                &format!("current/validators/{}", hex::encode(validator.address)),
                validator.power,
            )
            .await;

        Ok(())
    }

    /// Tombstone a validator by its address.
    pub async fn tombstone_validator(
        &mut self,
        Validator { address, .. }: Validator,
    ) -> Result<(), Report> {
        // Check to make sure the validator exists:
        let existing: Option<Power> = self
            .internal
            .get(&format!("current/validators/{}", hex::encode(address)))
            .await?;
        if existing.is_none() {
            bail!("Validator {} does not exist", hex::encode(address));
        }

        self.internal
            .put(
                &format!("current/validators/{}", hex::encode(address)),
                Power::from(0u32),
            )
            .await;

        Ok(())
    }

    /// Check a config for internal consistency and validity, as well as validity against the
    /// current config.
    pub async fn check_config(
        &self,
        Config {
            version,
            admin_config:
                AdminConfig {
                    admins,
                    voting_config: admin_voting_config,
                },
            oracle_config:
                OracleConfig {
                    enabled: _, // Can be enabled or not
                    oracles,
                    voting_config: oracle_voting_config,
                    max_enrolled_subdomains,
                },
            onion_config:
                OnionConfig {
                    enabled: _, // Can be enabled or not
                },
        }: &Config,
    ) -> Result<(), Report> {
        // Ensure the version is greater than the current version:
        let current_config = self.config().await?;
        if *version <= current_config.version {
            bail!("new config version must be greater than current version");
        }

        // Check that the voting configs are valid:
        self.check_voting_config(Total(admins.len() as u64), admin_voting_config)?;
        self.check_voting_config(Total(oracles.len() as u64), oracle_voting_config)?;

        // Ensure that max_enrolled_subdomains is non-zero:
        if *max_enrolled_subdomains == 0 {
            bail!("max_enrolled_subdomains must be non-zero");
        }

        // Ensure that max_enrolled_subdomains does not decrease:
        if *max_enrolled_subdomains < current_config.oracle_config.max_enrolled_subdomains {
            bail!("max_enrolled_subdomains cannot decrease");
        }

        Ok(())
    }

    pub fn check_voting_config(
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
}
