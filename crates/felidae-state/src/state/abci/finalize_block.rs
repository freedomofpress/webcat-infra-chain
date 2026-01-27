use std::num::NonZero;

use super::*;
use prost::bytes::Bytes;
use tendermint::abci::{Code, types::ExecTxResult};

impl<S: StateReadExt + StateWriteExt + 'static> State<S> {
    /// Finalize a block by processing all transactions and returning the app hash.
    /// This replaces BeginBlock, DeliverTx (for all txs), and EndBlock in ABCI 2.0.
    pub async fn finalize_block(
        &mut self,
        request::FinalizeBlock {
            txs,
            decided_last_commit: CommitInfo { round: _, votes },
            misbehavior,
            hash: _,
            height,
            time,
            next_validators_hash: _,
            proposer_address: _,
        }: request::FinalizeBlock,
    ) -> Result<response::FinalizeBlock, Report> {
        // ABCI -> ABCI++ migration note: BeginBlock provided the Header, but FinalizeBlock
        // does not, so we can't check the chain ID as we used to do in the ABCI BeginBlock
        // handler.

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

        // TODO: Jail inactive validators?

        // Tombstone byzantine validators
        for Misbehavior {
            validator: bad_validator,
            kind: _,
            height: _,
            time: _,
            total_voting_power: _,
        } in misbehavior
        {
            self.tombstone_validator(bad_validator).await?;
        }

        // Record the current block height and time:
        self.set_block_height(height).await?;
        self.set_block_time(time).await?;

        // Timeout expired votes in the vote queues
        self.admin_voting().await?.timeout_expired_votes().await?;
        self.oracle_voting().await?.timeout_expired_votes().await?;

        // ABCI -> ABCI++ migration note: We just call the old ABCI 1.0 DeliverTx logic,
        // but now for all txs.
        let mut tx_results = Vec::new();
        for tx_bytes in txs {
            // TODO: Check these ExecTxResult fields are correct
            let result = match self.deliver_tx(&tx_bytes).await {
                Ok(()) => ExecTxResult {
                    code: Code::Ok,
                    data: Bytes::new(),
                    log: String::new(),
                    info: String::new(),
                    gas_wanted: 0,
                    gas_used: 0,
                    events: vec![],
                    codespace: String::new(),
                },
                Err(e) => {
                    warn!(%e, "transaction failed in finalize_block");
                    ExecTxResult {
                        code: Code::Err(NonZero::new(1).expect("1 != 0")),
                        data: Bytes::new(),
                        log: e.to_string(),
                        info: String::new(),
                        gas_wanted: 0,
                        gas_used: 0,
                        events: vec![],
                        codespace: String::new(),
                    }
                }
            };
            tx_results.push(result);
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
            self.set_config(new_config.clone()).await?;

            self.sync_validators_from_config(&new_config.validators)
                .await?;
        }

        // Process ripe pending oracle observations into canonical state
        for (subdomain, vote_value) in self
            .oracle_voting()
            .await?
            .promote_pending_changes()
            .await?
        {
            self.update_canonical(subdomain.into(), vote_value.hash_observed)
                .await?;
        }

        // Get validator updates
        let validator_updates = self.active_validators().await?;

        Ok(response::FinalizeBlock {
            tx_results,
            validator_updates,
            consensus_param_updates: None,
            app_hash: Default::default(), // This gets filled in by the caller!
            events: vec![],
        })
    }
}
