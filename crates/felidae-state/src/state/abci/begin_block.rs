use super::*;

impl<S: StateReadExt + StateWriteExt + 'static> State<S> {
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
}
