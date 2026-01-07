use super::*;

impl<S: StateReadExt + StateWriteExt + 'static> State<S> {
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
        for (subdomain, vote_value) in self
            .oracle_voting()
            .await?
            .promote_pending_changes()
            .await?
        {
            // Extract hash_observed from the OracleVoteValue
            self.update_canonical(subdomain.into(), vote_value.hash_observed)
                .await?;
        }

        Ok(response::EndBlock {
            validator_updates: self.active_validators().await?,
            events: vec![],
            consensus_param_updates: None,
        })
    }
}
