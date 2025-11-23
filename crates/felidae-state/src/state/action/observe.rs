use super::*;

impl<S: StateReadExt + StateWriteExt + 'static> State<S> {
    /// Handle an observation action.
    #[instrument(skip(self, observe), fields(domain = %observe.observation.domain, zone = %observe.observation.zone))]
    pub(crate) async fn observe(&mut self, observe: &Observe) -> Result<(), Report> {
        let Observe {
            oracle: oracle @ OracleIdentity { identity },
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
            .any(|o| o.identity == oracle.identity)
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
}
