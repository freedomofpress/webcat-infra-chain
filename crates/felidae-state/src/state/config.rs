use super::*;

impl<S: StateReadExt + StateWriteExt + 'static> State<S> {
    /// Get the current config from the state.
    pub async fn config(&self) -> Result<Config, Report> {
        self.store
            .get::<Config>(Internal, "parameters/config")
            .await?
            .ok_or_eyre("config not found in state; is the state initialized?")
    }

    /// Set the current config in the state.
    pub(crate) async fn set_config(&mut self, config: Config) -> Result<(), Report> {
        self.store.put(Internal, "parameters/config", config);
        Ok(())
    }

    /// Check a config for internal consistency and validity, as well as validity against the
    /// current config.
    pub async fn check_config(&self, config: &Config) -> Result<(), Report> {
        // Ensure the version is greater than the current version:
        let current_config = self.config().await?;
        if config.version <= current_config.version {
            bail!(
                "new config version {} must be greater than current version {}",
                config.version,
                current_config.version
            );
        }

        // Stateless checks (no reference to chain state); these live on the
        // Config type itself in felidae-types, and are also run at genesis by
        // InitChain:
        config.check_stateless()?;

        // Ensure that max_enrolled_subdomains does not decrease:
        if config.oracles.max_enrolled_subdomains < current_config.oracles.max_enrolled_subdomains {
            bail!("max_enrolled_subdomains cannot decrease");
        }

        // Reject any validator key that is currently tombstoned. Tombstoning is
        // permanent, so listing such a key in a reconfigure is always a
        // mistake. Rejecting here (rather than silently dropping it at
        // promotion) surfaces the error to the submitting admin via CheckTx.
        for (i, validator) in config.validators.iter().enumerate() {
            if self.validator_status(&validator.public_key).await?
                == Some(super::validator::ValidatorStatus::Tombstoned)
            {
                bail!(
                    "validator at index {} ({}) is tombstoned and can never be re-added",
                    i,
                    hex::encode(validator.public_key.to_bytes()),
                );
            }
        }

        Ok(())
    }
}
