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
    pub async fn check_config(
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

        // Validate that no admin has an all-zero identity (placeholder entry):
        for (i, admin) in admins.iter().enumerate() {
            if Self::is_all_zeros(&admin.identity) {
                bail!(
                    "admin at index {} has an all-zero identity (placeholder not replaced)",
                    i
                );
            }
        }

        // Validate that no oracle has an all-zero identity (placeholder entry):
        for (i, oracle) in oracles.iter().enumerate() {
            if Self::is_all_zeros(&oracle.identity) {
                bail!(
                    "oracle at index {} has an all-zero identity (placeholder not replaced)",
                    i
                );
            }
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

    /// Check if a byte slice is all zeros (used to detect placeholder keys).
    fn is_all_zeros(bytes: &[u8]) -> bool {
        bytes.iter().all(|&b| b == 0)
    }
}
