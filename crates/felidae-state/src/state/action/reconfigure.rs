use super::*;

impl<S: StateReadExt + StateWriteExt + 'static> State<S> {
    /// Handle a reconfiguration action.
    #[instrument(skip(self, reconfig))]
    pub(crate) async fn reconfigure(&mut self, reconfig: &Reconfigure) -> Result<(), Report> {
        let Reconfigure {
            admin: admin @ Admin { identity },
            config,
            not_before,
            not_after,
        } = reconfig;

        // Check that the admin is a current admin. There is deliberately no
        // empty-set exception: genesis always installs a validated config with
        // a non-empty admin set, so a reconfigure is never permissionless.
        let current_config = self.config().await?;

        if !current_config.admins.authorized.iter().any(|a| a == admin) {
            bail!("not a current admin: {identity}");
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
                party: identity.to_string(),
                time: current_time,
                value: config.clone(),
            })
            .await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use felidae_types::transaction::{
        Admin, AdminConfig, Config, Delay, Identity, OnionConfig, Oracle, OracleConfig, Quorum,
        Reconfigure, Timeout, Total, ValidatorConfig, VotingConfig,
    };
    use tempfile::TempDir;
    use tendermint::{Time, block::Height};

    use crate::Store;

    /// Deterministic P-256 identity derived from a fixed low scalar (256 + n,
    /// so no `n` collides with the generator-point placeholder).
    fn test_identity(n: u8) -> Identity {
        let mut scalar = [0u8; 32];
        scalar[30] = 1;
        scalar[31] = n;
        let signing_key =
            p256::ecdsa::SigningKey::from_slice(&scalar).expect("low scalar is a valid key");
        Identity::from(*signing_key.verifying_key())
    }

    fn voting(total: u64, quorum: u64) -> VotingConfig {
        VotingConfig {
            total: Total(total),
            quorum: Quorum(quorum),
            timeout: Timeout(Duration::from_secs(3600)),
            delay: Delay(Duration::from_secs(0)),
        }
    }

    fn config(version: u32, admins: Vec<Admin>) -> Config {
        Config {
            version,
            admins: AdminConfig {
                voting: voting(admins.len() as u64, admins.len().max(1) as u64),
                authorized: admins,
            },
            oracles: OracleConfig {
                enabled: false,
                authorized: vec![Oracle {
                    identity: test_identity(20),
                    endpoint: url::Url::parse("http://127.0.0.1:8081").unwrap(),
                }],
                voting: voting(1, 1),
                max_enrolled_subdomains: 5,
                observation_timeout: Duration::from_secs(300),
            },
            onion: OnionConfig { enabled: false },
            validators: vec![],
            validator_config: ValidatorConfig::default(),
        }
    }

    /// State seeded via the unvalidated crate-internal `set_config`, with a
    /// block height and time so the reconfigure time-bounds checks pass.
    async fn setup_state(current: Config) -> (Store, TempDir) {
        let temp_dir = TempDir::new().expect("failed to create temp dir");
        let store = Store::init(temp_dir.path().to_path_buf())
            .await
            .expect("failed to create store");
        {
            let mut state = store.state.write().await;
            state.set_config(current).await.expect("set_config");
            state
                .set_block_height(Height::from(1u32))
                .await
                .expect("set_block_height");
            state
                .set_block_time(Time::from_unix_timestamp(1_700_000_000, 0).unwrap())
                .await
                .expect("set_block_time");
        }
        (store, temp_dir)
    }

    fn reconfigure_by(identity: Identity, new_config: Config) -> Reconfigure {
        Reconfigure {
            config: new_config,
            not_before: Time::from_unix_timestamp(0, 0).unwrap(),
            not_after: Time::from_unix_timestamp(2_000_000_000, 0).unwrap(),
            admin: Admin { identity },
        }
    }

    #[tokio::test]
    async fn reconfigure_requires_admin_membership_even_with_no_admins() {
        // The locked-open bootstrap is gone: an empty admin set (only
        // reachable here via the unvalidated test-only set_config) must NOT
        // grant a permissionless reconfigure. This pins the removal of the
        // old empty-set carve-out.
        let (store, _dir) = setup_state(config(0, vec![])).await;
        let mut state = store.state.write().await;

        let attempt = reconfigure_by(
            test_identity(9),
            config(
                1,
                vec![Admin {
                    identity: test_identity(9),
                }],
            ),
        );
        let err = state.reconfigure(&attempt).await.unwrap_err();
        assert!(
            err.to_string().contains("not a current admin"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn reconfigure_accepts_current_admin() {
        // Positive control: a member of the current admin set passes the
        // membership gate and the proposal is accepted into the vote queue.
        let admin = Admin {
            identity: test_identity(1),
        };
        let (store, _dir) = setup_state(config(1, vec![admin.clone()])).await;
        let mut state = store.state.write().await;

        let attempt = reconfigure_by(test_identity(1), config(2, vec![admin]));
        state
            .reconfigure(&attempt)
            .await
            .expect("current admin may reconfigure");
    }
}
