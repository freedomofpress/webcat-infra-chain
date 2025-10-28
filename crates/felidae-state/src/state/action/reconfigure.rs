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
}
