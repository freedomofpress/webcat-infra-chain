use std::collections::BTreeMap;

use super::*;

/// The status of a validator.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ValidatorStatus {
    /// Validator is active and participating in consensus.
    Active,
    /// Validator was removed from the `Config` by admins.
    AdminRemoved,
    /// Validator was temporarily removed for excessive downtime.
    Jailed,
    /// Validator was permanently banned for equivocation (double-signing).
    Tombstoned,
}

impl From<ValidatorStatus> for u32 {
    fn from(status: ValidatorStatus) -> Self {
        match status {
            ValidatorStatus::Active => 0,
            ValidatorStatus::AdminRemoved => 1,
            ValidatorStatus::Jailed => 2,
            ValidatorStatus::Tombstoned => 3,
        }
    }
}

impl TryFrom<u32> for ValidatorStatus {
    type Error = Report;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(ValidatorStatus::Active),
            1 => Ok(ValidatorStatus::AdminRemoved),
            2 => Ok(ValidatorStatus::Jailed),
            3 => Ok(ValidatorStatus::Tombstoned),
            _ => bail!("unknown validator status: {}", value),
        }
    }
}

impl felidae_proto::DomainType for ValidatorStatus {
    type Proto = u32;
}

impl<S: StateReadExt + StateWriteExt + 'static> State<S> {
    /// Declare a new validator by its address.
    pub(crate) async fn declare_validator(&mut self, validator: Update) -> Result<(), Report> {
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
                "validator {} already exists with power {}",
                hex::encode(validator.pub_key.to_bytes()),
                existing,
            );
        }

        let pub_key_hex = hex::encode(validator.pub_key.to_bytes());
        self.store.put(
            Internal,
            &format!("current/validators/{}", pub_key_hex),
            validator.power,
        );
        self.store.put(
            Internal,
            &format!("current/validator_status/{}", pub_key_hex),
            ValidatorStatus::Active,
        );

        Ok(())
    }

    /// Get the status of a validator by its public key bytes.
    pub(crate) async fn validator_status(
        &self,
        pub_key: &tendermint::PublicKey,
    ) -> Result<Option<ValidatorStatus>, Report> {
        self.store
            .get(
                Internal,
                &format!(
                    "current/validator_status/{}",
                    hex::encode(pub_key.to_bytes())
                ),
            )
            .await
    }

    /// Set the status of a validator by its public key bytes.
    pub(crate) fn set_validator_status(
        &mut self,
        pub_key: &tendermint::PublicKey,
        status: ValidatorStatus,
    ) {
        self.store.put(
            Internal,
            &format!(
                "current/validator_status/{}",
                hex::encode(pub_key.to_bytes())
            ),
            status,
        );
    }

    /// Tombstone a validator by its address.
    pub(crate) async fn tombstone_validator(
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
    pub async fn active_validators(&self) -> Result<Vec<Update>, Report> {
        let mut updates = vec![];
        let mut stream = Box::pin(self.store.prefix::<Power>(Internal, "current/validators/"));
        while let Some(Ok((key, power))) = stream.next().await {
            let pub_key = hex::decode(key.trim_start_matches("current/validators/"))?;
            // FYI the CometBFT convention is to set power to 0 to remove a validator.
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

    /// Sync validators from config to state. This compares the validators in the config with those
    /// in state and updates state accordingly:
    /// - Validators in config but not in state: added with their power using `declare_validator`
    /// - Validators in both: left unchanged (power cannot be updated via config... need to carefully handle tombstoned validators)
    /// - Validators in state but not in config: power set to 0 (i.e. they are removed)
    pub(crate) async fn sync_validators_from_config(
        &mut self,
        config_validators: &[felidae_types::transaction::Validator],
    ) -> Result<Vec<Update>, Report> {
        // An empty validators field means "not managed by config" — leave the
        // validator set untouched.  Without this guard the removal loop below
        // would interpret every state validator as absent from the config and
        // set them all to power 0, halting consensus.
        if config_validators.is_empty() {
            return Ok(vec![]);
        }

        // We grab all the current validators from the state (including those with power 0
        // which we need to be careful not to reset their power because they might be tombstoned)
        let mut state_validators = BTreeMap::new();
        let mut stream = Box::pin(self.store.prefix::<Power>(Internal, "current/validators/"));
        while let Some(Ok((key, power))) = stream.next().await {
            let pub_key_bytes = hex::decode(key.trim_start_matches("current/validators/"))?;
            let pub_key = tendermint::PublicKey::from_raw_ed25519(&pub_key_bytes)
                .ok_or_eyre("invalid ed25519 public key")?;
            state_validators.insert(pub_key_bytes, (pub_key, power));
        }

        // Create a map of config validators by public key bytes
        let mut config_validators_map = BTreeMap::new();
        for validator in config_validators {
            let pub_key_bytes: Vec<u8> = validator.public_key.to_vec();
            let pub_key = tendermint::PublicKey::from_raw_ed25519(&pub_key_bytes)
                .ok_or_eyre("invalid ed25519 public key in config")?;

            // Power validation is done in `check_config` and bails if larger than u32::MAX
            // so we can safely convert here from a u32.
            let power = Power::from(validator.power as u32);
            config_validators_map.insert(pub_key_bytes, (pub_key, power));
        }

        // Collect validator updates to return to CometBFT via FinalizeBlock.
        let mut updates = Vec::new();

        // Add new validators from config (only if they don't exist in state)
        for (pub_key_bytes, (pub_key, config_power)) in config_validators_map.iter() {
            if state_validators.contains_key(pub_key_bytes) {
                // Validator already exists - skip (currently power cannot be updated via config)
                debug!(
                    pub_key = hex::encode(pub_key.to_bytes()),
                    "validator already exists, skipping"
                );
            } else {
                info!(
                    pub_key = hex::encode(pub_key.to_bytes()),
                    power = config_power.value(),
                    "adding new validator"
                );
                let update = Update {
                    pub_key: *pub_key,
                    power: *config_power,
                };
                self.declare_validator(update.clone()).await?;
                updates.push(update);
            }
        }

        // Remove validators that are in state but NOT in the config by setting their power to 0.
        // The power=0 update must be returned so CometBFT sees the removal.
        for (pub_key_bytes, (pub_key, state_power)) in state_validators.iter() {
            if !config_validators_map.contains_key(pub_key_bytes) && state_power.value() > 0 {
                info!(
                    pub_key = hex::encode(pub_key.to_bytes()),
                    "removing validator (setting power to 0)"
                );
                let zero_power = Power::from(0u32);
                self.store.put(
                    Internal,
                    &format!("current/validators/{}", hex::encode(pub_key.to_bytes())),
                    zero_power,
                );
                updates.push(Update {
                    pub_key: *pub_key,
                    power: zero_power,
                });
            }
        }

        Ok(updates)
    }

    /// Record validator uptime for the current block.
    pub(crate) async fn mark_validators_voted(
        &mut self,
        addresses: BTreeSet<[u8; 20]>,
    ) -> Result<(), Report> {
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
}
