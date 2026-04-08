use std::collections::BTreeMap;

use super::*;

/// The status of a validator.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ValidatorStatus {
    /// Validator is active and participating in consensus.
    Active,
    /// Validator was removed from the `Config` by admins.
    Inactive,
    /// Validator was temporarily removed for excessive downtime.
    Jailed,
    /// Validator was permanently banned for equivocation (double-signing).
    Tombstoned,
}

impl From<ValidatorStatus> for u32 {
    fn from(status: ValidatorStatus) -> Self {
        match status {
            ValidatorStatus::Active => 0,
            ValidatorStatus::Inactive => 1,
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
            1 => Ok(ValidatorStatus::Inactive),
            2 => Ok(ValidatorStatus::Jailed),
            3 => Ok(ValidatorStatus::Tombstoned),
            _ => bail!("unknown validator status: {}", value),
        }
    }
}

impl felidae_proto::DomainType for ValidatorStatus {
    type Proto = u32;
}

/// Count of consecutive blocks a validator has been absent from consensus.
///
/// Stored at `current/validator_absence/{pub_key_hex}`. Reset to zero when the validator
/// votes or is jailed.
#[derive(Clone, Debug, Default)]
struct AbsenceCount(u64);

impl From<AbsenceCount> for u64 {
    fn from(c: AbsenceCount) -> Self {
        c.0
    }
}

impl TryFrom<u64> for AbsenceCount {
    type Error = Report;
    fn try_from(v: u64) -> Result<Self, Self::Error> {
        Ok(AbsenceCount(v))
    }
}

impl felidae_proto::DomainType for AbsenceCount {
    type Proto = u64;
}

/// Number of consecutive absent blocks before a validator is jailed.
///
/// TODO: Make this configurable via `Config`.
const CONSECUTIVE_ABSENCE_JAIL_THRESHOLD: u64 = 1_000;

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
    ///
    /// This handles state transitions from:
    /// - Active       --> Tombstoned
    /// - Inactive --> Tombstoned
    /// - Jailed       --> Tombstoned
    pub(crate) async fn tombstone_validator(
        &mut self,
        Validator {
            address: bad_address,
            ..
        }: Validator,
    ) -> Result<(), Report> {
        // Go through the list of active validators, taking the address (first 20 bytes of the
        // SHA-256 hash of the public key) as and checking if it matches the given address:
        let mut bad_pub_key = None;
        // We search all validators (not just active ones) since misbehavior evidence can arrive
        // for validators that are Jailed or Inactive.
        for pub_key in &self.all_validators().await? {
            let mut context = Sha256::new();
            context.update(pub_key.to_bytes());
            let pub_key_hash: [u8; 32] = context.finalize().into();
            let validator_address = &pub_key_hash[0..20];

            // If the address matches, we've found the bad validator:
            if validator_address == bad_address {
                bad_pub_key = Some(*pub_key);
                break;
            }
        }

        let Some(bad_pub_key) = bad_pub_key else {
            warn!(
                address = hex::encode(bad_address),
                "could not find validator to tombstone; it may have already been tombstoned",
            );
            return Ok(());
        };

        let pub_key_hex = hex::encode(bad_pub_key.to_bytes());

        if self.validator_status(&bad_pub_key).await? == Some(ValidatorStatus::Tombstoned) {
            warn!(pub_key = pub_key_hex, "validator is already tombstoned");
            return Ok(());
        }

        info!(pub_key = pub_key_hex, "tombstoning validator");
        self.store.put(
            Internal,
            &format!("current/validators/{}", pub_key_hex),
            Power::from(0u32),
        );
        self.set_validator_status(&bad_pub_key, ValidatorStatus::Tombstoned);

        Ok(())
    }

    /// Get all validators in state, regardless of power or status.
    pub(crate) async fn all_validators(&self) -> Result<Vec<tendermint::PublicKey>, Report> {
        let mut pub_keys = vec![];
        let mut stream = Box::pin(self.store.prefix::<Power>(Internal, "current/validators/"));
        while let Some(Ok((key, _power))) = stream.next().await {
            let pub_key_bytes = hex::decode(key.trim_start_matches("current/validators/"))?;
            pub_keys.push(
                tendermint::PublicKey::from_raw_ed25519(&pub_key_bytes)
                    .ok_or_eyre("invalid ed25519 public key")?,
            );
        }
        Ok(pub_keys)
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

    /// Sync validators from config to state.
    ///
    /// This handles state transitions from:
    /// - Active       --> Inactive  (validator absent from new Config)
    /// - Inactive     --> Active        (validator re-added to Config)
    /// - Jailed       --> Inactive  (validator absent from new Config while jailed)
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

        // Collect all state validators with their power and status, including those with power 0
        // (e.g. tombstoned or jailed validators) — we need their status to decide what to do.
        let mut state_validators: BTreeMap<
            Vec<u8>,
            (tendermint::PublicKey, Power, ValidatorStatus),
        > = BTreeMap::new();
        {
            let mut stream = Box::pin(self.store.prefix::<Power>(Internal, "current/validators/"));
            while let Some(Ok((key, power))) = stream.next().await {
                let pub_key_bytes = hex::decode(key.trim_start_matches("current/validators/"))?;
                let pub_key = tendermint::PublicKey::from_raw_ed25519(&pub_key_bytes)
                    .ok_or_eyre("invalid ed25519 public key")?;
                state_validators.insert(pub_key_bytes, (pub_key, power, ValidatorStatus::Active));
            }
        }

        // Look up status for each validator now that the stream is dropped.
        for (_, (pub_key, _, status)) in state_validators.iter_mut() {
            *status = match self.validator_status(pub_key).await? {
                Some(s) => s,
                None => {
                    // Validator predates status tracking — backfill as Active.
                    // Validators with power > 0 are correctly Active. Validators with power = 0
                    // (removed by the old sync code before status tracking was added) will be
                    // corrected to Inactive by the "absent from Config" loop below.
                    self.set_validator_status(pub_key, ValidatorStatus::Active);
                    ValidatorStatus::Active
                }
            };
        }

        // Determine the uniform validator power from the current active set.
        // All validators must have equal power; if none are active yet, fall back to 1.
        let uniform_power = state_validators
            .values()
            .find_map(|(_, power, status)| {
                if power.value() > 0 && *status == ValidatorStatus::Active {
                    Some(*power)
                } else {
                    None
                }
            })
            .unwrap_or_else(|| Power::from(1u32));

        // Build a map of config validators by public key bytes.
        let mut config_validators_map = BTreeMap::new();
        for validator in config_validators {
            let pub_key_bytes: Vec<u8> = validator.public_key.to_vec();
            let pub_key = tendermint::PublicKey::from_raw_ed25519(&pub_key_bytes)
                .ok_or_eyre("invalid ed25519 public key in config")?;
            config_validators_map.insert(pub_key_bytes, (pub_key, uniform_power));
        }

        let mut updates: Vec<Update> = Vec::new();

        // Handle validators present in Config:
        for (pub_key_bytes, (pub_key, config_power)) in config_validators_map.iter() {
            let pub_key_hex = hex::encode(pub_key.to_bytes());
            match state_validators.get(pub_key_bytes).map(|(_, _, s)| s) {
                None => {
                    // Brand new validator — add it as active.
                    info!(
                        pub_key = pub_key_hex,
                        power = config_power.value(),
                        "adding new validator"
                    );
                    self.declare_validator(Update {
                        pub_key: *pub_key,
                        power: *config_power,
                    })
                    .await?;
                    updates.push(Update {
                        pub_key: *pub_key,
                        power: *config_power,
                    });
                }
                Some(ValidatorStatus::Active) => {
                    // Already active so no change.
                    debug!(pub_key = pub_key_hex, "validator already active, skipping");
                }
                Some(ValidatorStatus::Inactive) => {
                    // Re-activated by admins - transition from Inactive back to Active.
                    info!(
                        pub_key = pub_key_hex,
                        power = config_power.value(),
                        "re-activating validator"
                    );
                    self.store.put(
                        Internal,
                        &format!("current/validators/{}", pub_key_hex),
                        *config_power,
                    );
                    self.set_validator_status(pub_key, ValidatorStatus::Active);
                    updates.push(Update {
                        pub_key: *pub_key,
                        power: *config_power,
                    });
                }
                Some(ValidatorStatus::Jailed) => {
                    // Jailed validators remain jailed
                    // TODO: implement unjailing
                    debug!(pub_key = pub_key_hex, "validator is jailed, skipping");
                }
                Some(ValidatorStatus::Tombstoned) => {
                    // Tombstoned validators can never be re-added.
                    warn!(
                        pub_key = pub_key_hex,
                        "ignoring tombstoned validator in config"
                    );
                }
            }
        }

        // Handle validators absent from Config:
        for (pub_key_bytes, (pub_key, _, status)) in state_validators.iter() {
            if config_validators_map.contains_key(pub_key_bytes) {
                continue;
            }
            let pub_key_hex = hex::encode(pub_key.to_bytes());
            match status {
                ValidatorStatus::Active => {
                    // Removed by admins - transition from Active to Inactive.
                    info!(pub_key = pub_key_hex, "removing validator");
                    self.store.put(
                        Internal,
                        &format!("current/validators/{}", pub_key_hex),
                        Power::from(0u32),
                    );
                    self.set_validator_status(pub_key, ValidatorStatus::Inactive);
                    updates.push(Update {
                        pub_key: *pub_key,
                        power: Power::from(0u32),
                    });
                }
                ValidatorStatus::Jailed => {
                    // Removed from Config while jailed - transition from Jailed to Inactive.
                    // Power is already 0 so no CometBFT update needed.
                    info!(pub_key = pub_key_hex, "removing jailed validator");
                    self.set_validator_status(pub_key, ValidatorStatus::Inactive);
                }
                ValidatorStatus::Inactive | ValidatorStatus::Tombstoned => {
                    // Already inactive so no change.
                }
            }
        }

        Ok(updates)
    }

    /// Record validator uptime for the current block, incrementing or resetting each active
    /// validator's consecutive absence count.
    pub(crate) async fn mark_validators_voted(
        &mut self,
        voted_addresses: BTreeSet<[u8; 20]>,
    ) -> Result<(), Report> {
        let active_validators = self.active_validators().await?;
        for Update { pub_key, .. } in active_validators {
            // Compute the address of this validator (first 20 bytes of SHA-256 of pub key):
            let mut context = Sha256::new();
            context.update(pub_key.to_bytes());
            let pub_key_hash: [u8; 32] = context.finalize().into();
            let validator_address: [u8; 20] =
                pub_key_hash[0..20].try_into().expect("slice is 20 bytes");

            let pub_key_hex = hex::encode(pub_key.to_bytes());
            let absence_key = format!("current/validator_absence/{}", pub_key_hex);

            if voted_addresses.contains(&validator_address) {
                debug!(
                    pub_key = pub_key_hex,
                    "validator voted, resetting absence count"
                );
                self.store.put(Internal, &absence_key, AbsenceCount(0));
            } else {
                let current: AbsenceCount = self
                    .store
                    .get(Internal, &absence_key)
                    .await?
                    .unwrap_or_default();
                let new_count = AbsenceCount(current.0 + 1);
                debug!(
                    pub_key = pub_key_hex,
                    absences = new_count.0,
                    "validator absent"
                );
                self.store.put(Internal, &absence_key, new_count);
            }
        }
        Ok(())
    }

    /// Jail any active validator that has exceeded the consecutive absence threshold.
    ///
    /// Implements transition Active --> Jailed.
    pub(crate) async fn jail_inactive_validators(&mut self) -> Result<(), Report> {
        let active_validators = self.active_validators().await?;
        for Update { pub_key, .. } in active_validators {
            let pub_key_hex = hex::encode(pub_key.to_bytes());
            let absence_key = format!("current/validator_absence/{}", pub_key_hex);
            let absences: AbsenceCount = self
                .store
                .get(Internal, &absence_key)
                .await?
                .unwrap_or_default();

            if absences.0 >= CONSECUTIVE_ABSENCE_JAIL_THRESHOLD {
                info!(
                    pub_key = pub_key_hex,
                    absences = absences.0,
                    "jailing validator for inactivity"
                );
                self.store.put(
                    Internal,
                    &format!("current/validators/{}", pub_key_hex),
                    Power::from(0u32),
                );
                self.set_validator_status(&pub_key, ValidatorStatus::Jailed);
                // Reset the absence count so that if the validator is later re-activated
                // (transition Jailed --> Active), the count starts fresh.
                self.store.put(Internal, &absence_key, AbsenceCount(0));
            }
        }
        Ok(())
    }
}
