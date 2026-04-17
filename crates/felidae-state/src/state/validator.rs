use std::collections::BTreeMap;

use bitvec::prelude::*;

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

/// Sliding-window uptime tracker for a validator.
///
/// Stored at `current/validator_uptime/{pub_key_hex}`. Uses a bitvec ring buffer where
/// `1` = signed and `0` = missed. Initialized with all `1`s as a grace period.
///
/// Note that this `Uptime` struct was taken from:
/// https://github.com/penumbra-zone/penumbra/blob/36a31c17974c23a7e84cc02c64f0062ae57e79b1/crates/core/component/stake/src/uptime.rs#L20-L29
///
/// Binary encoding (little-endian):
///   bytes [0..8]  — `as_of_block_height` (u64)
///   bytes [8..12] — `window_len` (u32)
///   bytes [12..]  — bitvec data (ceil(window_len / 8) bytes)
#[derive(Clone, Debug)]
struct Uptime {
    as_of_block_height: u64,
    bits: BitVec<u8, Lsb0>,
}

impl Uptime {
    fn new(initial_block_height: u64, window_len: usize) -> Self {
        Self {
            as_of_block_height: initial_block_height,
            bits: bitvec![u8, Lsb0; 1; window_len],
        }
    }

    fn mark_signed(&mut self, height: u64, signed: bool) {
        if height != self.as_of_block_height + 1 {
            // This indicates a bug — heights should always be sequential. Log it but don't
            // bail, since propagating this error would cause a chain halt.
            error!(
                expected = self.as_of_block_height + 1,
                got = height,
                "uptime tracker received non-sequential height; ring buffer index will be incorrect"
            );
        }
        let index = (height as usize) % self.bits.len();
        self.bits.set(index, signed);
        self.as_of_block_height = height;
    }

    fn num_missed_blocks(&self) -> usize {
        self.bits.iter_zeros().len()
    }

    fn window_len(&self) -> usize {
        self.bits.len()
    }
}

impl From<Uptime> for Bytes {
    fn from(mut uptime: Uptime) -> Self {
        let window_len = uptime.bits.len() as u32;
        uptime.bits.set_uninitialized(true);
        let bitvec_bytes = uptime.bits.into_vec();
        let mut buf = Vec::with_capacity(12 + bitvec_bytes.len());
        buf.extend_from_slice(&uptime.as_of_block_height.to_le_bytes());
        buf.extend_from_slice(&window_len.to_le_bytes());
        buf.extend_from_slice(&bitvec_bytes);
        Bytes::from(buf)
    }
}

impl TryFrom<Bytes> for Uptime {
    type Error = Report;

    fn try_from(b: Bytes) -> Result<Self, Self::Error> {
        if b.len() < 12 {
            bail!("uptime data too short: {} bytes", b.len());
        }
        let as_of_block_height = u64::from_le_bytes(b[0..8].try_into()?);
        let window_len = u32::from_le_bytes(b[8..12].try_into()?) as usize;
        let mut bits = BitVec::<u8, Lsb0>::from_vec(b[12..].to_vec());
        bits.truncate(window_len);
        Ok(Uptime {
            as_of_block_height,
            bits,
        })
    }
}

impl felidae_proto::DomainType for Uptime {
    type Proto = Bytes;
}

/// Uniform voting power assigned to every active validator.
///
/// 10^9 keeps jailed validators power of 1 negligible, fits within
/// `i32::MAX` leaving headroom for any incidental arithmetic, and stays well within
/// CometBFT's total-power limit of `i64::MAX / 8` even for large validator sets.
pub const BASE_VALIDATOR_POWER: u32 = 1_000_000_000;

impl<S: StateReadExt + StateWriteExt + 'static> State<S> {
    /// Declare a new validator by its public key.
    ///
    /// Always assigns `BASE_VALIDATOR_POWER`, ignoring any power value carried by the
    /// genesis `Update` — the genesis file's power is only used for the equal power
    /// sanity check in init_chain to warn the user that all validators must have the same power.
    pub(crate) async fn declare_validator(
        &mut self,
        pub_key: tendermint::PublicKey,
    ) -> Result<(), Report> {
        // Check to ensure the validator does not exist already (prevents redeclaring tombstoned
        // validators to set their power back to non-zero):
        let existing: Option<Power> = self
            .store
            .get(
                Internal,
                &format!("current/validators/{}", hex::encode(pub_key.to_bytes())),
            )
            .await?;
        if let Some(existing) = existing {
            bail!(
                "validator {} already exists with power {}",
                hex::encode(pub_key.to_bytes()),
                existing,
            );
        }

        let pub_key_hex = hex::encode(pub_key.to_bytes());
        self.store.put(
            Internal,
            &format!("current/validators/{}", pub_key_hex),
            Power::from(BASE_VALIDATOR_POWER),
        );
        self.store.put(
            Internal,
            &format!("current/validator_status/{}", pub_key_hex),
            ValidatorStatus::Active,
        );

        // Initialize the uptime tracker with a grace-period window (all 1s).
        let window_len = self.config().await?.validator_config.uptime_window as usize;
        let current_height = self.block_height().await.ok().map_or(0, |h| h.value());
        self.store.put(
            Internal,
            &format!("current/validator_uptime/{}", pub_key_hex),
            Uptime::new(current_height, window_len),
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
    ) -> Result<Option<Update>, Report> {
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
            return Ok(None);
        };

        let pub_key_hex = hex::encode(bad_pub_key.to_bytes());

        if self.validator_status(&bad_pub_key).await? == Some(ValidatorStatus::Tombstoned) {
            warn!(pub_key = pub_key_hex, "validator is already tombstoned");
            return Ok(None);
        }

        info!(pub_key = pub_key_hex, "tombstoning validator");
        self.store.put(
            Internal,
            &format!("current/validators/{}", pub_key_hex),
            Power::from(0u32),
        );
        self.set_validator_status(&bad_pub_key, ValidatorStatus::Tombstoned);

        Ok(Some(Update {
            pub_key: bad_pub_key,
            power: Power::from(0u32),
        }))
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

    /// Build a list of [`ValidatorInfo`] for every validator tracked on the chain.
    ///
    /// This is the data source for the `/validators` query endpoint. The returned entries
    /// cover validators in every lifecycle state (Active, Inactive, Jailed, Tombstoned);
    /// callers can filter by [`ValidatorInfo::status`] or by `power` as needed.
    pub async fn validator_info(
        &self,
    ) -> Result<Vec<felidae_types::response::ValidatorInfo>, Report> {
        let validator_config = self.config().await?.validator_config;
        let mut result = Vec::new();
        let mut powers: Vec<(tendermint::PublicKey, Power)> = Vec::new();
        {
            let mut stream = Box::pin(self.store.prefix::<Power>(Internal, "current/validators/"));
            while let Some(Ok((key, power))) = stream.next().await {
                let pub_key_bytes = hex::decode(key.trim_start_matches("current/validators/"))?;
                let pub_key = tendermint::PublicKey::from_raw_ed25519(&pub_key_bytes)
                    .ok_or_eyre("invalid ed25519 public key")?;
                powers.push((pub_key, power));
            }
        }
        for (pub_key, power) in powers {
            let pub_key_hex = hex::encode(pub_key.to_bytes());
            let mut ctx = Sha256::new();
            ctx.update(pub_key.to_bytes());
            let hash: [u8; 32] = ctx.finalize().into();
            let address_hex = hex::encode(&hash[0..20]);

            let status = match self.validator_status(&pub_key).await? {
                Some(ValidatorStatus::Active) => "active",
                Some(ValidatorStatus::Inactive) => "inactive",
                Some(ValidatorStatus::Jailed) => "jailed",
                Some(ValidatorStatus::Tombstoned) => "tombstoned",
                // Predates status tracking — treat as active when it still has power.
                None if power.value() > 0 => "active",
                None => "inactive",
            };

            let uptime: Option<Uptime> = self
                .store
                .get(
                    Internal,
                    &format!("current/validator_uptime/{}", pub_key_hex),
                )
                .await?;
            let (missed_blocks, uptime_window) = match &uptime {
                Some(u) => (u.num_missed_blocks() as u64, u.window_len() as u64),
                None => (0, validator_config.uptime_window),
            };

            result.push(felidae_types::response::ValidatorInfo {
                identity: pub_key_hex,
                address: address_hex,
                power: power.value(),
                status: status.to_string(),
                missed_blocks,
                uptime_window,
                missed_blocks_max: validator_config.missed_blocks_max,
                unjail_missed_max: validator_config.unjail_missed_max,
            });
        }
        Ok(result)
    }

    /// Get all validators with non-zero power (Active and Jailed).
    ///
    /// Jailed validators carry power=1 rather than being removed from the CometBFT set,
    /// so they appear here. Use [`validator_status`] to distinguish Active from Jailed.
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

        let config = self.config().await?;

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

        // Build a map of config validators by public key bytes.
        let mut config_validators_map = BTreeMap::new();
        for validator in config_validators {
            let pub_key_bytes: Vec<u8> = validator.public_key.to_vec();
            let pub_key = tendermint::PublicKey::from_raw_ed25519(&pub_key_bytes)
                .ok_or_eyre("invalid ed25519 public key in config")?;
            config_validators_map.insert(pub_key_bytes, pub_key);
        }

        let mut updates: Vec<Update> = Vec::new();

        // Handle validators present in Config:
        for (pub_key_bytes, pub_key) in config_validators_map.iter() {
            let pub_key_hex = hex::encode(pub_key.to_bytes());
            match state_validators.get(pub_key_bytes).map(|(_, _, s)| s) {
                None => {
                    // Brand new validator — add it as active with BASE_VALIDATOR_POWER.
                    info!(pub_key = pub_key_hex, "adding new validator");
                    self.declare_validator(*pub_key).await?;
                    updates.push(Update {
                        pub_key: *pub_key,
                        power: Power::from(BASE_VALIDATOR_POWER),
                    });
                }
                Some(ValidatorStatus::Active) => {
                    // Already active so no change.
                    debug!(pub_key = pub_key_hex, "validator already active, skipping");
                }
                Some(ValidatorStatus::Inactive) => {
                    // Re-activated by admins - transition from Inactive back to Active.
                    info!(pub_key = pub_key_hex, "re-activating validator");
                    self.store.put(
                        Internal,
                        &format!("current/validators/{}", pub_key_hex),
                        Power::from(BASE_VALIDATOR_POWER),
                    );
                    self.set_validator_status(pub_key, ValidatorStatus::Active);
                    // Reset uptime to a fresh grace period.
                    let window_len = config.validator_config.uptime_window as usize;
                    let current_height = self.block_height().await.ok().map_or(0, |h| h.value());
                    self.store.put(
                        Internal,
                        &format!("current/validator_uptime/{}", pub_key_hex),
                        Uptime::new(current_height, window_len),
                    );
                    updates.push(Update {
                        pub_key: *pub_key,
                        power: Power::from(BASE_VALIDATOR_POWER),
                    });
                }
                Some(ValidatorStatus::Jailed) => {
                    // Jailed validators unjail via uptime recovery.
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
                    // Set power to 0 so CometBFT removes them from the validator set.
                    info!(pub_key = pub_key_hex, "removing jailed validator");
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
                ValidatorStatus::Inactive | ValidatorStatus::Tombstoned => {
                    // Already inactive so no change.
                }
            }
        }

        Ok(updates)
    }

    /// Record validator uptime for the given block height.
    ///
    /// `voted_addresses` is the set of validator addresses (first 20 bytes of SHA-256 of pubkey)
    /// that signed the previous block as reported by CometBFT in `FinalizeBlock`.
    pub(crate) async fn mark_validators_voted(
        &mut self,
        height: u64,
        voted_addresses: BTreeSet<[u8; 20]>,
    ) -> Result<(), Report> {
        let window_len = self.config().await?.validator_config.uptime_window as usize;
        let active_validators = self.active_validators().await?;
        for Update { pub_key, .. } in active_validators {
            // Compute the address of this validator (first 20 bytes of SHA-256 of pub key):
            let mut context = Sha256::new();
            context.update(pub_key.to_bytes());
            let pub_key_hash: [u8; 32] = context.finalize().into();
            let validator_address: [u8; 20] =
                pub_key_hash[0..20].try_into().expect("slice is 20 bytes");

            // At height 1 there is no previous commit, so CometBFT reports no signers.
            // Mark everyone as signed to avoid an unfair miss at genesis.
            let signed = if height == 1 {
                true
            } else {
                voted_addresses.contains(&validator_address)
            };
            let pub_key_hex = hex::encode(pub_key.to_bytes());
            let uptime_key = format!("current/validator_uptime/{}", pub_key_hex);

            let mut uptime: Uptime = self
                .store
                .get(Internal, &uptime_key)
                .await?
                .unwrap_or_else(|| Uptime::new(height.saturating_sub(1), window_len));

            // If the window size changed in config, reset to a fresh grace-period tracker.
            if uptime.window_len() != window_len {
                uptime = Uptime::new(height.saturating_sub(1), window_len);
            }

            debug!(
                pub_key = pub_key_hex,
                height,
                signed,
                missed = uptime.num_missed_blocks(),
                "recording validator vote"
            );
            uptime.mark_signed(height, signed);
            self.store.put(Internal, &uptime_key, uptime);
        }
        Ok(())
    }

    /// Check all validators' uptime and update jailing status.
    ///
    /// Implements:
    /// - Active --> Jailed: power drops to 1 (not 0) so CometBFT still delivers their
    ///   votes, allowing them to continue tracking uptime, enabling
    ///   them to unjail automatically once their uptime recovers.
    /// - Jailed --> Active: once missed_blocks falls back within the threshold the
    ///   validator is unjailed and restored to BASE_VALIDATOR_POWER.
    pub(crate) async fn jail_inactive_validators(&mut self) -> Result<Vec<Update>, Report> {
        let validator_config = self.config().await?.validator_config;
        let missed_blocks_max = validator_config.missed_blocks_max as usize;
        let unjail_missed_max = validator_config.unjail_missed_max as usize;
        let all_pub_keys = self.all_validators().await?;
        let mut updates = vec![];

        for pub_key in all_pub_keys {
            let pub_key_hex = hex::encode(pub_key.to_bytes());
            let Some(status) = self.validator_status(&pub_key).await? else {
                continue;
            };

            match status {
                ValidatorStatus::Active => {
                    let uptime_key = format!("current/validator_uptime/{}", pub_key_hex);
                    let Some(uptime): Option<Uptime> =
                        self.store.get(Internal, &uptime_key).await?
                    else {
                        continue;
                    };
                    let missed = uptime.num_missed_blocks();
                    if missed > missed_blocks_max {
                        info!(
                            pub_key = pub_key_hex,
                            missed, missed_blocks_max, "jailing validator for insufficient uptime"
                        );
                        // Power drops to 1, not 0 so we still get votes for uptime tracking.
                        self.store.put(
                            Internal,
                            &format!("current/validators/{}", pub_key_hex),
                            Power::from(1u32),
                        );
                        self.set_validator_status(&pub_key, ValidatorStatus::Jailed);
                        updates.push(Update {
                            pub_key,
                            power: Power::from(1u32),
                        });
                    }
                }
                ValidatorStatus::Jailed => {
                    let uptime_key = format!("current/validator_uptime/{}", pub_key_hex);
                    let Some(uptime): Option<Uptime> =
                        self.store.get(Internal, &uptime_key).await?
                    else {
                        continue;
                    };
                    let missed = uptime.num_missed_blocks();
                    if missed <= unjail_missed_max {
                        info!(
                            pub_key = pub_key_hex,
                            missed, unjail_missed_max, "unjailing validator; uptime has recovered"
                        );
                        self.store.put(
                            Internal,
                            &format!("current/validators/{}", pub_key_hex),
                            Power::from(BASE_VALIDATOR_POWER),
                        );
                        self.set_validator_status(&pub_key, ValidatorStatus::Active);
                        updates.push(Update {
                            pub_key,
                            power: Power::from(BASE_VALIDATOR_POWER),
                        });
                    }
                }
                ValidatorStatus::Inactive | ValidatorStatus::Tombstoned => {}
            }
        }

        Ok(updates)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use felidae_types::transaction::{
        Admin, AdminConfig, Delay, OnionConfig, OracleConfig, Quorum, Timeout, Total,
        ValidatorConfig, VotingConfig,
    };
    use prost::bytes::Bytes;
    use tempfile::TempDir;
    use tendermint::block::Height;

    use super::*;
    use crate::Store;

    fn test_pub_key() -> tendermint::PublicKey {
        tendermint::PublicKey::from_raw_ed25519(&[1u8; 32]).expect("valid ed25519 key")
    }

    /// Compute the CometBFT validator address for a public key.
    fn validator_address(pub_key: &tendermint::PublicKey) -> [u8; 20] {
        let mut ctx = Sha256::new();
        ctx.update(pub_key.to_bytes());
        let hash: [u8; 32] = ctx.finalize().into();
        hash[0..20].try_into().expect("slice is 20 bytes")
    }

    fn test_config(validator_config: ValidatorConfig) -> Config {
        Config {
            version: 1,
            admins: AdminConfig {
                voting: VotingConfig {
                    total: Total(1),
                    quorum: Quorum(1),
                    timeout: Timeout(Duration::from_secs(3600)),
                    delay: Delay(Duration::from_secs(0)),
                },
                authorized: vec![Admin {
                    identity: Bytes::from(vec![0xabu8; 64]),
                }],
            },
            oracles: OracleConfig {
                enabled: false,
                voting: VotingConfig {
                    total: Total(1),
                    quorum: Quorum(1),
                    timeout: Timeout(Duration::from_secs(3600)),
                    delay: Delay(Duration::from_secs(0)),
                },
                max_enrolled_subdomains: 10,
                observation_timeout: Duration::from_secs(300),
                authorized: vec![],
            },
            onion: OnionConfig { enabled: false },
            validators: vec![],
            validator_config,
        }
    }

    /// Set up state with a config and a single declared validator at height 2.
    ///
    /// Returns the `(Store, TempDir)` pair; the `TempDir` must be kept alive for the test.
    async fn setup_state_with_validator(validator_config: ValidatorConfig) -> (Store, TempDir) {
        let temp_dir = TempDir::new().expect("failed to create temp dir");
        let store = Store::init(temp_dir.path().to_path_buf())
            .await
            .expect("failed to create store");

        let pub_key = test_pub_key();
        {
            let mut state = store.state.write().await;
            state
                .set_config(test_config(validator_config))
                .await
                .expect("set_config");
            // Start at height 2 so the height 1 special case does not affect the first vote.
            // (height 1 is the genesis block, so no votes are expected yet).
            state
                .set_block_height(Height::from(2u32))
                .await
                .expect("set_block_height");
            state
                .declare_validator(pub_key)
                .await
                .expect("declare_validator");
        }
        (store, temp_dir)
    }

    #[tokio::test]
    async fn test_active_to_jailed_on_excessive_misses() {
        // window=10, jail threshold=5 - missing 6 consecutive blocks should trigger jailing.
        let (store, _dir) = setup_state_with_validator(ValidatorConfig {
            uptime_window: 10,
            missed_blocks_max: 5,
            unjail_missed_max: 2,
        })
        .await;

        let pub_key = test_pub_key();
        let mut state = store.state.write().await;

        // Simulate 6 blocks where the validator does not vote.
        // An empty voted_addresses set means no validator signed.
        for height in 3u64..=8 {
            state
                .mark_validators_voted(height, BTreeSet::new())
                .await
                .expect("mark_validators_voted");
        }

        // The validator has 6 misses > missed_blocks_max of 5, so it should be jailed.
        let updates = state
            .jail_inactive_validators()
            .await
            .expect("jail_inactive_validators");

        assert_eq!(updates.len(), 1, "expected exactly one power update");
        let update = &updates[0];
        assert_eq!(
            update.pub_key, pub_key,
            "update should be for our validator"
        );
        assert_eq!(
            update.power,
            Power::from(1u32),
            "jailed validator power should be 1, not 0"
        );

        let status = state
            .validator_status(&pub_key)
            .await
            .expect("validator_status")
            .expect("status should be set");
        // And now we should be Jailed.
        assert_eq!(status, ValidatorStatus::Jailed);
    }

    #[tokio::test]
    async fn test_jailed_to_active_on_uptime_recovery() {
        // window=10, jail threshold=5, unjail threshold=2.
        //
        // Phase 1: jail by missing heights 3-8 (6 misses).
        // Phase 2: recover by signing heights 9-16.
        //   Heights 9-12 overwrite indices that were already 1 (grace period), no change.
        //   Heights 13-16 overwrite the 0s at indices 3-6, dropping missed from 6 down to 2.
        //   At missed=2 == unjail_missed_max the validator should be unjailed.
        let (store, _dir) = setup_state_with_validator(ValidatorConfig {
            uptime_window: 10,
            missed_blocks_max: 5,
            unjail_missed_max: 2,
        })
        .await;

        let pub_key = test_pub_key();
        let address = validator_address(&pub_key);
        let mut state = store.state.write().await;

        // Phase 1: miss enough blocks to trigger jailing.
        for height in 3u64..=8 {
            state
                .mark_validators_voted(height, BTreeSet::new())
                .await
                .expect("mark_validators_voted");
        }
        state
            .jail_inactive_validators()
            .await
            .expect("jail phase 1");
        assert_eq!(
            state.validator_status(&pub_key).await.unwrap(),
            Some(ValidatorStatus::Jailed),
            "should be Jailed after phase 1"
        );

        // Phase 2: sign every block during recovery.
        // The jailed validator still appears in active_validators (power=1 > 0),
        // so its uptime continues to be tracked.
        let voted = BTreeSet::from([address]);
        for height in 9u64..=15 {
            state
                .mark_validators_voted(height, voted.clone())
                .await
                .expect("mark_validators_voted");
        }

        // At height 15 we have 3 misses remaining - still above unjail_missed_max=2, so
        // calling jail_inactive_validators here must NOT unjail the validator.
        let updates = state
            .jail_inactive_validators()
            .await
            .expect("jail_inactive_validators mid-recovery");
        assert!(
            updates.is_empty(),
            "should not unjail while still above unjail_missed_max"
        );
        assert_eq!(
            state.validator_status(&pub_key).await.unwrap(),
            Some(ValidatorStatus::Jailed),
            "should still be Jailed at 3 missed"
        );

        // One more signed block brings missed down to 2 == unjail_missed_max.
        state
            .mark_validators_voted(16, voted)
            .await
            .expect("mark_validators_voted height 16");

        let updates = state
            .jail_inactive_validators()
            .await
            .expect("jail_inactive_validators after full recovery");

        assert_eq!(
            updates.len(),
            1,
            "expected exactly one power update on unjail"
        );
        let update = &updates[0];
        assert_eq!(update.pub_key, pub_key);
        assert_eq!(
            update.power,
            Power::from(BASE_VALIDATOR_POWER),
            "unjailed validator should be restored to BASE_VALIDATOR_POWER"
        );

        assert_eq!(
            state.validator_status(&pub_key).await.unwrap(),
            Some(ValidatorStatus::Active)
        );
    }

    #[tokio::test]
    async fn test_active_to_inactive_via_config_sync() {
        // If a validator is absent from the new Config validator list, it should transition
        // from Active to Inactive with power=0 returned as an update.
        // This also adds a new validator which should transition to be the only active validator.
        let (store, _dir) = setup_state_with_validator(ValidatorConfig::default()).await;

        let pub_key = test_pub_key();
        // A second key that will be the only entry in the new config, displacing test_pub_key.
        let other_key =
            tendermint::PublicKey::from_raw_ed25519(&[2u8; 32]).expect("valid ed25519 key");
        let other_validator = felidae_types::transaction::Validator {
            public_key: Bytes::copy_from_slice(&other_key.to_bytes()),
        };

        let mut state = store.state.write().await;

        // Sync with a config that only contains other_key - test_pub_key is absent.
        // Note: sync_validators_from_config treats an empty slice as "unmanaged" and is a no-op,
        // so we must pass a non-empty list.
        let updates = state
            .sync_validators_from_config(&[other_validator])
            .await
            .expect("sync_validators_from_config");

        // There should be two updates: power=0 for the removed validator and
        // power=BASE_VALIDATOR_POWER for the newly added one.
        let removed = updates
            .iter()
            .find(|u| u.pub_key == pub_key)
            .expect("update for removed validator");
        assert_eq!(
            removed.power,
            Power::from(0u32),
            "removed validator should have power=0"
        );

        assert_eq!(
            state.validator_status(&pub_key).await.unwrap(),
            Some(ValidatorStatus::Inactive)
        );

        // The newly added validator should be Active with BASE_VALIDATOR_POWER power.
        let added = updates
            .iter()
            .find(|u| u.pub_key == other_key)
            .expect("update for added validator");
        assert_eq!(added.power, Power::from(BASE_VALIDATOR_POWER));
        assert_eq!(
            state.validator_status(&other_key).await.unwrap(),
            Some(ValidatorStatus::Active)
        );
    }

    #[tokio::test]
    async fn test_jailed_to_inactive_via_config_sync() {
        // A jailed validator (power=1) that is removed from the Config should transition to
        // Inactive with power=0.
        let (store, _dir) = setup_state_with_validator(ValidatorConfig {
            uptime_window: 10,
            missed_blocks_max: 5,
            unjail_missed_max: 2,
        })
        .await;

        let pub_key = test_pub_key();
        let other_key =
            tendermint::PublicKey::from_raw_ed25519(&[2u8; 32]).expect("valid ed25519 key");
        let other_validator = felidae_types::transaction::Validator {
            public_key: Bytes::copy_from_slice(&other_key.to_bytes()),
        };

        let mut state = store.state.write().await;

        // Jail test_pub_key by simulating missed blocks.
        for height in 3u64..=8 {
            state
                .mark_validators_voted(height, BTreeSet::new())
                .await
                .expect("mark_validators_voted");
        }
        state.jail_inactive_validators().await.expect("jail phase");
        assert_eq!(
            state.validator_status(&pub_key).await.unwrap(),
            Some(ValidatorStatus::Jailed),
            "precondition: validator should be Jailed"
        );

        // Now sync with a config that doesn't include test_pub_key.
        let updates = state
            .sync_validators_from_config(&[other_validator])
            .await
            .expect("sync_validators_from_config");

        // The jailed validator should appear in the updates with power=0 so CometBFT
        // removes it from the validator set (it was sitting at power=1 while jailed).
        let removed = updates
            .iter()
            .find(|u| u.pub_key == pub_key)
            .expect("update for jailed and removed validator");
        assert_eq!(
            removed.power,
            Power::from(0u32),
            "removed jailed validator should have power=0"
        );

        assert_eq!(
            state.validator_status(&pub_key).await.unwrap(),
            Some(ValidatorStatus::Inactive)
        );
    }

    #[tokio::test]
    async fn test_active_to_tombstoned() {
        // Tombstoning an active validator should immediately set power=0 and return an update.
        // A second tombstone call for the same validator should be a no op (returns None).
        let (store, _dir) = setup_state_with_validator(ValidatorConfig::default()).await;

        let pub_key = test_pub_key();
        let address = validator_address(&pub_key);

        let mut state = store.state.write().await;

        let update = state
            .tombstone_validator(Validator {
                address,
                power: Power::from(BASE_VALIDATOR_POWER),
            })
            .await
            .expect("tombstone_validator");

        let update = update.expect("first tombstone should return Some(update)");
        assert_eq!(update.pub_key, pub_key);
        assert_eq!(
            update.power,
            Power::from(0u32),
            "tombstoned validator should have power=0"
        );
        assert_eq!(
            state.validator_status(&pub_key).await.unwrap(),
            Some(ValidatorStatus::Tombstoned)
        );

        // Calling tombstone again should be a no op - its already tombstoned.
        let second = state
            .tombstone_validator(Validator {
                address,
                power: Power::from(0u32),
            })
            .await
            .expect("second tombstone_validator");
        assert!(
            second.is_none(),
            "tombstoning an already tombstoned validator should return None"
        );
    }

    #[tokio::test]
    async fn test_inactive_to_active_via_config_sync() {
        // A validator that was removed (Inactive) should be reactivated when it reappears
        // in the Config, with power back up to BASE_VALIDATOR_POWER.
        let (store, _dir) = setup_state_with_validator(ValidatorConfig::default()).await;

        let pub_key = test_pub_key();
        let other_key =
            tendermint::PublicKey::from_raw_ed25519(&[2u8; 32]).expect("valid ed25519 key");
        let our_validator = felidae_types::transaction::Validator {
            public_key: Bytes::copy_from_slice(&pub_key.to_bytes()),
        };
        let other_validator = felidae_types::transaction::Validator {
            public_key: Bytes::copy_from_slice(&other_key.to_bytes()),
        };

        let mut state = store.state.write().await;

        // First sync: test_pub_key is absent from the config, so it transitions to Inactive.
        state
            .sync_validators_from_config(&[other_validator.clone()])
            .await
            .expect("sync 1");
        assert_eq!(
            state.validator_status(&pub_key).await.unwrap(),
            Some(ValidatorStatus::Inactive),
            "precondition: should be Inactive after first sync"
        );

        // Second sync: readd test_pub_key alongside the other validator.
        let updates = state
            .sync_validators_from_config(&[our_validator, other_validator])
            .await
            .expect("sync 2: readd test_pub_key");

        let reactivated = updates
            .iter()
            .find(|u| u.pub_key == pub_key)
            .expect("update for reactivated validator");
        assert_eq!(
            reactivated.power,
            Power::from(BASE_VALIDATOR_POWER),
            "reactivated validator should be restored to BASE_VALIDATOR_POWER"
        );
        assert_eq!(
            state.validator_status(&pub_key).await.unwrap(),
            Some(ValidatorStatus::Active)
        );
    }

    #[tokio::test]
    async fn test_jailed_to_tombstoned() {
        // A jailed validator has power=1 in CometBFT. Tombstoning it should produce a
        // power=0 update and transition the validator to Tombstoned.
        let (store, _dir) = setup_state_with_validator(ValidatorConfig {
            uptime_window: 10,
            missed_blocks_max: 5,
            unjail_missed_max: 2,
        })
        .await;

        let pub_key = test_pub_key();
        let address = validator_address(&pub_key);

        let mut state = store.state.write().await;

        // Jail the validator.
        for height in 3u64..=8 {
            state
                .mark_validators_voted(height, BTreeSet::new())
                .await
                .expect("mark_validators_voted");
        }
        state.jail_inactive_validators().await.expect("jail phase");
        assert_eq!(
            state.validator_status(&pub_key).await.unwrap(),
            Some(ValidatorStatus::Jailed),
            "precondition: validator should be Jailed"
        );

        // Tombstone the jailed validator.
        let update = state
            .tombstone_validator(Validator {
                address,
                power: Power::from(1u32),
            })
            .await
            .expect("tombstone_validator")
            .expect("should return Some(update) for a jailed validator");

        assert_eq!(update.pub_key, pub_key);
        assert_eq!(
            update.power,
            Power::from(0u32),
            "tombstoned validator should have power=0 regardless of prior jailed power"
        );
        assert_eq!(
            state.validator_status(&pub_key).await.unwrap(),
            Some(ValidatorStatus::Tombstoned)
        );
    }

    #[tokio::test]
    async fn test_inactive_to_tombstoned() {
        // Misbehavior evidence can arrive for a validator that was already removed from the
        // config (Inactive, power=0). tombstone_validator searches all_validators(), not just
        // active ones, so it should still find the validator and return a power=0 update.
        let (store, _dir) = setup_state_with_validator(ValidatorConfig::default()).await;

        let pub_key = test_pub_key();
        let address = validator_address(&pub_key);
        let other_key =
            tendermint::PublicKey::from_raw_ed25519(&[2u8; 32]).expect("valid ed25519 key");
        let other_validator = felidae_types::transaction::Validator {
            public_key: Bytes::copy_from_slice(&other_key.to_bytes()),
        };

        let mut state = store.state.write().await;

        // Drive test_pub_key to Inactive via config sync.
        state
            .sync_validators_from_config(&[other_validator])
            .await
            .expect("sync");
        assert_eq!(
            state.validator_status(&pub_key).await.unwrap(),
            Some(ValidatorStatus::Inactive),
            "precondition: validator should be Inactive"
        );

        // Evidence arrives for the now inactive validator.
        let update = state
            .tombstone_validator(Validator {
                address,
                power: Power::from(0u32),
            })
            .await
            .expect("tombstone_validator")
            .expect("should return Some(update) for an inactive validator");

        assert_eq!(update.pub_key, pub_key);
        assert_eq!(update.power, Power::from(0u32));
        assert_eq!(
            state.validator_status(&pub_key).await.unwrap(),
            Some(ValidatorStatus::Tombstoned)
        );
    }
}
