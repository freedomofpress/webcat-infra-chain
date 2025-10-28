use super::*;

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
                "Validator {} already exists with power {}",
                hex::encode(validator.pub_key.to_bytes()),
                existing,
            );
        }

        self.store.put(
            Internal,
            &format!(
                "current/validators/{}",
                hex::encode(validator.pub_key.to_bytes())
            ),
            validator.power,
        );

        Ok(())
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
