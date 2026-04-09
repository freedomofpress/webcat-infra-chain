use std::collections::BTreeMap;

use super::*;

impl<S: StateReadExt + StateWriteExt + 'static> State<S> {
    /// Initialize the chain state.
    #[instrument(skip(self, request,))]
    pub async fn init_chain(
        &mut self,
        request: request::InitChain,
    ) -> Result<response::InitChain, Report> {
        // The initial app hash should be the hash of the InitChain request canonicalized as a protobuf:
        let mut hasher = Sha256::new();
        hasher.update(
            tendermint_proto::v0_38::abci::RequestInitChain::from(request.clone()).encode_to_vec(),
        );
        let app_hash = AppHash::try_from(hasher.finalize().to_vec())?;

        // Ensure that the initial height is 1:
        if request.initial_height.value() != 1 {
            bail!("initial height must be 1");
        }

        // Set the chain ID in the state:
        self.set_chain_id(ChainId(request.chain_id)).await?;

        // TODO: Set the genesis time in the state

        // Load the initial config from the genesis file, or use a default if not provided:
        let config = if request.app_state_bytes.is_empty() {
            // Default config when no genesis config is provided:
            Config {
                version: 0,
                admins: AdminConfig {
                    authorized: vec![], // Default admin set: the first reconfig will set this
                    voting: VotingConfig {
                        total: Total(0),   // No admins required to initially reconfigure
                        quorum: Quorum(0), // No quorum required to initially reconfigure
                        timeout: Timeout(Duration::from_secs(0)), // No follow-up voting for initial reconfig
                        delay: Delay(Duration::from_secs(0)),     // No delay for initial reconfig
                    },
                },
                oracles: OracleConfig {
                    enabled: false,     // Oracles disabled initially
                    authorized: vec![], // No oracles initially
                    voting: VotingConfig {
                        total: Total(0),                                    // No oracles initially
                        quorum: Quorum(0),                                  // No voting initially
                        timeout: Timeout(Duration::from_secs(0)),           // No voting initially
                        delay: Delay(Duration::from_secs(i64::MAX as u64)), // No voting initially
                    },
                    max_enrolled_subdomains: 0, // No subdomains initially
                    observation_timeout: Duration::from_secs(i64::MAX as u64), // No observations initially
                },
                onion: OnionConfig { enabled: false },
                validators: vec![],
                validator_config: ValidatorConfig::default(),
            }
        } else {
            // Parse the JSON from app_state_bytes and extract the config:
            // The genesis file has app_state as JSON, which gets serialized to bytes
            let app_state: serde_json::Value = serde_json::from_slice(&request.app_state_bytes)
                .map_err(|e| eyre!("failed to parse app_state as JSON: {}", e))?;

            // Extract the config key from app_state
            let config_value = app_state
                .get("config")
                .ok_or_eyre("app_state must contain a 'config' key")?;

            // Deserialize the config from JSON
            serde_json::from_value(config_value.clone())
                .map_err(|e| eyre!("failed to deserialize config from app_state.config: {}", e))?
        };

        // Set the initial config in the state:
        self.set_config(config.clone()).await?;

        // If the initial config does have validators (optional),
        // we need to check that the public keys match the genesis validators exactly.
        if !config.validators.is_empty() {
            let genesis_keys: BTreeMap<Vec<u8>, ()> = request
                .validators
                .iter()
                .map(|v| (v.pub_key.to_bytes().to_vec(), ()))
                .collect();

            let config_keys: BTreeMap<Vec<u8>, ()> = config
                .validators
                .iter()
                .map(|v| (v.public_key.to_vec(), ()))
                .collect();

            if genesis_keys.len() != config_keys.len() {
                bail!(
                    "genesis has {} validators but config has {} validators",
                    genesis_keys.len(),
                    config_keys.len()
                );
            }

            for pub_key_bytes in genesis_keys.keys() {
                if !config_keys.contains_key(pub_key_bytes) {
                    bail!(
                        "validator {} in genesis is not in config",
                        hex::encode(pub_key_bytes)
                    );
                }
            }
        }

        // Ensure all genesis validators have equal power:
        if let Some(first) = request.validators.first() {
            let expected_power = first.power;
            for validator in request.validators.iter().skip(1) {
                if validator.power != expected_power {
                    bail!(
                        "all validators must have equal power at init_chain, but validator {} has power {} while first has power {}",
                        hex::encode(validator.pub_key.to_bytes()),
                        validator.power,
                        expected_power,
                    );
                }
            }
        }

        // Declare the initial validator set:
        for validator in request.validators.iter() {
            self.declare_validator(validator.clone()).await?;
        }

        Ok(response::InitChain {
            // TODO: permit changing consensus params?
            consensus_params: Some(request.consensus_params),
            validators: request.validators,
            app_hash,
        })
    }
}
