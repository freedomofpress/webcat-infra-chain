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

        // Load the initial config from the genesis file. There is no default:
        // a chain must launch with a complete, valid config in its genesis, so
        // that governance is never open to the first comer.
        if request.app_state_bytes.is_empty() {
            bail!(
                "genesis app_state is empty: a genesis file must carry an app_state.config \
                 (see docs/webcat-onboard-guide.md for authoring one)"
            );
        }

        // Parse the JSON from app_state_bytes and extract the config:
        // The genesis file has app_state as JSON, which gets serialized to bytes
        let app_state: serde_json::Value = serde_json::from_slice(&request.app_state_bytes)
            .map_err(|e| eyre!("failed to parse app_state as JSON: {}", e))?;

        // Extract the config key from app_state
        let config_value = app_state
            .get("config")
            .ok_or_eyre("app_state must contain a 'config' key")?;

        // Deserialize the config from JSON
        let config: Config = serde_json::from_value(config_value.clone())
            .map_err(|e| eyre!("failed to deserialize config from app_state.config: {}", e))?;

        // Validate the config before committing it. This is the only gate a
        // genesis config passes through — `check_config` belongs to the
        // reconfigure action and never sees genesis. Placeholder identities,
        // zero quorums, and node-fatal validator tuning are all rejected here.
        config.check_stateless()?;

        // Set the initial config in the state:
        self.set_config(config.clone()).await?;

        // If the initial config does have validators (optional),
        // we need to check that the public keys match the genesis validators exactly.
        if !config.validators.is_empty() {
            let genesis_keys: BTreeMap<Vec<u8>, ()> = request
                .validators
                .iter()
                .map(|v| (v.pub_key.to_bytes(), ()))
                .collect();

            let config_keys: BTreeMap<Vec<u8>, ()> = config
                .validators
                .iter()
                .map(|v| (v.public_key.as_bytes().to_vec(), ()))
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

        // Declare the initial validator set, overriding genesis powers with BASE_VALIDATOR_POWER:
        for validator in request.validators.iter() {
            self.declare_validator(validator.pub_key).await?;
        }

        // Build the response validator set with our canonical power, not the genesis file's power.
        let validators = request
            .validators
            .iter()
            .map(|v| Update {
                pub_key: v.pub_key,
                power: Power::from(BASE_VALIDATOR_POWER),
            })
            .collect();

        Ok(response::InitChain {
            // TODO: permit changing consensus params?
            consensus_params: Some(request.consensus_params),
            validators,
            app_hash,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use felidae_types::transaction::{
        Admin, AdminConfig, Delay, Identity, OnionConfig, Oracle, OracleConfig, Quorum, Timeout,
        Total, Validator, ValidatorConfig, ValidatorKey, VotingConfig,
    };
    use tempfile::TempDir;

    use super::*;
    use crate::Store;

    /// Deterministic P-256 identity derived from a fixed low scalar (256 + n,
    /// so no `n` collides with the generator-point placeholder at scalar 1).
    fn test_identity(n: u8) -> Identity {
        let mut scalar = [0u8; 32];
        scalar[30] = 1;
        scalar[31] = n;
        let signing_key =
            p256::ecdsa::SigningKey::from_slice(&scalar).expect("low scalar is a valid key");
        Identity::from(*signing_key.verifying_key())
    }

    /// A minimal but well-formed operator genesis config, mirroring the shape
    /// of the deployed testnet genesis files (no validators — the validator
    /// set is unmanaged until a later reconfigure).
    fn genesis_config() -> Config {
        Config {
            version: 0,
            admins: AdminConfig {
                voting: VotingConfig {
                    total: Total(1),
                    quorum: Quorum(1),
                    timeout: Timeout(Duration::from_secs(3600)),
                    delay: Delay(Duration::from_secs(0)),
                },
                authorized: vec![Admin {
                    identity: test_identity(1),
                }],
            },
            oracles: OracleConfig {
                enabled: true,
                voting: VotingConfig {
                    total: Total(1),
                    quorum: Quorum(1),
                    timeout: Timeout(Duration::from_secs(3600)),
                    delay: Delay(Duration::from_secs(0)),
                },
                max_enrolled_subdomains: 5,
                observation_timeout: Duration::from_secs(300),
                authorized: vec![Oracle {
                    identity: test_identity(2),
                    endpoint: url::Url::parse("http://127.0.0.1:8081").unwrap(),
                }],
            },
            onion: OnionConfig { enabled: false },
            validators: vec![],
            validator_config: ValidatorConfig::default(),
        }
    }

    fn init_chain_request(app_state_bytes: Vec<u8>) -> request::InitChain {
        request::InitChain {
            time: tendermint::Time::unix_epoch(),
            chain_id: "test-chain".to_string(),
            consensus_params: tendermint::consensus::Params {
                block: tendermint::block::Size {
                    max_bytes: 22_020_096,
                    max_gas: -1,
                    time_iota_ms: 1000,
                },
                evidence: tendermint::evidence::Params {
                    max_age_num_blocks: 100_000,
                    max_age_duration: tendermint::evidence::Duration(Duration::from_secs(
                        48 * 3600,
                    )),
                    max_bytes: 1_048_576,
                },
                validator: tendermint::consensus::params::ValidatorParams {
                    pub_key_types: vec![tendermint::public_key::Algorithm::Ed25519],
                },
                version: None,
                abci: Default::default(),
            },
            validators: vec![],
            app_state_bytes: app_state_bytes.into(),
            initial_height: tendermint::block::Height::from(1u32),
        }
    }

    fn app_state_bytes(config: &Config) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({ "config": config })).expect("config serializes")
    }

    async fn run_init_chain(app_state_bytes: Vec<u8>) -> Result<response::InitChain, Report> {
        let temp_dir = TempDir::new().expect("failed to create temp dir");
        let store = Store::init(temp_dir.path().to_path_buf())
            .await
            .expect("failed to create store");
        let mut state = store.state.write().await;
        state.init_chain(init_chain_request(app_state_bytes)).await
    }

    #[tokio::test]
    async fn init_chain_accepts_valid_genesis_config() {
        run_init_chain(app_state_bytes(&genesis_config()))
            .await
            .expect("well-formed genesis config is accepted");
    }

    #[tokio::test]
    async fn init_chain_rejects_empty_app_state() {
        // There is no default config: a chain must not be startable in a
        // locked-open state where the first reconfigure is permissionless.
        let err = run_init_chain(vec![]).await.unwrap_err();
        assert!(
            err.to_string().contains("app_state is empty"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn init_chain_rejects_bootstrap_shape() {
        // The old locked-open bootstrap shape (no parties, zero quorums) is
        // now plainly invalid input, whether hand-written or a template
        // filled in wrong — no path admits it.
        let config = Config {
            version: 0,
            admins: AdminConfig {
                authorized: vec![],
                voting: VotingConfig {
                    total: Total(0),
                    quorum: Quorum(0),
                    timeout: Timeout(Duration::from_secs(0)),
                    delay: Delay(Duration::from_secs(0)),
                },
            },
            oracles: OracleConfig {
                enabled: false,
                authorized: vec![],
                voting: VotingConfig {
                    total: Total(0),
                    quorum: Quorum(0),
                    timeout: Timeout(Duration::from_secs(0)),
                    delay: Delay(Duration::from_secs(i64::MAX as u64)),
                },
                max_enrolled_subdomains: 0,
                observation_timeout: Duration::from_secs(i64::MAX as u64),
            },
            onion: OnionConfig { enabled: false },
            validators: vec![],
            validator_config: ValidatorConfig::default(),
        };
        let err = run_init_chain(app_state_bytes(&config)).await.unwrap_err();
        assert!(
            err.to_string().contains("quorum"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn init_chain_rejects_placeholder_admin_identity() {
        // The placeholder is the P-256 generator point: a *valid* key whose
        // private half is publicly known. A genesis that retains it would hand
        // admin authority to anyone, so init_chain must refuse to start.
        let mut config = genesis_config();
        config.admins.authorized[0].identity = Identity::placeholder();
        let err = run_init_chain(app_state_bytes(&config)).await.unwrap_err();
        assert!(
            err.to_string().contains("placeholder"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn init_chain_rejects_zero_uptime_window() {
        // uptime_window = 0 would panic every node at the first FinalizeBlock
        // (remainder by zero in the uptime ring buffer).
        let mut config = genesis_config();
        config.validators = vec![Validator {
            public_key: ValidatorKey::from_bytes(&[1u8; 32]).expect("valid ed25519 key"),
        }];
        config.validator_config.uptime_window = 0;
        // Note: config.validators requires matching genesis validators, but
        // validation runs before that comparison, which is what we assert on.
        let err = run_init_chain(app_state_bytes(&config)).await.unwrap_err();
        assert!(
            err.to_string().contains("uptime_window"),
            "unexpected error: {err}"
        );
    }
}
