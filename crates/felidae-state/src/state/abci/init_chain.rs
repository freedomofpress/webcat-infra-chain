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
            tendermint_proto::v0_34::abci::RequestInitChain::from(request.clone()).encode_to_vec(),
        );
        let app_hash = AppHash::try_from(hasher.finalize().to_vec())?;

        // Ensure that the initial height is 1:
        if request.initial_height.value() != 1 {
            bail!("initial height must be 1");
        }

        // Set the chain ID in the state:
        self.set_chain_id(ChainId(request.chain_id)).await?;

        // TODO: Set the genesis time in the state

        // Ensure that the app state is empty:
        if !request.app_state_bytes.is_empty() {
            bail!("app state must be empty");
        }

        // Set the initial config in the state:
        self.set_config(Config {
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
        })
        .await?;

        // Declare the initial validator set:
        for validator in request.validators.iter() {
            self.declare_validator(validator.clone()).await?;
        }

        Ok(response::InitChain {
            // TODO: permit changing consensus params?
            consensus_params: Some(request.consensus_params),
            // TODO: permit declaring validators in initial chain params: reflect them here
            validators: request.validators,
            app_hash,
        })
    }
}
