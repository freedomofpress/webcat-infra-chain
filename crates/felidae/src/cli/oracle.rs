use color_eyre::eyre::OptionExt;
use felidae_types::{FQDN, KeyPair};
use reqwest::StatusCode;
use reqwest::Url;
use tendermint::block::Height;
use tendermint_rpc::HttpClient;
use tendermint_rpc::client::Client;

use super::Run;

#[derive(clap::Subcommand)]
pub enum Oracle {
    /// Initialize a new oracle for the network.
    ///
    /// This generates a new oracle keypair and stores it locally. It does not register
    /// the oracle with the network; that must be done via a reconfiguration transaction.
    Init(Init),
    /// Display the public identity of the oracle, if initialized.
    Identity(Identity),
    /// Observe a given domain and submit its enrollment status to the network.
    ///
    /// This requires that the admin has already been initialized.
    Observe(Observe),
}

impl Run for Oracle {
    async fn run(self) -> Result<(), color_eyre::Report> {
        match self {
            Self::Init(cmd) => cmd.run().await,
            Self::Identity(cmd) => cmd.run().await,
            Self::Observe(cmd) => cmd.run().await,
        }
    }
}

#[derive(clap::Args)]
pub struct Init {
    /// Home directory for storing oracle keys (defaults to platform-specific directory).
    #[clap(long)]
    pub homedir: Option<std::path::PathBuf>,
}

impl Run for Init {
    async fn run(self) -> Result<(), color_eyre::Report> {
        let keypath = keypath(self.homedir.as_deref()).await?;
        if keypath.exists() {
            return Err(color_eyre::eyre::eyre!(
                "oracle keypair already exists at: {}",
                keypath.display()
            ));
        }

        let keypair = hex::encode(KeyPair::generate().encode()?);
        println!("Writing new oracle keypair to: {}", keypath.display());
        tokio::fs::write(keypath, keypair).await?;

        Ok(())
    }
}

#[derive(clap::Args)]
pub struct Identity {
    /// Home directory for storing oracle keys (defaults to platform-specific directory).
    #[clap(long)]
    pub homedir: Option<std::path::PathBuf>,
}

impl Run for Identity {
    async fn run(self) -> Result<(), color_eyre::Report> {
        let keypair = keypair(self.homedir.as_deref()).await?;
        let public_key = keypair.public_key();
        println!("{}", hex::encode(public_key));

        Ok(())
    }
}

#[derive(clap::Args)]
pub struct Observe {
    /// Domain name to observe.
    #[clap(long, short)]
    pub domain: FQDN,
    /// Zone name to observe.
    #[clap(long, short)]
    pub zone: FQDN,
    /// Node to which to send the observation.
    #[clap(long, short, default_value = "http://localhost:26657")]
    pub node: Url,
    /// Chain ID of the target chain (pulls from the node if not specified).
    #[clap(long, short)]
    pub chain: Option<String>,
    /// Home directory for storing oracle keys (defaults to platform-specific directory).
    #[clap(long)]
    pub homedir: Option<std::path::PathBuf>,
}

impl Run for Observe {
    async fn run(self) -> Result<(), color_eyre::Report> {
        // Load the oracle keypair:
        let keypair = keypair(self.homedir.as_deref()).await?;

        // Create a Tendermint RPC client:
        let rpc_url = tendermint_rpc::Url::try_from(self.node.clone())
            .map_err(|e| color_eyre::eyre::eyre!("invalid RPC URL: {}", e))?;
        let rpc_client = HttpClient::new(rpc_url)
            .map_err(|e| color_eyre::eyre::eyre!("failed to create RPC client: {}", e))?;

        // We need reqwest for the enrollment endpoint:
        let http_client = reqwest::Client::new();

        // Fetch the hash from the well-known endpoint of the domain/zone:
        let enrollment_string = match http_client
            .get(format!(
                "https://{}/.well-known/webcat/enrollment.json",
                self.domain.to_string().trim_matches('.')
            ))
            .send()
            .await?
            .error_for_status()
        {
            Ok(response) => {
                let enrollment_string = response.text().await?;
                Some(enrollment_string)
            }
            Err(error) => match error.status() {
                // These status codes should be treated as "unenrolled":
                Some(StatusCode::NOT_FOUND | StatusCode::GONE) => None,
                // Any other errors should not result in an oracle observation:
                None => {
                    return Err(color_eyre::eyre::eyre!(
                        "failed to fetch enrollment: {}",
                        error
                    ));
                }
                Some(status) => {
                    return Err(color_eyre::eyre::eyre!(
                        "unexpected status code while fetching enrollment: HTTP {} {}",
                        status.as_u16(),
                        status.canonical_reason().unwrap_or("")
                    ));
                }
            },
        };

        if enrollment_string.is_some() {
            info!(domain = %self.domain, "fetched enrollment");
        } else {
            info!(domain = %self.domain, "no enrollment found");
        }

        // Get the latest block height from abci_info:
        let abci_info = rpc_client.abci_info().await?;
        let latest_height = abci_info.last_block_height.value();

        // Get the previous block (height - 1) to get its finalized app_hash.
        // The app_hash of a block is only known in the block that succeeds it,
        // so we need to use the previous block's information.
        let previous_height = if latest_height > 0 {
            Height::try_from(latest_height - 1)
                .map_err(|e| color_eyre::eyre::eyre!("invalid height: {}", e))?
        } else {
            return Err(color_eyre::eyre::eyre!(
                "cannot get previous block: chain is at height 0"
            ));
        };

        // Fetch the previous block to get its finalized app_hash:
        let block_result = rpc_client.block(previous_height).await?;
        let block = block_result.block;
        let last_block_height = block.header.height.value();
        let last_block_app_hash = hex::encode(block.header.app_hash.as_bytes());

        info!(
            last_block_height,
            last_block_app_hash,
            previous_height = previous_height.value(),
            "fetched previous block info"
        );

        // If the chain ID was not specified, pull it from the node:
        let chain_id = if let Some(chain_id) = self.chain {
            chain_id
        } else {
            let genesis: tendermint::Genesis<serde_json::Value> = rpc_client.genesis().await?;
            let chain_id = genesis.chain_id.to_string();
            info!(chain_id = %chain_id, "fetched chain ID from node");
            chain_id
        };

        // Create the witnessing transaction:
        let tx = felidae_oracle::witness(
            hex::encode(keypair.encode()?),
            chain_id,
            last_block_app_hash,
            last_block_height,
            self.domain.to_string(),
            self.zone.to_string(),
            enrollment_string.unwrap_or_default(),
        )?;

        // Submit the transaction to the node:
        let tx_bytes = hex::decode(&tx)
            .map_err(|e| color_eyre::eyre::eyre!("failed to decode transaction hex: {}", e))?;
        let broadcast_result = rpc_client.broadcast_tx_sync(tx_bytes).await?;

        info!(
            tx = %tx,
            code = ?broadcast_result.code,
            hash = %hex::encode(broadcast_result.hash.as_bytes()),
            "submitted transaction"
        );

        Ok(())
    }
}

async fn keypath(homedir: Option<&std::path::Path>) -> color_eyre::Result<std::path::PathBuf> {
    let oracle_dir = if let Some(homedir) = homedir {
        homedir.to_path_buf()
    } else {
        let directories = directories::ProjectDirs::from("press", "freedom", "felidae-oracle")
            .ok_or_eyre("could not determine internal storage directory")?;
        directories.data_local_dir().to_path_buf()
    };

    tokio::fs::create_dir_all(&oracle_dir).await?;

    let keypath = oracle_dir.join("oracle_key.pkcs8.hex");
    Ok(keypath)
}

async fn keypair(homedir: Option<&std::path::Path>) -> color_eyre::Result<KeyPair> {
    let keypath = keypath(homedir).await?;
    let keyhex = tokio::fs::read_to_string(&keypath).await.map_err(|_| {
        color_eyre::eyre::eyre!("could not read oracle keypair at: {}", keypath.display())
    })?;
    let keybytes = hex::decode(keyhex.trim()).map_err(|_| {
        color_eyre::eyre::eyre!(
            "could not decode oracle keypair hex at: {}",
            keypath.display()
        )
    })?;
    let keypair = KeyPair::decode(&keybytes).map_err(|_| {
        color_eyre::eyre::eyre!("could not parse oracle keypair at: {}", keypath.display())
    })?;
    Ok(keypair)
}
