use color_eyre::eyre::OptionExt;
use felidae_types::{FQDN, KeyPair};
use reqwest::StatusCode;
use reqwest::Url;
use serde::Deserialize;
use serde_with::{DisplayFromStr, base64::Base64, serde_as};

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
        // TODO: This implementation is made of ad-hoc bits to parse the necessary data from the
        // node, instead of using an actual Tendermint client library or even a JSON-RPC library.
        // This works, but it would be better to have a more robust implementation.

        // Load the oracle keypair:
        let keypair = keypair(self.homedir.as_deref()).await?;

        // We reuse this client:
        let client = reqwest::Client::new();

        // Fetch the hash from the well-known endpoint of the domain/zone:
        let enrollment_string = match client
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

        #[derive(Deserialize)]
        pub struct Result<R> {
            result: R,
        }
        #[derive(Deserialize)]
        struct Response<R> {
            response: R,
        }

        // Pull the app hash and block height from the node, with expected format:
        // {"jsonrpc":"2.0","id":-1,"result":{"response":{"data":"felidae","version":"0.1.0","last_block_height":"91","last_block_app_hash":"9aQxnXPb8V0SFV/u0xrPAH3XhMEALBt72QU6G8wilQk="}}}
        #[serde_as]
        #[derive(Deserialize)]
        struct LastBlock {
            #[serde_as(as = "DisplayFromStr")]
            last_block_height: u64,
            #[serde_as(as = "Base64")]
            last_block_app_hash: Vec<u8>,
        }
        let LastBlock {
            last_block_height,
            last_block_app_hash,
        } = client
            .get(self.node.join("/abci_info")?)
            .send()
            .await?
            .error_for_status()?
            .json::<Result<Response<LastBlock>>>()
            .await?
            .result
            .response;
        let last_block_app_hash = hex::encode(last_block_app_hash);

        info!(
            last_block_height,
            last_block_app_hash, "fetched last block info"
        );

        // If the chain ID was not specified, pull it from the node:
        let chain_id = if let Some(chain_id) = self.chain {
            chain_id
        } else {
            #[derive(Deserialize)]
            struct Genesis {
                genesis: GenesisContents,
            }
            #[derive(Deserialize)]
            struct GenesisContents {
                chain_id: String,
            }
            let chain_id = client
                .get(self.node.join("/genesis")?)
                .send()
                .await?
                .error_for_status()?
                .json::<Result<Genesis>>()
                .await?
                .result
                .genesis
                .chain_id;
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

        // Wait for 5 seconds to let the block stamp get finalized:
        // TODO: instead, get the blockstamp of the *previous* block!
        info!("waiting 5 seconds to allow blockstamp to finalize...");
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;

        // Submit the transaction to the node:
        let result = client
            .get(self.node.join("/broadcast_tx_sync")?)
            .query(&[("tx", format!("0x{}", tx))])
            .send()
            .await?
            .error_for_status()?
            .text()
            .await?;

        info!(tx = %tx, result = %result, "submitted transaction");

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
