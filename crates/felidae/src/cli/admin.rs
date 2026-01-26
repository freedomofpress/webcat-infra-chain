use color_eyre::eyre::OptionExt;
use felidae_types::KeyPair;
use reqwest::Url;

use super::Run;

#[derive(clap::Subcommand)]
pub enum Admin {
    /// Initialize a new admin for the network.
    ///
    /// This generates a new admin keypair and stores it locally. It does not register
    /// the admin with the network; that must be done via a reconfiguration transaction.
    Init(Init),
    /// Display the public identity of the admin, if initialized.
    Identity(Identity),
    /// Output a template configuration file for reconfiguration.
    Template(Template),
    /// Submit a reconfiguration transaction to the network.
    ///
    /// This requires that the admin has already been initialized.
    Config(Config),
}

impl Run for Admin {
    async fn run(self) -> Result<(), color_eyre::Report> {
        match self {
            Self::Init(cmd) => cmd.run().await,
            Self::Identity(cmd) => cmd.run().await,
            Self::Template(cmd) => cmd.run().await,
            Self::Config(cmd) => cmd.run().await,
        }
    }
}

#[derive(clap::Args)]
pub struct Init {
    /// Home directory for storing admin keys (defaults to platform-specific directory).
    #[clap(long)]
    pub homedir: Option<std::path::PathBuf>,
}

impl Run for Init {
    async fn run(self) -> Result<(), color_eyre::Report> {
        let keypath = keypath(self.homedir.as_deref()).await?;
        if keypath.exists() {
            return Err(color_eyre::eyre::eyre!(
                "admin keypair already exists at: {}",
                keypath.display()
            ));
        }

        let keypair = hex::encode(KeyPair::generate().encode()?);
        println!("Writing new admin keypair to: {}", keypath.display());
        tokio::fs::write(keypath, keypair).await?;

        Ok(())
    }
}

#[derive(clap::Args)]
pub struct Identity {
    /// Home directory for storing admin keys (defaults to platform-specific directory).
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
pub struct Config {
    /// Path to the configuration file.
    pub path: std::path::PathBuf,
    /// Node to which to send the configuration update.
    #[clap(long, short, default_value = "http://localhost:26657")]
    pub node: Url,
    /// Chain ID of the target chain.
    #[clap(long, short)]
    pub chain: String,
    /// Timeout duration for the reconfiguration to be valid.
    #[clap(long, short = 't', default_value = "10s")]
    pub signature_timeout: humantime::Duration,
    /// Home directory for storing admin keys (defaults to platform-specific directory).
    #[clap(long)]
    pub homedir: Option<std::path::PathBuf>,
}

impl Run for Config {
    async fn run(self) -> Result<(), color_eyre::Report> {
        // Load the admin keypair:
        let keypair = keypair(self.homedir.as_deref()).await?;

        // Read and parse the configuration file:
        let config_bytes = tokio::fs::read(&self.path).await.map_err(|_| {
            color_eyre::eyre::eyre!(
                "could not read configuration file at: {}",
                self.path.display()
            )
        })?;
        let config: felidae_types::transaction::Config = serde_json::from_slice(&config_bytes)
            .map_err(|_| {
                color_eyre::eyre::eyre!(
                    "could not parse configuration file at: {}",
                    self.path.display()
                )
            })?;

        // Create the reconfiguration transaction:
        let tx = felidae_admin::reconfigure(
            &keypair.encode()?,
            self.chain,
            self.signature_timeout.into(),
            config,
        )?;

        // Submit the transaction to the node:
        let response_text = reqwest::Client::new()
            .get(self.node.join("/broadcast_tx_sync")?)
            .query(&[("tx", format!("0x{}", tx))])
            .send()
            .await?
            .error_for_status()?
            .text()
            .await?;

        // Parse the CometBFT JSON-RPC response and check for transaction rejection:
        let response: BroadcastTxResponse = serde_json::from_str(&response_text)
            .map_err(|e| color_eyre::eyre::eyre!("failed to parse node response: {}", e))?;

        if response.result.code != 0 {
            return Err(color_eyre::eyre::eyre!(
                "transaction rejected: {}",
                response.result.log
            ));
        }

        info!(
            tx = %tx,
            hash = %response.result.hash,
            "transaction accepted"
        );

        Ok(())
    }
}

/// CometBFT JSON-RPC response for broadcast_tx_sync.
#[derive(serde::Deserialize)]
struct BroadcastTxResponse {
    result: BroadcastTxResult,
}

#[derive(serde::Deserialize)]
struct BroadcastTxResult {
    code: u32,
    log: String,
    hash: String,
}

#[derive(clap::Args)]
pub struct Template {
    /// Automatically read existing admin and oracle keys from their default paths.
    #[clap(long, alias = "auto")]
    pub read_local_keys: bool,
    /// Path to the admin keypair file (defaults to platform-specific directory if --auto is set).
    #[clap(long)]
    pub admin_pubkey: Option<std::path::PathBuf>,
    /// Path to the oracle keypair file (defaults to platform-specific directory if --auto is set).
    #[clap(long)]
    pub oracle_pubkey: Option<std::path::PathBuf>,
    /// Home directory for reading keys when --read-local-keys is set.
    ///
    /// When specified, both admin and oracle keys are expected to be in this directory
    /// (as admin_key.pkcs8.hex and oracle_key.pkcs8.hex respectively).
    #[clap(long)]
    pub homedir: Option<std::path::PathBuf>,
}

impl Run for Template {
    async fn run(self) -> Result<(), color_eyre::Report> {
        use felidae_types::transaction::{Admin, Oracle};
        use prost::bytes::Bytes;

        let mut template = felidae_types::transaction::Config::template(0);

        // Determine the admin key path
        let admin_keypath = if let Some(path) = self.admin_pubkey {
            Some(path)
        } else if self.read_local_keys {
            Some(keypath(self.homedir.as_deref()).await?)
        } else {
            None
        };

        // Determine the oracle key path
        let oracle_keypath_result = if let Some(path) = self.oracle_pubkey {
            Some(path)
        } else if self.read_local_keys {
            Some(oracle_keypath(self.homedir.as_deref()).await?)
        } else {
            None
        };

        // Load admin public key if path is available
        if let Some(path) = admin_keypath {
            match load_pubkey_from_keypair(&path).await {
                Ok(pubkey) => {
                    template.admins.authorized = vec![Admin {
                        identity: Bytes::from(pubkey),
                    }];
                }
                Err(e) => {
                    eprintln!(
                        "warning: could not load admin key from {}: {}",
                        path.display(),
                        e
                    );
                }
            }
        }

        // Load oracle public key if path is available
        if let Some(path) = oracle_keypath_result {
            match load_pubkey_from_keypair(&path).await {
                Ok(pubkey) => {
                    template.oracles.authorized = vec![Oracle {
                        identity: Bytes::from(pubkey),
                        endpoint: "127.0.0.1".to_string(),
                    }];
                }
                Err(e) => {
                    eprintln!(
                        "warning: could not load oracle key from {}: {}",
                        path.display(),
                        e
                    );
                }
            }
        }

        let json = serde_json::to_string_pretty(&template)?;
        println!("{}", json);
        Ok(())
    }
}

async fn keypath(homedir: Option<&std::path::Path>) -> color_eyre::Result<std::path::PathBuf> {
    let admin_dir = if let Some(homedir) = homedir {
        homedir.to_path_buf()
    } else {
        let directories = directories::ProjectDirs::from("press", "freedom", "felidae-admin")
            .ok_or_eyre("could not determine internal storage directory")?;
        directories.data_local_dir().to_path_buf()
    };

    tokio::fs::create_dir_all(&admin_dir).await?;

    let keypath = admin_dir.join("admin_key.pkcs8.hex");
    Ok(keypath)
}

async fn keypair(homedir: Option<&std::path::Path>) -> color_eyre::Result<KeyPair> {
    let keypath = keypath(homedir).await?;
    let keyhex = tokio::fs::read_to_string(&keypath).await.map_err(|_| {
        color_eyre::eyre::eyre!("could not read admin keypair at: {}", keypath.display())
    })?;
    let keybytes = hex::decode(keyhex.trim()).map_err(|_| {
        color_eyre::eyre::eyre!(
            "could not decode admin keypair hex at: {}",
            keypath.display()
        )
    })?;
    let keypair = KeyPair::decode(&keybytes).map_err(|_| {
        color_eyre::eyre::eyre!("could not parse admin keypair at: {}", keypath.display())
    })?;
    Ok(keypair)
}

/// Get the default oracle key path (mirrors the logic in oracle.rs).
async fn oracle_keypath(
    homedir: Option<&std::path::Path>,
) -> color_eyre::Result<std::path::PathBuf> {
    let oracle_dir = if let Some(homedir) = homedir {
        homedir.to_path_buf()
    } else {
        let directories = directories::ProjectDirs::from("press", "freedom", "felidae-oracle")
            .ok_or_eyre("could not determine internal storage directory")?;
        directories.data_local_dir().to_path_buf()
    };

    let keypath = oracle_dir.join("oracle_key.pkcs8.hex");
    Ok(keypath)
}

/// Load a public key from a keypair file at the given path.
async fn load_pubkey_from_keypair(path: &std::path::Path) -> color_eyre::Result<Vec<u8>> {
    let keyhex = tokio::fs::read_to_string(path)
        .await
        .map_err(|_| color_eyre::eyre::eyre!("could not read keypair at: {}", path.display()))?;
    let keybytes = hex::decode(keyhex.trim()).map_err(|_| {
        color_eyre::eyre::eyre!("could not decode keypair hex at: {}", path.display())
    })?;
    let keypair = KeyPair::decode(&keybytes)
        .map_err(|_| color_eyre::eyre::eyre!("could not parse keypair at: {}", path.display()))?;
    Ok(keypair.public_key())
}
