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
pub struct Template {}

impl Run for Template {
    async fn run(self) -> Result<(), color_eyre::Report> {
        let template = felidae_types::transaction::Config::template(0);
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
