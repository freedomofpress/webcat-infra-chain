mod commands;
mod light_block;
mod verification;

use clap::Parser;
use color_eyre::Result;
use reqwest::Url;
use tendermint_rpc::HttpClient;

#[derive(Parser)]
#[command(name = "felidae-publish")]
#[command(about = "Demo LCV logic")]
struct Args {
    /// Node RPC URL (e.g., http://localhost:26657)
    #[arg(default_value = "http://localhost:26657")]
    node: String,

    /// ABCI query server URL (e.g., http://localhost:80)
    #[arg(long, default_value = "http://localhost:80")]
    query_url: String,

    #[command(subcommand)]
    command: Command,
}

#[derive(clap::Subcommand)]
enum Command {
    /// Print `LightBlock`s as JSON
    Print {
        /// Block height to fetch (if not provided, uses latest)
        #[arg(long)]
        height: Option<u64>,
    },
    /// Verify `LightBlock`s and print the apphash
    Verify {
        /// Block height to fetch (if not provided, uses latest)
        #[arg(long)]
        height: Option<u64>,
    },
    /// Reconstruct the JMT from latest canonical leaves, verify the merkle proof up
    /// to the corresponding `LightBlock` `AppHash`
    Reconstruct,
}

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;
    let args = Args::parse();

    // Create Tendermint RPC client
    let rpc_url =
        Url::parse(&args.node).map_err(|e| color_eyre::eyre::eyre!("invalid RPC URL: {}", e))?;
    let rpc_url = tendermint_rpc::Url::try_from(rpc_url)
        .map_err(|e| color_eyre::eyre::eyre!("invalid RPC URL: {}", e))?;
    let client = HttpClient::new(rpc_url)
        .map_err(|e| color_eyre::eyre::eyre!("failed to create RPC client: {}", e))?;

    match args.command {
        Command::Print { height } => commands::print(&client, height).await?,
        Command::Verify { height } => commands::verify(&client, height).await?,
        Command::Reconstruct => commands::reconstruct(&client, &args.query_url).await?,
    }

    Ok(())
}
