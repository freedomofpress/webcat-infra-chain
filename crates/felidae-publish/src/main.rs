use clap::Parser;
use color_eyre::Result;
use reqwest::Url;
use serde::Serialize;
use tendermint_rpc::HttpClient;
use tendermint_rpc::client::Client;

#[derive(Parser)]
#[command(name = "felidae-publish")]
#[command(about = "Fetch and publish the latest light block from a CometBFT node")]
struct Args {
    /// Node RPC URL (e.g., http://localhost:26657)
    #[arg(default_value = "http://localhost:26657")]
    node: String,
}

// LightBlock structure: signed_header + validator_set
// This matches the standard Tendermint LightBlock structure but
// is not exported by the tendermint-rpc crate.
#[derive(Serialize)]
struct LightBlock {
    signed_header: tendermint::block::signed_header::SignedHeader,
    validator_set: tendermint::validator::Set,
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

    // Get the latest height from status
    let status = client.status().await?;
    let latest_height = status.sync_info.latest_block_height;

    // Fetch the latest commit (signed header)
    let commit_result = client.commit(latest_height).await?;
    let signed_header = commit_result.signed_header;
    let height = signed_header.header.height;

    // Fetch validators for the same height
    use tendermint_rpc::Paging;
    let validators_result = client.validators(height, Paging::All).await?;
    let all_validators = validators_result.validators;

    // Find the proposer from the header
    let proposer_address = signed_header.header.proposer_address;
    let proposer = all_validators
        .iter()
        .find(|v| v.address == proposer_address)
        .cloned();

    let validator_set = tendermint::validator::Set::new(all_validators, proposer);

    // Construct and output light block
    let light_block = LightBlock {
        signed_header,
        validator_set,
    };

    println!("{}", serde_json::to_string_pretty(&light_block)?);

    Ok(())
}
