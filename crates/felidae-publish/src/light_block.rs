use color_eyre::Result;
use serde::Serialize;
use tendermint_rpc::HttpClient;
use tendermint_rpc::client::Client;

/// LightBlock structure: signed_header + validator_set
/// This matches the standard Tendermint `LightBlock` structure but
/// is not exported by the tendermint-rpc crate.
#[derive(Serialize)]
pub struct LightBlock {
    pub signed_header: tendermint::block::signed_header::SignedHeader,
    pub validator_set: tendermint::validator::Set,
}

/// Fetch the latest light block from the node
pub async fn fetch_light_block(
    client: &HttpClient,
) -> Result<(LightBlock, tendermint_rpc::endpoint::status::Response)> {
    // Get the latest height from status
    let status = client.status().await?;
    let latest_height = status.sync_info.latest_block_height;
    fetch_light_block_at_height(client, latest_height.value()).await
}

/// Fetch a light block at a specific height
pub async fn fetch_light_block_at_height(
    client: &HttpClient,
    height: u64,
) -> Result<(LightBlock, tendermint_rpc::endpoint::status::Response)> {
    use tendermint::block::Height;
    use tendermint_rpc::Paging;

    let height =
        Height::try_from(height).map_err(|e| color_eyre::eyre::eyre!("invalid height: {}", e))?;

    // Get status for chain ID
    let status = client.status().await?;

    // Fetch the commit (signed header) for the specified height
    // Retry until the block is committed
    let commit_result = loop {
        match client.commit(height).await {
            Ok(result) => {
                // Successfully got the commit, block is committed
                break result;
            }
            Err(_) => {
                // Block not available yet, wait and retry
                tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
                continue;
            }
        }
    };
    let signed_header = commit_result.signed_header;

    // Fetch validators for the same height
    let validators_result = client.validators(height, Paging::All).await?;
    let all_validators = validators_result.validators;

    // Find the proposer from the header
    let proposer_address = signed_header.header.proposer_address;
    let proposer = all_validators
        .iter()
        .find(|v| v.address == proposer_address)
        .cloned();

    let validator_set = tendermint::validator::Set::new(all_validators, proposer);

    // Construct light block
    let light_block = LightBlock {
        signed_header,
        validator_set,
    };

    Ok((light_block, status))
}
