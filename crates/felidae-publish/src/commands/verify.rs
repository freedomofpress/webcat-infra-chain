use color_eyre::Result;
use tendermint_rpc::HttpClient;

use crate::light_block::{fetch_light_block, fetch_light_block_at_height};
use crate::verification::verify_light_block;

pub async fn verify(client: &HttpClient, height: Option<u64>) -> Result<()> {
    let (light_block, status) = if let Some(h) = height {
        fetch_light_block_at_height(client, h).await?
    } else {
        fetch_light_block(client).await?
    };
    let chain_id = status.node_info.network.to_string();
    verify_light_block(
        &light_block.signed_header,
        &light_block.validator_set,
        &chain_id,
    )?;
    let apphash = light_block.signed_header.header.app_hash;
    println!("LightBlock verified successfully!");
    println!("AppHash: {}", hex::encode(apphash.as_bytes()));
    Ok(())
}
