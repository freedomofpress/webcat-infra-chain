use color_eyre::Result;
use tendermint_rpc::HttpClient;

use crate::light_block::{fetch_light_block, fetch_light_block_at_height};

pub async fn print(
    client: &HttpClient,
    height: Option<u64>,
    timeout: std::time::Duration,
) -> Result<()> {
    let (light_block, _) = if let Some(h) = height {
        fetch_light_block_at_height(client, h, timeout).await?
    } else {
        fetch_light_block(client, timeout).await?
    };
    println!("{}", serde_json::to_string_pretty(&light_block)?);
    Ok(())
}
