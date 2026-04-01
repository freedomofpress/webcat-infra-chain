//! Integration tests for node-joining logic.
//!
//! Verifies that a new full node can bootstrap from an existing network
//! using `join_network()`, sync to the current block height, and serve
//! queries via `felidae query chain-info`.

use std::time::Duration;

use crate::binaries::find_binaries;
use crate::constants::{network_startup_timeout, poll_interval};
use crate::harness::TestNetwork;
use crate::helpers::{poll_until, query_chain_info};

/// Bootstraps a new full node onto a running devnet and verifies it syncs.
///
/// # Test Flow
///
/// 1. Create a local devnet with 3 validators.
/// 2. Wait for the network to produce blocks, then record the block height
///    as the sync target.
/// 3. Use `TestNetwork::join_and_start()` which internally calls
///    `join_network()` with genesis from node 0 and peer discovery from RPC.
/// 4. Poll `felidae query chain-info --json` on the new node until its
///    block height reaches the target.
#[tokio::test]
#[cfg(feature = "integration")]
async fn test_join_network_syncs_to_target_height() -> color_eyre::Result<()> {
    let (cometbft_bin, felidae_bin) = find_binaries()?;

    let mut network = TestNetwork::create(3).await?;
    network.start(
        cometbft_bin.to_str().unwrap(),
        felidae_bin.to_str().unwrap(),
    )?;
    network.wait_ready(network_startup_timeout()).await?;

    // Let the network advance, then record target height
    tokio::time::sleep(Duration::from_secs(5)).await;

    let target_height = query_chain_info(&felidae_bin, &network.query_url())?.block_height;
    eprintln!("[test] target block height: {target_height}");
    assert!(target_height >= 2, "network should have produced blocks");

    // Join and start a new full node
    let node = network
        .join_and_start(
            cometbft_bin.to_str().unwrap(),
            felidae_bin.to_str().unwrap(),
            "test-fullnode",
        )
        .await?;

    let joined_query_url = format!("http://{}:{}", node.bind_address, node.ports.felidae_query);
    eprintln!(
        "[test] joined node: rpc={}, p2p={}, abci={}, query={}",
        node.ports.cometbft_rpc,
        node.ports.cometbft_p2p,
        node.ports.felidae_abci,
        node.ports.felidae_query,
    );

    // Poll until the joined node reaches the target height
    poll_until(
        Duration::from_secs(60),
        poll_interval(),
        &format!("joined node syncs to height {target_height}"),
        || {
            match query_chain_info(&felidae_bin, &joined_query_url) {
                Ok(info) => {
                    eprintln!(
                        "[test] joined node height: {} (target: {target_height})",
                        info.block_height
                    );
                    Ok(info.block_height >= target_height)
                }
                Err(_) => Ok(false),
            }
        },
    )
    .await?;

    eprintln!("[test] joined node synced to target height {target_height}");
    Ok(())
}
