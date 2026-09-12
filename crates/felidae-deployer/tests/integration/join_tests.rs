//! Integration tests for node-joining logic.
//!
//! Verifies that a new full node can bootstrap from an existing network
//! using `join_network()`, sync to the current block height, and serve
//! queries via `felidae query chain-info`.

use std::time::Duration;

use felidae_deployer::join::{GenesisSource, JoinConfig, PeerSource};
use felidae_types::response::ChainInfo;

use crate::binaries::find_binaries;
use crate::constants::{network_startup_timeout, poll_interval};
use crate::harness::TestNetwork;
use crate::helpers::{poll_until_async, query_config, run_query_command};

/// Queries `felidae query chain-info --json` and parses the result.
fn query_chain_info(
    felidae_bin: &std::path::Path,
    query_url: &str,
) -> color_eyre::Result<ChainInfo> {
    let output = run_query_command(felidae_bin, "chain-info", query_url, &["--json"])?;
    let info: ChainInfo = serde_json::from_str(&output)?;
    Ok(info)
}

/// Bootstraps a new full node onto a running devnet and verifies it syncs.
///
/// # Test Flow
///
/// 1. Create a local devnet with 3 validators.
/// 2. Wait for the network to produce blocks, then record the block height
///    as the sync target.
/// 3. Run `join_network()` with genesis from the validator's local file and
///    peers auto-discovered from the CometBFT RPC.
/// 4. Start CometBFT and felidae processes for the joined node.
/// 5. Poll `felidae query chain-info --json` on the new node until its
///    block height reaches the target.
/// 6. Assert the node eventually syncs.
#[tokio::test]
#[cfg(feature = "integration")]
async fn test_join_network_syncs_to_target_height() -> color_eyre::Result<()> {
    // ── Step 0: locate binaries ──────────────────────────────────────────
    let (cometbft_bin, felidae_bin) = find_binaries()?;

    // ── Step 1: create and start devnet ──────────────────────────────────
    let mut network = TestNetwork::create(3).await?;
    network.start(
        cometbft_bin.to_str().unwrap(),
        felidae_bin.to_str().unwrap(),
    )?;
    network.wait_ready(network_startup_timeout()).await?;

    // ── Step 2: let the network advance, then record target height ──────
    tokio::time::sleep(Duration::from_secs(5)).await;

    let target_height = query_chain_info(&felidae_bin, &network.query_url())?.block_height;
    eprintln!("[test] target block height: {target_height}");
    assert!(target_height >= 2, "network should have produced blocks");

    // ── Step 3: join-network ─────────────────────────────────────────────
    // Use the authoritative genesis file from a validator node, and
    // auto-discover peers from the CometBFT RPC.
    // Join under the network's tree, so the full node's home is retained with it.
    let join_path = network.directory.join("fullnode");

    let genesis_file = network.network.nodes[0].genesis_path();
    let rpc_url: url::Url = network.rpc_url().parse()?;

    let config = JoinConfig {
        genesis_source: GenesisSource::File(genesis_file),
        peer_source: PeerSource::CometbftRpc(rpc_url),
        directory: join_path,
        find_free_ports: true,
        node_name: "test-fullnode".to_string(),
    };

    let node = felidae_deployer::join::join_network(config).await?;

    let joined_query_url = format!("http://{}:{}", node.bind_address, node.ports.felidae_query);
    eprintln!(
        "[test] joined node config written: rpc={}, p2p={}, abci={}, query={}",
        node.ports.cometbft_rpc,
        node.ports.cometbft_p2p,
        node.ports.felidae_abci,
        node.ports.felidae_query,
    );

    // ── Step 4: start the joined node ────────────────────────────────────
    // Through the harness, so its processes are logged, liveness-tracked, and
    // reaped.
    network.spawn_processes(
        &node,
        cometbft_bin.to_str().unwrap(),
        felidae_bin.to_str().unwrap(),
    )?;

    // ── Step 5: poll joined node until it reaches the target height ──────
    poll_until_async(
        Duration::from_secs(60),
        poll_interval(),
        "joined node syncs to target height",
        || async {
            let height = query_chain_info(&felidae_bin, &joined_query_url)?.block_height;
            eprintln!("[test] joined node height: {height} (target: {target_height})");
            Ok(height >= target_height)
        },
    )
    .await?;

    // ── Step 6: assert ───────────────────────────────────────────────────
    // Compare the Config value returned by the newly-joined node to one
    // reported by a genesis validator. Slightly more substantive than a simple
    // height check.
    let expected_config = query_config(&felidae_bin, &network.query_url())?;
    let joined_config = query_config(&felidae_bin, &joined_query_url)?;
    assert_eq!(
        joined_config, expected_config,
        "joined node's config should match the network's config"
    );
    eprintln!("[test] joined node state verified: config matches network");

    Ok(())
}
