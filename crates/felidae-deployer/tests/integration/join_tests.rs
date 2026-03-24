//! Integration tests for node-joining logic.
//!
//! Verifies that a new full node can bootstrap from an existing network
//! using `join_network()`, sync to the current block height, and serve
//! queries via `felidae query chain-info`.

use std::process::{Child, Command, Stdio};
use std::time::Duration;

use felidae_deployer::join::{GenesisSource, JoinConfig, PeerSource};
use felidae_types::response::ChainInfo;

use crate::binaries::find_binaries;
use crate::constants::network_startup_timeout;
use crate::harness::TestNetwork;
use crate::helpers::run_query_command;

/// Manages a joined node's processes so they are cleaned up on drop.
struct JoinedNode {
    cometbft: Child,
    felidae: Child,
}

impl Drop for JoinedNode {
    fn drop(&mut self) {
        let _ = self.cometbft.kill();
        let _ = self.cometbft.wait();
        let _ = self.felidae.kill();
        let _ = self.felidae.wait();
    }
}

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
    let join_dir = tempfile::tempdir()?;
    let join_path = join_dir.path().join("fullnode");

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
    let cometbft_child = Command::new(cometbft_bin.to_str().unwrap())
        .args(["start", "--home", &node.cometbft_home().to_string_lossy()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;

    let felidae_child = Command::new(felidae_bin.to_str().unwrap())
        .args([
            "start",
            "--abci-bind",
            &node.abci_address(),
            "--query-bind",
            &format!("{}:{}", node.bind_address, node.ports.felidae_query),
            "--homedir",
            &node.felidae_home().to_string_lossy(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;

    let _joined = JoinedNode {
        cometbft: cometbft_child,
        felidae: felidae_child,
    };

    // ── Step 5: poll joined node until it reaches the target height ──────
    let poll_timeout = Duration::from_secs(60);
    let poll_interval = Duration::from_secs(2);
    let start = std::time::Instant::now();

    loop {
        if start.elapsed() > poll_timeout {
            return Err(color_eyre::eyre::eyre!(
                "joined node did not sync to height {target_height} within {poll_timeout:?}"
            ));
        }

        match query_chain_info(&felidae_bin, &joined_query_url) {
            Ok(info) => {
                eprintln!(
                    "[test] joined node height: {} (target: {target_height})",
                    info.block_height
                );
                // ── Step 6: assert ───────────────────────────────────────
                if info.block_height >= target_height {
                    eprintln!(
                        "[test] joined node synced! height={} >= target={}",
                        info.block_height, target_height
                    );
                    return Ok(());
                }
            }
            Err(e) => {
                eprintln!("[test] query not ready yet: {e}");
            }
        }

        tokio::time::sleep(poll_interval).await;
    }
}
