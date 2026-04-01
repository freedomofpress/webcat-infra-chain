//! Admin reconfiguration integration tests.
//!
//! This module contains tests for the admin reconfiguration system, including
//! config updates, quorum enforcement, and BFT voting behavior.

use felidae_types::transaction::{Config, OracleConfig, Validator};
use std::time::Duration;
use tendermint_rpc::{Client, HttpClient};

use crate::binaries::find_binaries;
use crate::constants::{
    admin_reconfig_tx_timeout, consensus_propagation_wait, consensus_propagation_wait_long,
    inter_tx_delay, network_startup_timeout, poll_interval,
};
use crate::harness::TestNetwork;
use crate::helpers::{
    generate_ed25519_pubkey, poll_until, poll_until_async, query_admin_pending, query_admin_votes,
    query_cometbft_validators, query_config, read_genesis_validator_pubkeys, submit_admin_reconfig,
};

/// Verifies that admin reconfiguration transactions work correctly.
///
/// # Business Logic Tested
///
/// This test validates the admin reconfiguration flow:
///
/// 1. **Config Retrieval**: Query the current chain configuration
/// 2. **Config Modification**: Prepare a new configuration with incremented version
/// 3. **Admin Signing**: Sign the reconfiguration with an authorized admin key
/// 4. **Vote Submission**: Submit the signed reconfiguration transaction
/// 5. **Config Update**: Verify the new configuration takes effect
///
/// # Admin vs Oracle
///
/// Admin reconfiguration uses the same voting infrastructure as oracle observations:
/// - Both use VoteQueue for BFT consensus
/// - Both require quorum of authorized parties
/// - Both have configurable delays
///
/// Key differences:
/// - Admin votes on `Empty` key (singleton config)
/// - Oracle votes on domain keys (many-to-many)
/// - Admin changes affect the entire chain configuration
/// - Oracle changes affect individual domain mappings
#[tokio::test]
#[cfg(feature = "integration")]
async fn test_admin_reconfiguration() -> color_eyre::Result<()> {
    let (cometbft_bin, felidae_bin) = find_binaries()?;

    let mut network = TestNetwork::create(3).await?;
    network.start(
        cometbft_bin.to_str().unwrap(),
        felidae_bin.to_str().unwrap(),
    )?;
    network.wait_ready(network_startup_timeout()).await?;

    let rpc_client = HttpClient::new(network.rpc_url().as_str())?;

    // Get the current configuration via CLI
    let current_config = query_config(&felidae_bin, &network.query_url())?;
    eprintln!("[test] current config version: {}", current_config.version);

    // Create a new configuration with incremented version
    let new_config = Config {
        version: current_config.version + 1,
        admins: current_config.admins.clone(),
        oracles: OracleConfig {
            // Change the observation_timeout as a visible modification
            observation_timeout: Duration::from_secs(600), // Was 300
            ..current_config.oracles.clone()
        },
        onion: current_config.onion.clone(),
        validators: current_config.validators.clone(),
    };

    // Submit reconfiguration from all 3 admins to reach quorum
    for i in 0..3 {
        let admin_key = network.read_admin_key(i)?;

        // Create the reconfiguration transaction
        let tx_hex = felidae_admin::reconfigure(
            &admin_key,
            crate::constants::TEST_CHAIN_ID.to_string(),
            admin_reconfig_tx_timeout(),
            None, // Use default grace period
            new_config.clone(),
        )?;

        // Submit the transaction
        let tx_bytes = hex::decode(&tx_hex)?;
        let result = rpc_client.broadcast_tx_commit(tx_bytes).await?;

        eprintln!(
            "[test] admin {} reconfig tx: code={:?}, log={}",
            i, result.tx_result.code, result.tx_result.log
        );

        if !result.tx_result.code.is_ok() {
            // First admin might succeed, subsequent may conflict - that's okay
            eprintln!(
                "[test] admin {} tx result code not ok: {}",
                i, result.tx_result.log
            );
        }

        tokio::time::sleep(inter_tx_delay()).await;
    }

    // Poll for the config change to take effect (admin delay is 0s in test config)
    let expected_version = current_config.version;
    poll_until(
        consensus_propagation_wait_long(),
        poll_interval(),
        "config version incremented",
        || Ok(query_config(&felidae_bin, &network.query_url())?.version > expected_version),
    )
    .await?;

    // Verify the configuration was updated via CLI
    let updated_config = query_config(&felidae_bin, &network.query_url())?;
    eprintln!("[test] updated config version: {}", updated_config.version);

    // The version should have incremented
    assert!(
        updated_config.version > current_config.version,
        "config version should have incremented (was {}, now {})",
        current_config.version,
        updated_config.version
    );

    Ok(())
}

/// Verifies that admin reconfiguration requires a quorum of votes.
///
/// # Business Logic Tested
///
/// This test validates the BFT voting requirement for admin changes:
///
/// 1. **Quorum Enforcement**: Configuration changes require 2f+1 votes (for n=3, quorum=3)
/// 2. **Vote Accumulation**: Partial votes are stored but do not trigger changes
/// 3. **No Premature Changes**: Config remains unchanged until quorum is reached
///
/// # Byzantine Fault Tolerance
///
/// For a 3-validator network with quorum=3:
/// - 3/3 votes → config IS updated (unanimous agreement)
/// - 2/3 votes → config is NOT updated (below quorum)
/// - 1/3 votes → config is NOT updated (below quorum)
#[tokio::test]
#[cfg(feature = "integration")]
async fn test_admin_reconfig_minority_no_update() -> color_eyre::Result<()> {
    let (cometbft_bin, felidae_bin) = find_binaries()?;

    let mut network = TestNetwork::create(3).await?;
    network.start(
        cometbft_bin.to_str().unwrap(),
        felidae_bin.to_str().unwrap(),
    )?;
    network.wait_ready(network_startup_timeout()).await?;

    let rpc_client = HttpClient::new(network.rpc_url().as_str())?;

    // Get the current configuration via CLI
    let current_config = query_config(&felidae_bin, &network.query_url())?;
    eprintln!(
        "[test] current config version: {}, quorum: {}",
        current_config.version, current_config.admins.voting.quorum.0
    );

    // Create a new configuration with incremented version
    let new_config = Config {
        version: current_config.version + 1,
        admins: current_config.admins.clone(),
        oracles: OracleConfig {
            // Change the observation_timeout as a visible modification
            observation_timeout: Duration::from_secs(900), // Different from other tests
            ..current_config.oracles.clone()
        },
        onion: current_config.onion.clone(),
        validators: current_config.validators.clone(),
    };

    // Submit reconfiguration from only 2 of 3 admins (below quorum of 3)
    eprintln!("[test] submitting reconfig from only 2 of 3 admins (below quorum)");
    for i in 0..2 {
        let admin_key = network.read_admin_key(i)?;

        let tx_hex = felidae_admin::reconfigure(
            &admin_key,
            crate::constants::TEST_CHAIN_ID.to_string(),
            admin_reconfig_tx_timeout(),
            None, // Use default grace period
            new_config.clone(),
        )?;

        let tx_bytes = hex::decode(&tx_hex)?;
        let result = rpc_client.broadcast_tx_commit(tx_bytes).await?;

        eprintln!(
            "[test] admin {} reconfig tx: code={:?}, log={}",
            i, result.tx_result.code, result.tx_result.log
        );

        tokio::time::sleep(inter_tx_delay()).await;
    }

    // Wait enough time for any potential processing
    tokio::time::sleep(consensus_propagation_wait()).await;

    // Verify votes are accumulated but not applied via CLI
    let admin_votes = query_admin_votes(&felidae_bin, &network.query_url())?;
    eprintln!("[test] admin votes in queue: {}", admin_votes.len());

    // Should have 2 votes in the queue (not consumed into pending)
    assert_eq!(
        admin_votes.len(),
        2,
        "expected 2 admin votes in queue (below quorum), got {}",
        admin_votes.len()
    );

    // Verify no pending config changes via CLI
    let admin_pending = query_admin_pending(&felidae_bin, &network.query_url())?;
    eprintln!("[test] admin pending changes: {}", admin_pending.len());

    assert!(
        admin_pending.is_empty(),
        "expected no pending config changes (quorum not reached), got {}",
        admin_pending.len()
    );

    // Verify the configuration was NOT updated via CLI
    let unchanged_config = query_config(&felidae_bin, &network.query_url())?;
    eprintln!(
        "[test] config version after minority votes: {}",
        unchanged_config.version
    );

    // Version should NOT have changed
    assert_eq!(
        unchanged_config.version, current_config.version,
        "config version should NOT change without quorum (expected {}, got {})",
        current_config.version, unchanged_config.version
    );

    // observation_timeout should still be the original value (300s)
    assert_eq!(
        unchanged_config.oracles.observation_timeout, current_config.oracles.observation_timeout,
        "observation_timeout should NOT change without quorum"
    );

    eprintln!("[test] confirmed: minority admin votes do not update config");

    Ok(())
}

/// Verifies that a full quorum of admin votes successfully updates the config.
///
/// # Business Logic Tested
///
/// This test complements `test_admin_reconfig_minority_no_update` by showing
/// that when quorum IS reached, the configuration IS updated:
///
/// 1. **Quorum Detection**: When 3/3 admins vote for the same config, quorum is reached
/// 2. **Config Promotion**: After the delay period, the new config becomes active
/// 3. **State Verification**: Both version number and config values are updated
#[tokio::test]
#[cfg(feature = "integration")]
async fn test_admin_reconfig_full_quorum_success() -> color_eyre::Result<()> {
    let (cometbft_bin, felidae_bin) = find_binaries()?;

    let mut network = TestNetwork::create(3).await?;
    network.start(
        cometbft_bin.to_str().unwrap(),
        felidae_bin.to_str().unwrap(),
    )?;
    network.wait_ready(network_startup_timeout()).await?;

    let rpc_client = HttpClient::new(network.rpc_url().as_str())?;

    // Get the current configuration via CLI
    let current_config = query_config(&felidae_bin, &network.query_url())?;
    eprintln!(
        "[test] current config version: {}, quorum: {}",
        current_config.version, current_config.admins.voting.quorum.0
    );

    // Create a new configuration with incremented version and visible change
    let new_config = Config {
        version: current_config.version + 1,
        admins: current_config.admins.clone(),
        oracles: OracleConfig {
            // Change observation_timeout from 300s to 600s as a visible modification
            observation_timeout: Duration::from_secs(600),
            ..current_config.oracles.clone()
        },
        onion: current_config.onion.clone(),
        validators: current_config.validators.clone(),
    };

    // Submit reconfiguration from ALL 3 admins (meeting quorum)
    eprintln!("[test] submitting reconfig from all 3 admins (meeting quorum)");
    for i in 0..3 {
        let admin_key = network.read_admin_key(i)?;

        let tx_hex = felidae_admin::reconfigure(
            &admin_key,
            crate::constants::TEST_CHAIN_ID.to_string(),
            admin_reconfig_tx_timeout(),
            None, // Use default grace period
            new_config.clone(),
        )?;

        let tx_bytes = hex::decode(&tx_hex)?;
        let result = rpc_client.broadcast_tx_commit(tx_bytes).await?;

        eprintln!(
            "[test] admin {} reconfig tx: code={:?}, log={}",
            i, result.tx_result.code, result.tx_result.log
        );

        tokio::time::sleep(inter_tx_delay()).await;
    }

    // Poll for the config change to take effect (admin delay is 0s in test config)
    let target_version = current_config.version + 1;
    poll_until(
        consensus_propagation_wait_long(),
        poll_interval(),
        "config version updated after full quorum",
        || Ok(query_config(&felidae_bin, &network.query_url())?.version >= target_version),
    )
    .await?;

    // Verify votes were consumed (should be empty after quorum) via CLI
    let admin_votes = query_admin_votes(&felidae_bin, &network.query_url())?;
    eprintln!("[test] admin votes after quorum: {}", admin_votes.len());

    // Votes should have been consumed when quorum was reached
    assert!(
        admin_votes.is_empty(),
        "admin votes should be consumed after quorum, got {}",
        admin_votes.len()
    );

    // Verify the configuration WAS updated via CLI
    let updated_config = query_config(&felidae_bin, &network.query_url())?;
    eprintln!(
        "[test] updated config version: {}, observation_timeout: {:?}",
        updated_config.version, updated_config.oracles.observation_timeout
    );

    // Version should have incremented
    assert_eq!(
        updated_config.version,
        current_config.version + 1,
        "config version should increment after quorum (expected {}, got {})",
        current_config.version + 1,
        updated_config.version
    );

    // observation_timeout should be updated to 600s
    assert_eq!(
        updated_config.oracles.observation_timeout,
        Duration::from_secs(600),
        "observation_timeout should be updated to 600s after quorum"
    );

    eprintln!("[test] confirmed: full quorum successfully updates config");

    Ok(())
}

/// Tests adding and removing a validator via admin reconfiguration at the
/// config + CometBFT level using a dummy pubkey (no real backing node).
///
/// This is a fast check that the config propagation path correctly updates
/// both the felidae config and CometBFT's active validator set. For a full
/// end-to-end test with a real node, see `test_validator_onboarding_with_real_node`.
///
/// # Phases
///
/// 0. **Setup**: Start 3-validator network, verify initial state
/// 1. **Add 4th validator**: Submit config with genesis validators + dummy key
/// 2. **Remove 4th validator**: Revert to genesis validators, verify chain continues
#[tokio::test]
#[cfg(feature = "integration")]
async fn test_admin_validator_config_add_remove() -> color_eyre::Result<()> {
    let (cometbft_bin, felidae_bin) = find_binaries()?;

    let mut network = TestNetwork::create(3).await?;
    network.start(
        cometbft_bin.to_str().unwrap(),
        felidae_bin.to_str().unwrap(),
    )?;
    network.wait_ready(network_startup_timeout()).await?;

    let rpc_client = HttpClient::new(network.rpc_url().as_str())?;

    // ── Phase 0: Verify initial state ──

    let initial_config = query_config(&felidae_bin, &network.query_url())?;
    eprintln!(
        "[phase 0] initial config version: {}",
        initial_config.version
    );
    assert!(
        initial_config.validators.is_empty(),
        "initial config should have no validators field"
    );

    let initial_cometbft_vals = query_cometbft_validators(&rpc_client).await?;
    assert_eq!(
        initial_cometbft_vals.len(),
        3,
        "CometBFT should have 3 genesis validators"
    );

    // Read the 3 genesis validator pubkeys from priv_validator_key.json files
    let genesis_validators = read_genesis_validator_pubkeys(&network)?;
    assert_eq!(genesis_validators.len(), 3);

    // ── Phase 1: Add a 4th validator (dummy key) ──

    let new_pubkey = generate_ed25519_pubkey();
    eprintln!(
        "[phase 1] generated new validator pubkey: {}",
        hex::encode(&new_pubkey)
    );

    let mut phase1_validators = genesis_validators.clone();
    phase1_validators.push(Validator {
        public_key: new_pubkey.clone().into(),
        power: 5,
    });

    let phase1_config = Config {
        version: initial_config.version + 1,
        admins: initial_config.admins.clone(),
        oracles: initial_config.oracles.clone(),
        onion: initial_config.onion.clone(),
        validators: phase1_validators,
    };

    eprintln!("[phase 1] submitting config with 4 validators");
    submit_admin_reconfig(&network, &rpc_client, phase1_config).await?;

    let target_version = initial_config.version + 1;
    poll_until(
        consensus_propagation_wait_long(),
        poll_interval(),
        "phase 1: config version incremented",
        || Ok(query_config(&felidae_bin, &network.query_url())?.version >= target_version),
    )
    .await?;

    let config_after_phase1 = query_config(&felidae_bin, &network.query_url())?;
    assert_eq!(
        config_after_phase1.validators.len(),
        4,
        "config should have 4 validators"
    );

    // Poll CometBFT until it sees the 4th validator
    poll_until_async(
        consensus_propagation_wait_long(),
        poll_interval(),
        "phase 1: CometBFT sees 4 validators",
        || async {
            let vals = query_cometbft_validators(&rpc_client).await?;
            Ok(vals.len() == 4)
        },
    )
    .await?;

    let cometbft_vals_phase1 = query_cometbft_validators(&rpc_client).await?;
    assert_eq!(cometbft_vals_phase1.len(), 4);

    // Verify the new validator has power 5
    let new_val_entry = cometbft_vals_phase1
        .iter()
        .find(|(key, _)| key == &new_pubkey)
        .expect("new validator should be in CometBFT validator set");
    assert_eq!(new_val_entry.1, 5, "new validator should have power 5");
    eprintln!("[phase 1] confirmed: 4th validator added with power 5");

    // ── Phase 2: Remove the 4th validator ──

    let phase2_config = Config {
        version: config_after_phase1.version + 1,
        admins: config_after_phase1.admins.clone(),
        oracles: config_after_phase1.oracles.clone(),
        onion: config_after_phase1.onion.clone(),
        validators: genesis_validators.clone(),
    };

    eprintln!("[phase 2] submitting config with 3 validators (removing 4th)");
    submit_admin_reconfig(&network, &rpc_client, phase2_config).await?;

    let target_version = config_after_phase1.version + 1;
    poll_until(
        consensus_propagation_wait_long(),
        poll_interval(),
        "phase 2: config version incremented",
        || Ok(query_config(&felidae_bin, &network.query_url())?.version >= target_version),
    )
    .await?;

    let config_after_phase2 = query_config(&felidae_bin, &network.query_url())?;
    assert_eq!(
        config_after_phase2.validators.len(),
        3,
        "config should have 3 validators"
    );

    // Poll CometBFT until it shows 3 validators again
    poll_until_async(
        consensus_propagation_wait_long(),
        poll_interval(),
        "phase 2: CometBFT back to 3 validators",
        || async {
            let vals = query_cometbft_validators(&rpc_client).await?;
            Ok(vals.len() == 3)
        },
    )
    .await?;

    let cometbft_vals_phase2 = query_cometbft_validators(&rpc_client).await?;
    assert_eq!(
        cometbft_vals_phase2.len(),
        3,
        "CometBFT should be back to 3 validators"
    );
    eprintln!("[phase 2] confirmed: 4th validator removed");

    // Verify the chain is still producing blocks
    let height_before = rpc_client.latest_block().await?.block.header.height.value();
    tokio::time::sleep(consensus_propagation_wait()).await;
    let height_after = rpc_client.latest_block().await?.block.header.height.value();
    assert!(
        height_after > height_before,
        "chain should still produce blocks after validator removal (height {} → {})",
        height_before,
        height_after
    );
    eprintln!(
        "[phase 2] chain still live: height {} → {}",
        height_before, height_after
    );

    Ok(())
}

/// Tests the full validator onboarding lifecycle with a real node.
///
/// Pre-creates a 4-node network but only starts 3. Then onboards the 4th
/// validator via admin reconfiguration, starts its processes, and verifies
/// the chain produces blocks with all 4 validators active.
///
/// This exercises the real operator workflow: infrastructure pre-provisioned,
/// admin promotes validator, node joins consensus.
///
/// # Phases
///
/// 0. **Setup**: Create 4-node network, start only nodes 0-2
/// 1. **Declare validators**: Admin reconfig with all 4 genesis validator pubkeys
/// 2. **Start 4th node**: Bring up CometBFT + Felidae for node 3
/// 3. **Verify**: Chain produces blocks with 4 active validators
#[tokio::test]
#[cfg(feature = "integration")]
async fn test_validator_onboarding_with_real_node() -> color_eyre::Result<()> {
    let (cometbft_bin, felidae_bin) = find_binaries()?;

    // Create a 4-node network but only start nodes 0-2
    let mut network = TestNetwork::create(4).await?;
    network.network.check_ports_available()?;
    for i in 0..3 {
        network.start_node(
            i,
            cometbft_bin.to_str().unwrap(),
            felidae_bin.to_str().unwrap(),
        )?;
    }
    network.wait_ready(network_startup_timeout()).await?;

    let rpc_client = HttpClient::new(network.rpc_url().as_str())?;

    // ── Phase 0: Verify initial state (3 validators in CometBFT) ──

    let initial_config = query_config(&felidae_bin, &network.query_url())?;
    assert!(
        initial_config.validators.is_empty(),
        "initial config should have no validators field"
    );

    let initial_cometbft_vals = query_cometbft_validators(&rpc_client).await?;
    assert_eq!(
        initial_cometbft_vals.len(),
        4,
        "CometBFT genesis should have 4 validators (even though node 3 is not running)"
    );
    eprintln!(
        "[phase 0] CometBFT has {} validators in genesis, 3 nodes running",
        initial_cometbft_vals.len()
    );

    // Read all 4 genesis validator pubkeys
    let genesis_validators = read_genesis_validator_pubkeys(&network)?;
    assert_eq!(genesis_validators.len(), 4);
    eprintln!("[phase 0] read 4 genesis validator pubkeys");

    // ── Phase 1: Declare all 4 validators in config ──

    let phase1_config = Config {
        version: initial_config.version + 1,
        admins: initial_config.admins.clone(),
        oracles: initial_config.oracles.clone(),
        onion: initial_config.onion.clone(),
        validators: genesis_validators.clone(),
    };

    eprintln!("[phase 1] submitting config with 4 genesis validators");
    submit_admin_reconfig(&network, &rpc_client, phase1_config).await?;

    let target_version = initial_config.version + 1;
    poll_until(
        consensus_propagation_wait_long(),
        poll_interval(),
        "phase 1: config version incremented",
        || Ok(query_config(&felidae_bin, &network.query_url())?.version >= target_version),
    )
    .await?;

    let config_after_phase1 = query_config(&felidae_bin, &network.query_url())?;
    assert_eq!(
        config_after_phase1.validators.len(),
        4,
        "config should have 4 validators"
    );
    eprintln!("[phase 1] config now declares 4 validators");

    // ── Phase 2: Start the 4th node ──

    eprintln!("[phase 2] starting node 3");
    network.start_node(
        3,
        cometbft_bin.to_str().unwrap(),
        felidae_bin.to_str().unwrap(),
    )?;

    // Construct query URL for the 4th node
    let node3 = &network.network.nodes[3];
    let node3_query_url = format!("http://{}:{}", node3.bind_address, node3.ports.felidae_query);
    let node3_rpc_url = format!("http://{}:{}", node3.bind_address, node3.ports.cometbft_rpc);

    // Wait for the 4th node to sync (it should catch up via block sync)
    poll_until(
        Duration::from_secs(60),
        poll_interval(),
        "node 3 syncs and serves queries",
        || {
            match query_config(&felidae_bin, &node3_query_url) {
                Ok(config) => {
                    eprintln!(
                        "[phase 2] node 3 config version: {} (target: {})",
                        config.version, config_after_phase1.version
                    );
                    Ok(config.version >= config_after_phase1.version)
                }
                Err(_) => Ok(false),
            }
        },
    )
    .await?;
    eprintln!("[phase 2] node 3 is synced");

    // ── Phase 3: Verify chain liveness with 4 validators ──

    let node3_rpc = HttpClient::new(node3_rpc_url.as_str())?;

    // Verify CometBFT still has 4 active validators
    poll_until_async(
        consensus_propagation_wait_long(),
        poll_interval(),
        "CometBFT has 4 validators after node 3 joins",
        || async {
            let vals = query_cometbft_validators(&node3_rpc).await?;
            Ok(vals.len() == 4)
        },
    )
    .await?;

    // Verify blocks are still being produced
    let height_before = rpc_client.latest_block().await?.block.header.height.value();
    tokio::time::sleep(consensus_propagation_wait()).await;
    let height_after = rpc_client.latest_block().await?.block.header.height.value();
    assert!(
        height_after > height_before,
        "chain should produce blocks with 4 validators (height {} → {})",
        height_before,
        height_after
    );
    eprintln!(
        "[phase 3] chain live with 4 validators: height {} → {}",
        height_before, height_after
    );

    Ok(())
}

/// Verifies that submitting a config with an empty validators field is a no-op.
///
/// The `sync_validators_from_config` function treats `validators: vec![]` as
/// "not managed by config" and leaves the active validator set untouched.
/// This is a regression test for a bug where an empty validators field would
/// remove all validators, halting consensus.
#[tokio::test]
#[cfg(feature = "integration")]
async fn test_admin_reconfig_empty_validators_is_noop() -> color_eyre::Result<()> {
    let (cometbft_bin, felidae_bin) = find_binaries()?;

    let mut network = TestNetwork::create(3).await?;
    network.start(
        cometbft_bin.to_str().unwrap(),
        felidae_bin.to_str().unwrap(),
    )?;
    network.wait_ready(network_startup_timeout()).await?;

    let rpc_client = HttpClient::new(network.rpc_url().as_str())?;

    // Get CometBFT's initial validator set
    let initial_cometbft_vals = query_cometbft_validators(&rpc_client).await?;
    assert_eq!(initial_cometbft_vals.len(), 3);

    // Submit a reconfig with empty validators (the default)
    let current_config = query_config(&felidae_bin, &network.query_url())?;
    assert!(current_config.validators.is_empty());

    let new_config = Config {
        version: current_config.version + 1,
        admins: current_config.admins.clone(),
        oracles: OracleConfig {
            observation_timeout: Duration::from_secs(700),
            ..current_config.oracles.clone()
        },
        onion: current_config.onion.clone(),
        validators: vec![], // explicitly empty
    };

    eprintln!("[test] submitting reconfig with empty validators");
    submit_admin_reconfig(&network, &rpc_client, new_config).await?;

    let target_version = current_config.version + 1;
    poll_until(
        consensus_propagation_wait_long(),
        poll_interval(),
        "config version incremented after empty-validators reconfig",
        || Ok(query_config(&felidae_bin, &network.query_url())?.version >= target_version),
    )
    .await?;

    // Verify the config was updated (observation_timeout changed)
    let updated_config = query_config(&felidae_bin, &network.query_url())?;
    assert_eq!(
        updated_config.oracles.observation_timeout,
        Duration::from_secs(700),
        "observation_timeout should be updated"
    );

    // CometBFT should still have exactly 3 validators — empty validators is a no-op
    let cometbft_vals_after = query_cometbft_validators(&rpc_client).await?;
    assert_eq!(
        cometbft_vals_after.len(),
        3,
        "CometBFT should still have 3 validators after empty-validators reconfig"
    );
    assert_eq!(
        cometbft_vals_after, initial_cometbft_vals,
        "validator set should be unchanged"
    );

    // Verify chain is still producing blocks
    let height_before = rpc_client.latest_block().await?.block.header.height.value();
    tokio::time::sleep(consensus_propagation_wait()).await;
    let height_after = rpc_client.latest_block().await?.block.header.height.value();
    assert!(
        height_after > height_before,
        "chain should still produce blocks"
    );

    eprintln!("[test] confirmed: empty validators is a no-op, chain still live");

    Ok(())
}
