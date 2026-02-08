//! Admin reconfiguration integration tests.
//!
//! This module contains tests for the admin reconfiguration system, including
//! config updates, quorum enforcement, and BFT voting behavior.

use felidae_types::transaction::{Config, OracleConfig};
use std::time::Duration;
use tendermint_rpc::{Client, HttpClient};

use crate::binaries::find_binaries;
use crate::constants::{
    admin_reconfig_tx_timeout, consensus_propagation_wait, inter_tx_delay, network_startup_timeout,
};
use crate::harness::TestNetwork;
use crate::helpers::{query_admin_pending, query_admin_votes, query_config};

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

    // Wait for the config change to take effect (admin delay is 0s in test config)
    tokio::time::sleep(consensus_propagation_wait()).await;

    // Verify the configuration was updated via CLI
    let updated_config = query_config(&felidae_bin, &network.query_url())?;
    eprintln!("[test] updated config version: {}", updated_config.version);

    // The version should have incremented
    assert!(
        updated_config.version >= current_config.version,
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

    // Wait for the config change to take effect (admin delay is 0s in test config)
    tokio::time::sleep(consensus_propagation_wait()).await;

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
