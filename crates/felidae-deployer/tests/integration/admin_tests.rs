//! Admin reconfiguration integration tests.
//!
//! This module contains tests for the admin reconfiguration system, including
//! config updates, quorum enforcement, and BFT voting behavior.

use felidae_types::response::ChainInfo;
use felidae_types::transaction::{Config, OracleConfig, Validator};
use std::process::{Child, Command, Stdio};
use std::time::Duration;
use tendermint_rpc::{Client, HttpClient};

use felidae_deployer::join::{GenesisSource, JoinConfig, PeerSource};

use crate::binaries::find_binaries;
use crate::constants::{
    admin_reconfig_tx_timeout, consensus_propagation_wait, consensus_propagation_wait_long,
    inter_tx_delay, network_startup_timeout, poll_interval,
};
use crate::harness::TestNetwork;
use crate::helpers::{
    generate_ed25519_pubkey, poll_until, poll_until_async, query_admin_pending, query_admin_votes,
    query_cometbft_validators, query_config, read_genesis_validator_pubkeys,
    read_priv_validator_pubkey, run_query_command, submit_admin_reconfig,
};

/// Runs `felidae query chain-info --json` and parses the result.
fn query_chain_info(
    felidae_bin: &std::path::Path,
    query_url: &str,
) -> color_eyre::Result<ChainInfo> {
    let output = run_query_command(felidae_bin, "chain-info", query_url, &["--json"])?;
    let info: ChainInfo = serde_json::from_str(&output)?;
    Ok(info)
}

/// RAII wrapper ensuring a joined node's child processes are reaped on drop.
struct JoinedNodeProcs {
    cometbft: Child,
    felidae: Child,
}

impl Drop for JoinedNodeProcs {
    fn drop(&mut self) {
        let _ = self.cometbft.kill();
        let _ = self.cometbft.wait();
        let _ = self.felidae.kill();
        let _ = self.felidae.wait();
    }
}

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
        validator_config: current_config.validator_config.clone(),
    };

    // Submit reconfiguration from all 3 admins to reach quorum.
    // Uses broadcast_tx_sync (not broadcast_tx_commit) to avoid timeouts
    // when block processing takes longer than expected in CI.
    submit_admin_reconfig(&network, &rpc_client, new_config).await?;

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
        validator_config: current_config.validator_config.clone(),
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
        let result = rpc_client.broadcast_tx_sync(tx_bytes).await?;

        eprintln!(
            "[test] admin {} reconfig tx: code={:?}, log={}",
            i, result.code, result.log
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
        validator_config: current_config.validator_config.clone(),
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
        let result = rpc_client.broadcast_tx_sync(tx_bytes).await?;

        eprintln!(
            "[test] admin {} reconfig tx: code={:?}, log={}",
            i, result.code, result.log
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

/// Tests the full validator onboarding and offboarding lifecycle.
///
/// This test exercises adding and removing a validator via admin reconfiguration
/// on a 3-validator network, verifying that both the felidae config and CometBFT's
/// active validator set are updated correctly.
///
/// # Phases
///
/// 0. **Setup**: Start 3-validator network, verify initial state
/// 1. **Declare genesis validators**: Populate config.validators with the 3 genesis validators
/// 2. **Onboard 4th validator**: Add a dummy validator with power 5
/// 3. **Offboard 4th validator**: Remove it, verify chain continues
#[tokio::test]
#[cfg(feature = "integration")]
async fn test_admin_validator_onboarding_offboarding() -> color_eyre::Result<()> {
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
    eprintln!(
        "[phase 0] CometBFT has {} validators",
        initial_cometbft_vals.len()
    );

    // Read the 3 genesis validator pubkeys from priv_validator_key.json files
    let genesis_validators = read_genesis_validator_pubkeys(&network)?;
    assert_eq!(genesis_validators.len(), 3);
    eprintln!(
        "[phase 0] read {} genesis validator pubkeys",
        genesis_validators.len()
    );

    // ── Phase 1: Declare genesis validators in config ──

    let phase1_config = Config {
        version: initial_config.version + 1,
        admins: initial_config.admins.clone(),
        oracles: initial_config.oracles.clone(),
        onion: initial_config.onion.clone(),
        validators: genesis_validators.clone(),
    };

    eprintln!("[phase 1] submitting config with 3 genesis validators");
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
        3,
        "config should have 3 validators"
    );

    // CometBFT should still have exactly 3 validators (no-op sync)
    let cometbft_vals_phase1 = query_cometbft_validators(&rpc_client).await?;
    assert_eq!(
        cometbft_vals_phase1.len(),
        3,
        "CometBFT should still have 3 validators after declaring genesis set"
    );
    eprintln!("[phase 1] confirmed: 3 validators in config and CometBFT");

    // ── Phase 2: Onboard a 4th validator ──

    let new_pubkey = generate_ed25519_pubkey();
    eprintln!(
        "[phase 2] generated new validator pubkey: {}",
        hex::encode(&new_pubkey)
    );

    let mut phase2_validators = genesis_validators.clone();
    phase2_validators.push(Validator {
        public_key: new_pubkey.clone().into(),
        power: 5,
    });

    let phase2_config = Config {
        version: config_after_phase1.version + 1,
        admins: config_after_phase1.admins.clone(),
        oracles: config_after_phase1.oracles.clone(),
        onion: config_after_phase1.onion.clone(),
        validators: phase2_validators,
    };

    eprintln!("[phase 2] submitting config with 4 validators");
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
        4,
        "config should have 4 validators"
    );

    // Poll CometBFT until it sees the 4th validator (update takes effect after FinalizeBlock)
    poll_until_async(
        consensus_propagation_wait_long(),
        poll_interval(),
        "phase 2: CometBFT sees 4 validators",
        || async {
            let vals = query_cometbft_validators(&rpc_client).await?;
            Ok(vals.len() == 4)
        },
    )
    .await?;

    let cometbft_vals_phase2 = query_cometbft_validators(&rpc_client).await?;
    assert_eq!(
        cometbft_vals_phase2.len(),
        4,
        "CometBFT should have 4 validators"
    );

    // Verify the new validator has power 5
    let new_val_entry = cometbft_vals_phase2
        .iter()
        .find(|(key, _)| key == &new_pubkey)
        .expect("new validator should be in CometBFT validator set");
    assert_eq!(new_val_entry.1, 5, "new validator should have power 5");
    eprintln!("[phase 2] confirmed: 4th validator onboarded with power 5");

    // ── Phase 3: Offboard the 4th validator ──

    let phase3_config = Config {
        version: config_after_phase2.version + 1,
        admins: config_after_phase2.admins.clone(),
        oracles: config_after_phase2.oracles.clone(),
        onion: config_after_phase2.onion.clone(),
        validators: genesis_validators.clone(),
    };

    eprintln!("[phase 3] submitting config with 3 validators (removing 4th)");
    submit_admin_reconfig(&network, &rpc_client, phase3_config).await?;

    let target_version = config_after_phase2.version + 1;
    poll_until(
        consensus_propagation_wait_long(),
        poll_interval(),
        "phase 3: config version incremented",
        || Ok(query_config(&felidae_bin, &network.query_url())?.version >= target_version),
    )
    .await?;

    let config_after_phase3 = query_config(&felidae_bin, &network.query_url())?;
    assert_eq!(
        config_after_phase3.validators.len(),
        3,
        "config should have 3 validators"
    );

    // Poll CometBFT until it shows 3 validators again
    poll_until_async(
        consensus_propagation_wait_long(),
        poll_interval(),
        "phase 3: CometBFT back to 3 validators",
        || async {
            let vals = query_cometbft_validators(&rpc_client).await?;
            Ok(vals.len() == 3)
        },
    )
    .await?;

    let cometbft_vals_phase3 = query_cometbft_validators(&rpc_client).await?;
    assert_eq!(
        cometbft_vals_phase3.len(),
        3,
        "CometBFT should be back to 3 validators"
    );
    eprintln!("[phase 3] confirmed: 4th validator removed");

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
        "[phase 3] chain still live: height {} → {}",
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

/// End-to-end validator onboarding: bootstrap a brand-new node onto a running
/// network via `join_network`, then promote it from full-node to validator via
/// an admin reconfiguration, and verify the chain remains live with the
/// expanded validator set.
///
/// This complements `test_admin_validator_onboarding_offboarding`, which only
/// adds a dummy pubkey with no real node behind it. Here we exercise the full
/// flow: a real second node joins, syncs, and is promoted to signer.
///
/// # Phases
///
/// 0. Start 3-validator devnet.
/// 1. `join_network` as a full node. The joined node is pre-provisioned with
///    a `priv_validator_key.json` by the join logic; we read the pubkey back
///    from disk to feed into the later reconfig.
/// 2. Spawn the newcomer's CometBFT + felidae processes.
/// 3. Wait for the joined node to sync to the network's current height.
/// 4. Declare the 3 genesis validators in `config.validators` (seeding step;
///    the reconfig in Phase 5 must be additive, not replacing, or CometBFT
///    would lose all signers and halt).
/// 5. Submit an admin reconfig that adds the newcomer as a 4th validator.
/// 6. Assert: CometBFT sees 4 validators, the chain keeps advancing on both
///    the genesis node and the joined node, and both return identical
///    `Config` values from their query endpoints.
#[tokio::test]
#[cfg(feature = "integration")]
async fn test_validator_onboarding_joined_node() -> color_eyre::Result<()> {
    let (cometbft_bin, felidae_bin) = find_binaries()?;

    // ── Phase 0: Start devnet ──────────────────────────────────────────────
    let mut network = TestNetwork::create(3).await?;
    network.start(
        cometbft_bin.to_str().unwrap(),
        felidae_bin.to_str().unwrap(),
    )?;
    network.wait_ready(network_startup_timeout()).await?;

    let rpc_client = HttpClient::new(network.rpc_url().as_str())?;

    let initial_cometbft_vals = query_cometbft_validators(&rpc_client).await?;
    assert_eq!(
        initial_cometbft_vals.len(),
        3,
        "devnet should start with 3 validators"
    );
    let initial_config = query_config(&felidae_bin, &network.query_url())?;
    assert!(
        initial_config.validators.is_empty(),
        "initial config.validators should be empty"
    );
    eprintln!("[phase 0] 3-validator devnet ready");

    // ── Phase 1: Join as a full node ───────────────────────────────────────
    // `join_network` pre-provisions a `priv_validator_key.json` for the new
    // node, so we can read the consensus pubkey back after joining and feed
    // it into the admin reconfig that promotes the node to validator status.
    let join_dir = tempfile::tempdir()?;
    let join_path = join_dir.path().join("newcomer");

    let genesis_file = network.network.nodes[0].genesis_path();
    let rpc_url: url::Url = network.rpc_url().parse()?;

    let join_config = JoinConfig {
        genesis_source: GenesisSource::File(genesis_file),
        peer_source: PeerSource::CometbftRpc(rpc_url),
        directory: join_path,
        find_free_ports: true,
        node_name: "newcomer".to_string(),
    };

    let joined = felidae_deployer::join::join_network(join_config).await?;

    let new_validator_pubkey = read_priv_validator_pubkey(&joined.priv_validator_key_path())?;
    eprintln!(
        "[phase 1] newcomer joined; consensus pubkey: {}",
        hex::encode(&new_validator_pubkey)
    );

    let joined_query_url = format!(
        "http://{}:{}",
        joined.bind_address, joined.ports.felidae_query
    );

    // ── Phase 2: Spawn the newcomer's processes ────────────────────────────
    // Drop of JoinedNodeProcs will reap them on test exit.
    let cometbft_child = Command::new(cometbft_bin.to_str().unwrap())
        .args(["start", "--home", &joined.cometbft_home().to_string_lossy()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;

    let felidae_child = Command::new(felidae_bin.to_str().unwrap())
        .env("RUST_LOG", "info")
        .args([
            "start",
            "--abci-bind",
            &joined.abci_address(),
            "--query-bind",
            &format!("{}:{}", joined.bind_address, joined.ports.felidae_query),
            "--homedir",
            &joined.felidae_home().to_string_lossy(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;

    let _joined_procs = JoinedNodeProcs {
        cometbft: cometbft_child,
        felidae: felidae_child,
    };

    // ── Phase 3: Wait for the joined node to sync ──────────────────────────
    let sync_target = query_chain_info(&felidae_bin, &network.query_url())?.block_height;
    eprintln!("[phase 3] waiting for joined node to reach height {sync_target}");
    poll_until_async(
        network_startup_timeout(),
        poll_interval(),
        "joined node syncs to network height",
        || async {
            match query_chain_info(&felidae_bin, &joined_query_url) {
                Ok(info) => Ok(info.block_height >= sync_target),
                Err(_) => Ok(false),
            }
        },
    )
    .await?;
    eprintln!("[phase 3] joined node synced");

    // ── Phase 4: Seed genesis validators into config.validators ────────────
    // We must declare the existing 3 before adding a 4th, otherwise the
    // reconfig in Phase 5 would instruct CometBFT to replace the signers
    // with {newcomer}, halting the chain.
    let genesis_validators = read_genesis_validator_pubkeys(&network)?;
    assert_eq!(genesis_validators.len(), 3);

    let config_before_seed = query_config(&felidae_bin, &network.query_url())?;
    let seed_config = Config {
        version: config_before_seed.version + 1,
        admins: config_before_seed.admins.clone(),
        oracles: config_before_seed.oracles.clone(),
        onion: config_before_seed.onion.clone(),
        validators: genesis_validators.clone(),
    };

    eprintln!("[phase 4] seeding genesis validators into config");
    submit_admin_reconfig(&network, &rpc_client, seed_config).await?;

    let target_version = config_before_seed.version + 1;
    poll_until(
        consensus_propagation_wait_long(),
        poll_interval(),
        "phase 4: seed reconfig applied",
        || {
            let cfg = query_config(&felidae_bin, &network.query_url())?;
            Ok(cfg.version >= target_version && cfg.validators.len() == 3)
        },
    )
    .await?;

    // CometBFT set should still be 3 (no-op at the consensus layer).
    let cometbft_after_seed = query_cometbft_validators(&rpc_client).await?;
    assert_eq!(
        cometbft_after_seed.len(),
        3,
        "CometBFT validator set should be unchanged after seeding"
    );
    let config_after_seed = query_config(&felidae_bin, &network.query_url())?;

    // ── Phase 5: Onboard the joined node as a 4th validator ────────────────
    let mut phase5_validators = genesis_validators.clone();
    phase5_validators.push(Validator {
        public_key: new_validator_pubkey.clone().into(),
        power: 5,
    });

    let onboard_config = Config {
        version: config_after_seed.version + 1,
        admins: config_after_seed.admins.clone(),
        oracles: config_after_seed.oracles.clone(),
        onion: config_after_seed.onion.clone(),
        validators: phase5_validators,
    };

    eprintln!("[phase 5] onboarding newcomer as 4th validator");
    submit_admin_reconfig(&network, &rpc_client, onboard_config).await?;

    let onboard_target_version = config_after_seed.version + 1;
    poll_until(
        consensus_propagation_wait_long(),
        poll_interval(),
        "phase 5: onboarding reconfig applied in felidae config",
        || {
            let cfg = query_config(&felidae_bin, &network.query_url())?;
            Ok(cfg.version >= onboard_target_version && cfg.validators.len() == 4)
        },
    )
    .await?;

    // Wait for CometBFT to pick up the new validator set.
    poll_until_async(
        consensus_propagation_wait_long(),
        poll_interval(),
        "phase 5: CometBFT observes 4 validators",
        || async {
            let vals = query_cometbft_validators(&rpc_client).await?;
            Ok(vals.len() == 4)
        },
    )
    .await?;

    let cometbft_after_onboard = query_cometbft_validators(&rpc_client).await?;
    assert_eq!(cometbft_after_onboard.len(), 4);
    let newcomer_entry = cometbft_after_onboard
        .iter()
        .find(|(key, _)| key == &new_validator_pubkey)
        .expect("newcomer should appear in CometBFT validator set");
    assert_eq!(newcomer_entry.1, 5, "newcomer should have power 5");
    eprintln!("[phase 5] newcomer is in the CometBFT validator set with power 5");

    // ── Phase 6: Post-onboarding assertions ────────────────────────────────

    // Chain liveness: poll for advancing block height on the genesis node.
    // After a validator set change, CometBFT may briefly drop RPC connections,
    // so we use poll_until_async rather than bare `.await?` calls.
    // Grab a baseline height, retrying on transient connection errors.
    let height_before = {
        let rpc = &rpc_client;
        let h = std::sync::atomic::AtomicU64::new(0);
        poll_until_async(
            consensus_propagation_wait_long(),
            poll_interval(),
            "phase 6: read height_before from genesis node",
            || {
                let h = &h;
                async move {
                    let resp = rpc.latest_block().await?;
                    h.store(
                        resp.block.header.height.value(),
                        std::sync::atomic::Ordering::SeqCst,
                    );
                    Ok(true)
                }
            },
        )
        .await?;
        h.load(std::sync::atomic::Ordering::SeqCst)
    };
    tokio::time::sleep(consensus_propagation_wait()).await;
    // Check that height advanced.
    poll_until_async(
        consensus_propagation_wait_long(),
        poll_interval(),
        "phase 6: chain advances after onboarding",
        || {
            let rpc = &rpc_client;
            async move {
                let resp = rpc.latest_block().await?;
                Ok(resp.block.header.height.value() > height_before)
            }
        },
    )
    .await?;
    let height_after = rpc_client.latest_block().await?.block.header.height.value();
    eprintln!(
        "[phase 6] chain live on genesis node: {} → {}",
        height_before, height_after
    );

    // Newcomer still tracks network height.
    poll_until(
        consensus_propagation_wait_long(),
        poll_interval(),
        "joined node stays in sync post-onboarding",
        || {
            let joined_info = query_chain_info(&felidae_bin, &joined_query_url)?;
            Ok(joined_info.block_height >= height_after)
        },
    )
    .await?;

    // Newcomer remains a member of the active set at a later height — this is
    // a cheap proxy for "the newcomer is actually participating". CometBFT's
    // /validators endpoint at any given height only lists validators expected
    // to sign at that height.
    let later_vals = query_cometbft_validators(&rpc_client).await?;
    assert_eq!(
        later_vals.len(),
        4,
        "newcomer should remain in the active validator set at later heights"
    );
    assert!(
        later_vals.iter().any(|(k, _)| k == &new_validator_pubkey),
        "newcomer pubkey should still be in the active set"
    );

    // Config parity between genesis node and joined node: both views of
    // state should agree post-onboarding.
    let expected_config = query_config(&felidae_bin, &network.query_url())?;
    let joined_config = query_config(&felidae_bin, &joined_query_url)?;
    assert_eq!(
        joined_config, expected_config,
        "joined node's config should match the network's config post-onboarding"
    );
    assert_eq!(
        joined_config.validators.len(),
        4,
        "joined node should see 4 validators in config"
    );

    eprintln!("[phase 6] confirmed: validator onboarded end-to-end, state consistent across nodes");

    Ok(())
}
