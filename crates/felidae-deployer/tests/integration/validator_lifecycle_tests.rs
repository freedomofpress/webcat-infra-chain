//! Integration tests covering the validator lifecycle in a live network.
//!
//! These tests sit one level above the pure state-machine unit tests in
//! `crates/felidae-state/src/state/validator.rs::tests`. The unit tests exercise
//! the transition table directly; the tests in this file drive the same
//! transitions through a real CometBFT-in-the-loop deployment so the
//! ABCI/consensus plumbing stays in scope.

use std::time::Duration;

use felidae_state::BASE_VALIDATOR_POWER;
use felidae_types::transaction::{Config, Validator, ValidatorConfig, ValidatorStatus};
use tendermint_rpc::{Client, HttpClient};

use crate::binaries::find_binaries;
use crate::constants::{
    block_time, consensus_propagation_wait, consensus_propagation_wait_long,
    network_startup_timeout, poll_interval,
};
use crate::harness::TestNetwork;
use crate::helpers::{
    poll_until, poll_until_async, query_cometbft_validators, query_config, query_validator_info,
    read_genesis_validator_pubkeys, submit_admin_reconfig, wait_reconfig_applied,
};

/// Tight `ValidatorConfig` tuned for downtime tests: a 30-block uptime
/// window, jailing after 11 missed blocks, unjailing once misses fall to 5
/// or fewer. Keeps the wall-clock spent waiting for jail/unjail in seconds
/// rather than the production-default minutes, while still exercising the
/// real ring-buffer logic in `Uptime`.
fn downtime_validator_config() -> ValidatorConfig {
    ValidatorConfig {
        uptime_window: 30,
        missed_blocks_max: 10,
        unjail_missed_max: 5,
    }
}

/// Timeout for jailing assertions.
///
/// Worst case at `block_time=2s`:
///   - 11 missed blocks  ≈ 22 s
///   - 3 missed proposer turns × 3 s default timeout_propose ≈ 9 s
///   - startup overhead + scheduling jitter
///
/// `block_time * 15 + 45 s` lands comfortably above that envelope at both
/// 1-second (CI) and 2-second (`just integration`) block intervals while
/// staying well under the integration suite's per-test budget.
fn jail_timeout() -> Duration {
    block_time() * 15 + Duration::from_secs(45)
}

/// Timeout for unjail assertions.
///
/// After a jailed validator restarts, the ring buffer needs `~window_len`
/// signed heights to overwrite the missed positions before
/// `num_missed_blocks` falls below `unjail_missed_max`. Add headroom for
/// blocksync catch-up and proposal-timeout slack on top of `window_len`.
fn unjail_timeout() -> Duration {
    block_time() * 40 + Duration::from_secs(60)
}

/// Polls the chain for a block whose `last_commit.signatures` contains a
/// positive `BlockIdFlagCommit` signature from the given validator address.
///
/// `last_commit` in block `N` covers block `N-1`, so this proves the
/// validator was an active signer at some height *before* the latest one.
async fn poll_for_validator_signature(
    rpc_client: &HttpClient,
    validator_address: tendermint::account::Id,
    timeout: Duration,
) -> color_eyre::Result<u64> {
    let start = std::time::Instant::now();
    let mut last_height_seen = 0u64;
    loop {
        let block = rpc_client.latest_block().await?;
        let height = block.block.header.height.value();
        if height != last_height_seen {
            last_height_seen = height;
            if let Some(commit) = &block.block.last_commit {
                for sig in &commit.signatures {
                    if sig.is_commit()
                        && let Some(addr) = sig.validator_address()
                        && addr == validator_address
                    {
                        return Ok(commit.height.value());
                    }
                }
            }
        }
        if start.elapsed() > timeout {
            return Err(color_eyre::eyre::eyre!(
                "timed out waiting for validator {} to appear in a block signature \
                 (last height polled: {last_height_seen})",
                hex::encode(validator_address)
            ));
        }
        tokio::time::sleep(poll_interval()).await;
    }
}

/// Removes a genesis validator via admin reconfig and then re-adds it,
/// exercising the integration-level complement to the pure
/// `test_inactive_to_active_via_config_sync` unit test.
///
/// # Phases
///
/// 0. Start a 3-validator network and confirm the baseline CometBFT set.
/// 1. Seed the 3 genesis validators into `config.validators` (the empty-
///    field shortcut means "unmanaged", so we have to declare them before
///    removal can become meaningful).
/// 2. Submit a reconfig with validator-2 removed. Assert: CometBFT shows
///    only validators 0 and 1, the chain still produces blocks (2-of-2
///    must sign), and the felidae query reports validator-2 as
///    `"inactive"`.
/// 3. Submit a reconfig that re-adds validator-2 at the same pubkey.
///    Assert: power returns to `BASE_VALIDATOR_POWER`, status flips back
///    to `"active"`, and validator-2's CometBFT address appears in at
///    least one subsequent block's `last_commit.signatures` (proving it
///    is signing again, not merely present in the set).
#[tokio::test]
#[cfg(feature = "integration")]
async fn test_readd_removed_validator_resumes_signing() -> color_eyre::Result<()> {
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
        "initial config.validators should be empty (unmanaged)"
    );

    let genesis_validators = read_genesis_validator_pubkeys(&network)?;
    assert_eq!(genesis_validators.len(), 3);
    let target_key = genesis_validators[2].public_key;
    let target_pubkey: Vec<u8> = target_key.as_bytes().to_vec();
    let target_address = target_key.address();
    let target_identity = target_key.to_string();
    eprintln!(
        "[phase 0] will remove and re-add validator-2 (identity: {})",
        target_identity
    );

    // ── Phase 1: Seed config.validators with the 3 genesis validators ──────
    let phase1_config = Config {
        version: initial_config.version + 1,
        admins: initial_config.admins.clone(),
        oracles: initial_config.oracles.clone(),
        onion: initial_config.onion.clone(),
        validators: genesis_validators.clone(),
        validator_config: initial_config.validator_config.clone(),
    };
    eprintln!("[phase 1] seeding config.validators with 3 genesis validators");
    submit_admin_reconfig(&network, &rpc_client, phase1_config).await?;

    let phase1_target_version = initial_config.version + 1;
    let config_after_seed = wait_reconfig_applied(
        &felidae_bin,
        &network.query_url(),
        &rpc_client,
        phase1_target_version,
        "phase 1: seed reconfig applied",
    )
    .await?;
    assert_eq!(
        config_after_seed.validators.len(),
        3,
        "seeded config should list the 3 genesis validators"
    );

    // The seed is a no-op at the consensus layer — all 3 still active.
    let cometbft_after_seed = query_cometbft_validators(&rpc_client).await?;
    assert_eq!(cometbft_after_seed.len(), 3);

    // ── Phase 2: Remove validator-2 from the config ────────────────────────
    let remaining: Vec<Validator> = genesis_validators[..2].to_vec();
    let phase2_config = Config {
        version: config_after_seed.version + 1,
        admins: config_after_seed.admins.clone(),
        oracles: config_after_seed.oracles.clone(),
        onion: config_after_seed.onion.clone(),
        validators: remaining,
        validator_config: config_after_seed.validator_config.clone(),
    };
    eprintln!("[phase 2] submitting reconfig that removes validator-2");
    submit_admin_reconfig(&network, &rpc_client, phase2_config).await?;

    let phase2_target_version = config_after_seed.version + 1;
    let config_after_remove = wait_reconfig_applied(
        &felidae_bin,
        &network.query_url(),
        &rpc_client,
        phase2_target_version,
        "phase 2: removal reconfig applied in felidae config",
    )
    .await?;
    assert_eq!(
        config_after_remove.validators.len(),
        2,
        "config should list only the 2 remaining validators after removal"
    );

    // CometBFT should drop validator-2 from its active set.
    poll_until_async(
        consensus_propagation_wait_long(),
        poll_interval(),
        "phase 2: CometBFT drops validator-2",
        || async {
            let vals = query_cometbft_validators(&rpc_client).await?;
            Ok(vals.len() == 2 && !vals.iter().any(|(k, _)| k == &target_pubkey))
        },
    )
    .await?;

    // Felidae status for validator-2 should be `"inactive"` (admin-removed).
    let removed_info = query_validator_info(&felidae_bin, &network.query_url(), &target_identity)?
        .ok_or_else(|| {
            color_eyre::eyre::eyre!(
                "validator-2 should still be visible via /validators/{target_identity} after removal"
            )
        })?;
    assert_eq!(
        removed_info.status,
        ValidatorStatus::Inactive,
        "validator-2 should report status=inactive after admin removal, got {:?}",
        removed_info.status
    );
    assert_eq!(
        removed_info.power, 0,
        "validator-2 should report power=0 after admin removal, got {}",
        removed_info.power
    );

    // Verify chain liveness with only 2 active validators. With n=2 CometBFT
    // requires both to sign every block, but that's still expected to work
    // since neither was killed — only the validator-set entry was removed.
    let height_before = rpc_client.latest_block().await?.block.header.height.value();
    tokio::time::sleep(consensus_propagation_wait()).await;
    let height_after = rpc_client.latest_block().await?.block.header.height.value();
    assert!(
        height_after > height_before,
        "chain should continue producing blocks with 2 of 3 active validators \
         (height {height_before} → {height_after})"
    );
    eprintln!(
        "[phase 2] chain still live with 2 active validators: {} → {}",
        height_before, height_after
    );

    // ── Phase 3: Re-add validator-2 ────────────────────────────────────────
    let phase3_config = Config {
        version: config_after_remove.version + 1,
        admins: config_after_remove.admins.clone(),
        oracles: config_after_remove.oracles.clone(),
        onion: config_after_remove.onion.clone(),
        validators: genesis_validators.clone(),
        validator_config: config_after_remove.validator_config.clone(),
    };
    eprintln!("[phase 3] submitting reconfig that re-adds validator-2");
    submit_admin_reconfig(&network, &rpc_client, phase3_config).await?;

    let phase3_target_version = config_after_remove.version + 1;
    let config_after_readd = wait_reconfig_applied(
        &felidae_bin,
        &network.query_url(),
        &rpc_client,
        phase3_target_version,
        "phase 3: re-add reconfig applied in felidae config",
    )
    .await?;
    assert_eq!(
        config_after_readd.validators.len(),
        3,
        "config should list all 3 validators again after re-add"
    );

    poll_until_async(
        consensus_propagation_wait_long(),
        poll_interval(),
        "phase 3: CometBFT restores validator-2 at BASE_VALIDATOR_POWER",
        || async {
            let vals = query_cometbft_validators(&rpc_client).await?;
            Ok(vals
                .iter()
                .any(|(k, p)| k == &target_pubkey && *p == u64::from(BASE_VALIDATOR_POWER)))
        },
    )
    .await?;

    // The felidae view of validator-2 should be `"active"` again.
    let readded_info = query_validator_info(&felidae_bin, &network.query_url(), &target_identity)?
        .ok_or_else(|| {
            color_eyre::eyre::eyre!(
                "validator-2 should be visible via /validators/{target_identity} after re-add"
            )
        })?;
    assert_eq!(
        readded_info.status,
        ValidatorStatus::Active,
        "validator-2 should report status=active after re-add, got {:?}",
        readded_info.status
    );
    assert_eq!(
        readded_info.power,
        u64::from(BASE_VALIDATOR_POWER),
        "validator-2 should report power=BASE_VALIDATOR_POWER after re-add, got {}",
        readded_info.power
    );

    // Proof of life: validator-2's address must show up in a subsequent
    // block's last_commit signatures as a positive `BlockIdFlagCommit`. That
    // is what distinguishes "in the set" (membership) from "actually signing"
    // (participation).
    let signed_height = poll_for_validator_signature(
        &rpc_client,
        target_address,
        consensus_propagation_wait_long(),
    )
    .await?;
    eprintln!("[phase 3] validator-2 signed block at height {signed_height} after re-add");

    Ok(())
}

/// Kills one validator out of four and asserts the jail pipeline runs
/// end-to-end: CometBFT delivers vote info, the ABCI handler records misses
/// via `mark_validators_voted`, and `jail_inactive_validators` flips the
/// status to `Jailed` once misses exceed `missed_blocks_max`.
///
/// Uses N=4, not the N=3 the test plan literally specifies: with three
/// validators each at `BASE_VALIDATOR_POWER` and BFT requiring strictly
/// more than 2/3 voting power, killing one validator leaves only 2 / 3 of
/// total power (exactly 2/3, not strictly greater), which stalls consensus.
/// No blocks would be committed, so `jail_inactive_validators` would never
/// fire and the lifecycle could not be observed. With N=4 the surviving
/// 3 validators carry 3 / 4 ≈ 75 % of total power, comfortably above the
/// threshold, so the chain keeps committing while the jail timer runs out
/// on the killed validator. T3 already prescribes N=4 for the same reason.
///
/// # Assertions
///
/// 1. Within `jail_timeout()`, validator-3's CometBFT power drops from
///    `BASE_VALIDATOR_POWER` to `1` (the jailed marker, kept non-zero so
///    CometBFT continues delivering vote info to it).
/// 2. The chain keeps producing blocks throughout (height advances).
/// 3. The felidae query API reports validator-3 as `"jailed"`.
#[tokio::test]
#[cfg(feature = "integration")]
async fn test_validator_jailed_on_downtime() -> color_eyre::Result<()> {
    let (cometbft_bin, felidae_bin) = find_binaries()?;

    // ── Phase 0: Start a 4-validator devnet with tight jail thresholds ─────
    let mut network = TestNetwork::create_with_validator_config(
        4,
        block_time(),
        Some(downtime_validator_config()),
    )
    .await?;
    network.start(
        cometbft_bin.to_str().unwrap(),
        felidae_bin.to_str().unwrap(),
    )?;
    network.wait_ready(network_startup_timeout()).await?;

    let rpc_client = HttpClient::new(network.rpc_url().as_str())?;

    let cometbft_vals = query_cometbft_validators(&rpc_client).await?;
    assert_eq!(
        cometbft_vals.len(),
        4,
        "devnet should start with 4 validators"
    );

    // Capture the target's identity before tearing it down.
    let genesis_validators = read_genesis_validator_pubkeys(&network)?;
    assert_eq!(genesis_validators.len(), 4);
    let target_pubkey: Vec<u8> = genesis_validators[3].public_key.as_bytes().to_vec();
    let target_identity = genesis_validators[3].public_key.to_string();
    eprintln!("[phase 0] target validator-3 identity: {}", target_identity);

    // Wait for the network to push past the initial-block grace cases —
    // at height 1 CometBFT reports no signers, so `mark_validators_voted`
    // treats everyone as having signed. Polling to height ≥ 5 ensures the
    // uptime tracker is in steady-state for every validator.
    poll_until_async(
        consensus_propagation_wait(),
        poll_interval(),
        "warm up: chain reaches height >= 5",
        || async {
            let block = rpc_client.latest_block().await?;
            Ok(block.block.header.height.value() >= 5)
        },
    )
    .await?;
    let height_at_kill = rpc_client.latest_block().await?.block.header.height.value();
    eprintln!("[phase 0] killing validator-3 at height {}", height_at_kill);

    // ── Phase 1: Kill validator-3 (CometBFT + Felidae + Oracle) ────────────
    network.kill_validator(3)?;

    // ── Phase 2: Poll for the jailing transition ───────────────────────────
    // 2a. CometBFT power for validator-3 should drop to 1.
    poll_until_async(
        jail_timeout(),
        poll_interval(),
        "validator-3 power drops to 1 (jailed)",
        || async {
            let vals = query_cometbft_validators(&rpc_client).await?;
            Ok(vals.iter().any(|(k, p)| k == &target_pubkey && *p == 1))
        },
    )
    .await?;
    eprintln!("[phase 2] CometBFT reports validator-3 at power=1");

    // 2b. Surviving validators should still all be present at BASE power —
    // the jail path must not have collateral-damaged anyone.
    let after_jail = query_cometbft_validators(&rpc_client).await?;
    assert_eq!(
        after_jail.len(),
        4,
        "jailed validator should remain in the set with power=1, not be removed"
    );
    for (pk, power) in &after_jail {
        if pk == &target_pubkey {
            assert_eq!(*power, 1, "validator-3 should be at power=1");
        } else {
            assert_eq!(
                *power,
                u64::from(BASE_VALIDATOR_POWER),
                "surviving validator {} should retain BASE_VALIDATOR_POWER",
                hex::encode(pk)
            );
        }
    }

    // 2c. Chain liveness: height should have advanced beyond the kill
    // point, and should keep advancing.
    let height_after_jail = rpc_client.latest_block().await?.block.header.height.value();
    assert!(
        height_after_jail > height_at_kill,
        "chain should have advanced past height_at_kill={height_at_kill} \
         while validator-3 was being jailed (latest height={height_after_jail})"
    );
    let height_baseline = height_after_jail;
    poll_until_async(
        consensus_propagation_wait_long(),
        poll_interval(),
        "chain keeps producing blocks after jailing",
        || async {
            let block = rpc_client.latest_block().await?;
            Ok(block.block.header.height.value() > height_baseline)
        },
    )
    .await?;
    eprintln!(
        "[phase 2] chain still live post-jail: {} → {}",
        height_at_kill,
        rpc_client.latest_block().await?.block.header.height.value()
    );

    // 2d. The felidae query API should report validator-3 as `"jailed"`.
    poll_until(
        consensus_propagation_wait(),
        poll_interval(),
        "felidae query reports validator-3 status=jailed",
        || {
            let info = query_validator_info(&felidae_bin, &network.query_url(), &target_identity)?;
            Ok(info
                .map(|v| v.status == ValidatorStatus::Jailed && v.power == 1)
                .unwrap_or(false))
        },
    )
    .await?;
    eprintln!("[phase 2] felidae query reports validator-3 status=jailed");

    Ok(())
}

/// Jails validator-3 by killing its processes, then brings them back and
/// asserts the uptime ring buffer recovers the validator to `Active`.
///
/// This is the integration-level complement to
/// `validator.rs::tests::test_jailed_to_active_on_uptime_recovery`. The
/// unit test calls `mark_validators_voted` directly; this test exercises
/// the full pipeline — restart → blocksync → CometBFT delivers vote info →
/// ABCI handler records signs → `jail_inactive_validators` flips the
/// status back.
///
/// Self-contained: starts its own 4-validator network and walks the
/// validator through `Active → Jailed → Active`. We do not chain off T1
/// because nextest reuses test threads per run and downstream state in a
/// continuation would be brittle to ordering.
#[tokio::test]
#[cfg(feature = "integration")]
async fn test_jailed_validator_unjails_on_recovery() -> color_eyre::Result<()> {
    let (cometbft_bin, felidae_bin) = find_binaries()?;
    let cometbft_path = cometbft_bin.to_str().unwrap().to_owned();
    let felidae_path = felidae_bin.to_str().unwrap().to_owned();

    // ── Phase 0: Bring up a 4-validator devnet with tight thresholds ───────
    let mut network = TestNetwork::create_with_validator_config(
        4,
        block_time(),
        Some(downtime_validator_config()),
    )
    .await?;
    network.start(&cometbft_path, &felidae_path)?;
    network.wait_ready(network_startup_timeout()).await?;

    let rpc_client = HttpClient::new(network.rpc_url().as_str())?;

    let genesis_validators = read_genesis_validator_pubkeys(&network)?;
    let target_pubkey: Vec<u8> = genesis_validators[3].public_key.as_bytes().to_vec();
    let target_identity = genesis_validators[3].public_key.to_string();

    poll_until_async(
        consensus_propagation_wait(),
        poll_interval(),
        "warm up: chain reaches height >= 5",
        || async {
            let block = rpc_client.latest_block().await?;
            Ok(block.block.header.height.value() >= 5)
        },
    )
    .await?;

    // ── Phase 1: Kill validator-3 and wait for the jail transition ─────────
    network.kill_validator(3)?;
    poll_until_async(
        jail_timeout(),
        poll_interval(),
        "validator-3 is jailed (power=1)",
        || async {
            let vals = query_cometbft_validators(&rpc_client).await?;
            Ok(vals.iter().any(|(k, p)| k == &target_pubkey && *p == 1))
        },
    )
    .await?;
    let jailed_info = query_validator_info(&felidae_bin, &network.query_url(), &target_identity)?
        .ok_or_else(|| {
        color_eyre::eyre::eyre!("validator-3 missing from /validators after jail")
    })?;
    assert_eq!(jailed_info.status, ValidatorStatus::Jailed);
    let missed_at_jail = jailed_info.missed_blocks;
    eprintln!("[phase 1] validator-3 jailed with missed_blocks={missed_at_jail}");

    // ── Phase 2: Restart validator-3 and wait for unjail ───────────────────
    network.restart_validator(3, &cometbft_path, &felidae_path)?;
    eprintln!("[phase 2] validator-3 restarted; waiting for unjail");

    // The crucial guarantee from the jailed-but-power=1 design: CometBFT
    // keeps delivering vote info, so the uptime ring buffer keeps advancing.
    // Once signed heights overwrite enough of the missed positions, misses
    // fall below `unjail_missed_max` and the Jailed → Active transition
    // fires inside `jail_inactive_validators`.
    poll_until_async(
        unjail_timeout(),
        poll_interval(),
        "validator-3 unjails: power returns to BASE_VALIDATOR_POWER",
        || async {
            let vals = query_cometbft_validators(&rpc_client).await?;
            Ok(vals
                .iter()
                .any(|(k, p)| k == &target_pubkey && *p == u64::from(BASE_VALIDATOR_POWER)))
        },
    )
    .await?;

    // The query API should reflect the same transition.
    let recovered_info =
        query_validator_info(&felidae_bin, &network.query_url(), &target_identity)?.ok_or_else(
            || color_eyre::eyre::eyre!("validator-3 missing from /validators after unjail"),
        )?;
    assert_eq!(
        recovered_info.status,
        ValidatorStatus::Active,
        "validator-3 should be Active after uptime recovery, got {:?}",
        recovered_info.status
    );
    assert_eq!(
        recovered_info.power,
        u64::from(BASE_VALIDATOR_POWER),
        "validator-3 should be back at BASE_VALIDATOR_POWER, got {}",
        recovered_info.power
    );
    assert!(
        recovered_info.missed_blocks <= recovered_info.unjail_missed_max,
        "recovered missed_blocks ({}) should be at or below the unjail threshold ({})",
        recovered_info.missed_blocks,
        recovered_info.unjail_missed_max,
    );
    eprintln!(
        "[phase 2] validator-3 recovered: status={}, missed_blocks={}/{}",
        recovered_info.status, recovered_info.missed_blocks, recovered_info.uptime_window,
    );

    Ok(())
}

/// Verifies the chain stays live across a sustained jail — not just for a
/// single block, but for at least ten consecutive blocks after the jail
/// transition.
///
/// T1 already checks that one extra block lands after jailing fires, which
/// catches "jail breaks consensus entirely" but doesn't catch "chain
/// produces a block then immediately stalls". Polling for ten more is
/// cheap and gives a sturdier signal of sustained liveness.
///
/// Uses N=4 so quorum = ⌈2·N/3⌉+1 = 3: with one validator jailed the
/// surviving three still constitute a quorum. (N=3, where the test plan's
/// original title pointed, has zero fault tolerance — the chain would
/// stall the moment a validator is killed, and the test would never reach
/// its first assertion.)
#[tokio::test]
#[cfg(feature = "integration")]
async fn test_chain_survives_one_jailed_of_four() -> color_eyre::Result<()> {
    let (cometbft_bin, felidae_bin) = find_binaries()?;

    let mut network = TestNetwork::create_with_validator_config(
        4,
        block_time(),
        Some(downtime_validator_config()),
    )
    .await?;
    network.start(
        cometbft_bin.to_str().unwrap(),
        felidae_bin.to_str().unwrap(),
    )?;
    network.wait_ready(network_startup_timeout()).await?;

    let rpc_client = HttpClient::new(network.rpc_url().as_str())?;

    let genesis_validators = read_genesis_validator_pubkeys(&network)?;
    let target_pubkey: Vec<u8> = genesis_validators[3].public_key.as_bytes().to_vec();

    poll_until_async(
        consensus_propagation_wait(),
        poll_interval(),
        "warm up: chain reaches height >= 5",
        || async {
            let block = rpc_client.latest_block().await?;
            Ok(block.block.header.height.value() >= 5)
        },
    )
    .await?;

    network.kill_validator(3)?;
    poll_until_async(
        jail_timeout(),
        poll_interval(),
        "validator-3 is jailed (power=1)",
        || async {
            let vals = query_cometbft_validators(&rpc_client).await?;
            Ok(vals.iter().any(|(k, p)| k == &target_pubkey && *p == 1))
        },
    )
    .await?;

    // Snapshot the post-jail height, then poll for height advancement of
    // at least 10 blocks. This guards against the failure mode where the
    // chain produces one block after jailing and then stalls — which T1
    // would not detect.
    let baseline_height = rpc_client.latest_block().await?.block.header.height.value();
    let target_height = baseline_height + 10;
    eprintln!(
        "[liveness] post-jail baseline={baseline_height}, polling for height >= {target_height}"
    );

    // 10 blocks at block_time + slack for proposal timeouts on the absent
    // jailed validator's slot. `block_time * 25 + 30s` covers worst-case
    // 4× propose timeouts at 3s each on top of the 10 blocks.
    let liveness_timeout = block_time() * 25 + Duration::from_secs(30);
    poll_until_async(
        liveness_timeout,
        poll_interval(),
        "chain advances 10 blocks after jailing",
        || async {
            let block = rpc_client.latest_block().await?;
            Ok(block.block.header.height.value() >= target_height)
        },
    )
    .await?;

    // Validator-3 should still be present at power=1 (jailed marker), not
    // dropped from the set and not silently restored.
    let after_liveness = query_cometbft_validators(&rpc_client).await?;
    let v3_entry = after_liveness
        .iter()
        .find(|(k, _)| k == &target_pubkey)
        .expect("validator-3 should still appear in the CometBFT validator set");
    assert_eq!(
        v3_entry.1, 1,
        "validator-3 should remain jailed (power=1) while still down, got {}",
        v3_entry.1
    );

    let final_height = rpc_client.latest_block().await?.block.header.height.value();
    eprintln!(
        "[liveness] chain produced {} blocks after jail ({} → {})",
        final_height - baseline_height,
        baseline_height,
        final_height,
    );

    Ok(())
}

/// Pins the `power=1` design invariant: a jailed validator must keep
/// receiving vote info from CometBFT so its uptime tracker advances and
/// it can recover from jail on its own.
///
/// If a future refactor were to set jailed power to 0, `active_validators`
/// would stop returning the jailed validator and `mark_validators_voted`
/// would no longer update its `Uptime` bitvec. This test would then fail:
/// the missed-blocks counter would freeze at its jail-time value rather
/// than continue climbing.
///
/// We deliberately do not restart validator-3 here — the goal is to watch
/// its miss count grow while it stays down.
#[tokio::test]
#[cfg(feature = "integration")]
async fn test_jailed_validator_uptime_still_tracked() -> color_eyre::Result<()> {
    let (cometbft_bin, felidae_bin) = find_binaries()?;

    let mut network = TestNetwork::create_with_validator_config(
        4,
        block_time(),
        Some(downtime_validator_config()),
    )
    .await?;
    network.start(
        cometbft_bin.to_str().unwrap(),
        felidae_bin.to_str().unwrap(),
    )?;
    network.wait_ready(network_startup_timeout()).await?;

    let rpc_client = HttpClient::new(network.rpc_url().as_str())?;

    let genesis_validators = read_genesis_validator_pubkeys(&network)?;
    let target_pubkey: Vec<u8> = genesis_validators[3].public_key.as_bytes().to_vec();
    let target_identity = genesis_validators[3].public_key.to_string();

    poll_until_async(
        consensus_propagation_wait(),
        poll_interval(),
        "warm up: chain reaches height >= 5",
        || async {
            let block = rpc_client.latest_block().await?;
            Ok(block.block.header.height.value() >= 5)
        },
    )
    .await?;

    network.kill_validator(3)?;
    poll_until_async(
        jail_timeout(),
        poll_interval(),
        "validator-3 is jailed",
        || async {
            let vals = query_cometbft_validators(&rpc_client).await?;
            Ok(vals.iter().any(|(k, p)| k == &target_pubkey && *p == 1))
        },
    )
    .await?;

    // Snapshot the missed-blocks counter immediately after jail. The ring
    // buffer has `window_len` slots, so misses cannot exceed that bound;
    // we'll watch the counter rise from its jail-time value toward the
    // window length.
    let initial = query_validator_info(&felidae_bin, &network.query_url(), &target_identity)?
        .ok_or_else(|| {
            color_eyre::eyre::eyre!(
                "validator-3 should be visible via /validators/{target_identity} while jailed"
            )
        })?;
    assert_eq!(initial.status, ValidatorStatus::Jailed);
    let missed_at_jail = initial.missed_blocks;
    let height_at_jail = rpc_client.latest_block().await?.block.header.height.value();
    eprintln!(
        "[t4] at jail: height={height_at_jail}, missed_blocks={missed_at_jail}, window={}",
        initial.uptime_window
    );

    // Wait for several more blocks while v3 stays down. If the power=1
    // invariant holds, `mark_validators_voted` continues running on v3 and
    // each missed block ticks the counter up by one — until the bitvec
    // saturates at `uptime_window`.
    let blocks_to_wait = 8u64;
    let target_height = height_at_jail + blocks_to_wait;
    poll_until_async(
        block_time() * (blocks_to_wait as u32 * 3) + Duration::from_secs(30),
        poll_interval(),
        &format!("chain advances {blocks_to_wait} more blocks past jail"),
        || async {
            let block = rpc_client.latest_block().await?;
            Ok(block.block.header.height.value() >= target_height)
        },
    )
    .await?;

    let later = query_validator_info(&felidae_bin, &network.query_url(), &target_identity)?
        .ok_or_else(|| {
            color_eyre::eyre::eyre!(
                "validator-3 should still be visible via /validators/{target_identity}"
            )
        })?;
    assert_eq!(
        later.status,
        ValidatorStatus::Jailed,
        "validator-3 should still be jailed; it never restarted"
    );
    assert_eq!(
        later.power, 1,
        "jailed power must remain 1 so vote info keeps flowing"
    );
    let cap = later.uptime_window;
    assert!(
        later.missed_blocks > missed_at_jail || later.missed_blocks == cap,
        "missed_blocks should keep advancing past the jail-time value while \
         validator-3 stays down ({} → {}, window={})",
        missed_at_jail,
        later.missed_blocks,
        cap,
    );
    assert!(
        later.missed_blocks <= cap,
        "missed_blocks ({}) must not exceed uptime_window ({})",
        later.missed_blocks,
        cap,
    );
    eprintln!(
        "[t4] after {} more blocks: missed_blocks={} (was {}, capped at {})",
        blocks_to_wait, later.missed_blocks, missed_at_jail, cap
    );

    Ok(())
}
