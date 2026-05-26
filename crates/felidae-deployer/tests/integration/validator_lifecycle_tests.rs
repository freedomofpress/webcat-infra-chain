//! Integration tests covering the validator lifecycle in a live network.
//!
//! These tests sit one level above the pure state-machine unit tests in
//! `crates/felidae-state/src/state/validator.rs::tests`. The unit tests exercise
//! the transition table directly; the tests in this file drive the same
//! transitions through a real CometBFT-in-the-loop deployment so the
//! ABCI/consensus plumbing stays in scope.

use std::time::Duration;

use felidae_state::BASE_VALIDATOR_POWER;
use felidae_types::transaction::{Config, Validator};
use sha2::{Digest, Sha256};
use tendermint_rpc::{Client, HttpClient};

use crate::binaries::find_binaries;
use crate::constants::{
    consensus_propagation_wait, consensus_propagation_wait_long, network_startup_timeout,
    poll_interval,
};
use crate::harness::TestNetwork;
use crate::helpers::{
    poll_until, poll_until_async, query_cometbft_validators, query_config,
    query_validator_info, read_genesis_validator_pubkeys, submit_admin_reconfig,
};

/// Computes the CometBFT 20-byte address for a 32-byte ed25519 public key.
fn cometbft_address(pub_key_bytes: &[u8]) -> [u8; 20] {
    let mut hasher = Sha256::new();
    hasher.update(pub_key_bytes);
    let digest = hasher.finalize();
    let mut address = [0u8; 20];
    address.copy_from_slice(&digest[0..20]);
    address
}

/// Polls the chain for a block whose `last_commit.signatures` contains a
/// positive `BlockIdFlagCommit` signature from the given validator address.
///
/// `last_commit` in block `N` covers block `N-1`, so this proves the
/// validator was an active signer at some height *before* the latest one.
async fn poll_for_validator_signature(
    rpc_client: &HttpClient,
    validator_address: [u8; 20],
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
                        && addr.as_bytes() == validator_address
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
    let target_pubkey: Vec<u8> = genesis_validators[2].public_key.to_vec();
    let target_address = cometbft_address(&target_pubkey);
    let target_identity = hex::encode(&target_pubkey);
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
    poll_until(
        consensus_propagation_wait_long(),
        poll_interval(),
        "phase 1: seed reconfig applied",
        || {
            let cfg = query_config(&felidae_bin, &network.query_url())?;
            Ok(cfg.version >= phase1_target_version && cfg.validators.len() == 3)
        },
    )
    .await?;
    let config_after_seed = query_config(&felidae_bin, &network.query_url())?;
    assert_eq!(config_after_seed.validators.len(), 3);

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
    poll_until(
        consensus_propagation_wait_long(),
        poll_interval(),
        "phase 2: removal reconfig applied in felidae config",
        || {
            let cfg = query_config(&felidae_bin, &network.query_url())?;
            Ok(cfg.version >= phase2_target_version && cfg.validators.len() == 2)
        },
    )
    .await?;

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
        removed_info.status, "inactive",
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
    let config_after_remove = query_config(&felidae_bin, &network.query_url())?;
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
    poll_until(
        consensus_propagation_wait_long(),
        poll_interval(),
        "phase 3: re-add reconfig applied in felidae config",
        || {
            let cfg = query_config(&felidae_bin, &network.query_url())?;
            Ok(cfg.version >= phase3_target_version && cfg.validators.len() == 3)
        },
    )
    .await?;

    poll_until_async(
        consensus_propagation_wait_long(),
        poll_interval(),
        "phase 3: CometBFT restores validator-2 at BASE_VALIDATOR_POWER",
        || async {
            let vals = query_cometbft_validators(&rpc_client).await?;
            Ok(vals.iter().any(|(k, p)| {
                k == &target_pubkey && *p == u64::from(BASE_VALIDATOR_POWER)
            }))
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
        readded_info.status, "active",
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
    eprintln!(
        "[phase 3] validator-2 signed block at height {signed_height} after re-add"
    );

    Ok(())
}
