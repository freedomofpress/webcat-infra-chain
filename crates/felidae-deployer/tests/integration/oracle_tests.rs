//! Oracle observation integration tests.
//!
//! This module contains tests for the oracle observation system, including
//! vote submission, quorum detection, enrollment, unenrollment, and edge cases.

use felidae_types::KeyPair;
use tendermint_rpc::{Client, HttpClient};

use crate::binaries::find_binaries;
use crate::constants::{
    TEST_DOMAIN_EXAMPLE, TEST_DOMAIN_UNENROLL, TEST_DOMAIN_WEBCAT, TEST_DOMAINS,
    TEST_SUBDOMAIN_PREFIX_1, TEST_SUBDOMAIN_PREFIX_2, consensus_propagation_wait,
    consensus_propagation_wait_long, inter_tx_delay, network_startup_timeout, poll_interval,
    test_enrollment_json,
};
use crate::harness::TestNetwork;
use crate::helpers::{
    poll_until, query_config, query_enrollment_pending, query_enrollment_votes, query_snapshot,
    run_query_command, submit_observation,
};

/// Verifies that a 3-validator network can successfully bootstrap and produce blocks.
///
/// # Business Logic Tested
///
/// This test validates the foundational infrastructure that all other tests depend on:
///
/// 1. **Network Generation**: The `felidae-deployer` correctly generates:
///    - CometBFT configuration files (config.toml, genesis.json)
///    - Validator keys (node keys, priv_validator_key.json)
///    - Felidae keys (admin and oracle ECDSA-P256 keypairs)
///
/// 2. **Process Orchestration**: All 6 processes start successfully:
///    - 3 CometBFT nodes forming the consensus network
///    - 3 Felidae ABCI applications handling state
///
/// 3. **Consensus Bootstrap**: The network achieves consensus:
///    - Validators discover each other via persistent peers
///    - Block proposals are created and voted on
///    - Blocks are committed (height ≥ 2 indicates multiple rounds)
///
/// 4. **ABCI Integration**: The Felidae query API is accessible:
///    - HTTP server binds successfully
///    - `/config` endpoint returns the genesis configuration
///
/// # Failure Modes
///
/// - Port conflicts (another process using the test ports)
/// - Missing binaries (cometbft not in PATH, felidae build failure)
/// - Network partition (validators can't reach each other)
/// - ABCI handshake failure (version mismatch, protocol error)
/// - Oracle server startup failure
#[tokio::test]
#[cfg(feature = "integration")]
async fn test_three_validator_network_starts() -> color_eyre::Result<()> {
    let (cometbft_bin, felidae_bin) = find_binaries()?;

    let mut network = TestNetwork::create(3).await?;
    network.start(
        cometbft_bin.to_str().unwrap(),
        felidae_bin.to_str().unwrap(),
    )?;

    // Wait for network to be ready (blocks being produced indicates healthy consensus)
    network.wait_ready(network_startup_timeout()).await?;

    // Wait for oracle servers to be ready (health check returns OK)
    network
        .wait_oracles_ready(network_startup_timeout())
        .await?;

    // Verify the Felidae query API is operational via CLI
    let config = query_config(&felidae_bin, &network.query_url())?;
    eprintln!("[test] chain config via CLI: version={}", config.version);

    // Verify oracle servers are accessible
    for i in 0..3 {
        eprintln!("[test] oracle {} URL: {}", i, network.oracle_url(i));
    }

    Ok(())
}

/// Verifies that a single oracle can submit an observation and it appears in the vote queue.
///
/// # Business Logic Tested
///
/// This test exercises the vote submission path without reaching quorum:
///
/// 1. **Transaction Validation** (CheckTx):
///    - Oracle signature is valid ECDSA-P256
///    - Oracle public key is in the authorized list
///    - Chain ID matches the network
///    - Blockstamp is recent and valid
///
/// 2. **Vote Recording** (DeliverTx):
///    - Observation is parsed and validated
///    - Domain/zone relationship is verified
///    - Vote is stored in the vote queue keyed by domain
///
/// 3. **Query API**:
///    - `/enrollment/votes` returns the pending vote
///    - Domain-specific endpoint `/enrollment/votes/{domain}` works
///
/// # Why No Canonical Entry?
///
/// With only 1 of 3 oracles voting, quorum (3) is not reached. The observation
/// remains in the vote queue indefinitely until either:
/// - More oracles vote for the same hash (reaching quorum)
/// - The vote times out (after 300 seconds in test config)
#[tokio::test]
#[cfg(feature = "integration")]
async fn test_oracle_observation_single_domain() -> color_eyre::Result<()> {
    let (cometbft_bin, felidae_bin) = find_binaries()?;

    let mut network = TestNetwork::create(3).await?;
    network.start(
        cometbft_bin.to_str().unwrap(),
        felidae_bin.to_str().unwrap(),
    )?;
    network.wait_ready(network_startup_timeout()).await?;

    let rpc_client = HttpClient::new(network.rpc_url().as_str())?;

    // Debug: Verify the chain configuration is as expected via CLI
    let config = query_config(&felidae_bin, &network.query_url())?;
    eprintln!("[test] chain config version: {}", config.version);

    // Load the first oracle's signing key for transaction creation
    let oracle_key = network.read_oracle_key(0)?;
    let keypair = KeyPair::decode(&oracle_key)?;
    let oracle_pubkey = keypair.public_key();
    eprintln!(
        "[test] using oracle key (PKCS#8 len={}), pubkey={}",
        oracle_key.len(),
        hex::encode(&oracle_pubkey)
    );
    let enrollment = test_enrollment_json();
    eprintln!("[test] enrollment: {}", enrollment);

    // Submit observation - this creates a vote but won't reach quorum alone
    submit_observation(
        &rpc_client,
        &oracle_key,
        crate::constants::TEST_CHAIN_ID,
        TEST_DOMAIN_WEBCAT.0,
        TEST_DOMAIN_WEBCAT.1,
        Some(&enrollment),
    )
    .await?;

    // Poll for the vote to appear in the query API
    // Note: votes may not appear immediately due to block timing
    let mut found = false;
    for attempt in 1..=10 {
        tokio::time::sleep(poll_interval()).await;

        let block = rpc_client.latest_block().await?;
        let height = block.block.header.height.value();

        let votes = query_enrollment_votes(&felidae_bin, &network.query_url())?;
        let pending = query_enrollment_pending(&felidae_bin, &network.query_url())?;

        // Test the domain-specific vote query via CLI (with --domain filter)
        let domain_votes_output = run_query_command(
            &felidae_bin,
            "enrollment-votes",
            &network.query_url(),
            &["--domain", TEST_DOMAIN_WEBCAT.0.trim_end_matches('.')],
        )?;

        eprintln!(
            "[test] attempt {} (height={}): votes={:?}, pending={:?}, domain_votes={}",
            attempt, height, votes, pending, domain_votes_output
        );

        // Vote should appear in votes (not pending, since no quorum yet)
        if !votes.is_empty() || !pending.is_empty() {
            eprintln!(
                "[test] found {} votes, {} pending",
                votes.len(),
                pending.len()
            );
            found = true;
            break;
        }
    }

    assert!(
        found,
        "expected vote or pending for {} domain after 10 attempts",
        TEST_DOMAIN_WEBCAT.0
    );

    Ok(())
}

/// Verifies that observations reaching quorum are promoted to canonical state.
///
/// # Business Logic Tested
///
/// This is the **primary happy path** for domain enrollment in WEBCAT:
///
/// 1. **Vote Accumulation**:
///    - All 3 oracles submit observations for the same domain
///    - Each observation contains the same enrollment hash
///    - Votes accumulate in the vote queue
///
/// 2. **Quorum Detection** (VoteQueue::cast):
///    - After vote 3 is cast, quorum (3/3) is reached
///    - All votes for this domain are consumed
///    - The observation moves to "pending" state
///    - A timer starts for the delay period
///
/// 3. **Pending Promotion** (EndBlock):
///    - At each block end, pending changes are checked
///    - If `now - pending_time >= delay` (1s in tests), the change promotes
///    - The domain→hash mapping is written to the canonical substore
///
/// 4. **Canonical Query**:
///    - `/snapshot` returns the finalized mapping
///    - The enrollment hash is now visible to WEBCAT clients
#[tokio::test]
#[cfg(feature = "integration")]
async fn test_oracle_quorum_reached() -> color_eyre::Result<()> {
    let (cometbft_bin, felidae_bin) = find_binaries()?;

    let mut network = TestNetwork::create(3).await?;
    network.start(
        cometbft_bin.to_str().unwrap(),
        felidae_bin.to_str().unwrap(),
    )?;
    network.wait_ready(network_startup_timeout()).await?;

    let rpc_client = HttpClient::new(network.rpc_url().as_str())?;

    let enrollment = test_enrollment_json();

    // Submit observations from all 3 oracles for the same domain.
    // Each oracle independently observes the enrollment and submits a vote.
    // All votes have the same hash because they observe the same enrollment.
    for i in 0..3 {
        let oracle_key = network.read_oracle_key(i)?;
        submit_observation(
            &rpc_client,
            &oracle_key,
            crate::constants::TEST_CHAIN_ID,
            TEST_DOMAIN_EXAMPLE.0,
            TEST_DOMAIN_EXAMPLE.1,
            Some(&enrollment),
        )
        .await?;

        // Brief delay to ensure transactions are sequenced properly
        tokio::time::sleep(inter_tx_delay()).await;
    }

    // Poll for quorum and promotion instead of fixed sleep
    poll_until(
        consensus_propagation_wait_long(),
        poll_interval(),
        &format!("{} in canonical snapshot", TEST_DOMAIN_EXAMPLE.0),
        || {
            Ok(query_snapshot(&felidae_bin, &network.query_url())?
                .contains_key(TEST_DOMAIN_EXAMPLE.0))
        },
    )
    .await?;

    // Query the canonical snapshot via CLI - the enrollment should now be visible
    let snapshot = query_snapshot(&felidae_bin, &network.query_url())?;
    eprintln!("[test] snapshot: {:?}", snapshot);

    // Verify the domain appears in canonical state with the expected hash
    assert!(
        snapshot.contains_key(TEST_DOMAIN_EXAMPLE.0),
        "expected {} in canonical snapshot after quorum and delay",
        TEST_DOMAIN_EXAMPLE.0
    );

    Ok(())
}

/// Verifies that multiple domains can be enrolled concurrently.
#[tokio::test]
#[cfg(feature = "integration")]
async fn test_oracle_observation_multiple_domains() -> color_eyre::Result<()> {
    let (cometbft_bin, felidae_bin) = find_binaries()?;

    let mut network = TestNetwork::create(3).await?;
    network.start(
        cometbft_bin.to_str().unwrap(),
        felidae_bin.to_str().unwrap(),
    )?;
    network.wait_ready(network_startup_timeout()).await?;

    let rpc_client = HttpClient::new(network.rpc_url().as_str())?;

    let enrollment = test_enrollment_json();

    // Submit observations from all oracles for both test domains sequentially.
    for (domain, zone) in TEST_DOMAINS {
        for i in 0..3 {
            let oracle_key = network.read_oracle_key(i)?;
            submit_observation(
                &rpc_client,
                &oracle_key,
                crate::constants::TEST_CHAIN_ID,
                domain,
                zone,
                Some(&enrollment),
            )
            .await?;
            tokio::time::sleep(inter_tx_delay()).await;
        }
    }

    // Poll for both domains to reach quorum and be promoted
    poll_until(
        consensus_propagation_wait_long(),
        poll_interval(),
        "both domains in canonical snapshot",
        || {
            let snapshot = query_snapshot(&felidae_bin, &network.query_url())?;
            Ok(snapshot.contains_key(TEST_DOMAIN_WEBCAT.0)
                && snapshot.contains_key(TEST_DOMAIN_EXAMPLE.0))
        },
    )
    .await?;

    // Query the canonical snapshot via CLI
    let snapshot = query_snapshot(&felidae_bin, &network.query_url())?;
    eprintln!("[test] snapshot: {:?}", snapshot);

    // Both domains should appear in the canonical state
    assert!(
        snapshot.contains_key(TEST_DOMAIN_WEBCAT.0),
        "expected {} in canonical snapshot",
        TEST_DOMAIN_WEBCAT.0
    );
    assert!(
        snapshot.contains_key(TEST_DOMAIN_EXAMPLE.0),
        "expected {} in canonical snapshot",
        TEST_DOMAIN_EXAMPLE.0
    );

    Ok(())
}

/// Verifies that domains can be unenrolled by observing NotFound.
#[tokio::test]
#[cfg(feature = "integration")]
async fn test_oracle_unenrollment() -> color_eyre::Result<()> {
    let (cometbft_bin, felidae_bin) = find_binaries()?;

    let mut network = TestNetwork::create(3).await?;
    network.start(
        cometbft_bin.to_str().unwrap(),
        felidae_bin.to_str().unwrap(),
    )?;
    network.wait_ready(network_startup_timeout()).await?;

    let rpc_client = HttpClient::new(network.rpc_url().as_str())?;

    let enrollment = test_enrollment_json();

    // PHASE 1: Enroll the domain first
    eprintln!(
        "[test] Step 1: Enrolling domain {}.",
        TEST_DOMAIN_UNENROLL.0
    );
    for i in 0..3 {
        let oracle_key = network.read_oracle_key(i)?;
        submit_observation(
            &rpc_client,
            &oracle_key,
            crate::constants::TEST_CHAIN_ID,
            TEST_DOMAIN_UNENROLL.0,
            TEST_DOMAIN_UNENROLL.1,
            Some(&enrollment),
        )
        .await?;
        tokio::time::sleep(inter_tx_delay()).await;
    }

    // Poll for enrollment to become canonical
    poll_until(
        consensus_propagation_wait_long(),
        poll_interval(),
        &format!("{} enrolled", TEST_DOMAIN_UNENROLL.0),
        || {
            Ok(query_snapshot(&felidae_bin, &network.query_url())?
                .contains_key(TEST_DOMAIN_UNENROLL.0))
        },
    )
    .await?;

    // Verify the domain was enrolled via CLI
    let snapshot = query_snapshot(&felidae_bin, &network.query_url())?;
    eprintln!("[test] snapshot after enrollment: {:?}", snapshot);
    assert!(
        snapshot.contains_key(TEST_DOMAIN_UNENROLL.0),
        "expected {} to be enrolled first",
        TEST_DOMAIN_UNENROLL.0
    );

    // PHASE 2: Unenroll the domain
    eprintln!(
        "[test] Step 2: Unenrolling domain {}.",
        TEST_DOMAIN_UNENROLL.0
    );
    for i in 0..3 {
        let oracle_key = network.read_oracle_key(i)?;
        submit_observation(
            &rpc_client,
            &oracle_key,
            crate::constants::TEST_CHAIN_ID,
            TEST_DOMAIN_UNENROLL.0,
            TEST_DOMAIN_UNENROLL.1,
            None, // Without enrollment = NotFound = delete mapping
        )
        .await?;
        tokio::time::sleep(inter_tx_delay()).await;
    }

    // Poll for unenrollment to become canonical
    poll_until(
        consensus_propagation_wait_long(),
        poll_interval(),
        &format!("{} unenrolled", TEST_DOMAIN_UNENROLL.0),
        || {
            Ok(!query_snapshot(&felidae_bin, &network.query_url())?
                .contains_key(TEST_DOMAIN_UNENROLL.0))
        },
    )
    .await?;

    // Verify the domain was removed from canonical state via CLI
    let snapshot = query_snapshot(&felidae_bin, &network.query_url())?;
    eprintln!("[test] snapshot after unenrollment: {:?}", snapshot);
    assert!(
        !snapshot.contains_key(TEST_DOMAIN_UNENROLL.0),
        "expected {} to be unenrolled",
        TEST_DOMAIN_UNENROLL.0
    );

    Ok(())
}

/// Verifies that observations from unauthorized oracles are rejected.
#[tokio::test]
#[cfg(feature = "integration")]
async fn test_unauthorized_oracle_rejected() -> color_eyre::Result<()> {
    let (cometbft_bin, felidae_bin) = find_binaries()?;

    let mut network = TestNetwork::create(3).await?;
    network.start(
        cometbft_bin.to_str().unwrap(),
        felidae_bin.to_str().unwrap(),
    )?;
    network.wait_ready(network_startup_timeout()).await?;

    let rpc_client = HttpClient::new(network.rpc_url().as_str())?;

    // Generate a deterministic key that is NOT in the authorized oracle list.
    let unauthorized_key = {
        use p256::ecdsa::SigningKey;
        use p256::elliptic_curve::generic_array::GenericArray;
        let secret_bytes: [u8; 32] = [
            0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
            0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
            0x19, 0x1A, 0x1B, 0x1C,
        ];
        let signing_key = SigningKey::from_bytes(GenericArray::from_slice(&secret_bytes)).unwrap();
        use p256::pkcs8::EncodePrivateKey;
        signing_key.to_pkcs8_der().unwrap().as_bytes().to_vec()
    };

    let enrollment = test_enrollment_json();

    // Attempt to submit observation with unauthorized key.
    let result = submit_observation(
        &rpc_client,
        &unauthorized_key,
        crate::constants::TEST_CHAIN_ID,
        TEST_DOMAIN_WEBCAT.0,
        TEST_DOMAIN_WEBCAT.1,
        Some(&enrollment),
    )
    .await;

    // The transaction should be rejected
    assert!(
        result.is_err(),
        "expected unauthorized oracle submission to fail"
    );

    let err_msg = result.unwrap_err().to_string();

    assert!(
        err_msg.contains("not a current oracle") || err_msg.contains("transaction failed"),
        "expected 'not a current oracle' error, got: {}",
        err_msg
    );

    eprintln!("[test] confirmed receipt of rejection error: {}", err_msg);

    Ok(())
}

/// Verifies that partial quorum (below threshold) does not result in canonical entry.
#[tokio::test]
#[cfg(feature = "integration")]
async fn test_partial_quorum_no_canonical() -> color_eyre::Result<()> {
    let (cometbft_bin, felidae_bin) = find_binaries()?;

    let mut network = TestNetwork::create(3).await?;
    network.start(
        cometbft_bin.to_str().unwrap(),
        felidae_bin.to_str().unwrap(),
    )?;
    network.wait_ready(network_startup_timeout()).await?;

    let rpc_client = HttpClient::new(network.rpc_url().as_str())?;

    let enrollment = test_enrollment_json();

    // Use a subdomain that other tests don't use for quorum
    let partial_domain = format!("{}.{}", TEST_SUBDOMAIN_PREFIX_1, TEST_DOMAIN_WEBCAT.0);

    // Submit observations from only 2 of 3 oracles.
    for i in 0..2 {
        let oracle_key = network.read_oracle_key(i)?;
        submit_observation(
            &rpc_client,
            &oracle_key,
            crate::constants::TEST_CHAIN_ID,
            &partial_domain,
            TEST_DOMAIN_WEBCAT.1,
            Some(&enrollment),
        )
        .await?;
        tokio::time::sleep(inter_tx_delay()).await;
    }

    // Wait for potential processing (should not reach quorum)
    tokio::time::sleep(consensus_propagation_wait()).await;

    // Verify votes exist in the vote queue via CLI
    let votes = query_enrollment_votes(&felidae_bin, &network.query_url())?;
    eprintln!("[test] votes after partial quorum: {:?}", votes);

    // Votes should still be in the queue (not consumed by quorum)
    let partial_votes: Vec<_> = votes
        .iter()
        .filter(|v| v.domain.to_string() == partial_domain)
        .collect();
    assert_eq!(
        partial_votes.len(),
        2,
        "expected 2 votes in queue for {}, got {}",
        partial_domain,
        partial_votes.len()
    );

    // Verify the domain is NOT in canonical state via CLI
    let snapshot = query_snapshot(&felidae_bin, &network.query_url())?;
    eprintln!("[test] snapshot: {:?}", snapshot);

    assert!(
        !snapshot.contains_key(&partial_domain),
        "{} should NOT be in canonical snapshot without quorum",
        partial_domain
    );

    Ok(())
}

/// Verifies that enrollment can be updated by voting for a new hash.
#[tokio::test]
#[cfg(feature = "integration")]
async fn test_enrollment_update() -> color_eyre::Result<()> {
    let (cometbft_bin, felidae_bin) = find_binaries()?;

    let mut network = TestNetwork::create(3).await?;
    network.start(
        cometbft_bin.to_str().unwrap(),
        felidae_bin.to_str().unwrap(),
    )?;
    network.wait_ready(network_startup_timeout()).await?;

    let rpc_client = HttpClient::new(network.rpc_url().as_str())?;

    // Use a subdomain for update testing
    let update_domain = format!("{}.{}", TEST_SUBDOMAIN_PREFIX_2, TEST_DOMAIN_WEBCAT.0);

    // PHASE 1: Initial enrollment with enrollment_v1
    let enrollment_v1 = test_enrollment_json();

    eprintln!("[test] Phase 1: Initial enrollment for {}", update_domain);
    for i in 0..3 {
        let oracle_key = network.read_oracle_key(i)?;
        submit_observation(
            &rpc_client,
            &oracle_key,
            crate::constants::TEST_CHAIN_ID,
            &update_domain,
            TEST_DOMAIN_WEBCAT.1,
            Some(&enrollment_v1),
        )
        .await?;
        tokio::time::sleep(inter_tx_delay()).await;
    }

    // Poll for initial enrollment
    poll_until(
        consensus_propagation_wait_long(),
        poll_interval(),
        &format!("{update_domain} enrolled (v1)"),
        || Ok(query_snapshot(&felidae_bin, &network.query_url())?.contains_key(&update_domain)),
    )
    .await?;

    // Verify initial enrollment via CLI
    let snapshot_v1 = query_snapshot(&felidae_bin, &network.query_url())?;
    eprintln!("[test] snapshot after v1: {:?}", snapshot_v1);

    let hash_v1 = snapshot_v1.get(&update_domain).unwrap().clone();

    // PHASE 2: Update enrollment with a different enrollment (different hash)
    let enrollment_v2 = {
        use ed25519_dalek::SigningKey;
        let signing_key = SigningKey::from_bytes(&[2u8; 32]); // Different seed!
        let verifying_key = signing_key.verifying_key();
        let test_pubkey = base64_url::encode(verifying_key.as_bytes());

        serde_json::json!({
            "type": "sigsum",
            "signers": [test_pubkey],
            "threshold": 1,
            "policy": "BBBB",
            "max_age": 86400,
            "cas_url": "https://example.com/cas/v2",
            "logs": {}
        })
        .to_string()
    };

    eprintln!("[test] Phase 2: Update enrollment for {}", update_domain);
    for i in 0..3 {
        let oracle_key = network.read_oracle_key(i)?;
        submit_observation(
            &rpc_client,
            &oracle_key,
            crate::constants::TEST_CHAIN_ID,
            &update_domain,
            TEST_DOMAIN_WEBCAT.1,
            Some(&enrollment_v2),
        )
        .await?;
        tokio::time::sleep(inter_tx_delay()).await;
    }

    // Poll for the enrollment hash to change
    let hash_v1_ref = hash_v1.clone();
    poll_until(
        consensus_propagation_wait_long(),
        poll_interval(),
        &format!("{update_domain} enrollment hash updated"),
        || {
            let snapshot = query_snapshot(&felidae_bin, &network.query_url())?;
            Ok(snapshot
                .get(&update_domain)
                .map_or(false, |h| *h != hash_v1_ref))
        },
    )
    .await?;

    // Verify the enrollment was updated via CLI
    let snapshot_v2 = query_snapshot(&felidae_bin, &network.query_url())?;
    eprintln!("[test] snapshot after v2: {:?}", snapshot_v2);

    let hash_v2 = snapshot_v2.get(&update_domain).unwrap().clone();

    // The hash should have changed
    assert_ne!(
        hash_v1, hash_v2,
        "enrollment hash should change after update"
    );

    eprintln!("[test] hash changed: {} -> {}", hash_v1, hash_v2);

    Ok(())
}

/// Verifies that the subdomain limit is enforced per registered domain.
#[tokio::test]
#[cfg(feature = "integration")]
async fn test_subdomain_limit_enforcement() -> color_eyre::Result<()> {
    let (cometbft_bin, felidae_bin) = find_binaries()?;

    let mut network = TestNetwork::create(3).await?;
    network.start(
        cometbft_bin.to_str().unwrap(),
        felidae_bin.to_str().unwrap(),
    )?;
    network.wait_ready(network_startup_timeout()).await?;

    let rpc_client = HttpClient::new(network.rpc_url().as_str())?;

    let enrollment = test_enrollment_json();

    let (registered_domain, zone) = TEST_DOMAIN_EXAMPLE;

    // Create domains: the registered domain + 4 subdomains = 5 total (exactly at limit)
    let subdomains: Vec<String> = vec![
        registered_domain.to_string(),
        format!("{}.{}", TEST_SUBDOMAIN_PREFIX_1, registered_domain),
        format!("{}.{}", TEST_SUBDOMAIN_PREFIX_2, registered_domain),
        format!("{}1.{}", TEST_SUBDOMAIN_PREFIX_1, registered_domain),
        format!("{}1.{}", TEST_SUBDOMAIN_PREFIX_2, registered_domain),
    ];

    // PHASE 1: Enroll 5 entries under the registered domain (fills the limit exactly)
    eprintln!("[test] Phase 1: Enrolling {} entries", subdomains.len());

    for (idx, subdomain) in subdomains.iter().enumerate() {
        eprintln!("[test] Enrolling entry {}: {}", idx, subdomain);

        for i in 0..3 {
            let oracle_key = network.read_oracle_key(i)?;
            submit_observation(
                &rpc_client,
                &oracle_key,
                crate::constants::TEST_CHAIN_ID,
                subdomain,
                zone,
                Some(&enrollment),
            )
            .await?;
            tokio::time::sleep(inter_tx_delay()).await;
        }

        // Poll for this entry to reach canonical state before enrolling next
        let sd = subdomain.clone();
        poll_until(
            consensus_propagation_wait_long(),
            poll_interval(),
            &format!("{sd} enrolled"),
            || Ok(query_snapshot(&felidae_bin, &network.query_url())?.contains_key(&sd)),
        )
        .await?;
    }

    // Verify all entries are enrolled via CLI
    let snapshot = query_snapshot(&felidae_bin, &network.query_url())?;
    eprintln!("[test] snapshot after enrollments: {:?}", snapshot);

    for subdomain in &subdomains {
        assert!(
            snapshot.contains_key(subdomain),
            "entry {} should be enrolled",
            subdomain
        );
    }

    // PHASE 2: Attempt to enroll another subdomain (should fail, limit is 5)
    eprintln!("[test] Phase 2: Attempting 6th entry (should fail)");

    let over_limit_subdomain = format!("{}2.{}", TEST_SUBDOMAIN_PREFIX_2, registered_domain);

    let mut rejected = false;
    for i in 0..3 {
        let oracle_key = network.read_oracle_key(i)?;
        let result = submit_observation(
            &rpc_client,
            &oracle_key,
            crate::constants::TEST_CHAIN_ID,
            &over_limit_subdomain,
            zone,
            Some(&enrollment),
        )
        .await;

        if result.is_err() {
            let err_msg = result.unwrap_err().to_string();
            eprintln!("[test] over-limit subdomain rejected: {}", err_msg);
            rejected = true;
            break;
        }
        tokio::time::sleep(inter_tx_delay()).await;
    }

    // Give time for any processing
    tokio::time::sleep(consensus_propagation_wait()).await;

    // Verify the over-limit subdomain is NOT in canonical state via CLI
    let snapshot = query_snapshot(&felidae_bin, &network.query_url())?;
    eprintln!("[test] final snapshot: {:?}", snapshot);

    let in_canonical = snapshot.contains_key(&over_limit_subdomain);

    assert!(
        rejected || !in_canonical,
        "over-limit subdomain {} should NOT be enrolled (limit exceeded). rejected={}, in_canonical={}",
        over_limit_subdomain,
        rejected,
        in_canonical
    );

    eprintln!("[test] subdomain limit correctly enforced");

    Ok(())
}
