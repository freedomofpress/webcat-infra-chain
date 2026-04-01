//! Transaction submission and query helper functions.
//!
//! This module provides utilities for submitting transactions to the network
//! and querying state via the felidae CLI.

use std::collections::HashMap;
use std::process::Command;
use std::time::Duration;

use felidae_types::response::{AdminVote, ChainInfo, OracleVote, PendingObservation};
use felidae_types::transaction::Config;
use tendermint_rpc::{Client, HttpClient, Paging};

// =============================================================================
// POLLING UTILITIES
// =============================================================================

/// Polls a synchronous condition until it returns true or timeout is reached.
///
/// Useful for waiting on state changes that propagate through consensus,
/// where the exact timing depends on block production.
pub async fn poll_until(
    timeout: Duration,
    interval: Duration,
    description: &str,
    check: impl Fn() -> color_eyre::Result<bool>,
) -> color_eyre::Result<()> {
    let start = std::time::Instant::now();
    loop {
        match check() {
            Ok(true) => return Ok(()),
            Ok(false) => {}
            Err(e) => eprintln!("[poll_until] {description}: error (retrying): {e}"),
        }
        if start.elapsed() > timeout {
            return Err(color_eyre::eyre::eyre!(
                "condition not met within {timeout:?}: {description}"
            ));
        }
        tokio::time::sleep(interval).await;
    }
}

/// Polls an async condition until it returns true or timeout is reached.
///
/// Like `poll_until` but accepts an async check function, useful for polling
/// async RPC calls (e.g. CometBFT validator queries).
pub async fn poll_until_async<F, Fut>(
    timeout: Duration,
    interval: Duration,
    description: &str,
    check: F,
) -> color_eyre::Result<()>
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = color_eyre::Result<bool>>,
{
    let start = std::time::Instant::now();
    loop {
        match check().await {
            Ok(true) => return Ok(()),
            Ok(false) => {}
            Err(e) => eprintln!("[poll_until_async] {description}: error (retrying): {e}"),
        }
        if start.elapsed() > timeout {
            return Err(color_eyre::eyre::eyre!(
                "condition not met within {timeout:?}: {description}"
            ));
        }
        tokio::time::sleep(interval).await;
    }
}

// =============================================================================
// TRANSACTION SUBMISSION HELPERS
// =============================================================================

/// Submits a signed oracle observation transaction to the network.
///
/// # Transaction Structure
///
/// Oracle observations are ECDSA-P256 signed transactions containing:
///
/// ```text
/// Transaction {
///   chain_id: "felidae-integration-test",
///   actions: [
///     Observe {
///       oracle: { identity: <P256 pubkey> },
///       observation: {
///         domain: "example.com.",
///         zone: "com.",
///         hash_observed: Hash(<32 bytes>) | NotFound,
///         blockstamp: { block_height: N, app_hash: <32 bytes> }
///       }
///     }
///   ],
///   signatures: [<ECDSA signature>]
/// }
/// ```
///
/// # Blockstamp Validation
///
/// The blockstamp serves as a freshness proof for the observation:
///
/// 1. `block_height` must be ≤ current height (not in the future)
/// 2. `app_hash` must match the recorded app hash at that height
/// 3. The block at `block_height` must be within `observation_timeout` of current time
///
/// This prevents replay attacks and ensures oracles are observing recent state.
///
/// # Transaction Lifecycle
///
/// 1. **CheckTx**: Transaction is validated in the mempool (signature, format)
/// 2. **DeliverTx**: Transaction is executed during block finalization
/// 3. **EndBlock**: Quorum detection and pending promotion occur
/// 4. **Commit**: State changes are persisted
///
/// # Arguments
///
/// - `rpc_client`: CometBFT RPC client for transaction submission
/// - `oracle_key_bytes`: PKCS#8-encoded ECDSA-P256 private key
/// - `chain_id`: Must match the network's chain ID for replay protection
/// - `domain`: Fully qualified domain name to observe
/// - `zone`: Parent zone (domain must be subdomain of zone)
/// - `enrollment_json`: JSON enrollment data, or None for unenrollment
///
/// # Returns
///
/// The transaction hash as a hex string on success.
pub async fn submit_observation(
    rpc_client: &HttpClient,
    oracle_key_bytes: &[u8],
    chain_id: &str,
    domain: &str,
    zone: &str,
    enrollment_json: Option<&str>,
) -> color_eyre::Result<String> {
    // Fetch the latest block to construct a valid blockstamp.
    // We use height-1 because the app_hash in block N reflects state after block N-1.
    let block = rpc_client.latest_block().await?;
    let app_hash = hex::encode(block.block.header.app_hash.as_bytes());
    let height = block.block.header.height.value();
    let prev_height = if height > 0 { height - 1 } else { 0 };

    eprintln!(
        "[submit_observation] domain={}, zone={}, height={}, app_hash={}",
        domain,
        zone,
        prev_height,
        &app_hash[..16]
    );

    // Build and sign the witness transaction using the oracle library.
    // This handles enrollment JSON canonicalization and hash computation.
    let tx_hex = felidae_oracle::witness(
        hex::encode(oracle_key_bytes),
        chain_id.to_string(),
        app_hash,
        prev_height,
        domain.to_string(),
        zone.to_string(),
        enrollment_json.unwrap_or("").to_string(),
    )?;

    // Submit via broadcast_tx_commit for synchronous confirmation.
    // This waits for the transaction to be included in a block.
    let tx_bytes = hex::decode(&tx_hex)?;
    let result = rpc_client.broadcast_tx_commit(tx_bytes).await?;

    eprintln!(
        "[submit_observation] tx committed: hash={}, check_code={:?}, deliver_code={:?}, deliver_log={}",
        hex::encode(result.hash.as_bytes()),
        result.check_tx.code,
        result.tx_result.code,
        result.tx_result.log
    );

    // Non-zero check code indicates the transaction was rejected during mempool validation.
    // This catches issues like unauthorized oracles, invalid signatures, etc.
    if !result.check_tx.code.is_ok() {
        return Err(color_eyre::eyre::eyre!(
            "transaction failed at CheckTx: {}",
            result.check_tx.log
        ));
    }

    // Non-zero deliver code indicates the transaction was rejected during execution.
    // Common reasons: unauthorized oracle, invalid blockstamp, zone mismatch.
    if !result.tx_result.code.is_ok() {
        return Err(color_eyre::eyre::eyre!(
            "transaction failed at DeliverTx: {}",
            result.tx_result.log
        ));
    }

    Ok(hex::encode(result.hash.as_bytes()))
}

// =============================================================================
// QUERY HELPERS (CLI-based via escargot)
// =============================================================================

/// Runs a felidae query subcommand and returns the JSON output.
pub fn run_query_command(
    felidae_bin: &std::path::Path,
    subcommand: &str,
    query_url: &str,
    extra_args: &[&str],
) -> color_eyre::Result<String> {
    let mut cmd = Command::new(felidae_bin);
    cmd.arg("query")
        .arg("--query-url")
        .arg(query_url)
        .arg(subcommand);

    for arg in extra_args {
        cmd.arg(arg);
    }

    let output = cmd.output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(color_eyre::eyre::eyre!(
            "felidae query {} failed: {}",
            subcommand,
            stderr
        ));
    }

    let stdout = String::from_utf8(output.stdout)?;
    eprintln!(
        "[run_query_command] --query-url {} {} => {}",
        query_url, subcommand, stdout
    );
    Ok(stdout)
}

/// Queries the oracle votes via CLI for active votes in the voting queue.
///
/// Votes are in-flight observations that haven't yet reached quorum. Each vote
/// shows which oracle voted for which domain with what hash. Multiple oracles
/// voting for the same (domain, hash) pair will trigger quorum detection.
pub fn query_enrollment_votes(
    felidae_bin: &std::path::Path,
    query_url: &str,
) -> color_eyre::Result<Vec<OracleVote>> {
    let output = run_query_command(felidae_bin, "enrollment-votes", query_url, &[])?;
    let votes: Vec<OracleVote> = serde_json::from_str(&output)?;
    Ok(votes)
}

/// Queries the oracle pending via CLI for observations awaiting promotion.
///
/// Pending observations have reached quorum but are in the delay period before
/// becoming canonical. The delay provides a window for detecting and responding
/// to incorrect observations before they become permanent.
pub fn query_enrollment_pending(
    felidae_bin: &std::path::Path,
    query_url: &str,
) -> color_eyre::Result<Vec<PendingObservation>> {
    let output = run_query_command(felidae_bin, "enrollment-pending", query_url, &[])?;
    let pending: Vec<PendingObservation> = serde_json::from_str(&output)?;
    Ok(pending)
}

/// Queries the admin votes via CLI for active admin reconfiguration votes.
///
/// Admin votes work similarly to oracle votes but vote on the singleton chain
/// configuration rather than individual domains. Each authorized admin can
/// submit a signed reconfiguration vote with a proposed new config.
pub fn query_admin_votes(
    felidae_bin: &std::path::Path,
    query_url: &str,
) -> color_eyre::Result<Vec<AdminVote>> {
    let output = run_query_command(felidae_bin, "admin-votes", query_url, &[])?;
    let votes: Vec<AdminVote> = serde_json::from_str(&output)?;
    Ok(votes)
}

/// Queries the admin pending via CLI for config changes awaiting promotion.
///
/// Similar to enrollment pending, admin pending contains config changes that have
/// reached quorum but are waiting for the configured delay before being applied.
pub fn query_admin_pending(
    felidae_bin: &std::path::Path,
    query_url: &str,
) -> color_eyre::Result<Vec<serde_json::Value>> {
    let output = run_query_command(felidae_bin, "admin-pending", query_url, &[])?;
    let pending: Vec<serde_json::Value> = serde_json::from_str(&output)?;
    Ok(pending)
}

/// Queries the snapshot via CLI for the canonical domain→hash mappings.
///
/// The snapshot represents the finalized state visible to clients. Domains
/// appear here after:
/// 1. Quorum is reached (3/3 oracles agree for our test config)
/// 2. The delay period expires (1 second in tests)
/// 3. The EndBlock handler promotes pending→canonical
///
/// Returns a map from domain name to hex-encoded enrollment hash.
pub fn query_snapshot(
    felidae_bin: &std::path::Path,
    query_url: &str,
) -> color_eyre::Result<HashMap<String, String>> {
    let output = run_query_command(felidae_bin, "snapshot", query_url, &[])?;
    let snapshot: HashMap<String, String> = serde_json::from_str(&output)?;
    Ok(snapshot)
}

/// Queries `felidae query chain-info --json` and parses the result.
pub fn query_chain_info(
    felidae_bin: &std::path::Path,
    query_url: &str,
) -> color_eyre::Result<ChainInfo> {
    let output = run_query_command(felidae_bin, "chain-info", query_url, &["--json"])?;
    let info: ChainInfo = serde_json::from_str(&output)?;
    Ok(info)
}

/// Queries the chain config via CLI.
pub fn query_config(felidae_bin: &std::path::Path, query_url: &str) -> color_eyre::Result<Config> {
    let output = run_query_command(felidae_bin, "config", query_url, &[])?;
    let config: Config = serde_json::from_str(&output)?;
    Ok(config)
}

// =============================================================================
// VALIDATOR HELPERS
// =============================================================================

/// Reads the genesis validator Ed25519 public keys from each validator node's
/// `priv_validator_key.json` and returns them as `Validator` structs with the
/// given power, ready for use in a `Config.validators` field.
pub fn read_genesis_validator_pubkeys(
    network: &crate::harness::TestNetwork,
) -> color_eyre::Result<Vec<felidae_types::transaction::Validator>> {
    use base64::Engine;
    use color_eyre::eyre::OptionExt;

    let mut validators = Vec::new();
    for node in network
        .network
        .nodes
        .iter()
        .filter(|n| n.role.is_validator())
    {
        let content = std::fs::read_to_string(node.priv_validator_key_path())?;
        let key_json: serde_json::Value = serde_json::from_str(&content)?;
        let b64 = key_json["pub_key"]["value"]
            .as_str()
            .ok_or_eyre("missing pub_key.value in priv_validator_key.json")?;
        let pub_key_bytes = base64::engine::general_purpose::STANDARD.decode(b64)?;
        validators.push(felidae_types::transaction::Validator {
            public_key: pub_key_bytes.into(),
            power: 10,
        });
    }
    Ok(validators)
}

/// Queries CometBFT's active validator set via RPC and returns (pubkey_bytes, power) tuples,
/// sorted for deterministic comparison.
pub async fn query_cometbft_validators(
    rpc_client: &HttpClient,
) -> color_eyre::Result<Vec<(Vec<u8>, u64)>> {
    // Query at the latest height, not Height::default() which is Height(1) (genesis).
    let latest_height = rpc_client.latest_block().await?.block.header.height;
    let response = rpc_client.validators(latest_height, Paging::All).await?;
    let mut result: Vec<_> = response
        .validators
        .iter()
        .map(|v| {
            let key_bytes = match v.pub_key {
                tendermint::PublicKey::Ed25519(key) => key.as_bytes().to_vec(),
                _ => panic!("unexpected key type"),
            };
            (key_bytes, v.power.value())
        })
        .collect();
    result.sort();
    Ok(result)
}

/// Generates a random Ed25519 public key for use as a dummy validator.
pub fn generate_ed25519_pubkey() -> Vec<u8> {
    use ed25519_dalek::SigningKey;
    let mut secret = [0u8; 32];
    rand::Fill::fill(&mut secret, &mut rand::rng());
    SigningKey::from_bytes(&secret)
        .verifying_key()
        .to_bytes()
        .to_vec()
}

/// Submits an admin reconfiguration from all validator nodes in the network.
///
/// Reads each admin key, signs and submits the reconfiguration transaction,
/// and waits `inter_tx_delay()` between each submission.
pub async fn submit_admin_reconfig(
    network: &crate::harness::TestNetwork,
    rpc_client: &HttpClient,
    new_config: Config,
) -> color_eyre::Result<()> {
    let num_validators = network
        .network
        .nodes
        .iter()
        .filter(|n| n.role.is_validator())
        .count();
    for i in 0..num_validators {
        let admin_key = network.read_admin_key(i)?;
        let tx_hex = felidae_admin::reconfigure(
            &admin_key,
            crate::constants::TEST_CHAIN_ID.to_string(),
            crate::constants::admin_reconfig_tx_timeout(),
            None,
            new_config.clone(),
        )?;
        let tx_bytes = hex::decode(&tx_hex)?;
        // Use broadcast_tx_sync (submit to mempool, don't wait for block inclusion)
        // rather than broadcast_tx_commit, which can time out when validator set
        // updates cause longer block processing times. The subsequent polling
        // verifies the tx took effect.
        let result = rpc_client.broadcast_tx_sync(tx_bytes).await?;
        eprintln!(
            "[reconfig] admin {i}: code={:?}, log={}",
            result.code, result.log
        );
        tokio::time::sleep(crate::constants::inter_tx_delay()).await;
    }
    Ok(())
}
