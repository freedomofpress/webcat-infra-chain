//! Transaction submission and query helper functions.
//!
//! This module provides utilities for submitting transactions to the network
//! and querying state via the felidae CLI.

use std::collections::HashMap;
use std::process::Command;
use std::time::Duration;

use felidae_types::response::{
    AdminVote, ChainInfo, OracleVote, PendingObservation, ValidatorInfo,
};
use felidae_types::transaction::Config;
use tendermint_rpc::{Client, HttpClient, Paging};

// =============================================================================
// RPC UTILITIES
// =============================================================================

/// The chain's current height.
pub async fn latest_height(rpc_client: &HttpClient) -> color_eyre::Result<u64> {
    Ok(rpc_client.latest_block().await?.block.header.height.value())
}

/// A CometBFT RPC client that opens a fresh connection per request.
///
/// CometBFT reaps idle keep-alive connections, and these tests routinely leave
/// one idle across a sleep or a validator-set change. Reusing a socket the
/// server has just closed fails the in-flight request with `connection closed
/// before message completed`, and the RPC surface here is mostly bare `?` --
/// `broadcast_tx_sync` in `submit_admin_reconfig` above all -- so that lands
/// as a test failure rather than a retry.
///
/// Disabling the idle pool removes the race outright instead of hardening one
/// call site at a time. Connection setup against a loopback node is free.
pub fn rpc_client(url: &str) -> color_eyre::Result<HttpClient> {
    let inner = reqwest011::Client::builder()
        .pool_max_idle_per_host(0)
        // `Builder::client` discards the builder's own timeout; restate it.
        .timeout(Duration::from_secs(30))
        .build()?;
    Ok(HttpClient::builder(url.parse()?).client(inner).build()?)
}

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
        crate::harness::ensure_network_alive(description)?;
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
        crate::harness::ensure_network_alive(description)?;
        if start.elapsed() > timeout {
            return Err(color_eyre::eyre::eyre!(
                "condition not met within {timeout:?}: {description}"
            ));
        }
        tokio::time::sleep(interval).await;
    }
}

/// Wait for the chain to commit `blocks` further blocks, returning the height
/// reached.
///
/// Replaces the `height_before` / sleep / `height_after` / `assert!(after >
/// before)` shape. That shape asks whether a number grew, which is a weaker
/// question than it looks: a node whose ABCI service has died leaves its
/// CometBFT peer serving the last height it committed, so the assertion is
/// satisfied by a network that stopped before the test began -- as long as it
/// stopped at a height above the one sampled first.
///
/// Waiting for a *specific* number of further blocks cannot be satisfied that
/// way, and bounding it by a budget rather than a fixed sleep means a healthy
/// chain returns as soon as it has done the work instead of always paying the
/// worst case. Inheriting `poll_until_async` also inherits its liveness check.
pub async fn wait_blocks(
    rpc_client: &HttpClient,
    blocks: u64,
    budget: Duration,
    description: &str,
) -> color_eyre::Result<u64> {
    let start = latest_height(rpc_client).await?;
    let target = start + blocks;
    poll_until_async(budget, Duration::from_millis(500), description, || async {
        Ok(latest_height(rpc_client).await? >= target)
    })
    .await?;
    latest_height(rpc_client).await
}

// =============================================================================
// CROSS-NODE AGREEMENT
// =============================================================================

/// A node's view of committed state, read straight from its query port.
///
/// The CLI equivalent spawns a process per call, which is far too slow to
/// catch several nodes at the same height -- and catching them at the same
/// height is the whole point of [`assert_nodes_agree`].
pub async fn node_chain_info(
    http: &reqwest::Client,
    query_url: &str,
) -> color_eyre::Result<ChainInfo> {
    let info = http
        .get(format!("{query_url}/chain-info"))
        .send()
        .await?
        .error_for_status()?
        .json::<ChainInfo>()
        .await?;
    Ok(info)
}

/// Assert every node committed the same application state.
///
/// Nothing in this suite could previously ask whether two nodes *agree*. Tests
/// compare configs between a joined node and the genesis node; none compares
/// committed state. That left "this fault is liveness, not safety -- nodes
/// stop, they do not diverge" as a claim derived from reading the code rather
/// than one anybody had measured, and it left recovery untestable: a node that
/// restarts and rejoins is only actually recovered if its state matches its
/// peers'.
///
/// `/chain-info` reports the latest committed height and its app hash, but
/// nodes commit at slightly different moments, so a single round of requests
/// catches them at different heights and proves nothing. Instead this samples
/// every node repeatedly and compares hashes only where two nodes were seen at
/// the *same* height.
///
/// Fails if any shared height shows more than one hash, and also if no height
/// was observed by every node -- an assertion that never compared anything
/// must not pass quietly.
///
/// Returns the highest height at which all nodes were seen to agree.
pub async fn assert_nodes_agree(
    query_urls: &[String],
    settle: Duration,
) -> color_eyre::Result<u64> {
    use std::collections::BTreeMap;

    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()?;

    // height -> node index -> app hash
    let mut seen: BTreeMap<u64, BTreeMap<usize, String>> = BTreeMap::new();
    let deadline = std::time::Instant::now() + settle;
    while std::time::Instant::now() < deadline {
        for (index, url) in query_urls.iter().enumerate() {
            if let Ok(info) = node_chain_info(&http, url).await {
                seen.entry(info.block_height)
                    .or_default()
                    .insert(index, info.app_hash);
            }
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    let mut agreed_at = None;
    for (height, by_node) in &seen {
        let distinct: std::collections::BTreeSet<&String> = by_node.values().collect();
        if distinct.len() > 1 {
            let detail: Vec<String> = by_node
                .iter()
                .map(|(node, hash)| format!("node {node}: {}", &hash[..16.min(hash.len())]))
                .collect();
            return Err(color_eyre::eyre::eyre!(
                "nodes disagree on committed state at height {height}: {}",
                detail.join(", ")
            ));
        }
        if by_node.len() == query_urls.len() {
            agreed_at = Some(*height);
        }
    }

    agreed_at.ok_or_else(|| {
        color_eyre::eyre::eyre!(
            "no height was observed on all {} nodes within {settle:?}; \
             heights seen: {:?} -- the comparison would have been vacuous",
            query_urls.len(),
            seen.keys().collect::<Vec<_>>()
        )
    })
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

/// Queries the chain config via CLI.
pub fn query_config(felidae_bin: &std::path::Path, query_url: &str) -> color_eyre::Result<Config> {
    let output = run_query_command(felidae_bin, "config", query_url, &[])?;
    let config: Config = serde_json::from_str(&output)?;
    Ok(config)
}

// =============================================================================
// ORACLE HELPERS
// =============================================================================

/// Calls observe_domain_inner to perform enrollment observation
pub async fn run_oracle_observe(
    domain: &str,
    zone: &str,
    node_url: &str,
    chain: Option<&str>,
    homedir: &std::path::Path,
    enrollment_json: &str,
) -> color_eyre::Result<()> {
    use felidae::cli::oracle::observe_domain_inner;
    use reqwest::Url;

    let domain = domain.parse()?;
    let zone = zone.parse()?;
    let node: Url = node_url.parse()?;

    eprintln!(
        "[run_oracle_observe] domain={} zone={} node={}",
        domain, zone, node_url,
    );

    observe_domain_inner(
        domain,
        zone,
        node,
        chain.map(str::to_owned),
        Some(homedir),
        enrollment_json.to_owned(),
    )
    .await
}

// VALIDATOR HELPERS
// =============================================================================

/// Reads the 32-byte Ed25519 public key from a CometBFT `priv_validator_key.json`
/// file.
pub fn read_priv_validator_pubkey(path: &std::path::Path) -> color_eyre::Result<Vec<u8>> {
    use base64::Engine;
    use color_eyre::eyre::OptionExt;

    let content = std::fs::read_to_string(path)?;
    let key_json: serde_json::Value = serde_json::from_str(&content)?;
    let b64 = key_json["pub_key"]["value"]
        .as_str()
        .ok_or_eyre("missing pub_key.value in priv_validator_key.json")?;
    Ok(base64::engine::general_purpose::STANDARD.decode(b64)?)
}

/// Reads the genesis validator Ed25519 public keys from each validator node's
/// `priv_validator_key.json` and returns them as `Validator` structs with the
/// given power, ready for use in a `Config.validators` field.
pub fn read_genesis_validator_pubkeys(
    network: &crate::harness::TestNetwork,
) -> color_eyre::Result<Vec<felidae_types::transaction::Validator>> {
    use color_eyre::eyre::WrapErr;

    let mut validators = Vec::new();
    for node in network
        .network
        .nodes
        .iter()
        .filter(|n| n.role.is_validator())
    {
        let pub_key_bytes = read_priv_validator_pubkey(&node.priv_validator_key_path())?;
        let public_key = felidae_types::transaction::ValidatorKey::from_bytes(&pub_key_bytes)
            .wrap_err("invalid ed25519 public key in priv_validator_key.json")?;
        validators.push(felidae_types::transaction::Validator { public_key });
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
    // Exactly quorum, not every admin.
    //
    // Quorum is `n * 2 / 3 + 1`, which equals the validator count only at
    // n=3. At n=4 it is 3, so a fourth vote arrives *after* the config has
    // already been promoted and is rejected with "new config version N must
    // be greater than current version N" -- a correct rejection of a
    // meaningless vote, which this helper would then report as a failure.
    for i in 0..network.admin_quorum() {
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
        // A vote rejected at CheckTx silently starves the quorum (unanimous
        // at n=3): fail here with the offending admin and log, rather than
        // letting the caller's poll time out with no attribution.
        if !result.code.is_ok() {
            return Err(color_eyre::eyre::eyre!(
                "admin {i} reconfig vote rejected at CheckTx: {}",
                result.log
            ));
        }
        tokio::time::sleep(crate::constants::inter_tx_delay()).await;
    }
    Ok(())
}

/// Waits for an admin reconfiguration to reach quorum and apply, returning
/// the applied config for content assertions.
///
/// Provides informative error messages about the specific failure
/// that caused an admin reconfigure timeout, for debugging test harnesses.
pub async fn wait_reconfig_applied(
    felidae_bin: &std::path::Path,
    query_url: &str,
    rpc_client: &HttpClient,
    target_version: u32,
    description: &str,
) -> color_eyre::Result<Config> {
    // Quorum + promotion needs ~3 blocks once votes hit the mempool; 15 is
    // deep headroom that still fails fast when the pipeline is broken.
    const BLOCK_BUDGET: u64 = 15;
    let hard_cap = 4 * crate::constants::consensus_propagation_wait_long();

    let start = std::time::Instant::now();
    let start_height = rpc_client.latest_block().await?.block.header.height.value();
    loop {
        match query_config(felidae_bin, query_url) {
            Ok(cfg) if cfg.version >= target_version => return Ok(cfg),
            Ok(_) => {}
            Err(e) => eprintln!("[wait_reconfig_applied] {description}: error (retrying): {e}"),
        }

        let height = match rpc_client.latest_block().await {
            Ok(block) => block.block.header.height.value(),
            Err(e) => {
                eprintln!("[wait_reconfig_applied] {description}: height error (retrying): {e}");
                start_height
            }
        };
        crate::harness::ensure_network_alive(description)?;
        if height.saturating_sub(start_height) >= BLOCK_BUDGET || start.elapsed() >= hard_cap {
            let current = query_config(felidae_bin, query_url)
                .map(|c| c.version.to_string())
                .unwrap_or_else(|e| format!("<query failed: {e}>"));
            let votes = query_admin_votes(felidae_bin, query_url)
                .map(|votes| {
                    let versions: Vec<u32> = votes.iter().map(|vote| vote.config.version).collect();
                    format!(
                        "{} live vote(s) proposing version(s) {versions:?}",
                        votes.len()
                    )
                })
                .unwrap_or_else(|e| format!("<vote query failed: {e}>"));
            let pending = query_admin_pending(felidae_bin, query_url)
                .map(|p| format!("{} pending change(s)", p.len()))
                .unwrap_or_else(|e| format!("<pending query failed: {e}>"));
            return Err(color_eyre::eyre::eyre!(
                "{description}: config version {target_version} not applied within \
                 {} blocks / {:.1?} (height {start_height} → {height}); \
                 current version: {current}; admin queue: {votes}; {pending}",
                height.saturating_sub(start_height),
                start.elapsed(),
            ));
        }
        tokio::time::sleep(crate::constants::poll_interval()).await;
    }
}

/// Polls until the admin vote queue holds `expected` entries, returning them.
///
/// `broadcast_tx_sync` returns once a transaction is admitted to the mempool,
/// not once it is committed. How long the vote then takes to reach queryable
/// state is bounded by block production, so a caller that asserts on the queue
/// has to wait for it rather than assume a fixed number of blocks have passed.
pub async fn wait_admin_votes(
    felidae_bin: &std::path::Path,
    query_url: &str,
    expected: usize,
) -> color_eyre::Result<Vec<AdminVote>> {
    poll_until(
        crate::constants::consensus_propagation_wait_long(),
        crate::constants::poll_interval(),
        &format!("{expected} admin vote(s) visible in the queue"),
        || Ok(query_admin_votes(felidae_bin, query_url)?.len() == expected),
    )
    .await?;
    query_admin_votes(felidae_bin, query_url)
}

/// Queries every validator the chain knows about via `felidae query validators
/// --json`. Returns the parsed list of `ValidatorInfo`.
pub fn query_all_validators(
    felidae_bin: &std::path::Path,
    query_url: &str,
) -> color_eyre::Result<Vec<ValidatorInfo>> {
    let output = run_query_command(felidae_bin, "validators", query_url, &["--json"])?;
    let validators: Vec<ValidatorInfo> = serde_json::from_str(&output)?;
    Ok(validators)
}

/// Queries a single validator's info by hex-encoded ed25519 identity (full key
/// or unambiguous prefix) via `felidae query validators <id> --json`. Returns
/// `Ok(Some(_))` on success, `Ok(None)` if the route returned 404, and an
/// error for any other CLI failure.
pub fn query_validator_info(
    felidae_bin: &std::path::Path,
    query_url: &str,
    id: &str,
) -> color_eyre::Result<Option<ValidatorInfo>> {
    let output = Command::new(felidae_bin)
        .args([
            "query",
            "--query-url",
            query_url,
            "validators",
            id,
            "--json",
        ])
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // `error_for_status()` in the CLI surfaces 404 by printing the status
        // line to stderr. Distinguish "not found" from real errors so callers
        // can poll for a validator that hasn't been registered yet.
        if stderr.contains("404") {
            return Ok(None);
        }
        return Err(color_eyre::eyre::eyre!(
            "felidae query validators {id} failed: {stderr}"
        ));
    }

    let stdout = String::from_utf8(output.stdout)?;
    let validators: Vec<ValidatorInfo> = serde_json::from_str(&stdout)?;
    Ok(validators.into_iter().next())
}
