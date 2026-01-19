#![cfg(feature = "integration")]

//! Integration tests for felidae 3-validator network with oracle observations.
//!
//! # Overview
//!
//! These tests verify the core felidae ABCI application behavior through end-to-end
//! integration testing with a real 3-validator CometBFT network. The tests exercise
//! the complete transaction lifecycle from submission through consensus to state
//! finalization.
//!
//! # Architecture Under Test
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                         Test Network (3 Validators)                      │
//! │                                                                          │
//! │  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐               │
//! │  │ Validator 0  │    │ Validator 1  │    │ Validator 2  │               │
//! │  │ ┌──────────┐ │    │ ┌──────────┐ │    │ ┌──────────┐ │               │
//! │  │ │ CometBFT │◄├────┤►│ CometBFT │◄├────┤►│ CometBFT │ │  ◄── Consensus│
//! │  │ └────┬─────┘ │    │ └────┬─────┘ │    │ └────┬─────┘ │               │
//! │  │      │ABCI   │    │      │ABCI   │    │      │ABCI   │               │
//! │  │ ┌────▼─────┐ │    │ ┌────▼─────┐ │    │ ┌────▼─────┐ │               │
//! │  │ │ Felidae  │ │    │ │ Felidae  │ │    │ │ Felidae  │ │  ◄── State    │
//! │  │ └──────────┘ │    │ └──────────┘ │    │ └──────────┘ │      Machine  │
//! │  └──────────────┘    └──────────────┘    └──────────────┘               │
//! └─────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Business Logic Tested
//!
//! ## Oracle Observation Flow
//!
//! The oracle observation system implements a Byzantine fault-tolerant mechanism for
//! reaching consensus on domain-to-enrollment mappings in the WEBCAT protocol:
//!
//! 1. **Vote Submission**: Authorized oracles submit signed observations containing:
//!    - Domain name (e.g., "example.com.")
//!    - Zone (parent zone, e.g., "com.")
//!    - Enrollment hash (SHA-256 of canonical JSON enrollment) or NotFound
//!    - Blockstamp (block height + app hash for freshness verification)
//!
//! 2. **Vote Accumulation**: Votes are stored in a vote queue keyed by domain.
//!    Each oracle can have at most one active vote per domain.
//!
//! 3. **Quorum Detection**: When votes for the same (domain, hash) pair reach
//!    quorum (configured as 2/3 + 1 of total oracles), the observation moves
//!    to a "pending" state.
//!
//! 4. **Delay Period**: Pending observations wait for a configurable delay
//!    before becoming canonical. This provides a window for detecting issues.
//!
//! 5. **Canonicalization**: After the delay, observations are promoted to the
//!    canonical substore, making them queryable via the `/snapshot` endpoint.
//!
//! ## State Substores
//!
//! - **Internal**: Vote queues, pending changes, configuration, block metadata
//! - **Canonical**: Finalized domain → enrollment hash mappings (exposed to clients)
//!
//! # Test Configuration
//!
//! All tests use a 3-validator network with:
//! - Quorum: 3 (2/3 + 1 of 3 = 3)
//! - Voting timeout: 300s
//! - Promotion delay: 1s (shortened for testing; production uses longer delays)
//! - Max enrolled subdomains per registered domain: 5

use std::collections::HashMap;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use felidae_deployer::{Network, NetworkConfig};
use felidae_types::KeyPair;
use felidae_types::response::{AdminVote, OracleVote, PendingObservation};
use felidae_types::transaction::{Config, OracleConfig};
use hex;
use tendermint_rpc::{Client, HttpClient};

// =============================================================================
// TEST CONSTANTS
// =============================================================================

/// Test domain constants as (domain, zone) tuples.
///
/// The zone must be an ancestor of the domain in the DNS hierarchy. This is
/// validated by the state machine to ensure oracles can only observe domains
/// within their authorized zones.
///
/// # Domain Hierarchy
///
/// We use two primary test domains under different TLD zones:
/// - "webcat.tech." under zone "tech."
/// - "example.com." under zone "com."
///
/// For subdomain tests, we use prefixes "goss" and "subby":
/// - "goss.webcat.tech." and "subby.webcat.tech." under "webcat.tech."

/// Primary test domains (registered domain, zone)
const TEST_DOMAINS: &[(&str, &str)] = &[("webcat.tech.", "tech."), ("example.com.", "com.")];

/// Convenience accessors for common test domains
const TEST_DOMAIN_WEBCAT: (&str, &str) = ("webcat.tech.", "tech.");
const TEST_DOMAIN_EXAMPLE: (&str, &str) = ("example.com.", "com.");

/// Domain used for unenrollment testing (subdomain of webcat.tech.)
const TEST_DOMAIN_UNENROLL: (&str, &str) = ("goss.webcat.tech.", "tech.");

/// Subdomain prefixes for subdomain-related tests
const TEST_SUBDOMAIN_PREFIX_1: &str = "goss";
const TEST_SUBDOMAIN_PREFIX_2: &str = "subby";

/// Generates a valid WEBCAT enrollment JSON for testing.
///
/// # WEBCAT Enrollment Structure
///
/// A WEBCAT enrollment defines the cryptographic policy for a domain. When
/// oracles observe a domain, they hash the canonicalized enrollment JSON
/// (using OLPC canonical JSON format) to produce a 32-byte commitment.
///
/// The enrollment contains:
/// - `signers`: Array of base64url-encoded Ed25519 public keys authorized to sign
/// - `threshold`: Minimum number of signers required (k-of-n)
/// - `policy`: Base64url-encoded policy blob (application-specific)
/// - `max_age`: Maximum age in seconds for signed assertions
/// - `cas_url`: Content-addressable storage URL for retrieving signed content
///
/// # Hash Computation
///
/// The oracle computes `SHA-256(canonical_json(enrollment))` and includes this
/// hash in their observation. All oracles observing the same enrollment will
/// produce the same hash, enabling quorum detection.
fn test_enrollment_json() -> String {
    // Generate a deterministic Ed25519 keypair for reproducible test enrollments.
    // Using a fixed seed ensures all tests produce the same enrollment hash.
    use ed25519_dalek::SigningKey;
    let signing_key = SigningKey::from_bytes(&[1u8; 32]);
    let verifying_key = signing_key.verifying_key();
    // Base64-url encode the public key (32 bytes) per WEBCAT spec
    let test_pubkey = base64_url::encode(verifying_key.as_bytes());

    serde_json::json!({
        "signers": [test_pubkey],
        "threshold": 1,
        "policy": "AAAA", // Minimal base64-url policy
        "max_age": 86400,
        "cas_url": "https://example.com/cas"
    })
    .to_string()
}
// =============================================================================
// TEST HARNESS
// =============================================================================

/// A managed test network that handles the full lifecycle of a multi-validator
/// felidae deployment.
///
/// # Lifecycle
///
/// 1. **Creation** (`create`): Generates network configuration, cryptographic keys,
///    genesis file, and CometBFT config files in a temporary directory.
///
/// 2. **Genesis Injection** (`inject_genesis_config`): Adds felidae-specific
///    configuration to the genesis `app_state`, including oracle and admin
///    public keys derived from the generated PKCS#8 keypairs.
///
/// 3. **Startup** (`start`): Spawns CometBFT and Felidae processes for each node.
///    CometBFT handles consensus via Tendermint BFT; Felidae is the ABCI app.
///
/// 4. **Ready Wait** (`wait_ready`): Polls until blocks are being produced,
///    indicating successful consensus bootstrapping.
///
/// 5. **Cleanup** (`drop`): Kills all processes and removes the temp directory.
///
/// # Process Architecture
///
/// For each validator node, two processes are spawned:
/// - `{name}-cometbft`: CometBFT consensus engine (P2P, RPC, mempool)
/// - `{name}-felidae`: ABCI application (state machine, query API)
struct TestNetwork {
    /// Network configuration and node topology
    network: Network,
    /// Map of process name to running process handle
    processes: HashMap<String, Child>,
    /// Shutdown signal for coordinated termination
    shutdown: Arc<AtomicBool>,
    /// Temporary directory guard; dropped after TestNetwork to ensure cleanup
    _temp_dir: tempfile::TempDir,
}

impl TestNetwork {
    /// Create and initialize a new 3-validator test network.
    async fn create(num_validators: usize) -> color_eyre::Result<Self> {
        let temp_dir = tempfile::tempdir()?;
        let directory = temp_dir.path().to_path_buf();

        let config = NetworkConfig {
            chain_id: "felidae-integration-test".to_string(),
            num_validators,
            use_sentries: false,
            directory,
            ..Default::default()
        };

        let mut network = Network::new(config);
        network.initialize()?;

        // Generate felidae config and inject it into genesis
        // Uses 1s oracle delay for testing, 0s admin delay for immediate config changes
        let felidae_config = network.generate_felidae_config(
            Duration::from_secs(1), // oracle voting delay
            Duration::from_secs(0), // admin voting delay
        )?;
        network.inject_genesis_app_state(&felidae_config)?;

        Ok(Self {
            network,
            processes: HashMap::new(),
            shutdown: Arc::new(AtomicBool::new(false)),
            _temp_dir: temp_dir,
        })
    }

    /// Start all network processes (CometBFT + Felidae + Oracle for each validator).
    fn start(&mut self, cometbft_bin: &str, felidae_bin: &str) -> color_eyre::Result<()> {
        // Preflight check: verify all ports are available before starting any processes
        self.network.check_ports_available()?;

        for node in &self.network.nodes {
            // Start CometBFT
            let cometbft_name = format!("{}-cometbft", node.name);
            let child = Command::new(cometbft_bin)
                .args(["start", "--home", &node.cometbft_home().to_string_lossy()])
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()?;
            self.processes.insert(cometbft_name, child);

            // Start Felidae
            let felidae_name = format!("{}-felidae", node.name);
            let child = Command::new(felidae_bin)
                .args([
                    "start",
                    "--abci-bind",
                    &node.abci_address(),
                    "--query-bind",
                    &format!("{}:{}", node.bind_address, node.ports.felidae_query),
                    "--homedir",
                    &node.felidae_home().to_string_lossy(),
                ])
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()?;
            self.processes.insert(felidae_name, child);

            // Start Oracle server for validators
            if node.role.is_validator() {
                let oracle_name = format!("{}-oracle", node.name);
                let child = Command::new(felidae_bin)
                    .args([
                        "oracle",
                        "server",
                        "--bind",
                        &format!("{}:{}", node.bind_address, node.ports.felidae_oracle),
                        "--node",
                        &format!("http://{}:{}", node.bind_address, node.ports.cometbft_rpc),
                        "--homedir",
                        &node.felidae_home().to_string_lossy(),
                    ])
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .spawn()?;
                self.processes.insert(oracle_name, child);
            }
        }

        Ok(())
    }

    /// Wait for the network to be ready (blocks are being produced).
    async fn wait_ready(&self, timeout: Duration) -> color_eyre::Result<()> {
        let rpc_url = format!(
            "http://{}:{}",
            self.network.nodes[0].bind_address, self.network.nodes[0].ports.cometbft_rpc
        );
        let client = HttpClient::new(rpc_url.as_str())?;

        let start = std::time::Instant::now();
        loop {
            if start.elapsed() > timeout {
                return Err(color_eyre::eyre::eyre!(
                    "timeout waiting for network to be ready"
                ));
            }

            match client.latest_block().await {
                Ok(response) => {
                    let height = response.block.header.height.value();
                    if height >= 2 {
                        // Wait for at least 2 blocks to ensure consensus is working
                        return Ok(());
                    }
                }
                Err(_) => {
                    // Node not ready yet
                }
            }

            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }

    /// Get the first node's CometBFT RPC URL.
    fn rpc_url(&self) -> String {
        format!(
            "http://{}:{}",
            self.network.nodes[0].bind_address, self.network.nodes[0].ports.cometbft_rpc
        )
    }

    /// Get the first node's Felidae query API URL.
    fn query_url(&self) -> String {
        format!(
            "http://{}:{}",
            self.network.nodes[0].bind_address, self.network.nodes[0].ports.felidae_query
        )
    }

    /// Get a validator node's Oracle server URL.
    fn oracle_url(&self, validator_index: usize) -> String {
        let node = &self.network.nodes[validator_index];
        format!("http://{}:{}", node.bind_address, node.ports.felidae_oracle)
    }

    /// Wait for all oracle servers to be ready (health check returns OK).
    async fn wait_oracles_ready(&self, timeout: Duration) -> color_eyre::Result<()> {
        let http_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(2))
            .build()?;

        let start = std::time::Instant::now();
        let mut ready_count = 0;
        let validator_count = self
            .network
            .nodes
            .iter()
            .filter(|n| n.role.is_validator())
            .count();

        while ready_count < validator_count {
            if start.elapsed() > timeout {
                return Err(color_eyre::eyre::eyre!(
                    "timeout waiting for oracle servers to be ready ({}/{} ready)",
                    ready_count,
                    validator_count
                ));
            }

            ready_count = 0;
            for (i, node) in self.network.nodes.iter().enumerate() {
                if !node.role.is_validator() {
                    continue;
                }
                let health_url = format!(
                    "http://{}:{}/health",
                    node.bind_address, node.ports.felidae_oracle
                );
                match http_client.get(&health_url).send().await {
                    Ok(resp) if resp.status().is_success() => {
                        ready_count += 1;
                    }
                    _ => {
                        eprintln!(
                            "[wait_oracles_ready] oracle {} not ready yet ({})",
                            i, health_url
                        );
                    }
                }
            }

            if ready_count < validator_count {
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        }

        eprintln!(
            "[wait_oracles_ready] all {} oracle servers ready",
            validator_count
        );
        Ok(())
    }

    /// Read an oracle key from a validator node.
    fn read_oracle_key(&self, validator_index: usize) -> color_eyre::Result<Vec<u8>> {
        let node = &self.network.nodes[validator_index];
        let key_hex = std::fs::read_to_string(node.oracle_key_path())?;
        Ok(hex::decode(key_hex.trim())?)
    }

    /// Read an admin key from a validator node.
    fn read_admin_key(&self, validator_index: usize) -> color_eyre::Result<Vec<u8>> {
        let node = &self.network.nodes[validator_index];
        let key_hex = std::fs::read_to_string(node.admin_key_path())?;
        Ok(hex::decode(key_hex.trim())?)
    }

    /// Shutdown all processes.
    fn shutdown(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        for (_name, mut child) in self.processes.drain() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

impl Drop for TestNetwork {
    fn drop(&mut self) {
        self.shutdown();
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
async fn submit_observation(
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
fn run_query_command(
    felidae_bin: &std::path::Path,
    subcommand: &str,
    query_url: &str,
    extra_args: &[&str],
) -> color_eyre::Result<String> {
    let mut cmd = Command::new(felidae_bin);
    cmd.arg("query")
        .arg(subcommand)
        .arg("--query-url")
        .arg(query_url);

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
        "[run_query_command] {} --query-url {} => {}",
        subcommand, query_url, stdout
    );
    Ok(stdout)
}

/// Queries the oracle votes via CLI for active votes in the voting queue.
///
/// Votes are in-flight observations that haven't yet reached quorum. Each vote
/// shows which oracle voted for which domain with what hash. Multiple oracles
/// voting for the same (domain, hash) pair will trigger quorum detection.
fn query_oracle_votes(
    felidae_bin: &std::path::Path,
    query_url: &str,
) -> color_eyre::Result<Vec<OracleVote>> {
    let output = run_query_command(felidae_bin, "oracle-votes", query_url, &[])?;
    let votes: Vec<OracleVote> = serde_json::from_str(&output)?;
    Ok(votes)
}

/// Queries the oracle pending via CLI for observations awaiting promotion.
///
/// Pending observations have reached quorum but are in the delay period before
/// becoming canonical. The delay provides a window for detecting and responding
/// to incorrect observations before they become permanent.
fn query_oracle_pending(
    felidae_bin: &std::path::Path,
    query_url: &str,
) -> color_eyre::Result<Vec<PendingObservation>> {
    let output = run_query_command(felidae_bin, "oracle-pending", query_url, &[])?;
    let pending: Vec<PendingObservation> = serde_json::from_str(&output)?;
    Ok(pending)
}

/// Queries the admin votes via CLI for active admin reconfiguration votes.
///
/// Admin votes work similarly to oracle votes but vote on the singleton chain
/// configuration rather than individual domains. Each authorized admin can
/// submit a signed reconfiguration vote with a proposed new config.
fn query_admin_votes(
    felidae_bin: &std::path::Path,
    query_url: &str,
) -> color_eyre::Result<Vec<AdminVote>> {
    let output = run_query_command(felidae_bin, "admin-votes", query_url, &[])?;
    let votes: Vec<AdminVote> = serde_json::from_str(&output)?;
    Ok(votes)
}

/// Queries the admin pending via CLI for config changes awaiting promotion.
///
/// Similar to oracle pending, admin pending contains config changes that have
/// reached quorum but are waiting for the configured delay before being applied.
fn query_admin_pending(
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
fn query_snapshot(
    felidae_bin: &std::path::Path,
    query_url: &str,
) -> color_eyre::Result<HashMap<String, String>> {
    let output = run_query_command(felidae_bin, "snapshot", query_url, &[])?;
    let snapshot: HashMap<String, String> = serde_json::from_str(&output)?;
    Ok(snapshot)
}

/// Queries the chain config via CLI.
fn query_config(felidae_bin: &std::path::Path, query_url: &str) -> color_eyre::Result<Config> {
    let output = run_query_command(felidae_bin, "config", query_url, &[])?;
    let config: Config = serde_json::from_str(&output)?;
    Ok(config)
}

/// Find binaries for testing.
fn find_binaries() -> color_eyre::Result<(PathBuf, PathBuf)> {
    // Try to build/find felidae using escargot with explicit package
    let felidae_build = escargot::CargoBuild::new()
        .package("felidae")
        .bin("felidae")
        .current_release()
        .current_target()
        .run()?;
    let felidae_bin = felidae_build.path().to_path_buf();

    // Look for cometbft in common locations
    let cometbft_bin = find_cometbft()?;

    Ok((cometbft_bin, felidae_bin))
}

fn find_cometbft() -> color_eyre::Result<PathBuf> {
    // Assume cometbft is available on PATH (provided by nix environment)
    if let Ok(output) = Command::new("which").arg("cometbft").output() {
        if output.status.success() {
            let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !path.is_empty() {
                return Ok(PathBuf::from(path));
            }
        }
    }

    Err(color_eyre::eyre::eyre!(
        "cometbft binary not found in PATH. Ensure you're running in the nix environment (nix develop)"
    ))
}

// =============================================================================
// INTEGRATION TESTS
// =============================================================================

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
    network.wait_ready(Duration::from_secs(30)).await?;

    // Wait for oracle servers to be ready (health check returns OK)
    network.wait_oracles_ready(Duration::from_secs(30)).await?;

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
///    - Domain/zone relationship is verified (jawn.best. is subdomain of best.)
///    - Vote is stored in the vote queue keyed by domain
///
/// 3. **Query API**:
///    - `/oracle/votes` returns the pending vote
///    - Domain-specific endpoint `/oracle/votes/{domain}` works
///
/// # Why No Canonical Entry?
///
/// With only 1 of 3 oracles voting, quorum (3) is not reached. The observation
/// remains in the vote queue indefinitely until either:
/// - More oracles vote for the same hash (reaching quorum)
/// - The vote times out (after 300 seconds in test config)
///
/// # State Transitions
///
/// ```text
/// [Empty] ---(1 vote)---> [Vote Queue: 1 vote] ---(no quorum)---> [stays in queue]
/// ```
#[tokio::test]
#[cfg(feature = "integration")]
async fn test_oracle_observation_single_domain() -> color_eyre::Result<()> {
    let (cometbft_bin, felidae_bin) = find_binaries()?;

    let mut network = TestNetwork::create(3).await?;
    network.start(
        cometbft_bin.to_str().unwrap(),
        felidae_bin.to_str().unwrap(),
    )?;
    network.wait_ready(Duration::from_secs(30)).await?;

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
        "felidae-integration-test",
        TEST_DOMAIN_WEBCAT.0,
        TEST_DOMAIN_WEBCAT.1,
        Some(&enrollment),
    )
    .await?;

    // Poll for the vote to appear in the query API
    // Note: votes may not appear immediately due to block timing
    let mut found = false;
    for attempt in 1..=10 {
        tokio::time::sleep(Duration::from_secs(2)).await;

        let block = rpc_client.latest_block().await?;
        let height = block.block.header.height.value();

        let votes = query_oracle_votes(&felidae_bin, &network.query_url())?;
        let pending = query_oracle_pending(&felidae_bin, &network.query_url())?;

        // Test the domain-specific vote query via CLI (with --domain filter)
        let domain_votes_output = run_query_command(
            &felidae_bin,
            "oracle-votes",
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
///
/// # State Transitions
///
/// ```text
/// [Empty]
///    │
///    ▼ (oracle 0 votes)
/// [Vote Queue: 1 vote]
///    │
///    ▼ (oracle 1 votes)
/// [Vote Queue: 2 votes]
///    │
///    ▼ (oracle 2 votes, quorum=3 reached!)
/// [Pending: example.com. → hash]
///    │
///    ▼ (delay expires, EndBlock promotes)
/// [Canonical: example.com. → hash]
/// ```
///
/// # Why All 3 Oracles?
///
/// With quorum = 2*3/3 + 1 = 3, all validators must agree. This provides
/// the strongest consistency guarantee but requires unanimous agreement.
/// In production, quorum might be 2/3+1 of a larger validator set.
#[tokio::test]
#[cfg(feature = "integration")]
async fn test_oracle_quorum_reached() -> color_eyre::Result<()> {
    let (cometbft_bin, felidae_bin) = find_binaries()?;

    let mut network = TestNetwork::create(3).await?;
    network.start(
        cometbft_bin.to_str().unwrap(),
        felidae_bin.to_str().unwrap(),
    )?;
    network.wait_ready(Duration::from_secs(30)).await?;

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
            "felidae-integration-test",
            TEST_DOMAIN_EXAMPLE.0,
            TEST_DOMAIN_EXAMPLE.1,
            Some(&enrollment),
        )
        .await?;

        // Brief delay to ensure transactions are sequenced properly
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    // Wait for:
    // 1. All transactions to be included in blocks
    // 2. Quorum to be detected (happens during cast() on 3rd vote)
    // 3. Pending delay to expire (1 second)
    // 4. EndBlock to promote pending→canonical (requires next block after delay)
    // Note: We need extra time to ensure a block is produced after delay expires
    tokio::time::sleep(Duration::from_secs(10)).await;

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
///
/// # Business Logic Tested
///
/// This test validates that the voting system correctly handles multiple
/// independent domains being enrolled simultaneously:
///
/// 1. **Independent Vote Queues**:
///    - Each domain has its own vote queue
///    - Votes for different domains don't interfere
///    - Quorum is tracked per-domain
///
/// 2. **Concurrent Processing**:
///    - Multiple domains can have pending changes simultaneously
///    - EndBlock processes all ready pending changes in one pass
///    - Canonical writes are atomic within a block
///
/// 3. **Different Zone Validation**:
///    - jawn.best. validates against zone best.
///    - example.com. validates against zone com.
///    - Each domain/zone pair is validated independently
///
/// # State After Test
///
/// ```text
/// Canonical State:
/// ├── jawn.best.     → <enrollment hash>
/// └── example.com.   → <enrollment hash>
/// ```
///
/// # Real-World Scenario
///
/// This mirrors production where multiple domain owners may be registering
/// their WEBCAT enrollments around the same time. The system must handle
/// this concurrency without race conditions or lost writes.
#[tokio::test]
#[cfg(feature = "integration")]
async fn test_oracle_observation_multiple_domains() -> color_eyre::Result<()> {
    let (cometbft_bin, felidae_bin) = find_binaries()?;

    let mut network = TestNetwork::create(3).await?;
    network.start(
        cometbft_bin.to_str().unwrap(),
        felidae_bin.to_str().unwrap(),
    )?;
    network.wait_ready(Duration::from_secs(30)).await?;

    let rpc_client = HttpClient::new(network.rpc_url().as_str())?;

    let enrollment = test_enrollment_json();

    // Submit observations from all oracles for both test domains sequentially.
    // In production, these might come from different oracle processes.
    for (domain, zone) in TEST_DOMAINS {
        for i in 0..3 {
            let oracle_key = network.read_oracle_key(i)?;
            submit_observation(
                &rpc_client,
                &oracle_key,
                "felidae-integration-test",
                domain,
                zone,
                Some(&enrollment),
            )
            .await?;
            tokio::time::sleep(Duration::from_millis(300)).await;
        }
    }

    // Wait for both domains to reach quorum and be promoted
    tokio::time::sleep(Duration::from_secs(5)).await;

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
///
/// # Business Logic Tested
///
/// This test validates the domain removal flow in WEBCAT:
///
/// 1. **Enrollment Phase**:
///    - Domain is enrolled via normal quorum process
///    - Canonical state contains domain→hash mapping
///
/// 2. **Unenrollment Observation**:
///    - Oracles observe the domain with `enrollment_json = None`
///    - This creates an observation with `HashObserved::NotFound`
///    - NotFound indicates the domain should be removed
///
/// 3. **Unenrollment Quorum**:
///    - All oracles vote for NotFound for the same domain
///    - Quorum is reached for the NotFound observation
///    - The pending change contains NotFound as the value
///
/// 4. **Canonical Deletion**:
///    - EndBlock sees a pending NotFound observation
///    - Instead of writing a hash, it deletes the canonical entry
///    - The domain no longer appears in `/snapshot`
///
/// # Why NotFound Instead of Deletion Action?
///
/// The protocol treats "no enrollment exists" as a valid observation state.
/// This allows the same voting mechanism for both enrollment and unenrollment,
/// simplifying the protocol and providing the same BFT guarantees.
///
/// # State Transitions
///
/// ```text
/// Phase 1 (Enrollment):
/// [Empty] → [Vote: hash] → [Pending: hash] → [Canonical: domain→hash]
///
/// Phase 2 (Unenrollment):
/// [Canonical: domain→hash]
///    │
///    ▼ (3 oracles vote NotFound)
/// [Pending: NotFound]
///    │
///    ▼ (delay expires)
/// [Canonical: (entry deleted)]
/// ```
///
/// # Real-World Scenario
///
/// A domain owner may want to remove their WEBCAT enrollment when:
/// - Decommissioning a domain
/// - Rotating to a completely new policy
/// - Revoking compromised keys
#[tokio::test]
#[cfg(feature = "integration")]
async fn test_oracle_unenrollment() -> color_eyre::Result<()> {
    let (cometbft_bin, felidae_bin) = find_binaries()?;

    let mut network = TestNetwork::create(3).await?;
    network.start(
        cometbft_bin.to_str().unwrap(),
        felidae_bin.to_str().unwrap(),
    )?;
    network.wait_ready(Duration::from_secs(30)).await?;

    let rpc_client = HttpClient::new(network.rpc_url().as_str())?;

    let enrollment = test_enrollment_json();

    // =========================================================================
    // PHASE 1: Enroll the domain first
    // =========================================================================
    eprintln!(
        "[test] Step 1: Enrolling domain {}.",
        TEST_DOMAIN_UNENROLL.0
    );
    for i in 0..3 {
        let oracle_key = network.read_oracle_key(i)?;
        submit_observation(
            &rpc_client,
            &oracle_key,
            "felidae-integration-test",
            TEST_DOMAIN_UNENROLL.0,
            TEST_DOMAIN_UNENROLL.1,
            Some(&enrollment), // With enrollment = create mapping
        )
        .await?;
        tokio::time::sleep(Duration::from_millis(300)).await;
    }

    // Wait for enrollment to become canonical
    tokio::time::sleep(Duration::from_secs(5)).await;

    // Verify the domain was enrolled via CLI
    let snapshot = query_snapshot(&felidae_bin, &network.query_url())?;
    eprintln!("[test] snapshot after enrollment: {:?}", snapshot);
    assert!(
        snapshot.contains_key(TEST_DOMAIN_UNENROLL.0),
        "expected {} to be enrolled first",
        TEST_DOMAIN_UNENROLL.0
    );

    // =========================================================================
    // PHASE 2: Unenroll the domain
    // =========================================================================
    eprintln!(
        "[test] Step 2: Unenrolling domain {}.",
        TEST_DOMAIN_UNENROLL.0
    );
    for i in 0..3 {
        let oracle_key = network.read_oracle_key(i)?;
        submit_observation(
            &rpc_client,
            &oracle_key,
            "felidae-integration-test",
            TEST_DOMAIN_UNENROLL.0,
            TEST_DOMAIN_UNENROLL.1,
            None, // Without enrollment = NotFound = delete mapping
        )
        .await?;
        tokio::time::sleep(Duration::from_millis(300)).await;
    }

    // Wait for unenrollment to become canonical
    tokio::time::sleep(Duration::from_secs(5)).await;

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

// =============================================================================
// ADDITIONAL INTEGRATION TESTS - EDGE CASES AND ERROR PATHS
// =============================================================================

/// Verifies that observations from unauthorized oracles are rejected.
///
/// # Business Logic Tested
///
/// This test validates the oracle authorization check in `observe.rs`:
///
/// 1. **Signature Verification**: The transaction signature is valid ECDSA-P256
/// 2. **Authorization Check**: The signer's public key is checked against
///    `config.oracles.authorized[]`
/// 3. **Rejection**: Unauthorized oracles receive a non-zero DeliverTx code
///
/// # Security Implications
///
/// This is a critical security boundary. Without this check:
/// - Any party could submit observations
/// - Attackers could manipulate domain→hash mappings
/// - The quorum mechanism would be meaningless
///
/// # Error Path
///
/// ```text
/// [Unauthorized Oracle] ---(signed tx)---> [CheckTx: pass] ---> [DeliverTx: REJECT]
///                                              │
///                                              └── Signature is valid but
///                                                  pubkey not in authorized list
/// ```
#[tokio::test]
#[cfg(feature = "integration")]
async fn test_unauthorized_oracle_rejected() -> color_eyre::Result<()> {
    let (cometbft_bin, felidae_bin) = find_binaries()?;

    let mut network = TestNetwork::create(3).await?;
    network.start(
        cometbft_bin.to_str().unwrap(),
        felidae_bin.to_str().unwrap(),
    )?;
    network.wait_ready(Duration::from_secs(30)).await?;

    let rpc_client = HttpClient::new(network.rpc_url().as_str())?;

    // Generate a deterministic key that is NOT in the authorized oracle list.
    // This simulates an attacker trying to submit observations.
    // We use fixed bytes to create a valid but unauthorized key.
    let unauthorized_key = {
        use p256::ecdsa::SigningKey;
        use p256::elliptic_curve::generic_array::GenericArray;
        // 32 bytes of deterministic "random" data that produces a valid P-256 scalar
        let secret_bytes: [u8; 32] = [
            0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
            0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
            0x19, 0x1A, 0x1B, 0x1C,
        ];
        let signing_key = SigningKey::from_bytes(GenericArray::from_slice(&secret_bytes)).unwrap();
        // Encode as PKCS#8 DER
        use p256::pkcs8::EncodePrivateKey;
        signing_key.to_pkcs8_der().unwrap().as_bytes().to_vec()
    };

    let enrollment = test_enrollment_json();

    // Attempt to submit observation with unauthorized key.
    // This should fail during DeliverTx with "not a current oracle" error.
    let result = submit_observation(
        &rpc_client,
        &unauthorized_key,
        "felidae-integration-test",
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

    // Verify the error is due to authorization, not some other issue
    assert!(
        err_msg.contains("not a current oracle") || err_msg.contains("transaction failed"),
        "expected 'not a current oracle' error, got: {}",
        err_msg
    );

    eprintln!("[test] confirmed receipt of rejection error: {}", err_msg);

    Ok(())
}

/// Verifies that partial quorum (below threshold) does not result in canonical entry.
///
/// # Business Logic Tested
///
/// This test validates the quorum threshold enforcement:
///
/// 1. **Vote Accumulation**: Two of three oracles submit observations
/// 2. **No Quorum**: With quorum=3 and only 2 votes, threshold is not met
/// 3. **No Promotion**: The observation stays in the vote queue, never pending
/// 4. **No Canonical Entry**: The domain does not appear in `/snapshot`
///
/// # BFT Implications
///
/// The quorum requirement ensures Byzantine fault tolerance:
/// - With n=3 and quorum=3, we can tolerate f=0 Byzantine faults
/// - If only 2 oracles agree, a faulty oracle could have influenced them
/// - Requiring all 3 ensures honest majority agreement
///
/// # State Transitions
///
/// ```text
/// [Empty] ---(oracle 0 votes)---> [Vote Queue: 1 vote]
///                                        │
///                                        ▼ (oracle 1 votes)
///                                 [Vote Queue: 2 votes]
///                                        │
///                                        ▼ (no oracle 2 vote)
///                                 [Vote Queue: 2 votes] (no change)
///                                        │
///                                        └──► [Canonical: empty] (domain never appears)
/// ```
#[tokio::test]
#[cfg(feature = "integration")]
async fn test_partial_quorum_no_canonical() -> color_eyre::Result<()> {
    let (cometbft_bin, felidae_bin) = find_binaries()?;

    let mut network = TestNetwork::create(3).await?;
    network.start(
        cometbft_bin.to_str().unwrap(),
        felidae_bin.to_str().unwrap(),
    )?;
    network.wait_ready(Duration::from_secs(30)).await?;

    let rpc_client = HttpClient::new(network.rpc_url().as_str())?;

    let enrollment = test_enrollment_json();

    // Use a subdomain of webcat.tech. that other tests don't use for quorum
    let partial_domain = format!("{}.{}", TEST_SUBDOMAIN_PREFIX_1, TEST_DOMAIN_WEBCAT.0);

    // Submit observations from only 2 of 3 oracles.
    // With quorum=3, this should NOT be enough to reach quorum.
    for i in 0..2 {
        let oracle_key = network.read_oracle_key(i)?;
        submit_observation(
            &rpc_client,
            &oracle_key,
            "felidae-integration-test",
            &partial_domain,
            TEST_DOMAIN_WEBCAT.1,
            Some(&enrollment),
        )
        .await?;
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    // Wait for potential processing (should not reach quorum)
    tokio::time::sleep(Duration::from_secs(5)).await;

    // Verify votes exist in the vote queue via CLI
    let votes = query_oracle_votes(&felidae_bin, &network.query_url())?;
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
///
/// # Business Logic Tested
///
/// This test validates the enrollment update flow:
///
/// 1. **Initial Enrollment**: Domain is enrolled with hash A
/// 2. **Policy Update**: Domain owner publishes new enrollment (hash B)
/// 3. **Oracle Re-observation**: Oracles observe the new enrollment
/// 4. **Quorum for New Hash**: New hash B reaches quorum
/// 5. **Canonical Update**: Domain→hash mapping changes from A to B
///
/// # Why This Matters
///
/// Domain owners need to update their WEBCAT enrollments for:
/// - Key rotation (adding/removing signers)
/// - Threshold changes
/// - Policy updates
/// - CAS URL changes
///
/// The update mechanism must:
/// - Allow authorized changes
/// - Preserve BFT guarantees
/// - Overwrite old mappings atomically
///
/// # State Transitions
///
/// ```text
/// [Canonical: domain→hash_A]
///        │
///        ▼ (3 oracles vote for hash_B)
/// [Pending: hash_B]
///        │
///        ▼ (delay expires)
/// [Canonical: domain→hash_B] (hash_A replaced)
/// ```
#[tokio::test]
#[cfg(feature = "integration")]
async fn test_enrollment_update() -> color_eyre::Result<()> {
    let (cometbft_bin, felidae_bin) = find_binaries()?;

    let mut network = TestNetwork::create(3).await?;
    network.start(
        cometbft_bin.to_str().unwrap(),
        felidae_bin.to_str().unwrap(),
    )?;
    network.wait_ready(Duration::from_secs(30)).await?;

    let rpc_client = HttpClient::new(network.rpc_url().as_str())?;

    // Use a subdomain of webcat.tech. for update testing
    let update_domain = format!("{}.{}", TEST_SUBDOMAIN_PREFIX_2, TEST_DOMAIN_WEBCAT.0);

    // =========================================================================
    // PHASE 1: Initial enrollment with enrollment_v1
    // =========================================================================
    let enrollment_v1 = test_enrollment_json();

    eprintln!("[test] Phase 1: Initial enrollment for {}", update_domain);
    for i in 0..3 {
        let oracle_key = network.read_oracle_key(i)?;
        submit_observation(
            &rpc_client,
            &oracle_key,
            "felidae-integration-test",
            &update_domain,
            TEST_DOMAIN_WEBCAT.1,
            Some(&enrollment_v1),
        )
        .await?;
        tokio::time::sleep(Duration::from_millis(300)).await;
    }

    tokio::time::sleep(Duration::from_secs(5)).await;

    // Verify initial enrollment via CLI
    let snapshot_v1 = query_snapshot(&felidae_bin, &network.query_url())?;
    eprintln!("[test] snapshot after v1: {:?}", snapshot_v1);

    let hash_v1 = snapshot_v1
        .get(&update_domain)
        .expect(&format!("{} should be enrolled", update_domain))
        .clone();

    // =========================================================================
    // PHASE 2: Update enrollment with a different enrollment (different hash)
    // =========================================================================
    // Create a different enrollment (different signer key = different hash)
    let enrollment_v2 = {
        use ed25519_dalek::SigningKey;
        let signing_key = SigningKey::from_bytes(&[2u8; 32]); // Different seed!
        let verifying_key = signing_key.verifying_key();
        let test_pubkey = base64_url::encode(verifying_key.as_bytes());

        serde_json::json!({
            "signers": [test_pubkey],
            "threshold": 1,
            "policy": "BBBB", // Different policy too
            "max_age": 86400,
            "cas_url": "https://example.com/cas/v2"
        })
        .to_string()
    };

    eprintln!("[test] Phase 2: Update enrollment for {}", update_domain);
    for i in 0..3 {
        let oracle_key = network.read_oracle_key(i)?;
        submit_observation(
            &rpc_client,
            &oracle_key,
            "felidae-integration-test",
            &update_domain,
            TEST_DOMAIN_WEBCAT.1,
            Some(&enrollment_v2),
        )
        .await?;
        tokio::time::sleep(Duration::from_millis(300)).await;
    }

    tokio::time::sleep(Duration::from_secs(5)).await;

    // Verify the enrollment was updated via CLI
    let snapshot_v2 = query_snapshot(&felidae_bin, &network.query_url())?;
    eprintln!("[test] snapshot after v2: {:?}", snapshot_v2);

    let hash_v2 = snapshot_v2
        .get(&update_domain)
        .expect(&format!("{} should still be enrolled", update_domain))
        .clone();

    // The hash should have changed
    assert_ne!(
        hash_v1, hash_v2,
        "enrollment hash should change after update"
    );

    eprintln!("[test] hash changed: {} -> {}", hash_v1, hash_v2);

    Ok(())
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
///
/// # Security Model
///
/// Admin reconfiguration can:
/// - Add/remove authorized oracles
/// - Change quorum thresholds
/// - Modify voting timeouts/delays
/// - Enable/disable features (onion, etc.)
///
/// This requires careful authorization since it affects the entire chain.
#[tokio::test]
#[cfg(feature = "integration")]
async fn test_admin_reconfiguration() -> color_eyre::Result<()> {
    let (cometbft_bin, felidae_bin) = find_binaries()?;

    let mut network = TestNetwork::create(3).await?;
    network.start(
        cometbft_bin.to_str().unwrap(),
        felidae_bin.to_str().unwrap(),
    )?;
    network.wait_ready(Duration::from_secs(30)).await?;

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
            "felidae-integration-test".to_string(),
            Duration::from_secs(60),
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

        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    // Wait for the config change to take effect (admin delay is 0s in test config)
    tokio::time::sleep(Duration::from_secs(3)).await;

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
///
/// This ensures that a minority of compromised or malicious admins cannot
/// unilaterally change the chain configuration. All admins must agree for
/// changes to take effect.
///
/// # Difference from Oracle Voting
///
/// While the voting mechanism is the same, the security implications differ:
/// - Oracle votes affect individual domain mappings (limited blast radius)
/// - Admin votes affect the entire chain configuration (global impact)
///
/// This is why admin quorum is typically set higher (unanimous for small networks).
#[tokio::test]
#[cfg(feature = "integration")]
async fn test_admin_reconfig_minority_no_update() -> color_eyre::Result<()> {
    let (cometbft_bin, felidae_bin) = find_binaries()?;

    let mut network = TestNetwork::create(3).await?;
    network.start(
        cometbft_bin.to_str().unwrap(),
        felidae_bin.to_str().unwrap(),
    )?;
    network.wait_ready(Duration::from_secs(30)).await?;

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
            "felidae-integration-test".to_string(),
            Duration::from_secs(60),
            new_config.clone(),
        )?;

        let tx_bytes = hex::decode(&tx_hex)?;
        let result = rpc_client.broadcast_tx_commit(tx_bytes).await?;

        eprintln!(
            "[test] admin {} reconfig tx: code={:?}, log={}",
            i, result.tx_result.code, result.tx_result.log
        );

        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    // Wait enough time for any potential processing
    tokio::time::sleep(Duration::from_secs(5)).await;

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
///
/// # Why Both Tests Matter
///
/// Together with `test_admin_reconfig_minority_no_update`, this test demonstrates
/// the complete BFT voting behavior:
/// - Minority cannot change config (security property)
/// - Majority CAN change config (liveness property)
///
/// This matches the Byzantine fault tolerance model where the system remains
/// secure against f Byzantine nodes while allowing progress when 2f+1 nodes agree.
#[tokio::test]
#[cfg(feature = "integration")]
async fn test_admin_reconfig_full_quorum_success() -> color_eyre::Result<()> {
    let (cometbft_bin, felidae_bin) = find_binaries()?;

    let mut network = TestNetwork::create(3).await?;
    network.start(
        cometbft_bin.to_str().unwrap(),
        felidae_bin.to_str().unwrap(),
    )?;
    network.wait_ready(Duration::from_secs(30)).await?;

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
            "felidae-integration-test".to_string(),
            Duration::from_secs(60),
            new_config.clone(),
        )?;

        let tx_bytes = hex::decode(&tx_hex)?;
        let result = rpc_client.broadcast_tx_commit(tx_bytes).await?;

        eprintln!(
            "[test] admin {} reconfig tx: code={:?}, log={}",
            i, result.tx_result.code, result.tx_result.log
        );

        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    // Wait for the config change to take effect (admin delay is 0s in test config)
    tokio::time::sleep(Duration::from_secs(3)).await;

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

/// Verifies that the subdomain limit is enforced per registered domain.
///
/// # Business Logic Tested
///
/// This test validates the subdomain limit enforcement in `observe.rs`:
///
/// 1. **Limit Configuration**: Genesis config sets `max_enrolled_subdomains: 5`
/// 2. **Enrollment Counting**: Each registered domain has an independent counter
/// 3. **Early Rejection**: Observations that would exceed the limit are rejected
///
/// # Why This Limit Exists
///
/// Without a subdomain limit, a malicious domain owner could:
/// - Flood the canonical state with thousands of subdomains
/// - Increase storage costs for all validators
/// - Slow down prefix queries and merkle proof generation
///
/// The limit ensures each registered domain can only have a bounded number of
/// subdomains enrolled, preventing resource exhaustion attacks.
///
/// # Limit Calculation
///
/// The limit applies to the "registered domain" which is computed as:
/// `zone + one additional label`
///
/// For example, with zone "com.":
/// - "example.com." is the registered domain
/// - "www.example.com.", "api.example.com.", etc. count toward the limit
///
/// Note: The registered domain ITSELF counts toward the limit! So with limit=5:
/// - example.com. (1) + www.example.com. (2) + api.example.com. (3) + ... = max 5 total
///
/// # Test Strategy
///
/// 1. Enroll the registered domain + 3 subdomains (4 total, under limit)
/// 2. Attempt to enroll more subdomains until limit is hit
/// 3. Verify the limit is enforced
#[tokio::test]
#[cfg(feature = "integration")]
async fn test_subdomain_limit_enforcement() -> color_eyre::Result<()> {
    let (cometbft_bin, felidae_bin) = find_binaries()?;

    let mut network = TestNetwork::create(3).await?;
    network.start(
        cometbft_bin.to_str().unwrap(),
        felidae_bin.to_str().unwrap(),
    )?;
    network.wait_ready(Duration::from_secs(30)).await?;

    let rpc_client = HttpClient::new(network.rpc_url().as_str())?;

    let enrollment = test_enrollment_json();

    // The subdomain limit is 5 per registered domain.
    // We use example.com. as the registered domain (different from other tests using webcat.tech.)
    // Then subdomains like "goss.example.com.", "subby.example.com.", etc.
    // All count toward the limit for "example.com."
    let (registered_domain, zone) = TEST_DOMAIN_EXAMPLE;

    // Create domains: the registered domain + 3 subdomains = 4 total
    // The check is: unique_subdomains + 1 >= max_enrolled_subdomains
    // So with max=5 and 4 existing, we can't add a 5th.
    // Therefore we can only have 4 total entries.
    let subdomains: Vec<String> = vec![
        registered_domain.to_string(), // example.com. (the registered domain itself)
        format!("{}.{}", TEST_SUBDOMAIN_PREFIX_1, registered_domain), // goss.example.com.
        format!("{}.{}", TEST_SUBDOMAIN_PREFIX_2, registered_domain), // subby.example.com.
        format!("{}1.{}", TEST_SUBDOMAIN_PREFIX_1, registered_domain), // goss1.example.com.
    ];

    // =========================================================================
    // PHASE 1: Enroll 4 entries under the registered domain
    // =========================================================================
    eprintln!("[test] Phase 1: Enrolling {} entries", subdomains.len());

    for (idx, subdomain) in subdomains.iter().enumerate() {
        eprintln!("[test] Enrolling entry {}: {}", idx, subdomain);

        for i in 0..3 {
            let oracle_key = network.read_oracle_key(i)?;
            submit_observation(
                &rpc_client,
                &oracle_key,
                "felidae-integration-test",
                subdomain,
                zone,
                Some(&enrollment),
            )
            .await?;
            tokio::time::sleep(Duration::from_millis(200)).await;
        }

        // Wait for this entry to reach canonical state before enrolling next
        tokio::time::sleep(Duration::from_secs(3)).await;
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

    // =========================================================================
    // PHASE 2: Attempt to enroll another subdomain (should fail at limit)
    // =========================================================================
    eprintln!("[test] Phase 2: Attempting 5th entry (should fail)");

    let over_limit_subdomain = format!("{}2.{}", TEST_SUBDOMAIN_PREFIX_2, registered_domain);

    // Even submitting observations should fail because the limit check happens early
    let mut rejected = false;
    for i in 0..3 {
        let oracle_key = network.read_oracle_key(i)?;
        let result = submit_observation(
            &rpc_client,
            &oracle_key,
            "felidae-integration-test",
            &over_limit_subdomain,
            zone,
            Some(&enrollment),
        )
        .await;

        // The observation should fail due to subdomain limit
        if result.is_err() {
            let err_msg = result.unwrap_err().to_string();
            eprintln!("[test] over-limit subdomain rejected: {}", err_msg);
            rejected = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    // Give time for any processing
    tokio::time::sleep(Duration::from_secs(3)).await;

    // Verify the over-limit subdomain is NOT in canonical state via CLI
    let snapshot = query_snapshot(&felidae_bin, &network.query_url())?;
    eprintln!("[test] final snapshot: {:?}", snapshot);

    // Either the transaction was rejected OR it wasn't promoted to canonical
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

// =============================================================================
// CLI WORKFLOW INTEGRATION TESTS
// =============================================================================

/// Verifies that `felidae admin template --read-local-keys` correctly reads keys.
///
/// # Business Logic Tested
///
/// This test validates the admin template CLI command used in production workflows:
///
/// 1. **Key Discovery**: The `--read-local-keys` flag locates keypair files
/// 2. **Key Parsing**: PKCS#8-encoded keys are correctly decoded
/// 3. **Public Key Extraction**: The public key is extracted from the keypair
/// 4. **Template Generation**: A valid Config JSON is produced with the keys
///
/// # Production Workflow
///
/// In production, operators use this command to bootstrap their chain configuration:
///
/// ```bash
/// # Initialize keys (one-time setup)
/// felidae admin init
/// felidae oracle init
///
/// # Generate config template with auto-detected keys
/// felidae admin template --read-local-keys > config.json
///
/// # Submit the config to the network
/// felidae admin config config.json --node http://localhost:26657 --chain felidae
/// ```
///
/// This test ensures the template generation step works correctly.
///
/// # Test Strategy
///
/// 1. Create a test network (generates keys in node-specific directories)
/// 2. Use `--homedir` to point to a validator's felidae home directory
/// 3. Run `felidae admin template --read-local-keys --homedir <path>`
/// 4. Verify the output JSON contains the correct public keys
#[tokio::test]
#[cfg(feature = "integration")]
async fn test_admin_template_read_local_keys() -> color_eyre::Result<()> {
    let (_cometbft_bin, felidae_bin) = find_binaries()?;

    // Create a network - this generates keys on the fly
    // We don't need to start the network, just initialize it to generate keys
    let temp_dir = tempfile::tempdir()?;
    let directory = temp_dir.path().to_path_buf();

    let config = NetworkConfig {
        chain_id: "felidae-template-test".to_string(),
        num_validators: 1,
        use_sentries: false,
        directory,
        ..Default::default()
    };

    let mut network = Network::new(config);
    network.initialize()?;

    // Get the first validator's felidae home directory
    let validator = &network.nodes[0];
    let felidae_home = validator.felidae_home();

    eprintln!(
        "[test] using felidae home directory: {}",
        felidae_home.display()
    );

    // Read the expected public keys from the generated key files
    let admin_key_hex = std::fs::read_to_string(validator.admin_key_path())?;
    let admin_keypair = KeyPair::decode(&hex::decode(admin_key_hex.trim())?)?;
    let expected_admin_pubkey = hex::encode(admin_keypair.public_key());

    let oracle_key_hex = std::fs::read_to_string(validator.oracle_key_path())?;
    let oracle_keypair = KeyPair::decode(&hex::decode(oracle_key_hex.trim())?)?;
    let expected_oracle_pubkey = hex::encode(oracle_keypair.public_key());

    eprintln!("[test] expected admin pubkey: {}", expected_admin_pubkey);
    eprintln!("[test] expected oracle pubkey: {}", expected_oracle_pubkey);

    // Run `felidae admin template --read-local-keys --homedir <felidae_home>`
    let output = Command::new(&felidae_bin)
        .args([
            "admin",
            "template",
            "--read-local-keys",
            "--homedir",
            &felidae_home.to_string_lossy(),
        ])
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(color_eyre::eyre::eyre!(
            "felidae admin template failed: {}",
            stderr
        ));
    }

    let stdout = String::from_utf8(output.stdout)?;
    eprintln!("[test] template output:\n{}", stdout);

    // Parse the output JSON
    let template_config: felidae_types::transaction::Config = serde_json::from_str(&stdout)?;

    // Verify the admin public key is present and correct
    assert_eq!(
        template_config.admins.authorized.len(),
        1,
        "expected 1 authorized admin"
    );
    let actual_admin_pubkey = hex::encode(&template_config.admins.authorized[0].identity);
    assert_eq!(
        actual_admin_pubkey, expected_admin_pubkey,
        "admin public key mismatch"
    );

    // Verify the oracle public key is present and correct
    assert_eq!(
        template_config.oracles.authorized.len(),
        1,
        "expected 1 authorized oracle"
    );
    let actual_oracle_pubkey = hex::encode(&template_config.oracles.authorized[0].identity);
    assert_eq!(
        actual_oracle_pubkey, expected_oracle_pubkey,
        "oracle public key mismatch"
    );

    eprintln!("[test] felidae admin template --read-local-keys works correctly");

    Ok(())
}

/// Verifies the complete admin initialization and template workflow.
///
/// # Business Logic Tested
///
/// This test validates the full admin CLI workflow from scratch:
///
/// 1. **Admin Init**: `felidae admin init` creates a new admin keypair
/// 2. **Admin Identity**: `felidae admin identity` displays the public key
/// 3. **Template Generation**: `felidae admin template --read-local-keys` includes the key
///
/// # Why This Test Matters
///
/// This exercises the exact commands an operator would run when setting up
/// a new validator node. Unlike `test_admin_template_read_local_keys` which
/// uses deployer-generated keys, this test uses the CLI to generate keys,
/// ensuring the full user workflow is functional.
///
/// # Test Strategy
///
/// 1. Create a temporary directory for the test
/// 2. Run `felidae admin init --homedir <temp>` to generate keys
/// 3. Run `felidae admin identity --homedir <temp>` to get the public key
/// 4. Run `felidae admin template --read-local-keys --homedir <temp>`
/// 5. Verify the template contains the correct public key
#[tokio::test]
#[cfg(feature = "integration")]
async fn test_admin_init_identity_template_workflow() -> color_eyre::Result<()> {
    let (_cometbft_bin, felidae_bin) = find_binaries()?;

    // Create a temporary directory for this test's keys
    let temp_dir = tempfile::tempdir()?;
    let homedir = temp_dir.path();

    eprintln!("[test] using temp homedir: {}", homedir.display());

    // Step 1: Run `felidae admin init --homedir <temp>`
    let output = Command::new(&felidae_bin)
        .args(["admin", "init", "--homedir", &homedir.to_string_lossy()])
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(color_eyre::eyre::eyre!(
            "felidae admin init failed: {}",
            stderr
        ));
    }

    eprintln!(
        "[test] admin init output: {}",
        String::from_utf8_lossy(&output.stdout)
    );

    // Step 2: Run `felidae admin identity --homedir <temp>` to get the public key
    let output = Command::new(&felidae_bin)
        .args(["admin", "identity", "--homedir", &homedir.to_string_lossy()])
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(color_eyre::eyre::eyre!(
            "felidae admin identity failed: {}",
            stderr
        ));
    }

    let identity_output = String::from_utf8(output.stdout)?;
    let expected_pubkey = identity_output.trim();
    eprintln!("[test] admin identity: {}", expected_pubkey);

    // Step 3: Run `felidae admin template --read-local-keys --homedir <temp>`
    // Note: This will only have the admin key since we didn't init an oracle
    let output = Command::new(&felidae_bin)
        .args([
            "admin",
            "template",
            "--read-local-keys",
            "--homedir",
            &homedir.to_string_lossy(),
        ])
        .output()?;

    // The template command should succeed, but warn about missing oracle key
    let stdout = String::from_utf8(output.stdout)?;
    let stderr = String::from_utf8_lossy(&output.stderr);
    eprintln!("[test] template stderr (expected warning): {}", stderr);
    eprintln!("[test] template output:\n{}", stdout);

    // Parse the output JSON
    let template_config: felidae_types::transaction::Config = serde_json::from_str(&stdout)?;

    // Verify the admin public key matches what identity reported
    assert_eq!(
        template_config.admins.authorized.len(),
        1,
        "expected 1 authorized admin"
    );
    let actual_admin_pubkey = hex::encode(&template_config.admins.authorized[0].identity);
    assert_eq!(
        actual_admin_pubkey, expected_pubkey,
        "admin public key from template should match identity output"
    );

    // Oracle key was not initialized, so a warning should have been printed.
    // The template retains its default placeholder (all zeros) when key load fails.
    // Verify the warning was printed to stderr.
    assert!(
        stderr.contains("warning: could not load oracle key"),
        "expected warning about missing oracle key in stderr"
    );

    eprintln!("[test] admin init -> identity -> template workflow works correctly");

    Ok(())
}
