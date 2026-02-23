//! Test network harness for managing multi-validator felidae deployments.
//!
//! This module provides the `TestNetwork` struct which handles the full lifecycle
//! of a test network, including process management, key access, and cleanup.

use std::collections::HashMap;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use felidae_deployer::{Network, NetworkConfig};
use tendermint_rpc::{Client, HttpClient};

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
pub struct TestNetwork {
    /// Network configuration and node topology
    pub network: Network,
    /// Map of process name to running process handle
    processes: HashMap<String, Child>,
    /// Shutdown signal for coordinated termination
    shutdown: Arc<AtomicBool>,
    /// Temporary directory guard; dropped after TestNetwork to ensure cleanup
    _temp_dir: tempfile::TempDir,
}

impl TestNetwork {
    /// Create and initialize a new test network with the specified number of validators.
    pub async fn create(num_validators: usize) -> color_eyre::Result<Self> {
        let temp_dir = tempfile::tempdir()?;
        let directory = temp_dir.path().to_path_buf();

        let config = NetworkConfig {
            chain_id: crate::constants::TEST_CHAIN_ID.to_string(),
            num_validators,
            use_sentries: false,
            directory,
            timeout_commit: crate::constants::timeout_commit_str(),
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
    pub fn start(&mut self, cometbft_bin: &str, felidae_bin: &str) -> color_eyre::Result<()> {
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
    pub async fn wait_ready(&self, timeout: Duration) -> color_eyre::Result<()> {
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
    pub fn rpc_url(&self) -> String {
        format!(
            "http://{}:{}",
            self.network.nodes[0].bind_address, self.network.nodes[0].ports.cometbft_rpc
        )
    }

    /// Get the first node's Felidae query API URL.
    pub fn query_url(&self) -> String {
        format!(
            "http://{}:{}",
            self.network.nodes[0].bind_address, self.network.nodes[0].ports.felidae_query
        )
    }

    /// Get a validator node's Oracle server URL.
    pub fn oracle_url(&self, validator_index: usize) -> String {
        let node = &self.network.nodes[validator_index];
        format!("http://{}:{}", node.bind_address, node.ports.felidae_oracle)
    }

    /// Wait for all oracle servers to be ready (health check returns OK).
    pub async fn wait_oracles_ready(&self, timeout: Duration) -> color_eyre::Result<()> {
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
    pub fn read_oracle_key(&self, validator_index: usize) -> color_eyre::Result<Vec<u8>> {
        let node = &self.network.nodes[validator_index];
        let key_hex = std::fs::read_to_string(node.oracle_key_path())?;
        Ok(hex::decode(key_hex.trim())?)
    }

    /// Read an admin key from a validator node.
    pub fn read_admin_key(&self, validator_index: usize) -> color_eyre::Result<Vec<u8>> {
        let node = &self.network.nodes[validator_index];
        let key_hex = std::fs::read_to_string(node.admin_key_path())?;
        Ok(hex::decode(key_hex.trim())?)
    }

    /// Shutdown all processes and wait for ports to be released.
    pub fn shutdown(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        for (_name, mut child) in self.processes.drain() {
            let _ = child.kill();
            let _ = child.wait();
        }

        // After SIGKILL + reap, the kernel may still hold TCP sockets briefly.
        // Poll until every port used by this network is genuinely free, so the
        // next test can bind without races.
        let ports = self.network.collect_required_ports();
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        loop {
            let all_free = ports
                .iter()
                .all(|(port, _)| std::net::TcpListener::bind(("127.0.0.1", *port)).is_ok());
            if all_free {
                break;
            }
            if std::time::Instant::now() > deadline {
                eprintln!("[shutdown] warning: ports still held after 10s, proceeding anyway");
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }

        // Give the OS time to fully reclaim resources (file descriptors, tmpfs
        // pages, process table entries) before the next test spins up another
        // 9-process cluster.
        std::thread::sleep(Duration::from_secs(2));
    }
}

impl Drop for TestNetwork {
    fn drop(&mut self) {
        self.shutdown();
    }
}
