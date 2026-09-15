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
use felidae_types::transaction::ValidatorConfig;
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
        return Self::create_with_block_time(num_validators, crate::constants::block_time()).await;
    }

    pub async fn create_with_block_time(
        num_validators: usize,
        block_time: Duration,
    ) -> color_eyre::Result<Self> {
        Self::create_with_validator_config(num_validators, block_time, None).await
    }

    /// Create a test network with an explicit `ValidatorConfig` override at genesis.
    ///
    /// `validator_config` of `None` keeps the production defaults (10_000-block
    /// uptime window, 500 missed-blocks jail threshold). Tests that need to
    /// exercise jailing in seconds rather than minutes should pass tight
    /// thresholds so the lifecycle fires within the test's wall-clock budget.
    pub async fn create_with_validator_config(
        num_validators: usize,
        block_time: Duration,
        validator_config: Option<ValidatorConfig>,
    ) -> color_eyre::Result<Self> {
        let temp_dir = tempfile::tempdir()?;
        let directory = temp_dir.path().to_path_buf();

        let config = NetworkConfig {
            chain_id: crate::constants::TEST_CHAIN_ID.to_string(),
            num_validators,
            use_sentries: false,
            directory,
            timeout_commit: format!("{}s", block_time.as_secs()),
            ..Default::default()
        };

        let mut network = Network::new(config);
        network.initialize()?;

        // Generate felidae config and inject it into genesis
        // Uses 1s oracle delay for testing, 0s admin delay for immediate config changes
        let mut felidae_config = network.generate_felidae_config(
            Duration::from_secs(1), // oracle voting delay
            Duration::from_secs(0), // admin voting delay
        )?;
        if let Some(vc) = validator_config {
            felidae_config.validator_config = vc;
        }
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

        for index in 0..self.network.nodes.len() {
            self.spawn_node_processes(index, cometbft_bin, felidae_bin)?;
        }

        Ok(())
    }

    /// Spawn the CometBFT + Felidae (+ Oracle, for validators) processes for a
    /// single node and insert their handles into `self.processes`.
    ///
    /// Used by [`start`](Self::start) for the initial bring-up and by
    /// [`restart_validator`](Self::restart_validator) to bring a previously
    /// killed validator back online with the same home directory.
    fn spawn_node_processes(
        &mut self,
        index: usize,
        cometbft_bin: &str,
        felidae_bin: &str,
    ) -> color_eyre::Result<()> {
        let node = &self.network.nodes[index];

        // Start CometBFT
        let cometbft_name = format!("{}-cometbft", node.name);
        let child = Command::new(cometbft_bin)
            .args(["start", "--home", &node.cometbft_home().to_string_lossy()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        self.processes.insert(cometbft_name, child);

        // Start Felidae
        let felidae_name = format!("{}-felidae", node.name);
        let felidae_log = std::fs::File::create(node.home_dir.join("felidae.log"))?;
        let child = Command::new(felidae_bin)
            .env("RUST_LOG", "info")
            .args([
                "start",
                "--abci-bind",
                &node.abci_address(),
                "--query-bind",
                &format!("{}:{}", node.bind_address, node.ports.felidae_query),
                "--homedir",
                &node.felidae_home().to_string_lossy(),
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::from(felidae_log))
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
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()?;
            self.processes.insert(oracle_name, child);
        }

        Ok(())
    }

    /// Kill the CometBFT, Felidae, and Oracle processes for a single validator
    /// node by index, leaving its home directory (and signing key) intact.
    ///
    /// Used to drive downtime-based lifecycle scenarios (jail/unjail). The
    /// caller is responsible for waiting on the consequences (e.g. polling
    /// CometBFT's validator set for a power drop to `1`).
    ///
    /// After this returns, the node's TCP ports may still be held briefly by
    /// the kernel; [`restart_validator`](Self::restart_validator) handles that
    /// by polling until the ports are free before respawning.
    pub fn kill_validator(&mut self, index: usize) -> color_eyre::Result<()> {
        if index >= self.network.nodes.len() {
            return Err(color_eyre::eyre::eyre!(
                "kill_validator: index {index} out of range (network has {} nodes)",
                self.network.nodes.len()
            ));
        }
        let node_name = self.network.nodes[index].name.clone();
        let prefixes = [
            format!("{node_name}-cometbft"),
            format!("{node_name}-felidae"),
            format!("{node_name}-oracle"),
        ];

        for prefix in &prefixes {
            if let Some(mut child) = self.processes.remove(prefix) {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
        eprintln!("[kill_validator] killed processes for node {node_name}");
        Ok(())
    }

    /// Restart the processes previously stopped by
    /// [`kill_validator`](Self::kill_validator), reusing the node's home
    /// directory so its consensus key and any on-disk state are preserved.
    ///
    /// Polls for the node's TCP ports to become free before spawning, so a
    /// freshly killed validator can be restarted back-to-back without the
    /// `address already in use` race that the kernel's TIME_WAIT window can
    /// otherwise produce.
    pub fn restart_validator(
        &mut self,
        index: usize,
        cometbft_bin: &str,
        felidae_bin: &str,
    ) -> color_eyre::Result<()> {
        if index >= self.network.nodes.len() {
            return Err(color_eyre::eyre::eyre!(
                "restart_validator: index {index} out of range (network has {} nodes)",
                self.network.nodes.len()
            ));
        }

        let node = &self.network.nodes[index];
        let ports_to_free = [
            node.ports.cometbft_p2p,
            node.ports.cometbft_rpc,
            node.ports.felidae_abci,
            node.ports.felidae_query,
        ]
        .into_iter()
        .chain(if node.role.is_validator() {
            Some(node.ports.felidae_oracle)
        } else {
            None
        })
        .collect::<Vec<_>>();

        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        loop {
            let all_free = ports_to_free
                .iter()
                .all(|port| std::net::TcpListener::bind(("127.0.0.1", *port)).is_ok());
            if all_free {
                break;
            }
            if std::time::Instant::now() > deadline {
                return Err(color_eyre::eyre::eyre!(
                    "restart_validator: node {} ports still held after 10s",
                    node.name
                ));
            }
            std::thread::sleep(Duration::from_millis(100));
        }

        self.spawn_node_processes(index, cometbft_bin, felidae_bin)?;
        eprintln!(
            "[restart_validator] restarted processes for node {}",
            self.network.nodes[index].name
        );
        Ok(())
    }

    /// Wait for the network to be ready (blocks are being produced).
    pub async fn wait_ready(&mut self, timeout: Duration) -> color_eyre::Result<()> {
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
                Err(e) => {
                    eprintln!("[wait_ready] RPC error (retrying): {e}");
                    // Check if any process has exited unexpectedly
                    for (name, child) in &mut self.processes {
                        if let Some(status) = child.try_wait()? {
                            return Err(color_eyre::eyre::eyre!(
                                "process '{name}' exited unexpectedly: {status}"
                            ));
                        }
                    }
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
