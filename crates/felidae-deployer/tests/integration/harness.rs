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
use tendermint_rpc::Client;

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
    /// Map of process name to running process handle.
    ///
    /// Shared with [`liveness`], so a polling helper can notice that a node
    /// died without every call site having to thread a handle through.
    processes: Processes,
    /// Shutdown signal for coordinated termination
    shutdown: Arc<AtomicBool>,
    /// Where this network's nodes keep their state and logs. Retained after the
    /// test ends; see the note in `create_with_validator_config`.
    pub directory: std::path::PathBuf,
    /// The config injected at genesis.
    ///
    /// Kept so tests can ask how many parties a vote needs rather than
    /// hardcoding it. Quorum moves with the validator count -- 3-of-3 at n=3,
    /// 3-of-4, 4-of-5 -- so a literal `3` is right at two topologies and
    /// silently wrong at the third.
    pub genesis_config: felidae_types::transaction::Config,
}

/// The child processes of the network currently under test.
type Processes = Arc<std::sync::Mutex<HashMap<String, Child>>>;

/// The network under test, if one is running.
///
/// A process-wide slot rather than a handle threaded through every helper.
/// That is sound here because these tests are necessarily serial -- they bind
/// fixed ports, and `just integration` passes `--test-threads 1` -- so at most
/// one `TestNetwork` exists at a time. [`TestNetwork::start`] installs itself
/// and [`Drop`] clears the slot.
static LIVE_NETWORK: std::sync::Mutex<Option<Processes>> = std::sync::Mutex::new(None);

/// Names of any processes belonging to the running network that have exited,
/// with their statuses. Empty when every process is alive, or when no network
/// is registered.
///
/// A validator whose ABCI service dies leaves its CometBFT peer answering RPC
/// from its last block, so polls against it time out without saying why.
pub fn dead_processes() -> Vec<String> {
    let Ok(slot) = LIVE_NETWORK.lock() else {
        return Vec::new();
    };
    let Some(processes) = slot.as_ref() else {
        return Vec::new();
    };
    let Ok(mut processes) = processes.lock() else {
        return Vec::new();
    };
    let mut dead: Vec<String> = processes
        .iter_mut()
        .filter_map(|(name, child)| match child.try_wait() {
            Ok(Some(status)) => Some(format!("{name} ({status})")),
            Ok(None) => None,
            Err(e) => Some(format!("{name} (status unavailable: {e})")),
        })
        .collect();
    dead.sort();
    dead
}

/// `Err` naming the dead processes if any have exited, otherwise `Ok(())`.
///
/// Call this from any loop that waits on chain state: a condition that depends
/// on a node which is no longer running will never be met, and failing with
/// the reason beats timing out without one.
pub fn ensure_network_alive(context: &str) -> color_eyre::Result<()> {
    let dead = dead_processes();
    if dead.is_empty() {
        return Ok(());
    }
    Err(color_eyre::eyre::eyre!(
        "{context}: process(es) exited during the run: {}",
        dead.join(", ")
    ))
}

/// The port layout for this run, shifted by `FELIDAE_TEST_PORT_OFFSET`.
///
/// The bases in `ports.rs` are compile-time constants, so without this two runs
/// fight over 26657 and repeated campaigns must run strictly serially.
///
/// One offset shifts all five families together. A run occupies
/// `base .. base + 500` in each, so **use multiples of 1000**. Default 0.
///
/// Concurrency still needs a separate worktree per lane: two `cargo nextest`
/// invocations against one target directory serialise on the cargo lock.
fn port_strategy() -> felidae_deployer::PortAllocationStrategy {
    let offset: u16 = std::env::var("FELIDAE_TEST_PORT_OFFSET")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let base = felidae_deployer::PortAllocationStrategy::default();
    if offset == 0 {
        return base;
    }
    eprintln!("[harness] port offset: +{offset}");
    felidae_deployer::PortAllocationStrategy {
        cometbft_p2p_base: base.cometbft_p2p_base + offset,
        cometbft_rpc_base: base.cometbft_rpc_base + offset,
        felidae_abci_base: base.felidae_abci_base + offset,
        felidae_query_base: base.felidae_query_base + offset,
        felidae_oracle_base: base.felidae_oracle_base + offset,
        node_offset: base.node_offset,
    }
}

impl TestNetwork {
    /// The process map, locked. Panics only if a previous holder panicked,
    /// which in a test harness should fail loudly rather than be papered over.
    fn lock_processes(&self) -> std::sync::MutexGuard<'_, HashMap<String, Child>> {
        self.processes.lock().expect("process map poisoned")
    }

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
        // Keep the network tree, always. Retaining only on failure can't be
        // done from `Drop`: tests fail by returning `Err`, so
        // `thread::panicking()` is false. A full suite leaves ~60 MB under
        // `TMPDIR`, which is per-invocation in the nix shell and in CI.
        let directory = tempfile::tempdir()?.keep();
        eprintln!("[harness] network directory: {}", directory.display());

        let config = NetworkConfig {
            chain_id: crate::constants::TEST_CHAIN_ID.to_string(),
            num_validators,
            use_sentries: false,
            directory: directory.clone(),
            timeout_commit: format!("{}s", block_time.as_secs()),
            port_strategy: port_strategy(),
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
            genesis_config: felidae_config,
            network,
            processes: Arc::new(std::sync::Mutex::new(HashMap::new())),
            shutdown: Arc::new(AtomicBool::new(false)),
            directory,
        })
    }

    /// Start all network processes (CometBFT + Felidae + Oracle for each validator).
    pub fn start(&mut self, cometbft_bin: &str, felidae_bin: &str) -> color_eyre::Result<()> {
        // Preflight check: verify all ports are available before starting any processes
        self.network.check_ports_available()?;

        // Publish the process map before spawning, so a node that dies during
        // bring-up is already visible to `dead_processes`.
        *LIVE_NETWORK.lock().expect("liveness slot poisoned") = Some(self.processes.clone());

        for index in 0..self.network.nodes.len() {
            self.spawn_node_processes(index, cometbft_bin, felidae_bin)?;
        }

        Ok(())
    }

    /// Spawn the processes for the node at `index` in the network topology.
    ///
    /// Used by [`start`](Self::start) for the initial bring-up and by
    /// [`restart_validator`](Self::restart_validator) to bring a previously
    /// killed validator back online with the same home directory.
    fn spawn_node_processes(
        &self,
        index: usize,
        cometbft_bin: &str,
        felidae_bin: &str,
    ) -> color_eyre::Result<()> {
        self.spawn_processes(&self.network.nodes[index], cometbft_bin, felidae_bin)
    }

    /// Spawn the CometBFT + Felidae (+ Oracle, for validators) processes for
    /// `node` and insert their handles into `self.processes`.
    ///
    /// Public so a node that joins after genesis runs under the same
    /// supervision: logs captured in its home, liveness-tracked, and reaped at
    /// teardown. Join it under [`directory`](Self::directory) so its home is
    /// retained with the rest of the tree. A newcomer spawned outside the
    /// harness dies anonymously -- no logs, no tree, and a sync wait that can
    /// only time out.
    pub fn spawn_processes(
        &self,
        node: &felidae_deployer::WebcatNode,
        cometbft_bin: &str,
        felidae_bin: &str,
    ) -> color_eyre::Result<()> {
        // Felidae first; see `wait_for_abci` below.
        let felidae_name = format!("{}-felidae", node.name);
        let felidae_log = std::fs::File::create(node.home_dir.join("felidae.log"))?;
        let felidae_log_out = felidae_log.try_clone()?;
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
            .stdout(Stdio::from(felidae_log_out))
            .stderr(Stdio::from(felidae_log))
            .spawn()?;
        self.lock_processes().insert(felidae_name, child);

        // CometBFT dials ABCI as soon as it starts and backs off a flat 3s on
        // refusal. felidae opens RocksDB before it binds, so starting CometBFT
        // without waiting costs every node the full 3s.
        wait_for_abci(&node.abci_address(), Duration::from_secs(30))?;

        // Then CometBFT, keeping its log beside felidae's.
        //
        // CometBFT logs to stdout, so both streams have to be captured. Without
        // this, what CometBFT did when its ABCI socket died is unknowable from
        // a retained tree -- and that is the half of the story felidae.log
        // cannot tell.
        let cometbft_name = format!("{}-cometbft", node.name);
        let cometbft_log = std::fs::File::create(node.home_dir.join("cometbft.log"))?;
        let cometbft_log_err = cometbft_log.try_clone()?;
        let child = Command::new(cometbft_bin)
            .args(["start", "--home", &node.cometbft_home().to_string_lossy()])
            .stdout(Stdio::from(cometbft_log))
            .stderr(Stdio::from(cometbft_log_err))
            .spawn()?;
        self.lock_processes().insert(cometbft_name, child);

        // Start Oracle server for validators
        if node.role.is_validator() {
            let oracle_name = format!("{}-oracle", node.name);
            let oracle_log = std::fs::File::create(node.home_dir.join("oracle.log"))?;
            let oracle_log_out = oracle_log.try_clone()?;
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
                .stdout(Stdio::from(oracle_log_out))
                .stderr(Stdio::from(oracle_log))
                .spawn()?;
            self.lock_processes().insert(oracle_name, child);
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
            let existing = self.lock_processes().remove(prefix);
            if let Some(mut child) = existing {
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
        let client = crate::helpers::rpc_client(rpc_url.as_str())?;

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
                }
            }

            // Bring-up is the one place a node reliably dies, so check every
            // iteration rather than only when the RPC call fails.
            ensure_network_alive("waiting for the network to be ready")?;

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

    /// How many validators this network has.
    pub fn validator_count(&self) -> usize {
        self.network.validators().count()
    }

    /// How many admins must vote before a reconfiguration is promoted.
    pub fn admin_quorum(&self) -> usize {
        self.genesis_config.admins.voting.quorum.0 as usize
    }

    /// How many oracles must agree before an observation becomes canonical.
    pub fn oracle_quorum(&self) -> usize {
        self.genesis_config.oracles.voting.quorum.0 as usize
    }

    /// One short of admin quorum: the largest vote that must *not* promote.
    pub fn admin_minority(&self) -> usize {
        self.admin_quorum().saturating_sub(1)
    }

    /// One short of oracle quorum.
    pub fn oracle_minority(&self) -> usize {
        self.oracle_quorum().saturating_sub(1)
    }

    /// A specific node's felidae query URL.
    pub fn node_query_url(&self, index: usize) -> String {
        let node = &self.network.nodes[index];
        format!("http://{}:{}", node.bind_address, node.ports.felidae_query)
    }

    /// Every node's felidae query URL, in node order.
    pub fn query_urls(&self) -> Vec<String> {
        (0..self.network.nodes.len())
            .map(|i| self.node_query_url(i))
            .collect()
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
        // Name any process that died on its own before teardown kills the
        // rest. A bare `?` on RPC to a dead node fails as an HTTP error; this
        // puts the cause beside it in the test's output.
        let dead = dead_processes();
        if !dead.is_empty() {
            eprintln!(
                "[harness] process(es) exited during the run: {}",
                dead.join(", ")
            );
        }
        // Deregister first, so a poll racing teardown isn't told the network
        // "died".
        *LIVE_NETWORK.lock().expect("liveness slot poisoned") = None;
        let drained: Vec<(String, Child)> = self.lock_processes().drain().collect();
        for (_name, mut child) in drained {
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

/// Poll until `addr` accepts a TCP connection, or `timeout` elapses.
///
/// Used to sequence felidae's ABCI listener ahead of CometBFT's first dial.
fn wait_for_abci(addr: &str, timeout: Duration) -> color_eyre::Result<()> {
    let deadline = std::time::Instant::now() + timeout;
    let target: std::net::SocketAddr = addr.parse()?;
    while std::time::Instant::now() < deadline {
        if std::net::TcpStream::connect_timeout(&target, Duration::from_millis(200)).is_ok() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    Err(color_eyre::eyre::eyre!(
        "felidae did not accept on {addr} within {timeout:?}"
    ))
}
