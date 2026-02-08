//! Network configuration and management for felidae deployments.

use std::fs;
use std::io::Write;
use std::net::TcpListener;
use std::path::PathBuf;
use std::time::Duration;

use bytes::Bytes;
use color_eyre::eyre::{Result, WrapErr};
use ed25519_dalek::SigningKey;
use felidae_types::KeyPair;
use felidae_types::transaction::{
    Admin, AdminConfig, Config, Delay, OnionConfig, Oracle, OracleConfig, Quorum, Timeout, Total,
    VotingConfig,
};
use p256::SecretKey;
use pkcs8::EncodePrivateKey;
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::node::{NodeRole, WebcatNode};
use crate::ports::PortAllocationStrategy;

/// The deployment platform for the network.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Platform {
    /// Local deployment (localhost).
    #[default]
    Local,
    /// Docker/container deployment.
    Docker,
    /// Kubernetes deployment.
    Kubernetes,
}

/// Configuration for creating a network.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// The chain ID for the network.
    pub chain_id: String,
    /// Number of validator nodes.
    pub num_validators: usize,
    /// Whether to create sentry nodes for validators.
    pub use_sentries: bool,
    /// The deployment platform.
    pub platform: Platform,
    /// The base directory for the network.
    pub directory: PathBuf,
    /// Port allocation strategy.
    #[serde(default)]
    pub port_strategy: PortAllocationStrategy,
    /// CometBFT timeout_commit setting (block interval).
    #[serde(default = "default_timeout_commit")]
    pub timeout_commit: String,
}

fn default_timeout_commit() -> String {
    "1s".to_string()
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            chain_id: "felidae-test".to_string(),
            num_validators: 1,
            use_sentries: false,
            platform: Platform::Local,
            directory: PathBuf::from("/tmp/felidae-network"),
            port_strategy: PortAllocationStrategy::default(),
            timeout_commit: default_timeout_commit(),
        }
    }
}

/// A felidae network consisting of multiple nodes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Network {
    /// The network configuration.
    pub config: NetworkConfig,
    /// The nodes in this network.
    pub nodes: Vec<WebcatNode>,
}

impl Network {
    /// Create a new network from configuration.
    pub fn new(config: NetworkConfig) -> Self {
        let mut nodes = Vec::new();
        let mut node_index = 0;

        // Create validator nodes
        for i in 0..config.num_validators {
            let name = format!("validator-{}", i);
            let ports = config.port_strategy.allocate(node_index);
            let home_dir = config.directory.join(&name);
            nodes.push(WebcatNode::new(name, NodeRole::Validator, ports, home_dir));
            node_index += 1;
        }

        // Create sentry nodes if requested
        if config.use_sentries {
            for i in 0..config.num_validators {
                let name = format!("sentry-{}", i);
                let ports = config.port_strategy.allocate(node_index);
                let home_dir = config.directory.join(&name);
                nodes.push(WebcatNode::new(name, NodeRole::Sentry, ports, home_dir));
                node_index += 1;
            }
        }

        Self { config, nodes }
    }

    /// Get all validator nodes.
    pub fn validators(&self) -> impl Iterator<Item = &WebcatNode> {
        self.nodes.iter().filter(|n| n.role == NodeRole::Validator)
    }

    /// Get all sentry nodes.
    pub fn sentries(&self) -> impl Iterator<Item = &WebcatNode> {
        self.nodes.iter().filter(|n| n.role == NodeRole::Sentry)
    }

    /// Get all full nodes.
    pub fn full_nodes(&self) -> impl Iterator<Item = &WebcatNode> {
        self.nodes.iter().filter(|n| n.role == NodeRole::FullNode)
    }

    /// Collect all ports that will be used by this network.
    ///
    /// # Returns
    /// A vector of (port, description) tuples for all ports that will be bound
    pub fn collect_required_ports(&self) -> Vec<(u16, String)> {
        let mut ports = Vec::new();

        for node in &self.nodes {
            ports.push((
                node.ports.cometbft_p2p,
                format!("{} CometBFT P2P", node.name),
            ));
            ports.push((
                node.ports.cometbft_rpc,
                format!("{} CometBFT RPC", node.name),
            ));
            ports.push((
                node.ports.felidae_abci,
                format!("{} Felidae ABCI", node.name),
            ));
            ports.push((
                node.ports.felidae_query,
                format!("{} Felidae Query", node.name),
            ));
            // Oracle port is used by validators
            if node.role.is_validator() {
                ports.push((
                    node.ports.felidae_oracle,
                    format!("{} Felidae Oracle", node.name),
                ));
            }
        }

        ports
    }

    /// Check that all required ports are available before starting the network.
    ///
    /// This performs a preflight check by attempting to bind to each port and immediately
    /// releasing it.
    ///
    /// # Returns
    /// * `Ok(())` if all ports are available
    /// * `Err` with details about unavailable ports
    pub fn check_ports_available(&self) -> Result<()> {
        let ports = self.collect_required_ports();
        check_ports_available(&ports)
    }

    /// Initialize the network by creating all necessary directories and files.
    pub fn initialize(&mut self) -> Result<()> {
        // Create base directory
        fs::create_dir_all(&self.config.directory)
            .wrap_err_with(|| format!("failed to create directory: {:?}", self.config.directory))?;

        // Initialize each node
        for i in 0..self.nodes.len() {
            initialize_node(&mut self.nodes[i])?;
        }

        // Generate shared genesis
        let genesis = self.generate_genesis()?;
        let genesis_path = self.config.directory.join("genesis.json");
        let mut file = fs::File::create(&genesis_path)
            .wrap_err_with(|| format!("failed to create genesis file: {:?}", genesis_path))?;
        file.write_all(genesis.as_bytes())?;

        // Copy genesis to each node
        for node in &self.nodes {
            let node_genesis = node.genesis_path();
            fs::copy(&genesis_path, &node_genesis)
                .wrap_err_with(|| format!("failed to copy genesis to {:?}", node_genesis))?;
        }

        // Generate config.toml for each node with persistent_peers
        self.generate_configs()?;

        // Save network metadata
        let network_json = serde_json::to_string_pretty(&self)?;
        let network_path = self.config.directory.join("network.json");
        let mut file = fs::File::create(&network_path)
            .wrap_err_with(|| format!("failed to create network.json: {:?}", network_path))?;
        file.write_all(network_json.as_bytes())?;

        Ok(())
    }

    fn generate_genesis(&self) -> Result<String> {
        let validators: Vec<_> = self
            .nodes
            .iter()
            .filter(|n| n.role.is_validator())
            .collect();

        let mut validator_entries = Vec::new();
        for (i, node) in validators.iter().enumerate() {
            // Read the validator's public key from priv_validator_key.json
            let priv_val_key_path = node.priv_validator_key_path();
            let priv_val_key_content = fs::read_to_string(&priv_val_key_path)
                .wrap_err_with(|| format!("failed to read {:?}", priv_val_key_path))?;
            let priv_val_key: serde_json::Value = serde_json::from_str(&priv_val_key_content)?;

            let pub_key = &priv_val_key["pub_key"];

            validator_entries.push(serde_json::json!({
                "address": priv_val_key["address"],
                "pub_key": pub_key,
                "power": "10",
                "name": format!("validator-{}", i)
            }));
        }

        // Use current time for genesis to avoid blockstamp timeout issues
        let genesis_time = chrono::Utc::now()
            .format("%Y-%m-%dT%H:%M:%S%.9fZ")
            .to_string();

        let genesis = serde_json::json!({
            "genesis_time": genesis_time,
            "chain_id": self.config.chain_id,
            "initial_height": "1",
            "consensus_params": {
                "block": {
                    "max_bytes": "22020096",
                    "max_gas": "-1",
                    "time_iota_ms": "1000"
                },
                "evidence": {
                    "max_age_num_blocks": "100000",
                    "max_age_duration": "172800000000000",
                    "max_bytes": "1048576"
                },
                "validator": {
                    "pub_key_types": ["ed25519"]
                },
                "version": {}
            },
            "validators": validator_entries,
            "app_hash": ""
        });

        Ok(serde_json::to_string_pretty(&genesis)?)
    }

    fn generate_configs(&self) -> Result<()> {
        // Build persistent_peers string
        let persistent_peers: Vec<String> = self
            .nodes
            .iter()
            .filter_map(|n| n.persistent_peer_address())
            .collect();

        for node in &self.nodes {
            // Generate config.toml for this node
            // Filter out this node from persistent_peers
            let peers: Vec<_> = persistent_peers
                .iter()
                .filter(|p| {
                    if let Some(ref id) = node.node_id {
                        !p.starts_with(id)
                    } else {
                        true
                    }
                })
                .cloned()
                .collect();

            // Derive all consensus timeouts from timeout_commit so they scale
            // correctly for both fast test blocks (1s) and slow production blocks (50-60s).
            let timeouts = ConsensusTimeouts::from_timeout_commit(&self.config.timeout_commit);
            let config = generate_config_toml(node, &peers.join(","), &timeouts)?;
            let mut file = fs::File::create(node.config_toml_path())?;
            file.write_all(config.as_bytes())?;
        }

        Ok(())
    }

    /// Generate a felidae chain configuration from this network's generated keys.
    ///
    /// This method reads the PKCS#8-encoded admin and oracle keys from each validator,
    /// extracts the public keys, and builds a `Config` suitable for use in genesis or
    /// for submitting as a reconfiguration transaction.
    ///
    /// # Arguments
    ///
    /// * `oracle_voting_delay` - Delay before pending oracle observations become canonical
    /// * `admin_voting_delay` - Delay before pending admin config changes take effect
    ///
    /// # Voting Configuration
    ///
    /// The method automatically sets:
    /// - `total` = number of validators
    /// - `quorum` = 2*n/3 + 1 (BFT-safe threshold)
    /// - `timeout` = 5 minutes for oracles, 1 minute for admins
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use std::time::Duration;
    /// use felidae_deployer::{Network, NetworkConfig};
    ///
    /// let config = NetworkConfig {
    ///     num_validators: 3,
    ///     ..Default::default()
    /// };
    /// let mut network = Network::new(config);
    /// network.initialize().unwrap();
    ///
    /// let felidae_config = network.generate_felidae_config(
    ///     Duration::from_secs(1),  // oracle delay (short for testing)
    ///     Duration::from_secs(0),  // admin delay (immediate for testing)
    /// ).unwrap();
    /// ```
    pub fn generate_felidae_config(
        &self,
        oracle_voting_delay: Duration,
        admin_voting_delay: Duration,
    ) -> Result<Config> {
        // Extract oracle public keys from each validator's PKCS#8 keypair file
        let mut oracle_configs = Vec::new();
        for node in self.nodes.iter().filter(|n| n.role.is_validator()) {
            let key_hex = fs::read_to_string(node.oracle_key_path()).wrap_err_with(|| {
                format!("failed to read oracle key: {:?}", node.oracle_key_path())
            })?;
            let key_bytes =
                hex::decode(key_hex.trim()).wrap_err("failed to decode oracle key hex")?;
            let keypair =
                KeyPair::decode(&key_bytes).wrap_err("failed to decode oracle key PKCS#8")?;
            let public_key = keypair.public_key();

            oracle_configs.push(Oracle {
                identity: Bytes::from(public_key),
                endpoint: format!("{}:{}", node.bind_address, node.ports.felidae_oracle),
            });
        }

        // Extract admin public keys from each validator's PKCS#8 keypair file
        let mut admin_configs = Vec::new();
        for node in self.nodes.iter().filter(|n| n.role.is_validator()) {
            let key_hex = fs::read_to_string(node.admin_key_path()).wrap_err_with(|| {
                format!("failed to read admin key: {:?}", node.admin_key_path())
            })?;
            let key_bytes =
                hex::decode(key_hex.trim()).wrap_err("failed to decode admin key hex")?;
            let keypair =
                KeyPair::decode(&key_bytes).wrap_err("failed to decode admin key PKCS#8")?;
            let public_key = keypair.public_key();

            admin_configs.push(Admin {
                identity: Bytes::from(public_key),
            });
        }

        let num_validators = self.nodes.iter().filter(|n| n.role.is_validator()).count();

        // Build the chain configuration with BFT-safe quorum thresholds
        // For n validators, quorum = 2*n/3 + 1
        Ok(Config {
            version: 0,
            admins: AdminConfig {
                voting: VotingConfig {
                    total: Total(num_validators as u64),
                    quorum: Quorum(((num_validators * 2) / 3 + 1) as u64),
                    timeout: Timeout(Duration::from_secs(60)),
                    delay: Delay(admin_voting_delay),
                },
                authorized: admin_configs,
            },
            oracles: OracleConfig {
                enabled: true,
                voting: VotingConfig {
                    total: Total(num_validators as u64),
                    quorum: Quorum(((num_validators * 2) / 3 + 1) as u64),
                    timeout: Timeout(Duration::from_secs(300)),
                    delay: Delay(oracle_voting_delay),
                },
                max_enrolled_subdomains: 5,
                observation_timeout: Duration::from_secs(300),
                authorized: oracle_configs,
            },
            onion: OnionConfig { enabled: false },
        })
    }

    /// Inject a felidae configuration into the genesis files of all nodes.
    ///
    /// This modifies each node's genesis.json to include an `app_state` section
    /// containing the provided chain configuration. All nodes must have identical
    /// genesis files for consensus to work.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use std::time::Duration;
    /// use felidae_deployer::{Network, NetworkConfig};
    ///
    /// let config = NetworkConfig {
    ///     num_validators: 3,
    ///     ..Default::default()
    /// };
    /// let mut network = Network::new(config);
    /// network.initialize().unwrap();
    ///
    /// let felidae_config = network.generate_felidae_config(
    ///     Duration::from_secs(1),
    ///     Duration::from_secs(0),
    /// ).unwrap();
    /// network.inject_genesis_app_state(&felidae_config).unwrap();
    /// ```
    pub fn inject_genesis_app_state(&self, config: &Config) -> Result<()> {
        for node in &self.nodes {
            let genesis_path = node.genesis_path();
            let genesis_content = fs::read_to_string(&genesis_path)
                .wrap_err_with(|| format!("failed to read genesis: {:?}", genesis_path))?;
            let mut genesis: serde_json::Value =
                serde_json::from_str(&genesis_content).wrap_err("failed to parse genesis JSON")?;

            genesis["app_state"] = serde_json::json!({
                "config": serde_json::to_value(config)?
            });

            let updated_genesis = serde_json::to_string_pretty(&genesis)?;
            fs::write(&genesis_path, updated_genesis)
                .wrap_err_with(|| format!("failed to write genesis: {:?}", genesis_path))?;
        }
        Ok(())
    }

    /// Generate process-compose.yaml content for this network.
    ///
    /// The config uses simple `process_started` dependencies to ensure processes
    /// start in the right order without complex health checks that might cause
    /// premature exits.
    ///
    /// # Arguments
    /// * `felidae_command` - The command to run felidae (e.g., "felidae" or "cargo run --bin felidae --release --")
    /// * `felidae_working_dir` - Optional working directory for felidae processes (needed for cargo run in dev mode)
    pub fn generate_process_compose_config(
        &self,
        felidae_command: &str,
        felidae_working_dir: Option<&std::path::Path>,
    ) -> String {
        let mut processes = Vec::new();

        // Format the working_dir line if provided
        let working_dir_line = felidae_working_dir
            .map(|p| format!("\n    working_dir: {}", p.display()))
            .unwrap_or_default();

        for node in &self.nodes {
            // CometBFT process
            let cometbft_name = format!("{}-cometbft", node.name);
            let cometbft_home = node.cometbft_home();
            processes.push(format!(
                r#"  {name}:
    command: cometbft start --home {home}
    availability:
      restart: on_failure
      max_restarts: 3"#,
                name = cometbft_name,
                home = cometbft_home.display(),
            ));

            // Felidae process (depends on CometBFT starting)
            let felidae_name = format!("{}-felidae", node.name);
            let felidae_home = node.felidae_home();
            let query_bind = format!("{}:{}", node.bind_address, node.ports.felidae_query);
            processes.push(format!(
                r#"  {name}:
    command: {felidae_cmd} start --abci-bind {abci_bind} --query-bind {query_bind} --homedir {home}{working_dir}
    depends_on:
      {cometbft_dep}:
        condition: process_started
    availability:
      restart: on_failure
      max_restarts: 3"#,
                name = felidae_name,
                felidae_cmd = felidae_command,
                abci_bind = node.abci_address(),
                query_bind = query_bind,
                home = felidae_home.display(),
                cometbft_dep = cometbft_name,
                working_dir = working_dir_line,
            ));

            // Oracle server for validators
            if node.role.is_validator() {
                let oracle_name = format!("{}-oracle", node.name);
                let oracle_bind = format!("{}:{}", node.bind_address, node.ports.felidae_oracle);
                processes.push(format!(
                    r#"  {name}:
    command: {felidae_cmd} oracle server --bind {bind} --node http://{rpc_host}:{rpc_port} --homedir {home}{working_dir}
    depends_on:
      {felidae_dep}:
        condition: process_started
    availability:
      restart: on_failure
      max_restarts: 3"#,
                    name = oracle_name,
                    felidae_cmd = felidae_command,
                    bind = oracle_bind,
                    rpc_host = node.bind_address,
                    rpc_port = node.ports.cometbft_rpc,
                    home = felidae_home.display(),
                    felidae_dep = felidae_name,
                    working_dir = working_dir_line,
                ));
            }
        }

        format!(
            r#"version: "0.5"

# Process-compose configuration for felidae network
# Generated by felidae-deployer

log_level: info

processes:
{processes}
"#,
            processes = processes.join("\n\n")
        )
    }
}

/// Check that all specified ports are available on localhost.
///
/// This performs a preflight check by attempting to bind to each port and immediately
/// releasing it. While this has a TOCTOU (time-of-check-time-of-use) race condition,
/// it provides early feedback about port conflicts before starting all processes.
///
/// # Arguments
/// * `ports` - List of (port, description) tuples to check
///
/// # Returns
/// * `Ok(())` if all ports are available
/// * `Err` with details about unavailable ports
pub fn check_ports_available(ports: &[(u16, String)]) -> Result<()> {
    let mut unavailable = Vec::new();

    for (port, description) in ports {
        // Attempt to bind to the port on localhost
        // Note: This has a TOCTOU race - the port could be taken between this check
        // and when we actually start the process. However, catching most conflicts
        // early is better than failing after starting some processes.
        match TcpListener::bind(("127.0.0.1", *port)) {
            Ok(_listener) => {
                // Port is available, listener is dropped automatically releasing the port
            }
            Err(e) => {
                unavailable.push(format!("  {} (port {}): {}", description, port, e));
            }
        }
    }

    if !unavailable.is_empty() {
        return Err(color_eyre::eyre::eyre!(
            "The following ports are not available:\n{}\n\n\
             hint: Check for other running processes using these ports with:\n\
                   lsof -i :<port> or ss -tlnp | grep <port>",
            unavailable.join("\n")
        ));
    }

    Ok(())
}

/// Initialize a single node by creating directories and generating keys.
fn initialize_node(node: &mut WebcatNode) -> Result<()> {
    // Create directories
    fs::create_dir_all(node.cometbft_config_dir())?;
    fs::create_dir_all(node.cometbft_data_dir())?;
    fs::create_dir_all(node.felidae_home())?;

    // Generate node key and get node ID
    let (node_key_json, node_id) = generate_node_key()?;
    node.node_id = Some(node_id);

    let mut file = fs::File::create(node.node_key_path())?;
    file.write_all(node_key_json.as_bytes())?;

    // For validators, generate priv_validator_key
    if node.role.is_validator() {
        let priv_validator_key = generate_priv_validator_key()?;
        let mut file = fs::File::create(node.priv_validator_key_path())?;
        file.write_all(priv_validator_key.as_bytes())?;

        // Initialize priv_validator_state
        let priv_validator_state = r#"{
  "height": "0",
  "round": 0,
  "step": 0
}"#;
        let mut file = fs::File::create(node.priv_validator_state_path())?;
        file.write_all(priv_validator_state.as_bytes())?;

        // Generate felidae keys
        generate_felidae_keys(node)?;
    }

    Ok(())
}

/// Generate a CometBFT node_key.json and return (json_content, node_id).
fn generate_node_key() -> Result<(String, String)> {
    let secret_bytes: [u8; 32] = rand::random();
    let signing_key = SigningKey::from_bytes(&secret_bytes);
    let verifying_key = signing_key.verifying_key();

    // Node ID is the first 20 bytes of SHA256(pubkey), hex-encoded
    let mut hasher = Sha256::new();
    hasher.update(verifying_key.as_bytes());
    let hash = hasher.finalize();
    let node_id = hex::encode(&hash[..20]);

    // CometBFT uses a specific JSON format with amino encoding
    let priv_key_bytes = signing_key.to_bytes();
    let pub_key_bytes = verifying_key.to_bytes();

    // Combine private and public key bytes (ed25519 convention)
    let mut full_key = Vec::with_capacity(64);
    full_key.extend_from_slice(&priv_key_bytes);
    full_key.extend_from_slice(&pub_key_bytes);

    let node_key = serde_json::json!({
        "priv_key": {
            "type": "tendermint/PrivKeyEd25519",
            "value": base64_encode(&full_key)
        }
    });

    Ok((serde_json::to_string_pretty(&node_key)?, node_id))
}

/// Generate a CometBFT priv_validator_key.json.
fn generate_priv_validator_key() -> Result<String> {
    let secret_bytes: [u8; 32] = rand::random();
    let signing_key = SigningKey::from_bytes(&secret_bytes);
    let verifying_key = signing_key.verifying_key();

    // Address is the first 20 bytes of SHA256(pubkey), hex-encoded uppercase
    let mut hasher = Sha256::new();
    hasher.update(verifying_key.as_bytes());
    let hash = hasher.finalize();
    let address = hex::encode_upper(&hash[..20]);

    let priv_key_bytes = signing_key.to_bytes();
    let pub_key_bytes = verifying_key.to_bytes();

    let mut full_key = Vec::with_capacity(64);
    full_key.extend_from_slice(&priv_key_bytes);
    full_key.extend_from_slice(&pub_key_bytes);

    let priv_validator_key = serde_json::json!({
        "address": address,
        "pub_key": {
            "type": "tendermint/PubKeyEd25519",
            "value": base64_encode(&pub_key_bytes)
        },
        "priv_key": {
            "type": "tendermint/PrivKeyEd25519",
            "value": base64_encode(&full_key)
        }
    });

    Ok(serde_json::to_string_pretty(&priv_validator_key)?)
}

/// Generate felidae admin and oracle keys as PKCS#8-encoded ECDSA-P256 keys.
fn generate_felidae_keys(node: &WebcatNode) -> Result<()> {
    // Generate proper ECDSA-P256 keys in PKCS#8 format (same as felidae admin/oracle init)
    let admin_secret = SecretKey::random(&mut OsRng);
    let admin_pkcs8 = admin_secret
        .to_pkcs8_der()
        .wrap_err("failed to encode admin key to PKCS#8")?;

    let oracle_secret = SecretKey::random(&mut OsRng);
    let oracle_pkcs8 = oracle_secret
        .to_pkcs8_der()
        .wrap_err("failed to encode oracle key to PKCS#8")?;

    let mut file = fs::File::create(node.admin_key_path())?;
    file.write_all(hex::encode(admin_pkcs8.as_bytes()).as_bytes())?;

    let mut file = fs::File::create(node.oracle_key_path())?;
    file.write_all(hex::encode(oracle_pkcs8.as_bytes()).as_bytes())?;

    Ok(())
}

/// Derived CometBFT consensus timeouts, scaled from `timeout_commit`.
///
/// CometBFT's default timeouts assume ~1s block times. When `timeout_commit` is
/// increased significantly (e.g. 50-60s), the other consensus timeouts must scale
/// proportionally. The formulas here reproduce the CometBFT defaults at 1s and
/// scale smoothly for longer block times.
struct ConsensusTimeouts {
    /// How long to wait for a proposal before prevoting nil.
    /// Formula: max(3s, block_time * 60%). At 1s→3s, 50s→30s.
    timeout_propose: String,
    /// How much timeout_propose grows per failed round.
    /// Formula: max(500ms, block_time * 10%). At 1s→500ms, 50s→5s.
    timeout_propose_delta: String,
    /// How long to wait after +2/3 conflicting prevotes before voting nil.
    /// Formula: max(1s, block_time * 10%). At 1s→1s, 50s→5s.
    timeout_prevote: String,
    /// How much timeout_prevote grows per failed round.
    /// Formula: max(500ms, block_time * 4%). At 1s→500ms, 50s→2s.
    timeout_prevote_delta: String,
    /// How long to wait after +2/3 conflicting precommits before precommitting nil.
    /// Same formula as timeout_prevote.
    timeout_precommit: String,
    /// How much timeout_precommit grows per failed round.
    /// Same formula as timeout_prevote_delta.
    timeout_precommit_delta: String,
    /// The block interval itself.
    timeout_commit: String,
    /// RPC timeout for /broadcast_tx_commit.
    /// Formula: clamp(block_time * 10, 30s, 180s).
    timeout_broadcast_tx_commit: String,
}

impl ConsensusTimeouts {
    fn from_timeout_commit(timeout_commit: &str) -> Self {
        let block_secs: u64 = timeout_commit.trim_end_matches('s').parse().unwrap_or(1);
        let block_ms = block_secs * 1000;

        Self {
            timeout_propose: fmt_ms((block_ms * 3 / 5).max(3000)),
            timeout_propose_delta: fmt_ms((block_ms / 10).max(500)),
            timeout_prevote: fmt_ms((block_ms / 10).max(1000)),
            timeout_prevote_delta: fmt_ms((block_ms / 25).max(500)),
            timeout_precommit: fmt_ms((block_ms / 10).max(1000)),
            timeout_precommit_delta: fmt_ms((block_ms / 25).max(500)),
            timeout_commit: timeout_commit.to_string(),
            timeout_broadcast_tx_commit: format!("{}s", (block_secs * 10).clamp(30, 180)),
        }
    }
}

/// Format a millisecond duration as "Xs" if whole seconds, otherwise "Xms".
fn fmt_ms(ms: u64) -> String {
    if ms >= 1000 && ms % 1000 == 0 {
        format!("{}s", ms / 1000)
    } else {
        format!("{}ms", ms)
    }
}

/// Generate config.toml for a node.
fn generate_config_toml(
    node: &WebcatNode,
    persistent_peers: &str,
    timeouts: &ConsensusTimeouts,
) -> Result<String> {
    let config = format!(
        r#"# This is a TOML config file.
# For more information, see https://github.com/toml-lang/toml

proxy_app = "tcp://{abci_address}"
moniker = "{moniker}"
fast_sync = true
db_backend = "goleveldb"
db_dir = "data"
log_level = "info"
log_format = "plain"
genesis_file = "config/genesis.json"
priv_validator_key_file = "config/priv_validator_key.json"
priv_validator_state_file = "data/priv_validator_state.json"
priv_validator_laddr = ""
node_key_file = "config/node_key.json"
abci = "socket"
filter_peers = false

[rpc]
laddr = "{rpc_address}"
cors_allowed_origins = []
cors_allowed_methods = ["HEAD", "GET", "POST"]
cors_allowed_headers = ["Origin", "Accept", "Content-Type", "X-Requested-With", "X-Server-Time"]
grpc_laddr = ""
grpc_max_open_connections = 900
unsafe = false
max_open_connections = 900
max_subscription_clients = 100
max_subscriptions_per_client = 5
experimental_subscription_buffer_size = 200
experimental_websocket_write_buffer_size = 200
experimental_close_on_slow_client = false
timeout_broadcast_tx_commit = "{timeout_broadcast_tx_commit}"
max_body_bytes = 1000000
max_header_bytes = 1048576
tls_cert_file = ""
tls_key_file = ""
pprof_laddr = ""

[p2p]
laddr = "{p2p_address}"
external_address = ""
seeds = ""
persistent_peers = "{persistent_peers}"
upnp = false
addr_book_file = "config/addrbook.json"
addr_book_strict = false
max_num_inbound_peers = 40
max_num_outbound_peers = 10
unconditional_peer_ids = ""
persistent_peers_max_dial_period = "0s"
flush_throttle_timeout = "100ms"
max_packet_msg_payload_size = 1024
send_rate = 5120000
recv_rate = 5120000
pex = true
seed_mode = false
private_peer_ids = ""
allow_duplicate_ip = true
handshake_timeout = "20s"
dial_timeout = "3s"

[mempool]
version = "v0"
recheck = true
broadcast = true
wal_dir = ""
size = 5000
max_txs_bytes = 1073741824
cache_size = 10000
keep-invalid-txs-in-cache = false
max_tx_bytes = 1048576
max_batch_bytes = 0

[statesync]
enable = false
rpc_servers = ""
trust_height = 0
trust_hash = ""
trust_period = "168h0m0s"
discovery_time = "15s"
temp_dir = ""
chunk_request_timeout = "10s"
chunk_fetchers = "4"

[consensus]
wal_file = "data/cs.wal/wal"
timeout_propose = "{timeout_propose}"
timeout_propose_delta = "{timeout_propose_delta}"
timeout_prevote = "{timeout_prevote}"
timeout_prevote_delta = "{timeout_prevote_delta}"
timeout_precommit = "{timeout_precommit}"
timeout_precommit_delta = "{timeout_precommit_delta}"
timeout_commit = "{timeout_commit}"
double_sign_check_height = 0
skip_timeout_commit = false
create_empty_blocks = true
create_empty_blocks_interval = "0s"
peer_gossip_sleep_duration = "100ms"
peer_query_maj23_sleep_duration = "2s"

[storage]
discard_abci_responses = false

[tx_index]
indexer = "kv"
psql-conn = ""

[instrumentation]
prometheus = false
prometheus_listen_addr = ":26660"
max_open_connections = 3
namespace = "cometbft"
"#,
        abci_address = node.abci_address(),
        moniker = node.name,
        rpc_address = node.rpc_listen_address(),
        p2p_address = node.p2p_listen_address(),
        persistent_peers = persistent_peers,
        timeout_propose = timeouts.timeout_propose,
        timeout_propose_delta = timeouts.timeout_propose_delta,
        timeout_prevote = timeouts.timeout_prevote,
        timeout_prevote_delta = timeouts.timeout_prevote_delta,
        timeout_precommit = timeouts.timeout_precommit,
        timeout_precommit_delta = timeouts.timeout_precommit_delta,
        timeout_commit = timeouts.timeout_commit,
        timeout_broadcast_tx_commit = timeouts.timeout_broadcast_tx_commit,
    );

    Ok(config)
}

fn base64_encode(data: &[u8]) -> String {
    use std::io::Write;
    let mut buf = Vec::new();
    {
        let mut encoder =
            base64::write::EncoderWriter::new(&mut buf, &base64::engine::general_purpose::STANDARD);
        encoder.write_all(data).unwrap();
    }
    String::from_utf8(buf).unwrap()
}
