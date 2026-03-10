//! Logic for bootstrapping a new node onto an existing felidae network.
//!
//! Requires a genesis file and peer info in order to bootstrap a connection.
//! The peer info may be discovered from a remote CometBFT URL, if available.
//! It's crucial that the genesis file be byte-for-byte identical to the genesis
//! JSON as provided at genesis time.
use std::fs;
use std::io::Write;
use std::net::{SocketAddr, TcpListener};
use std::path::PathBuf;

use color_eyre::eyre::{Result, WrapErr};
use rand::seq::SliceRandom;

use crate::network::generate_config_toml;
use crate::node::{NodeRole, WebcatNode};
use crate::ports::NodePorts;

/// Peer information discovered from the network.
#[derive(Debug, Clone)]
pub struct PeerInfo {
    /// CometBFT node ID (hex-encoded).
    pub node_id: String,
    /// The peer's P2P listen address (host:port, no protocol prefix).
    pub listen_addr: String,
    /// The peer's moniker.
    pub moniker: String,
}

impl PeerInfo {
    /// Format as a CometBFT persistent_peer string: `node_id@host:port`.
    pub fn to_persistent_peer(&self) -> String {
        format!("{}@{}", self.node_id, self.listen_addr)
    }
}

/// How the genesis file should be obtained.
pub enum GenesisSource {
    /// Use a local genesis.json on disk.
    File(PathBuf),
    /// Fetch genesis from a URL, preserving the response body byte-for-byte.
    Url(url::Url),
}

/// How peers should be discovered.
pub enum PeerSource {
    /// Auto-discover peers from a CometBFT JSON-RPC endpoint.
    CometbftRpc(url::Url),
    /// Explicit persistent peers (in `node_id@host:port` format).
    Explicit(Vec<String>),
}

/// Configuration for joining a network.
pub struct JoinConfig {
    /// How to obtain the genesis file.
    pub genesis_source: GenesisSource,
    /// How to discover peers.
    pub peer_source: PeerSource,
    /// Output directory for the new node's configuration.
    pub directory: PathBuf,
    /// If true, scan for free ports instead of using defaults.
    pub find_free_ports: bool,
    /// Node name/moniker.
    pub node_name: String,
}

/// Bootstrap a new node by fetching genesis and discovering peers, then writing
/// local config files.
///
/// Genesis content is preserved byte-for-byte from the source to avoid AppHash
/// mismatches caused by JSON reserialization changing key order or formatting.
/// See GH131 for more info.
pub async fn join_network(config: JoinConfig) -> Result<WebcatNode> {
    // Resolve genesis — always preserved byte-for-byte.
    let genesis_raw = match &config.genesis_source {
        GenesisSource::File(path) => {
            let raw = fs::read_to_string(path)
                .wrap_err_with(|| format!("failed to read genesis file: {}", path.display()))?;
            let _: serde_json::Value =
                serde_json::from_str(&raw).wrap_err("failed to parse genesis JSON")?;
            raw
        }
        GenesisSource::Url(url) => fetch_genesis_url(url).await?,
    };

    // Resolve peers.
    let persistent_peers = match &config.peer_source {
        PeerSource::CometbftRpc(url) => {
            let peers = discover_peers(url).await?;
            peers
        }
        PeerSource::Explicit(peers) => peers.join(","),
    };
    tracing::info!(%persistent_peers, "peers for config");

    // Allocate ports for the new node.
    let ports = if config.find_free_ports {
        find_free_ports()?
    } else {
        NodePorts {
            cometbft_p2p: 26656,
            cometbft_rpc: 26657,
            felidae_abci: 26658,
            felidae_query: 8080,
            felidae_oracle: 8081,
        }
    };

    // Create the node structure.
    let mut node = WebcatNode::new(
        config.node_name,
        NodeRole::FullNode,
        ports,
        config.directory.clone(),
    );

    // Create directory structure.
    fs::create_dir_all(node.cometbft_config_dir())
        .wrap_err("failed to create cometbft config dir")?;
    fs::create_dir_all(node.cometbft_data_dir()).wrap_err("failed to create cometbft data dir")?;
    fs::create_dir_all(node.felidae_home()).wrap_err("failed to create felidae home dir")?;

    // Generate a node key for this new node.
    let (node_key_json, node_id) = crate::network::generate_node_key()?;
    node.node_id = Some(node_id.clone());
    tracing::info!(%node_id, "generated node key");

    let mut file = fs::File::create(node.node_key_path())?;
    file.write_all(node_key_json.as_bytes())?;

    // Write genesis exactly as received to preserve byte-for-byte integrity.
    // Reserialization would change key ordering or whitespace, causing AppHash mismatches.
    // See GH131 for more info.
    fs::write(node.genesis_path(), &genesis_raw).wrap_err("failed to write genesis.json")?;

    // Generate a priv_validator_key up front. A joined node boots as a full
    // node (its pubkey is not in the genesis validator set), but having a
    // consensus key pre-provisioned means the node can later be promoted to
    // validator status via an admin reconfiguration without any manual key
    // wrangling — the pubkey is discoverable at `priv_validator_key_path()`.
    // Without this, CometBFT would auto-generate the key at first start,
    // forcing callers to either race the daemon or restart the node.
    let (priv_validator_key_json, _pub_key) = crate::network::generate_priv_validator_key()?;
    fs::write(node.priv_validator_key_path(), priv_validator_key_json)
        .wrap_err("failed to write priv_validator_key.json")?;

    // Initialize priv_validator_state (empty, since this is a full node).
    let priv_validator_state = r#"{
  "height": "0",
  "round": 0,
  "step": 0
}"#;
    fs::write(node.priv_validator_state_path(), priv_validator_state)
        .wrap_err("failed to write priv_validator_state.json")?;

    // Generate config.toml with discovered peers.
    let config_toml = generate_config_toml(&node, &persistent_peers, "1s")?;
    fs::write(node.config_toml_path(), config_toml).wrap_err("failed to write config.toml")?;

    tracing::info!(
        cometbft_home = %node.cometbft_home().display(),
        p2p_port = node.ports.cometbft_p2p,
        rpc_port = node.ports.cometbft_rpc,
        abci_port = node.ports.felidae_abci,
        "node config written"
    );

    Ok(node)
}

/// Discover peers from a CometBFT RPC endpoint.
async fn discover_peers(url: &url::Url) -> Result<String> {
    let client = reqwest::Client::new();

    let mut peers: Vec<PeerInfo> = Vec::new();
    match fetch_node_info(&client, url).await {
        Ok(info) => {
            tracing::info!(
                node_id = %info.node_id,
                listen_addr = %info.listen_addr,
                "bootstrap node info"
            );
            peers.push(info);
        }
        Err(e) => {
            tracing::warn!("failed to fetch bootstrap node info: {}", e);
        }
    }

    match fetch_peers(&client, url).await {
        Ok(extra_peers) => {
            tracing::info!(count = extra_peers.len(), "discovered additional peers");
            peers.extend(extra_peers);
        }
        Err(e) => {
            tracing::warn!("failed to fetch peers from bootstrap node: {}", e);
        }
    }

    if peers.is_empty() {
        tracing::warn!("no peers discovered; the new node may have trouble syncing");
    }

    let persistent_peers = peers
        .iter()
        .map(|p| p.to_persistent_peer())
        .collect::<Vec<_>>()
        .join(",");

    Ok(persistent_peers)
}

/// Fetch a raw genesis JSON file from a URL (not a CometBFT RPC endpoint).
///
/// Returns the raw response body as-is to preserve byte-for-byte integrity.
/// See GH131 for details on the genesis JSON structure.
async fn fetch_genesis_url(url: &url::Url) -> Result<String> {
    tracing::info!(%url, "fetching genesis from URL");
    let client = reqwest::Client::new();
    let genesis_raw = client
        .get(url.as_str())
        .send()
        .await
        .wrap_err("failed to request genesis")?
        .error_for_status()
        .wrap_err("genesis request returned error status")?
        .text()
        .await
        .wrap_err("failed to read genesis response body")?;
    // Validate that the response is valid JSON.
    let _: serde_json::Value =
        serde_json::from_str(&genesis_raw).wrap_err("genesis from URL is not valid JSON")?;
    tracing::info!("fetched genesis from URL");
    Ok(genesis_raw)
}

/// Fetch the bootstrap node's own identity and P2P listen address.
async fn fetch_node_info(client: &reqwest::Client, base_url: &url::Url) -> Result<PeerInfo> {
    let status_url = base_url
        .join("status")
        .wrap_err("failed to build status URL")?;
    let status: serde_json::Value = client
        .get(status_url)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;

    let node_info = status
        .get("result")
        .and_then(|v| v.get("node_info"))
        .ok_or_else(|| color_eyre::eyre::eyre!("missing result.node_info in status response"))?;

    let node_id = node_info
        .get("id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| color_eyre::eyre::eyre!("missing node_info.id"))?
        .to_string();

    let listen_addr = node_info
        .get("listen_addr")
        .and_then(|v| v.as_str())
        .ok_or_else(|| color_eyre::eyre::eyre!("missing node_info.listen_addr"))?
        .replace("tcp://", "");

    let moniker = node_info
        .get("moniker")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();

    // The listen_addr from /status is often 0.0.0.0:port — for localhost networks,
    // we need to replace the bind-all address with the actual host from the RPC URL.
    let listen_addr = rewrite_unspecified_host(&listen_addr, base_url.host_str());

    Ok(PeerInfo {
        node_id,
        listen_addr,
        moniker,
    })
}

/// Fetch peers from the bootstrap node's /net_info endpoint.
async fn fetch_peers(client: &reqwest::Client, base_url: &url::Url) -> Result<Vec<PeerInfo>> {
    let net_info_url = base_url
        .join("net_info")
        .wrap_err("failed to build net_info URL")?;
    tracing::debug!(%net_info_url, "fetching net_info");
    let resp: serde_json::Value = client
        .get(net_info_url)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;

    let raw_peers = resp
        .get("result")
        .and_then(|v| v.get("peers"))
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    if raw_peers.is_empty() {
        tracing::debug!("bootstrap node reports 0 peers");
        return Ok(Vec::new());
    }

    let mut peers: Vec<PeerInfo> = Vec::new();
    let threshold = 5;

    // Shuffle so different joining nodes get different peer subsets.
    let mut raw_peers = raw_peers;
    raw_peers.shuffle(&mut rand::rng());

    for raw_peer in &raw_peers {
        if peers.len() >= threshold {
            break;
        }

        let node_id = raw_peer
            .get("node_info")
            .and_then(|v| v.get("id"))
            .and_then(|v| v.as_str());
        let listen_addr = raw_peer
            .get("node_info")
            .and_then(|v| v.get("listen_addr"))
            .and_then(|v| v.as_str());
        let moniker = raw_peer
            .get("node_info")
            .and_then(|v| v.get("moniker"))
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        if let (Some(id), Some(addr)) = (node_id, listen_addr) {
            let addr = addr.replace("tcp://", "");
            let addr = rewrite_unspecified_host(&addr, base_url.host_str());

            // Skip obviously-internal addresses (unless it's a localhost dev network).
            if !address_is_usable(&addr) {
                tracing::debug!(%addr, "skipping peer with unusable address");
                continue;
            }

            peers.push(PeerInfo {
                node_id: id.to_string(),
                listen_addr: addr,
                moniker: moniker.to_string(),
            });
        }
    }

    Ok(peers)
}

/// If the address uses an unspecified bind (0.0.0.0), replace the host portion
/// with the host from the RPC URL we're connecting to. This is common for
/// localhost dev networks where nodes bind to 0.0.0.0 but are reachable at 127.0.0.1.
fn rewrite_unspecified_host(addr: &str, host: Option<&str>) -> String {
    if let Ok(sa) = addr.parse::<SocketAddr>() {
        if sa.ip().is_unspecified() {
            if let Some(host) = host {
                return format!("{}:{}", host, sa.port());
            }
        }
    }
    addr.to_string()
}

/// Check whether an address is usable as a peer address.
/// Accepts loopback (for localhost dev networks) but rejects unspecified (0.0.0.0).
fn address_is_usable(addr: &str) -> bool {
    match addr.parse::<SocketAddr>() {
        Ok(sa) => !sa.ip().is_unspecified(),
        // If it's not a valid SocketAddr, it might be a hostname — allow it.
        Err(_) => !addr.is_empty(),
    }
}

/// Find free ports for all node services by binding to port 0.
fn find_free_ports() -> Result<NodePorts> {
    Ok(NodePorts {
        cometbft_p2p: pick_free_port()?,
        cometbft_rpc: pick_free_port()?,
        felidae_abci: pick_free_port()?,
        felidae_query: pick_free_port()?,
        felidae_oracle: pick_free_port()?,
    })
}

/// Bind to port 0 on localhost and return the OS-assigned port.
fn pick_free_port() -> Result<u16> {
    let listener = TcpListener::bind("127.0.0.1:0").wrap_err("failed to bind to ephemeral port")?;
    let port = listener.local_addr()?.port();
    Ok(port)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rewrite_unspecified_host() {
        assert_eq!(
            rewrite_unspecified_host("0.0.0.0:26656", Some("127.0.0.1")),
            "127.0.0.1:26656"
        );
        assert_eq!(
            rewrite_unspecified_host("10.0.0.5:26656", Some("127.0.0.1")),
            "10.0.0.5:26656"
        );
    }

    #[test]
    fn test_address_is_usable() {
        assert!(address_is_usable("127.0.0.1:26656"));
        assert!(address_is_usable("10.0.0.1:26656"));
        assert!(!address_is_usable("0.0.0.0:26656"));
        assert!(!address_is_usable(""));
    }

    #[test]
    fn test_peer_info_to_persistent_peer() {
        let info = PeerInfo {
            node_id: "abc123".into(),
            listen_addr: "10.0.0.1:26656".into(),
            moniker: "test".into(),
        };
        assert_eq!(info.to_persistent_peer(), "abc123@10.0.0.1:26656");
    }

    /// Genesis JSON with intentional non-canonical formatting: specific whitespace,
    /// key ordering, and number representations that `serde_json::to_string_pretty`
    /// would change. If the join logic roundtrips through `Value`, this content
    /// will NOT survive byte-for-byte.
    const QUIRKY_GENESIS: &str = r#"{"genesis_time":"2024-01-01T00:00:00.000000000Z","chain_id":"test-chain","initial_height":"1","consensus_params":{"block":{"max_bytes":"22020096","max_gas":"-1"},"evidence":{"max_age_num_blocks":"100000","max_age_duration":"172800000000000","max_bytes":"1048576"},"validator":{"pub_key_types":["ed25519"]},"version":{"app":"0"},"abci":{"vote_extensions_enable_height":"0"}},"validators":[{"address":"AABBCCDD","pub_key":{"type":"tendermint/PubKeyEd25519","value":"base64key=="},"power":"10","name":"node0"}],"app_hash":"","app_state":{"admin_keys":["key1"]}}"#;

    #[tokio::test]
    async fn test_file_genesis_preserves_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let genesis_path = dir.path().join("genesis.json");
        fs::write(&genesis_path, QUIRKY_GENESIS).unwrap();

        let out_dir = dir.path().join("node");
        let config = JoinConfig {
            genesis_source: GenesisSource::File(genesis_path),
            peer_source: PeerSource::Explicit(vec!["abc@127.0.0.1:26656".into()]),
            directory: out_dir.clone(),
            find_free_ports: true,
            node_name: "test-node".into(),
        };

        let node = join_network(config).await.unwrap();
        let written = fs::read_to_string(node.genesis_path()).unwrap();
        assert_eq!(
            written, QUIRKY_GENESIS,
            "genesis must be preserved byte-for-byte; reserialization would change formatting"
        );
    }

    #[tokio::test]
    async fn test_url_genesis_preserves_bytes() {
        use tokio::sync::oneshot;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let (tx, rx) = oneshot::channel::<()>();

        // Spawn a tiny HTTP server that serves the quirky genesis.
        let server_handle = tokio::spawn(async move {
            let app = axum::Router::new().route(
                "/genesis.json",
                axum::routing::get(|| async { QUIRKY_GENESIS }),
            );
            axum::serve(listener, app)
                .with_graceful_shutdown(async {
                    rx.await.ok();
                })
                .await
                .unwrap();
        });

        let genesis_url =
            url::Url::parse(&format!("http://127.0.0.1:{}/genesis.json", port)).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let out_dir = dir.path().join("node");

        let config = JoinConfig {
            genesis_source: GenesisSource::Url(genesis_url),
            peer_source: PeerSource::Explicit(vec!["abc@127.0.0.1:26656".into()]),
            directory: out_dir.clone(),
            find_free_ports: true,
            node_name: "test-node".into(),
        };

        let node = join_network(config).await.unwrap();
        let written = fs::read_to_string(node.genesis_path()).unwrap();
        assert_eq!(
            written, QUIRKY_GENESIS,
            "genesis fetched from URL must be preserved byte-for-byte"
        );

        tx.send(()).ok();
        server_handle.abort();
    }

    #[tokio::test]
    async fn test_rpc_peer_discovery() {
        use tokio::sync::oneshot;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let (tx, rx) = oneshot::channel::<()>();

        let server_handle = tokio::spawn(async move {
            let app = axum::Router::new()
                .route(
                    "/status",
                    axum::routing::get(|| async {
                        r#"{"result":{"node_info":{"id":"deadbeef01234567","listen_addr":"tcp://127.0.0.1:26656","moniker":"boot"}}}"#
                    }),
                )
                .route(
                    "/net_info",
                    axum::routing::get(|| async {
                        r#"{"result":{"peers":[]}}"#
                    }),
                );
            axum::serve(listener, app)
                .with_graceful_shutdown(async {
                    rx.await.ok();
                })
                .await
                .unwrap();
        });

        let cometbft_url = url::Url::parse(&format!("http://127.0.0.1:{}", port)).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let genesis_path = dir.path().join("genesis.json");
        fs::write(&genesis_path, QUIRKY_GENESIS).unwrap();
        let out_dir = dir.path().join("node");

        let config = JoinConfig {
            genesis_source: GenesisSource::File(genesis_path),
            peer_source: PeerSource::CometbftRpc(cometbft_url),
            directory: out_dir.clone(),
            find_free_ports: true,
            node_name: "test-node".into(),
        };

        let node = join_network(config).await.unwrap();

        // Genesis should still be preserved byte-for-byte.
        let written = fs::read_to_string(node.genesis_path()).unwrap();
        assert_eq!(written, QUIRKY_GENESIS);

        // Config should contain the discovered peer.
        let config_toml = fs::read_to_string(node.config_toml_path()).unwrap();
        assert!(
            config_toml.contains("deadbeef01234567"),
            "config.toml should contain the discovered peer ID"
        );

        tx.send(()).ok();
        server_handle.abort();
    }

    #[test]
    fn test_find_free_ports() {
        let ports = find_free_ports().unwrap();
        // All ports should be non-zero and distinct.
        let all = [
            ports.cometbft_p2p,
            ports.cometbft_rpc,
            ports.felidae_abci,
            ports.felidae_query,
            ports.felidae_oracle,
        ];
        for p in &all {
            assert!(*p > 0);
        }
        // Check uniqueness (very likely given OS assignment, but let's verify).
        let mut unique = all.to_vec();
        unique.sort();
        unique.dedup();
        assert_eq!(unique.len(), all.len(), "all ports should be unique");
    }
}
