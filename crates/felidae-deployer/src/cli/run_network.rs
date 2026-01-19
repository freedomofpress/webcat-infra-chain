//! Run network command implementation.

use std::collections::HashMap;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use clap::Parser;
use color_eyre::eyre::{Context, Result};
use tracing::{error, info, warn};

use super::Run;
use felidae_deployer::Network;

/// Run a felidae network from a directory.
#[derive(Parser)]
pub struct RunNetwork {
    /// Directory containing the network configuration (network.json).
    /// If not specified, a temporary directory will be created automatically.
    #[arg(long)]
    pub directory: Option<PathBuf>,

    /// Use process-compose to manage processes (uses pre-generated process-compose.yaml).
    #[arg(long, default_value = "false")]
    pub process_compose: bool,

    /// Path to the felidae binary.
    #[arg(long, default_value = "felidae")]
    pub felidae_bin: String,

    /// Path to the cometbft binary.
    #[arg(long, default_value = "cometbft")]
    pub cometbft_bin: String,

    /// Development mode: build felidae from the current workspace using cargo.
    /// This overrides --felidae-bin.
    #[arg(long)]
    pub dev: bool,
}

/// Build felidae from the workspace using escargot and return the path to the binary.
fn build_felidae_from_workspace() -> Result<PathBuf> {
    info!("Building felidae from workspace (this may take a moment)...");

    let cargo_build = escargot::CargoBuild::new()
        .bin("felidae")
        .current_release()
        .current_target()
        .run()
        .wrap_err("failed to build felidae from workspace")?;

    let bin_path = cargo_build.path().to_path_buf();
    info!("Built felidae at: {}", bin_path.display());

    Ok(bin_path)
}

impl Run for RunNetwork {
    async fn run(mut self) -> Result<()> {
        // In dev mode (without process-compose), build felidae from the workspace
        if self.dev && !self.process_compose {
            let felidae_path = build_felidae_from_workspace()?;
            self.felidae_bin = felidae_path.to_string_lossy().into_owned();
        }

        // Determine the directory to use - either provided or create a temporary one
        let (directory, _temp_dir_guard) = match self.directory {
            Some(ref dir) => (dir.clone(), None),
            None => {
                warn!("No --directory specified, creating temporary network configuration");
                warn!("This network will be deleted when the process exits");

                // Create a temporary directory
                let temp_dir =
                    tempfile::tempdir().wrap_err("failed to create temporary directory")?;
                let temp_path = temp_dir.path().to_path_buf();

                info!(
                    "Creating default network in temporary directory: {:?}",
                    temp_path
                );

                // Create default network configuration
                let config = felidae_deployer::NetworkConfig {
                    directory: temp_path.clone(),
                    ..Default::default()
                };

                let mut network = Network::new(config);
                network
                    .initialize()
                    .wrap_err("failed to initialize temporary network")?;

                info!(
                    "Temporary network initialized with {} nodes",
                    network.nodes.len()
                );

                (temp_path, Some(temp_dir))
            }
        };

        // Load network configuration
        let network_path = directory.join("network.json");
        let network_json = std::fs::read_to_string(&network_path)
            .wrap_err_with(|| format!("failed to read network.json from {:?}", network_path))?;
        let network: Network =
            serde_json::from_str(&network_json).wrap_err("failed to parse network.json")?;

        info!(
            "Loaded network with {} nodes from {:?}",
            network.nodes.len(),
            directory
        );

        if self.process_compose {
            // In dev mode with process-compose, regenerate config to use cargo run
            if self.dev {
                info!("Dev mode: regenerating process-compose.yaml to build felidae ad-hoc...");
                // Match the release mode of the current felidae-deployer binary
                let felidae_command = if cfg!(not(debug_assertions)) {
                    "cargo run --bin felidae --release --"
                } else {
                    "cargo run --bin felidae --"
                };
                let workspace_root = std::env::current_dir()
                    .wrap_err("failed to get current directory for workspace root")?;
                let config_content =
                    network.generate_process_compose_config(felidae_command, Some(&workspace_root));
                let config_path = directory.join("process-compose.yaml");
                std::fs::write(&config_path, &config_content)
                    .wrap_err_with(|| format!("failed to write {:?}", config_path))?;
            } else {
                // Use pre-generated process-compose.yaml from create-network
                let config_path = directory.join("process-compose.yaml");
                if !config_path.exists() {
                    return Err(color_eyre::eyre::eyre!(
                        "process-compose.yaml not found at {:?}\n\
                         hint: run 'felidae-deployer create-network' first to generate the config",
                        config_path
                    ));
                }
            }

            info!("Starting network with process-compose...");
            let status = Command::new("process-compose")
                .args(["up", "--use-uds"])
                .current_dir(&directory)
                .status()
                .wrap_err("failed to run process-compose")?;

            if !status.success() {
                return Err(color_eyre::eyre::eyre!(
                    "process-compose exited with status: {}",
                    status
                ));
            }
        } else {
            // Run processes directly with prefixed output
            run_processes_directly(&network, &self).await?;
        }

        Ok(())
    }
}

/// Check if a binary exists (either in PATH or as a path).
fn check_binary_exists(bin: &str) -> bool {
    // Check if it's an absolute or relative path that exists
    if std::path::Path::new(bin).exists() {
        return true;
    }
    // Check if it's in PATH using `which`
    Command::new("which")
        .arg(bin)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Run all processes directly with prefixed log output.
async fn run_processes_directly(network: &Network, args: &RunNetwork) -> Result<()> {
    // Validate binaries exist before starting anything
    let mut missing = Vec::new();
    if !check_binary_exists(&args.cometbft_bin) {
        missing.push(format!(
            "cometbft: '{}' (use --cometbft-bin to specify path)",
            args.cometbft_bin
        ));
    }
    if !check_binary_exists(&args.felidae_bin) {
        missing.push(format!(
            "felidae: '{}' (use --felidae-bin to specify path)",
            args.felidae_bin
        ));
    }
    if !missing.is_empty() {
        return Err(color_eyre::eyre::eyre!(
            "Required binaries not found:\n  {}\n\n\
             hint: Build the project first with 'cargo build --release' and 'just build-cometbft',\n\
                   then specify paths like:\n\
                   --felidae-bin ./target/release/felidae --cometbft-bin ./cometbft/build/cometbft",
            missing.join("\n  ")
        ));
    }

    // Preflight check: verify all ports are available before starting any processes
    let num_ports = network.collect_required_ports().len();
    info!("Checking availability of {} ports...", num_ports);
    network.check_ports_available()?;
    info!("All ports are available");

    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_clone = shutdown.clone();

    // Set up Ctrl+C handler
    ctrlc::set_handler(move || {
        warn!("Received Ctrl+C, shutting down...");
        shutdown_clone.store(true, Ordering::SeqCst);
    })
    .wrap_err("failed to set Ctrl+C handler")?;

    let mut children: HashMap<String, Child> = HashMap::new();
    let mut handles = Vec::new();

    // Start all processes
    for node in &network.nodes {
        // Start CometBFT
        let cometbft_name = format!("{}-cometbft", node.name);
        let child = start_process_with_prefix(
            &cometbft_name,
            &args.cometbft_bin,
            &["start", "--home", &node.cometbft_home().to_string_lossy()],
            shutdown.clone(),
        )?;
        if let Some((c, h)) = child {
            children.insert(cometbft_name, c);
            handles.push(h);
        }

        // Start Felidae
        let felidae_name = format!("{}-felidae", node.name);
        let child = start_process_with_prefix(
            &felidae_name,
            &args.felidae_bin,
            &[
                "start",
                "--abci-bind",
                &node.abci_address(),
                "--query-bind",
                &format!("{}:{}", node.bind_address, node.ports.felidae_query),
                "--homedir",
                &node.felidae_home().to_string_lossy(),
            ],
            shutdown.clone(),
        )?;
        if let Some((c, h)) = child {
            children.insert(felidae_name, c);
            handles.push(h);
        }

        // Start Oracle server for validators
        if node.role.is_validator() {
            let oracle_name = format!("{}-oracle", node.name);
            let child = start_process_with_prefix(
                &oracle_name,
                &args.felidae_bin,
                &[
                    "oracle",
                    "server",
                    "--bind",
                    &format!("{}:{}", node.bind_address, node.ports.felidae_oracle),
                    "--node",
                    &format!("http://{}:{}", node.bind_address, node.ports.cometbft_rpc),
                    "--homedir",
                    &node.felidae_home().to_string_lossy(),
                ],
                shutdown.clone(),
            )?;
            if let Some((c, h)) = child {
                children.insert(oracle_name, c);
                handles.push(h);
            }
        }
    }

    info!("Started {} processes", children.len());
    print_node_info(network);

    // Wait for shutdown signal
    while !shutdown.load(Ordering::SeqCst) {
        // Check if any process has exited
        let mut exited = Vec::new();
        for (name, child) in children.iter_mut() {
            match child.try_wait() {
                Ok(Some(status)) => {
                    if status.success() {
                        info!("{} exited successfully", name);
                    } else {
                        error!("{} exited with status: {}", name, status);
                    }
                    exited.push(name.clone());
                }
                Ok(None) => {} // Still running
                Err(e) => {
                    error!("Error checking {} status: {}", name, e);
                }
            }
        }

        // If any critical process exited, shut down everything
        if !exited.is_empty() {
            warn!("Processes exited: {:?}, initiating shutdown", exited);
            shutdown.store(true, Ordering::SeqCst);
        }

        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
    }

    // Kill all remaining processes
    info!("Terminating all processes...");
    for (name, mut child) in children {
        if let Err(e) = child.kill() {
            // Process may have already exited
            if e.kind() != std::io::ErrorKind::InvalidInput {
                warn!("Failed to kill {}: {}", name, e);
            }
        }
        let _ = child.wait();
    }

    // Wait for output threads to finish
    for handle in handles {
        let _ = handle.join();
    }

    info!("All processes terminated");
    Ok(())
}

/// Start a process and spawn a thread to prefix its output.
fn start_process_with_prefix(
    name: &str,
    bin: &str,
    args: &[&str],
    shutdown: Arc<AtomicBool>,
) -> Result<Option<(Child, std::thread::JoinHandle<()>)>> {
    info!("Starting {}: {} {}", name, bin, args.join(" "));

    let mut child = Command::new(bin)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .wrap_err_with(|| {
            format!(
                "failed to start {} (binary '{}' not found in PATH or at specified path)\n\
                 hint: specify the binary path with --felidae-bin or --cometbft-bin,\n\
                       or ensure the binary is built and in your PATH",
                name, bin
            )
        })?;

    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let name_owned = name.to_string();

    let handle = std::thread::spawn(move || {
        let mut handles = Vec::new();

        if let Some(stdout) = stdout {
            let name = name_owned.clone();
            let shutdown = shutdown.clone();
            handles.push(std::thread::spawn(move || {
                let reader = BufReader::new(stdout);
                for line in reader.lines() {
                    if shutdown.load(Ordering::SeqCst) {
                        break;
                    }
                    if let Ok(line) = line {
                        println!("[{}] {}", name, line);
                    }
                }
            }));
        }

        if let Some(stderr) = stderr {
            let name = name_owned;
            handles.push(std::thread::spawn(move || {
                let reader = BufReader::new(stderr);
                for line in reader.lines() {
                    if shutdown.load(Ordering::SeqCst) {
                        break;
                    }
                    if let Ok(line) = line {
                        eprintln!("[{}] {}", name, line);
                    }
                }
            }));
        }

        for handle in handles {
            let _ = handle.join();
        }
    });

    Ok(Some((child, handle)))
}

/// Print information about all nodes in the network.
fn print_node_info(network: &Network) {
    println!("\n=== Network Nodes ===");
    for node in &network.nodes {
        println!(
            "{} ({})",
            node.name,
            match node.role {
                felidae_deployer::NodeRole::Validator => "validator",
                felidae_deployer::NodeRole::Sentry => "sentry",
                felidae_deployer::NodeRole::FullNode => "full node",
            }
        );
        println!(
            "  CometBFT P2P:  {}:{}",
            node.bind_address, node.ports.cometbft_p2p
        );
        println!(
            "  CometBFT RPC:  {}:{}",
            node.bind_address, node.ports.cometbft_rpc
        );
        println!("  Felidae ABCI:  {}", node.abci_address());
        println!(
            "  Felidae Query: {}:{}",
            node.bind_address, node.ports.felidae_query
        );
        if node.role.is_validator() {
            println!(
                "  Oracle:        {}:{}",
                node.bind_address, node.ports.felidae_oracle
            );
        }
    }
    println!("=====================\n");
}
