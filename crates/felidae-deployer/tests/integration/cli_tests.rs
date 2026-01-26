//! CLI workflow integration tests.
//!
//! This module contains tests for the felidae CLI commands, particularly
//! the admin template workflow used in production setups.

use std::process::Command;

use felidae_deployer::{Network, NetworkConfig};
use felidae_types::KeyPair;

use crate::binaries::find_binaries;

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
