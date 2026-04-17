//! Validator query integration tests.
//!
//! These tests exercise the `/validators` and `/validators/{id}` HTTP routes
//! together with the corresponding `felidae query validators [id] --json`
//! CLI subcommand, asserting that validator status and identifying fields
//! are reported correctly against a live 3-validator network.

use std::collections::BTreeSet;
use std::process::Command;

use felidae_state::BASE_VALIDATOR_POWER;
use felidae_types::response::ValidatorInfo;
use sha2::{Digest, Sha256};
use tendermint_rpc::HttpClient;

use crate::binaries::find_binaries;
use crate::constants::network_startup_timeout;
use crate::harness::TestNetwork;
use crate::helpers::{query_cometbft_validators, run_query_command};

/// Computes a CometBFT-style 20-byte address (hex) from a 32-byte ed25519
/// public key, matching the derivation used by `validator_info` server-side.
fn cometbft_address_hex(pub_key_bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(pub_key_bytes);
    let digest = hasher.finalize();
    hex::encode(&digest[0..20])
}

/// Runs `felidae query validators [id] --json` and parses the JSON array.
fn query_validators_cli(
    felidae_bin: &std::path::Path,
    query_url: &str,
    id: Option<&str>,
) -> color_eyre::Result<Vec<ValidatorInfo>> {
    let extra_args: Vec<&str> = match id {
        Some(id) => vec![id, "--json"],
        None => vec!["--json"],
    };
    let output = run_query_command(felidae_bin, "validators", query_url, &extra_args)?;
    let validators: Vec<ValidatorInfo> = serde_json::from_str(&output)?;
    Ok(validators)
}

/// Verifies that `felidae query validators --json` returns one entry per
/// genesis validator, all reported as `"active"` with the bootstrap power.
///
/// This is the happy-path test: a freshly started 3-validator network should
/// report three active validators, with identities and CometBFT addresses
/// matching what the CometBFT RPC reports.
#[tokio::test]
#[cfg(feature = "integration")]
async fn test_validators_query_lists_active_validators() -> color_eyre::Result<()> {
    let (cometbft_bin, felidae_bin) = find_binaries()?;

    let mut network = TestNetwork::create(3).await?;
    network.start(
        cometbft_bin.to_str().unwrap(),
        felidae_bin.to_str().unwrap(),
    )?;
    network.wait_ready(network_startup_timeout()).await?;

    let validators = query_validators_cli(&felidae_bin, &network.query_url(), None)?;

    assert_eq!(
        validators.len(),
        3,
        "expected 3 validators in a 3-validator network, got {}: {:?}",
        validators.len(),
        validators
    );

    // Cross-reference identities & addresses against what CometBFT reports.
    let rpc_client = HttpClient::new(network.rpc_url().as_str())?;
    let cometbft_vals = query_cometbft_validators(&rpc_client).await?;

    let cometbft_identities: BTreeSet<String> = cometbft_vals
        .iter()
        .map(|(pk, _)| hex::encode(pk))
        .collect();
    let reported_identities: BTreeSet<String> =
        validators.iter().map(|v| v.identity.clone()).collect();
    assert_eq!(
        reported_identities, cometbft_identities,
        "identities reported by /validators should match CometBFT's validator set"
    );

    for v in &validators {
        assert_eq!(
            v.status, "active",
            "validator {} should be active in a healthy network, got {:?}",
            v.identity, v.status
        );
        assert_eq!(
            v.power,
            u64::from(BASE_VALIDATOR_POWER),
            "validator {} should carry BASE_VALIDATOR_POWER",
            v.identity
        );
        let pub_key_bytes = hex::decode(&v.identity)?;
        let expected_address = cometbft_address_hex(&pub_key_bytes);
        assert_eq!(
            v.address, expected_address,
            "address field for {} should be the SHA-256[0..20] of the pubkey",
            v.identity
        );
        // Uptime accounting fields should be populated and self-consistent.
        assert!(
            v.uptime_window > 0,
            "uptime_window should be > 0 for validator {}",
            v.identity
        );
        assert!(
            v.missed_blocks <= v.uptime_window,
            "missed_blocks ({}) should never exceed uptime_window ({}) for {}",
            v.missed_blocks,
            v.uptime_window,
            v.identity,
        );
        assert!(
            v.missed_blocks_max > 0,
            "missed_blocks_max threshold should be > 0",
        );
        assert!(
            v.unjail_missed_max < v.missed_blocks_max,
            "unjail threshold ({}) should be strictly below jail threshold ({})",
            v.unjail_missed_max,
            v.missed_blocks_max,
        );
    }

    eprintln!(
        "[test] /validators reported {} active validators with matching identities",
        validators.len()
    );
    Ok(())
}

/// Verifies that `felidae query validators <prefix> --json` returns exactly
/// the matching validator. Exercises both full-id and prefix lookups, plus
/// the leading `0x` strip behaviour implemented in the route handler.
#[tokio::test]
#[cfg(feature = "integration")]
async fn test_validators_query_prefix_lookup() -> color_eyre::Result<()> {
    let (cometbft_bin, felidae_bin) = find_binaries()?;

    let mut network = TestNetwork::create(3).await?;
    network.start(
        cometbft_bin.to_str().unwrap(),
        felidae_bin.to_str().unwrap(),
    )?;
    network.wait_ready(network_startup_timeout()).await?;

    let all = query_validators_cli(&felidae_bin, &network.query_url(), None)?;
    assert_eq!(all.len(), 3, "expected 3 validators in test network");
    let target = &all[0];

    // Full identity lookup.
    let by_full = query_validators_cli(&felidae_bin, &network.query_url(), Some(&target.identity))?;
    assert_eq!(
        by_full.len(),
        1,
        "full-identity lookup should match exactly one validator"
    );
    assert_eq!(by_full[0].identity, target.identity);
    assert_eq!(by_full[0].status, "active");

    // Prefix lookup using the first 8 hex chars of the identity. The chance
    // of a collision among 3 random ed25519 keys at 32 bits is negligible.
    let prefix: String = target.identity.chars().take(8).collect();
    let by_prefix = query_validators_cli(&felidae_bin, &network.query_url(), Some(&prefix))?;
    assert_eq!(
        by_prefix.len(),
        1,
        "8-char identity prefix should resolve to exactly one validator"
    );
    assert_eq!(by_prefix[0].identity, target.identity);

    // `0x` prefix should be stripped before matching.
    let with_0x = format!("0x{}", prefix);
    let by_0x = query_validators_cli(&felidae_bin, &network.query_url(), Some(&with_0x))?;
    assert_eq!(
        by_0x.len(),
        1,
        "lookup with `0x` prefix should still match the validator"
    );
    assert_eq!(by_0x[0].identity, target.identity);

    // Address lookup should also work — the route accepts either pubkey or
    // address prefix.
    let by_address =
        query_validators_cli(&felidae_bin, &network.query_url(), Some(&target.address))?;
    assert_eq!(
        by_address.len(),
        1,
        "lookup by full address should resolve to exactly one validator"
    );
    assert_eq!(by_address[0].identity, target.identity);

    Ok(())
}

/// Verifies that a lookup for a validator that does not exist surfaces an
/// error from the CLI (the underlying route returns 404 with a plain-text
/// body, which `error_for_status()` in the CLI promotes to a failure).
#[tokio::test]
#[cfg(feature = "integration")]
async fn test_validators_query_unknown_id_errors() -> color_eyre::Result<()> {
    let (cometbft_bin, felidae_bin) = find_binaries()?;

    let mut network = TestNetwork::create(3).await?;
    network.start(
        cometbft_bin.to_str().unwrap(),
        felidae_bin.to_str().unwrap(),
    )?;
    network.wait_ready(network_startup_timeout()).await?;

    // Run the CLI directly so we can inspect both exit code and the HTTP
    // status code surfaced to stderr.
    let output = Command::new(&felidae_bin)
        .args([
            "query",
            "--query-url",
            &network.query_url(),
            "validators",
            // No real validator identity will start with this many leading f's.
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "--json",
        ])
        .output()?;

    assert!(
        !output.status.success(),
        "CLI lookup of a non-existent validator id should fail; got success with stdout={}",
        String::from_utf8_lossy(&output.stdout)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("404"),
        "expected 404 status in stderr, got: {stderr}"
    );

    // Confirm the route also responds 404 on the wire (independent of the
    // CLI's behaviour).
    let url = format!(
        "{}/validators/ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        network.query_url()
    );
    let response = reqwest::Client::new().get(&url).send().await?;
    assert_eq!(
        response.status(),
        reqwest::StatusCode::NOT_FOUND,
        "GET /validators/<unknown> should return 404"
    );

    Ok(())
}

/// Verifies the raw HTTP route at `/validators` returns a JSON array whose
/// entries cover the full schema of `ValidatorInfo`. This complements the
/// CLI tests above by exercising the route directly (so a regression that
/// only changed the CLI wouldn't mask the route returning malformed JSON).
#[tokio::test]
#[cfg(feature = "integration")]
async fn test_validators_route_returns_well_formed_json() -> color_eyre::Result<()> {
    let (cometbft_bin, felidae_bin) = find_binaries()?;

    let mut network = TestNetwork::create(3).await?;
    network.start(
        cometbft_bin.to_str().unwrap(),
        felidae_bin.to_str().unwrap(),
    )?;
    network.wait_ready(network_startup_timeout()).await?;

    let url = format!("{}/validators", network.query_url());
    let response = reqwest::Client::new().get(&url).send().await?;

    assert_eq!(
        response.status(),
        reqwest::StatusCode::OK,
        "GET /validators should return 200 OK"
    );
    let content_type = response
        .headers()
        .get("content-type")
        .expect("response should have Content-Type header")
        .to_str()?
        .to_string();
    assert!(
        content_type.starts_with("application/json"),
        "Content-Type should be application/json, got {content_type}"
    );

    // Parse twice: once as `Value` for shape checks, once as the typed
    // `Vec<ValidatorInfo>` to confirm the schema matches what the CLI uses.
    let body = response.text().await?;
    let raw: serde_json::Value = serde_json::from_str(&body)?;
    let arr = raw.as_array().expect("response should be a JSON array");
    assert_eq!(
        arr.len(),
        3,
        "expected 3 validators in array, got {}",
        arr.len()
    );
    for entry in arr {
        for key in [
            "identity",
            "address",
            "power",
            "status",
            "missed_blocks",
            "uptime_window",
            "missed_blocks_max",
            "unjail_missed_max",
        ] {
            assert!(
                entry.get(key).is_some(),
                "validator entry missing required field `{key}`: {entry}"
            );
        }
    }

    let typed: Vec<ValidatorInfo> = serde_json::from_str(&body)?;
    assert_eq!(typed.len(), 3);
    for v in &typed {
        assert_eq!(
            v.status, "active",
            "validator {} should be active, got {:?}",
            v.identity, v.status
        );
    }

    Ok(())
}
