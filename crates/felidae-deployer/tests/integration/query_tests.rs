//! Query route integration tests.
//!
//! This module tests the felidae query HTTP API routes directly via reqwest,
//! verifying status codes and response structure.

use crate::binaries::find_binaries;
use crate::constants::network_startup_timeout;
use crate::harness::TestNetwork;

/// Verifies that GET `/` returns 200 OK with a JSON listing of available endpoints.
///
/// # Route Under Test
///
/// The root route was added to provide API discoverability. It returns a JSON
/// object with an `endpoints` array, where each entry has `path` and `description`
/// fields documenting the available query API surface.
#[tokio::test]
#[cfg(feature = "integration")]
async fn test_root_route_returns_ok_with_endpoints() -> color_eyre::Result<()> {
    let (cometbft_bin, felidae_bin) = find_binaries()?;

    let mut network = TestNetwork::create(3).await?;
    network.start(
        cometbft_bin.to_str().unwrap(),
        felidae_bin.to_str().unwrap(),
    )?;
    network.wait_ready(network_startup_timeout()).await?;

    let client = reqwest::Client::new();
    let url = format!("{}/", network.query_url());

    let response = client.get(&url).send().await?;

    // Verify 200 OK
    assert_eq!(
        response.status(),
        reqwest::StatusCode::OK,
        "GET / should return 200 OK"
    );

    // Verify Content-Type is JSON
    let content_type = response
        .headers()
        .get("content-type")
        .expect("response should have Content-Type header")
        .to_str()?;
    assert_eq!(
        content_type, "application/json",
        "Content-Type should be application/json"
    );

    // Parse the body as JSON
    let body: serde_json::Value = response.json().await?;

    // Verify top-level structure has an "endpoints" array
    let endpoints = body
        .get("endpoints")
        .expect("response should have 'endpoints' field")
        .as_array()
        .expect("'endpoints' should be an array");

    assert!(!endpoints.is_empty(), "endpoints array should not be empty");

    // Verify each endpoint has the expected fields
    for endpoint in endpoints {
        assert!(
            endpoint.get("path").is_some(),
            "each endpoint should have a 'path' field"
        );
        assert!(
            endpoint.get("description").is_some(),
            "each endpoint should have a 'description' field"
        );
        assert!(endpoint["path"].is_string(), "'path' should be a string");
        assert!(
            endpoint["description"].is_string(),
            "'description' should be a string"
        );
    }

    // Verify well-known routes are present
    let paths: Vec<&str> = endpoints
        .iter()
        .filter_map(|e| e["path"].as_str())
        .collect();

    let expected_paths = ["/config", "/oracles", "/snapshot", "/enrollment/votes"];
    for expected in &expected_paths {
        assert!(
            paths.contains(expected),
            "expected endpoint '{}' in root route listing, got: {:?}",
            expected,
            paths
        );
    }

    eprintln!(
        "[test] GET / returned {} endpoints: {:?}",
        endpoints.len(),
        paths
    );

    Ok(())
}

/// Verifies that GET `/config` returns 200 OK with parseable chain configuration JSON.
///
/// This complements the CLI-based config query in other tests by exercising
/// the HTTP route directly.
#[tokio::test]
#[cfg(feature = "integration")]
async fn test_config_route_returns_ok_json() -> color_eyre::Result<()> {
    let (cometbft_bin, felidae_bin) = find_binaries()?;

    let mut network = TestNetwork::create(3).await?;
    network.start(
        cometbft_bin.to_str().unwrap(),
        felidae_bin.to_str().unwrap(),
    )?;
    network.wait_ready(network_startup_timeout()).await?;

    let client = reqwest::Client::new();
    let url = format!("{}/config", network.query_url());

    let response = client.get(&url).send().await?;

    assert_eq!(
        response.status(),
        reqwest::StatusCode::OK,
        "GET /config should return 200 OK"
    );

    let body: serde_json::Value = response.json().await?;

    // Config should have a version field
    assert!(
        body.get("version").is_some(),
        "config response should have a 'version' field"
    );

    eprintln!("[test] GET /config returned version: {}", body["version"]);

    Ok(())
}
