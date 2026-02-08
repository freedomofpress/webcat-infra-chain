//! Test constants, timing functions, and enrollment data generation.
//!
//! This module contains constants used across integration tests, including
//! test domain names, zone configurations, enrollment JSON generation,
//! and block-time-relative duration functions for timing-sensitive operations.

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
pub const TEST_DOMAINS: &[(&str, &str)] = &[("webcat.tech.", "tech."), ("example.com.", "com.")];

/// Convenience accessors for common test domains
pub const TEST_DOMAIN_WEBCAT: (&str, &str) = ("webcat.tech.", "tech.");
pub const TEST_DOMAIN_EXAMPLE: (&str, &str) = ("example.com.", "com.");

/// Domain used for unenrollment testing (subdomain of webcat.tech.)
pub const TEST_DOMAIN_UNENROLL: (&str, &str) = ("goss.webcat.tech.", "tech.");

/// Subdomain prefixes for subdomain-related tests
pub const TEST_SUBDOMAIN_PREFIX_1: &str = "goss";
pub const TEST_SUBDOMAIN_PREFIX_2: &str = "subby";

/// The chain ID used in all integration tests.
pub const TEST_CHAIN_ID: &str = "felidae-integration-test";

// ---------------------------------------------------------------------------
// Block-time-relative timing functions
// ---------------------------------------------------------------------------
//
// Every duration in the integration tests derives from a single base unit:
// `block_time()`, which reads `FELIDAE_BLOCK_TIME_SECS` (default: 1).
//
// This keeps CI fast (1s blocks ≈ 2 min) while allowing ad-hoc production-
// like runs with `FELIDAE_BLOCK_TIME_SECS=60`.

use std::time::Duration;

/// Base block interval. Reads `FELIDAE_BLOCK_TIME_SECS` (default `1`).
pub fn block_time() -> Duration {
    let secs: u64 = std::env::var("FELIDAE_BLOCK_TIME_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1);
    Duration::from_secs(secs)
}

/// CometBFT `timeout_commit` value as a string (e.g. `"1s"`).
pub fn timeout_commit_str() -> String {
    format!("{}s", block_time().as_secs())
}

/// Timeout for the network to spawn processes and produce first blocks.
/// Fixed 30s base + 3 block times.
pub fn network_startup_timeout() -> Duration {
    Duration::from_secs(30) + block_time() * 3
}

/// Pause between sequential transaction submissions.
/// `max(300ms, block_time / 3)` — avoids flooding the mempool while
/// remaining responsive at short block intervals.
pub fn inter_tx_delay() -> Duration {
    let third = block_time() / 3;
    std::cmp::max(Duration::from_millis(300), third)
}

/// Standard wait for vote → quorum → promotion (5 blocks).
pub fn consensus_propagation_wait() -> Duration {
    block_time() * 5
}

/// Conservative wait for quorum + promotion (10 blocks).
pub fn consensus_propagation_wait_long() -> Duration {
    block_time() * 10
}

/// Interval between state-check polls. `max(2s, block_time)`.
pub fn poll_interval() -> Duration {
    std::cmp::max(Duration::from_secs(2), block_time())
}

/// Admin transaction validity window. `max(60s, 10 blocks)`.
pub fn admin_reconfig_tx_timeout() -> Duration {
    std::cmp::max(Duration::from_secs(60), block_time() * 10)
}

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
pub fn test_enrollment_json() -> String {
    // Generate a deterministic Ed25519 keypair for reproducible test enrollments.
    // Using a fixed seed ensures all tests produce the same enrollment hash.
    use ed25519_dalek::SigningKey;
    let signing_key = SigningKey::from_bytes(&[1u8; 32]);
    let verifying_key = signing_key.verifying_key();
    // Base64-url encode the public key (32 bytes) per WEBCAT spec
    let test_pubkey = base64_url::encode(verifying_key.as_bytes());

    serde_json::json!({
        "type": "sigsum",
        "signers": [test_pubkey],
        "threshold": 1,
        "policy": "AAAA", // Minimal base64-url policy
        "max_age": 86400,
        "cas_url": "https://example.com/cas",
        "logs": {}
    })
    .to_string()
}
