//! Test constants and enrollment data generation.
//!
//! This module contains constants used across integration tests, including
//! test domain names, zone configurations, and enrollment JSON generation.

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
        "signers": [test_pubkey],
        "threshold": 1,
        "policy": "AAAA", // Minimal base64-url policy
        "max_age": 86400,
        "cas_url": "https://example.com/cas"
    })
    .to_string()
}
