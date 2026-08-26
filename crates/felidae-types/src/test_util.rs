//! Deterministic key material for tests.
//!
//! Enabled by the `test-util` cargo feature (and always within this crate's
//! own tests). Nothing here is fit for production use: every key is derived
//! from a public, fixed input.

use sha2::{Digest, Sha256};

use crate::transaction::{Identity, ValidatorKey};

/// A P-256 identity from a small fixed scalar.
///
/// The scalar is `256 + n`, so no `n` yields scalar 1 — whose public key is the
/// generator point, i.e. [`Identity::placeholder`]. The derivation is pinned
/// by snapshot tests; do not change it.
pub fn test_identity(n: u8) -> Identity {
    let mut scalar = [0u8; 32];
    scalar[30] = 1;
    scalar[31] = n;
    let signing_key =
        p256::ecdsa::SigningKey::from_slice(&scalar).expect("low scalar is a valid key");
    Identity::from(*signing_key.verifying_key())
}

/// A P-256 identity derived from a name, for tests that want readable parties.
///
/// Distinct names give distinct identities (up to SHA-256 collision), and the
/// same name always gives the same identity.
pub fn identity_named(name: &str) -> Identity {
    // A SHA-256 digest is a valid P-256 scalar unless it is zero or exceeds the
    // group order; both are vanishingly unlikely, but re-hash rather than panic.
    let mut digest = Sha256::digest(name.as_bytes());
    loop {
        if let Ok(signing_key) = p256::ecdsa::SigningKey::from_slice(&digest) {
            return Identity::from(*signing_key.verifying_key());
        }
        digest = Sha256::digest(digest);
    }
}

/// An ed25519 validator key with every byte set to `n`.
pub fn test_validator_key(n: u8) -> ValidatorKey {
    ValidatorKey::from_bytes(&[n; 32]).expect("32 bytes is a valid key length")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn named_identities_are_deterministic_and_distinct() {
        assert_eq!(identity_named("alice"), identity_named("alice"));
        assert_ne!(identity_named("alice"), identity_named("bob"));
        assert_ne!(identity_named("alice"), Identity::placeholder());
    }

    #[test]
    fn numbered_identity_never_hits_placeholder() {
        for n in [0u8, 1, 2, 255] {
            assert_ne!(test_identity(n), Identity::placeholder());
        }
    }
}
