//! This tiny crate is a utility for creating signed witness transactions in Felidae.
//!
//! It exposes a single function, `witness`, which takes the necessary parameters
//! and returns a signed transaction as a hex-encoded string, ready to submit to a node.
//!
//! It can be compiled to WebAssembly for use in web browsers or other WASM environments, as well as
//! used in native Rust code. Due to the cross-compilation requirements, it has a slightly more
//! stringly-typed interface than otherwise one might prefer.

use serde::{Deserialize, Serialize};

use sha2::Digest;
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

pub use felidae_types::{
    AppHash, FQDN, Height, SignError, Signer,
    transaction::{ChainId, HashObserved},
};
use felidae_types::{
    KeyPair,
    transaction::{self, AuthenticatedTx},
};

/// Errors that may occur when creating a witness transaction.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    /// Signing the transaction failed.
    #[error(transparent)]
    Sign(#[from] SignError),
    /// Authenticating the signed transaction failed.
    #[error(transparent)]
    Auth(#[from] felidae_types::ParseError),
    /// The domain or zone name was invalid.
    #[error(transparent)]
    Fqdn(#[from] fqdn::Error),
    /// The hash observed was not valid hex, or invalid length.
    #[error("invalid app hash: {0}")]
    Hex(#[from] hex::FromHexError),
    /// The block height was invalid.
    #[error("block height {0} is out of range")]
    BlockHeightOutOfRange(u64),
    /// The signing key was not valid hex, or not a valid key.
    #[error("invalid signing key")]
    InvalidSigningKey,
    /// Invalid enrollment JSON.
    #[error("invalid enrollment JSON: {0}")]
    Enrollment(#[from] serde_json::Error),
    /// Bad canonicalization of enrollment JSON.
    #[error("failed to canonicalize enrollment JSON: {0}")]
    Canonicalization(#[from] canonical_json::CanonicalJSONError),
    /// Invalid enrollment data
    #[error("invalid enrollment: {0}")]
    InvalidEnrollment(String),
}

#[cfg(target_arch = "wasm32")]
type WitnessError = JsError;
#[cfg(not(target_arch = "wasm32"))]
type WitnessError = Error;

/// Enrollment policy structure as defined in the spec:
/// https://github.com/freedomofpress/webcat-spec/blob/main/server.md
#[derive(Serialize, Deserialize)]
struct Enrollment {
    /// An array of Ed25519 public keys, base64-encoded. TODO: Validation?
    signers: Vec<String>,
    /// The minimum number of distinct valid signatures required to accept a manifest as valid.
    threshold: u32,
    /// A base64-encoded string representing the compiled Sigsum policy. TODO: More validation?
    policy: String,
    /// The maximum number of seconds a manifest may remain valid after its signing timestamp.
    max_age: u64,
    /// The base URL of the Content Addressable Storage (CAS).
    cas_url: String,
}

/// Create a hex-encoded, signed transaction witnessing the given observation on the given chain,
/// using the given oracle signing key.
///
/// The oracle signing key must be the hex encoding of a valid ECDSA-P256 private key in PKCS#8
/// format.
#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub fn witness(
    signing_key: String,
    chain_id: String,
    app_hash: String,
    block_height: u64,
    domain: String,
    zone: String,
    enrollment: String,
) -> Result<String, WitnessError> {
    let keypair = KeyPair::decode(&hex::decode(signing_key).map_err(|_| Error::InvalidSigningKey)?)
        .map_err(|_| Error::InvalidSigningKey)?;
    let identity = keypair.public_key().to_vec();

    // Get the canonical hash of the enrollment:
    let hash_observed = if !enrollment.is_empty() {
        let enrollment: Enrollment = serde_json::from_str(&enrollment)?;

        // Validate enrollment constraints from the spec
        // https://github.com/freedomofpress/webcat-spec/blob/main/server.md
        // Threshold must be at least 1.
        if enrollment.threshold == 0 {
            return Err(Error::InvalidEnrollment(
                "threshold must be at least 1".to_string(),
            ));
        }
        // From the spec:
        // The value of threshold MUST be less than or equal to the number of entries in signers
        if enrollment.threshold as usize > enrollment.signers.len() {
            return Err(Error::InvalidEnrollment(format!(
                "threshold ({}) must be less than or equal to the number of signers ({})",
                enrollment.threshold,
                enrollment.signers.len()
            )));
        }

        let canonicalized = canonical_json::to_string(&serde_json::to_value(&enrollment)?)?;
        let canonical_hash = sha2::Sha256::digest(&canonicalized).into();
        HashObserved::Hash(canonical_hash)
    } else {
        HashObserved::NotFound
    };

    let tx = transaction::Builder::new(ChainId(chain_id))
        .observe(
            identity,
            transaction::Observation {
                domain: transaction::Domain {
                    name: domain.parse()?,
                },
                zone: transaction::Zone {
                    name: zone.parse()?,
                },
                hash_observed,
                blockstamp: transaction::Blockstamp {
                    app_hash: hex::decode(app_hash)?
                        .try_into()
                        .map_err(|_| hex::FromHexError::InvalidStringLength)?,
                    block_height: block_height
                        .try_into()
                        .map_err(|_| Error::BlockHeightOutOfRange(block_height))?,
                },
            },
        )
        .build()
        .sign_to_proto(keypair)?;

    // Check the result of signing and return the JSON or error.
    let _auth_tx = AuthenticatedTx::from_proto(&tx)?;

    Ok(hex::encode(tx))
}
