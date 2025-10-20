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
    #[error(transparent)]
    Hex(#[from] hex::FromHexError),
    /// The block height was invalid.
    #[error("block height {0} is out of range")]
    BlockHeightOutOfRange(u64),
    /// The signing key was not valid hex, or not a valid key.
    #[error("invalid signing key")]
    InvalidSigningKey,
}

#[cfg(target_arch = "wasm32")]
type WitnessError = JsError;
#[cfg(not(target_arch = "wasm32"))]
type WitnessError = Error;

/// Create a JSON-encoded, signed transaction witnessing the given observation on the given chain,
/// using the given oracle signing key.
///
/// The oracle signing key must be the hex encoding of a valid ECDSA-P256 private key in PKCS#8
/// format.
#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub fn witness_json(
    signing_key: String,
    chain_id: String,
    app_hash: String,
    block_height: u64,
    domain: String,
    zone: String,
    hash_observed: String,
) -> Result<String, WitnessError> {
    let keypair = KeyPair::decode(&hex::decode(signing_key).map_err(|_| Error::InvalidSigningKey)?)
        .map_err(|_| Error::InvalidSigningKey)?;
    let identity = keypair.public_key().to_vec();

    let tx = transaction::Builder::new(ChainId(chain_id))
        .observe(
            identity,
            transaction::Observation {
                domain: transaction::Domain {
                    name: domain.parse()?,
                },
                zone: transaction::Domain {
                    name: zone.parse()?,
                },
                hash_observed: if !hash_observed.is_empty() {
                    HashObserved::Hash(
                        hex::decode(hash_observed)?
                            .try_into()
                            .map_err(|_| hex::FromHexError::InvalidStringLength)?,
                    )
                } else {
                    HashObserved::NotFound
                },
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
        .sign_to_json(keypair)?;

    // Check the result of signing and return the JSON or error.
    let _auth_tx = AuthenticatedTx::from_json(&tx)?;

    Ok(tx)
}
