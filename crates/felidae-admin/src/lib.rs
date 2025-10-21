use std::time::Duration;

pub use felidae_types::{
    AppHash, FQDN, Height, SignError, Signer,
    transaction::{ChainId, HashObserved},
};
use felidae_types::{
    KeyPair,
    transaction::{self, AuthenticatedTx, Config},
};
use tendermint::Time;

/// Errors that may occur when creating a witness transaction.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    /// Signing the transaction failed.
    #[error(transparent)]
    Sign(#[from] SignError),
    /// Authenticating the signed transaction failed.
    #[error(transparent)]
    Auth(#[from] felidae_types::ParseError),
    /// The hash observed was not valid hex, or invalid length.
    #[error(transparent)]
    Hex(#[from] hex::FromHexError),
    /// The signing key was not valid hex, or not a valid key.
    #[error("invalid signing key")]
    InvalidSigningKey,
    /// The timeout duration was invalid.
    #[error("invalid timeout duration")]
    InvalidTimeout,
}

/// Create a hex-encoded, signed transaction witnessing the given observation on the given chain,
/// using the given oracle signing key.
///
/// The admin signing key must be a valid ECDSA-P256 private key in PKCS#8 format.
pub fn reconfigure(
    signing_key: &[u8],
    chain_id: String,
    timeout: Duration,
    config: Config,
) -> Result<String, Error> {
    let keypair = KeyPair::decode(signing_key).map_err(|_| Error::InvalidSigningKey)?;
    let admin = keypair.public_key().to_vec();

    // Set the time window for validity of the reconfiguration based on the current time and
    // specified timeout.
    let not_before = (Time::now() - Duration::from_secs(5)).map_err(|_| Error::InvalidTimeout)?;
    let not_after = (not_before + timeout).map_err(|_| Error::InvalidTimeout)?;

    let tx = transaction::Builder::new(ChainId(chain_id))
        .reconfigure(admin, not_before, not_after, config)
        .build()
        .sign_to_proto(keypair)?;

    // Check the result of signing and return the JSON or error.
    let _auth_tx = AuthenticatedTx::from_proto(&tx)?;

    Ok(hex::encode(tx))
}
