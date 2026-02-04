//! This tiny crate is a utility for creating signed reconfiguration transactions in Felidae.
//!
//! It exposes a single function, `reconfigure`, which takes the necessary parameters
//! and returns a signed transaction as a hex-encoded string, ready to submit to a node.

use std::time::Duration;

/// Default grace period for the `not_before` timestamp in reconfiguration transactions.
///
/// This value determines how far back in time (relative to wall clock) the `not_before` bound
/// is set. It must be large enough to account for the lag between wall clock time and blockchain
/// block time.
///
/// **Critical relationship with CometBFT's `timeout_commit`:**
///
/// The blockchain's block time advances only when new blocks are finalized. With CometBFT,
/// blocks are produced at intervals determined by `timeout_commit` in `config.toml`. If
/// `timeout_commit` is set to 60 seconds, the blockchain clock may lag up to 60 seconds
/// behind wall clock time.
///
/// This grace period **must be greater than `timeout_commit`** to ensure that reconfiguration
/// transactions are not rejected with "current time is before the not_before bound" errors.
/// A safe default is 2-3x the expected `timeout_commit` value.
///
/// Default: 5 minutes (300 seconds), suitable for `timeout_commit` values up to ~2 minutes.
pub const DEFAULT_NOT_BEFORE_GRACE_PERIOD: Duration = Duration::from_secs(300);

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
///
/// # Arguments
///
/// * `signing_key` - The admin's ECDSA-P256 private key in PKCS#8 DER format.
/// * `chain_id` - The chain ID of the target network.
/// * `timeout` - How long the transaction remains valid after submission (`not_after` bound).
/// * `not_before_grace` - Grace period for the `not_before` timestamp. If `None`, uses
///   [`DEFAULT_NOT_BEFORE_GRACE_PERIOD`]. See that constant's documentation for details on
///   how this relates to CometBFT's `timeout_commit` configuration.
/// * `config` - The new configuration to propose.
pub fn reconfigure(
    signing_key: &[u8],
    chain_id: String,
    timeout: Duration,
    not_before_grace: Option<Duration>,
    config: Config,
) -> Result<String, Error> {
    let keypair = KeyPair::decode(signing_key).map_err(|_| Error::InvalidSigningKey)?;
    let admin = keypair.public_key().to_vec();

    // Set the time window for validity of the reconfiguration based on the current time and
    // specified timeout. The grace period must be large enough to account for the lag between
    // wall clock time and blockchain block time (see DEFAULT_NOT_BEFORE_GRACE_PERIOD docs).
    let grace = not_before_grace.unwrap_or(DEFAULT_NOT_BEFORE_GRACE_PERIOD);
    let not_before = (Time::now() - grace).map_err(|_| Error::InvalidTimeout)?;
    let not_after = (not_before + grace).map_err(|_| Error::InvalidTimeout)?;
    let not_after = (not_after + timeout).map_err(|_| Error::InvalidTimeout)?;

    let tx = transaction::Builder::new(ChainId(chain_id))
        .reconfigure(admin, not_before, not_after, config)
        .build()
        .sign_to_proto(keypair)?;

    // Check the result of signing and return the JSON or error.
    let _auth_tx = AuthenticatedTx::from_proto(&tx)?;

    Ok(hex::encode(tx))
}
