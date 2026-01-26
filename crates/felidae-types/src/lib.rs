//! Domain types used in Felidae's transactions and storage.

use std::any::type_name;
use std::fmt::Display;

pub use felidae_proto::transaction::{
    AsyncSigner, KeyPair, KeyPairs, SignError, Signer, VerifyError,
};

pub use fqdn::FQDN;
pub use tendermint::AppHash;
pub use tendermint::block::Height;

#[derive(thiserror::Error, Debug)]
#[error("Cannot parse invalid {0}: {1}")]
pub struct ParseError(&'static str, String);

impl ParseError {
    /// Create a new parse error for the given type and value.
    pub fn new<T>(value: impl Display) -> Self {
        Self(type_name::<T>(), value.to_string())
    }
}

/// If we have a signature verification error, report it as a parse error for the signature type.
impl From<VerifyError> for ParseError {
    fn from(_: VerifyError) -> Self {
        Self("signature", String::new())
    }
}

pub mod response;
pub mod transaction;
