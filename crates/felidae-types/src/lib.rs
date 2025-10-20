pub use felidae_proto::transaction::{
    AsyncSigner, KeyPair, KeyPairs, SignError, Signer, VerifyError,
};

pub use fqdn::FQDN;
pub use tendermint::AppHash;
pub use tendermint::block::Height;

#[derive(thiserror::Error, Debug)]
#[error("Cannot parse invalid {0}")]
pub struct ParseError(&'static str);

/// If we have a signature verification error, report it as a parse error for the signature type.
impl From<VerifyError> for ParseError {
    fn from(_: VerifyError) -> Self {
        Self("signature")
    }
}

pub mod transaction;
