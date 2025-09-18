use std::any::TypeId;

use felidae_proto::transaction::{self as proto, VerifyError};

#[derive(thiserror::Error, Debug)]
#[error("Cannot parse invalid {0:?}")]
pub struct ParseError(TypeId);

/// If we have a signature verification error, report it as a parse error for the signature type.
impl From<VerifyError> for ParseError {
    fn from(_: VerifyError) -> Self {
        Self(TypeId::of::<proto::Signature>())
    }
}

pub mod transaction;
