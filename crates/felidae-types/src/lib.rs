use std::any::TypeId;

#[derive(thiserror::Error, Debug)]
#[error("Cannot parse invalid {0:?}")]
pub struct ParseError(TypeId);

pub mod transaction;
