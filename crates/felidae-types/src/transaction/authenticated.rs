use super::*;

/// A transaction that has been signed and whose signatures have been verified.
///
/// This transaction is not necessarily valid, either internally or against the current state.
/// However, it is guaranteed that it was signed by the claimed public keys.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AuthenticatedTx(Transaction);

impl Deref for AuthenticatedTx {
    type Target = Transaction;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AuthenticatedTx {
    /// Deserialize a transaction from JSON, verify all its signatures, and convert it into the
    /// domain type.
    pub fn from_json(json: &str) -> Result<AuthenticatedTx, crate::ParseError> {
        Ok(AuthenticatedTx(
            proto::Transaction::authenticate_from_json(json)?.try_into()?,
        ))
    }

    /// Decode a transaction from bytes, verify all its signatures, and convert it into the domain
    /// type.
    pub fn from_proto<B: AsRef<[u8]>>(buf: B) -> Result<AuthenticatedTx, crate::ParseError> {
        Ok(AuthenticatedTx(
            proto::Transaction::authenticate_from_proto(buf)?.try_into()?,
        ))
    }
}

impl Transaction {
    /// Serialize the transaction to JSON, signing all its actions with the given signer.
    pub fn sign_to_json(self, signer: impl Signer) -> Result<String, SignError> {
        proto::Transaction::from(self).sign_to_json(signer)
    }

    /// Encode the transaction to bytes, signing all its actions with the given signer.
    pub fn sign_to_proto(self, signer: impl Signer) -> Result<Vec<u8>, SignError> {
        proto::Transaction::from(self).sign_to_proto(signer)
    }
}
