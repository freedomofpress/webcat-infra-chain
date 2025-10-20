use std::{any::Any, collections::HashMap};

use prost::{Message as _, bytes::Bytes};
pub use ring::error::Unspecified as VerifyError;
use ring::{
    digest::{Context, Digest},
    signature::{ECDSA_P256_SHA256_FIXED, UnparsedPublicKey},
};

use felidae_traverse::Traverse;

mod signer;
pub use signer::{AsyncSigner, KeyPair, KeyPairs, Signer};

#[derive(thiserror::Error, Debug)]
pub enum SignError {
    #[error("No keypair available for public key in transaction")]
    MissingKeypair,
    #[error("Transaction already contains a signature")]
    AlreadySigned,
}

impl super::Signature {
    /// Create a new blank signature for the given public key.
    pub fn unsigned(public_key: Bytes) -> Self {
        Self {
            public_key,
            signature: Bytes::new(),
        }
    }
}

impl From<super::Signature> for UnparsedPublicKey<Bytes> {
    fn from(sig: super::Signature) -> Self {
        UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, sig.public_key)
    }
}

impl super::Transaction {
    /// Decode a transaction and verify all its signatures, stripping them in the process.
    pub fn authenticate_from_proto<B: AsRef<[u8]>>(
        context: Context,
        buf: B,
    ) -> Result<Self, VerifyError> {
        let tx = Self::decode(buf.as_ref()).map_err(|_| VerifyError)?;
        let mut tx = tx.verify_all(context).map_err(|_| VerifyError)?;
        tx.unsign_all();
        Ok(tx)
    }

    /// Deserialize a transaction from JSON and verify all its signatures, stripping them in the process.
    pub fn authenticate_from_json(context: Context, s: &str) -> Result<Self, VerifyError> {
        let tx: Self = serde_json::from_str(s).map_err(|_| VerifyError)?;
        let mut tx = tx.verify_all(context).map_err(|_| VerifyError)?;
        tx.unsign_all();
        Ok(tx)
    }

    /// Encode a transaction and fill in all its signatures using the given signer.
    pub fn sign_to_proto(
        self,
        context: Context,
        signer: impl Signer,
    ) -> Result<Vec<u8>, SignError> {
        let tx = self.sign_all(signer, context)?;
        Ok(tx.encode_to_vec())
    }

    /// Serialize a transaction to JSON and fill in all its signatures using the given signer.
    pub fn sign_to_json(self, context: Context, signer: impl Signer) -> Result<String, SignError> {
        let tx = self.sign_all(signer, context)?;
        serde_json::to_string(&tx).map_err(|_| SignError::AlreadySigned)
    }

    /// Compute the hash of the transaction as a protobuf message.
    ///
    /// The hash is computed after removing all signatures from the transaction, so that it can
    /// be computed as an *input* to signing.
    pub fn hash(&self, mut context: Context) -> Digest
    where
        Self: prost::Message + Sized,
    {
        let mut unbound = self.clone();
        unbound.unsign_all();
        context.update(&unbound.encode_to_vec());
        context.finish()
    }

    /// Fill in every blank signature with a valid signature over the hash of the transaction.
    fn sign_all(mut self, signer: impl Signer, context: Context) -> Result<Self, SignError>
    where
        Self: prost::Message + Sized,
    {
        // Compute the transaction hash once:
        let digest = self.hash(context);

        // Then traverse the transaction, filling in signatures as we go:
        let mut result = Ok(());
        self.traverse_mut(&mut |v| {
            if let Some(super::Signature {
                public_key,
                signature,
            }) = (v as &mut dyn Any).downcast_mut::<super::Signature>()
            {
                if signature.is_empty() {
                    if let Some(sig) = signer.sign_with(public_key.as_ref(), digest) {
                        *signature = sig.into();
                    } else {
                        // No keypair available:
                        result = Err(SignError::MissingKeypair);
                    }
                } else {
                    // Signature already present:
                    result = Err(SignError::AlreadySigned);
                }
            }
        });

        // If we succeeded, return the signed transaction:
        result.map(|()| self)
    }

    /// Remove all signatures from this object and its sub-objects.
    fn unsign_all(&mut self) {
        self.traverse_mut(&mut |v| {
            if let Some(super::Signature { signature, .. }) =
                (v as &mut dyn Any).downcast_mut::<super::Signature>()
            {
                signature.clear();
            }
        });
    }

    /// Verify every signature in the transaction against the hash of the transaction.
    fn verify_all(self, context: Context) -> Result<Self, VerifyError> {
        let digest = self.hash(context);
        let mut result = Ok(());
        self.traverse(&mut |v| {
            if let Some(super::Signature {
                public_key,
                signature,
                ..
            }) = (v as &dyn Any).downcast_ref::<super::Signature>()
            {
                if !signature.is_empty() {
                    if let Err(e) = UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, public_key)
                        .verify(digest.as_ref(), signature)
                    {
                        result = Err(e);
                    }
                } else {
                    // Missing signature is an error:
                    result = Err(VerifyError);
                }
            }
        });
        result.map(|()| self)
    }
}

mod test;
