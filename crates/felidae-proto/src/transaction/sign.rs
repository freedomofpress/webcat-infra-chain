//! We use NIST P-256 ECDSA signatures over SHA-256 hashes for transaction signing throughout
//! Felidae, as this is widely supported by a variety of environments including web browsers and
//! hardware security modules.

use std::{any::Any, collections::HashMap};

use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use prost::{Message as _, bytes::Bytes};
use sha2::{Digest, Sha256, digest::Output};

#[derive(thiserror::Error, Debug)]
#[error("Signature verification failed")]
pub struct VerifyError;

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

impl super::Transaction {
    /// Decode a transaction and verify all its signatures, stripping them in the process.
    pub fn authenticate_from_proto<B: AsRef<[u8]>>(buf: B) -> Result<Self, VerifyError> {
        let tx = Self::decode(buf.as_ref()).map_err(|_| VerifyError)?;
        let mut tx = tx.verify_all().map_err(|_| VerifyError)?;
        tx.unsign_all();
        Ok(tx)
    }

    /// Deserialize a transaction from JSON and verify all its signatures, stripping them in the process.
    pub fn authenticate_from_json(s: &str) -> Result<Self, VerifyError> {
        let tx: Self = serde_json::from_str(s).map_err(|_| VerifyError)?;
        let mut tx = tx.verify_all().map_err(|_| VerifyError)?;
        tx.unsign_all();
        Ok(tx)
    }

    /// Encode a transaction and fill in all its signatures using the given signer.
    pub fn sign_to_proto(self, signer: impl Signer) -> Result<Vec<u8>, SignError> {
        let tx = self.sign_all(signer)?;
        Ok(tx.encode_to_vec())
    }

    /// Serialize a transaction to JSON and fill in all its signatures using the given signer.
    pub fn sign_to_json(self, signer: impl Signer) -> Result<String, SignError> {
        let tx = self.sign_all(signer)?;
        serde_json::to_string(&tx).map_err(|_| SignError::AlreadySigned)
    }

    /// Compute the hash of the transaction as a protobuf message.
    ///
    /// The hash is computed after removing all signatures from the transaction, so that it can
    /// be computed as an *input* to signing.
    pub fn hash(&self) -> Output<Sha256>
    where
        Self: prost::Message + Sized,
    {
        let mut unbound = self.clone();
        unbound.unsign_all();
        let mut context = Sha256::new();
        context.update(unbound.encode_to_vec());
        context.finalize()
    }

    /// Fill in every blank signature with a valid signature over the hash of the transaction.
    fn sign_all(mut self, signer: impl Signer) -> Result<Self, SignError>
    where
        Self: prost::Message + Sized,
    {
        // Compute the transaction hash once:
        let digest = self.hash();

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
    fn verify_all(self) -> Result<Self, VerifyError> {
        let digest = self.hash();
        let mut result = Ok(());
        self.traverse(&mut |v| {
            if let Some(super::Signature {
                public_key,
                signature,
                ..
            }) = (v as &dyn Any).downcast_ref::<super::Signature>()
                && !verify(public_key.as_ref(), signature.as_ref(), digest.as_ref())
            {
                result = Err(VerifyError);
            }
        });
        result.map(|()| self)
    }
}

fn verify(public_key: &[u8], signature: &[u8], digest: &[u8]) -> bool {
    // Parse the signature from bytes:
    let Ok(signature) = <[u8; 64]>::try_from(signature) else {
        return false;
    };
    let signature = match Signature::from_bytes(&signature.into()) {
        Ok(sig) => sig,
        Err(_) => return false,
    };
    // Decode the public key as an encoded point:
    let Ok(public_key) = public_key.try_into() else {
        return false;
    };
    // Parse the verifying key from the encoded point:
    let verifying_key = match VerifyingKey::from_encoded_point(&public_key) {
        Ok(vk) => vk,
        Err(_) => return false,
    };
    // Verify the signature:
    verifying_key.verify(digest, &signature).is_ok()
}

mod test;
