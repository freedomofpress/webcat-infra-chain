use p256::{
    SecretKey,
    ecdsa::{Signature, SigningKey, signature::Signer as _},
};
use pkcs8::{DecodePrivateKey, EncodePrivateKey};
use rand_core::OsRng;

use super::*;

/// A signer is something that can sign a digest using one or more keypairs.
pub trait Signer {
    /// This should return the signature if and only if the public key matches a keypair that can
    /// produce a signature through the signer.
    fn sign_with(&self, public_key: &[u8], digest: Output<Sha256>) -> Option<Vec<u8>>;
}

/// An async signer is something that can sign a digest using one or more keypairs,
/// potentially performing asynchronous operations to do so.
pub trait AsyncSigner {
    /// This should return the signature if and only if the public key matches a keypair that can
    /// produce a signature through the signer.
    fn sign_with(
        &self,
        public_key: &[u8],
        digest: Output<Sha256>,
    ) -> impl Future<Output = Option<Vec<u8>>> + Send + '_;
}

#[derive(Debug)]
pub struct KeyPair {
    signing_key: SigningKey,
}

impl KeyPair {
    /// Create a fresh new keypair.
    pub fn generate() -> Self {
        let secret_key = SecretKey::random(&mut OsRng);
        let signing_key = SigningKey::from(secret_key);
        Self { signing_key }
    }

    /// Get the public key corresponding to this keypair.
    pub fn public_key(&self) -> Vec<u8> {
        self.signing_key
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec()
    }

    /// Create a new keypair from the given PKCS#8-encoded private key.
    pub fn decode(pkcs8: &[u8]) -> Result<Self, pkcs8::Error> {
        let secret_key = SecretKey::from_pkcs8_der(pkcs8)?;
        let signing_key = SigningKey::from(secret_key);
        Ok(Self { signing_key })
    }

    /// Serialize the keypair to PKCS#8 format.
    pub fn encode(&self) -> Result<Vec<u8>, pkcs8::Error> {
        let secret_key = self.signing_key.as_nonzero_scalar();
        let secret_key = SecretKey::from(secret_key);
        Ok(secret_key.to_pkcs8_der()?.as_bytes().to_vec())
    }
}

impl Signer for KeyPair {
    fn sign_with(&self, public_key: &[u8], digest: Output<Sha256>) -> Option<Vec<u8>> {
        if self.public_key() == public_key {
            let signature: Signature = self.signing_key.sign(digest.as_ref());
            Some(signature.to_bytes().to_vec())
        } else {
            None
        }
    }
}

/// A collection of keypairs, indexed by public key.
pub struct KeyPairs {
    keypairs: HashMap<Bytes, KeyPair>,
}

impl KeyPairs {
    /// Create an empty collection of keypairs.
    pub fn new() -> Self {
        Self {
            keypairs: HashMap::new(),
        }
    }

    /// Insert a keypair into the collection.
    pub fn insert(&mut self, keypair: KeyPair) {
        self.keypairs
            .insert(Bytes::from(keypair.public_key()), keypair);
    }

    /// Remove a keypair from the collection by its public key.
    pub fn remove(&mut self, public_key: &[u8]) -> bool {
        self.keypairs.remove(public_key).is_some()
    }
}

impl Default for KeyPairs {
    fn default() -> Self {
        Self::new()
    }
}

impl FromIterator<KeyPair> for KeyPairs {
    fn from_iter<T: IntoIterator<Item = KeyPair>>(iter: T) -> Self {
        let mut keypairs = Self::new();
        for kp in iter {
            keypairs.insert(kp);
        }
        keypairs
    }
}

impl Signer for KeyPairs {
    fn sign_with(&self, public_key: &[u8], digest: Output<Sha256>) -> Option<Vec<u8>> {
        self.keypairs
            .get(public_key)
            .and_then(|kp| kp.sign_with(public_key, digest))
    }
}
