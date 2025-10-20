use ring::rand::SystemRandom;
use ring::signature::KeyPair as _;

use super::*;

/// A signer is something that can sign a digest using one or more keypairs.
pub trait Signer {
    /// This should return the signature if and only if the public key matches a keypair that can
    /// produce a signature through the signer.
    fn sign_with(&self, public_key: &[u8], digest: Digest) -> Option<Vec<u8>>;
}

/// An async signer is something that can sign a digest using one or more keypairs,
/// potentially performing asynchronous operations to do so.
pub trait AsyncSigner {
    /// This should return the signature if and only if the public key matches a keypair that can
    /// produce a signature through the signer.
    fn sign_with(
        &self,
        public_key: &[u8],
        digest: Digest,
    ) -> impl Future<Output = Option<Vec<u8>>> + Send + '_;
}

#[derive(Debug)]
pub struct KeyPair {
    keypair: ring::signature::EcdsaKeyPair,
}

impl KeyPair {
    /// Create a fresh new keypair.
    pub fn generate() -> Result<Self, ring::error::Unspecified> {
        let rng = SystemRandom::new();
        let pkcs8_bytes = ring::signature::EcdsaKeyPair::generate_pkcs8(
            &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            &rng,
        )?;
        let keypair = ring::signature::EcdsaKeyPair::from_pkcs8(
            &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            pkcs8_bytes.as_ref(),
            &rng,
        )?;
        Ok(Self { keypair })
    }

    /// Get the public key corresponding to this keypair.
    pub fn public_key(&self) -> &[u8] {
        self.keypair.public_key().as_ref()
    }

    /// Create a new keypair from the given PKCS#8-encoded private key.
    pub fn decode(pkcs8: &[u8]) -> Result<Self, ring::error::Unspecified> {
        let rng = SystemRandom::new();
        let keypair = ring::signature::EcdsaKeyPair::from_pkcs8(
            &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            pkcs8,
            &rng,
        )?;
        Ok(Self { keypair })
    }

    /// Serialize the keypair to PKCS#8 format.
    pub fn encode(&self) -> Result<Vec<u8>, ring::error::Unspecified> {
        // Note: ring doesn't provide direct PKCS#8 serialization
        // This would need to be implemented or use another crate
        Err(ring::error::Unspecified)
    }
}

impl Signer for KeyPair {
    fn sign_with(&self, public_key: &[u8], digest: Digest) -> Option<Vec<u8>> {
        if self.public_key() == public_key {
            let rng = SystemRandom::new();
            let signature = self.keypair.sign(&rng, digest.as_ref()).ok()?;
            Some(signature.as_ref().to_vec())
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
            .insert(Bytes::from(keypair.public_key().as_ref().to_vec()), keypair);
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
    fn sign_with(&self, public_key: &[u8], digest: Digest) -> Option<Vec<u8>> {
        self.keypairs
            .get(public_key)
            .and_then(|kp| kp.sign_with(public_key, digest))
    }
}
