use super::*;

/// A signer is something that can sign a digest using one or more Ed25519 keypairs.
pub trait Signer {
    /// This should return the signature if and only if the public key matches a keypair that can
    /// produce a signature through the signer.
    fn sign_with(&self, public_key: &[u8], digest: Digest) -> Option<Vec<u8>>;
}

/// An async signer is something that can sign a digest using one or more Ed25519 keypairs,
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

impl Signer for Ed25519KeyPair {
    fn sign_with(&self, public_key: &[u8], digest: Digest) -> Option<Vec<u8>> {
        if self.public_key().as_ref() == public_key {
            let signature = self.sign(digest.as_ref());
            Some(signature.as_ref().to_vec())
        } else {
            None
        }
    }
}

/// A collection of Ed25519 keypairs, indexed by public key.
pub struct Ed25519KeyPairs {
    keypairs: HashMap<Bytes, Ed25519KeyPair>,
}

impl Ed25519KeyPairs {
    /// Create an empty collection of keypairs.
    pub fn new() -> Self {
        Self {
            keypairs: HashMap::new(),
        }
    }

    /// Insert a keypair into the collection.
    pub fn insert(&mut self, keypair: Ed25519KeyPair) {
        self.keypairs
            .insert(Bytes::from(keypair.public_key().as_ref().to_vec()), keypair);
    }

    /// Remove a keypair from the collection by its public key.
    pub fn remove(&mut self, public_key: &[u8]) -> Option<Ed25519KeyPair> {
        self.keypairs.remove(public_key)
    }
}

impl Default for Ed25519KeyPairs {
    fn default() -> Self {
        Self::new()
    }
}

impl FromIterator<Ed25519KeyPair> for Ed25519KeyPairs {
    fn from_iter<T: IntoIterator<Item = Ed25519KeyPair>>(iter: T) -> Self {
        let mut keypairs = Self::new();
        for kp in iter {
            keypairs.insert(kp);
        }
        keypairs
    }
}

impl Signer for Ed25519KeyPairs {
    fn sign_with(&self, public_key: &[u8], digest: Digest) -> Option<Vec<u8>> {
        self.keypairs
            .get(public_key)
            .and_then(|kp| kp.sign_with(public_key, digest))
    }
}
