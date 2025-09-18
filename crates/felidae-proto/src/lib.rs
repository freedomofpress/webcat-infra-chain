pub mod transaction {
    include!(concat!(env!("OUT_DIR"), "/felidae.transaction.rs"));

    /// Functionality for signing and verifying transactions.
    mod sign;
    pub use sign::{AsyncSigner, Ed25519KeyPairs, SignError, Signer, VerifyError};
}
