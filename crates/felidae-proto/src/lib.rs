pub mod transaction {
    include!(concat!(env!("OUT_DIR"), "/felidae.transaction.rs"));

    /// Functionality for signing and verifying transactions.
    mod sign;
    pub use sign::{AsyncSigner, KeyPair, KeyPairs, SignError, Signer, VerifyError};
}
