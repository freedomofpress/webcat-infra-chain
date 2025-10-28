//! We use protobuf as a canonical encoding for transactions and other data structures.
//!
//! This crate contains the protobuf definitions (as generated Rust code) as well as the
//! [`DomainType`] trait for converting between domain types and their protobuf representations. The
//! domain types themselves are defined in the `felidae-types` crate.
//!
//! # Signing and Verifying
//!
//! All signing and verification occurs on the protobuf representation of transactions. The domain
//! types do not contain signatures; instead, signatures are added to and verified from the protobuf
//! types. Furthermore, all signatures are over the protobuf encoding of the entire transaction with
//! signatures removed. This prevents malleability attacks by construction.
//!
//! In order to facilitate this, the protobuf types have methods for signing and verifying
//! transactions, as well as for serializing and deserializing them to and from both protobuf binary
//! format and JSON format. The domain types have convenience methods that delegate to the protobuf
//! methods for signing and verifying.
//!
//! As an end-user of this system, all you need to do is to add a
//! `felidae_proto::transaction::Signature` wherever you need a signature in any new protobuf
//! message, and then whenever you use `sign_to_proto`, `sign_to_json`, `authenticate_from_proto`,
//! or `authenticate_from_json`, the signatures will be handled automatically, since transaction
//! signing traverses the entire structure of the protobuf type looking for
//! `felidae_proto::transaction::Signature` to sign. You will of course need to provide a `Signer`
//! implementation that knows how to sign for the relevant public keys.

pub mod transaction {
    include!(concat!(env!("OUT_DIR"), "/felidae.transaction.rs"));

    /// Functionality for signing and verifying transactions.
    mod sign;
    pub use sign::{AsyncSigner, KeyPair, KeyPairs, SignError, Signer, VerifyError};
}

/// A marker type that captures the relationships between a domain type (`Self`) and a protobuf type (`Self::Proto`).
pub trait DomainType
where
    Self: Clone + Sized + TryFrom<Self::Proto>,
    Self::Proto: prost::Message + Default + From<Self> + Send + Sync + 'static,
    color_eyre::Report: From<<Self as TryFrom<Self::Proto>>::Error>,
{
    type Proto;

    /// Encode this domain type to a byte vector, via proto type `P`.
    fn encode_to_vec(&self) -> Vec<u8> {
        use prost::Message;
        self.to_proto().encode_to_vec()
    }

    /// Convert this domain type to the associated proto type.
    ///
    /// This uses the `From` impl internally, so it works exactly
    /// like `.into()`, but does not require type inference.
    fn to_proto(&self) -> Self::Proto {
        Self::Proto::from(self.clone())
    }

    /// Decode this domain type from a byte buffer, via proto type `P`.
    fn decode<B: bytes::Buf>(buf: B) -> color_eyre::Result<Self> {
        <Self::Proto as prost::Message>::decode(buf)?
            .try_into()
            .map_err(Into::into)
    }
}

#[macro_export]
macro_rules! domain_types {
    ($name:ty : $proto:ty) => {
        impl ::felidae_proto::DomainType for $name {
            type Proto = $proto;
        }
    };
    ($($name:ty : $proto:ty),* $(,)?) => {
        $(domain_types!($name : $proto);)*
    };
}

impl DomainType for tendermint::Time {
    type Proto = transaction::Timestamp;
}

impl From<tendermint::Time> for transaction::Timestamp {
    fn from(time: tendermint::Time) -> Self {
        let timestamp = tendermint_proto::google::protobuf::Timestamp::from(time);
        Self {
            seconds: timestamp.seconds,
            nanos: timestamp.nanos,
        }
    }
}

impl TryFrom<transaction::Timestamp> for tendermint::Time {
    type Error = color_eyre::Report;

    fn try_from(value: transaction::Timestamp) -> Result<Self, Self::Error> {
        let timestamp = tendermint_proto::google::protobuf::Timestamp {
            seconds: value.seconds,
            nanos: value.nanos,
        };
        Ok(tendermint::Time::try_from(timestamp)?)
    }
}

impl DomainType for tendermint::block::Height {
    type Proto = u64;
}

impl DomainType for tendermint::vote::Power {
    type Proto = u64;
}

impl DomainType for tendermint::AppHash {
    type Proto = bytes::Bytes;
}

impl DomainType for () {
    type Proto = ();
}

impl DomainType for Vec<u8> {
    type Proto = bytes::Bytes;
}

impl DomainType for bytes::Bytes {
    type Proto = bytes::Bytes;
}
