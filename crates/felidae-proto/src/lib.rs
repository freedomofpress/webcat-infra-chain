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
