use felidae_proto::transaction as proto;

pub struct Transaction {
    pub chain_id: String,
}

impl TryFrom<proto::Transaction> for Transaction {
    type Error = crate::ParseError;

    fn try_from(value: proto::Transaction) -> Result<Self, Self::Error> {
        let proto::Transaction { chain_id } = value;
        Ok(Transaction { chain_id })
    }
}
