use prost::bytes::Bytes;
use tendermint::Time;

use crate::transaction::{
    Action, Admin, ChainId, Config, Observation, Observe, Oracle, Reconfigure, Transaction,
};

pub struct Builder {
    chain_id: ChainId,
    actions: Vec<Action>,
}

impl Builder {
    pub fn new(chain_id: ChainId) -> Self {
        Self {
            chain_id,
            actions: Vec::new(),
        }
    }

    fn action(mut self, action: Action) -> Self {
        self.actions.push(action);
        self
    }

    pub fn reconfigure(
        self,
        admin: impl Into<Bytes>,
        not_before: Time,
        not_after: Time,
        config: Config,
    ) -> Self {
        self.action(Action::Reconfigure(Reconfigure {
            admin: Admin {
                identity: admin.into(),
            },
            config,
            not_before,
            not_after,
        }))
    }

    pub fn observe(self, oracle: impl Into<Bytes>, observation: Observation) -> Self {
        self.action(Action::Observe(Observe {
            oracle: Oracle {
                identity: oracle.into(),
            },
            observation,
        }))
    }

    pub fn build(self) -> Transaction {
        Transaction {
            chain_id: self.chain_id,
            actions: self.actions,
        }
    }
}
