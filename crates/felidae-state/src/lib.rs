//! All of the on-chain logic for the Felidae state machine.
//
// This crate goes all the way from the ABCI interface down to the storage layer, defining the core
// state machine logic for the chain.

#[macro_use]
extern crate tracing;

use std::{collections::BTreeSet, str::FromStr, time::Duration};

use color_eyre::{
    Report,
    eyre::{OptionExt, bail, eyre},
};
use felidae_types::{
    FQDN,
    transaction::{
        Action, Admin, AdminConfig, AuthenticatedTx, Blockstamp, ChainId, Config, Delay, Domain,
        Empty, HashObserved, Observation, Observe, OnionConfig, Oracle, OracleConfig,
        PrefixOrderDomain, Quorum, Reconfigure, Timeout, Total, Transaction, VotingConfig,
    },
};
use futures::{Stream, StreamExt};
use prost::Message;
use prost::bytes::Bytes;
use sha2::{Digest, Sha256};
use tendermint::{
    AppHash, Time,
    abci::{
        request, response,
        types::{BlockSignatureInfo, CommitInfo, Misbehavior, Validator, VoteInfo},
    },
    block::{BlockIdFlag, Header, Height},
    validator::Update,
    vote::Power,
};

mod store;
pub use store::Store;
use store::{
    StateReadExt, StateWriteExt,
    Substore::{Canonical, Internal},
};

pub use state::Vote;

/// ABCI service implementation for [`State`].
mod abci;

/// A wrapper around a storage backend that provides domain-specific methods for accessing and
/// modifying the state.
///
/// Always prefer to use `State` over directly using the storage backend, as `State` provides
/// higher-level abstractions.
#[derive(Debug, Clone)]
pub struct State<S> {
    store: S,
}

impl<S> State<S> {
    /// Create a new state with the given store.
    pub fn new(store: S) -> Self {
        Self { store }
    }
}

mod state {
    use super::*;

    // Think of this module as a table of contents for the state submodules.
    //
    // Each submodule handles a specific aspect of the state management; state changes flow from
    // incoming ABCI commands, through action interpretation, to validator and voting behavior, making
    // use of intermediate state such as app hash, chain ID, config, height, and time, and ultimately
    // resulting in updates to the canonical state.

    /// Top-level ABCI commands. Each of these is triggered by an ABCI request defined in the
    /// top-level ABCI implementation module.
    mod abci;

    /// How to interpret each action in a transaction.
    mod action;

    /// Managing validators.
    mod validator;
    /// Managing votes by admins and oracles.
    mod voting;

    /// Setting and querying the application hash.
    mod app_hash;
    /// Setting and querying the chain ID.
    mod chain_id;
    /// Setting and querying the chain configuration.
    mod config;
    /// Setting and querying the block height.
    mod height;
    /// Setting and querying the consensus block time.
    mod time;

    /// Setting and querying the canonical state externally observed and snapshotted.
    mod canonical;

    /// Utility functions.
    mod util;

    pub use voting::Vote;
}
