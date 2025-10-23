use color_eyre::Report;
use color_eyre::eyre::{Context, eyre};
use felidae_proto::DomainType;
use felidae_types::transaction::VotingConfig;
use futures::{StreamExt, TryStreamExt};
use std::collections::HashMap;
use std::fmt::Debug;
use std::hash::Hash;
use tendermint::Time;

use crate::State;
use crate::store::Substore::Internal;

/// Key construction and parsing functions for the vote queue.
mod keys;

pub struct VoteQueue<K, V> {
    internal_state_prefix: &'static str,
    config: VotingConfig,
    _key: std::marker::PhantomData<fn(&K)>,
    _value: std::marker::PhantomData<fn(&V)>,
}

pub struct Vote<K, V> {
    pub party: String,
    pub time: Time,
    pub key: K,
    pub value: V,
}

impl<K: DomainType<Proto = String> + TryFrom<String>, V: DomainType + Eq + Hash + Debug>
    VoteQueue<K, V>
where
    Report: From<<V as TryFrom<V::Proto>>::Error>,
    Report: From<<K as TryFrom<K::Proto>>::Error>,
    String: From<K>,
{
    pub fn new(prefix: &'static str, config: VotingConfig) -> VoteQueue<K, V> {
        VoteQueue {
            internal_state_prefix: prefix,
            config,
            _key: std::marker::PhantomData,
            _value: std::marker::PhantomData,
        }
    }

    #[instrument(skip(self, state), fields(queue = self.internal_state_prefix))]
    pub async fn timeout_expired_votes(&self, state: &mut State) -> Result<(), Report> {
        // Remove any votes older than now - config.vote_timeout
        let now = state.block_time().await?;
        let old_votes = state
            .store
            .index_prefix::<()>(Internal, &self.votes_by_timestamp_all_prefix())
            .await
            .map(|result| {
                let (key, ()) = result?;
                let (time, key, party) = self.parse_index_votes_by_timestamp_key_party(&key)?;
                Ok::<_, Report>((time, key.to_string(), party.to_string()))
            })
            .try_take_while(|(time, _key, _party)| {
                let filter = now.duration_since(*time).unwrap_or_default() > self.config.timeout.0;
                async move { Ok(filter) }
            })
            .try_collect::<Vec<_>>()
            .await?;
        for (time, key, party) in old_votes {
            info!(key, party, %time, "removing expired vote");
            state
                .store
                .delete(
                    Internal,
                    &self.votes_by_key_party_timestamp(&key, &party, time),
                )
                .await;
            state
                .store
                .index_delete(
                    Internal,
                    &self.index_votes_by_timestamp_key_party(time, &key, &party),
                )
                .await;
        }

        Ok(())
    }

    #[instrument(skip(self, state), fields(queue = self.internal_state_prefix))]
    pub async fn promote_pending_changes(&self, state: &mut State) -> Result<Vec<(K, V)>, Report> {
        // Promote any pending changes older than now - config.delay to the canonical state by
        // deleting them from the pending queue and returning them to be applied.

        // Get all the pending changes older than now - config.delay:
        let now = state.block_time().await?;
        let pending = state
            .store
            .index_prefix::<V>(Internal, &self.index_pending_by_timestamp_all_prefix())
            .await
            .map(|result| {
                let (key, value) = result?;
                let (time, key) = self.parse_index_pending_by_timestamp_key(&key)?;
                Ok::<_, Report>((time, key.to_string(), value))
            })
            .try_take_while(|(time, _key, _value)| {
                let filter = now.duration_since(*time).unwrap_or_default() > self.config.delay.0;
                async move { Ok(filter) }
            })
            .try_collect::<Vec<_>>()
            .await?;

        // Delete them from the pending queue:
        let mut promoted = vec![];
        for (time, key, value) in pending {
            info!(key, ?value, "promoting pending change to canonical state");
            state
                .store
                .delete(Internal, &self.pending_by_key_timestamp(&key, time))
                .await;
            state
                .store
                .index_delete(Internal, &self.index_pending_by_timestamp_key(time, &key))
                .await;
            promoted.push((key.try_into()?, value));
        }

        Ok(promoted)
    }

    #[instrument(skip(self, state, party, time, key, value), fields(queue = self.internal_state_prefix))]
    pub async fn cast(
        &self,
        state: &mut State,
        Vote {
            party,
            time,
            key,
            value,
        }: Vote<K, V>,
    ) -> Result<(), Report> {
        let key = String::from(key);
        info!(key, party, ?value, "casting vote");

        // 0. Remove any pre-existing vote by this party for this key
        let votes_by_party = state
            .store
            .prefix::<V>(
                Internal,
                &self.votes_by_key_party_prefix(&key, &party, true),
            )
            .await
            .map_ok(|(key, _)| key.to_string())
            .try_collect::<Vec<_>>()
            .await?;
        for key in votes_by_party {
            state.store.delete(Internal, &key).await;
        }

        // 1. Add to the list of votes by key/party/timestamp
        state
            .store
            .put(
                Internal,
                &self.votes_by_key_party_timestamp(&key, &party, time),
                value.clone(),
            )
            .await;

        // 2. Add to the index of votes by timestamp/key/party
        state
            .store
            .index_put(
                Internal,
                &self.index_votes_by_timestamp_key_party(time, &key, &party),
                value.clone(),
            )
            .await;

        // 3. If the votes by key/party/timestamp exceed the quorum, move the change to the pending
        //    queue by key/timestamp and by timestamp/key, deleting all the accumulated votes by
        //    key/party/timestamp and timestamp/key/party, and also deleting any existing pending
        //    changes for this key (in both key/timestamp and timestamp/key).

        // Get all the votes for this key:
        let votes = state
            .store
            .prefix::<V>(Internal, &self.votes_by_key_prefix(&key, true))
            .await
            .map(|result| {
                let (key, value) = result?;
                let (_key, party, time) = self.parse_votes_by_key_party_timestamp(&key)?;
                Ok::<_, Report>((party.to_string(), time, value))
            })
            .try_collect::<Vec<_>>()
            .await?;

        // Tally the votes by value and see if any value has reached the quorum:
        let mut tally = HashMap::new();
        for (_party, _time, value) in votes.iter() {
            *tally.entry(value).or_insert(0) += 1;
        }
        let mut winner = None;
        for (value, count) in tally {
            if count >= self.config.quorum.0 {
                winner = Some(value);
                break;
            }
        }

        // If we have a winner, we can proceed to promote it to the pending queue, otherwise we're
        // now done...
        let Some(winning_value) = winner else {
            return Ok(());
        };

        info!(
            key,
            ?winning_value,
            "vote reached quorum; promoting to pending"
        );

        // Delete all the votes for this key:
        for (party, time, _) in votes.iter() {
            state
                .store
                .delete(
                    Internal,
                    &self.votes_by_key_party_timestamp(&key, party, *time),
                )
                .await;
            state
                .store
                .index_delete(
                    Internal,
                    &self.index_votes_by_timestamp_key_party(*time, &key, party),
                )
                .await;
        }

        // Delete any existing pending changes for this key:
        let pending_changes = state
            .store
            .prefix::<V>(Internal, &self.pending_by_key_prefix(&key, true))
            .await
            .map(|result| {
                let (key, _value) = result?;
                let (_key, time) = self.parse_pending_by_key_timestamp(&key)?;
                Ok::<_, Report>(time)
            })
            .try_collect::<Vec<_>>()
            .await?;
        for time in pending_changes {
            info!(key, %time, "overwriting existing pending change");
            state
                .store
                .delete(Internal, &self.pending_by_key_timestamp(&key, time))
                .await;
            state
                .store
                .index_delete(Internal, &self.index_pending_by_timestamp_key(time, &key))
                .await;
        }

        // Add the winning value to the pending queue:
        state
            .store
            .put(
                Internal,
                &self.pending_by_key_timestamp(&key, time),
                winning_value.clone(),
            )
            .await;
        state
            .store
            .index_put(
                Internal,
                &self.index_pending_by_timestamp_key(time, &key),
                winning_value.clone(),
            )
            .await;

        Ok(())
    }

    pub async fn pending_for_key(&self, state: &State, key: &str) -> Result<Option<V>, Report> {
        let pending = state
            .store
            .prefix::<V>(Internal, &self.pending_by_key_prefix(key, true))
            .await
            .map_ok(|(_key, value)| value)
            .try_collect::<Vec<_>>()
            .await?;
        if pending.len() > 1 {
            Err(eyre!(
                "multiple pending changes for key {} in vote queue",
                key
            ))
        } else {
            Ok(pending.into_iter().next())
        }
    }

    pub async fn pending_for_key_prefix(
        &self,
        state: &State,
        prefix: &str,
    ) -> Result<Vec<(K, V)>, Report> {
        let pending = state
            .store
            .prefix::<V>(Internal, &self.pending_by_key_prefix(prefix, false)) // Allow inexact key matches
            .await
            .map(|result| {
                let (key, value) = result?;
                let (key, _time) = self.parse_pending_by_key_timestamp(&key)?;
                Ok::<_, Report>((key.to_string().try_into()?, value))
            })
            .try_collect::<Vec<_>>()
            .await?;
        Ok(pending)
    }

    pub async fn votes_for_key(&self, state: &State, key: &str) -> Result<Vec<Vote<K, V>>, Report> {
        let votes = state
            .store
            .prefix::<V>(Internal, &self.votes_by_key_prefix(key, true))
            .await
            .map(|result| {
                let (key, value) = result?;
                let (key, party, time) = self.parse_votes_by_key_party_timestamp(&key)?;
                Ok::<_, Report>(Vote {
                    party: party.to_string(),
                    time,
                    key: key.to_string().try_into()?,
                    value,
                })
            })
            .try_collect::<Vec<_>>()
            .await?;
        Ok(votes)
    }

    pub async fn votes_for_key_prefix(
        &self,
        state: &State,
        prefix: &str,
    ) -> Result<Vec<Vote<K, V>>, Report> {
        let votes = state
            .store
            .prefix::<V>(Internal, &self.votes_by_key_prefix(prefix, false)) // Allow inexact key matches
            .await
            .map(|result| {
                let (key, value) = result?;
                let (key, party, time) = self.parse_votes_by_key_party_timestamp(&key)?;
                Ok::<_, Report>(Vote {
                    party: party.to_string(),
                    time,
                    key: key.to_string().try_into()?,
                    value,
                })
            })
            .try_collect::<Vec<_>>()
            .await?;
        Ok(votes)
    }
}
