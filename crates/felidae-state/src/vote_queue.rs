use color_eyre::Report;
use color_eyre::eyre::{Context, eyre};
use felidae_proto::DomainType;
use felidae_types::transaction::VotingConfig;
use futures::TryStreamExt;
use std::collections::HashMap;
use std::hash::Hash;
use tendermint::Time;

use crate::State;

/// Key construction and parsing functions for the vote queue.
mod keys;

pub struct VoteQueue<T> {
    internal_state_prefix: &'static str,
    config: VotingConfig,
    _marker: std::marker::PhantomData<T>,
}

pub struct Vote<T> {
    pub party: String,
    pub time: Time,
    pub key: String,
    pub value: T,
}

impl<T: DomainType + Eq + Hash> VoteQueue<T>
where
    Report: From<<T as TryFrom<T::Proto>>::Error>,
{
    pub fn new(prefix: &'static str, config: VotingConfig) -> VoteQueue<T> {
        VoteQueue {
            internal_state_prefix: prefix,
            config,
            _marker: std::marker::PhantomData,
        }
    }

    pub async fn timeout_expired_votes(&self, state: &mut State) -> Result<(), Report> {
        // Remove any votes older than now - config.vote_timeout
        let now = state.block_time().await?;
        let old_votes = state
            .internal
            .index_prefix::<()>(&self.votes_by_timestamp_all_prefix())
            .map_ok(|(key, ())| {
                let (time, key, party) = self
                    .parse_index_votes_by_timestamp_key_party(&key)
                    .expect("valid votes_by_timestamp key");
                (time, key.to_string(), party.to_string())
            })
            .try_take_while(|(time, _key, _party)| {
                let filter = now.duration_since(*time).unwrap_or_default() > self.config.timeout.0;
                async move { Ok(filter) }
            })
            .try_collect::<Vec<_>>()
            .await?;
        for (time, key, party) in old_votes {
            state
                .internal
                .delete(&self.votes_by_key_party_timestamp(&key, &party, time))
                .await;
            state
                .internal
                .index_delete(&self.index_votes_by_timestamp_key_party(time, &key, &party))
                .await;
        }

        Ok(())
    }

    pub async fn promote_pending_changes(
        &self,
        state: &mut State,
    ) -> Result<Vec<(String, T)>, Report> {
        // Promote any pending changes older than now - config.delay to the canonical state by
        // deleting them from the pending queue and returning them to be applied.

        // Get all the pending changes older than now - config.delay:
        let now = state.block_time().await?;
        let pending = state
            .internal
            .index_prefix::<T>(&self.index_pending_by_timestamp_all_prefix())
            .map_ok(|(key, value)| {
                let (time, key) = self
                    .parse_index_pending_by_timestamp_key(&key)
                    .expect("valid pending_by_timestamp key");
                (time, key.to_string(), value)
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
            state
                .internal
                .delete(&self.pending_by_key_timestamp(&key, time))
                .await;
            state
                .internal
                .index_delete(&self.index_pending_by_timestamp_key(time, &key))
                .await;
            promoted.push((key, value));
        }

        Ok(promoted)
    }

    pub async fn cast(
        &self,
        state: &mut State,
        Vote {
            party,
            time,
            key,
            value,
        }: &Vote<T>,
    ) -> Result<(), Report> {
        // 0. Remove any pre-existing vote by this party for this key
        let votes_by_party = state
            .internal
            .prefix::<T>(&self.votes_by_key_party_prefix(key, party, true))
            .map_ok(|(key, _)| key.to_string())
            .try_collect::<Vec<_>>()
            .await?;
        for key in votes_by_party {
            state.internal.delete(&key).await;
        }

        // 1. Add to the list of votes by key/party/timestamp
        state
            .internal
            .put(
                &self.votes_by_key_party_timestamp(key, party, *time),
                value.clone(),
            )
            .await;

        // 2. Add to the index of votes by timestamp/key/party
        state
            .internal
            .index_put(
                &self.index_votes_by_timestamp_key_party(*time, key, party),
                value.clone(),
            )
            .await;

        // 3. If the votes by key/party/timestamp exceed the quorum, move the change to the pending
        //    queue by key/timestamp and by timestamp/key, deleting all the accumulated votes by
        //    key/party/timestamp and timestamp/key/party, and also deleting any existing pending
        //    changes for this key (in both key/timestamp and timestamp/key).

        // Get all the votes for this key:
        let votes = state
            .internal
            .prefix::<T>(&self.votes_by_key_prefix(key, true))
            .map_ok(|(key, value)| {
                let (_key, party, time) = self
                    .parse_votes_by_key_party_timestamp(&key)
                    .expect("valid votes_by_key_party_timestamp key");
                (party.to_string(), time, value)
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

        // Delete all the votes for this key:
        for (party, time, _) in votes.iter() {
            state
                .internal
                .delete(&self.votes_by_key_party_timestamp(key, party, *time))
                .await;
            state
                .internal
                .index_delete(&self.index_votes_by_timestamp_key_party(*time, key, party))
                .await;
        }

        // Delete any existing pending changes for this key:
        let pending_changes = state
            .internal
            .prefix::<T>(&self.pending_by_key_prefix(key, true))
            .map_ok(|(key, _)| {
                let (_key, time) = self
                    .parse_pending_by_key_timestamp(&key)
                    .expect("valid pending_by_key_timestamp key");
                time
            })
            .try_collect::<Vec<_>>()
            .await?;
        for time in pending_changes {
            state
                .internal
                .delete(&self.pending_by_key_timestamp(key, time))
                .await;
            state
                .internal
                .index_delete(&self.index_pending_by_timestamp_key(time, key))
                .await;
        }

        // Add the winning value to the pending queue:
        state
            .internal
            .put(
                &self.pending_by_key_timestamp(key, *time),
                winning_value.clone(),
            )
            .await;
        state
            .internal
            .index_put(
                &self.index_pending_by_timestamp_key(*time, key),
                winning_value.clone(),
            )
            .await;

        Ok(())
    }

    pub async fn pending_for_key(&self, state: &State, key: &str) -> Result<Option<T>, Report> {
        let pending = state
            .internal
            .prefix::<T>(&self.pending_by_key_prefix(key, true))
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
    ) -> Result<Vec<(String, T)>, Report> {
        let pending = state
            .internal
            .prefix::<T>(&self.pending_by_key_prefix(prefix, false)) // Allow inexact key matches
            .map_ok(|(key, value)| {
                let (key, _time) = self
                    .parse_pending_by_key_timestamp(&key)
                    .expect("valid pending_by_key_timestamp key");
                (key.to_string(), value)
            })
            .try_collect::<Vec<_>>()
            .await?;
        Ok(pending)
    }

    pub async fn votes_for_key(&self, state: &State, key: &str) -> Result<Vec<Vote<T>>, Report> {
        let votes = state
            .internal
            .prefix::<T>(&self.votes_by_key_prefix(key, true))
            .map_ok(|(key, value)| {
                let (key, party, time) = self
                    .parse_votes_by_key_party_timestamp(&key)
                    .expect("valid votes_by_key_party_timestamp key");
                Vote {
                    party: party.to_string(),
                    time,
                    key: key.to_string(),
                    value,
                }
            })
            .try_collect::<Vec<_>>()
            .await?;
        Ok(votes)
    }

    pub async fn votes_for_key_prefix(
        &self,
        state: &State,
        prefix: &str,
    ) -> Result<Vec<Vote<T>>, Report> {
        let votes = state
            .internal
            .prefix::<T>(&self.votes_by_key_prefix(prefix, false)) // Allow inexact key matches
            .map_ok(|(key, value)| {
                let (key, party, time) = self
                    .parse_votes_by_key_party_timestamp(&key)
                    .expect("valid votes_by_key_party_timestamp key");
                Vote {
                    party: party.to_string(),
                    time,
                    key: key.to_string(),
                    value,
                }
            })
            .try_collect::<Vec<_>>()
            .await?;
        Ok(votes)
    }
}
