use super::super::*;
use super::common::setup_test_state;
use crate::store::Substore::Internal;
use felidae_types::transaction::{ChainId, Delay, Quorum, Timeout, Total};
use futures::TryStreamExt;
use std::time::Duration;

#[tokio::test]
async fn test_vote_expiration_removes_votes_and_indexes() {
    let (store, initial_block_time) = setup_test_state().await;
    let mut state_guard = store.state.write().await;

    let timeout = Duration::from_secs(3600);
    // Use quorum equal to total so that the test votes never reach quorum (and thus remain in the vote queue).
    let make_config = || VotingConfig {
        total: Total(10),
        quorum: Quorum(10),
        timeout: Timeout(timeout),
        delay: Delay(Duration::from_secs(86400)),
    };

    let key = ChainId("key_expiration".to_string());
    let value = ChainId("value_expiration".to_string());

    // Cast a bunch of votes with timestamps old enough to expire
    {
        let mut vote_queue: VoteQueue<'_, _, ChainId, ChainId> =
            VoteQueue::new(&mut *state_guard, "test_queue", make_config());
        for i in 0..3 {
            let vote_time = Time::from_unix_timestamp(
                initial_block_time.unix_timestamp() - timeout.as_secs() as i64 - 100 - i as i64,
                0,
            )
            .expect("valid timestamp");
            vote_queue
                .cast(Vote {
                    party: format!("party_{i}"),
                    time: vote_time,
                    key: key.clone(),
                    value: value.clone(),
                })
                .await
                .expect("cast vote");
        }

        let votes_before = vote_queue
            .votes_for_key(key.clone())
            .await
            .expect("get votes before timeout");
        assert_eq!(
            votes_before.len(),
            3,
            "should have three votes before timeout"
        );
    }

    // Now shift current block time to be sufficiently ahead of the old vote timestamps
    let block_time_after_timeout =
        Time::from_unix_timestamp(initial_block_time.unix_timestamp() + 1, 0)
            .expect("valid block time after timeout");
    state_guard
        .set_block_time(block_time_after_timeout)
        .await
        .expect("failed to advance block time");

    {
        // And now we can check that the votes get expired as we expect.
        let mut vote_queue: VoteQueue<'_, _, ChainId, ChainId> =
            VoteQueue::new(&mut *state_guard, "test_queue", make_config());
        vote_queue
            .timeout_expired_votes()
            .await
            .expect("timeout_expired_votes should succeed");

        let votes_after = vote_queue
            .votes_for_key(key.clone())
            .await
            .expect("get votes after timeout");
        assert!(
            votes_after.is_empty(),
            "expired votes should be removed from the primary storage"
        );
    }

    // Verify the timestamp index is also cleared.
    let remaining_index_entries = state_guard
        .store
        .index_prefix::<()>(Internal, b"test_queue/votes_by_timestamp/")
        .try_collect::<Vec<_>>()
        .await
        .expect("collect remaining index entries");
    assert!(
        remaining_index_entries.is_empty(),
        "expired votes should be removed from the timestamp index"
    );
}

#[tokio::test]
async fn test_vote_expiration_boundary_behavior() {
    let (store, initial_block_time) = setup_test_state().await;
    let mut state_guard = store.state.write().await;

    let timeout = Duration::from_secs(3600);
    let make_config = || VotingConfig {
        total: Total(10),
        quorum: Quorum(10), // Prevent promotion
        timeout: Timeout(timeout),
        delay: Delay(Duration::from_secs(86400)),
    };

    let key = ChainId("key_boundary".to_string());
    let value_old = ChainId("value_old".to_string());
    let value_new = ChainId("value_new".to_string());

    {
        let mut vote_queue: VoteQueue<'_, _, ChainId, ChainId> =
            VoteQueue::new(&mut *state_guard, "test_queue", make_config());

        // Vote exactly at the timeout boundary.
        let boundary_time = Time::from_unix_timestamp(
            initial_block_time.unix_timestamp() - timeout.as_secs() as i64,
            0,
        )
        .expect("valid boundary timestamp");
        vote_queue
            .cast(Vote {
                party: "boundary_party".to_string(),
                time: boundary_time,
                key: key.clone(),
                value: value_old.clone(),
            })
            .await
            .expect("cast boundary vote");

        // Slightly newer vote that should remain after timeout.
        let newer_time = Time::from_unix_timestamp(
            initial_block_time.unix_timestamp() - timeout.as_secs() as i64 + 10,
            0,
        )
        .expect("valid newer timestamp");
        vote_queue
            .cast(Vote {
                party: "newer_party".to_string(),
                time: newer_time,
                key: key.clone(),
                value: value_new.clone(),
            })
            .await
            .expect("cast newer vote");
    }

    // Set current block time to initial_block_time (same as setup), so the boundary vote is exactly timeout seconds old.
    {
        let mut vote_queue: VoteQueue<'_, _, ChainId, ChainId> =
            VoteQueue::new(&mut *state_guard, "test_queue", make_config());

        vote_queue
            .timeout_expired_votes()
            .await
            .expect("timeout_expired_votes should succeed");

        let votes = vote_queue
            .votes_for_key(key.clone())
            .await
            .expect("get votes after boundary check");

        assert_eq!(
            votes.len(),
            1,
            "only the newer vote should remain when at the timeout boundary"
        );
        assert_eq!(
            votes[0].value.clone(),
            value_new,
            "newer vote should be retained"
        );
    }
}

#[tokio::test]
async fn test_delay_boundary_behavior() {
    let (store, initial_block_time) = setup_test_state().await;
    let mut state_guard = store.state.write().await;

    let delay = Duration::from_secs(86400);
    let make_config = || VotingConfig {
        total: Total(10),
        quorum: Quorum(3),
        timeout: Timeout(Duration::from_secs(3600)),
        delay: Delay(delay),
    };

    let key = ChainId("key_delay_boundary".to_string());
    let value = ChainId("value_delay_boundary".to_string());

    {
        let mut vote_queue: VoteQueue<'_, _, ChainId, ChainId> =
            VoteQueue::new(&mut *state_guard, "test_queue", make_config());

        // Create a pending change exactly at the delay boundary.
        // The pending change timestamp is set to the vote that triggers quorum (the last vote).
        // We want the last vote to be exactly `delay` seconds before the current block time.
        let boundary_time = Time::from_unix_timestamp(
            initial_block_time.unix_timestamp() - delay.as_secs() as i64,
            0,
        )
        .expect("valid boundary timestamp");

        // Cast quorum votes, with the last vote (i=2) at the boundary time
        for i in 0..3 {
            let vote_time = if i == 2 {
                boundary_time // Last vote at boundary
            } else {
                Time::from_unix_timestamp(boundary_time.unix_timestamp() - 10 + i as i64, 0)
                    .expect("valid timestamp")
            };
            vote_queue
                .cast(Vote {
                    party: format!("party_{i}"),
                    time: vote_time,
                    key: key.clone(),
                    value: value.clone(),
                })
                .await
                .expect("cast vote");
        }

        // Verify pending change exists
        let pending = vote_queue
            .pending_for_key(key.clone())
            .await
            .expect("get pending should succeed");
        assert!(
            pending.is_some(),
            "should have pending change after quorum reached"
        );
    }

    // Set current block time to initial_block_time (same as setup), so the pending change is exactly delay seconds old.
    {
        let mut vote_queue: VoteQueue<'_, _, ChainId, ChainId> =
            VoteQueue::new(&mut *state_guard, "test_queue", make_config());

        let promoted = vote_queue
            .promote_pending_changes()
            .await
            .expect("promote_pending_changes should succeed");

        // The pending change at the boundary should be promoted once the delay has elapsed
        assert_eq!(
            promoted.len(),
            1,
            "pending change at the delay boundary should be promoted when delay has elapsed"
        );
        assert_eq!(promoted[0].0, key.clone(), "promoted key should match");
        assert_eq!(promoted[0].1, value.clone(), "promoted value should match");

        // Verify it's removed from the pending queue
        let pending = vote_queue
            .pending_for_key(key.clone())
            .await
            .expect("get pending after boundary check should succeed");
        assert!(
            pending.is_none(),
            "boundary pending change should be removed after promotion"
        );
    }
}
