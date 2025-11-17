use super::super::*;
use super::common::setup_test_state;
use felidae_types::transaction::{ChainId, Delay, Quorum, Timeout, Total};
use std::time::Duration;

#[tokio::test]
async fn test_pending_change_promotion() {
    let (store, initial_block_time) = setup_test_state().await;
    let mut state_guard = store.state.write().await;

    let delay = Duration::from_secs(86400); // We set 1 day
    let config = VotingConfig {
        total: Total(10),
        quorum: Quorum(3),
        timeout: Timeout(Duration::from_secs(3600)),
        delay: Delay(delay),
    };

    let mut vote_queue = VoteQueue::new(&mut *state_guard, "test_queue", config);

    // Cast quorum votes to create a pending change
    // Use a timestamp that's old enough (e.g., 2 days ago, as long as its greater than the delay we are good)
    let old_timestamp = initial_block_time.unix_timestamp() - (2 * 86400);
    let pending_time = Time::from_unix_timestamp(old_timestamp, 0).expect("valid timestamp");

    let key = ChainId("test_key".to_string());
    let value = ChainId("test_value".to_string());

    // Cast exactly quorum votes for the same key and value
    // Track the last vote time - this is what will be used as the pending change timestamp
    let mut last_vote_time = pending_time;
    for i in 0..3 {
        let vote_time = Time::from_unix_timestamp(pending_time.unix_timestamp() + i as i64, 0)
            .expect("valid timestamp");
        last_vote_time = vote_time;

        let vote = Vote {
            party: format!("party_{}", i),
            time: vote_time,
            key: key.clone(),
            value: value.clone(),
        };

        vote_queue.cast(vote).await.expect("cast vote failed");
    }

    // Verify pending change exists
    let pending = vote_queue
        .pending_for_key(key.clone())
        .await
        .expect("get pending failed");
    assert!(
        pending.is_some(),
        "should have pending change after quorum reached"
    );
    assert_eq!(
        pending.unwrap(),
        value.clone(),
        "pending value should match the voted value"
    );

    // Advance block time past the delay
    // The pending change was created with the timestamp of the last vote (last_vote_time),
    // so we need block_time > last_vote_time + delay
    let new_block_time = Time::from_unix_timestamp(
        last_vote_time.unix_timestamp() + delay.as_secs() as i64 + 1,
        0,
    )
    .expect("valid timestamp");

    state_guard
        .set_block_time(new_block_time)
        .await
        .expect("failed to set block time");

    // Recreate vote_queue (the previous one was dropped) to call promote_pending_changes()
    let config2 = VotingConfig {
        total: Total(10),
        quorum: Quorum(3),
        timeout: Timeout(Duration::from_secs(3600)),
        delay: Delay(delay),
    };
    let mut vote_queue: VoteQueue<'_, _, ChainId, ChainId> =
        VoteQueue::new(&mut *state_guard, "test_queue", config2);
    let promoted = vote_queue
        .promote_pending_changes()
        .await
        .expect("promote_pending_changes failed");

    // Verify it's returned
    assert_eq!(
        promoted.len(),
        1,
        "should return exactly one promoted change"
    );
    assert_eq!(promoted[0].0, key.clone(), "promoted key should match");
    assert_eq!(promoted[0].1, value.clone(), "promoted value should match");

    // Verify it's removed from pending queue
    let pending_after = vote_queue
        .pending_for_key(key.clone())
        .await
        .expect("get pending failed");
    assert!(
        pending_after.is_none(),
        "pending change should be removed after promotion"
    );
}

#[tokio::test]
async fn test_pending_change_overwriting() {
    let (store, initial_block_time) = setup_test_state().await;
    let mut state_guard = store.state.write().await;

    let delay = Duration::from_secs(86400); // 1 day delay
    let key = ChainId("test_key_overwrite".to_string());
    let value_a = ChainId("value_a".to_string());
    let value_b = ChainId("value_b".to_string());

    let old_timestamp = initial_block_time.unix_timestamp() - (2 * 86400);
    let base_time_a =
        Time::from_unix_timestamp(old_timestamp, 0).expect("valid timestamp for value A");
    let mut last_vote_time_a = base_time_a;

    // Create initial pending change for value A
    {
        let config = VotingConfig {
            total: Total(10),
            quorum: Quorum(3),
            timeout: Timeout(Duration::from_secs(3600)),
            delay: Delay(delay),
        };
        let mut vote_queue: VoteQueue<'_, _, ChainId, ChainId> =
            VoteQueue::new(&mut *state_guard, "test_queue", config);

        for i in 0..3 {
            let vote_time =
                Time::from_unix_timestamp(base_time_a.unix_timestamp() + i as i64, 0).unwrap();
            last_vote_time_a = vote_time;
            let vote = Vote {
                party: format!("party_a_{}", i),
                time: vote_time,
                key: key.clone(),
                value: value_a.clone(),
            };

            vote_queue.cast(vote).await.expect("cast vote A failed");
        }

        let pending_a = vote_queue
            .pending_for_key(key.clone())
            .await
            .expect("get pending failed");
        assert_eq!(
            pending_a,
            Some(value_a.clone()),
            "initial pending should be value A"
        );
    }

    // Advance block time so the initial pending would be promotable if not overwritten later
    let block_time_after_a = Time::from_unix_timestamp(
        last_vote_time_a.unix_timestamp() + delay.as_secs() as i64 + 5,
        0,
    )
    .expect("valid timestamp after value A quorum");
    state_guard
        .set_block_time(block_time_after_a)
        .await
        .expect("failed to set block time after value A");

    // Cast quorum votes for value B, which should overwrite the pending change
    let base_time_b =
        Time::from_unix_timestamp(last_vote_time_a.unix_timestamp() + 100, 0).unwrap();
    let mut last_vote_time_b = base_time_b;

    {
        let config_b = VotingConfig {
            total: Total(10),
            quorum: Quorum(3),
            timeout: Timeout(Duration::from_secs(3600)),
            delay: Delay(delay),
        };
        let mut vote_queue: VoteQueue<'_, _, ChainId, ChainId> =
            VoteQueue::new(&mut *state_guard, "test_queue", config_b);

        for i in 0..3 {
            let vote_time =
                Time::from_unix_timestamp(base_time_b.unix_timestamp() + i as i64, 0).unwrap();
            last_vote_time_b = vote_time;
            let vote = Vote {
                party: format!("party_b_{}", i),
                time: vote_time,
                key: key.clone(),
                value: value_b.clone(),
            };

            vote_queue.cast(vote).await.expect("cast vote B failed");
        }

        let pending_b = vote_queue
            .pending_for_key(key.clone())
            .await
            .expect("get pending failed after overwrite");
        assert_eq!(
            pending_b,
            Some(value_b.clone()),
            "pending change should now be value B"
        );
    }

    // Since block time is still only old_pending_time + delay + 5, the new pending should NOT promote yet
    {
        let config_promote = VotingConfig {
            total: Total(10),
            quorum: Quorum(3),
            timeout: Timeout(Duration::from_secs(3600)),
            delay: Delay(delay),
        };
        let mut vote_queue: VoteQueue<'_, _, ChainId, ChainId> =
            VoteQueue::new(&mut *state_guard, "test_queue", config_promote);
        let promoted_none = vote_queue
            .promote_pending_changes()
            .await
            .expect("promote pending (should be empty)");
        assert!(
            promoted_none.is_empty(),
            "new pending should not promote yet (delay reset)"
        );
    }

    // Now advance block time past the new pending delay and ensure it promotes
    let block_time_after_b = Time::from_unix_timestamp(
        last_vote_time_b.unix_timestamp() + delay.as_secs() as i64 + 1,
        0,
    )
    .expect("valid timestamp after value B quorum");
    state_guard
        .set_block_time(block_time_after_b)
        .await
        .expect("failed to set block time after value B");

    {
        let config_final = VotingConfig {
            total: Total(10),
            quorum: Quorum(3),
            timeout: Timeout(Duration::from_secs(3600)),
            delay: Delay(delay),
        };
        let mut vote_queue: VoteQueue<'_, _, ChainId, ChainId> =
            VoteQueue::new(&mut *state_guard, "test_queue", config_final);
        let promoted = vote_queue
            .promote_pending_changes()
            .await
            .expect("promote pending after delay");
        assert_eq!(
            promoted,
            vec![(key.clone(), value_b.clone())],
            "should promote the new pending value B"
        );
    }
}

#[tokio::test]
async fn test_pending_change_same_value_no_reset() {
    let (store, initial_block_time) = setup_test_state().await;
    let mut state_guard = store.state.write().await;

    let delay = Duration::from_secs(86400); // 1 day delay
    let key = ChainId("test_key_same_value".to_string());
    let value = ChainId("value_same".to_string());

    let old_timestamp = initial_block_time.unix_timestamp() - (2 * 86400);
    let base_time_initial =
        Time::from_unix_timestamp(old_timestamp, 0).expect("valid timestamp for initial pending");
    let mut last_vote_time_initial = base_time_initial;

    // Create initial pending change
    {
        let config = VotingConfig {
            total: Total(10),
            quorum: Quorum(3),
            timeout: Timeout(Duration::from_secs(3600)),
            delay: Delay(delay),
        };
        let mut vote_queue: VoteQueue<'_, _, ChainId, ChainId> =
            VoteQueue::new(&mut *state_guard, "test_queue", config);

        for i in 0..3 {
            let vote_time =
                Time::from_unix_timestamp(base_time_initial.unix_timestamp() + i as i64, 0)
                    .unwrap();
            last_vote_time_initial = vote_time;
            let vote = Vote {
                party: format!("party_initial_{}", i),
                time: vote_time,
                key: key.clone(),
                value: value.clone(),
            };

            vote_queue
                .cast(vote)
                .await
                .expect("cast initial vote failed");
        }

        let pending_initial = vote_queue
            .pending_for_key(key.clone())
            .await
            .expect("get pending failed");
        assert_eq!(
            pending_initial,
            Some(value.clone()),
            "initial pending should be set"
        );
    }

    // Advance block time so the initial pending would be promotable if timer wasn't reset
    let block_time_near_promotion = Time::from_unix_timestamp(
        last_vote_time_initial.unix_timestamp() + delay.as_secs() as i64 - 10,
        0,
    )
    .expect("valid timestamp near promotion");
    state_guard
        .set_block_time(block_time_near_promotion)
        .await
        .expect("failed to set block time near promotion");

    // Cast quorum votes for the SAME value, which should NOT reset the timer
    let base_time_second =
        Time::from_unix_timestamp(last_vote_time_initial.unix_timestamp() + 100, 0).unwrap();
    let mut last_vote_time_second = base_time_second;

    {
        let config_second = VotingConfig {
            total: Total(10),
            quorum: Quorum(3),
            timeout: Timeout(Duration::from_secs(3600)),
            delay: Delay(delay),
        };
        let mut vote_queue: VoteQueue<'_, _, ChainId, ChainId> =
            VoteQueue::new(&mut *state_guard, "test_queue", config_second);

        for i in 0..3 {
            let vote_time =
                Time::from_unix_timestamp(base_time_second.unix_timestamp() + i as i64, 0).unwrap();
            last_vote_time_second = vote_time;
            let vote = Vote {
                party: format!("party_second_{}", i),
                time: vote_time,
                key: key.clone(),
                value: value.clone(), // Same value
            };

            vote_queue
                .cast(vote)
                .await
                .expect("cast second vote failed");
        }

        // Verify the pending change still exists with the same value
        let pending_after = vote_queue
            .pending_for_key(key.clone())
            .await
            .expect("get pending failed after same-value quorum");
        assert_eq!(
            pending_after,
            Some(value.clone()),
            "pending change should still exist with same value"
        );
    }

    // Verify the timer was NOT reset: the pending change should still be promotable
    // based on the original timestamp, not the new one
    let block_time_after_original_delay = Time::from_unix_timestamp(
        last_vote_time_initial.unix_timestamp() + delay.as_secs() as i64 + 1,
        0,
    )
    .expect("valid timestamp after original delay");
    // This should be BEFORE the second delay would expire
    assert!(
        block_time_after_original_delay.unix_timestamp()
            < last_vote_time_second.unix_timestamp() + delay.as_secs() as i64,
        "original delay should expire before second delay would"
    );

    state_guard
        .set_block_time(block_time_after_original_delay)
        .await
        .expect("failed to set block time after original delay");

    {
        let config_promote = VotingConfig {
            total: Total(10),
            quorum: Quorum(3),
            timeout: Timeout(Duration::from_secs(3600)),
            delay: Delay(delay),
        };
        let mut vote_queue: VoteQueue<'_, _, ChainId, ChainId> =
            VoteQueue::new(&mut *state_guard, "test_queue", config_promote);
        let promoted = vote_queue
            .promote_pending_changes()
            .await
            .expect("promote pending should succeed");
        assert_eq!(
            promoted,
            vec![(key.clone(), value.clone())],
            "should promote based on original timestamp, not reset timer"
        );
    }
}

#[tokio::test]
async fn test_multiple_pending_changes_partial_promotion() {
    let (store, initial_block_time) = setup_test_state().await;
    let mut state_guard = store.state.write().await;

    let delay = Duration::from_secs(86400);
    let key_a = ChainId("key_a".to_string());
    let key_b = ChainId("key_b".to_string());
    let value_a = ChainId("value_a".to_string());
    let value_b = ChainId("value_b".to_string());

    let old_timestamp = initial_block_time.unix_timestamp() - (3 * 86400);
    let base_time_a =
        Time::from_unix_timestamp(old_timestamp, 0).expect("valid timestamp for key A");
    let base_time_b =
        Time::from_unix_timestamp(old_timestamp + 2 * 86400, 0).expect("valid timestamp for key B");
    let mut last_vote_time_a = base_time_a;
    let mut last_vote_time_b = base_time_b;

    let make_config = || VotingConfig {
        total: Total(10),
        quorum: Quorum(3),
        timeout: Timeout(Duration::from_secs(3600)),
        delay: Delay(delay),
    };
    {
        let mut vote_queue = VoteQueue::new(&mut *state_guard, "test_queue", make_config());

        for i in 0..3 {
            let vote_time = Time::from_unix_timestamp(base_time_a.unix_timestamp() + i as i64, 0)
                .expect("valid timestamp");
            last_vote_time_a = vote_time;
            vote_queue
                .cast(Vote {
                    party: format!("party_a_{i}"),
                    time: vote_time,
                    key: key_a.clone(),
                    value: value_a.clone(),
                })
                .await
                .expect("cast vote for key A");
        }

        for i in 0..3 {
            let vote_time = Time::from_unix_timestamp(base_time_b.unix_timestamp() + i as i64, 0)
                .expect("valid timestamp");
            last_vote_time_b = vote_time;
            vote_queue
                .cast(Vote {
                    party: format!("party_b_{i}"),
                    time: vote_time,
                    key: key_b.clone(),
                    value: value_b.clone(),
                })
                .await
                .expect("cast vote for key B");
        }

        for (key, expected) in [
            (key_a.clone(), value_a.clone()),
            (key_b.clone(), value_b.clone()),
        ] {
            let pending = vote_queue
                .pending_for_key(key.clone())
                .await
                .expect("get pending failed");
            assert_eq!(
                pending,
                Some(expected),
                "pending value should exist for {key:?}"
            );
        }
    }

    // Advance block time so only key A should be promotable.
    let block_time_after_a = Time::from_unix_timestamp(
        last_vote_time_a.unix_timestamp() + delay.as_secs() as i64 + 1,
        0,
    )
    .expect("valid timestamp after key A");
    assert!(
        block_time_after_a.unix_timestamp()
            < last_vote_time_b.unix_timestamp() + delay.as_secs() as i64,
        "key B should still be waiting"
    );
    state_guard
        .set_block_time(block_time_after_a)
        .await
        .expect("failed to set block time after key A");

    {
        let mut vote_queue = VoteQueue::new(&mut *state_guard, "test_queue", make_config());
        let promoted = vote_queue
            .promote_pending_changes()
            .await
            .expect("promote pending (first)");
        assert_eq!(
            promoted,
            vec![(key_a.clone(), value_a.clone())],
            "only key A should have promoted"
        );

        let pending_a = vote_queue
            .pending_for_key(key_a.clone())
            .await
            .expect("get pending A failed");
        assert!(
            pending_a.is_none(),
            "key A pending should be cleared after promotion"
        );

        let pending_b = vote_queue
            .pending_for_key(key_b.clone())
            .await
            .expect("get pending B failed");
        assert_eq!(
            pending_b,
            Some(value_b.clone()),
            "key B pending should remain"
        );
    }

    // Now advance block time so key B becomes promotable.
    let block_time_after_b = Time::from_unix_timestamp(
        last_vote_time_b.unix_timestamp() + delay.as_secs() as i64 + 1,
        0,
    )
    .expect("valid timestamp after key B");
    state_guard
        .set_block_time(block_time_after_b)
        .await
        .expect("failed to set block time after key B");

    {
        let mut vote_queue = VoteQueue::new(&mut *state_guard, "test_queue", make_config());
        let promoted = vote_queue
            .promote_pending_changes()
            .await
            .expect("promote pending (second)");
        assert_eq!(
            promoted,
            vec![(key_b.clone(), value_b.clone())],
            "key B should promote after delay"
        );
    }
}

#[tokio::test]
async fn test_pending_for_key_none() {
    let (store, _) = setup_test_state().await;
    let mut state_guard = store.state.write().await;

    let config = VotingConfig {
        total: Total(10),
        quorum: Quorum(3),
        timeout: Timeout(Duration::from_secs(3600)),
        delay: Delay(Duration::from_secs(86400)),
    };

    let vote_queue: VoteQueue<'_, _, ChainId, ChainId> =
        VoteQueue::new(&mut *state_guard, "test_queue", config);
    let pending = vote_queue
        .pending_for_key(ChainId("key_query_none".to_string()))
        .await
        .expect("pending_for_key with no entries should succeed");
    assert!(
        pending.is_none(),
        "should return None when no pending change exists"
    );
}

#[tokio::test]
async fn test_pending_for_key_single_entry() {
    let (store, initial_block_time) = setup_test_state().await;
    let mut state_guard = store.state.write().await;

    let config = VotingConfig {
        total: Total(10),
        quorum: Quorum(3),
        timeout: Timeout(Duration::from_secs(3600)),
        delay: Delay(Duration::from_secs(86400)),
    };

    let key = ChainId("key_query_single".to_string());
    let value = ChainId("value_query_single".to_string());

    let mut vote_queue: VoteQueue<'_, _, ChainId, ChainId> =
        VoteQueue::new(&mut *state_guard, "test_queue", config);
    for i in 0..3 {
        let vote_time =
            Time::from_unix_timestamp(initial_block_time.unix_timestamp() + i as i64, 0)
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

    let pending = vote_queue
        .pending_for_key(key)
        .await
        .expect("pending_for_key with single entry should succeed");
    assert_eq!(
        pending,
        Some(value),
        "pending change should return the stored value"
    );
}

#[tokio::test]
async fn test_pending_for_key_multiple_entries_error() {
    use crate::store::Substore::Internal;

    let (store, initial_block_time) = setup_test_state().await;
    let mut state_guard = store.state.write().await;

    let make_config = || VotingConfig {
        total: Total(10),
        quorum: Quorum(3),
        timeout: Timeout(Duration::from_secs(3600)),
        delay: Delay(Duration::from_secs(86400)),
    };

    let key = ChainId("key_query_duplicate".to_string());
    let value = ChainId("value_query_duplicate".to_string());

    let mut vote_queue: VoteQueue<'_, _, ChainId, ChainId> =
        VoteQueue::new(&mut *state_guard, "test_queue", make_config());
    let mut last_vote_time = initial_block_time;
    for i in 0..3 {
        let vote_time =
            Time::from_unix_timestamp(initial_block_time.unix_timestamp() + i as i64, 0)
                .expect("valid timestamp");
        last_vote_time = vote_time;
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

    // Manually insert a duplicate pending entry for the same key to trigger the error path.
    let duplicate_time = Time::from_unix_timestamp(last_vote_time.unix_timestamp() + 10, 0)
        .expect("valid duplicate timestamp");
    let key_str: String = key.clone().into();

    let pending_key = format!(
        "test_queue/pending_by_key/{}/{}",
        key_str,
        duplicate_time.to_rfc3339()
    );
    state_guard.store.put(Internal, &pending_key, value.clone());

    let mut index_key = b"test_queue/pending_by_timestamp/".to_vec();
    index_key.extend_from_slice(&duplicate_time.unix_timestamp().to_be_bytes());
    index_key.push(b'/');
    index_key.extend_from_slice(key_str.as_bytes());
    state_guard
        .store
        .index_put(Internal, &index_key, value.clone());

    let vote_queue: VoteQueue<'_, _, ChainId, ChainId> =
        VoteQueue::new(&mut *state_guard, "test_queue", make_config());
    let err = vote_queue
        .pending_for_key(key)
        .await
        .expect_err("should error when multiple pending changes exist");
    assert!(
        err.to_string().contains("multiple pending changes"),
        "error message should mention duplicate pending entries"
    );
}
