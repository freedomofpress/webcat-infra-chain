use super::super::*;
use super::common::setup_test_state;
use crate::store::Substore::Internal;
use felidae_types::transaction::{ChainId, Delay, Quorum, Timeout, Total};
use futures::TryStreamExt;
use std::time::Duration;

#[test]
fn test_vote_expiration_removes_votes_and_indexes() {
    let rt = tokio::runtime::Runtime::new().expect("runtime");
    rt.block_on(async {
        let (store, initial_block_time) = setup_test_state().await;
        let mut state_guard = store.state.write().await;

        let timeout = Duration::from_secs(3600);
        let make_config = || VotingConfig {
            total: Total(10),
            quorum: Quorum(2),
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
    });
}
