use super::*;
use crate::store::Store;
use felidae_types::transaction::{ChainId, Delay, Quorum, Timeout, Total};
use std::time::Duration;
use tempfile::TempDir;

use proptest::prelude::*;

/// Helper function to set up a test state with block height and time configured
async fn setup_test_state() -> (Store, Time) {
    let temp_dir = TempDir::new().expect("failed to create temp dir");
    let store = Store::init(temp_dir.path().to_path_buf())
        .await
        .expect("failed to create store");

    let mut state_guard = store.state.write().await;

    // Set block height first (required before setting block time)
    use tendermint::block::Height;
    state_guard
        .set_block_height(Height::from(1u32))
        .await
        .expect("failed to set block height");

    // Set block time so timeout_expired_votes and promote_pending_changes work
    // Note: vote times are truncated to seconds when stored, so we truncate here too
    let block_time =
        Time::from_unix_timestamp(Time::now().unix_timestamp(), 0).expect("valid timestamp");
    state_guard
        .set_block_time(block_time)
        .await
        .expect("failed to set block time");

    drop(state_guard); // Release the lock

    (store, block_time)
}

#[test]
fn proptest_single_vote_cast_and_retrieval_below_quorum() {
    let config = proptest::test_runner::Config {
        cases: 100, // Limit to 100 test cases
        ..Default::default()
    };
    proptest!(config, |(
        total in 1u64..=100u64,
        quorum in 1u64..=100u64,
        key in "[a-zA-Z0-9_]+",
        value in "[a-zA-Z0-9_]+",
        party in "[a-zA-Z0-9_]+",
    )| {
        // Ensure quorum < total and quorum > 1 (so single vote doesn't reach quorum)
        let total = total.max(3); // Need at least 3 for quorum < total and quorum > 1
        let quorum = quorum.min(total.saturating_sub(1)).max(2); // quorum must be at least 2

        let rt = tokio::runtime::Runtime::new().expect("runtime");
        rt.block_on(async {
            let (store, block_time) = setup_test_state().await;
            let mut state_guard = store.state.write().await;

            let config = VotingConfig {
                total: Total(total),
                quorum: Quorum(quorum),
                timeout: Timeout(Duration::from_secs(3600)),
                delay: Delay(Duration::from_secs(86400)),
            };

            let mut vote_queue = VoteQueue::new(&mut *state_guard, "test_queue", config);

            let vote = Vote {
                party: party.clone(),
                time: block_time,
                key: ChainId(key.clone()),
                value: ChainId(value.clone()),
            };

            vote_queue
                .cast(vote.clone())
                .await
                .map_err(|e| proptest::test_runner::TestCaseError::fail(format!("cast failed: {e}")))?;

            // Property: After casting a vote, it should be retrievable
            let votes = vote_queue
                .votes_for_key(ChainId(key.clone()))
                .await
                .map_err(|e| proptest::test_runner::TestCaseError::fail(format!("get votes failed: {e}")))?;

            prop_assert_eq!(votes.len(), 1, "should have exactly one vote");
            prop_assert_eq!(votes[0].party.clone(), party.clone());
            prop_assert_eq!(votes[0].key.clone(), ChainId(key.clone()));
            prop_assert_eq!(votes[0].value.clone(), ChainId(value.clone()));
            prop_assert_eq!(votes[0].time, block_time);

            // Property: Vote should also be retrievable via prefix query
            let votes_by_prefix = vote_queue
                .votes_for_key_prefix(ChainId(key.clone()), None)
                .await
                .map_err(|e| proptest::test_runner::TestCaseError::fail(format!("get votes by prefix failed: {e}")))?;

            prop_assert_eq!(votes_by_prefix.len(), 1, "should find vote via key prefix");
            prop_assert_eq!(votes_by_prefix[0].party.clone(), party.clone());
            prop_assert_eq!(votes_by_prefix[0].value.clone(), ChainId(value.clone()));

            Ok(())
        })?;
    });
}

#[test]
fn proptest_vote_replacement() {
    let config = proptest::test_runner::Config {
        cases: 100, // Limit to 100 test cases
        ..Default::default()
    };
    proptest!(config, |(
        total in 3u64..=100u64,
        quorum in 2u64..=100u64,
        key in "[a-zA-Z0-9_]+",
        value1 in "[a-zA-Z0-9_]+",
        value2 in "[a-zA-Z0-9_]+",
        party in "[a-zA-Z0-9_]+",
    )| {
        // Ensure value1 != value2
        if value1 == value2 {
            return Ok(());
        }

        // Ensure quorum < total and quorum > 1 (so single vote doesn't reach quorum)
        let total = total.max(3);
        let quorum = quorum.min(total.saturating_sub(1)).max(2);

        let rt = tokio::runtime::Runtime::new().expect("runtime");
        rt.block_on(async {
            let (store, block_time) = setup_test_state().await;
            let mut state_guard = store.state.write().await;

            let config = VotingConfig {
                total: Total(total),
                quorum: Quorum(quorum),
                timeout: Timeout(Duration::from_secs(3600)),
                delay: Delay(Duration::from_secs(86400)),
            };

            let mut vote_queue = VoteQueue::new(&mut *state_guard, "test_queue", config);

            // Cast first vote
            let vote1 = Vote {
                party: party.clone(),
                time: block_time,
                key: ChainId(key.clone()),
                value: ChainId(value1.clone()),
            };

            vote_queue
                .cast(vote1.clone())
                .await
                .map_err(|e| proptest::test_runner::TestCaseError::fail(format!("cast first vote failed: {e}")))?;

            // Cast second vote with same party and key, but different value
            // Use a slightly later time to ensure it's the "latest" vote
            let vote2_time = Time::from_unix_timestamp(
                block_time.unix_timestamp() + 1,
                0,
            ).expect("valid timestamp");

            let vote2 = Vote {
                party: party.clone(),
                time: vote2_time,
                key: ChainId(key.clone()),
                value: ChainId(value2.clone()),
            };

            vote_queue
                .cast(vote2.clone())
                .await
                .map_err(|e| proptest::test_runner::TestCaseError::fail(format!("cast second vote failed: {e}")))?;

            // Property: Only the latest vote should exist
            let votes = vote_queue
                .votes_for_key(ChainId(key.clone()))
                .await
                .map_err(|e| proptest::test_runner::TestCaseError::fail(format!("get votes failed: {e}")))?;

            prop_assert_eq!(votes.len(), 1, "should have exactly one vote after replacement");
            prop_assert_eq!(votes[0].party.clone(), party.clone());
            prop_assert_eq!(votes[0].key.clone(), ChainId(key.clone()));
            prop_assert_eq!(votes[0].value.clone(), ChainId(value2.clone()), "should have the second vote's value");
            prop_assert_eq!(votes[0].time, vote2_time, "should have the second vote's time");

            // Property: Verify via prefix query as well
            let votes_by_prefix = vote_queue
                .votes_for_key_prefix(ChainId(key.clone()), None)
                .await
                .map_err(|e| proptest::test_runner::TestCaseError::fail(format!("get votes by prefix failed: {e}")))?;

            prop_assert_eq!(votes_by_prefix.len(), 1, "should find exactly one vote via key prefix");
            prop_assert_eq!(votes_by_prefix[0].party.clone(), party.clone());
            prop_assert_eq!(votes_by_prefix[0].value.clone(), ChainId(value2.clone()), "prefix query should return second vote's value");

            Ok(())
        })?;
    });
}

#[test]
fn proptest_multiple_parties_voting() {
    let config = proptest::test_runner::Config {
        cases: 100, // Limit to 100 test cases
        ..Default::default()
    };
    proptest!(config, |(
        total in 3u64..=100u64,
        quorum in 2u64..=100u64,
        key in "[a-zA-Z0-9_]+",
        value in "[a-zA-Z0-9_]+",
        parties in proptest::collection::vec("[a-zA-Z0-9_]+", 2..=20), // 2 to 20 parties
    )| {
        // Ensure quorum is high enough that multiple votes won't immediately reach quorum
        // This allows us to verify all votes are present before promotion
        let total = total.max(3);
        let quorum = quorum.min(total.saturating_sub(1)).max(parties.len() as u64 + 1); // quorum > number of parties

        // Ensure all parties are unique (or at least handle duplicates)
        // For simplicity, we'll just proceed and count unique parties
        let unique_parties: std::collections::HashSet<_> = parties.iter().collect();
        let num_unique_parties = unique_parties.len();

        let rt = tokio::runtime::Runtime::new().expect("runtime");
        rt.block_on(async {
            let (store, block_time) = setup_test_state().await;
            let mut state_guard = store.state.write().await;

            let config = VotingConfig {
                total: Total(total),
                quorum: Quorum(quorum),
                timeout: Timeout(Duration::from_secs(3600)),
                delay: Delay(Duration::from_secs(86400)),
            };

            let mut vote_queue = VoteQueue::new(&mut *state_guard, "test_queue", config);

            // Cast votes from all parties for the same key and value
            // Use slightly different times to ensure uniqueness
            for (i, party) in parties.iter().enumerate() {
                let vote_time = Time::from_unix_timestamp(
                    block_time.unix_timestamp() + i as i64,
                    0,
                ).expect("valid timestamp");

                let vote = Vote {
                    party: party.clone(),
                    time: vote_time,
                    key: ChainId(key.clone()),
                    value: ChainId(value.clone()),
                };

                vote_queue
                    .cast(vote)
                    .await
                    .map_err(|e| proptest::test_runner::TestCaseError::fail(format!("cast vote from party {} failed: {e}", party)))?;
            }

            // Property: All votes should be present
            let votes = vote_queue
                .votes_for_key(ChainId(key.clone()))
                .await
                .map_err(|e| proptest::test_runner::TestCaseError::fail(format!("get votes failed: {e}")))?;

            // If parties had duplicates, we expect only unique party votes
            // (since same party voting twice replaces the first vote)
            prop_assert_eq!(
                votes.len(),
                num_unique_parties,
                "should have exactly {} votes (one per unique party)",
                num_unique_parties
            );

            // Property: All votes should have the same key and value
            for vote in &votes {
                prop_assert_eq!(vote.key.clone(), ChainId(key.clone()), "all votes should have the same key");
                prop_assert_eq!(vote.value.clone(), ChainId(value.clone()), "all votes should have the same value");
            }

            // Property: Verify vote counts by value
            let votes_by_value: std::collections::HashMap<_, _> = votes
                .iter()
                .fold(std::collections::HashMap::new(), |mut acc, vote| {
                    *acc.entry(vote.value.clone()).or_insert(0) += 1;
                    acc
                });

            prop_assert_eq!(
                votes_by_value.len(),
                1,
                "should have votes for exactly one value"
            );
            prop_assert_eq!(
                votes_by_value.get(&ChainId(value.clone())).copied().unwrap_or(0),
                num_unique_parties,
                "should have {} votes for the expected value",
                num_unique_parties
            );

            // Property: Verify all unique parties are represented
            let vote_parties: std::collections::HashSet<_> = votes.iter().map(|v| &v.party).collect();
            prop_assert_eq!(
                vote_parties.len(),
                num_unique_parties,
                "should have votes from {} unique parties",
                num_unique_parties
            );

            // Property: Verify via prefix query as well
            let votes_by_prefix = vote_queue
                .votes_for_key_prefix(ChainId(key.clone()), None)
                .await
                .map_err(|e| proptest::test_runner::TestCaseError::fail(format!("get votes by prefix failed: {e}")))?;

            prop_assert_eq!(
                votes_by_prefix.len(),
                num_unique_parties,
                "prefix query should return {} votes",
                num_unique_parties
            );

            // All prefix query results should have the same value
            for vote in &votes_by_prefix {
                prop_assert_eq!(vote.value.clone(), ChainId(value.clone()), "prefix query votes should all have the same value");
            }

            Ok(())
        })?;
    });
}
