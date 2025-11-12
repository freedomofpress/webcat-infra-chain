use super::super::*;
use super::common::setup_test_state;
use felidae_types::transaction::{ChainId, Delay, Quorum, Timeout, Total};
use std::time::Duration;

use proptest::prelude::*;

#[test]
fn proptest_quorum_reached_exactly() {
    let config = proptest::test_runner::Config {
        cases: 100, // Limit to 100 test cases
        ..Default::default()
    };
    proptest!(config, |(
        total in 2u64..=100u64,
        quorum in 2u64..=100u64,
        key in "[a-zA-Z0-9_]+",
        value in "[a-zA-Z0-9_]+",
    )| {
        // Ensure quorum <= total and quorum >= 2
        let total = total.max(2);
        let quorum = quorum.min(total).max(2);

        // Generate exactly quorum number of unique parties
        // We generate parties and take unique ones until we have quorum
        let mut parties = Vec::new();
        let mut party_counter = 0u64;
        while parties.len() < quorum as usize {
            parties.push(format!("party_{}", party_counter));
            party_counter += 1;
        }

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

            // Cast exactly quorum votes for the same key and value
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

            // Property: Value should now be in the pending queue
            let pending = vote_queue
                .pending_for_key(ChainId(key.clone()))
                .await
                .map_err(|e| proptest::test_runner::TestCaseError::fail(format!("get pending failed: {e}")))?;

            prop_assert!(
                pending.is_some(),
                "should have pending change after quorum reached"
            );
            prop_assert_eq!(
                pending.unwrap(),
                ChainId(value.clone()),
                "pending value should match the voted value"
            );

            // Property: All votes should be deleted (no votes remain)
            let votes = vote_queue
                .votes_for_key(ChainId(key.clone()))
                .await
                .map_err(|e| proptest::test_runner::TestCaseError::fail(format!("get votes failed: {e}")))?;

            prop_assert_eq!(
                votes.len(),
                0,
                "all votes should be deleted after quorum reached"
            );

            Ok(())
        })?;
    });
}

#[test]
fn proptest_quorum_exceeded() {
    let config = proptest::test_runner::Config {
        cases: 100, // Limit to 100 test cases
        ..Default::default()
    };
    proptest!(config, |(
        total in 2u64..=100u64,
        quorum in 2u64..=100u64,
        extra_votes in 1u64..=5u64,
        key in "[a-zA-Z0-9_]+",
        value in "[a-zA-Z0-9_]+",
    )| {
        // Ensure quorum <= total and quorum >= 2
        let quorum = quorum.max(2);
        let votes_needed = quorum + extra_votes;
        let total = total.max(votes_needed).max(quorum);

        // Generate exactly votes_needed unique parties
        let mut parties = Vec::new();
        let mut party_counter = 0u64;
        while parties.len() < votes_needed as usize {
            parties.push(format!("party_{}", party_counter));
            party_counter += 1;
        }

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

            // Cast votes_needed votes for the same key and value
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

            // Property: Value should be in pending queue
            let pending = vote_queue
                .pending_for_key(ChainId(key.clone()))
                .await
                .map_err(|e| proptest::test_runner::TestCaseError::fail(format!("get pending failed: {e}")))?;

            prop_assert!(
                pending.is_some(),
                "should have pending change after quorum exceeded"
            );
            prop_assert_eq!(
                pending.unwrap(),
                ChainId(value.clone()),
                "pending value should match the voted value"
            );

            // Property: No quorum remains outstanding (fewer than quorum votes left)
            let votes = vote_queue
                .votes_for_key(ChainId(key.clone()))
                .await
                .map_err(|e| proptest::test_runner::TestCaseError::fail(format!("get votes failed: {e}")))?;

            prop_assert_eq!(
                votes.len() < quorum as usize,
                true,
                "after exceeding quorum, fewer than quorum votes should remain"
            );
            // Note that in a real case these stale votes would get evicted by the timeout mechanism

            Ok(())
        })?;
    });
}

#[test]
fn proptest_multiple_values_competing() {
    let config = proptest::test_runner::Config {
        cases: 100, // Limit to 100 test cases
        ..Default::default()
    };
    proptest!(config, |(
        total in 3u64..=100u64,
        quorum in 2u64..=100u64,
        key in "[a-zA-Z0-9_]+",
        value_primary in "[a-zA-Z0-9_]+",
        value_other in "[a-zA-Z0-9_]+",
        pre_votes_primary in 0u64..=10u64,
        pre_votes_other in 0u64..=10u64,
    )| {
        if value_primary == value_other {
            return Ok(());
        }

        let quorum = quorum.min(total).max(2);
        let mut pre_primary = pre_votes_primary.min(quorum.saturating_sub(1));
        let pre_other = pre_votes_other.min(quorum.saturating_sub(1));

        if pre_primary + pre_other == 0 {
            pre_primary = 1;
        }

        let extra_needed = quorum.saturating_sub(pre_primary).max(1);
        if pre_primary + pre_other + extra_needed > total {
            return Ok(());
        }

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

            let mut party_counter = 0u64;
            let mut next_party = || {
                let name = format!("party_{}", party_counter);
                party_counter += 1;
                name
            };

            for i in 0..pre_primary {
                let vote_time = Time::from_unix_timestamp(
                    block_time.unix_timestamp() + i as i64,
                    0,
                ).expect("valid timestamp");

                let vote = Vote {
                    party: next_party(),
                    time: vote_time,
                    key: ChainId(key.clone()),
                    value: ChainId(value_primary.clone()),
                };

                vote_queue
                    .cast(vote)
                    .await
                    .map_err(|e| proptest::test_runner::TestCaseError::fail(format!("cast primary vote failed: {e}")))?;
            }

            for i in 0..pre_other {
                let vote_time = Time::from_unix_timestamp(
                    block_time.unix_timestamp() + (pre_primary + i) as i64,
                    0,
                ).expect("valid timestamp");

                let vote = Vote {
                    party: next_party(),
                    time: vote_time,
                    key: ChainId(key.clone()),
                    value: ChainId(value_other.clone()),
                };

                vote_queue
                    .cast(vote)
                    .await
                    .map_err(|e| proptest::test_runner::TestCaseError::fail(format!("cast other vote failed: {e}")))?;
            }

            let pending_before = vote_queue
                .pending_for_key(ChainId(key.clone()))
                .await
                .map_err(|e| proptest::test_runner::TestCaseError::fail(format!("get pending before failed: {e}")))?;
            prop_assert!(
                pending_before.is_none(),
                "no value should be pending before quorum is reached"
            );

            let votes_before = vote_queue
                .votes_for_key(ChainId(key.clone()))
                .await
                .map_err(|e| proptest::test_runner::TestCaseError::fail(format!("get votes before failed: {e}")))?;
            prop_assert_eq!(
                votes_before.len() as u64,
                pre_primary + pre_other,
                "votes should remain in queue before quorum"
            );

            for i in 0..extra_needed {
                let vote_time = Time::from_unix_timestamp(
                    block_time.unix_timestamp() + (pre_primary + pre_other + i) as i64,
                    0,
                ).expect("valid timestamp");

                let vote = Vote {
                    party: next_party(),
                    time: vote_time,
                    key: ChainId(key.clone()),
                    value: ChainId(value_primary.clone()),
                };

                vote_queue
                    .cast(vote)
                    .await
                    .map_err(|e| proptest::test_runner::TestCaseError::fail(format!("cast extra vote failed: {e}")))?;
            }

            let pending_after = vote_queue
                .pending_for_key(ChainId(key.clone()))
                .await
                .map_err(|e| proptest::test_runner::TestCaseError::fail(format!("get pending after failed: {e}")))?;
            prop_assert!(
                pending_after.is_some(),
                "value should be pending after quorum is reached"
            );
            prop_assert_eq!(
                pending_after.unwrap(),
                ChainId(value_primary.clone()),
                "pending value should match the one that hit quorum"
            );

            let votes_after = vote_queue
                .votes_for_key(ChainId(key.clone()))
                .await
                .map_err(|e| proptest::test_runner::TestCaseError::fail(format!("get votes after failed: {e}")))?;
            prop_assert_eq!(
                votes_after.len(),
                0,
                "all votes should be cleared once a value reaches quorum"
            );

            Ok(())
        })?;
    });
}

#[test]
fn proptest_quorum_with_vote_replacement() {
    let config = proptest::test_runner::Config {
        cases: 100, // Limit to 100 test cases
        ..Default::default()
    };
    proptest!(config, |(
        total in 3u64..=100u64,
        quorum in 3u64..=100u64,
        key in "[a-zA-Z0-9_]+",
        value_a in "[a-zA-Z0-9_]+",
        value_b in "[a-zA-Z0-9_]+",
    )| {
        if value_a == value_b {
            return Ok(());
        }

        let quorum = quorum.min(total).max(3);
        let votes_needed = quorum + 1;
        if votes_needed > total {
            return Ok(());
        }

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

            let mut party_counter = 0u64;
            let mut next_party = || {
                let name = format!("party_{}", party_counter);
                party_counter += 1;
                name
            };

        // We cast quorum - 1 votes for value A
        let mut parties_a = Vec::new();
        for i in 0..(quorum - 1) {
                let vote_time = Time::from_unix_timestamp(
                    block_time.unix_timestamp() + i as i64,
                    0,
                ).expect("valid timestamp");

                let party = next_party();
                let vote = Vote {
                    party: party.clone(),
                    time: vote_time,
                    key: ChainId(key.clone()),
                    value: ChainId(value_a.clone()),
                };

                vote_queue
                    .cast(vote)
                    .await
                    .map_err(|e| proptest::test_runner::TestCaseError::fail(format!("cast vote A failed: {e}")))?;

                parties_a.push(party);
            }

            // The first party replaces value A with value B (so now there are quorum - 2 votes for value A)
            let replacement_party = parties_a[0].clone();
            let replacement_time = Time::from_unix_timestamp(
                block_time.unix_timestamp() + (quorum - 1) as i64,
                0,
            ).expect("valid timestamp");
            let replacement_vote = Vote {
                party: replacement_party.clone(),
                time: replacement_time,
                key: ChainId(key.clone()),
                value: ChainId(value_b.clone()),
            };
            vote_queue
                .cast(replacement_vote)
                .await
                .map_err(|e| proptest::test_runner::TestCaseError::fail(format!("cast replacement vote failed: {e}")))?;

            // Then we cast 2 more votes for value A, to reach quorum.
            for offset in 0..2 {
                let final_party = next_party();
                let final_time = Time::from_unix_timestamp(
                    block_time.unix_timestamp() + (quorum + offset) as i64,
                    0,
                ).expect("valid timestamp");
                let final_vote = Vote {
                    party: final_party.clone(),
                    time: final_time,
                    key: ChainId(key.clone()),
                    value: ChainId(value_a.clone()),
                };
                vote_queue
                    .cast(final_vote)
                    .await
                    .map_err(|e| proptest::test_runner::TestCaseError::fail(format!("cast additional vote failed: {e}")))?;
            }

            let pending = vote_queue
                .pending_for_key(ChainId(key.clone()))
                .await
                .map_err(|e| proptest::test_runner::TestCaseError::fail(format!("get pending failed: {e}")))?;
            prop_assert!(
                pending.is_some(),
                "value should be pending after quorum is reached"
            );
            prop_assert_eq!(
                pending.unwrap(),
                ChainId(value_a.clone()),
                "pending value should be the one that maintained quorum"
            );

            let votes = vote_queue
                .votes_for_key(ChainId(key.clone()))
                .await
                .map_err(|e| proptest::test_runner::TestCaseError::fail(format!("get votes failed: {e}")))?;
            prop_assert_eq!(
                votes.len(),
                0,
                "all votes should be cleared once quorum is reached"
            );

            Ok(())
        })?;
    });
}
