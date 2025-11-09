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
