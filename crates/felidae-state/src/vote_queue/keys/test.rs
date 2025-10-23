use super::*;

use felidae_types::transaction::{Delay, Domain, Quorum, Timeout, Total};
use std::time::Duration;

#[test]
fn test_vote_queue_keys() {
    let queue: VoteQueue<Domain, ()> = VoteQueue::new(
        "my_prefix/",
        VotingConfig {
            total: Total(5),
            quorum: Quorum(3),
            delay: Delay(Duration::from_secs(600)),
            timeout: Timeout(Duration::from_secs(300)),
        },
    );
    let t = Time::from_unix_timestamp(123, 456).unwrap();
    assert_eq!(
        queue.votes_by_key_party_timestamp("my_key", "party1", t),
        "my_prefix/votes_by_key/my_key/party1/1970-01-01T00:02:03Z"
    );
    assert_eq!(
        queue.index_votes_by_timestamp_key_party(t, "my_key", "party1"),
        b"my_prefix/votes_by_timestamp/\x00\x00\x00\x00\x00\x00\x00\x7b/my_key/party1"
    );
    assert_eq!(
        queue.pending_by_key_timestamp("my_key", t),
        "my_prefix/pending_by_key/my_key/1970-01-01T00:02:03Z"
    );
    assert_eq!(
        queue.index_pending_by_timestamp_key(t, "my_key"),
        b"my_prefix/pending_by_timestamp/\x00\x00\x00\x00\x00\x00\x00\x7b/my_key"
    );
}

#[test]
fn test_votes_by_key_party_timestamp_inverse() {
    let queue: VoteQueue<Domain, ()> = VoteQueue::new(
        "my_prefix/",
        VotingConfig {
            total: Total(5),
            quorum: Quorum(3),
            delay: Delay(Duration::from_secs(600)),
            timeout: Timeout(Duration::from_secs(300)),
        },
    );

    let test_key = "test_key";
    let test_party = "test_party";
    let test_time = Time::from_unix_timestamp(1234567890, 0).unwrap();

    let constructed_key = queue.votes_by_key_party_timestamp(test_key, test_party, test_time);
    let (parsed_key, parsed_party, parsed_time) = queue
        .parse_votes_by_key_party_timestamp(&constructed_key)
        .expect("parse should succeed");

    assert_eq!(parsed_key, test_key);
    assert_eq!(parsed_party, test_party);
    assert_eq!(parsed_time, test_time);
}

#[test]
fn test_index_votes_by_timestamp_key_party_inverse() {
    let queue: VoteQueue<Domain, ()> = VoteQueue::new(
        "my_prefix/",
        VotingConfig {
            total: Total(5),
            quorum: Quorum(3),
            delay: Delay(Duration::from_secs(600)),
            timeout: Timeout(Duration::from_secs(300)),
        },
    );

    let test_key = "test_key";
    let test_party = "test_party";
    let test_time = Time::from_unix_timestamp(1234567890, 0).unwrap();

    let constructed_index =
        queue.index_votes_by_timestamp_key_party(test_time, test_key, test_party);
    let (parsed_time, parsed_key, parsed_party) = queue
        .parse_index_votes_by_timestamp_key_party(&constructed_index)
        .expect("parse should succeed");

    assert_eq!(parsed_time, test_time);
    assert_eq!(parsed_key, test_key);
    assert_eq!(parsed_party, test_party);
}

#[test]
fn test_pending_by_key_timestamp_inverse() {
    let queue: VoteQueue<Domain, ()> = VoteQueue::new(
        "my_prefix/",
        VotingConfig {
            total: Total(5),
            quorum: Quorum(3),
            delay: Delay(Duration::from_secs(600)),
            timeout: Timeout(Duration::from_secs(300)),
        },
    );

    let test_key = "test_key";
    let test_time = Time::from_unix_timestamp(1234567890, 0).unwrap();

    let constructed_pending = queue.pending_by_key_timestamp(test_key, test_time);
    let (parsed_key, parsed_time) = queue
        .parse_pending_by_key_timestamp(&constructed_pending)
        .expect("parse should succeed");

    assert_eq!(parsed_key, test_key);
    assert_eq!(parsed_time, test_time);
}

#[test]
fn test_index_pending_by_timestamp_key_inverse() {
    let queue: VoteQueue<Domain, ()> = VoteQueue::new(
        "my_prefix/",
        VotingConfig {
            total: Total(5),
            quorum: Quorum(3),
            delay: Delay(Duration::from_secs(600)),
            timeout: Timeout(Duration::from_secs(300)),
        },
    );

    let test_key = "test_key";
    let test_time = Time::from_unix_timestamp(1234567890, 0).unwrap();

    let constructed_pending_index = queue.index_pending_by_timestamp_key(test_time, test_key);
    let (parsed_time, parsed_key) = queue
        .parse_index_pending_by_timestamp_key(&constructed_pending_index)
        .expect("parse should succeed");

    assert_eq!(parsed_time, test_time);
    assert_eq!(parsed_key, test_key);
}
