use crate::Store;
use felidae_types::{
    FQDN,
    transaction::{
        Admin, AdminConfig, Blockstamp, Config, Delay, Domain, HashObserved, Observation, Observe,
        OnionConfig, Oracle, OracleConfig, OracleIdentity, PrefixOrderDomain, Quorum, Timeout,
        Total, VotingConfig, Zone,
    },
};
use prost::bytes::Bytes;
use std::time::Duration;
use tempfile::TempDir;
use tendermint::{AppHash, Time, block::Height};

fn oracle_identity() -> Bytes {
    Bytes::from(vec![1u8; 64])
}

fn test_app_hash() -> AppHash {
    AppHash::try_from(vec![42u8; 32]).expect("valid app hash")
}

fn test_config(oracle: &Bytes, obs_timeout_secs: u64, max_subdomains: u64) -> Config {
    Config {
        version: 1,
        admins: AdminConfig {
            voting: VotingConfig {
                total: Total(1),
                quorum: Quorum(1),
                timeout: Timeout(Duration::from_secs(3600)),
                delay: Delay(Duration::from_secs(0)),
            },
            authorized: vec![Admin {
                identity: Bytes::from(vec![0xabu8; 64]),
            }],
        },
        oracles: OracleConfig {
            enabled: true,
            voting: VotingConfig {
                total: Total(1),
                quorum: Quorum(1),
                timeout: Timeout(Duration::from_secs(3600)),
                delay: Delay(Duration::from_secs(0)),
            },
            max_enrolled_subdomains: max_subdomains,
            observation_timeout: Duration::from_secs(obs_timeout_secs),
            authorized: vec![Oracle {
                identity: oracle.clone(),
                endpoint: "127.0.0.1".to_string(),
            }],
        },
        onion: OnionConfig { enabled: false },
    }
}

/// Set up test state. TempDir must be kept alive for duration of the test.
async fn setup_state(obs_timeout_secs: u64, max_subdomains: u64) -> (Store, TempDir) {
    let temp_dir = TempDir::new().expect("failed to create temp dir");
    let store = Store::init(temp_dir.path().to_path_buf())
        .await
        .expect("failed to create store");

    let oracle = oracle_identity();
    let app_hash = test_app_hash();
    let block_4_time = Time::from_unix_timestamp(1_700_000_000, 0).expect("valid timestamp");
    let current_time = Time::from_unix_timestamp(1_700_000_060, 0).expect("valid timestamp");

    {
        let mut state = store.state.write().await;

        state
            .set_config(test_config(&oracle, obs_timeout_secs, max_subdomains))
            .await
            .expect("set_config");

        // Set block 4 time + app hash
        state
            .set_block_height(Height::from(4u32))
            .await
            .expect("set_block_height to 4");
        state
            .set_block_time(block_4_time)
            .await
            .expect("set_block_time for block 4");
        state
            .record_app_hash(app_hash)
            .await
            .expect("record_app_hash");

        // Block 5: current block
        state
            .set_block_height(Height::from(5u32))
            .await
            .expect("set_block_height to 5");
        state
            .set_block_time(current_time)
            .await
            .expect("set_block_time for block 5");
    }

    (store, temp_dir)
}

fn mock_observe(
    oracle: &Bytes,
    subdomain: &str,
    zone: &str,
    blockstamp_height: u32,
    app_hash: &AppHash,
    hash_observed: HashObserved,
) -> Observe {
    Observe {
        oracle: OracleIdentity {
            identity: oracle.clone(),
        },
        observation: Observation {
            domain: Domain {
                name: FQDN::from_ascii_str(subdomain).expect("valid subdomain FQDN"),
            },
            zone: Zone {
                name: FQDN::from_ascii_str(zone).expect("valid zone FQDN"),
            },
            blockstamp: Blockstamp {
                block_height: Height::from(blockstamp_height),
                app_hash: app_hash.clone(),
            },
            hash_observed,
        },
    }
}

#[tokio::test]
async fn test_observe_unauthorized_oracle() {
    let (store, _dir) = setup_state(300, 10).await;
    let app_hash = test_app_hash();
    let unauthorized = Bytes::from(vec![0xffu8; 64]);

    let mut state = store.state.write().await;
    let observe = mock_observe(
        &unauthorized,
        "sub.example.com.",
        "com.",
        4,
        &app_hash,
        HashObserved::Hash([1u8; 32]),
    );

    let err = state.observe(&observe).await.unwrap_err();
    assert!(
        err.to_string().contains("not a current oracle"),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn test_observe_future_block() {
    let (store, _dir) = setup_state(300, 10).await;
    let oracle = oracle_identity();
    let app_hash = test_app_hash();

    let mut state = store.state.write().await;

    // Current block is 5, so this block is in the future
    let observe = mock_observe(
        &oracle,
        "sub.example.com.",
        "com.",
        6,
        &app_hash,
        HashObserved::Hash([1u8; 32]),
    );

    let err = state.observe(&observe).await.unwrap_err();
    assert!(
        err.to_string().contains("is in the future"),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn test_observe_stale_block() {
    // observation_timeout = 30 s, but block 4 is 60 s before the current block — too old.
    let (store, _dir) = setup_state(30, 10).await;
    let oracle = oracle_identity();
    let app_hash = test_app_hash();

    let mut state = store.state.write().await;
    let observe = mock_observe(
        &oracle,
        "sub.example.com.",
        "com.",
        4,
        &app_hash,
        HashObserved::Hash([1u8; 32]),
    );

    let err = state.observe(&observe).await.unwrap_err();
    assert!(
        err.to_string().contains("blockstamp is too old"),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn test_observe_app_hash_mismatch() {
    let (store, _dir) = setup_state(300, 10).await;
    let oracle = oracle_identity();
    let wrong_hash = AppHash::try_from(vec![0xffu8; 32]).expect("valid app hash");

    let mut state = store.state.write().await;
    let observe = mock_observe(
        &oracle,
        "sub.example.com.",
        "com.",
        4,
        &wrong_hash,
        HashObserved::Hash([1u8; 32]),
    );

    let err = state.observe(&observe).await.unwrap_err();
    assert!(
        err.to_string().contains("does not match recorded app hash"),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn test_observe_no_subdomain() {
    let (store, _dir) = setup_state(300, 10).await;
    let oracle = oracle_identity();
    let app_hash = test_app_hash();

    let mut state = store.state.write().await;
    let observe = mock_observe(
        &oracle,
        "example.com.",
        "example.com.",
        4,
        &app_hash,
        HashObserved::Hash([1u8; 32]),
    );

    let err = state.observe(&observe).await.unwrap_err();
    assert!(
        err.to_string().contains("must be a strict subdomain"),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn test_observe_domain_wrong_zone() {
    let (store, _dir) = setup_state(300, 10).await;
    let oracle = oracle_identity();
    let app_hash = test_app_hash();

    let mut state = store.state.write().await;
    let observe = mock_observe(
        &oracle,
        "sub.other.org.",
        "example.com.",
        4,
        &app_hash,
        HashObserved::Hash([1u8; 32]),
    );

    let err = state.observe(&observe).await.unwrap_err();
    assert!(
        err.to_string().contains("is not a subdomain of zone"),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn test_observe_delete_nonexistent_subdomain() {
    let (store, _dir) = setup_state(300, 10).await;
    let oracle = oracle_identity();
    let app_hash = test_app_hash();

    // NotFound vote for a subdomain not in canonical/pending state should be rejected
    let mut state = store.state.write().await;
    let observe = mock_observe(
        &oracle,
        "sub.example.com.",
        "com.",
        4,
        &app_hash,
        HashObserved::NotFound,
    );

    let err = state.observe(&observe).await.unwrap_err();
    assert!(
        err.to_string().contains("already queued for deletion"),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn test_observe_success() {
    // Testing with quorum = 1, so valid observation moves to pending queue
    let (store, _dir) = setup_state(300, 10).await;
    let oracle = oracle_identity();
    let app_hash = test_app_hash();
    let hash = [0xdeu8; 32];

    let mut state = store.state.write().await;
    let observe = mock_observe(
        &oracle,
        "sub.example.com.",
        "com.",
        4,
        &app_hash,
        HashObserved::Hash(hash),
    );
    state
        .observe(&observe)
        .await
        .expect("observe should succeed");

    let subdomain = PrefixOrderDomain::from(Domain {
        name: FQDN::from_ascii_str("sub.example.com.").unwrap(),
    });
    let pending = state
        .oracle_voting()
        .await
        .unwrap()
        .pending_for_key(subdomain)
        .await
        .unwrap();

    assert!(
        pending.is_some(),
        "vote should reach quorum and move to pending"
    );
    assert_eq!(
        pending.unwrap().hash_observed,
        HashObserved::Hash(hash),
        "pending value should match observed hash"
    );
}

#[tokio::test]
async fn test_observe_not_found() {
    let (store, _dir) = setup_state(300, 10).await;
    let oracle = oracle_identity();
    let app_hash = test_app_hash();

    let mut state = store.state.write().await;

    state
        .update_canonical(
            Domain {
                name: FQDN::from_ascii_str("sub.example.com.").unwrap(),
            },
            HashObserved::Hash([1u8; 32]),
        )
        .await
        .unwrap();

    let observe = mock_observe(
        &oracle,
        "sub.example.com.",
        "com.",
        4,
        &app_hash,
        HashObserved::NotFound,
    );
    state
        .observe(&observe)
        .await
        .expect("NotFound vote for existing canonical subdomain should succeed");
}

#[tokio::test]
async fn test_observe_update_existing_canonical_subdomain() {
    let (store, _dir) = setup_state(300, 1).await;
    let oracle = oracle_identity();
    let app_hash = test_app_hash();

    let mut state = store.state.write().await;

    state
        .update_canonical(
            Domain {
                name: FQDN::from_ascii_str("sub.example.com.").unwrap(),
            },
            HashObserved::Hash([1u8; 32]),
        )
        .await
        .unwrap();

    let observe = mock_observe(
        &oracle,
        "sub.example.com.",
        "com.",
        4,
        &app_hash,
        HashObserved::Hash([2u8; 32]),
    );
    state
        .observe(&observe)
        .await
        .expect("updating an existing canonical subdomain should succeed at the limit");
}

#[tokio::test]
async fn test_observe_subdomain_limit_exceeded() {
    let (store, _dir) = setup_state(300, 1).await;
    let oracle = oracle_identity();
    let app_hash = test_app_hash();

    let mut state = store.state.write().await;

    state
        .update_canonical(
            Domain {
                name: FQDN::from_ascii_str("existing.example.com.").unwrap(),
            },
            HashObserved::Hash([1u8; 32]),
        )
        .await
        .unwrap();

    let observe = mock_observe(
        &oracle,
        "new.example.com.",
        "com.",
        4,
        &app_hash,
        HashObserved::Hash([2u8; 32]),
    );

    let err = state.observe(&observe).await.unwrap_err();
    assert!(
        err.to_string()
            .contains("would exceed max enrolled subdomains"),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn test_limit_check_new_subdomain_under_limit() {
    let (store, _dir) = setup_state(300, 5).await;
    let mut state = store.state.write().await;

    let subdomain = PrefixOrderDomain::from(Domain {
        name: FQDN::from_ascii_str("new.example.com.").unwrap(),
    });
    let registered_domain = PrefixOrderDomain::from(Domain {
        name: FQDN::from_ascii_str("example.com.").unwrap(),
    });

    state
        .check_subdomain_limit_before_pending_exact(subdomain, registered_domain)
        .await
        .expect("should succeed: count 0 + 1 <= limit 5");
}

#[tokio::test]
async fn test_limit_check_new_subdomain_at_limit() {
    // max = 1; one subdomain already in canonical state.
    // Adding a new subdomain would push the count to 2, exceeding the limit.
    let (store, _dir) = setup_state(300, 1).await;
    let mut state = store.state.write().await;

    state
        .update_canonical(
            Domain {
                name: FQDN::from_ascii_str("existing.example.com.").unwrap(),
            },
            HashObserved::Hash([1u8; 32]),
        )
        .await
        .unwrap();

    let subdomain = PrefixOrderDomain::from(Domain {
        name: FQDN::from_ascii_str("new.example.com.").unwrap(),
    });
    let registered_domain = PrefixOrderDomain::from(Domain {
        name: FQDN::from_ascii_str("example.com.").unwrap(),
    });

    let err = state
        .check_subdomain_limit_before_pending_exact(subdomain, registered_domain)
        .await
        .unwrap_err();
    assert!(
        err.to_string()
            .contains("would exceed max enrolled subdomains"),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn test_limit_check_update_existing_canonical_subdomain() {
    let (store, _dir) = setup_state(300, 1).await;
    let mut state = store.state.write().await;

    state
        .update_canonical(
            Domain {
                name: FQDN::from_ascii_str("sub.example.com.").unwrap(),
            },
            HashObserved::Hash([1u8; 32]),
        )
        .await
        .unwrap();

    let subdomain = PrefixOrderDomain::from(Domain {
        name: FQDN::from_ascii_str("sub.example.com.").unwrap(),
    });
    let registered_domain = PrefixOrderDomain::from(Domain {
        name: FQDN::from_ascii_str("example.com.").unwrap(),
    });

    state
        .check_subdomain_limit_before_pending_exact(subdomain, registered_domain)
        .await
        .expect("updating an already-counted subdomain should not trigger the limit check");
}

#[tokio::test]
async fn test_limit_check_pending_subdomain_counts_toward_limit() {
    let (store, _dir) = setup_state(300, 1).await;
    let oracle = oracle_identity();
    let app_hash = test_app_hash();
    let mut state = store.state.write().await;

    // Observe "existing.example.com." — quorum = 1 means it goes straight to pending.
    let observe = mock_observe(
        &oracle,
        "existing.example.com.",
        "com.",
        4,
        &app_hash,
        HashObserved::Hash([1u8; 32]),
    );
    state
        .observe(&observe)
        .await
        .expect("first observe should succeed");

    // Now check whether adding "new.example.com." would exceed the limit.
    let subdomain = PrefixOrderDomain::from(Domain {
        name: FQDN::from_ascii_str("new.example.com.").unwrap(),
    });
    let registered_domain = PrefixOrderDomain::from(Domain {
        name: FQDN::from_ascii_str("example.com.").unwrap(),
    });

    let err = state
        .check_subdomain_limit_before_pending_exact(subdomain, registered_domain)
        .await
        .unwrap_err();
    assert!(
        err.to_string()
            .contains("would exceed max enrolled subdomains"),
        "pending entry should count toward the subdomain limit; unexpected error: {err}"
    );
}
