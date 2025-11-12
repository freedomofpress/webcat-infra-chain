use super::super::*;
use crate::store::Store;
use tempfile::TempDir;

/// Helper function to set up a test state with block height and time configured
pub async fn setup_test_state() -> (Store, Time) {
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
