//! Liveness policy for the query port.
//!
//! The query API answers from the latest committed snapshot and never speaks to
//! the ABCI side. That decoupling is deliberate — reads must not be able to
//! stall consensus — but it costs us an observability gap: a node whose ABCI
//! connection has died keeps answering `/config` and `/chain-info` with frozen
//! data indefinitely, so a 200 from either says nothing about whether this node
//! still participates.
//!
//! `/healthz` asks the one question the others cannot: how long has it been
//! since this node committed a block?

use std::time::Duration;

use cnidarium::{Snapshot, StateDelta};
use color_eyre::Report;
use felidae_state::State;
use felidae_types::response::Health;
use tendermint::Time;

/// Assemble a health report from the latest committed state.
pub async fn report(
    state: &State<StateDelta<Snapshot>>,
    tolerance: Duration,
    now: Time,
) -> Result<Health, Report> {
    let block_time = state.block_time().await?;
    // A block stamped in the future is clock skew, not staleness; call it fresh
    // rather than letting the subtraction wrap.
    let block_age = now.duration_since(block_time).unwrap_or_default();

    Ok(Health {
        healthy: block_age <= tolerance,
        block_height: state.block_height().await?.value(),
        block_time,
        block_age_secs: block_age.as_secs(),
        tolerance_secs: tolerance.as_secs(),
    })
}
