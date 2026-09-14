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
//! since this node committed a block? Staleness is judged against the chain's
//! own observed cadence, so the common case needs neither a reading of
//! CometBFT's `timeout_commit` nor a hand-tuned threshold.

use std::time::Duration;

use cnidarium::{Snapshot, StateDelta};
use color_eyre::Report;
use felidae_state::State;
use felidae_types::response::Health;
use tendermint::Time;

/// Blocks sampled when inferring the chain's cadence.
const SAMPLE_BLOCKS: u64 = 20;

/// Missed blocks tolerated before a node stops calling itself healthy. Ten
/// consecutive misses is well past ordinary proposer timeout jitter.
const STALL_FACTOR: u32 = 10;

/// Floor under the inferred tolerance. Without it a fast chain would flap on a
/// single slow round, and a chain too young to have measured an interval would
/// have no tolerance at all.
const MIN_TOLERANCE: Duration = Duration::from_secs(30);

/// How `/healthz` decides whether this node is still advancing.
#[derive(Clone, Copy, Debug, Default)]
pub struct Policy {
    /// Operator override for the staleness tolerance. `None` infers it from
    /// the chain's observed block interval.
    pub max_block_age: Option<Duration>,
}

impl Policy {
    /// The age at which a node stops calling itself healthy, given the chain's
    /// observed cadence.
    fn tolerance(&self, interval: Option<Duration>) -> Duration {
        self.max_block_age.unwrap_or_else(|| {
            interval
                .map(|i| i.saturating_mul(STALL_FACTOR))
                .unwrap_or(MIN_TOLERANCE)
                .max(MIN_TOLERANCE)
        })
    }
}

/// Assemble a health report from the latest committed state.
pub async fn report(
    state: &State<StateDelta<Snapshot>>,
    policy: Policy,
    now: Time,
) -> Result<Health, Report> {
    let block_height = state.block_height().await?.value();
    let block_time = state.block_time().await?;
    let interval = state.observed_block_interval(SAMPLE_BLOCKS).await?;
    let tolerance = policy.tolerance(interval);
    // A block stamped in the future is clock skew, not staleness; call it fresh
    // rather than letting the subtraction wrap.
    let block_age = now.duration_since(block_time).unwrap_or_default();

    Ok(Health {
        healthy: block_age <= tolerance,
        block_height,
        block_time,
        block_age_secs: block_age.as_secs(),
        tolerance_secs: tolerance.as_secs(),
        observed_interval_secs: interval.map(|i| i.as_secs()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const INFER: Policy = Policy {
        max_block_age: None,
    };

    #[test]
    fn a_fast_chain_gets_the_floor() {
        // Ten 1s blocks is 10s, under the floor, so the floor wins and one slow
        // round cannot flap the endpoint.
        assert_eq!(INFER.tolerance(Some(Duration::from_secs(1))), MIN_TOLERANCE);
    }

    #[test]
    fn a_slow_chain_scales_with_its_interval() {
        assert_eq!(
            INFER.tolerance(Some(Duration::from_secs(6))),
            Duration::from_secs(60)
        );
    }

    #[test]
    fn a_chain_too_young_to_measure_gets_the_floor() {
        assert_eq!(INFER.tolerance(None), MIN_TOLERANCE);
    }

    #[test]
    fn an_override_beats_both() {
        let policy = Policy {
            max_block_age: Some(Duration::from_secs(5)),
        };
        assert_eq!(
            policy.tolerance(Some(Duration::from_secs(600))),
            Duration::from_secs(5)
        );
        assert_eq!(policy.tolerance(None), Duration::from_secs(5));
    }

    #[test]
    fn an_absurd_interval_saturates_rather_than_panicking() {
        // A health handler is the last place that should be able to panic.
        assert_eq!(INFER.tolerance(Some(Duration::MAX)), Duration::MAX);
    }
}
