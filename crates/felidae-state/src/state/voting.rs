use super::*;

mod vote_queue;
use vote_queue::VoteQueue;

pub use vote_queue::Vote;

impl<S: StateReadExt + StateWriteExt + 'static> State<S> {
    /// Get the vote queue for oracle observations.
    pub async fn oracle_voting<'a>(
        &'a mut self,
    ) -> Result<VoteQueue<'a, S, PrefixOrderDomain, HashObserved>, Report> {
        let config = self.config().await?.oracles.voting.clone();
        Ok(VoteQueue::<S, PrefixOrderDomain, HashObserved>::new(
            self,
            "oracle_voting/",
            config,
        ))
    }

    /// Get the vote queue for admin updates.
    pub async fn admin_voting<'a>(&'a mut self) -> Result<VoteQueue<'a, S, Empty, Config>, Report> {
        let config = self.config().await?.admins.voting.clone();
        Ok(VoteQueue::<S, Empty, Config>::new(
            self,
            "admin_voting/",
            config,
        ))
    }
}
