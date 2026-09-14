use super::*;

impl<S: StateReadExt + StateWriteExt + 'static> State<S> {
    /// Get the current block time from the state.
    pub async fn block_time(&self) -> Result<Time, Report> {
        self.store
            .get::<Time>(Internal, "current/block_time")
            .await?
            .ok_or_eyre("block time not found in state; is the state initialized?")
    }

    /// Set the current block time in the state.
    pub(crate) async fn set_block_time(&mut self, time: Time) -> Result<(), Report> {
        self.store.put(Internal, "current/block_time", time);
        self.record_block_time(time).await?;
        Ok(())
    }

    /// Get the time of a specific block from the state.
    pub async fn time_of_block(&self, height: Height) -> Result<Time, Report> {
        self.store
            .get::<Time>(Internal, &format!("blocktime/{}", util::pad_height(height)))
            .await?
            .ok_or_eyre("block time not found in state")
    }

    /// Mean interval between recent committed blocks, sampled over at most
    /// `samples` of them.
    ///
    /// `None` until a second block exists to compare against. Averaging across
    /// a span rather than differencing the newest pair keeps proposer timing
    /// jitter out of the answer, which matters when a caller is using this to
    /// decide whether the chain has stopped.
    pub async fn observed_block_interval(
        &self,
        samples: u64,
    ) -> Result<Option<std::time::Duration>, Report> {
        let height = self.block_height().await?;
        let span = samples.min(height.value().saturating_sub(1));
        if span == 0 {
            return Ok(None);
        }
        let newest = self.block_time().await?;
        // A chain whose history predates block-time recording has no older
        // sample to compare against. Decline to infer rather than fail: callers
        // use this to judge liveness, and a missing datum is not a fault.
        let Ok(oldest) = self
            .time_of_block(Height::try_from(height.value() - span)?)
            .await
        else {
            return Ok(None);
        };
        Ok(Some(newest.duration_since(oldest)? / span as u32))
    }

    /// Record the time of the current block in the state.
    pub(crate) async fn record_block_time(&mut self, time: Time) -> Result<(), Report> {
        let height = self.block_height().await?;
        self.store.put(
            Internal,
            &format!("blocktime/{}", util::pad_height(height)),
            time,
        );
        Ok(())
    }
}
