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
