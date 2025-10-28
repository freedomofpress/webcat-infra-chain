use super::*;

impl<S: StateReadExt + StateWriteExt + 'static> State<S> {
    /// Get the current block height from the state.
    pub async fn block_height(&self) -> Result<Height, Report> {
        self.store
            .get::<Height>(Internal, "current/block_height")
            .await?
            .ok_or_eyre("block height not found in state; is the state initialized?")
    }

    /// Set the current block height in the state.
    pub(crate) async fn set_block_height(&mut self, height: Height) -> Result<(), Report> {
        self.store.put(Internal, "current/block_height", height);
        Ok(())
    }
}
