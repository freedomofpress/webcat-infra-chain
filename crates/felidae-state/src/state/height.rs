use super::*;

impl<S: StateReadExt + StateWriteExt + 'static> State<S> {
    /// Get the current block height from the state, else default to 0.
    pub async fn block_height(&self) -> Result<Height, Report> {
        Ok(self
            .store
            .get::<Height>(Internal, "current/block_height")
            .await?
            .unwrap_or(Height::from(0u32)))
    }

    /// Set the current block height in the state.
    pub(crate) async fn set_block_height(&mut self, height: Height) -> Result<(), Report> {
        self.store.put(Internal, "current/block_height", height);
        Ok(())
    }
}
