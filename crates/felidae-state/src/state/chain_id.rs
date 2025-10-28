use super::*;

impl<S: StateReadExt + StateWriteExt + 'static> State<S> {
    /// Get the current chain ID from the state.
    pub async fn chain_id(&self) -> Result<ChainId, Report> {
        self.store
            .get::<ChainId>(Internal, "parameters/chain_id")
            .await?
            .ok_or_eyre("chain ID not found in state; is the state initialized?")
    }

    /// Set the current chain ID in the state.
    ///
    /// This should only be called once, during initial setup.
    pub(crate) async fn set_chain_id(&mut self, chain_id: ChainId) -> Result<(), Report> {
        let existing = self.chain_id().await.ok();
        if existing.is_some() {
            bail!("chain ID is already set; cannot set it again");
        }

        self.store.put(Internal, "parameters/chain_id", chain_id);
        Ok(())
    }
}
