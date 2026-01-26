use super::*;

impl<S: StateReadExt + StateWriteExt + 'static> State<S> {
    /// Record the current block's app hash in the state.
    pub(crate) async fn record_current_app_hash(
        &mut self,
        app_hash: AppHash,
    ) -> Result<(), Report> {
        let height = self.block_height().await?.value();
        self.store.put(
            Internal,
            &format!("apphash/{}", util::pad_height(height.try_into()?)),
            app_hash.clone(),
        );
        Ok(())
    }

    /// Get the app hash of a specific previous block from the state.
    pub async fn previous_app_hash(&self, block_height: Height) -> Result<AppHash, Report> {
        self.store
            .get::<AppHash>(
                Internal,
                &format!("apphash/{}", util::pad_height(block_height)),
            )
            .await?
            .ok_or_eyre("app hash not found in state")
    }
}
