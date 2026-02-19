use tracing::info;

use super::*;

impl<S: StateReadExt + StateWriteExt + 'static> State<S> {
    /// Record the app hash of the previous block in the state.
    pub(crate) async fn record_app_hash(&mut self, app_hash: AppHash) -> Result<(), Report> {
        let height = self.block_height().await?.value() - 1;
        info!(
            height,
            app_hash = hex::encode(app_hash.as_bytes()),
            "recording app hash for block"
        );
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
