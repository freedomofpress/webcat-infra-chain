use super::*;

impl<S: StateReadExt + StateWriteExt + 'static> State<S> {
    /// Deliver transaction bytes to the state.
    pub async fn deliver_tx(&mut self, tx_bytes: &[u8]) -> Result<(), Report> {
        let tx = AuthenticatedTx::from_proto(tx_bytes)?;
        self.deliver_authenticated_tx(&tx).await
    }

    /// Execute a transaction against the current state, without committing the results yet.
    async fn deliver_authenticated_tx(&mut self, tx: &AuthenticatedTx) -> Result<(), Report> {
        let Transaction { actions, .. } = &**tx;

        // First, check the chain ID to see if it matches the current chain ID.
        let current_chain_id = self.chain_id().await?;
        if tx.chain_id != current_chain_id {
            bail!(
                "transaction chain ID {} does not match current chain ID {}",
                tx.chain_id.0,
                current_chain_id.0,
            );
        }

        // Ensure the transaction is non-empty:
        if actions.is_empty() {
            bail!("transaction must contain at least one action");
        }

        // Then, apply each action in order:
        for action in actions {
            use Action::*;
            match action {
                Reconfigure(reconfig) => self.reconfigure(reconfig).await?,
                Observe(observe) => self.observe(observe).await?,
            }
        }

        Ok(())
    }
}
