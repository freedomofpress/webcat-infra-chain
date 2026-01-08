use std::net::SocketAddr;

use clap::Parser;
use color_eyre::{
    Report,
    eyre::{OptionExt, bail},
};
use felidae_state::Store;

use super::Run;

mod query;

#[derive(Parser)]
pub struct Start {
    /// Socket address for the ABCI server to bind to.
    #[clap(long, default_value = "127.0.0.1:26658")]
    abci_bind: SocketAddr,
    /// Socket address for the query server to bind to.
    #[clap(long, default_value = "127.0.0.1:8080")]
    query_bind: SocketAddr,
    /// Home directory for storing state (defaults to platform-specific directory).
    #[clap(long)]
    pub homedir: Option<std::path::PathBuf>,
}

impl Run for Start {
    async fn run(self) -> color_eyre::Result<()> {
        let Self {
            abci_bind,
            query_bind,
            homedir,
        } = self;

        // Determine the internal and canonical storage directories:
        let storage_dir = if let Some(homedir) = homedir {
            homedir.join("storage")
        } else {
            directories::ProjectDirs::from("press", "freedom", "felidae")
                .ok_or_eyre("could not determine storage directory")?
                .data_local_dir()
                .join("storage")
                .to_path_buf()
        };

        // Load up the storage/state backend, which implements the ABCI service:
        let state = Store::init(storage_dir).await?;

        // We use a clone of the committed storage for queries:
        let storage = state.storage.clone();

        // Split the state service into its ABCI components:
        let (consensus, mempool, snapshot, info) = tower_abci::v038::split::service(state, 4);

        // Start the ABCI server:
        let abci = tokio::spawn(async move {
            tower_abci::v038::ServerBuilder::default()
                .mempool(mempool)
                .info(info)
                .snapshot(snapshot)
                .consensus(consensus)
                .finish()
                .ok_or_eyre("could not construct ABCI server")?
                .listen_tcp(abci_bind)
                .await
                .or_else(|e| {
                    bail!("could not start ABCI server on {abci_bind}: {e}");
                })
        });

        // Start the query server:
        let query = tokio::spawn(async move {
            let listener = tokio::net::TcpListener::bind(query_bind).await?;
            axum::serve(listener, query::app(storage)).await?;

            Ok::<_, Report>(())
        });

        // Wait for everything to exit:
        tokio::select! {
            res = abci => res??,
            res = query => res??,
        }

        Ok(())
    }
}
