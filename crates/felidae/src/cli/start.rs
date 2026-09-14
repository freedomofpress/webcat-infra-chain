use std::{net::SocketAddr, time::Duration};

use clap::Parser;
use color_eyre::{
    Report,
    eyre::{OptionExt, bail},
};
use felidae_state::Store;

use super::Run;

mod fail_fast;
mod health;
mod query;

use fail_fast::FailFast;

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
    /// How stale the newest committed block may be before `/healthz` reports
    /// unhealthy (e.g. "45s", "2m"). Defaults to ten times the chain's own
    /// observed block interval, with a 30s floor.
    #[clap(long, value_parser = humantime::parse_duration)]
    health_max_block_age: Option<Duration>,
}

impl Run for Start {
    async fn run(self) -> color_eyre::Result<()> {
        let Self {
            abci_bind,
            query_bind,
            homedir,
            health_max_block_age,
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

        // Split the state service into its ABCI components. `FailFast` wraps the
        // service before the split so that a panic anywhere in ABCI request
        // handling ends the process rather than silently killing one connection
        // and leaving the query port answering for a node with no consensus:
        let (consensus, mempool, snapshot, info) =
            tower_abci::v038::split::service(FailFast::new(state), 4);

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
            let policy = health::Policy {
                max_block_age: health_max_block_age,
            };
            axum::serve(listener, query::app(storage, policy)).await?;

            Ok::<_, Report>(())
        });

        // Wait for everything to exit:
        tokio::select! {
            res = abci => res??,
            res = query => res??,
            _ = tokio::signal::ctrl_c() => {
                info!("received shutdown signal");
            }
        }

        Ok(())
    }
}
