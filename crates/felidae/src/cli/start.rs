use std::net::{IpAddr, Ipv4Addr};

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
    /// Which port should the ABCI server listen on?
    #[clap(long, default_value = "26658")]
    abci: u16,
    /// Which host/address should the ABCI server bind to?
    #[clap(long, default_value = "127.0.0.1")]
    abci_host: IpAddr,
    /// Which port should the query server listen on?
    #[clap(long, default_value = "80")]
    query: u16,
    /// Home directory for storing state (defaults to platform-specific directory).
    #[clap(long)]
    pub homedir: Option<std::path::PathBuf>,
}

impl Run for Start {
    async fn run(self) -> color_eyre::Result<()> {
        let Self {
            abci,
            abci_host,
            query,
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
        let (consensus, mempool, snapshot, info) = tower_abci::v034::split::service(state, 4);

        // Start the ABCI server:
        let abci = tokio::spawn(async move {
            tower_abci::v034::ServerBuilder::default()
                .mempool(mempool)
                .info(info)
                .snapshot(snapshot)
                .consensus(consensus)
                .finish()
                .ok_or_eyre("could not construct ABCI server")?
                .listen_tcp((abci_host, abci))
                .await
                .or_else(|e| {
                    bail!("could not start ABCI server on port {abci}: {e}");
                })
        });

        // Start the query server:
        let query = tokio::spawn(async move {
            let listener =
                tokio::net::TcpListener::bind((IpAddr::V4(Ipv4Addr::UNSPECIFIED), query)).await?;
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
