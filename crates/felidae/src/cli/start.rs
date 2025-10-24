use std::net::{IpAddr, Ipv4Addr};

use clap::Parser;
use color_eyre::{
    Report,
    eyre::{OptionExt, bail},
};
use felidae_state::Store;
use felidae_types::transaction::Domain;

use super::Run;

#[derive(Parser)]
pub struct Start {
    /// Which port should the ABCI server listen on?
    #[clap(long, default_value = "26658")]
    abci: u16,
    /// Which port should the query server listen on?
    #[clap(long, default_value = "80")]
    query: u16,
}

impl Run for Start {
    async fn run(self) -> color_eyre::Result<()> {
        let Self { abci, query } = self;

        // Determine the internal and canonical storage directories:
        // TODO: allow overriding these via CLI args
        let storage_dir = directories::ProjectDirs::from("press", "freedom", "felidae")
            .ok_or_eyre("could not determine storage directory")?
            .data_local_dir()
            .join("storage")
            .to_path_buf();

        // Load up the storage/state backend, which implements the ABCI service:
        let mut state = Store::init(storage_dir).await?;

        // The query state is a fork of the main state, so that queries do not interfere with
        // in-progress writes.
        let mut query_state = state.fork().await;

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
                .listen_tcp((IpAddr::V4(Ipv4Addr::LOCALHOST), abci))
                .await
                .or_else(|e| {
                    bail!("could not start ABCI server on port {abci}: {e}");
                })
        });

        // TODO: serve snapshot JSON with whole thing at '/' and subdomains at '/example.com'
        let query = tokio::spawn(async move {
            use axum::{Router, extract::Path, routing::get};

            let app = Router::new().route(
                "/",
                get(|Path(domain): Path<Domain>| async move {
                    // Although we never write or commit to the query state, aborting it at the
                    // start of the query state updates it to the latest snapshot:
                    query_state.abort();

                    // Get a list of canonical subdomains for the given domain:
                    let state = query_state.state.read().await;
                    let domain_hashes = state.canonical_subdomains_hashes(domain).await;
                }),
            );

            let listener =
                tokio::net::TcpListener::bind((IpAddr::V4(Ipv4Addr::UNSPECIFIED), query)).await?;
            axum::serve(listener, app).await?;

            Ok::<_, Report>(())
        });

        // Wait for everything to exit:
        tokio::select! {
            res = abci => res??,
        }

        Ok(())
    }
}
