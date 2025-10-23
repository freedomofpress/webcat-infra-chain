use std::{
    env,
    net::{IpAddr, Ipv4Addr},
    num::NonZero,
    task::{Context, Poll},
};

use clap::Parser;
use color_eyre::eyre::{OptionExt, bail};
use felidae_state::{State, Store};
use futures::future::BoxFuture;
use tendermint::{abci::Code, block::Height, v0_34::abci};
use tower::{BoxError, Service};

use super::Run;

#[derive(Parser)]
pub struct Start {
    /// Which port should the ABCI server listen on?
    #[clap(long, default_value = "26658")]
    abci: u16,
}

#[derive(Clone)]
pub struct CoreService {
    state: State,
}

impl Service<tendermint::v0_34::abci::Request> for CoreService {
    type Response = tendermint::v0_34::abci::Response;
    type Error = BoxError;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> std::task::Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    #[instrument(name = "abci", skip(self, req))]
    fn call(&mut self, req: tendermint::v0_34::abci::Request) -> Self::Future {
        debug!(?req);

        let mut state = self.state.clone();

        Box::pin(async move {
            match req {
                abci::Request::Echo(echo) => Ok(abci::Response::Echo(abci::response::Echo {
                    message: echo.message,
                })),
                abci::Request::Flush => Ok(abci::Response::Flush),
                abci::Request::Info(_info) => {
                    let last_block_height =
                        state.block_height().await.unwrap_or(Height::from(0u32));
                    let last_block_app_hash = state
                        .root_hashes()
                        .await
                        .map(|h| h.app_hash)
                        .unwrap_or_default();

                    Ok(abci::Response::Info(abci::response::Info {
                        data: env!("CARGO_PKG_NAME").to_string(),
                        version: env!("CARGO_PKG_VERSION").to_string(),
                        app_version: env!("CARGO_PKG_VERSION").to_string().parse().unwrap_or(0),
                        last_block_height,
                        last_block_app_hash,
                    }))
                }
                abci::Request::InitChain(init_chain) => {
                    let response = state.init_chain(init_chain).await?;
                    Ok(abci::Response::InitChain(response))
                }
                abci::Request::BeginBlock(begin_block) => {
                    let response = state.begin_block(begin_block).await?;
                    Ok(abci::Response::BeginBlock(response))
                }
                abci::Request::CheckTx(check_tx) => {
                    // Use a forked state for CheckTx, so we don't modify any state until DeliverTx.
                    let mut state = state.fork().await;

                    let reject = |e: String| {
                        Ok(abci::Response::CheckTx(abci::response::CheckTx {
                            code: Code::Err(NonZero::new(1).expect("1 != 0")),
                            log: e,
                            ..Default::default()
                        }))
                    };

                    if let Err(e) = state.deliver_tx(&check_tx.tx).await {
                        return reject(e.to_string());
                    }

                    // Discard the forked state after CheckTx (explicitly).
                    state.abort();

                    Ok(abci::Response::CheckTx(abci::response::CheckTx::default()))
                }
                abci::Request::DeliverTx(abci::request::DeliverTx { tx: tx_bytes }) => {
                    let reject = |e| {
                        warn!(%e);
                        Ok(abci::Response::DeliverTx(abci::response::DeliverTx {
                            code: Code::Err(NonZero::new(1).expect("1 != 0")),
                            log: e,
                            ..Default::default()
                        }))
                    };

                    if let Err(e) = state.deliver_tx(&tx_bytes).await {
                        return reject(e.to_string());
                    }

                    Ok(abci::Response::DeliverTx(
                        abci::response::DeliverTx::default(),
                    ))
                }
                abci::Request::EndBlock(end_block) => {
                    let response = state.end_block(end_block).await?;
                    Ok(abci::Response::EndBlock(response))
                }
                abci::Request::Commit => {
                    state.commit().await?;

                    Ok(abci::Response::Commit(abci::response::Commit {
                        data: state.root_hashes().await?.app_hash.into(),
                        ..Default::default()
                    }))
                }
                // Unimplemented ABCI methods:
                abci::Request::SetOption(_set_option) => {
                    Ok(abci::Response::SetOption(abci::response::SetOption {
                        code: Code::Err(NonZero::new(1).expect("1 != 0")),
                        log: "set option is not implemented".to_string(),
                        info: "".to_string(),
                    }))
                }
                abci::Request::Query(_query) => Ok(abci::Response::Query(abci::response::Query {
                    code: Code::Err(NonZero::new(1).expect("1 != 0")),
                    log: "query is not implemented".to_string(),
                    ..Default::default()
                })),
                abci::Request::ListSnapshots => Err("snapshots are not implemented".into()),
                abci::Request::OfferSnapshot(_offer_snapshot) => {
                    Err("snapshots are not implemented".into())
                }
                abci::Request::LoadSnapshotChunk(_load_snapshot_chunk) => {
                    Err("snapshots are not implemented".into())
                }
                abci::Request::ApplySnapshotChunk(_apply_snapshot_chunk) => {
                    Err("snapshots are not implemented".into())
                }
            }
        })
    }
}

impl Run for Start {
    async fn run(self) -> color_eyre::Result<()> {
        let Self { abci } = self;

        // Determine the internal and canonical storage directories:
        // TODO: allow overriding these via CLI args
        let directories = directories::ProjectDirs::from("press", "freedom", "felidae")
            .ok_or_eyre("could not determine storage directory")?;
        let storage_dir = directories.data_local_dir().join("storage").to_path_buf();
        std::fs::create_dir_all(&storage_dir)
            .or_else(|e| bail!("could not create storage directory: {e}"))?;

        // Load up the storage backend:
        let state = State::new(Store::init(storage_dir).await?);

        // All the ABCI services share the same core state:
        let core = CoreService { state };

        let (consensus, mempool, snapshot, info) = tower_abci::v034::split::service(core, 4);

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

        // TODO: serve snapshot JSON with whole thing at '/' and prefixes at '/.com.example'

        // Wait for everything to exit:
        tokio::select! {
            res = abci => res??,
        }

        Ok(())
    }
}
