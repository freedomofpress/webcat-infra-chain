use std::{
    env,
    net::{IpAddr, Ipv4Addr},
    num::NonZero,
    task::{Context, Poll},
};

use clap::Parser;
use color_eyre::eyre::{OptionExt, bail};
use felidae_state::{State, Store};
use felidae_types::transaction::AuthenticatedTx;
use futures::future::BoxFuture;
use tendermint::{
    abci::Code,
    block::Height,
    v0_34::abci::{self, ConsensusRequest, ConsensusResponse, MempoolResponse},
};
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
    storage: Store,
    pending: Option<State>,
}

impl Service<abci::MempoolRequest> for CoreService {
    type Response = abci::MempoolResponse;
    type Error = BoxError;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> std::task::Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: abci::MempoolRequest) -> Self::Future {
        info!(?req);

        // Create a new state for this request, which we will never commit:
        let mut state = State::new(self.storage.clone());

        Box::pin(async move {
            let reject = || {
                // Rejecting a transaction means returning a non-zero code
                Ok(MempoolResponse::CheckTx(abci::response::CheckTx {
                    code: Code::Err(NonZero::new(1).expect("1 != 0")),
                    ..Default::default()
                }))
            };

            // Get the bytes of the transaction from the request:
            let abci::MempoolRequest::CheckTx(abci::request::CheckTx {
                tx: tx_bytes,
                kind: _,
            }) = req;

            // Parse the proto into the domain type, validating structure and verifying signatures:
            let Ok(tx) = AuthenticatedTx::from_proto(tx_bytes) else {
                warn!("failed to parse or authenticate transaction");
                return reject();
            };

            // Try to execute the transaction against the current state:
            if let Err(e) = state.deliver_authenticated_tx(&tx).await {
                warn!("transaction execution failed: {e}");
                return reject();
            }

            // Abort the state since this is just a mempool check:
            state.abort();

            Ok(MempoolResponse::CheckTx(abci::response::CheckTx::default()))
        })
    }
}

impl Service<ConsensusRequest> for CoreService {
    type Response = abci::ConsensusResponse;
    type Error = BoxError;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> std::task::Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: ConsensusRequest) -> Self::Future {
        info!(?req);

        let mut state = self
            .pending
            .clone()
            .expect("pending state must be initialized before consensus calls");

        Box::pin(async move {
            let response = match req {
                ConsensusRequest::InitChain(init_chain) => {
                    ConsensusResponse::InitChain(state.init_chain(init_chain).await?)
                }

                ConsensusRequest::BeginBlock(begin_block) => {
                    ConsensusResponse::BeginBlock(state.begin_block(begin_block).await?)
                }

                ConsensusRequest::DeliverTx(abci::request::DeliverTx { tx: tx_bytes }) => {
                    let reject = || {
                        // Rejecting a transaction means returning a non-zero code
                        Ok(ConsensusResponse::DeliverTx(abci::response::DeliverTx {
                            code: Code::Err(NonZero::new(1).expect("1 != 0")),
                            ..Default::default()
                        }))
                    };

                    // Parse the proto into the domain type, validating structure and verifying signatures:
                    let Ok(tx) = AuthenticatedTx::from_proto(tx_bytes) else {
                        warn!("failed to parse or authenticate transaction");
                        return reject();
                    };

                    // Try to execute the transaction against the current state:
                    if let Err(e) = state.deliver_authenticated_tx(&tx).await {
                        warn!("transaction execution failed: {e}");
                        return reject();
                    }

                    ConsensusResponse::DeliverTx(abci::response::DeliverTx::default())
                }

                ConsensusRequest::EndBlock(end_block) => {
                    ConsensusResponse::EndBlock(state.end_block(end_block).await?)
                }

                ConsensusRequest::Commit => {
                    state.commit().await?;

                    ConsensusResponse::Commit(abci::response::Commit {
                        data: state.root_hashes().await?.app_hash.into(),
                        ..Default::default()
                    })
                }
            };

            Ok(response)
        })
    }
}

impl Service<abci::InfoRequest> for CoreService {
    type Response = abci::InfoResponse;
    type Error = BoxError;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> std::task::Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: abci::InfoRequest) -> Self::Future {
        info!(?req);

        let storage = self.storage.clone();

        Box::pin(async move {
            Ok(match req {
                abci::InfoRequest::Info(abci::request::Info {
                    version: _,
                    block_version: _,
                    p2p_version: _,
                    abci_version: _,
                }) => {
                    // Create a read-only state to get current height and app hash
                    let state = State::new(storage);

                    // Get the current height, defaulting to 0 if uninitialized
                    let last_block_height =
                        state.block_height().await.unwrap_or(Height::from(0u32));

                    // Get the current app hash, defaulting to empty if uninitialized
                    let last_block_app_hash = state
                        .root_hashes()
                        .await
                        .map(|hashes| hashes.app_hash)
                        .unwrap_or_default();

                    abci::InfoResponse::Info(abci::response::Info {
                        data: env!("CARGO_PKG_NAME").to_string(),
                        version: env!("CARGO_PKG_VERSION").to_string(),
                        app_version: env!("CARGO_PKG_VERSION").to_string().parse().unwrap_or(0),
                        last_block_height,
                        last_block_app_hash,
                    })
                }
                abci::InfoRequest::Query(abci::request::Query {
                    data: _,
                    path: _,
                    height: _,
                    prove: _,
                }) => abci::InfoResponse::Query(abci::response::Query {
                    code: Code::Err(NonZero::new(1).expect("1 != 0")),
                    log: "query is not implemented".to_string(),
                    ..Default::default()
                }),
                abci::InfoRequest::Echo(abci::request::Echo { message }) => {
                    abci::InfoResponse::Echo(abci::response::Echo { message })
                }
                abci::InfoRequest::SetOption(abci::request::SetOption { key: _, value: _ }) => {
                    abci::InfoResponse::SetOption(abci::response::SetOption {
                        code: Code::Err(NonZero::new(1).expect("1 != 0")),
                        log: "set option is not implemented".to_string(),
                        info: "".to_string(),
                    })
                }
            })
        })
    }
}

impl Service<abci::SnapshotRequest> for CoreService {
    type Response = abci::SnapshotResponse;
    type Error = BoxError;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> std::task::Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: abci::SnapshotRequest) -> Self::Future {
        info!(?req);

        Box::pin(async move { Err("snapshots are not implemented".into()) })
    }
}

impl Run for Start {
    async fn run(self) -> color_eyre::Result<()> {
        let Self { abci } = self;

        // Determine the internal and canonical storage directories:
        // TODO: allow overriding these via CLI args
        // TODO: multiple storages means the possibility of a torn write: mitigate this?
        let directories = directories::ProjectDirs::from("press", "freedom", "felidae")
            .ok_or_eyre("could not determine storage directory")?;
        let storage_dir = directories.data_local_dir().join("storage").to_path_buf();
        std::fs::create_dir_all(&storage_dir)
            .or_else(|e| bail!("could not create storage directory: {e}"))?;

        // Load up the storage backend:
        let storage = Store::init(storage_dir).await?;

        // All the ABCI services share the same core state:
        let mut core = CoreService {
            storage: storage.clone(),
            pending: None,
        };

        // Start the ABCI server:
        let abci = tokio::spawn(async move {
            tower_abci::v034::ServerBuilder::default()
                .mempool(core.clone())
                .info(core.clone())
                .snapshot(core.clone())
                .consensus({
                    // In consensus, we need to keep track of pending state between calls:
                    core.pending = Some(State::new(storage));
                    core
                })
                .finish()
                .ok_or_eyre("could not construct ABCI server")?
                .listen_tcp((IpAddr::V4(Ipv4Addr::LOCALHOST), abci))
                .await
                .or_else(|e| {
                    bail!("could not start ABCI server on port {abci}: {e}");
                })
        });

        // Wait for everything to exit:
        tokio::select! {
            res = abci => res??,
        }

        Ok(())
    }
}
