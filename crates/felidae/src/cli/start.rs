use std::{
    env,
    net::{IpAddr, Ipv4Addr},
    num::NonZero,
    task::{Context, Poll},
};

use clap::Parser;
use cnidarium::Storage;
use color_eyre::eyre::{OptionExt, bail};
use felidae_state::State;
use felidae_types::transaction::AuthenticatedTx;
use futures::future::BoxFuture;
use prost::bytes::Bytes;
use tendermint::{
    AppHash,
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
    /// Which port should the RPC server listen on?
    #[clap(long, default_value = "1371")]
    rpc: u16,
}

#[derive(Clone)]
pub struct CoreService {
    internal: Storage,
    canonical: Storage,
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
        let state = State::new(self.internal.clone(), self.canonical.clone());

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

        let mut state = State::new(self.internal.clone(), self.canonical.clone());

        Box::pin(async move {
            Ok(match req {
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
                        data: state.root_hashes().await?.app_hash.0.to_vec().into(),
                        ..Default::default()
                    })
                }
            })
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

        Box::pin(async move {
            Ok(match req {
                abci::InfoRequest::Info(abci::request::Info {
                    version,
                    block_version,
                    p2p_version,
                    abci_version,
                }) => abci::InfoResponse::Info(abci::response::Info {
                    data: env!("CARGO_PKG_NAME").to_string(),
                    version: env!("CARGO_PKG_VERSION").to_string(),
                    app_version: env!("CARGO_PKG_VERSION").to_string().parse().unwrap_or(0),
                    last_block_height: Height::from(0u32), // FIXME: return the correct height
                    last_block_app_hash: AppHash::try_from(Bytes::new()).expect("invalid app hash"), // FIXME: return the correct app hash
                }),
                abci::InfoRequest::Query(abci::request::Query {
                    data,
                    path,
                    height,
                    prove,
                }) => abci::InfoResponse::Query(abci::response::Query {
                    code: Code::Err(NonZero::new(1).expect("1 != 0")),
                    log: "query is not implemented".to_string(),
                    ..Default::default()
                }),
                abci::InfoRequest::Echo(abci::request::Echo { message }) => {
                    abci::InfoResponse::Echo(abci::response::Echo { message })
                }
                abci::InfoRequest::SetOption(abci::request::SetOption { key, value }) => {
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
        let Self { abci, rpc } = self;

        // Load up the internal and canonical storage backends:
        let internal = Storage::load(todo!("specify path"), vec![])
            .await
            .or_else(|e| {
                bail!("could not open storage at specified path: {e}");
            })?;
        let canonical = Storage::load(todo!("specify path"), vec![])
            .await
            .or_else(|e| {
                bail!("could not open storage at specified path: {e}");
            })?;

        // All the ABCI services share the same core state:
        let core = CoreService {
            internal: internal.clone(),
            canonical: canonical.clone(),
        };

        // Start the ABCI server:
        tower_abci::v034::ServerBuilder::default()
            .mempool(core.clone())
            .consensus(core.clone())
            .info(core.clone())
            .snapshot(core)
            .finish()
            .ok_or_eyre("could not construct ABCI server")?
            .listen_tcp((IpAddr::V4(Ipv4Addr::LOCALHOST), abci))
            .await
            .or_else(|e| {
                bail!("could not start ABCI server on port {abci}: {e}");
            })?;

        Ok(())
    }
}
