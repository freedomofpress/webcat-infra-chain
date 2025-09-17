use std::{
    env,
    net::{IpAddr, Ipv4Addr},
    num::NonZero,
    task::{Context, Poll},
};

use clap::Parser;
use color_eyre::eyre::{OptionExt, bail};
use felidae_proto as proto;
use felidae_types::transaction::Transaction;
use futures::future::BoxFuture;
use prost::{Message, bytes::Bytes};
use tendermint::{
    AppHash,
    abci::Code,
    block::Height,
    v0_34::abci::{self, ConsensusResponse, MempoolResponse},
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
pub struct Mempool {}

impl Service<abci::MempoolRequest> for Mempool {
    type Response = abci::MempoolResponse;
    type Error = BoxError;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> std::task::Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: abci::MempoolRequest) -> Self::Future {
        info!(?req);

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

            // Parse a proto from bytes:
            let Ok(tx_proto) = proto::transaction::Transaction::decode(tx_bytes) else {
                return reject();
            };

            // Parse the proto into the domain type, performing further validation:
            let Ok(tx) = Transaction::try_from(tx_proto) else {
                return reject();
            };

            // TODO: Speculatively execute the transaction against the chain state without
            // committing the results of the execution

            Ok(MempoolResponse::CheckTx(abci::response::CheckTx::default()))
        })
    }
}

#[derive(Clone)]
pub struct Consensus {}

impl Service<abci::ConsensusRequest> for Consensus {
    type Response = abci::ConsensusResponse;
    type Error = BoxError;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> std::task::Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: abci::ConsensusRequest) -> Self::Future {
        info!(?req);

        Box::pin(async move {
            Ok(match req {
                abci::ConsensusRequest::InitChain(abci::request::InitChain {
                    time: _,
                    chain_id,
                    consensus_params,
                    validators,
                    app_state_bytes,
                    initial_height,
                }) => {
                    // TODO: construct initial state from app_state_bytes
                    let app_state = String::from_utf8(app_state_bytes.to_vec())?;
                    info!(app_state);

                    let app_hash = AppHash::try_from(Bytes::new()).expect("invalid app hash"); // TODO: initial app hash

                    ConsensusResponse::InitChain(abci::response::InitChain {
                        consensus_params: Some(consensus_params),
                        validators,
                        app_hash,
                    })
                }

                abci::ConsensusRequest::BeginBlock(abci::request::BeginBlock {
                    hash,
                    header,
                    last_commit_info,
                    byzantine_validators,
                }) => ConsensusResponse::BeginBlock(abci::response::BeginBlock {
                    // TODO: tombstone byzantine validators
                    // TODO: track validator uptime
                    ..Default::default()
                }),

                abci::ConsensusRequest::DeliverTx(abci::request::DeliverTx { tx }) => {
                    // Delivering a transaction is just running its CheckTx logic again:
                    let mut mempool = Mempool {};
                    let MempoolResponse::CheckTx(abci::response::CheckTx {
                        code,
                        data,
                        log,
                        info,
                        gas_wanted,
                        gas_used,
                        events,
                        codespace,
                        ..
                    }) = mempool
                        .call(abci::MempoolRequest::CheckTx(abci::request::CheckTx {
                            tx: tx.clone(),
                            kind: abci::request::CheckTxKind::New,
                        }))
                        .await?;

                    ConsensusResponse::DeliverTx(abci::response::DeliverTx {
                        code,
                        data,
                        log,
                        info,
                        gas_wanted,
                        gas_used,
                        events,
                        codespace,
                    })
                }

                abci::ConsensusRequest::EndBlock(abci::request::EndBlock { height: _ }) => {
                    ConsensusResponse::EndBlock(abci::response::EndBlock {
                        ..Default::default()
                    })
                }

                abci::ConsensusRequest::Commit => {
                    let app_hash = Bytes::new(); // TODO: calculate app hash

                    ConsensusResponse::Commit(abci::response::Commit {
                        data: app_hash,
                        ..Default::default()
                    })
                }
            })
        })
    }
}

#[derive(Clone)]
pub struct Info {}

impl Service<abci::InfoRequest> for Info {
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

#[derive(Clone)]
pub struct Snapshot {}

impl Service<abci::SnapshotRequest> for Snapshot {
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
        let mempool = Mempool {};
        let consensus = Consensus {};
        let info = Info {};
        let snapshot = Snapshot {};
        let server = tower_abci::v034::ServerBuilder::default()
            .mempool(mempool)
            .consensus(consensus)
            .info(info)
            .snapshot(snapshot)
            .finish()
            .ok_or_eyre("could not construct ABCI server")?;
        server
            .listen_tcp((IpAddr::V4(Ipv4Addr::LOCALHOST), abci))
            .await
            .or_else(|e| {
                bail!("could not start ABCI server on port {abci}: {e}");
            })?;
        Ok(())
    }
}
