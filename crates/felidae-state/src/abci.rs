use std::{
    num::NonZero,
    task::{Context, Poll},
};

use futures::future::BoxFuture;
use tendermint::{abci::Code, block::Height, v0_34::abci};
use tower::{BoxError, Service};
use tracing::Instrument;

impl Service<tendermint::v0_34::abci::Request> for crate::Store {
    type Response = tendermint::v0_34::abci::Response;
    type Error = BoxError;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> std::task::Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    #[instrument(name = "abci", skip(self, req))]
    fn call(&mut self, req: tendermint::v0_34::abci::Request) -> Self::Future {
        debug!(?req);

        let mut store: crate::Store = self.clone();

        Box::pin(async move {
            match req {
                abci::Request::Echo(echo) => Ok(abci::Response::Echo(abci::response::Echo {
                    message: echo.message,
                })),
                abci::Request::Flush => Ok(abci::Response::Flush),
                abci::Request::Info(_info) => {
                    let state = store.state.write().await;
                    let last_block_height =
                        state.block_height().await.unwrap_or(Height::from(0u32));
                    let last_block_app_hash = store
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
                    let response = store
                        .state
                        .write()
                        .await
                        .init_chain(init_chain)
                        .instrument(info_span!("InitChain"))
                        .await?;
                    Ok(abci::Response::InitChain(response))
                }
                abci::Request::BeginBlock(begin_block) => {
                    let response = store
                        .state
                        .write()
                        .await
                        .begin_block(begin_block)
                        .instrument(info_span!("BeginBlock"))
                        .await?;
                    Ok(abci::Response::BeginBlock(response))
                }
                abci::Request::CheckTx(check_tx) => {
                    // Fork the state so we can run DeliverTx without affecting the original state.
                    let store = store.fork().await;

                    let reject = |e: String| {
                        Ok(abci::Response::CheckTx(abci::response::CheckTx {
                            code: Code::Err(NonZero::new(1).expect("1 != 0")),
                            log: e,
                            ..Default::default()
                        }))
                    };

                    if let Err(e) = store
                        .state
                        .write()
                        .await
                        .deliver_tx(&check_tx.tx)
                        .instrument(info_span!("CheckTx"))
                        .await
                    {
                        return reject(e.to_string());
                    }

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

                    if let Err(e) = store
                        .state
                        .write()
                        .await
                        .deliver_tx(&tx_bytes)
                        .instrument(info_span!("DeliverTx"))
                        .await
                    {
                        return reject(e.to_string());
                    }

                    Ok(abci::Response::DeliverTx(
                        abci::response::DeliverTx::default(),
                    ))
                }
                abci::Request::EndBlock(end_block) => {
                    let response = store
                        .state
                        .write()
                        .await
                        .end_block(end_block)
                        .instrument(info_span!("EndBlock"))
                        .await?;
                    Ok(abci::Response::EndBlock(response))
                }
                abci::Request::Commit => {
                    store.commit().await?;

                    Ok(abci::Response::Commit(abci::response::Commit {
                        data: store.root_hashes().await?.app_hash.into(),
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
