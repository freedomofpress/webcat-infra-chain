use std::{
    num::NonZero,
    task::{Context, Poll},
};

use futures::future::BoxFuture;
use prost::bytes::Bytes;
use tendermint::{abci::Code, block::Height, v0_38::abci};
use tower::{BoxError, Service};
use tracing::Instrument;

/// This is where we translate ABCI requests into calls into our Store implementation.
///
/// It is relatively straightforward, mapping each ABCI request to the corresponding method on the
/// Store's State. The *MOST IMPORTANT THING* to note is that CheckTx *must not* modify the state;
/// instead, it should fork the state and apply the transaction to the forked state only, discarding
/// any ephemeral changes afterwards.
impl Service<tendermint::v0_38::abci::Request> for crate::Store {
    type Response = tendermint::v0_38::abci::Response;
    type Error = BoxError;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> std::task::Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    #[instrument(name = "abci", skip(self, req))]
    fn call(&mut self, req: tendermint::v0_38::abci::Request) -> Self::Future {
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
                abci::Request::FinalizeBlock(finalize_block) => {
                    let mut response = store
                        .state
                        .write()
                        .await
                        .finalize_block(finalize_block)
                        .instrument(info_span!("FinalizeBlock"))
                        .await?;
                    // ABCI -> ABCI++ migration note: Compute the app hash after all state changes are made (ABCI 2.0)
                    // and then record it.
                    response.app_hash = store.root_hashes().await?.app_hash;
                    let current_height = store
                        .state
                        .read()
                        .await
                        .block_height()
                        .await
                        .unwrap_or(Height::from(0u32));
                    if current_height.value() > 0 {
                        store
                            .state
                            .write()
                            .await
                            .record_app_hash(response.app_hash.clone())
                            .await?;
                    }
                    Ok(abci::Response::FinalizeBlock(response))
                }
                abci::Request::CheckTx(check_tx) => {
                    // !!! EXTREMELY IMPORTANT !!!
                    // Fork the state so we can run DeliverTx without affecting the original state:
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
                abci::Request::Commit => {
                    store.commit().await?;

                    // In ABCI 2.0, app_hash is returned in FinalizeBlock, not Commit
                    Ok(abci::Response::Commit(abci::response::Commit {
                        ..Default::default()
                    }))
                }
                // Unimplemented ABCI methods:
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
                // minimal ABCI++ methods impls
                abci::Request::PrepareProposal(prepare_proposal) => {
                    let mut txs = Vec::new();
                    let mut total_bytes = 0i64;
                    let max_bytes = prepare_proposal.max_tx_bytes;
                    for tx in prepare_proposal.txs {
                        let tx_len = tx.len() as i64;
                        if total_bytes + tx_len > max_bytes {
                            break;
                        }
                        total_bytes += tx_len;
                        txs.push(tx);
                    }
                    Ok(abci::Response::PrepareProposal(
                        abci::response::PrepareProposal { txs },
                    ))
                }
                abci::Request::ProcessProposal(_process_proposal) => Ok(
                    abci::Response::ProcessProposal(abci::response::ProcessProposal::Accept),
                ),
                abci::Request::ExtendVote(_extend_vote) => {
                    Ok(abci::Response::ExtendVote(abci::response::ExtendVote {
                        vote_extension: Bytes::new(),
                    }))
                }
                abci::Request::VerifyVoteExtension(verify_vote_extension) => {
                    let status = if verify_vote_extension.vote_extension.is_empty() {
                        abci::response::VerifyVoteExtension::Accept
                    } else {
                        abci::response::VerifyVoteExtension::Reject
                    };
                    Ok(abci::Response::VerifyVoteExtension(status))
                }
            }
        })
    }
}
