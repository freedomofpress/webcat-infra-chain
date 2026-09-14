//! Turn a panic in the ABCI service into process death.
//!
//! `tower_abci`'s `listen_tcp` spawns a task per accepted connection and never
//! looks at it again (`tower-abci-0.19.1`, `src/v038/server.rs:173`), so a
//! panic while serving a request kills only that connection. The listener task
//! stays pending, the `select!` in [`super::Start::run`] never fires, and the
//! node lingers on with a query port that still answers and no consensus
//! behind it. Wrapping the service closes that gap: a panic here takes the
//! process with it, and whatever supervises the node gets its chance to
//! restart it.
//!
//! This is deliberately narrower than `panic = "abort"`. Query handlers are
//! read-only and already turn their errors into 500s, so a panic serving a
//! request from the outside should not cost the node its consensus connection.

use std::{
    any::Any,
    panic::AssertUnwindSafe,
    sync::Arc,
    task::{Context, Poll},
};

use futures::{FutureExt, future::BoxFuture};
use tendermint::v0_38::abci::{Request, Response};
use tower::{BoxError, Service};

/// What to do with a caught panic. Production aborts; tests substitute a
/// recorder so they can observe the decision without dying for it.
type OnPanic = Arc<dyn Fn(Box<dyn Any + Send>) + Send + Sync>;

/// Wraps an ABCI service so that a panic inside it ends the process.
pub struct FailFast<S> {
    inner: S,
    on_panic: OnPanic,
}

impl<S> FailFast<S> {
    /// Wrap `inner` so that a panic aborts the node.
    pub fn new(inner: S) -> Self {
        Self::with_handler(
            inner,
            Arc::new(|_| {
                // `color_eyre`'s hook has already printed the panic report by
                // the time we unwind to here, so just say why we are leaving.
                error!("ABCI service panicked; aborting so the node can be restarted");
                std::process::abort()
            }),
        )
    }

    fn with_handler(inner: S, on_panic: OnPanic) -> Self {
        Self { inner, on_panic }
    }
}

/// Hand a caught panic to `on_panic`, then surface it as a service error.
///
/// The error is mostly a formality: in production `on_panic` never returns.
fn panicked(on_panic: &OnPanic, payload: Box<dyn Any + Send>) -> BoxError {
    on_panic(payload);
    BoxError::from("ABCI service panicked")
}

/// Run `f`, routing a panic out of band rather than letting it unwind.
///
/// [`AssertUnwindSafe`] is honest here because nothing resumes: the state the
/// panic may have poisoned is never read again on this side of `on_panic`.
fn guard<T>(on_panic: &OnPanic, f: impl FnOnce() -> T) -> Result<T, BoxError> {
    std::panic::catch_unwind(AssertUnwindSafe(f)).map_err(|payload| panicked(on_panic, payload))
}

impl<S> Service<Request> for FailFast<S>
where
    S: Service<Request, Response = Response, Error = BoxError>,
    S::Future: Send + 'static,
{
    type Response = Response;
    type Error = BoxError;
    type Future = BoxFuture<'static, Result<Response, BoxError>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let on_panic = self.on_panic.clone();
        match guard(&on_panic, || self.inner.poll_ready(cx)) {
            Ok(ready) => ready,
            Err(e) => Poll::Ready(Err(e)),
        }
    }

    fn call(&mut self, req: Request) -> Self::Future {
        let on_panic = self.on_panic.clone();
        // Both halves can panic: building the future, and polling it. The
        // cnidarium delta panic that motivated this lands in the second.
        let started = guard(&on_panic, || self.inner.call(req));
        Box::pin(async move {
            match started {
                Err(e) => Err(e),
                Ok(future) => AssertUnwindSafe(future)
                    .catch_unwind()
                    .await
                    .unwrap_or_else(|payload| Err(panicked(&on_panic, payload))),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    /// Stands in for the cnidarium delta panic, on either side of the await.
    struct Panics {
        in_future: bool,
    }

    impl Service<Request> for Panics {
        type Response = Response;
        type Error = BoxError;
        type Future = BoxFuture<'static, Result<Response, BoxError>>;

        fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _: Request) -> Self::Future {
            if self.in_future {
                Box::pin(async { panic!("delta must not have been applied") })
            } else {
                panic!("delta must not have been applied")
            }
        }
    }

    /// Drive one request through the wrapper, reporting how often the panic
    /// handler fired and whether the caller saw an error.
    async fn call_once(in_future: bool) -> (usize, bool) {
        let hits = Arc::new(AtomicUsize::new(0));
        let seen = hits.clone();
        let mut service = FailFast::with_handler(
            Panics { in_future },
            Arc::new(move |_| {
                seen.fetch_add(1, Ordering::SeqCst);
            }),
        );

        let result = service.call(Request::Flush).await;
        (hits.load(Ordering::SeqCst), result.is_err())
    }

    #[tokio::test]
    async fn a_panic_while_polling_the_future_is_caught() {
        assert_eq!(call_once(true).await, (1, true));
    }

    #[tokio::test]
    async fn a_panic_while_building_the_future_is_caught() {
        assert_eq!(call_once(false).await, (1, true));
    }
}
