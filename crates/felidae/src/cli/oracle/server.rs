use axum::{Router, extract::State, http::StatusCode, response::Json, routing::post};
use color_eyre::Report;
use felidae_types::FQDN;
use reqwest::Url;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::info;

use super::{Server, observe_domain};

#[derive(Deserialize)]
struct ObserveRequest {
    domain: String,
    zone: String,
}

#[derive(Serialize)]
struct ObserveResponse {
    success: bool,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    tx_hash: Option<String>,
}

#[derive(Clone)]
struct AppState {
    node: Url,
    chain: Option<String>,
    homedir: Option<std::path::PathBuf>,
}

pub async fn run(server: Server) -> Result<(), Report> {
    let Server {
        port,
        host,
        node,
        chain,
        homedir,
    } = server;

    let state = Arc::new(AppState {
        node,
        chain,
        homedir,
    });

    let app = Router::new()
        .route("/observe", post(handle_observe))
        .route("/health", axum::routing::get(|| async { "OK" }))
        .with_state(state);

    let addr = format!("{}:{}", host, port);
    info!(addr = %addr, "starting oracle API server");

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

async fn handle_observe(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ObserveRequest>,
) -> Result<Json<ObserveResponse>, (StatusCode, Json<ObserveResponse>)> {
    // Parse domain and zone
    let domain = match req.domain.parse::<FQDN>() {
        Ok(d) => d,
        Err(e) => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ObserveResponse {
                    success: false,
                    message: format!("invalid domain: {}", e),
                    tx_hash: None,
                }),
            ));
        }
    };

    let zone = match req.zone.parse::<FQDN>() {
        Ok(z) => z,
        Err(e) => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ObserveResponse {
                    success: false,
                    message: format!("invalid zone: {}", e),
                    tx_hash: None,
                }),
            ));
        }
    };

    info!(domain = %domain, zone = %zone, "received observation request");

    // Perform the observation
    match observe_domain(
        domain,
        zone,
        state.node.clone(),
        state.chain.clone(),
        state.homedir.as_deref(),
    )
    .await
    {
        Ok(()) => Ok(Json(ObserveResponse {
            success: true,
            message: "observation submitted successfully".to_string(),
            tx_hash: None, // TODO: could return tx hash if we modify observe_domain?
        })),
        Err(e) => {
            info!(error = %e, "observation failed");
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ObserveResponse {
                    success: false,
                    message: format!("observation failed: {}", e),
                    tx_hash: None,
                }),
            ))
        }
    }
}
