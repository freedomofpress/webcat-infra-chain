use axum::{Router, extract::State, http::StatusCode, response::Json, routing::post};
use color_eyre::Report;
use felidae_types::FQDN;
use reqwest::Url;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{debug, info, warn};

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
    // Log incoming request for testing
    info!(
        raw_domain = %req.domain,
        raw_zone = %req.zone,
        node = %state.node,
        chain = ?state.chain,
        "received /observe API request"
    );
    debug!(
        "full request body: domain={}, zone={}",
        req.domain, req.zone
    );

    // Parse domain and zone
    let domain = match req.domain.parse::<FQDN>() {
        Ok(d) => {
            debug!(parsed_domain = %d, "successfully parsed domain");
            d
        }
        Err(e) => {
            warn!(raw_domain = %req.domain, error = %e, "failed to parse domain");
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
        Ok(z) => {
            debug!(parsed_zone = %z, "successfully parsed zone");
            z
        }
        Err(e) => {
            warn!(raw_zone = %req.zone, error = %e, "failed to parse zone");
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

    info!(
        domain = %domain,
        zone = %zone,
        "parsed observation request, starting observation"
    );

    // Perform the observation
    info!(
        domain = %domain,
        zone = %zone,
        node = %state.node,
        "calling observe_domain function"
    );

    match observe_domain(
        domain.clone(),
        zone.clone(),
        state.node.clone(),
        state.chain.clone(),
        state.homedir.as_deref(),
    )
    .await
    {
        Ok(()) => {
            info!(
                domain = %domain,
                zone = %zone,
                "observation submitted successfully"
            );
            Ok(Json(ObserveResponse {
                success: true,
                message: "observation submitted successfully".to_string(),
                tx_hash: None, // TODO: could return tx hash if we modify observe_domain?
            }))
        }
        Err(e) => {
            warn!(
                domain = %domain,
                zone = %zone,
                error = %e,
                "observation failed"
            );
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
