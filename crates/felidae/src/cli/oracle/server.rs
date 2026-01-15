use axum::{
    Router,
    extract::{Query, State},
    http::StatusCode,
    response::Json,
    routing::{get, post},
};
use color_eyre::Report;
use felidae_types::FQDN;
use getrandom::getrandom;
use reqwest::Url;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, info, warn};

use super::{Server, observe_domain, zone};

#[derive(Deserialize)]
struct ObserveRequest {
    domain: String,
    pow_token: PoWToken,
}

#[derive(Deserialize, Serialize, Clone)]
struct PoWToken {
    challenge: String,
    nonce: u64,
    timestamp: u64,
}

#[derive(Serialize)]
struct PoWChallengeResponse {
    challenge: String,
    timestamp: u64,
    difficulty: u8,
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
    pow_secret: String,
    pow_difficulty: u8,
}

pub async fn run(server: Server) -> Result<(), Report> {
    let Server {
        port,
        host,
        node,
        chain,
        homedir,
    } = server;

    // Load or generate PoW secret (persisted to file for consistency across restarts)
    let pow_secret = load_or_generate_pow_secret(homedir.as_deref()).await?;

    // Get PoW difficulty from environment, so we can tune this via envvar if it needs to be adjusted
    let pow_difficulty: u8 = std::env::var("POW_DIFFICULTY")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(19)
        .max(8); // Minimum difficulty of 8 bits

    let state = Arc::new(AppState {
        node,
        chain,
        homedir,
        pow_secret,
        pow_difficulty,
    });

    let app = Router::new()
        .route("/observe", post(handle_observe))
        .route("/pow-challenge", get(handle_pow_challenge))
        .route("/health", axum::routing::get(|| async { "OK" }))
        .with_state(state);

    let addr = format!("{}:{}", host, port);
    info!(addr = %addr, "starting oracle API server");

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

/// Get the path to the PoW secret file
async fn pow_secret_path(
    homedir: Option<&std::path::Path>,
) -> color_eyre::Result<std::path::PathBuf> {
    let oracle_dir = if let Some(homedir) = homedir {
        homedir.to_path_buf()
    } else {
        let directories = directories::ProjectDirs::from("press", "freedom", "felidae-oracle")
            .ok_or_else(|| {
                color_eyre::eyre::eyre!("could not determine internal storage directory")
            })?;
        directories.data_local_dir().to_path_buf()
    };

    tokio::fs::create_dir_all(&oracle_dir).await?;

    let secret_path = oracle_dir.join("pow_secret.hex");
    Ok(secret_path)
}

/// Load or generate PoW secret
async fn load_or_generate_pow_secret(
    homedir: Option<&std::path::Path>,
) -> color_eyre::Result<String> {
    let secret_path = pow_secret_path(homedir).await?;

    if secret_path.exists() {
        // Load existing secret
        let secret_hex = tokio::fs::read_to_string(&secret_path).await.map_err(|e| {
            color_eyre::eyre::eyre!(
                "failed to read PoW secret from {}: {}",
                secret_path.display(),
                e
            )
        })?;
        let secret = secret_hex.trim().to_string();
        info!("Loaded PoW secret from {}", secret_path.display());
        Ok(secret)
    } else {
        // Generate new secret
        let mut secret_bytes = [0u8; 32];
        getrandom(&mut secret_bytes)
            .map_err(|e| color_eyre::eyre::eyre!("failed to generate random secret: {}", e))?;
        let secret = hex::encode(secret_bytes);

        tokio::fs::write(&secret_path, &secret).await.map_err(|e| {
            color_eyre::eyre::eyre!(
                "failed to write PoW secret to {}: {}",
                secret_path.display(),
                e
            )
        })?;

        info!(
            "Generated new PoW secret and saved to {}",
            secret_path.display()
        );
        Ok(secret)
    }
}

/// Generate a domain-bound PoW challenge
fn generate_pow_challenge(domain: &str, timestamp: u64, secret: &str) -> String {
    let data = format!("{}:{}:{}", domain, timestamp, secret);
    let mut hasher = Sha256::new();
    hasher.update(data.as_bytes());
    hex::encode(hasher.finalize())
}

/// Validate a PoW token
fn validate_pow_token(token: &PoWToken, domain: &str, secret: &str, difficulty: u8) -> bool {
    // Reconstruct and verify challenge
    let expected_challenge = generate_pow_challenge(domain, token.timestamp, secret);
    if expected_challenge != token.challenge {
        warn!("PoW challenge mismatch");
        return false;
    }

    // Check timestamp (5 minute window)
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let age = now.abs_diff(token.timestamp);

    if age > 5 * 60 {
        warn!("PoW token expired (age: {}s)", age);
        return false;
    }

    // Verify PoW: hash(challenge + nonce) must have at least 'difficulty' leading zero bits
    let hash_input = format!("{}{}", token.challenge, token.nonce);
    let mut hasher = Sha256::new();
    hasher.update(hash_input.as_bytes());
    let hash = hasher.finalize();

    // Count leading zero bits
    let mut leading_zeros = 0;
    for byte in hash.iter() {
        if *byte == 0 {
            leading_zeros += 8;
        } else {
            leading_zeros += byte.leading_zeros() as u8;
            break;
        }
    }

    if leading_zeros < difficulty {
        warn!(
            "PoW insufficient (got {} leading zeros, need {})",
            leading_zeros, difficulty
        );
        return false;
    }

    true
}

/// Handle PoW challenge request
async fn handle_pow_challenge(
    State(state): State<Arc<AppState>>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> Result<Json<PoWChallengeResponse>, (StatusCode, Json<ObserveResponse>)> {
    let domain = params.get("domain").ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(ObserveResponse {
                success: false,
                message: "domain parameter is required".to_string(),
                tx_hash: None,
            }),
        )
    })?;

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let challenge = generate_pow_challenge(domain, timestamp, &state.pow_secret);

    info!(
        domain = %domain,
        timestamp = timestamp,
        "generated PoW challenge"
    );

    Ok(Json(PoWChallengeResponse {
        challenge,
        timestamp,
        difficulty: state.pow_difficulty,
    }))
}

async fn handle_observe(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ObserveRequest>,
) -> Result<Json<ObserveResponse>, (StatusCode, Json<ObserveResponse>)> {
    // Log incoming request
    info!(
        raw_domain = %req.domain,
        node = %state.node,
        chain = ?state.chain,
        "received /observe API request"
    );
    debug!("full request body: domain={}", req.domain);

    // Validate PoW token
    let normalized_domain = req.domain.trim().trim_end_matches('.').to_string();
    if !validate_pow_token(
        &req.pow_token,
        &normalized_domain,
        &state.pow_secret,
        state.pow_difficulty,
    ) {
        warn!(domain = %req.domain, "PoW validation failed");
        return Err((
            StatusCode::FORBIDDEN,
            Json(ObserveResponse {
                success: false,
                message: "Invalid or expired PoW token".to_string(),
                tx_hash: None,
            }),
        ));
    }
    info!(domain = %req.domain, "PoW token validated successfully");

    // Parse domain
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

    // Infer zone from domain using Mozilla Public Suffix List (PSL)
    let zone = match zone::infer_zone(&domain) {
        Ok(z) => {
            debug!(inferred_zone = %z, "successfully inferred zone");
            z
        }
        Err(e) => {
            warn!(domain = %domain, error = %e, "failed to infer zone");
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ObserveResponse {
                    success: false,
                    message: format!("failed to infer zone from domain: {}", e),
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
