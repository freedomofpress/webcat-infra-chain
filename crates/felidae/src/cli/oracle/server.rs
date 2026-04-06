use axum::{
    Router,
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Json},
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
use thiserror::Error;
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

/// User-facing errors that can occur during an observation request. Used to
/// convert internal errors to user-visible message and HTTP status code.
#[derive(Error, Debug)]
pub enum ObserveError {
    #[error("Domain parameter is required")]
    MissingDomainParameter,
    #[error("Invalid or expired PoW token")]
    InvalidPoWToken,
    #[error("Invalid domain")]
    InvalidDomain,
    #[error("Failed to infer zone from domain")]
    ZoneInferenceFailed,
    #[error("Observation already submitted — your request is being processed.")]
    AlreadySubmitted,
    #[error("This oracle is not authorized to submit observations.")]
    OracleNotAuthorized,
    #[error("Submission timed out. Please try again.")]
    SubmissionTimeout,
    #[error("Submission failed due to a timing issue. Please try again.")]
    BlockstampInFuture,
    #[error("This domain is not enrolled and cannot be unenrolled.")]
    CannotUnenrollNotEnrolled,
    #[error("The subdomain limit for this domain has been reached.")]
    SubdomainLimitExceeded,
    #[error("The domain is not valid for enrollment under its zone.")]
    InvalidDomainForZone,
    #[error("Observation was rejected by the network.")]
    NetworkRejected,
    #[error("Network error communicating with the chain. Please try again.")]
    NetworkError,
    #[error("Observation failed. Please try again later.")]
    ObservationFailed,
}

impl ObserveError {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::MissingDomainParameter => StatusCode::BAD_REQUEST,
            Self::InvalidPoWToken => StatusCode::FORBIDDEN,
            Self::InvalidDomain => StatusCode::BAD_REQUEST,
            Self::ZoneInferenceFailed => StatusCode::BAD_REQUEST,
            Self::AlreadySubmitted => StatusCode::INTERNAL_SERVER_ERROR,
            Self::OracleNotAuthorized => StatusCode::INTERNAL_SERVER_ERROR,
            Self::SubmissionTimeout => StatusCode::INTERNAL_SERVER_ERROR,
            Self::BlockstampInFuture => StatusCode::INTERNAL_SERVER_ERROR,
            Self::CannotUnenrollNotEnrolled => StatusCode::UNPROCESSABLE_ENTITY,
            Self::SubdomainLimitExceeded => StatusCode::UNPROCESSABLE_ENTITY,
            Self::InvalidDomainForZone => StatusCode::UNPROCESSABLE_ENTITY,
            Self::NetworkRejected => StatusCode::INTERNAL_SERVER_ERROR,
            Self::NetworkError => StatusCode::INTERNAL_SERVER_ERROR,
            Self::ObservationFailed => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

impl IntoResponse for ObserveError {
    fn into_response(self) -> axum::response::Response {
        let body = Json(ObserveResponse {
            success: false,
            message: self.to_string(),
            tx_hash: None,
        });
        (self.status_code(), body).into_response()
    }
}

fn observation_error(e: &Report) -> ObserveError {
    let diagnostic = format!("{e}");

    if diagnostic.contains("tx already exists in cache") {
        ObserveError::AlreadySubmitted
    } else if diagnostic.contains("not a current oracle") {
        ObserveError::OracleNotAuthorized
    } else if diagnostic.contains("blockstamp is too old")
        || diagnostic.contains("observation timeout")
    {
        ObserveError::SubmissionTimeout
    } else if diagnostic.contains("blockstamp is in the future") {
        ObserveError::BlockstampInFuture
    } else if diagnostic.contains("cannot vote to delete") {
        ObserveError::CannotUnenrollNotEnrolled
    } else if diagnostic.contains("would exceed max enrolled subdomains") {
        ObserveError::SubdomainLimitExceeded
    } else if diagnostic.contains("is not a subdomain of")
        || diagnostic.contains("must be a strict subdomain")
    {
        ObserveError::InvalidDomainForZone
    } else if diagnostic.contains("transaction rejected")
        || diagnostic.contains("transaction failed")
    {
        ObserveError::NetworkRejected
    } else if diagnostic.contains("invalid domain") || diagnostic.contains("failed to infer zone") {
        ObserveError::InvalidDomain
    } else if diagnostic.contains("timeout") || diagnostic.contains("connection") {
        ObserveError::NetworkError
    } else {
        ObserveError::ObservationFailed
    }
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
        bind,
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

    info!(addr = %bind, "starting oracle API server");

    let listener = tokio::net::TcpListener::bind(bind).await?;
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
) -> Result<Json<PoWChallengeResponse>, ObserveError> {
    let domain = params
        .get("domain")
        .ok_or(ObserveError::MissingDomainParameter)?;

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
) -> Result<Json<ObserveResponse>, ObserveError> {
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
        return Err(ObserveError::InvalidPoWToken);
    }
    info!(domain = %req.domain, "PoW token validated successfully");

    // Parse domain
    let domain = req.domain.parse::<FQDN>().map_err(|e| {
        warn!(raw_domain = %req.domain, error = %e, "failed to parse domain");
        ObserveError::InvalidDomain
    })?;
    debug!(parsed_domain = %domain, "successfully parsed domain");

    // Infer zone from domain using Mozilla Public Suffix List (PSL)
    let zone = zone::infer_zone(&domain).map_err(|e| {
        warn!(domain = %domain, error = %e, "failed to infer zone");
        ObserveError::ZoneInferenceFailed
    })?;
    debug!(inferred_zone = %zone, "successfully inferred zone");

    info!(
        domain = %domain,
        zone = %zone,
        "parsed observation request, starting observation"
    );

    // Perform the observation
    observe_domain(
        domain.clone(),
        zone.clone(),
        state.node.clone(),
        state.chain.clone(),
        state.homedir.as_deref(),
    )
    .await
    .map_err(|e| {
        warn!(domain = %domain, zone = %zone, error = %e, "observation failed");
        observation_error(&e)
    })?;

    info!(domain = %domain, zone = %zone, "observation submitted successfully");
    Ok(Json(ObserveResponse {
        success: true,
        message: "observation submitted successfully".to_string(),
        tx_hash: None,
    }))
}
