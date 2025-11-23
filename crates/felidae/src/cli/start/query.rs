use axum::body::Body;
use axum::{Router, extract::Path, routing::get};
use cnidarium::{StateDelta, Storage};
use color_eyre::Report;
use felidae_admin::HashObserved;
use felidae_state::{State, Vote};
use felidae_types::transaction::{Config, Domain, Empty};
use fqdn::FQDN;
use futures::StreamExt;
use reqwest::StatusCode;
use serde::Serialize;
use tendermint::Time;

pub fn app(storage: Storage) -> Router {
    let config = {
        let storage = storage.clone();
        move || async move {
            let state = State::new(StateDelta::new(storage.latest_snapshot()));
            match state.config().await {
                Err(e) => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    [("Content-Type", "text/plain")],
                    Body::from(e.to_string()),
                ),
                Ok(config) => (
                    StatusCode::OK,
                    [("Content-Type", "application/json")],
                    Body::from(serde_json::to_string_pretty(&config).unwrap()),
                ),
            }
        }
    };

    let admin_votes = {
        let storage = storage.clone();
        move || async move {
            let state = State::new(StateDelta::new(storage.latest_snapshot()));

            let get_votes = async move {
                let mut state = state;
                let vote_queue = state.admin_voting().await?;
                let votes = vote_queue.votes_for_key_prefix(Empty, None).await?;
                #[derive(Serialize)]
                struct AdminVote {
                    admin: String,
                    time: Time,
                    config: Config,
                }
                let votes: Vec<AdminVote> = votes
                    .into_iter()
                    .map(
                        |Vote {
                             party, time, value, ..
                         }| {
                            AdminVote {
                                admin: party,
                                time,
                                config: value,
                            }
                        },
                    )
                    .collect();
                Ok::<_, Report>(votes)
            };

            match get_votes.await {
                Err(e) => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    [("Content-Type", "text/plain")],
                    Body::from(e.to_string()),
                ),
                Ok(votes) => (
                    StatusCode::OK,
                    [("Content-Type", "application/json")],
                    Body::from(serde_json::to_string_pretty(&votes).unwrap()),
                ),
            }
        }
    };

    let oracle_votes = || {
        let storage = storage.clone();
        move |domain: Domain| async move {
            let state = State::new(StateDelta::new(storage.latest_snapshot()));

            let get_votes = async move {
                let mut state = state;
                let vote_queue = state.oracle_voting().await?;
                // When the domain is not the root, include the trailing dot, so that we only get
                // actual subdomains as opposed to random similar prefixes, but for the root domain,
                // don't include the dot so we get every domain.
                let votes = if domain.name != FQDN::default() {
                    vote_queue
                        .votes_for_key_prefix(domain.into(), Some('.'))
                        .await?
                } else {
                    vote_queue
                        .votes_for_key_prefix(
                            Domain {
                                name: FQDN::default(),
                            }
                            .into(),
                            None,
                        )
                        .await?
                };
                #[derive(Serialize)]
                struct OracleVote {
                    oracle: String,
                    time: Time,
                    domain: Domain,
                    hash: HashObserved,
                }
                let votes: Vec<OracleVote> = votes
                    .into_iter()
                    .map(
                        |Vote {
                             party,
                             time,
                             value,
                             key,
                         }| {
                            OracleVote {
                                oracle: party,
                                time,
                                domain: key.into(),
                                hash: value,
                            }
                        },
                    )
                    .collect();
                Ok::<_, Report>(votes)
            };

            match get_votes.await {
                Err(e) => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    [("Content-Type", "text/plain")],
                    Body::from(e.to_string()),
                ),
                Ok(votes) => (
                    StatusCode::OK,
                    [("Content-Type", "application/json")],
                    Body::from(serde_json::to_string_pretty(&votes).unwrap()),
                ),
            }
        }
    };

    let admin_pending = {
        let storage = storage.clone();
        move || async move {
            let state = State::new(StateDelta::new(storage.latest_snapshot()));

            let get_pending = async move {
                let mut state = state;
                let vote_queue = state.admin_voting().await?;
                let pending = vote_queue.pending_for_key_prefix(Empty, None).await?;
                #[derive(Serialize)]
                struct PendingConfig {
                    time: Time,
                    config: Config,
                }
                let pending: Vec<PendingConfig> = pending
                    .into_iter()
                    .map(|(time, _, value)| PendingConfig {
                        time,
                        config: value,
                    })
                    .collect();
                Ok::<_, Report>(pending)
            };

            match get_pending.await {
                Err(e) => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    [("Content-Type", "text/plain")],
                    Body::from(e.to_string()),
                ),
                Ok(pending) => (
                    StatusCode::OK,
                    [("Content-Type", "application/json")],
                    Body::from(serde_json::to_string_pretty(&pending).unwrap()),
                ),
            }
        }
    };

    let oracle_pending = || {
        let storage = storage.clone();
        move |domain: Domain| async move {
            let state = State::new(StateDelta::new(storage.latest_snapshot()));

            let get_pending = async move {
                let mut state = state;
                let vote_queue = state.oracle_voting().await?;
                // When the domain is not the root, include the trailing dot, so that we only get
                // actual subdomains as opposed to random similar prefixes, but for the root domain,
                // don't include the dot so we get every domain.
                let pending = if domain.name != FQDN::default() {
                    vote_queue
                        .pending_for_key_prefix(domain.into(), Some('.'))
                        .await?
                } else {
                    vote_queue
                        .pending_for_key_prefix(
                            Domain {
                                name: FQDN::default(),
                            }
                            .into(),
                            None,
                        )
                        .await?
                };
                #[derive(Serialize)]
                struct PendingObservation {
                    time: Time,
                    domain: Domain,
                    hash: HashObserved,
                }
                let pending: Vec<PendingObservation> = pending
                    .into_iter()
                    .map(|(time, key, value)| PendingObservation {
                        time,
                        domain: key.into(),
                        hash: value,
                    })
                    .collect();
                Ok::<_, Report>(pending)
            };

            match get_pending.await {
                Err(e) => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    [("Content-Type", "text/plain")],
                    Body::from(e.to_string()),
                ),
                Ok(pending) => (
                    StatusCode::OK,
                    [("Content-Type", "application/json")],
                    Body::from(serde_json::to_string_pretty(&pending).unwrap()),
                ),
            }
        }
    };

    let oracles = {
        let storage = storage.clone();
        move || async move {
            let state = State::new(StateDelta::new(storage.latest_snapshot()));
            match state.config().await {
                Err(e) => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    [("Content-Type", "text/plain")],
                    Body::from(e.to_string()),
                ),
                Ok(config) => {
                    #[derive(Serialize)]
                    struct OracleInfo {
                        identity: String,
                        endpoint: String,
                    }
                    let oracles: Vec<OracleInfo> = config
                        .oracles
                        .authorized
                        .into_iter()
                        .map(|oracle| OracleInfo {
                            identity: hex::encode(oracle.identity),
                            endpoint: oracle.endpoint,
                        })
                        .collect();
                    (
                        StatusCode::OK,
                        [("Content-Type", "application/json")],
                        Body::from(serde_json::to_string_pretty(&oracles).unwrap()),
                    )
                }
            }
        }
    };

    let snapshot = || {
        let storage = storage.clone();
        move |domain| async move {
            // Get a list of canonical subdomains for the given domain:
            let state = State::new(StateDelta::new(storage.latest_snapshot()));
            match state.canonical_subdomains_hashes(domain).await {
                Err(e) => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    [("Content-Type", "text/plain")],
                    Body::from(e.to_string()),
                ),
                Ok(stream) => {
                    // This is a streaming response to avoid collecting the entire snapshot
                    // in memory at once:
                    let entries = stream.enumerate().map(move |(i, result)| {
                        let (domain, hash) = result?;
                        let hash = hex::encode(hash);
                        let entry = if i == 0 {
                            format!("\"{domain}\":\"{hash}\"")
                        } else {
                            format!(",\"{domain}\":\"{hash}\"")
                        };
                        Ok::<_, Report>(entry)
                    });

                    (
                        StatusCode::OK,
                        [("Content-Type", "application/json")],
                        Body::from_stream(
                            futures::stream::once(async { Ok("{".to_string()) })
                                .chain(entries)
                                .chain(futures::stream::once(async { Ok("}".to_string()) })),
                        ),
                    )
                }
            }
        }
    };

    // Duplicate underlying services as needed for routing:
    let root_snapshot = snapshot();
    let domain_snapshot = snapshot();
    let root_oracle_votes = oracle_votes();
    let domain_oracle_votes = oracle_votes();
    let root_oracle_pending = oracle_pending();
    let domain_oracle_pending = oracle_pending();

    Router::new()
        .route("/config", get(move || async { config().await }))
        .route("/oracles", get(move || async { oracles().await }))
        .route("/admin/votes", get(move || async { admin_votes().await }))
        .route(
            "/admin/pending",
            get(move || async { admin_pending().await }),
        )
        .route(
            "/oracle/votes",
            get(move || async {
                root_oracle_votes(Domain {
                    name: FQDN::default(),
                })
                .await
            }),
        )
        .route(
            "/oracle/votes/{domain}",
            get(move |Path(domain): Path<String>| async move {
                match permissive_domain(domain) {
                    Ok(domain) => domain_oracle_votes(domain).await,
                    Err(e) => e,
                }
            }),
        )
        .route(
            "/oracle/pending",
            get(move || async {
                root_oracle_pending(Domain {
                    name: FQDN::default(),
                })
                .await
            }),
        )
        .route(
            "/oracle/pending/{domain}",
            get(move |Path(domain): Path<String>| async move {
                match permissive_domain(domain) {
                    Ok(domain) => domain_oracle_pending(domain).await,
                    Err(e) => e,
                }
            }),
        )
        .route(
            "/snapshot",
            get(move || async move {
                root_snapshot(Domain {
                    name: FQDN::default(),
                })
                .await
            }),
        )
        .route(
            "/snapshot/{domain}",
            get(move |Path(domain): Path<String>| async move {
                match permissive_domain(domain) {
                    Ok(domain) => domain_snapshot(domain).await,
                    Err(e) => e,
                }
            }),
        )
}

/// Parse the domain name, permissively.
#[allow(clippy::type_complexity)]
fn permissive_domain(
    domain: String,
) -> Result<Domain, (StatusCode, [(&'static str, &'static str); 1], Body)> {
    if domain.is_empty() {
        Ok(Domain {
            name: FQDN::default(),
        })
    } else {
        let mut canonicalized = domain.trim_matches('.').to_string();
        canonicalized.push('.');
        match FQDN::from_ascii_str(&canonicalized) {
            Ok(name) => Ok(Domain { name }),
            Err(e) => Err((
                StatusCode::BAD_REQUEST,
                [("Content-Type", "text/plain")],
                Body::from(format!("invalid domain name: {e}")),
            )),
        }
    }
}
