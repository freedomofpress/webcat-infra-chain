//! Validate configs under strict domain-type parsing (upgrade pre-flight).

use color_eyre::eyre::{WrapErr, bail, eyre};
use felidae_types::response::{AdminVote, PendingConfig};
use felidae_types::transaction::Config;
use prost::Message;
use reqwest::Url;
use std::io::Read;
use std::path::PathBuf;

use super::super::Run;

/// Validate config(s) under strict domain-type parsing.
///
/// Since validator public keys became typed, the strict parsers reject any
/// validator entry whose public key is not a well-formed 32-byte ed25519 key,
/// and clamp `u64` fields that exceed proto's `i64` range. This command pushes
/// each config through both parsing paths and reports pass/fail, without
/// touching the chain.
///
/// Note on scope: configs are fetched as JSON from the query endpoint, which
/// the node has *already* domain-parsed server-side, then reconstructed into
/// proto before decoding. So this does not read raw committed proto bytes — it
/// cannot reproduce old on-chain encodings (e.g. proto3 field absence from
/// pre-validator software; that case is pinned by a unit test in
/// felidae-types). Its live value over `query config` is twofold: it also
/// validates *staged* configs (`/admin/pending`, `/admin/votes`) that
/// `query config` never sees, and its proto round-trip catches the `u64`/`i64`
/// boundary that serde-only deserialization silently accepts.
///
/// With --url, fetches every surface where a config is persisted (`/config`,
/// `/admin/pending`, `/admin/votes`) from a live node's query endpoint.
/// Otherwise parses a single config JSON from a file or stdin, and also runs
/// the stateless semantic checks InitChain enforces — useful for pre-flighting
/// a draft genesis config or reconfigure before it reaches the chain.
#[derive(clap::Args)]
pub struct ParseConfig {
    /// Query endpoint of a live node (e.g. https://node.example.com:8080).
    /// Validates the current config, pending reconfigures, and admin votes.
    #[arg(long, conflicts_with = "file")]
    pub url: Option<Url>,

    /// Path to a config JSON file. If neither --url nor a file is given,
    /// reads a config JSON from stdin.
    pub file: Option<PathBuf>,
}

impl Run for ParseConfig {
    async fn run(self) -> color_eyre::Result<()> {
        match (self.url, self.file) {
            (Some(url), _) => validate_live(url).await,
            (None, Some(path)) => {
                let json = std::fs::read_to_string(&path)
                    .wrap_err_with(|| format!("reading {}", path.display()))?;
                validate_one(&json, &path.display().to_string())
            }
            (None, None) => {
                let mut json = String::new();
                std::io::stdin().read_to_string(&mut json)?;
                validate_one(&json, "stdin")
            }
        }
    }
}

/// Validate a single config JSON through both strict parsing paths, plus the
/// stateless semantic checks InitChain and reconfigure enforce (placeholder
/// identities, zero quorums, node-fatal validator tuning). Drafts only: live
/// surfaces skip this, since anything already committed has passed it.
fn validate_one(json: &str, source: &str) -> color_eyre::Result<()> {
    let config: Config = serde_json::from_str(json)
        .wrap_err_with(|| format!("{source}: failed strict domain-type deserialization"))?;
    roundtrip_via_proto(&config, source)?;
    config
        .check_stateless()
        .wrap_err_with(|| format!("{source}: failed semantic validation"))?;
    println!("{source}: ok — {}", summarize(&config));
    Ok(())
}

/// Fetch and validate every config surface served by a live node.
async fn validate_live(url: Url) -> color_eyre::Result<()> {
    let config_json = fetch(&url, "/config").await?;
    let config: Config = serde_json::from_str(&config_json)
        .wrap_err("live /config failed strict domain-type deserialization")?;
    roundtrip_via_proto(&config, "current config")?;
    println!("current config: ok — {}", summarize(&config));

    validate_list::<PendingConfig, _>(&url, "/admin/pending", "pending config", |p| &p.config)
        .await?;
    validate_list::<AdminVote, _>(&url, "/admin/votes", "admin vote", |v| &v.config).await?;

    Ok(())
}

/// Fetch a JSON array of config-bearing entries, validating and summarizing the
/// embedded `Config` of each. These surfaces are usually empty; when they are
/// not, each config is pushed through the same strict path as the current one.
async fn validate_list<T, F>(
    base: &Url,
    path: &str,
    label: &str,
    get_config: F,
) -> color_eyre::Result<()>
where
    T: serde::de::DeserializeOwned,
    F: Fn(&T) -> &Config,
{
    let json = fetch(base, path).await?;
    let items: Vec<T> = serde_json::from_str(&json)
        .wrap_err_with(|| format!("live {path} failed strict domain-type deserialization"))?;
    if items.is_empty() {
        println!("{label}s: none");
    }
    for (i, item) in items.iter().enumerate() {
        let config = get_config(item);
        let context = format!("{label} #{i}");
        roundtrip_via_proto(config, &context)?;
        println!("{context}: ok — {}", summarize(config));
    }
    Ok(())
}

/// Dense one-line summary of every parsed section, so a successful pre-flight
/// visibly confirms that oracles, admins, onion, and validator tuning all
/// decoded — not merely the validator list.
fn summarize(config: &Config) -> String {
    let admins = &config.admins;
    let oracles = &config.oracles;
    let vc = &config.validator_config;
    let flag = |b| if b { "enabled" } else { "disabled" };
    format!(
        "version {} | admins: {} (quorum {}/{}) | oracles: {}, {} authorized, max_subdomains {} | onion: {} | validators: {} | validator_cfg: window {}, missed_max {}, unjail_max {}",
        config.version,
        admins.authorized.len(),
        admins.voting.quorum.0,
        admins.voting.total.0,
        flag(oracles.enabled),
        oracles.authorized.len(),
        oracles.max_enrolled_subdomains,
        flag(config.onion.enabled),
        config.validators.len(),
        vc.uptime_window,
        vc.missed_blocks_max,
        vc.unjail_missed_max,
    )
}

async fn fetch(base: &Url, path: &str) -> color_eyre::Result<String> {
    let url = base.join(path)?;
    reqwest::Client::new()
        .get(url.clone())
        .send()
        .await
        .wrap_err_with(|| format!("GET {url}"))?
        .error_for_status()
        .wrap_err_with(|| format!("GET {url}"))?
        .text()
        .await
        .wrap_err_with(|| format!("GET {url}"))
}

/// Round-trip a domain `Config` through its protobuf encoding, exercising the
/// same prost decode + `TryFrom<proto::Config>` path an upgraded node uses when
/// reading a committed config out of state. Because the proto bytes are
/// reconstructed from an already-parsed `Config`, this proves conversion
/// symmetry and surfaces the `u64`/`i64` boundary; it does not re-decode the
/// original on-chain bytes.
fn roundtrip_via_proto(config: &Config, context: &str) -> color_eyre::Result<()> {
    let bytes = felidae_proto::transaction::Config::from(config.clone()).encode_to_vec();
    let decoded = felidae_proto::transaction::Config::decode(bytes.as_slice())
        .wrap_err_with(|| format!("{context}: proto decode failed"))?;
    let domain = Config::try_from(decoded)
        .map_err(|e| eyre!("{context}: strict proto -> domain parse failed: {e}"))?;
    if domain != *config {
        bail!("{context}: proto round-trip diverged from original");
    }
    Ok(())
}
