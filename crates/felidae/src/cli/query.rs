//! Query subcommands for interacting with the Felidae query server.

use std::collections::HashMap;

use felidae_types::response::{
    AdminVote, ChainInfo, Health, OracleVote, PendingConfig, PendingObservation, ValidatorInfo,
};
use felidae_types::transaction::Config as ChainConfig;
use reqwest::Url;

use super::Run;

#[derive(clap::Args)]
pub struct Query {
    /// Felidae query server URL.
    #[clap(
        long,
        visible_alias = "node-url",
        default_value = "http://localhost:8080"
    )]
    pub query_url: Url,

    #[command(subcommand)]
    pub command: QueryCommand,
}

#[derive(clap::Subcommand)]
pub enum QueryCommand {
    /// Query basic chain info (height, chain ID, block time, app hash).
    ChainInfo(ChainInfoCmd),
    /// Ask whether a node is still committing blocks. Exits non-zero if not.
    Health(HealthCmd),
    /// Query canonical domain→hash mappings.
    Snapshot(Snapshot),
    /// Query active oracle votes in the vote queue.
    EnrollmentVotes(EnrollmentVotes),
    /// Query pending oracle observations awaiting promotion.
    EnrollmentPending(EnrollmentPending),
    /// Query active admin reconfiguration votes.
    AdminVotes(AdminVotes),
    /// Query pending admin config changes.
    AdminPending(AdminPending),
    /// Query current chain configuration.
    Config(Config),
    /// List validators on the chain, or look one up by id.
    #[command(visible_alias = "validator", visible_alias = "val")]
    Validators(Validators),
}

impl Run for Query {
    async fn run(self) -> color_eyre::Result<()> {
        let query_url = self.query_url;
        match self.command {
            QueryCommand::ChainInfo(cmd) => cmd.run(query_url).await,
            QueryCommand::Health(cmd) => cmd.run(query_url).await,
            QueryCommand::Snapshot(cmd) => cmd.run(query_url).await,
            QueryCommand::EnrollmentVotes(cmd) => cmd.run(query_url).await,
            QueryCommand::EnrollmentPending(cmd) => cmd.run(query_url).await,
            QueryCommand::AdminVotes(cmd) => cmd.run(query_url).await,
            QueryCommand::AdminPending(cmd) => cmd.run(query_url).await,
            QueryCommand::Config(cmd) => cmd.run(query_url).await,
            QueryCommand::Validators(cmd) => cmd.run(query_url).await,
        }
    }
}

#[derive(clap::Args)]
pub struct ChainInfoCmd {
    /// Emit output as JSON.
    #[clap(long)]
    pub json: bool,
}

impl ChainInfoCmd {
    async fn run(self, query_url: Url) -> color_eyre::Result<()> {
        let info: ChainInfo = reqwest::Client::new()
            .get(query_url.join("/chain-info")?)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;

        if self.json {
            println!("{}", serde_json::to_string(&info)?);
        } else {
            println!("Chain ID:     {}", info.chain_id);
            println!("Block Height: {}", info.block_height);
            println!("Block Time:   {}", info.block_time);
            println!("App Hash:     {}", info.app_hash);
        }
        Ok(())
    }
}

#[derive(clap::Args)]
pub struct HealthCmd {
    /// Emit output as JSON.
    #[clap(long)]
    pub json: bool,
    /// This node's CometBFT RPC, e.g. `http://127.0.0.1:26657`.
    ///
    /// With it, `health` can tell "this node is broken" from "the chain is
    /// stopped", which `/healthz` alone cannot. See the exit codes below.
    #[clap(long)]
    pub peer: Option<Url>,
}

/// What `health` concluded, and what an operator should do about it.
///
/// `/healthz` answers "am I still committing blocks", which is the right
/// question for routing and the wrong one for restarting. When a chain halts,
/// *every* node reports unhealthy -- including the ones that are working --
/// so a restart triggered by a 503 cycles the whole validator set without
/// fixing anything.
///
/// Comparing the app's height against the CometBFT process feeding it
/// separates the cases. A node whose ABCI service has died sits permanently
/// behind its own peer, because it panicked partway through a block. A healthy
/// node on a halted chain is level with its peer: both stopped at the same
/// height.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
enum Verdict {
    /// Committing blocks. Exit 0.
    Advancing,
    /// Not advancing and behind its own peer: this node is the problem.
    /// Exit 1.
    NodeBehind,
    /// Not advancing, but level with its CometBFT peer, so the chain is
    /// stopped rather than this node. Restarting will not help. Exit 2.
    ChainStopped,
    /// Replaying history. Its peer may lead by a block mid-apply, which is
    /// not a fault; restarting would only set the sync back. Exit 2.
    CatchingUp,
    /// No peer given, so the cases cannot be told apart. Exit 3.
    Unknown,
}

impl Verdict {
    fn code(self) -> i32 {
        match self {
            Verdict::Advancing => 0,
            Verdict::NodeBehind => 1,
            Verdict::ChainStopped | Verdict::CatchingUp => 2,
            Verdict::Unknown => 3,
        }
    }

    fn describe(self) -> &'static str {
        match self {
            Verdict::Advancing => "advancing",
            Verdict::NodeBehind => "this node is behind its own CometBFT peer",
            Verdict::ChainStopped => "chain stopped (this node is level with its peer)",
            Verdict::CatchingUp => "catching up",
            Verdict::Unknown => "not advancing (pass --peer to tell why)",
        }
    }

    /// Decide what the operator should do, not merely whether to route here.
    async fn judge(health: &Health, peer: Option<&Url>) -> Self {
        if health.healthy {
            return Verdict::Advancing;
        }
        let Some(peer) = peer else {
            return Verdict::Unknown;
        };
        let status = peer_status(peer).await.inspect_err(|e| {
            eprintln!("could not reach {peer}: {e}");
        });
        Self::against(health.block_height, status.ok())
    }

    /// Judge a stalled node against its peer's status. `None` means the peer
    /// did not answer, which is itself a broken node.
    fn against(app_height: u64, peer: Option<PeerStatus>) -> Self {
        match peer {
            None => Verdict::NodeBehind,
            Some(PeerStatus {
                catching_up: true, ..
            }) => Verdict::CatchingUp,
            Some(PeerStatus { height, .. }) if height > app_height => Verdict::NodeBehind,
            Some(_) => Verdict::ChainStopped,
        }
    }
}

/// The slice of CometBFT's `/status` that the verdict turns on.
struct PeerStatus {
    height: u64,
    catching_up: bool,
}

/// Where this node's CometBFT peer stands.
async fn peer_status(peer: &Url) -> color_eyre::Result<PeerStatus> {
    let status: serde_json::Value = probe_client()?
        .get(peer.join("/status")?)
        .send()
        .await?
        .json()
        .await?;
    let sync = status
        .pointer("/result/sync_info")
        .ok_or_else(|| color_eyre::eyre::eyre!("no sync_info in /status from {peer}"))?;
    let height = sync["latest_block_height"]
        .as_str()
        .and_then(|h| h.parse().ok())
        .ok_or_else(|| color_eyre::eyre::eyre!("could not read latest_block_height from {peer}"))?;
    Ok(PeerStatus {
        height,
        catching_up: sync["catching_up"].as_bool().unwrap_or(false),
    })
}

/// A health probe must answer, even about a process that hangs on its socket.
fn probe_client() -> color_eyre::Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()?)
}

impl HealthCmd {
    async fn run(self, query_url: Url) -> color_eyre::Result<()> {
        // Deliberately no `error_for_status`: an unhealthy node answers 503
        // with the very report we want to show.
        let response = probe_client()?
            .get(query_url.join("/healthz")?)
            .send()
            .await?;
        let status = response.status();
        let body = response.text().await?;

        let Ok(health) = serde_json::from_str::<Health>(&body) else {
            // A node that has not finished InitChain answers in plain text.
            eprintln!("node reported {status}: {}", body.trim());
            std::process::exit(1);
        };

        let verdict = Verdict::judge(&health, self.peer.as_ref()).await;
        if self.json {
            print_json(&health, verdict)?;
        } else {
            print_text(&health, verdict);
        }

        // Exit non-zero so this composes with shell health checks; exit 2
        // specifically means "do not restart this node".
        let code = verdict.code();
        if code != 0 {
            std::process::exit(code);
        }
        Ok(())
    }
}

fn print_json(health: &Health, verdict: Verdict) -> color_eyre::Result<()> {
    #[derive(serde::Serialize)]
    struct Out<'a> {
        verdict: Verdict,
        #[serde(flatten)]
        health: &'a Health,
    }
    println!("{}", serde_json::to_string(&Out { verdict, health })?);
    Ok(())
}

fn print_text(health: &Health, verdict: Verdict) {
    println!("Healthy:      {}", health.healthy);
    println!("Block Height: {}", health.block_height);
    println!("Block Time:   {}", health.block_time);
    println!(
        "Block Age:    {}s (tolerance {}s)",
        health.block_age_secs, health.tolerance_secs
    );
    println!("Verdict:      {}", verdict.describe());
}

#[derive(clap::Args)]
pub struct Snapshot {}

impl Snapshot {
    async fn run(self, query_url: Url) -> color_eyre::Result<()> {
        let response: HashMap<String, String> = reqwest::Client::new()
            .get(query_url.join("/snapshot")?)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;

        println!("{}", serde_json::to_string_pretty(&response)?);
        Ok(())
    }
}

#[derive(clap::Args)]
pub struct EnrollmentVotes {
    /// Filter by domain (optional).
    #[clap(long)]
    pub domain: Option<String>,
}

impl EnrollmentVotes {
    async fn run(self, query_url: Url) -> color_eyre::Result<()> {
        let endpoint = match &self.domain {
            Some(domain) => format!("/enrollment/votes/{}", domain),
            None => "/enrollment/votes".to_string(),
        };

        let response: Vec<OracleVote> = reqwest::Client::new()
            .get(query_url.join(&endpoint)?)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;

        println!("{}", serde_json::to_string_pretty(&response)?);
        Ok(())
    }
}

#[derive(clap::Args)]
pub struct EnrollmentPending {}

impl EnrollmentPending {
    async fn run(self, query_url: Url) -> color_eyre::Result<()> {
        let response: Vec<PendingObservation> = reqwest::Client::new()
            .get(query_url.join("/enrollment/pending")?)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;

        println!("{}", serde_json::to_string_pretty(&response)?);
        Ok(())
    }
}

#[derive(clap::Args)]
pub struct AdminVotes {}

impl AdminVotes {
    async fn run(self, query_url: Url) -> color_eyre::Result<()> {
        let response: Vec<AdminVote> = reqwest::Client::new()
            .get(query_url.join("/admin/votes")?)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;

        println!("{}", serde_json::to_string_pretty(&response)?);
        Ok(())
    }
}

#[derive(clap::Args)]
pub struct AdminPending {}

impl AdminPending {
    async fn run(self, query_url: Url) -> color_eyre::Result<()> {
        let response: Vec<PendingConfig> = reqwest::Client::new()
            .get(query_url.join("/admin/pending")?)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;

        println!("{}", serde_json::to_string_pretty(&response)?);
        Ok(())
    }
}

#[derive(clap::Args)]
pub struct Config {}

impl Config {
    async fn run(self, query_url: Url) -> color_eyre::Result<()> {
        let response: ChainConfig = reqwest::Client::new()
            .get(query_url.join("/config")?)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;

        println!("{}", serde_json::to_string_pretty(&response)?);
        Ok(())
    }
}

#[derive(clap::Args)]
pub struct Validators {
    /// Optional validator id (full or prefix of the hex public key or address) to
    /// restrict the listing to a single validator.
    pub id: Option<String>,

    /// Emit output as JSON instead of a human-readable table.
    #[clap(long)]
    pub json: bool,
}

impl Validators {
    async fn run(self, query_url: Url) -> color_eyre::Result<()> {
        let endpoint = match &self.id {
            Some(id) => format!("/validators/{}", id),
            None => "/validators".to_string(),
        };

        let validators: Vec<ValidatorInfo> = reqwest::Client::new()
            .get(query_url.join(&endpoint)?)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;

        if self.json {
            println!("{}", serde_json::to_string_pretty(&validators)?);
            return Ok(());
        }

        render_validators_table(&validators);
        Ok(())
    }
}

fn render_validators_table(validators: &[ValidatorInfo]) {
    if validators.is_empty() {
        println!("(no validators)");
        return;
    }

    // Total power across the set so we can render each validator's share. Jailed validators
    // carry power=1, so this stays meaningful even when some of the set is down.
    let total_power: u128 = validators.iter().map(|v| v.power as u128).sum();

    struct Row {
        identity: String,
        status: String,
        power: String,
        uptime: String,
    }

    let rows: Vec<Row> = validators
        .iter()
        .map(|v| {
            let power_share = if total_power == 0 {
                "n/a".to_string()
            } else {
                let pct = (v.power as f64) * 100.0 / (total_power as f64);
                format!("{} ({:.2}%)", v.power, pct)
            };
            let signed = v.uptime_window.saturating_sub(v.missed_blocks);
            let uptime_pct = if v.uptime_window == 0 {
                "n/a".to_string()
            } else {
                format!("{:.2}%", (signed as f64) * 100.0 / (v.uptime_window as f64))
            };
            let uptime = format!("{}/{} ({})", signed, v.uptime_window, uptime_pct);
            Row {
                identity: v.identity.to_string(),
                status: v.status.to_string(),
                power: power_share,
                uptime,
            }
        })
        .collect();

    let headers = ["IDENTITY", "STATUS", "POWER", "SIGNED/WINDOW"];
    let mut widths = headers.map(|h| h.len());
    for row in &rows {
        widths[0] = widths[0].max(row.identity.len());
        widths[1] = widths[1].max(row.status.len());
        widths[2] = widths[2].max(row.power.len());
        widths[3] = widths[3].max(row.uptime.len());
    }

    let print_row = |cells: [&str; 4]| {
        println!(
            "{:<w0$}  {:<w1$}  {:<w2$}  {:<w3$}",
            cells[0],
            cells[1],
            cells[2],
            cells[3],
            w0 = widths[0],
            w1 = widths[1],
            w2 = widths[2],
            w3 = widths[3],
        );
    };

    print_row(headers);
    print_row([
        &"-".repeat(widths[0]),
        &"-".repeat(widths[1]),
        &"-".repeat(widths[2]),
        &"-".repeat(widths[3]),
    ]);
    for row in &rows {
        print_row([&row.identity, &row.status, &row.power, &row.uptime]);
    }
}

#[cfg(test)]
mod tests {
    use super::{PeerStatus, Verdict};

    fn peer(height: u64, catching_up: bool) -> Option<PeerStatus> {
        Some(PeerStatus {
            height,
            catching_up,
        })
    }

    #[test]
    fn behind_its_peer_means_restart() {
        assert_eq!(Verdict::against(2, peer(3, false)), Verdict::NodeBehind);
    }

    #[test]
    fn level_with_its_peer_means_the_chain_stopped() {
        assert_eq!(Verdict::against(3, peer(3, false)), Verdict::ChainStopped);
    }

    #[test]
    fn a_syncing_peer_one_block_ahead_is_not_a_fault() {
        assert_eq!(Verdict::against(2, peer(3, true)), Verdict::CatchingUp);
    }

    #[test]
    fn an_unreachable_peer_means_restart() {
        assert_eq!(Verdict::against(3, None), Verdict::NodeBehind);
    }
}
