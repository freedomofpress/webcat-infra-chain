//! Query subcommands for interacting with the Felidae query server.

use std::collections::HashMap;

use felidae_types::response::{
    AdminVote, ChainInfo, OracleVote, PendingConfig, PendingObservation, ValidatorInfo,
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
                identity: v.identity.clone(),
                status: v.status.clone(),
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
