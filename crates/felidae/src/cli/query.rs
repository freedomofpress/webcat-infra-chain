//! Query subcommands for interacting with the Felidae query server.

use std::collections::HashMap;

use felidae_types::response::{AdminVote, OracleVote, PendingConfig, PendingObservation};
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
    /// Query canonical domain→hash mappings.
    Snapshot(Snapshot),
    /// Query active oracle votes in the vote queue.
    OracleVotes(OracleVotes),
    /// Query pending oracle observations awaiting promotion.
    OraclePending(OraclePending),
    /// Query active admin reconfiguration votes.
    AdminVotes(AdminVotes),
    /// Query pending admin config changes.
    AdminPending(AdminPending),
    /// Query current chain configuration.
    Config(Config),
}

impl Run for Query {
    async fn run(self) -> color_eyre::Result<()> {
        let query_url = self.query_url;
        match self.command {
            QueryCommand::Snapshot(cmd) => cmd.run(query_url).await,
            QueryCommand::OracleVotes(cmd) => cmd.run(query_url).await,
            QueryCommand::OraclePending(cmd) => cmd.run(query_url).await,
            QueryCommand::AdminVotes(cmd) => cmd.run(query_url).await,
            QueryCommand::AdminPending(cmd) => cmd.run(query_url).await,
            QueryCommand::Config(cmd) => cmd.run(query_url).await,
        }
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
pub struct OracleVotes {
    /// Filter by domain (optional).
    #[clap(long)]
    pub domain: Option<String>,
}

impl OracleVotes {
    async fn run(self, query_url: Url) -> color_eyre::Result<()> {
        let endpoint = match &self.domain {
            Some(domain) => format!("/oracle/votes/{}", domain),
            None => "/oracle/votes".to_string(),
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
pub struct OraclePending {}

impl OraclePending {
    async fn run(self, query_url: Url) -> color_eyre::Result<()> {
        let response: Vec<PendingObservation> = reqwest::Client::new()
            .get(query_url.join("/oracle/pending")?)
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
