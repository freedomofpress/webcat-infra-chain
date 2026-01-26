//! Query subcommands for interacting with the Felidae query server.

use std::collections::HashMap;

use felidae_types::response::{AdminVote, OracleVote, PendingConfig, PendingObservation};
use felidae_types::transaction::Config as ChainConfig;
use reqwest::Url;

use super::Run;

#[derive(clap::Subcommand)]
pub enum Query {
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
        match self {
            Self::Snapshot(cmd) => cmd.run().await,
            Self::OracleVotes(cmd) => cmd.run().await,
            Self::OraclePending(cmd) => cmd.run().await,
            Self::AdminVotes(cmd) => cmd.run().await,
            Self::AdminPending(cmd) => cmd.run().await,
            Self::Config(cmd) => cmd.run().await,
        }
    }
}

#[derive(clap::Args)]
pub struct Snapshot {
    /// Felidae query server URL.
    #[clap(long, default_value = "http://localhost:8080")]
    pub query_url: Url,
}

impl Run for Snapshot {
    async fn run(self) -> color_eyre::Result<()> {
        let response: HashMap<String, String> = reqwest::Client::new()
            .get(self.query_url.join("/snapshot")?)
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
    /// Felidae query server URL.
    #[clap(long, default_value = "http://localhost:8080")]
    pub query_url: Url,
    /// Filter by domain (optional).
    #[clap(long)]
    pub domain: Option<String>,
}

impl Run for OracleVotes {
    async fn run(self) -> color_eyre::Result<()> {
        let endpoint = match &self.domain {
            Some(domain) => format!("/oracle/votes/{}", domain),
            None => "/oracle/votes".to_string(),
        };

        let response: Vec<OracleVote> = reqwest::Client::new()
            .get(self.query_url.join(&endpoint)?)
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
pub struct OraclePending {
    /// Felidae query server URL.
    #[clap(long, default_value = "http://localhost:8080")]
    pub query_url: Url,
}

impl Run for OraclePending {
    async fn run(self) -> color_eyre::Result<()> {
        let response: Vec<PendingObservation> = reqwest::Client::new()
            .get(self.query_url.join("/oracle/pending")?)
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
pub struct AdminVotes {
    /// Felidae query server URL.
    #[clap(long, default_value = "http://localhost:8080")]
    pub query_url: Url,
}

impl Run for AdminVotes {
    async fn run(self) -> color_eyre::Result<()> {
        let response: Vec<AdminVote> = reqwest::Client::new()
            .get(self.query_url.join("/admin/votes")?)
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
pub struct AdminPending {
    /// Felidae query server URL.
    #[clap(long, default_value = "http://localhost:8080")]
    pub query_url: Url,
}

impl Run for AdminPending {
    async fn run(self) -> color_eyre::Result<()> {
        let response: Vec<PendingConfig> = reqwest::Client::new()
            .get(self.query_url.join("/admin/pending")?)
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
pub struct Config {
    /// Felidae query server URL.
    #[clap(long, default_value = "http://localhost:8080")]
    pub query_url: Url,
}

impl Run for Config {
    async fn run(self) -> color_eyre::Result<()> {
        let response: ChainConfig = reqwest::Client::new()
            .get(self.query_url.join("/config")?)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;

        println!("{}", serde_json::to_string_pretty(&response)?);
        Ok(())
    }
}
