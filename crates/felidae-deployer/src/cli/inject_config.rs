//! Inject config command implementation.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use clap::Parser;
use color_eyre::eyre::{Context, Result, eyre};
use tracing::info;
use url::Url;

use super::Run;
use felidae_deployer::network::{
    felidae_config, identity_from_key_file, inject_genesis_config, write_new_key,
};
use felidae_types::transaction::{Admin, Config, Identity, Oracle, Quorum, Total};

/// Inject a chain config into the `app_state.config` of one or more CometBFT
/// genesis files. InitChain refuses a genesis without a valid config, so this
/// (or equivalent) must run before a chain first starts.
///
/// With --config, an operator-authored config JSON is validated and injected
/// verbatim. Without it, a single-admin/single-oracle dev config (1-of-1
/// quorums) is generated, creating admin and oracle keys if missing in the
/// same locations the `felidae` CLI uses — so `felidae admin ...` and
/// `felidae oracle server` find them without further flags.
#[derive(Parser)]
pub struct InjectConfig {
    /// Genesis file to modify. May be given multiple times; every file
    /// receives an identical app_state (genesis must match on all nodes).
    #[arg(long, required = true)]
    pub genesis: Vec<PathBuf>,

    /// Path to an authored config JSON to validate and inject verbatim,
    /// instead of generating a dev config.
    #[arg(long)]
    pub config: Option<PathBuf>,

    /// Directory holding (or to hold) the dev admin key.
    /// Defaults to the `felidae admin` homedir.
    #[arg(long, conflicts_with = "config")]
    pub admin_homedir: Option<PathBuf>,

    /// Directory holding (or to hold) the dev oracle key.
    /// Defaults to the `felidae oracle` homedir.
    #[arg(long, conflicts_with = "config")]
    pub oracle_homedir: Option<PathBuf>,

    /// Delay before admin config changes take effect (generated config).
    #[arg(long, default_value = "0s", value_parser = humantime::parse_duration, conflicts_with = "config")]
    pub admin_delay: Duration,

    /// Delay before oracle observations become canonical (generated config).
    #[arg(long, default_value = "1s", value_parser = humantime::parse_duration, conflicts_with = "config")]
    pub oracle_delay: Duration,

    /// Oracle endpoint recorded in the generated config.
    #[arg(
        long,
        default_value = "http://127.0.0.1:8081",
        conflicts_with = "config"
    )]
    pub oracle_endpoint: Url,
}

impl Run for InjectConfig {
    async fn run(self) -> Result<()> {
        let config = match &self.config {
            Some(path) => {
                let json = fs::read_to_string(path)
                    .wrap_err_with(|| format!("failed to read config {:?}", path))?;
                serde_json::from_str(&json)
                    .wrap_err_with(|| format!("failed to parse config {:?}", path))?
            }
            None => {
                let admin_dir = homedir(self.admin_homedir.as_deref(), "felidae-admin")?;
                let oracle_dir = homedir(self.oracle_homedir.as_deref(), "felidae-oracle")?;
                dev_config(
                    &admin_dir,
                    &oracle_dir,
                    self.admin_delay,
                    self.oracle_delay,
                    self.oracle_endpoint.clone(),
                )?
            }
        };

        // Pre-flight with the same stateless validation InitChain runs, so a
        // bad config fails here instead of at chain start.
        config.check_stateless()?;

        for genesis in &self.genesis {
            inject_genesis_config(genesis, &config)?;
            info!("injected config into {}", genesis.display());
        }
        Ok(())
    }
}

/// Resolve a key homedir: an explicit path, or the felidae CLI's default
/// (`ProjectDirs` data dir for the given application name).
fn homedir(explicit: Option<&Path>, app: &str) -> Result<PathBuf> {
    match explicit {
        Some(dir) => Ok(dir.to_path_buf()),
        None => directories::ProjectDirs::from("press", "freedom", app)
            .map(|d| d.data_local_dir().to_path_buf())
            .ok_or_else(|| eyre!("could not determine default homedir for {app}")),
    }
}

/// Build a single-admin/single-oracle dev config from the keys in the given
/// homedirs, generating any key that does not yet exist. Key locations and
/// format (`*_key.pkcs8.hex`) match `felidae admin init` / `felidae oracle init`.
fn dev_config(
    admin_dir: &Path,
    oracle_dir: &Path,
    admin_delay: Duration,
    oracle_delay: Duration,
    oracle_endpoint: Url,
) -> Result<Config> {
    let admin = Admin {
        identity: load_or_create_key(&admin_dir.join("admin_key.pkcs8.hex"))?,
    };
    let oracle = Oracle {
        identity: load_or_create_key(&oracle_dir.join("oracle_key.pkcs8.hex"))?,
        endpoint: oracle_endpoint,
    };
    felidae_config(
        vec![admin],
        vec![oracle],
        Total(1),
        Quorum(1),
        admin_delay,
        oracle_delay,
    )
}

/// Load the identity from a PKCS#8 hex keypair file, generating a fresh P-256
/// key there first if the file does not exist.
fn load_or_create_key(path: &Path) -> Result<Identity> {
    if !path.exists() {
        let dir = path.parent().expect("key path has a parent directory");
        fs::create_dir_all(dir)
            .wrap_err_with(|| format!("failed to create key directory {:?}", dir))?;
        write_new_key(path)?;
        info!("generated key at {}", path.display());
    }
    identity_from_key_file(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// End-to-end over the dev path: fresh keys, generated config, injection
    /// into a bare genesis; the result must parse and pass validation.
    #[test]
    fn dev_config_generates_keys_and_injects() {
        let tmp = tempfile::tempdir().unwrap();
        let admin_dir = tmp.path().join("admin");
        let oracle_dir = tmp.path().join("oracle");

        let config = dev_config(
            &admin_dir,
            &oracle_dir,
            Duration::from_secs(0),
            Duration::from_secs(1),
            Url::parse("http://127.0.0.1:8081").unwrap(),
        )
        .expect("dev config generates");
        config.check_stateless().expect("dev config is valid");

        // Keys persist and are reused, not regenerated:
        let again = dev_config(
            &admin_dir,
            &oracle_dir,
            Duration::from_secs(0),
            Duration::from_secs(1),
            Url::parse("http://127.0.0.1:8081").unwrap(),
        )
        .expect("dev config regenerates");
        assert_eq!(config, again, "existing keys must be reused");

        // Injection round-trips through a genesis file:
        let genesis_path = tmp.path().join("genesis.json");
        fs::write(&genesis_path, r#"{"chain_id": "test", "app_hash": ""}"#).unwrap();
        inject_genesis_config(&genesis_path, &config).expect("injects");

        let genesis: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&genesis_path).unwrap()).unwrap();
        let injected: Config =
            serde_json::from_value(genesis["app_state"]["config"].clone()).expect("config parses");
        assert_eq!(injected, config);
        assert_eq!(genesis["chain_id"], "test", "other genesis fields survive");
    }
}
