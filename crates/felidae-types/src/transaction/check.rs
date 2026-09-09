//! Stateless validation of [`Config`] values.

use super::{
    AdminConfig, Config, Identity, OnionConfig, OracleConfig, Total, ValidatorConfig, VotingConfig,
};

/// A config that failed stateless validation.
#[derive(Debug, thiserror::Error)]
#[error("invalid config: {0}")]
pub struct InvalidConfig(String);

macro_rules! invalid {
    ($($arg:tt)*) => { return Err(InvalidConfig(format!($($arg)*))) };
}

impl Config {
    /// Stateless validation, shared verbatim between the genesis and reconfigure
    /// paths: no chain state is read, only checks intrinsic to the config value
    /// itself. State-relative checks (version monotonicity, tombstoned
    /// validators, `max_enrolled_subdomains` monotonicity) live in
    /// `check_config` in `felidae-state`, which only the reconfigure path runs.
    ///
    /// Every config that ever reaches state passes through here: there is no
    /// default and no bypass. In particular, not-yet-operational shapes (empty
    /// party lists, zero quorums) are rejected on both paths: a chain can never
    /// start, nor regress to, an invalid Config.
    pub fn check_stateless(&self) -> Result<(), InvalidConfig> {
        let Config {
            version: _, // Monotonicity is relative to state; checked by the caller.
            admins:
                AdminConfig {
                    authorized: admins,
                    voting: admin_voting_config,
                },
            oracles:
                OracleConfig {
                    enabled: _, // Can be enabled or not
                    authorized: oracles,
                    voting: oracle_voting_config,
                    max_enrolled_subdomains,
                    observation_timeout: _, // Any timeout is acceptable
                },
            onion: OnionConfig {
                enabled: _, // Can be enabled or not
            },
            validators,
            validator_config:
                ValidatorConfig {
                    uptime_window,
                    missed_blocks_max,
                    unjail_missed_max,
                },
        } = self;

        // Check that the voting configs are valid:
        check_voting_config(Total(admins.len() as u64), admin_voting_config)?;
        check_voting_config(Total(oracles.len() as u64), oracle_voting_config)?;

        // Ensure that max_enrolled_subdomains is non-zero:
        if *max_enrolled_subdomains == 0 {
            invalid!("max_enrolled_subdomains must be non-zero");
        }

        // Validate that no admin has the well-known placeholder identity from the template:
        for (i, admin) in admins.iter().enumerate() {
            if admin.identity == Identity::placeholder() {
                invalid!(
                    "admin at index {} has a placeholder identity (placeholder not replaced)",
                    i
                );
            }
        }

        // Validate that no oracle has the well-known placeholder identity from the template:
        for (i, oracle) in oracles.iter().enumerate() {
            if oracle.identity == Identity::placeholder() {
                invalid!(
                    "oracle at index {} has a placeholder identity (placeholder not replaced)",
                    i
                );
            }
        }

        // Validate that no validator has an all-zero public key (placeholder entry):
        for (i, validator) in validators.iter().enumerate() {
            if is_all_zeros(validator.public_key.as_bytes()) {
                invalid!(
                    "validator at index {} has an all-zero public key (placeholder not replaced)",
                    i
                );
            }
        }

        // Validate uptime config:
        if *uptime_window == 0 {
            invalid!("validator_config.uptime_window must be non-zero");
        }
        if *missed_blocks_max >= *uptime_window {
            invalid!(
                "validator_config.missed_blocks_max ({}) must be less than uptime_window ({})",
                missed_blocks_max,
                uptime_window,
            );
        }
        if *unjail_missed_max >= *missed_blocks_max {
            invalid!(
                "validator_config.unjail_missed_max ({}) must be less than missed_blocks_max ({}) \
                 to prevent oscillation at the jail threshold",
                unjail_missed_max,
                missed_blocks_max,
            );
        }

        Ok(())
    }
}

/// Ensure that a voting config is internally consistent, and valid with respect to the expected
/// total number of voting parties.
fn check_voting_config(
    expected_total: Total,
    voting_config: &VotingConfig,
) -> Result<(), InvalidConfig> {
    let VotingConfig {
        total,
        quorum,
        timeout: _, // Any timeout is acceptable
        delay: _,   // Any delay is acceptable
    } = voting_config;

    // Ensure the total matches the expected total:
    if *total != expected_total {
        invalid!(
            "voting config total {} does not match expected total {}",
            total.0,
            expected_total.0
        );
    }

    // Ensure the quorum is non-zero and less than or equal to the total:
    if quorum.0 == 0 {
        invalid!("voting config quorum must be non-zero");
    }
    if quorum.0 > total.0 {
        invalid!(
            "voting config quorum {} cannot be greater than total {}",
            quorum.0,
            total.0
        );
    }

    Ok(())
}

/// Check if a byte slice is all zeros (used to detect placeholder keys).
fn is_all_zeros(bytes: &[u8]) -> bool {
    bytes.iter().all(|&b| b == 0)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::super::{Admin, Delay, Oracle, Quorum, Timeout, Validator, ValidatorKey};
    use super::*;
    use crate::test_util::test_identity;

    fn voting(total: u64, quorum: u64) -> VotingConfig {
        VotingConfig {
            total: Total(total),
            quorum: Quorum(quorum),
            timeout: Timeout(Duration::from_secs(60)),
            delay: Delay(Duration::from_secs(0)),
        }
    }

    /// A realistic operator-supplied genesis config: real identities, sane
    /// voting thresholds, one managed validator, default uptime tuning.
    fn genesis_config() -> Config {
        Config {
            version: 0,
            admins: AdminConfig {
                voting: voting(1, 1),
                authorized: vec![Admin {
                    identity: test_identity(1),
                }],
            },
            oracles: OracleConfig {
                enabled: true,
                voting: voting(1, 1),
                max_enrolled_subdomains: 5,
                observation_timeout: Duration::from_secs(300),
                authorized: vec![Oracle {
                    identity: test_identity(2),
                    endpoint: url::Url::parse("http://127.0.0.1:8081").unwrap(),
                }],
            },
            onion: OnionConfig { enabled: false },
            validators: vec![Validator {
                public_key: ValidatorKey::from_bytes(&[1u8; 32]).expect("valid ed25519 key"),
            }],
            validator_config: ValidatorConfig::default(),
        }
    }

    /// The historical "locked-open" bootstrap shape: no parties, zero voting
    /// thresholds, oracles dormant with `max_enrolled_subdomains = 0`. Once an
    /// internal default at InitChain, now invalid everywhere — kept as a
    /// fixture to pin that it stays rejected.
    fn bootstrap_config() -> Config {
        Config {
            version: 0,
            admins: AdminConfig {
                authorized: vec![],
                voting: voting(0, 0),
            },
            oracles: OracleConfig {
                enabled: false,
                authorized: vec![],
                voting: voting(0, 0),
                max_enrolled_subdomains: 0,
                observation_timeout: Duration::from_secs(i64::MAX as u64),
            },
            onion: OnionConfig { enabled: false },
            validators: vec![],
            validator_config: ValidatorConfig::default(),
        }
    }

    #[test]
    fn accepts_realistic_config() {
        genesis_config()
            .check_stateless()
            .expect("realistic genesis config is valid");
    }

    #[test]
    fn rejects_bootstrap_shape() {
        // Zero quorums must never pass validation, at genesis or reconfigure:
        // no chain may exist in a state where governance needs no votes.
        let err = bootstrap_config().check_stateless().unwrap_err();
        assert!(
            err.to_string().contains("quorum"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn rejects_placeholder_admin() {
        let mut config = genesis_config();
        config.admins.authorized[0].identity = Identity::placeholder();
        let err = config.check_stateless().unwrap_err();
        assert!(
            err.to_string().contains("placeholder"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn rejects_placeholder_oracle() {
        let mut config = genesis_config();
        config.oracles.authorized[0].identity = Identity::placeholder();
        let err = config.check_stateless().unwrap_err();
        assert!(
            err.to_string().contains("placeholder"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn rejects_all_zero_validator_key() {
        let mut config = genesis_config();
        config.validators = vec![Validator {
            public_key: ValidatorKey::from_bytes(&[0u8; 32])
                .expect("32 zero bytes parse as an ed25519 key"),
        }];
        let err = config.check_stateless().unwrap_err();
        assert!(
            err.to_string().contains("all-zero"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn rejects_node_fatal_validator_tuning() {
        // uptime_window = 0 would make mark_signed divide by zero at the
        // first block, crashing every node deterministically.
        let mut config = genesis_config();
        config.validator_config.uptime_window = 0;
        let err = config.check_stateless().unwrap_err();
        assert!(
            err.to_string().contains("uptime_window"),
            "unexpected error: {err}"
        );

        // missed_blocks_max >= uptime_window silently disables jailing.
        let mut config = genesis_config();
        config.validator_config = ValidatorConfig {
            uptime_window: 10,
            missed_blocks_max: 10,
            unjail_missed_max: 2,
        };
        let err = config.check_stateless().unwrap_err();
        assert!(
            err.to_string().contains("missed_blocks_max"),
            "unexpected error: {err}"
        );

        // unjail_missed_max >= missed_blocks_max re-enables jail oscillation.
        let mut config = genesis_config();
        config.validator_config = ValidatorConfig {
            uptime_window: 10,
            missed_blocks_max: 5,
            unjail_missed_max: 5,
        };
        let err = config.check_stateless().unwrap_err();
        assert!(
            err.to_string().contains("unjail_missed_max"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn rejects_inconsistent_voting() {
        // Zero quorum with a non-empty party list: promotion would need no votes.
        let mut config = genesis_config();
        config.admins.voting = voting(1, 0);
        let err = config.check_stateless().unwrap_err();
        assert!(
            err.to_string().contains("quorum"),
            "unexpected error: {err}"
        );

        // Quorum above total.
        let mut config = genesis_config();
        config.admins.voting = voting(1, 2);
        let err = config.check_stateless().unwrap_err();
        assert!(
            err.to_string().contains("quorum"),
            "unexpected error: {err}"
        );

        // Total that does not match the authorized list. This also covers the
        // template's own shape (placeholder party with total = 0).
        let mut config = genesis_config();
        config.admins.voting = voting(0, 0);
        let err = config.check_stateless().unwrap_err();
        assert!(
            err.to_string().contains("does not match"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn rejects_zero_max_subdomains() {
        // A zero enrollment cap is always an authoring error.
        let mut config = genesis_config();
        config.oracles.max_enrolled_subdomains = 0;
        let err = config.check_stateless().unwrap_err();
        assert!(
            err.to_string().contains("max_enrolled_subdomains"),
            "unexpected error: {err}"
        );
    }
}
