use clap::Parser;
use color_eyre::Result;
use reqwest::Url;
use serde::Serialize;
use tendermint::block::signed_header::SignedHeader;
use tendermint::crypto::default::signature::Verifier;
use tendermint::crypto::signature::Verifier as VerifierTrait;
use tendermint::validator::Set as ValidatorSet;
use tendermint::vote::{Type as VoteType, ValidatorIndex, Vote};
use tendermint_rpc::HttpClient;
use tendermint_rpc::client::Client;

#[derive(Parser)]
#[command(name = "felidae-publish")]
#[command(about = "Fetch and verify LightBlocks from a CometBFT node")]
struct Args {
    /// Node RPC URL (e.g., http://localhost:26657)
    #[arg(default_value = "http://localhost:26657")]
    node: String,

    /// ABCI query server URL (e.g., http://localhost:80)
    #[arg(long, default_value = "http://localhost:80")]
    query_url: String,

    #[command(subcommand)]
    command: Command,
}

#[derive(clap::Subcommand)]
enum Command {
    /// Print the latest LightBlock as JSON
    Print,
    /// Verify the LightBlock and print the apphash
    Verify,
    /// Get canonical leaves from the query server
    Leaves,
}

// LightBlock structure: signed_header + validator_set
// This matches the standard Tendermint `LightBlock` structure but
// is not exported by the tendermint-rpc crate.
#[derive(Serialize)]
struct LightBlock {
    signed_header: tendermint::block::signed_header::SignedHeader,
    validator_set: tendermint::validator::Set,
}

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;
    let args = Args::parse();

    // Create Tendermint RPC client
    let rpc_url =
        Url::parse(&args.node).map_err(|e| color_eyre::eyre::eyre!("invalid RPC URL: {}", e))?;
    let rpc_url = tendermint_rpc::Url::try_from(rpc_url)
        .map_err(|e| color_eyre::eyre::eyre!("invalid RPC URL: {}", e))?;
    let client = HttpClient::new(rpc_url)
        .map_err(|e| color_eyre::eyre::eyre!("failed to create RPC client: {}", e))?;

    match args.command {
        Command::Print => {
            let (light_block, _) = fetch_light_block(&client).await?;
            println!("{}", serde_json::to_string_pretty(&light_block)?);
        }
        Command::Verify => {
            let (light_block, status) = fetch_light_block(&client).await?;
            let chain_id = status.node_info.network.to_string();
            verify_light_block(
                &light_block.signed_header,
                &light_block.validator_set,
                &chain_id,
            )?;
            let apphash = light_block.signed_header.header.app_hash;
            println!("LightBlock verified successfully!");
            println!("AppHash: {}", hex::encode(apphash.as_bytes()));
        }
        Command::Leaves => {
            let query_url = Url::parse(&args.query_url)
                .map_err(|e| color_eyre::eyre::eyre!("invalid query URL: {}", e))?;
            let leaves_url = query_url
                .join("/canonical/leaves")
                .map_err(|e| color_eyre::eyre::eyre!("failed to construct leaves URL: {}", e))?;

            let response = reqwest::Client::new()
                .get(leaves_url)
                .send()
                .await
                .map_err(|e| color_eyre::eyre::eyre!("failed to fetch canonical leaves: {}", e))?;

            if !response.status().is_success() {
                let status = response.status();
                let text = response.text().await.unwrap_or_default();
                return Err(color_eyre::eyre::eyre!(
                    "query server returned error {}: {}",
                    status,
                    text
                ));
            }

            let leaves: serde_json::Value = response
                .json()
                .await
                .map_err(|e| color_eyre::eyre::eyre!("failed to parse response: {}", e))?;

            println!("{}", serde_json::to_string_pretty(&leaves)?);
        }
    }

    Ok(())
}

/// Fetch the latest light block from the node
async fn fetch_light_block(
    client: &HttpClient,
) -> Result<(LightBlock, tendermint_rpc::endpoint::status::Response)> {
    // Get the latest height from status
    let status = client.status().await?;
    let latest_height = status.sync_info.latest_block_height;

    // Fetch the latest commit (signed header)
    let commit_result = client.commit(latest_height).await?;
    let signed_header = commit_result.signed_header;
    let height = signed_header.header.height;

    // Fetch validators for the same height
    use tendermint_rpc::Paging;
    let validators_result = client.validators(height, Paging::All).await?;
    let all_validators = validators_result.validators;

    // Find the proposer from the header
    let proposer_address = signed_header.header.proposer_address;
    let proposer = all_validators
        .iter()
        .find(|v| v.address == proposer_address)
        .cloned();

    let validator_set = tendermint::validator::Set::new(all_validators, proposer);

    // Construct light block
    let light_block = LightBlock {
        signed_header,
        validator_set,
    };

    Ok((light_block, status))
}

/// Verify a `LightBlock` by checking commit structure, voting power, and signatures.
///
/// This implements light client verification that verifies:
/// - The commit structure matches the header
/// - >2/3 of the validator set has signed
/// - Each signature is cryptographically valid
fn verify_light_block(
    signed_header: &SignedHeader,
    validator_set: &ValidatorSet,
    chain_id: &str,
) -> Result<()> {
    let commit = &signed_header.commit;
    let header = &signed_header.header;

    // NOTE!! Clients / the browser extension should first verify the validator_set matches what is
    // bundled in the browser extension.

    // Check that we have the same number of signature slots as validators
    // (one slot per validator, even if some are absent)
    if validator_set.validators().len() != commit.signatures.len() {
        return Err(color_eyre::eyre::eyre!(
            "validator set size ({}) doesn't match commit signatures count ({})",
            validator_set.validators().len(),
            commit.signatures.len()
        ));
    }

    // Verify height matches
    if header.height != commit.height {
        return Err(color_eyre::eyre::eyre!(
            "header height ({}) doesn't match commit height ({})",
            header.height,
            commit.height
        ));
    }

    // Verify block ID matches
    if header.hash() != commit.block_id.hash {
        return Err(color_eyre::eyre::eyre!(
            "header hash doesn't match commit block ID hash"
        ));
    }

    // Calculate voting power needed (>2/3)
    // total_voting_power() returns a Power type which can be converted to u64
    let total_voting_power_u64: u64 = validator_set.total_voting_power().into();
    let total_voting_power: i64 = total_voting_power_u64 as i64;
    let voting_power_needed = (total_voting_power * 2) / 3;

    let mut tallied_voting_power: i64 = 0;

    // Verify each signature
    for (idx, commit_sig) in commit.signatures.iter().enumerate() {
        // Get the corresponding validator
        let validator = validator_set
            .validators()
            .get(idx)
            .ok_or_else(|| color_eyre::eyre::eyre!("validator index {} out of bounds", idx))?;

        // Extract timestamp and signature from CommitSig, only processing commits
        let (timestamp, signature_bytes) = match commit_sig {
            tendermint::block::CommitSig::BlockIdFlagAbsent => {
                // Skip absent signatures (this means that the validator could have been offline, not voted, etc.
                // not necessarily a problem unless we don't have enough validators online to progress)
                continue;
            }
            tendermint::block::CommitSig::BlockIdFlagCommit {
                timestamp,
                signature,
                ..
            } => {
                let sig = signature.as_ref().ok_or_else(|| {
                    color_eyre::eyre::eyre!("signature missing for validator {}", idx)
                })?;
                (timestamp, sig.clone())
            }
            tendermint::block::CommitSig::BlockIdFlagNil { .. } => {
                // We only count voting power for signatures that are for the block
                // so we skip nil votes
                continue;
            }
        };

        // Construct the vote
        let vote = Vote {
            vote_type: VoteType::Precommit,
            height: commit.height,
            round: commit.round,
            block_id: Some(commit.block_id),
            timestamp: Some(*timestamp),
            validator_address: validator.address,
            validator_index: ValidatorIndex::try_from(idx).expect("validator index out of bounds"),
            signature: Some(signature_bytes.clone()),
            extension: vec![],
            extension_signature: None,
        };

        // Get the vote sign bytes (canonical bytes that were signed)
        let mut sign_bytes_buffer = Vec::new();
        let chain_id = tendermint::chain::Id::try_from(chain_id)
            .map_err(|e| color_eyre::eyre::eyre!("invalid chain ID: {}", e))?;
        vote.to_signable_bytes(chain_id, &mut sign_bytes_buffer)
            .map_err(|e| color_eyre::eyre::eyre!("failed to create signable bytes: {}", e))?;

        // Verify the signature using the validator's public key
        // Verifier::verify takes PublicKey by value, not by reference
        Verifier::verify(validator.pub_key, &sign_bytes_buffer, &signature_bytes).map_err(|e| {
            color_eyre::eyre::eyre!("signature verification failed for validator {}: {}", idx, e)
        })?;

        // Signature is valid, add voting power
        let power_u64: u64 = validator.power();
        tallied_voting_power += power_u64 as i64;
    }

    // Check that we have >2/3 voting power
    if tallied_voting_power <= voting_power_needed {
        return Err(color_eyre::eyre::eyre!(
            "insufficient voting power: got {} (needed >{})",
            tallied_voting_power,
            voting_power_needed
        ));
    }

    Ok(())
}
