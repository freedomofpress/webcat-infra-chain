use clap::Parser;
use color_eyre::Result;
use felidae_state::{Store, Substore};
use reqwest::Url;
use serde::{Deserialize, Serialize};
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
    Print {
        /// Block height to fetch (if not provided, uses latest)
        #[arg(long)]
        height: Option<u64>,
    },
    /// Verify the LightBlock and print the apphash
    Verify {
        /// Block height to fetch (if not provided, uses latest)
        #[arg(long)]
        height: Option<u64>,
    },
    /// Reconstruct the JMT from latest canonical leaves, verify the merkle proof up
    /// to the corresponding `LightBlock`, and print the root hash
    Reconstruct,
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
        Command::Print { height } => {
            let (light_block, _) = if let Some(h) = height {
                fetch_light_block_at_height(&client, h).await?
            } else {
                fetch_light_block(&client).await?
            };
            println!("{}", serde_json::to_string_pretty(&light_block)?);
        }
        Command::Verify { height } => {
            let (light_block, status) = if let Some(h) = height {
                fetch_light_block_at_height(&client, h).await?
            } else {
                fetch_light_block(&client).await?
            };
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
        Command::Reconstruct => {
            // First, get the leaves from the query server
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

            #[derive(Deserialize)]
            struct Leaf {
                key: String,
                value: String, // hex-encoded
            }

            #[derive(Deserialize)]
            struct MerkleProofInfo {
                representative_key: String,
                proof_bytes: Vec<String>, // Array of hex-encoded proof bytes
            }

            #[derive(Deserialize)]
            struct Proof {
                canonical_root_hash: String,
                app_hash: String,
                #[serde(skip_serializing_if = "Option::is_none")]
                merkle_proof: Option<MerkleProofInfo>,
            }

            #[derive(Deserialize)]
            struct CanonicalLeavesResponse {
                block_height: u64,
                leaves: Vec<Leaf>,
                proof: Proof,
            }

            let response_data: CanonicalLeavesResponse = response
                .json()
                .await
                .map_err(|e| color_eyre::eyre::eyre!("failed to parse response: {}", e))?;

            let block_height = response_data.block_height;
            let leaves = response_data.leaves;

            println!("Block height: {}", block_height);

            // In CometBFT, the app_hash in block header at height N is the state root after processing block N-1.
            // The proof's app_hash is from block N (the current state).
            // So we need to fetch the light block at height N+1 to get the app_hash that corresponds to block N's state.
            let (light_block, status) = fetch_light_block_at_height(&client, block_height).await?;
            let chain_id = status.node_info.network.to_string();
            verify_light_block(
                &light_block.signed_header,
                &light_block.validator_set,
                &chain_id,
            )?;

            // Fetch the next block to get the app_hash that corresponds to block N's state
            let latest_height = status.sync_info.latest_block_height.value();
            let next_block_height = block_height + 1;

            // If block N is the latest block, wait for block N+1 to be committed
            if block_height >= latest_height {
                eprintln!(
                    "Block {} is the latest block. Waiting for block {} to be committed...",
                    block_height, next_block_height
                );

                // Poll for the next block
                let mut attempts = 0;
                let max_attempts = 60; // Wait up to a minute
                loop {
                    match fetch_light_block_at_height(&client, next_block_height).await {
                        Ok((next_light_block, _)) => {
                            // Block N+1 is now available
                            let app_hash = next_light_block.signed_header.header.app_hash;
                            let app_hash_bytes = app_hash.as_bytes();
                            let proof_app_hash_bytes = hex::decode(&response_data.proof.app_hash)
                                .map_err(|e| {
                                color_eyre::eyre::eyre!(
                                    "failed to decode app_hash from proof: {}",
                                    e
                                )
                            })?;

                            eprintln!(
                                "Light block app_hash (hex) from height {}: {}",
                                next_block_height,
                                hex::encode(app_hash_bytes)
                            );
                            eprintln!(
                                "Proof app_hash (hex) from block {}: {}",
                                block_height, response_data.proof.app_hash
                            );

                            if app_hash_bytes != proof_app_hash_bytes.as_slice() {
                                return Err(color_eyre::eyre::eyre!(
                                    "app hash mismatch: light block (height {}) {} != proof (block {}) {}",
                                    next_block_height,
                                    hex::encode(app_hash_bytes),
                                    block_height,
                                    response_data.proof.app_hash
                                ));
                            }
                            break;
                        }
                        Err(_) => {
                            attempts += 1;
                            if attempts >= max_attempts {
                                return Err(color_eyre::eyre::eyre!(
                                    "timeout waiting for block {} to be committed (waited {} attempts)",
                                    next_block_height,
                                    attempts
                                ));
                            }
                            tokio::time::sleep(tokio::time::Duration::from_millis(1000)).await;
                        }
                    }
                }
            } else {
                // Block N+1 already exists, fetch it directly
                let (next_light_block, _) =
                    fetch_light_block_at_height(&client, next_block_height).await?;
                let app_hash = next_light_block.signed_header.header.app_hash;
                let app_hash_bytes = app_hash.as_bytes();
                let proof_app_hash_bytes =
                    hex::decode(&response_data.proof.app_hash).map_err(|e| {
                        color_eyre::eyre::eyre!("failed to decode app_hash from proof: {}", e)
                    })?;

                eprintln!(
                    "Light block app_hash (hex) from height {}: {}",
                    next_block_height,
                    hex::encode(app_hash_bytes)
                );
                eprintln!(
                    "Proof app_hash (hex) from block {}: {}",
                    block_height, response_data.proof.app_hash
                );

                if app_hash_bytes != proof_app_hash_bytes.as_slice() {
                    return Err(color_eyre::eyre::eyre!(
                        "app hash mismatch: light block (height {}) {} != proof (block {}) {}",
                        next_block_height,
                        hex::encode(app_hash_bytes),
                        block_height,
                        response_data.proof.app_hash
                    ));
                }
            }

            // Create a temporary storage to reconstruct the tree
            let temp_dir =
                std::env::temp_dir().join(format!("felidae-reconstruct-{}", std::process::id()));
            let mut store = Store::init(temp_dir.clone()).await?;

            // Insert all leaves into the canonical substore
            // The keys already include "canonical/" prefix, so we can use them directly with put_raw
            for leaf in &leaves {
                let value_bytes = hex::decode(&leaf.value).map_err(|e| {
                    color_eyre::eyre::eyre!(
                        "failed to decode hex value for key {}: {}",
                        leaf.key,
                        e
                    )
                })?;
                // put_raw expects the full prefixed key (which already includes "canonical/")
                store.put_raw(&leaf.key, value_bytes).await;
            }

            // Commit to get the root hash
            store.commit().await?;

            // Get the canonical root hash
            let root_hash = store.root_hash(Some(Substore::Canonical)).await?;
            let reconstructed_canonical_root_hash = hex::encode(root_hash.0.as_slice());
            println!("JMT reconstructed successfully!");
            println!("Canonical root hash: {}", reconstructed_canonical_root_hash);

            // Verify the canonical root hash matches (necessary but not sufficient)
            let expected_canonical_root_hash = &response_data.proof.canonical_root_hash;
            if reconstructed_canonical_root_hash != *expected_canonical_root_hash {
                return Err(color_eyre::eyre::eyre!(
                    "canonical root hash mismatch: reconstructed {} != expected {}",
                    reconstructed_canonical_root_hash,
                    expected_canonical_root_hash
                ));
            }

            let app_hash_bytes: Vec<u8> = hex::decode(&response_data.proof.app_hash)
                .map_err(|e| color_eyre::eyre::eyre!("failed to decode app_hash: {}", e))?;

            // If we have a Merkle proof, use it to verify canonical_root_hash is in app_hash
            if let Some(merkle_proof_info) = &response_data.proof.merkle_proof {
                println!("Verifying canonical root hash is included in AppHash...");
                use ibc_proto::ics23::CommitmentProof as ProtoCommitmentProof;
                use ibc_types_core_commitment::MerkleProof;
                use ibc_types_core_commitment::{MerklePath, MerkleRoot};
                use prost::Message;

                // Decode the proof bytes
                let proofs: Vec<ibc_proto::ics23::CommitmentProof> = merkle_proof_info
                    .proof_bytes
                    .iter()
                    .map(|proof_hex| {
                        let proof_bytes = hex::decode(proof_hex).map_err(|e| {
                            color_eyre::eyre::eyre!("failed to decode proof hex: {}", e)
                        })?;
                        ProtoCommitmentProof::decode(proof_bytes.as_slice()).map_err(|e| {
                            color_eyre::eyre::eyre!("failed to decode CommitmentProof: {}", e)
                        })
                    })
                    .collect::<Result<Vec<_>, _>>()?;

                let merkle_proof = MerkleProof { proofs };

                // The proof has 2 parts:
                // 1. Proof from key to canonical_root_hash (within canonical substore)
                // 2. Proof from canonical_root_hash to app_hash (substore root to app root)
                //
                // We need to verify the full proof to ensure canonical_root_hash is in app_hash.
                // The second proof should contain all necessary sibling hashes (including internal_root_hash)
                // without requiring us to load the full internal substore.
                if merkle_proof.proofs.len() >= 2 {
                    // Use the actual JMT proof spec from cnidarium/jmt
                    // This is the correct spec that matches how JMT generates proofs
                    use cnidarium::ics23_spec;
                    use ibc_proto::ics23::ProofSpec as ProtoProofSpec;

                    // Get the actual JMT proof spec (returns ics23::ProofSpec)
                    let jmt_spec_ics23 = ics23_spec();

                    // Convert from ics23::ProofSpec to ibc_proto::ics23::ProofSpec
                    let jmt_spec = ProtoProofSpec {
                        leaf_spec: jmt_spec_ics23
                            .leaf_spec
                            .map(|leaf| ibc_proto::ics23::LeafOp {
                                hash: leaf.hash,
                                prehash_key: leaf.prehash_key,
                                prehash_value: leaf.prehash_value,
                                length: leaf.length,
                                prefix: leaf.prefix,
                            }),
                        inner_spec: jmt_spec_ics23.inner_spec.map(|inner| {
                            ibc_proto::ics23::InnerSpec {
                                hash: inner.hash,
                                child_order: inner.child_order,
                                min_prefix_length: inner.min_prefix_length,
                                max_prefix_length: inner.max_prefix_length,
                                child_size: inner.child_size,
                                empty_child: inner.empty_child,
                            }
                        }),
                        max_depth: jmt_spec_ics23.max_depth,
                        min_depth: jmt_spec_ics23.min_depth,
                        prehash_key_before_comparison: jmt_spec_ics23.prehash_key_before_comparison,
                    };

                    // Get the representative key and value for the first proof
                    let proof_key = merkle_proof_info.representative_key.as_bytes().to_vec();
                    let proof_value = leaves
                        .iter()
                        .find(|leaf| leaf.key == merkle_proof_info.representative_key)
                        .map(|leaf| hex::decode(&leaf.value).unwrap_or_default())
                        .ok_or_else(|| {
                            color_eyre::eyre::eyre!(
                                "representative key {} not found in leaves",
                                merkle_proof_info.representative_key
                            )
                        })?;

                    // Extract the key within the canonical substore (without "canonical/" prefix)
                    let canonical_key = proof_key.strip_prefix(b"canonical/").ok_or_else(|| {
                        color_eyre::eyre::eyre!(
                            "representative key {} doesn't start with 'canonical/'",
                            merkle_proof_info.representative_key
                        )
                    })?;

                    // Construct the MerklePath for the full proof
                    // Keys are from root to leaf: ["canonical", "<key-within-canonical>"]
                    let merkle_path = MerklePath {
                        key_path: vec![
                            "canonical".to_string(),
                            String::from_utf8_lossy(canonical_key).to_string(),
                        ],
                    };

                    let merkle_root = MerkleRoot {
                        hash: app_hash_bytes.clone(),
                    };

                    // Verify the full proof - this proves:
                    // 1. The key/value is in canonical_root_hash
                    // 2. canonical_root_hash is in app_hash
                    merkle_proof
                        .verify_membership(
                            &[jmt_spec.clone(), jmt_spec],
                            merkle_root,
                            merkle_path,
                            proof_value,
                            0,
                        )
                        .map_err(|e| {
                            color_eyre::eyre::eyre!(
                                "Failed to verify Merkle proof (canonical_root_hash in AppHash): {}",
                                e
                            )
                        })?;

                    println!("Verified that canonical_root_hash is included in AppHash!");
                } else {
                    return Err(color_eyre::eyre::eyre!(
                        "Merkle proof should have at least 2 parts, got {}",
                        merkle_proof.proofs.len()
                    ));
                }
            } else {
                // No Merkle proof available - we can't verify without it
                eprintln!(
                    "No Merkle proof available - cannot verify canonical_root_hash inclusion in AppHash"
                );
            }

            // Clean up temporary directory (but a Clever Client might leave this around such that Later (TM) they
            // can do incremental updates)
            let _ = std::fs::remove_dir_all(&temp_dir);
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
    fetch_light_block_at_height(client, latest_height.value()).await
}

/// Fetch a light block at a specific height
async fn fetch_light_block_at_height(
    client: &HttpClient,
    height: u64,
) -> Result<(LightBlock, tendermint_rpc::endpoint::status::Response)> {
    use tendermint::block::Height;
    use tendermint_rpc::Paging;

    let height =
        Height::try_from(height).map_err(|e| color_eyre::eyre::eyre!("invalid height: {}", e))?;

    // Get status for chain ID
    let status = client.status().await?;

    // Fetch the commit (signed header) for the specified height
    let commit_result = client.commit(height).await?;
    let signed_header = commit_result.signed_header;

    // Fetch validators for the same height
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
