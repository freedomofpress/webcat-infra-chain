use cnidarium::ics23_spec;
use color_eyre::Result;
use felidae_state::{Store, Substore};
use ibc_proto::ics23::CommitmentProof as ProtoCommitmentProof;
use ibc_proto::ics23::ProofSpec as ProtoProofSpec;
use ibc_types_core_commitment::MerkleProof;
use ibc_types_core_commitment::{MerklePath, MerkleRoot};
use prost::Message;
use reqwest::Url;
use serde::Deserialize;
use tendermint_rpc::HttpClient;

use crate::light_block::fetch_light_block_at_height;
use crate::verification::verify_light_block;

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
    leaves: Vec<[String; 2]>, // Array of [key, value] pairs
    proof: Proof,
}

pub async fn reconstruct(client: &HttpClient, query_url: &str) -> Result<()> {
    // First, get the leaves from the query server
    let query_url =
        Url::parse(query_url).map_err(|e| color_eyre::eyre::eyre!("invalid query URL: {}", e))?;
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
    let (light_block, status) = fetch_light_block_at_height(client, block_height).await?;
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
            match fetch_light_block_at_height(client, next_block_height).await {
                Ok((next_light_block, _)) => {
                    // Block N+1 is now available
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
        let (next_light_block, _) = fetch_light_block_at_height(client, next_block_height).await?;
        let app_hash = next_light_block.signed_header.header.app_hash;
        let app_hash_bytes = app_hash.as_bytes();
        let proof_app_hash_bytes = hex::decode(&response_data.proof.app_hash)
            .map_err(|e| color_eyre::eyre::eyre!("failed to decode app_hash from proof: {}", e))?;

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
    let temp_dir = std::env::temp_dir().join(format!("felidae-reconstruct-{}", std::process::id()));
    let mut store = Store::init(temp_dir.clone()).await?;

    // Insert all leaves into the canonical substore
    // The keys already include "canonical/" prefix, so we can use them directly with put_raw
    for leaf in &leaves {
        let key = &leaf[0];
        let value_hex = &leaf[1];
        let value_bytes = hex::decode(value_hex).map_err(|e| {
            color_eyre::eyre::eyre!("failed to decode hex value for key {}: {}", key, e)
        })?;
        // put_raw expects the full prefixed key (which already includes "canonical/")
        store.put_raw(key, value_bytes).await;
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

        // Decode the proof bytes
        let proofs: Vec<ibc_proto::ics23::CommitmentProof> = merkle_proof_info
            .proof_bytes
            .iter()
            .map(|proof_hex| {
                let proof_bytes = hex::decode(proof_hex)
                    .map_err(|e| color_eyre::eyre::eyre!("failed to decode proof hex: {}", e))?;
                ProtoCommitmentProof::decode(proof_bytes.as_slice())
                    .map_err(|e| color_eyre::eyre::eyre!("failed to decode CommitmentProof: {}", e))
            })
            .collect::<Result<Vec<_>, _>>()?;

        let merkle_proof = MerkleProof { proofs };

        // The proof has 2 parts:
        // 1. Proof from key to canonical_root_hash (within canonical substore)
        // 2. Proof from canonical_root_hash to app_hash (substore root to app root)
        //
        // See in crate `cnidarium` `Snapshot::get_with_proof` where this happens.
        if merkle_proof.proofs.len() >= 2 {
            // Get the actual JMT proof spec (returns ics23::ProofSpec)
            let jmt_spec_ics23 = ics23_spec();

            // Convert from ics23::ProofSpec to `ibc_proto::ics23::ProofSpec`
            // which is what `MerkleProof::verify_membership` expects
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
                inner_spec: jmt_spec_ics23
                    .inner_spec
                    .map(|inner| ibc_proto::ics23::InnerSpec {
                        hash: inner.hash,
                        child_order: inner.child_order,
                        min_prefix_length: inner.min_prefix_length,
                        max_prefix_length: inner.max_prefix_length,
                        child_size: inner.child_size,
                        empty_child: inner.empty_child,
                    }),
                max_depth: jmt_spec_ics23.max_depth,
                min_depth: jmt_spec_ics23.min_depth,
                prehash_key_before_comparison: jmt_spec_ics23.prehash_key_before_comparison,
            };

            // Get the representative key and value for the first proof
            let proof_key = merkle_proof_info.representative_key.as_bytes().to_vec();
            let proof_value = leaves
                .iter()
                .find(|leaf| leaf[0] == merkle_proof_info.representative_key)
                .map(|leaf| hex::decode(&leaf[1]).unwrap_or_default())
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
            // We need to bail here because this likely means the second part of the proof
            // which proves `canonical_root_hash` is in `app_hash` is missing, and that's
            // the one we care about (we already checked the root of the canonical substore
            // matches what we got from the query server).
            return Err(color_eyre::eyre::eyre!(
                "Merkle proof should have at least 2 parts, got {}",
                merkle_proof.proofs.len()
            ));
        }
    } else {
        // No Merkle proof available - we can't verify without it and shouldn't blindly trust
        // what we get from the server, so we need to error out.
        return Err(color_eyre::eyre::eyre!(
            "No Merkle proof available - cannot verify canonical_root_hash inclusion in AppHash"
        ));
    }

    // Clean up temporary directory (but a Clever Client might leave this around such that Later (TM) they
    // can do incremental updates)
    let _ = std::fs::remove_dir_all(&temp_dir);

    Ok(())
}
