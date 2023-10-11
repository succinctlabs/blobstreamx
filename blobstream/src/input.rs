use std::fs;
use std::path::Path;

use async_trait::async_trait;
use ethers::types::H256;
use itertools::Itertools;
use log::info;
use plonky2x::frontend::merkle::tree::InclusionProof;
use plonky2x::prelude::RichField;
use serde::Deserialize;
use subtle_encoding::hex;
use tendermint_proto::types::BlockId as RawBlockId;
use tendermint_proto::Protobuf;
use zk_tendermint::consts::*;
use zk_tendermint::input::{InputDataFetcher, InputDataMode};

#[derive(Debug, Deserialize)]
pub struct DataCommitmentResponse {
    pub result: DataCommitment,
}

#[derive(Debug, Deserialize)]
pub struct DataCommitment {
    pub data_commitment: String,
}

#[async_trait]
pub trait DataCommitmentInputs {
    async fn get_data_commitment(&self, start_block: u64, end_block: u64) -> [u8; 32];

    async fn get_data_commitment_inputs<const MAX_LEAVES: usize, F: RichField>(
        &mut self,
        start_block_number: u64,
        end_block_number: u64,
    ) -> (
        [u8; 32],                                                             // start_header_hash
        [u8; 32],                                                             // end_header_hash
        Vec<[u8; 32]>,                                                        // data_hashes
        Vec<InclusionProof<HEADER_PROOF_DEPTH, PROTOBUF_HASH_SIZE_BYTES, F>>, // data_hash_proofs
        Vec<InclusionProof<HEADER_PROOF_DEPTH, PROTOBUF_BLOCK_ID_SIZE_BYTES, F>>, // prev_header_proofs
        [u8; 32], // expected_data_commitment
    );
}

#[async_trait]
impl DataCommitmentInputs for InputDataFetcher {
    async fn get_data_commitment(&self, start_block: u64, end_block: u64) -> [u8; 32] {
        // If start_block == end_block, then return a dummy commitment.
        // This will occur in the context of data commitment's map reduce when leaves that contain blocks beyond the end_block.
        if end_block <= start_block {
            return [0u8; 32];
        }

        let file_name = format!(
            "{}/{}-{}/data_commitment.json",
            self.fixture_path,
            start_block.to_string().as_str(),
            end_block.to_string().as_str()
        );
        let fetched_result = match &self.mode {
            InputDataMode::Rpc(url) => {
                let query_url = format!(
                    "{}/data_commitment?start={}&end={}",
                    url,
                    start_block.to_string().as_str(),
                    end_block.to_string().as_str()
                );
                info!("Querying url: {}", query_url);
                let res = reqwest::get(query_url).await.unwrap().text().await.unwrap();
                if self.save {
                    // Ensure the directory exists
                    if let Some(parent) = Path::new(&file_name).parent() {
                        fs::create_dir_all(parent).unwrap();
                    }
                    fs::write(file_name.as_str(), res.as_bytes()).expect("Unable to write file");
                }
                res
            }
            InputDataMode::Fixture => {
                let file_content = fs::read_to_string(file_name.as_str());
                info!("Fixture name: {}", file_name.as_str());
                file_content.unwrap()
            }
        };
        let v: DataCommitmentResponse =
            serde_json::from_str(&fetched_result).expect("Failed to parse JSON");

        hex::decode_upper(v.result.data_commitment)
            .unwrap()
            .try_into()
            .unwrap()
    }

    async fn get_data_commitment_inputs<const MAX_LEAVES: usize, F: RichField>(
        &mut self,
        start_block_number: u64,
        end_block_number: u64,
    ) -> (
        [u8; 32],                                                             // start_header_hash
        [u8; 32],                                                             // end_header_hash
        Vec<[u8; 32]>,                                                        // data_hashes
        Vec<InclusionProof<HEADER_PROOF_DEPTH, PROTOBUF_HASH_SIZE_BYTES, F>>, // data_hash_proofs
        Vec<InclusionProof<HEADER_PROOF_DEPTH, PROTOBUF_BLOCK_ID_SIZE_BYTES, F>>, // prev_header_proofs
        [u8; 32], // expected_data_commitment
    ) {
        let mut data_hashes = Vec::new();
        let mut data_hash_proofs = Vec::new();
        let mut prev_header_proofs = Vec::new();
        for i in start_block_number..end_block_number + 1 {
            let header = self.get_header_from_number(i).await;
            let data_hash = header.data_hash.unwrap();
            data_hashes.push(data_hash.as_bytes().try_into().unwrap());

            let data_hash_proof = self.get_inclusion_proof::<PROTOBUF_HASH_SIZE_BYTES, F>(
                &header,
                DATA_HASH_INDEX as u64,
                header.data_hash.unwrap().encode_vec(),
            );
            data_hash_proofs.push(data_hash_proof);
            let prev_header_proof = self.get_inclusion_proof::<PROTOBUF_BLOCK_ID_SIZE_BYTES, F>(
                &header,
                LAST_BLOCK_ID_INDEX as u64,
                Protobuf::<RawBlockId>::encode_vec(header.last_block_id.unwrap_or_default()),
            );
            prev_header_proofs.push(prev_header_proof);
        }

        // If there is no data commitment, each of the above vectors will be empty.
        if !data_hashes.is_empty() {
            // Remove the data hash and corresponding proof of end_block, as data_commitment does not include it.
            data_hashes.pop();
            data_hash_proofs.pop();

            // Remove prev_header_proof of start_block, as data_commitment does not include it.
            prev_header_proofs = prev_header_proofs[1..].to_vec();
        }

        let mut data_hash_proofs_formatted = data_hash_proofs
            .into_iter()
            .map(
                |proof| InclusionProof::<HEADER_PROOF_DEPTH, PROTOBUF_HASH_SIZE_BYTES, F> {
                    proof: proof.proof,
                    leaf: proof.leaf,
                },
            )
            .collect_vec();

        let mut prev_header_proofs_formatted = prev_header_proofs
            .into_iter()
            .map(
                |proof| InclusionProof::<HEADER_PROOF_DEPTH, PROTOBUF_BLOCK_ID_SIZE_BYTES, F> {
                    proof: proof.proof,
                    leaf: proof.leaf,
                },
            )
            .collect_vec();

        let num_so_far = data_hashes.len();
        // Extend data_hashes, data_hash_proofs, and prev_header_proofs to MAX_LEAVES.
        for _ in num_so_far..MAX_LEAVES {
            data_hashes.push([0u8; 32]);
            data_hash_proofs_formatted.push(InclusionProof::<
                HEADER_PROOF_DEPTH,
                PROTOBUF_HASH_SIZE_BYTES,
                F,
            > {
                proof: [H256::zero(); HEADER_PROOF_DEPTH].to_vec(),
                leaf: [0u8; PROTOBUF_HASH_SIZE_BYTES],
            });
            prev_header_proofs_formatted.push(InclusionProof::<
                HEADER_PROOF_DEPTH,
                PROTOBUF_BLOCK_ID_SIZE_BYTES,
                F,
            > {
                proof: [H256::zero(); HEADER_PROOF_DEPTH].to_vec(),
                leaf: [0u8; PROTOBUF_BLOCK_ID_SIZE_BYTES],
            });
        }

        let expected_data_commitment = self
            .get_data_commitment(start_block_number, end_block_number)
            .await;

        let mut start_header = [0u8; 32];
        let mut end_header = [0u8; 32];
        if start_block_number < end_block_number {
            start_header = self
                .get_header_from_number(start_block_number)
                .await
                .hash()
                .as_bytes()
                .try_into()
                .unwrap();
            end_header = self
                .get_header_from_number(end_block_number)
                .await
                .hash()
                .as_bytes()
                .try_into()
                .unwrap();
        }

        (
            start_header,
            end_header,
            data_hashes,
            data_hash_proofs_formatted,
            prev_header_proofs_formatted,
            expected_data_commitment,
        )
    }
}
