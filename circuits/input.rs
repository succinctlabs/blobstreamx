use std::fs;
use std::path::Path;

use async_trait::async_trait;
use ethers::types::H256;
use log::info;
use plonky2x::frontend::merkle::tree::InclusionProof;
use plonky2x::prelude::RichField;
use serde::Deserialize;
use subtle_encoding::hex;
use tendermint_proto::types::BlockId as RawBlockId;
use tendermint_proto::Protobuf;
use tendermintx::input::{InputDataFetcher, InputDataMode};

use crate::consts::*;

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
    async fn get_last_block_id_proof<F: RichField>(
        &mut self,
        block_number: u64,
    ) -> InclusionProof<HEADER_PROOF_DEPTH, PROTOBUF_BLOCK_ID_SIZE_BYTES, F>;

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
        Vec<InclusionProof<HEADER_PROOF_DEPTH, PROTOBUF_BLOCK_ID_SIZE_BYTES, F>>, // last_block_id_proofs
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
            InputDataMode::Rpc => {
                let query_url = format!(
                    "{}/data_commitment?start={}&end={}",
                    self.url,
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

    async fn get_last_block_id_proof<F: RichField>(
        &mut self,
        block_number: u64,
    ) -> InclusionProof<HEADER_PROOF_DEPTH, PROTOBUF_BLOCK_ID_SIZE_BYTES, F> {
        let curr_header = self.get_signed_header_from_number(block_number).await;

        let prev_header = self.get_signed_header_from_number(block_number - 1).await;
        let last_block_id_proof = self.get_inclusion_proof::<PROTOBUF_BLOCK_ID_SIZE_BYTES, F>(
            &curr_header.header,
            LAST_BLOCK_ID_INDEX as u64,
            Protobuf::<RawBlockId>::encode_vec(
                curr_header.header.last_block_id.unwrap_or_default(),
            ),
        );
        last_block_id_proof
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
        Vec<InclusionProof<HEADER_PROOF_DEPTH, PROTOBUF_BLOCK_ID_SIZE_BYTES, F>>, // last_block_id_proofs
        [u8; 32], // expected_data_commitment
    ) {
        let mut data_hashes = Vec::new();
        let mut data_hash_proofs = Vec::new();
        let mut last_block_id_proofs = Vec::new();
        for i in start_block_number..end_block_number + 2 {
            let signed_header = self.get_signed_header_from_number(i).await;

            // Don't include the data hash and corresponding proof of end_block, as the circuit's
            // data_commitment is computed over the range [start_block, end_block], inclusive.
            if i < end_block_number {
                let data_hash = signed_header.header.data_hash.unwrap();
                data_hashes.push(data_hash.as_bytes().try_into().unwrap());

                let data_hash_proof = self.get_inclusion_proof::<PROTOBUF_HASH_SIZE_BYTES, F>(
                    &signed_header.header,
                    DATA_HASH_INDEX as u64,
                    signed_header.header.data_hash.unwrap().encode_vec(),
                );
                data_hash_proofs.push(data_hash_proof);
            }

            // Don't include last_block_id of start, as the data_commitment circuit only requires
            // the last block id's of blocks in the range [start_block + 1, end_block + 1]. Specifically,
            // the circuit needs the last_block_id proofs from the next block of every block in the
            // data_commitment range shifted by one.
            if i > start_block_number {
                let last_block_id_proof = self
                    .get_inclusion_proof::<PROTOBUF_BLOCK_ID_SIZE_BYTES, F>(
                        &signed_header.header,
                        LAST_BLOCK_ID_INDEX as u64,
                        Protobuf::<RawBlockId>::encode_vec(
                            signed_header.header.last_block_id.unwrap_or_default(),
                        ),
                    );
                last_block_id_proofs.push(last_block_id_proof);
            }
        }

        let mut data_hash_proofs_formatted = data_hash_proofs
            .into_iter()
            .map(
                |proof| InclusionProof::<HEADER_PROOF_DEPTH, PROTOBUF_HASH_SIZE_BYTES, F> {
                    proof: proof.proof,
                    leaf: proof.leaf,
                },
            )
            .collect::<Vec<_>>();

        let mut last_block_id_proofs_formatted = last_block_id_proofs
            .into_iter()
            .map(
                |proof| InclusionProof::<HEADER_PROOF_DEPTH, PROTOBUF_BLOCK_ID_SIZE_BYTES, F> {
                    proof: proof.proof,
                    leaf: proof.leaf,
                },
            )
            .collect::<Vec<_>>();

        let num_so_far = data_hashes.len();
        // Extend data_hashes, data_hash_proofs, and last_block_id_proofs to MAX_LEAVES.
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
            last_block_id_proofs_formatted.push(InclusionProof::<
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
        // If start_block_number >= end_block_number, then start_header and end_header are dummy values.
        if start_block_number < end_block_number {
            start_header = self
                .get_signed_header_from_number(start_block_number)
                .await
                .header
                .hash()
                .as_bytes()
                .try_into()
                .unwrap();
            end_header = self
                .get_signed_header_from_number(end_block_number)
                .await
                .header
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
            last_block_id_proofs_formatted,
            expected_data_commitment,
        )
    }
}
