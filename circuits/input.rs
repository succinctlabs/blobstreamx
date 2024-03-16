use std::fs;
use std::path::Path;

use async_trait::async_trait;
use ethers::types::H256;
use log::info;
use plonky2x::frontend::merkle::tree::InclusionProof;
use plonky2x::prelude::RichField;
use serde::Deserialize;
use subtle_encoding::hex;
use tendermint::block::signed_header::SignedHeader;
use tendermint_proto::types::BlockId as RawBlockId;
use tendermint_proto::Protobuf;
use tendermintx::input::tendermint_utils::CommitResponse;
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

#[derive(Debug, Clone)]
pub struct DataCommitmentInputs<F: RichField> {
    pub start_header_hash: [u8; 32],
    pub end_header_hash: [u8; 32],
    pub data_hash_proofs: Vec<InclusionProof<HEADER_PROOF_DEPTH, PROTOBUF_HASH_SIZE_BYTES, F>>,
    pub last_block_id_proofs:
        Vec<InclusionProof<HEADER_PROOF_DEPTH, PROTOBUF_BLOCK_ID_SIZE_BYTES, F>>,
    pub expected_data_commitment: [u8; 32],
}

#[async_trait]
pub trait DataCommitmentInputFetcher {
    async fn get_data_commitment(&mut self, start_block: u64, end_block: u64) -> [u8; 32];

    /// Get the latest block number.
    async fn get_latest_block_number(&self) -> u64;

    /// Get signed headers in the range [start_block_number, end_block_number] inclusive.
    /// Note: Assumes start_block_number and end_block_number are less than or equal to the latest
    /// block number.
    async fn get_signed_header_range(
        &self,
        start_block_number: u64,
        end_block_number: u64,
    ) -> Vec<SignedHeader>;

    async fn get_data_commitment_inputs<const MAX_LEAVES: usize, F: RichField>(
        &mut self,
        start_block_number: u64,
        end_block_number: u64,
    ) -> DataCommitmentInputs<F>;
}

const MAX_NUM_RETRIES: usize = 3;

#[async_trait]
impl DataCommitmentInputFetcher for InputDataFetcher {
    async fn get_data_commitment(&mut self, start_block: u64, end_block: u64) -> [u8; 32] {
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
        let route = format!(
            "data_commitment?start={}&end={}",
            start_block.to_string().as_str(),
            end_block.to_string().as_str()
        );
        let fetched_result = match &self.mode {
            InputDataMode::Rpc => {
                let res = self.request_from_rpc(&route, MAX_NUM_RETRIES).await;
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

    async fn get_latest_block_number(&self) -> u64 {
        let route = "commit";
        let res = self.request_from_rpc(route, MAX_NUM_RETRIES).await;
        let v: CommitResponse = serde_json::from_str(&res).expect("Failed to parse JSON");
        v.result.signed_header.header.height.into()
    }

    // Assumes start_block_number and end_block_number are less than or equal to the latest block number.
    async fn get_signed_header_range(
        &self,
        start_block_number: u64,
        end_block_number: u64,
    ) -> Vec<SignedHeader> {
        // Note: Tested with 500+ concurrent requests, but monitor for any issues.
        const MAX_BATCH_SIZE: usize = 200;

        let mut signed_headers = Vec::new();
        let mut curr_block = start_block_number;
        while curr_block <= end_block_number {
            let batch_end_block =
                std::cmp::min(curr_block + MAX_BATCH_SIZE as u64, end_block_number + 1);
            // Batch request the headers in the range [curr_block, batch_end_block).
            let batch_signed_header_futures = (curr_block..batch_end_block)
                .map(|i| self.get_signed_header_from_number(i))
                .collect::<Vec<_>>();
            let batch_signed_headers: Vec<SignedHeader> =
                futures::future::join_all(batch_signed_header_futures).await;
            signed_headers.extend(batch_signed_headers);

            curr_block += MAX_BATCH_SIZE as u64;
        }

        signed_headers
    }

    // start_block_number and end_block_number are not guaranteed to be less than the latest_block.
    // Fetch the latest block number, and use it to determine the actual range of signed headers to fetch.
    async fn get_data_commitment_inputs<const MAX_LEAVES: usize, F: RichField>(
        &mut self,
        start_block_number: u64,
        end_block_number: u64,
    ) -> DataCommitmentInputs<F> {
        let mut data_hash_proofs = Vec::new();
        let mut last_block_id_proofs = Vec::new();

        // Only request up to latest_block_number.
        let latest_block_number = self.get_latest_block_number().await;
        let request_end_block_number = std::cmp::min(end_block_number, latest_block_number);
        let signed_headers = self
            .get_signed_header_range(start_block_number, request_end_block_number)
            .await;

        for i in start_block_number..request_end_block_number + 1 {
            let signed_header = &signed_headers[(i - start_block_number) as usize];

            // Don't include the data hash and corresponding proof of end_block, as the circuit's
            // data_commitment is computed over the range [start_block, end_block - 1].
            if i < request_end_block_number {
                let data_hash = signed_header.header.data_hash.unwrap();

                let data_hash_proof = self.get_inclusion_proof::<PROTOBUF_HASH_SIZE_BYTES, F>(
                    &signed_header.header,
                    DATA_HASH_INDEX as u64,
                    data_hash.encode_vec(),
                );
                data_hash_proofs.push(data_hash_proof);
            }

            // Don't include last_block_id of start, as the data_commitment circuit only requires
            // the last block id's of blocks in the range [start_block + 1, end_block]. Specifically,
            // the circuit needs the last_block_id proofs of data_commitment range shifted by one
            // block to the right.
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

        let num_so_far = data_hash_proofs_formatted.len();
        // Extend data_hash_proofs and last_block_id_proofs to length MAX_LEAVES.
        for _ in num_so_far..MAX_LEAVES {
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

        // Fetch the expected data commitment.
        let expected_data_commitment = self
            .get_data_commitment(start_block_number, request_end_block_number)
            .await;

        let mut start_header = [0u8; 32];
        let mut end_header = [0u8; 32];
        // If start_block_number >= end_block_number, then start_header and end_header are dummy values.
        if start_block_number < request_end_block_number {
            start_header = signed_headers[0]
                .header
                .hash()
                .as_bytes()
                .try_into()
                .unwrap();
            end_header = signed_headers[signed_headers.len() - 1]
                .header
                .hash()
                .as_bytes()
                .try_into()
                .unwrap();
        }

        DataCommitmentInputs {
            start_header_hash: start_header,
            end_header_hash: end_header,
            data_hash_proofs: data_hash_proofs_formatted,
            last_block_id_proofs: last_block_id_proofs_formatted,
            expected_data_commitment,
        }
    }
}
#[cfg(test)]
mod tests {

    use std::env;

    use plonky2x::backend::circuit::{DefaultParameters, PlonkParameters};

    use super::*;

    const D: usize = 2;
    type L = DefaultParameters;
    type F = <L as PlonkParameters<D>>::Field;

    // Ensure that get_data_commitment_inputs doesn't fail with inputs greater than the latest block.
    #[cfg_attr(feature = "ci", ignore)]
    #[tokio::test]
    async fn test_get_data_commitment_inputs() {
        env_logger::init();
        env::set_var("RUST_LOG", "debug");
        dotenv::dotenv().ok();
        let mut fetcher = InputDataFetcher::default();
        let start_block = 3000000;
        let end_block = 3000010;
        let _ = fetcher
            .get_data_commitment_inputs::<32, F>(start_block, end_block)
            .await;
    }
}
