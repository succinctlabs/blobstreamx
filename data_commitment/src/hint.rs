use std::fs;
use std::path::Path;

use async_trait::async_trait;
use celestia::consts::*;
use celestia::input_data::utils::convert_to_h256;
use celestia::input_data::{InputDataFetcher, InputDataMode};
use celestia::variables::*;
use ethers::types::H256;
use itertools::Itertools;
use plonky2x::frontend::hint::simple::hint::Hint;
use plonky2x::frontend::merkle::tree::InclusionProof;
use plonky2x::frontend::uint::uint64::U64Variable;
use plonky2x::frontend::vars::ValueStream;
use plonky2x::prelude::{Bytes32Variable, PlonkParameters, RichField};
use serde::{Deserialize, Serialize};
use subtle_encoding::hex;
use tendermint_proto::types::BlockId as RawBlockId;
use tendermint_proto::Protobuf;
use tokio::runtime::Runtime;

use crate::vars::*;

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
        start_header_hash: H256,
        end_block_number: u64,
        end_header_hash: H256,
    ) -> (
        Vec<[u8; 32]>,                                                            // data_hashes
        Vec<InclusionProof<HEADER_PROOF_DEPTH, PROTOBUF_HASH_SIZE_BYTES, F>>, // data_hash_proofs
        Vec<InclusionProof<HEADER_PROOF_DEPTH, PROTOBUF_BLOCK_ID_SIZE_BYTES, F>>, // prev_header_proofs
        [u8; 32], // expected_data_commitment
    );
}

#[async_trait]
impl DataCommitmentInputs for InputDataFetcher {
    async fn get_data_commitment(&self, start_block: u64, end_block: u64) -> [u8; 32] {
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
                println!("Retrieving fixture");
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
        start_header_hash: H256,
        end_block_number: u64,
        end_header_hash: H256,
    ) -> (
        Vec<[u8; 32]>,                                                            // data_hashes
        Vec<InclusionProof<HEADER_PROOF_DEPTH, PROTOBUF_HASH_SIZE_BYTES, F>>, // data_hash_proofs
        Vec<InclusionProof<HEADER_PROOF_DEPTH, PROTOBUF_BLOCK_ID_SIZE_BYTES, F>>, // prev_header_proofs
        [u8; 32], // expected_data_commitment
    ) {
        let start_header = self.get_header_from_number(start_block_number).await;
        let computed_start_header_hash = start_header.hash();
        assert_eq!(
            computed_start_header_hash.as_bytes(),
            start_header_hash.as_bytes()
        );

        let end_header = self.get_header_from_number(end_block_number).await;
        let computed_end_header_hash = end_header.hash();
        assert_eq!(
            computed_end_header_hash.as_bytes(),
            end_header_hash.as_bytes()
        );

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

        // Remove end_block's data_hash, as data_commitment does not include it.
        data_hashes.pop();

        // Remove end_block's data_hash_proof, as data_commitment does not check it.
        data_hash_proofs.pop();

        // Remove start_block's prev_header_proof, as data_commitment does not check it.
        prev_header_proofs = prev_header_proofs[1..].to_vec();

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

        // Extend data_hashes, data_hash_proofs, and prev_header_proofs to MAX_LEAVES.
        for _ in (end_block_number - start_block_number) as usize..MAX_LEAVES {
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

        (
            data_hashes,
            data_hash_proofs_formatted,
            prev_header_proofs_formatted,
            expected_data_commitment,
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DataCommitmentOffchainInputs<const MAX_LEAVES: usize> {}

impl<const MAX_LEAVES: usize, L: PlonkParameters<D>, const D: usize> Hint<L, D>
    for DataCommitmentOffchainInputs<MAX_LEAVES>
{
    fn hint(&self, input_stream: &mut ValueStream<L, D>, output_stream: &mut ValueStream<L, D>) {
        let start_block = input_stream.read_value::<U64Variable>();
        let start_header_hash = input_stream.read_value::<Bytes32Variable>();
        let end_block = input_stream.read_value::<U64Variable>();
        let end_header_hash = input_stream.read_value::<Bytes32Variable>();

        let mut data_fetcher = InputDataFetcher::new();

        let rt = Runtime::new().expect("failed to create tokio runtime");
        let result = rt.block_on(async {
            data_fetcher
                .get_data_commitment_inputs::<MAX_LEAVES, L::Field>(
                    start_block,
                    start_header_hash,
                    end_block,
                    end_header_hash,
                )
                .await
        });
        let data_comm_proof = DataCommitmentProofValueType {
            data_hashes: convert_to_h256(result.0),
            start_block_height: start_block,
            start_header: start_header_hash,
            end_block_height: end_block,
            end_header: end_header_hash,
            data_hash_proofs: result.1,
            prev_header_proofs: result.2,
        };
        // Write the inputs to the data commitment circuit.
        output_stream.write_value::<DataCommitmentProofVariable<MAX_LEAVES>>(data_comm_proof);
        // Write the expected data commitment.
        output_stream.write_value::<Bytes32Variable>(H256(result.3));
    }
}
