use std::collections::HashMap;
use std::path::Path;
use std::{env, fs};

use ethers::types::H256;
use log::info;
use plonky2x::frontend::merkle::tree::InclusionProof;
use plonky2x::prelude::RichField;
use serde::Deserialize;
use subtle_encoding::hex;
use tendermint::block::Header;
use tendermint_proto::types::BlockId as RawBlockId;
use tendermint_proto::Protobuf;
use tendermintx::input::tendermint_utils::{
    generate_proofs_from_header, Hash, HeaderResponse, Proof,
};

use crate::consts::*;

#[derive(Debug, Deserialize)]
pub struct DataCommitmentResponse {
    pub result: DataCommitment,
}

#[derive(Debug, Deserialize)]
pub struct DataCommitment {
    pub data_commitment: String,
}

pub enum InputDataMode {
    Rpc(String),
    Fixture,
}

pub struct InputDataFetcher {
    pub mode: InputDataMode,
    pub proof_cache: HashMap<Hash, Vec<Proof>>,
    pub save: bool,
    pub fixture_path: String,
}

impl Default for InputDataFetcher {
    fn default() -> Self {
        Self::new()
    }
}

impl InputDataFetcher {
    pub fn new() -> Self {
        dotenv::dotenv().ok();
        let url = env::var("RPC_MOCHA_4").expect("RPC_MOCHA_4 is not set in .env");

        let mode = if url.is_empty() || url == "fixture" {
            println!("Using fixture mode for data fetcher");
            InputDataMode::Fixture
        } else {
            println!("Using rpc mode for data fetch with rpc {:?}", url.as_str());
            InputDataMode::Rpc(url.clone())
        };

        Self {
            mode,
            proof_cache: HashMap::new(),
            save: false,
            fixture_path: "./circuits/fixtures/mocha-4".to_string(),
        }
    }

    pub fn set_save(&mut self, save: bool) {
        self.save = save;
    }

    pub async fn get_header_from_number(&self, block_number: u64) -> Header {
        let file_name = format!(
            "{}/{}/header.json",
            self.fixture_path,
            block_number.to_string().as_str()
        );
        let fetched_result = match &self.mode {
            InputDataMode::Rpc(url) => {
                let query_url = format!(
                    "{}/header?height={}",
                    url,
                    block_number.to_string().as_str()
                );
                info!("Querying url {:?}", query_url.as_str());
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
        let v: HeaderResponse =
            serde_json::from_str(&fetched_result).expect("Failed to parse JSON");
        v.result.header
    }

    pub fn get_merkle_proof(
        &mut self,
        block_header: &Header,
        index: u64,
        encoded_leaf: Vec<u8>,
    ) -> (Vec<u8>, Vec<H256>) {
        let hash: Hash = block_header.hash().as_bytes().try_into().unwrap();
        let proofs = match self.proof_cache.get(&hash) {
            Some(proofs) => proofs.clone(),
            None => {
                let (hash, proofs) = generate_proofs_from_header(block_header);
                self.proof_cache.insert(hash, proofs.clone());
                proofs
            }
        };
        let proof = proofs[index as usize].clone();
        (encoded_leaf, convert_to_h256(proof.aunts))
    }

    pub fn get_inclusion_proof<const LEAF_SIZE_BYTES: usize, F: RichField>(
        &mut self,
        block_header: &Header,
        index: u64,
        encoded_leaf: Vec<u8>,
    ) -> InclusionProof<HEADER_PROOF_DEPTH, LEAF_SIZE_BYTES, F> {
        let (leaf, proof) = self.get_merkle_proof(block_header, index, encoded_leaf);
        InclusionProof {
            leaf: leaf.try_into().unwrap(),
            proof,
        }
    }

    pub async fn get_data_commitment(&self, start_block: u64, end_block: u64) -> [u8; 32] {
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

    pub async fn get_data_commitment_inputs<const MAX_LEAVES: usize, F: RichField>(
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
            let last_block_id_proof = self.get_inclusion_proof::<PROTOBUF_BLOCK_ID_SIZE_BYTES, F>(
                &header,
                LAST_BLOCK_ID_INDEX as u64,
                Protobuf::<RawBlockId>::encode_vec(header.last_block_id.unwrap_or_default()),
            );
            last_block_id_proofs.push(last_block_id_proof);
        }

        // If there is no data commitment, each of the above vectors will be empty.
        if !data_hashes.is_empty() {
            // Remove the data hash and corresponding proof of end_block, as data_commitment does not include it.
            data_hashes.pop();
            data_hash_proofs.pop();

            // Remove last_block_id_proof of start_block, as data_commitment does not include it.
            last_block_id_proofs = last_block_id_proofs[1..].to_vec();
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
            last_block_id_proofs_formatted,
            expected_data_commitment,
        )
    }
}

pub fn convert_to_h256(aunts: Vec<[u8; 32]>) -> Vec<H256> {
    let mut aunts_h256 = Vec::new();
    for aunt in aunts {
        aunts_h256.push(H256::from_slice(&aunt));
    }
    aunts_h256
}
