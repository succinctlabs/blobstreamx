pub mod tendermint_utils;
pub mod types;
pub mod utils;

use std::{collections::HashMap, fs};

use self::tendermint_utils::{
    generate_proofs_from_header, Hash, Header, Proof, SignedBlockResponse,
};
use self::utils::{convert_to_h256, get_path_indices};
use crate::{inputs::TempMerkleInclusionProof, utils::TempSignedBlock};

enum InputDataMode {
    Rpc(String),
    Fixture,
}

struct InputDataFetcher {
    mode: InputDataMode,
    proof_cache: HashMap<Hash, Vec<Proof>>,
}

impl InputDataFetcher {
    pub fn new(mode: InputDataMode) -> Self {
        Self {
            mode,
            proof_cache: HashMap::new(),
        }
    }

    pub async fn get_block_from_number(self, block_number: u64) -> Box<TempSignedBlock> {
        let fetched_result = match self.mode {
            InputDataMode::Rpc(url) => {
                let query_url = format!(
                    "{}/signed_block?height={}",
                    url,
                    block_number.to_string().as_str()
                );
                let res = reqwest::get(url).await.unwrap().text().await.unwrap();
                res
            }
            InputDataMode::Fixture => {
                let file_name = format!(
                    "./src/fixtures/mocha-3/{}/signed_block.json",
                    block_number.to_string().as_str()
                );
                let file_content = fs::read_to_string(file_name.as_str());
                file_content.unwrap()
            }
        };
        let v: SignedBlockResponse =
            serde_json::from_str(&fetched_result).expect("Failed to parse JSON");
        let temp_block = v.result;
        todo!()
    }

    // TODO: return validators, validator_hash_proof
    pub fn get_validators_input(block: &TempSignedBlock, index: usize) {
        todo!()
    }

    pub fn get_merkle_proof(
        &mut self,
        block_header: &Header,
        index: u64,
        encoded_leaf: Vec<u8>,
    ) -> TempMerkleInclusionProof {
        let hash: Hash = block_header.hash().as_bytes().try_into().unwrap();
        let proofs = match self.proof_cache.get(&hash) {
            Some(proofs) => proofs.clone(),
            None => {
                let (hash, proofs) = generate_proofs_from_header(&block_header);
                self.proof_cache.insert(hash, proofs.clone());
                proofs.clone()
            }
        };
        let total = proofs[0].total;
        // TODO: check that the markle proof is valid
        // before returning
        TempMerkleInclusionProof {
            enc_leaf: encoded_leaf,
            path: get_path_indices(index, total),
            proof: convert_to_h256(proofs[index as usize].aunts.clone()),
        }
    }

    pub fn get_step_inputs<const VALIDATOR_SET_SIZE_MAX: usize>(prev_block_number: u64) -> Vec<u8> {
        todo!()
    }

    pub fn get_skip_inputs(trusted_block_number: u64, target_block_number: u64) -> Vec<u8> {
        todo!()
    }
}
