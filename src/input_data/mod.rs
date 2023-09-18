pub mod tendermint_utils;
pub mod types;
pub mod utils;

use std::{collections::HashMap, fs};

use crate::input_data::types::get_validators_as_input;

use self::tendermint_utils::{
    generate_proofs_from_header, Hash, Header, Proof, SignedBlockResponse, TempSignedBlock,
};
use self::types::{update_present_on_trusted_header, TempMerkleInclusionProof};
use self::utils::{convert_to_h256, get_path_indices};
use crate::utils::{
    BLOCK_HEIGHT_INDEX, LAST_BLOCK_ID_INDEX, NEXT_VALIDATORS_HASH_INDEX, TOTAL_HEADER_FIELDS,
    VALIDATORS_HASH_INDEX,
};
use ethers::types::H256;
use tendermint::{validator::Set as ValidatorSet, vote::SignedVote, vote::ValidatorIndex};
use tendermint_proto::types::BlockId as RawBlockId;
use tendermint_proto::Protobuf;

pub enum InputDataMode {
    Rpc(String),
    Fixture,
}

pub struct InputDataFetcher {
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

    pub async fn get_block_from_number(&self, block_number: u64) -> Box<TempSignedBlock> {
        let fetched_result = match &self.mode {
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
        Box::new(temp_block)
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

    pub async fn get_step_inputs<const VALIDATOR_SET_SIZE_MAX: usize>(
        &mut self,
        prev_block_number: u64,
        prev_header_hash: H256,
    ) -> Vec<u8> {
        let prev_block = self.get_block_from_number(prev_block_number).await;
        let computed_prev_header_hash = prev_block.header.hash();
        assert_eq!(
            computed_prev_header_hash.as_bytes(),
            prev_header_hash.as_bytes()
        );
        let next_block = self.get_block_from_number(prev_block_number + 1).await;
        let next_block_header = next_block.header.hash();
        let next_block_validators = get_validators_as_input::<VALIDATOR_SET_SIZE_MAX>(&next_block);

        let next_block_validators_hash_proof = self.get_merkle_proof(
            &next_block.header,
            VALIDATORS_HASH_INDEX as u64,
            next_block.header.validators_hash.encode_vec(),
        );

        let last_block_id_hash = next_block.header.last_block_id.unwrap().hash;
        let encoded_last_block_id =
            Protobuf::<RawBlockId>::encode_vec(next_block.header.last_block_id.unwrap_or_default());
        assert_eq!(
            last_block_id_hash.as_bytes(),
            &encoded_last_block_id[2..34],
            "prev header hash doesn't pass sanity check"
        );
        let next_block_last_block_id_proof = self.get_merkle_proof(
            &next_block.header,
            LAST_BLOCK_ID_INDEX as u64,
            encoded_last_block_id,
        );

        let prev_block_next_validators_hash_proof = self.get_merkle_proof(
            &prev_block.header,
            NEXT_VALIDATORS_HASH_INDEX as u64,
            prev_block.header.next_validators_hash.encode_vec(),
        );
        todo!()
    }

    pub async fn get_skip_inputs<const VALIDATOR_SET_SIZE_MAX: usize>(
        &mut self,
        trusted_block_number: u64,
        trusted_block_hash: H256,
        target_block_number: u64,
    ) -> Vec<u8> {
        let trusted_block = self.get_block_from_number(trusted_block_number).await;
        let computed_trusted_header_hash = trusted_block.header.hash();
        assert_eq!(
            computed_trusted_header_hash.as_bytes(),
            trusted_block_hash.as_bytes()
        );
        let target_block = self.get_block_from_number(target_block_number + 1).await;
        let target_block_header = target_block.header.hash();
        let mut target_block_validators =
            get_validators_as_input::<VALIDATOR_SET_SIZE_MAX>(&target_block);
        update_present_on_trusted_header(
            &mut target_block_validators,
            &target_block,
            &trusted_block,
        );

        let target_block_validators_hash_proof = self.get_merkle_proof(
            &target_block.header,
            VALIDATORS_HASH_INDEX as u64,
            target_block.header.validators_hash.encode_vec(),
        );

        let trusted_block_validator_fields =
            get_validators_as_input::<VALIDATOR_SET_SIZE_MAX>(&trusted_block);
        let trusted_block_validator_hash_proof = self.get_merkle_proof(
            &trusted_block.header,
            VALIDATORS_HASH_INDEX as u64,
            trusted_block.header.validators_hash.encode_vec(),
        );

        // TODO: need 1 more merkle proof for the block height of the target block
        // to ensure that it matches the provided target_block_number

        todo!()
    }
}
