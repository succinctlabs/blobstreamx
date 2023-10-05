pub mod tendermint_utils;
pub mod types;
pub mod utils;

use std::collections::HashMap;
use std::path::Path;
use std::{env, fs};

use ethers::types::H256;
use itertools::Itertools;
use plonky2x::frontend::merkle::tree::InclusionProof;
use plonky2x::prelude::RichField;
use subtle_encoding::hex;
use tendermint_proto::types::BlockId as RawBlockId;
use tendermint_proto::Protobuf;

use self::tendermint_utils::{
    generate_proofs_from_header, DataCommitmentResponse, Hash, Header, HeaderResponse, Proof,
    SignedBlock, SignedBlockResponse,
};
use self::types::update_present_on_trusted_header;
use self::utils::convert_to_h256;
use crate::consts::{
    BLOCK_HEIGHT_INDEX, DATA_HASH_INDEX, HEADER_PROOF_DEPTH, LAST_BLOCK_ID_INDEX,
    NEXT_VALIDATORS_HASH_INDEX, PROTOBUF_BLOCK_ID_SIZE_BYTES, PROTOBUF_HASH_SIZE_BYTES,
    VALIDATORS_HASH_INDEX,
};
use crate::input_data::types::{get_validators_as_input, get_validators_fields_as_input};
use crate::variables::*;

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
            fixture_path: "./fixtures/mocha-4".to_string(),
        }
    }

    pub fn set_save(&mut self, save: bool) {
        self.save = save;
    }

    pub async fn get_block_from_number(&self, block_number: u64) -> Box<SignedBlock> {
        let file_name = format!(
            "{}/{}/signed_block.json",
            self.fixture_path,
            block_number.to_string().as_str()
        );
        let fetched_result = match &self.mode {
            InputDataMode::Rpc(url) => {
                let query_url = format!(
                    "{}/signed_block?height={}",
                    url,
                    block_number.to_string().as_str()
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
        let v: SignedBlockResponse =
            serde_json::from_str(&fetched_result).expect("Failed to parse JSON");
        let temp_block = v.result;
        Box::new(temp_block)
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

    pub async fn get_step_inputs<const VALIDATOR_SET_SIZE_MAX: usize, F: RichField>(
        &mut self,
        prev_block_number: u64,
        prev_header_hash: H256,
    ) -> (
        [u8; 32],
        bool,
        Vec<Validator<F>>,
        InclusionProof<HEADER_PROOF_DEPTH, PROTOBUF_HASH_SIZE_BYTES, F>,
        InclusionProof<HEADER_PROOF_DEPTH, PROTOBUF_BLOCK_ID_SIZE_BYTES, F>,
        InclusionProof<HEADER_PROOF_DEPTH, PROTOBUF_HASH_SIZE_BYTES, F>,
    ) {
        println!("Getting step inputs");
        let prev_block = self.get_block_from_number(prev_block_number).await;
        let computed_prev_header_hash = prev_block.header.hash();
        assert_eq!(
            computed_prev_header_hash.as_bytes(),
            prev_header_hash.as_bytes()
        );
        let next_block = self.get_block_from_number(prev_block_number + 1).await;
        let round_present = next_block.commit.round.value() != 0;

        let next_block_header = next_block.header.hash();

        let next_block_validators =
            get_validators_as_input::<VALIDATOR_SET_SIZE_MAX, F>(&next_block);
        assert_eq!(
            next_block_validators.len(),
            VALIDATOR_SET_SIZE_MAX,
            "validator set size needs to be the provided validator_set_size_max"
        );

        let next_block_validators_hash_proof = self.get_inclusion_proof(
            &next_block.header,
            VALIDATORS_HASH_INDEX as u64,
            next_block.header.validators_hash.encode_vec(),
        );

        let last_block_id_hash = next_block.header.last_block_id.unwrap().hash;
        let encoded_last_block_id =
            Protobuf::<RawBlockId>::encode_vec(next_block.header.last_block_id.unwrap_or_default());
        println!("encoded_last_block_id {:?}", encoded_last_block_id);
        assert_eq!(
            last_block_id_hash.as_bytes(),
            &encoded_last_block_id[2..34],
            "prev header hash doesn't pass sanity check"
        );
        let next_block_last_block_id_proof = self.get_inclusion_proof(
            &next_block.header,
            LAST_BLOCK_ID_INDEX as u64,
            encoded_last_block_id,
        );

        let prev_block_next_validators_hash_proof = self.get_inclusion_proof(
            &prev_block.header,
            NEXT_VALIDATORS_HASH_INDEX as u64,
            prev_block.header.next_validators_hash.encode_vec(),
        );
        (
            next_block_header.as_bytes().try_into().unwrap(),
            round_present,
            next_block_validators,
            next_block_validators_hash_proof,
            next_block_last_block_id_proof,
            prev_block_next_validators_hash_proof,
        )
    }

    pub async fn get_skip_inputs<const VALIDATOR_SET_SIZE_MAX: usize, F: RichField>(
        &mut self,
        trusted_block_number: u64,
        trusted_block_hash: H256,
        target_block_number: u64,
    ) -> (
        Vec<Validator<F>>,                                               // validators
        [u8; 32],                                                        // target_header
        bool,                                                            // round_present
        HeightProofValueType<F>, // target_block_height_proof,
        InclusionProof<HEADER_PROOF_DEPTH, PROTOBUF_HASH_SIZE_BYTES, F>, // target_header_validators_hash_proof,
        [u8; 32],                                                        // trusted_header
        InclusionProof<HEADER_PROOF_DEPTH, PROTOBUF_HASH_SIZE_BYTES, F>, // trusted_validators_hash_proof
        Vec<ValidatorHashField<F>>, // trusted_validators_hash_fields
    ) {
        let trusted_block = self.get_block_from_number(trusted_block_number).await;
        let computed_trusted_header_hash = trusted_block.header.hash();
        assert_eq!(
            computed_trusted_header_hash.as_bytes(),
            trusted_block_hash.as_bytes()
        );
        let target_block = self.get_block_from_number(target_block_number).await;
        let target_block_header = target_block.header.hash();
        let round_present = target_block.commit.round.value() != 0;
        let mut target_block_validators =
            get_validators_as_input::<VALIDATOR_SET_SIZE_MAX, F>(&target_block);
        update_present_on_trusted_header(
            &mut target_block_validators,
            &target_block,
            &trusted_block,
        );

        let temp_target_block_height_proof = self.get_merkle_proof(
            &target_block.header,
            BLOCK_HEIGHT_INDEX as u64,
            target_block.header.height.encode_vec(),
        );

        let target_block_height_proof = HeightProofValueType::<F> {
            height: target_block.header.height.value(),
            enc_height_byte_length: target_block.header.height.encode_vec().len() as u32,
            proof: temp_target_block_height_proof.1,
        };

        let target_block_validators_hash_proof = self.get_inclusion_proof(
            &target_block.header,
            VALIDATORS_HASH_INDEX as u64,
            target_block.header.validators_hash.encode_vec(),
        );

        let trusted_block_validator_fields =
            get_validators_fields_as_input::<VALIDATOR_SET_SIZE_MAX, F>(&trusted_block);
        let trusted_block_validator_hash_proof = self.get_inclusion_proof(
            &trusted_block.header,
            VALIDATORS_HASH_INDEX as u64,
            trusted_block.header.validators_hash.encode_vec(),
        );

        (
            target_block_validators,
            target_block_header.as_bytes().try_into().unwrap(),
            round_present,
            target_block_height_proof,
            target_block_validators_hash_proof,
            trusted_block_hash.as_bytes().try_into().unwrap(),
            trusted_block_validator_hash_proof,
            trusted_block_validator_fields,
        )
    }
}

mod test {

    // Run with cargo test --lib input_data::test::test_fixture_generation_asdf -- --nocapture
    #[tokio::test]
    async fn test_fixture_generation_asdf() {
        // TODO: Clippy does not recognize imports in Tokio tests.
        use std::env;

        use crate::input_data::InputDataFetcher;

        env::set_var(
            "RPC_MOCHA_4",
            "http://rpc.testnet.celestia.citizencosmos.space",
        );

        let block_height = 11105u64;
        let mut fetcher = InputDataFetcher::new();
        fetcher.set_save(true);
        let _block = fetcher.get_block_from_number(block_height).await;
    }
}
