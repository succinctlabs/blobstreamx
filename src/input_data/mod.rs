pub mod tendermint_utils;
pub mod types;
pub mod utils;

use std::path::Path;
use std::{collections::HashMap, fs};

use self::tendermint_utils::{
    generate_proofs_from_header, Hash, Header, Proof, SignedBlockResponse, TempSignedBlock,
};
use self::types::{update_present_on_trusted_header, TempMerkleInclusionProof};
use self::utils::{convert_to_h256, get_path_indices};
use crate::consts::{
    BLOCK_HEIGHT_INDEX, LAST_BLOCK_ID_INDEX, NEXT_VALIDATORS_HASH_INDEX, VALIDATORS_HASH_INDEX,
};
use crate::input_data::types::{get_validators_as_input, get_validators_fields_as_input};
use crate::variables::HeightProofValueType;
use crate::verify::{Validator, ValidatorHashField};
use ethers::types::H256;
use plonky2x::frontend::ecc::ed25519::curve::ed25519::Ed25519;
use plonky2x::prelude::RichField;
use tendermint_proto::types::BlockId as RawBlockId;
use tendermint_proto::Protobuf;

pub enum InputDataMode {
    Rpc(String),
    Fixture,
}

pub struct InputDataFetcher {
    mode: InputDataMode,
    proof_cache: HashMap<Hash, Vec<Proof>>,
    save: bool,
}

impl InputDataFetcher {
    pub fn new(mode: InputDataMode) -> Self {
        Self {
            mode,
            proof_cache: HashMap::new(),
            save: false,
        }
    }

    pub fn set_save(&mut self, save: bool) {
        self.save = save;
    }

    pub async fn get_block_from_number(&self, block_number: u64) -> Box<TempSignedBlock> {
        let fetched_result = match &self.mode {
            InputDataMode::Rpc(url) => {
                let query_url = format!(
                    "{}/signed_block?height={}",
                    url,
                    block_number.to_string().as_str()
                );
                let res = reqwest::get(query_url).await.unwrap().text().await.unwrap();
                if self.save {
                    println!("hi");
                    let file_name = format!(
                        "./src/fixtures/updated/{}/signed_block.json",
                        block_number.to_string().as_str()
                    );
                    // Ensure the directory exists
                    if let Some(parent) = Path::new(&file_name).parent() {
                        fs::create_dir_all(parent).unwrap();
                    }
                    fs::write(file_name.as_str(), res.as_bytes()).expect("Unable to write file");
                }
                res
            }
            InputDataMode::Fixture => {
                let file_name = format!(
                    "./src/fixtures/updated/{}/signed_block.json",
                    block_number.to_string().as_str()
                );
                println!("{:?}", file_name);
                let file_content = fs::read_to_string(file_name.as_str());
                println!("Getting fixture");
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
                let (hash, proofs) = generate_proofs_from_header(block_header);
                self.proof_cache.insert(hash, proofs.clone());
                proofs
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

    pub async fn get_step_inputs<const VALIDATOR_SET_SIZE_MAX: usize, F: RichField>(
        &mut self,
        prev_block_number: u64,
        prev_header_hash: H256,
    ) -> (
        [u8; 32],
        bool,
        Vec<Validator<Ed25519, F>>,
        TempMerkleInclusionProof,
        TempMerkleInclusionProof,
        TempMerkleInclusionProof,
    ) {
        println!("Getting step inputs");
        let prev_block = self.get_block_from_number(prev_block_number).await;
        let computed_prev_header_hash = prev_block.header.hash();
        assert_eq!(
            computed_prev_header_hash.as_bytes(),
            prev_header_hash.as_bytes()
        );
        println!("prev_block_hash {:?}", computed_prev_header_hash);
        let next_block = self.get_block_from_number(prev_block_number + 1).await;
        let round_present = next_block.commit.round.value() != 0;

        let next_block_header = next_block.header.hash();
        println!("prev_block_hash {:?}", next_block_header);

        let next_block_validators =
            get_validators_as_input::<VALIDATOR_SET_SIZE_MAX, F>(&next_block);
        assert_eq!(
            next_block_validators.len(),
            VALIDATOR_SET_SIZE_MAX,
            "validator set size needs to be the provided validator_set_size_max"
        );

        let next_block_validators_hash_proof = self.get_merkle_proof(
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
        Vec<Validator<Ed25519, F>>,          // validators
        [u8; 32],                            // target_header
        bool,                                // round_present
        HeightProofValueType<F>,             // target_block_height_proof,
        TempMerkleInclusionProof,            // target_header_validators_hash_proof,
        [u8; 32],                            // trusted_header
        TempMerkleInclusionProof,            // trusted_validators_hash_proof
        Vec<ValidatorHashField<Ed25519, F>>, // trusted_validators_hash_fields
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
            height: target_block.header.height.value().into(),
            enc_height_byte_length: target_block.header.height.encode_vec().len() as u32,
            proof: temp_target_block_height_proof.proof,
        };

        let target_block_validators_hash_proof = self.get_merkle_proof(
            &target_block.header,
            VALIDATORS_HASH_INDEX as u64,
            target_block.header.validators_hash.encode_vec(),
        );

        let trusted_block_validator_fields =
            get_validators_fields_as_input::<VALIDATOR_SET_SIZE_MAX, F>(&trusted_block);
        let trusted_block_validator_hash_proof = self.get_merkle_proof(
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
        use crate::input_data::{InputDataFetcher, InputDataMode};

        let block_height = 11105u64;
        let mut fetcher = InputDataFetcher::new(InputDataMode::Rpc(
            "http://rpc.testnet.celestia.citizencosmos.space".to_string(),
        ));
        fetcher.set_save(true);
        let _block = fetcher.get_block_from_number(block_height).await;
    }
}
