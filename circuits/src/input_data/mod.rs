pub mod tendermint_utils;
pub mod types;
pub mod utils;

use std::collections::HashMap;
use std::path::Path;
use std::{env, fs};

use async_trait::async_trait;
use ethers::types::H256;
use itertools::Itertools;
use plonky2x::frontend::ecc::ed25519::curve::ed25519::Ed25519;
use plonky2x::frontend::merkle::tree::InclusionProof;
use plonky2x::prelude::RichField;
use subtle_encoding::hex;
use tendermint_proto::types::BlockId as RawBlockId;
use tendermint_proto::Protobuf;

use self::tendermint_utils::{
    generate_proofs_from_header, DataCommitmentResponse, Hash, Header, HeaderResponse, Proof,
    SignedBlockResponse, TempSignedBlock,
};
use self::types::{update_present_on_trusted_header, TempMerkleInclusionProof};
use self::utils::{convert_to_h256, get_path_indices};
use crate::consts::{
    BLOCK_HEIGHT_INDEX, DATA_HASH_INDEX, HEADER_PROOF_DEPTH, LAST_BLOCK_ID_INDEX,
    NEXT_VALIDATORS_HASH_INDEX, PROTOBUF_BLOCK_ID_SIZE_BYTES, PROTOBUF_HASH_SIZE_BYTES,
    VALIDATORS_HASH_INDEX,
};
use crate::input_data::types::{get_validators_as_input, get_validators_fields_as_input};
use crate::variables::HeightProofValueType;
use crate::verify::{Validator, ValidatorHashField};

#[async_trait]
pub trait DataFetcher {
    async fn get_block(&self, block_number: u64) -> Box<TempSignedBlock>;
    async fn get_header(&self, block_number: u64) -> Header;
    async fn get_header_range(
        &self,
        start_block_number: u64,
        end_block_number: u64,
    ) -> Vec<Header> {
        let mut headers = Vec::new();
        for block_number in start_block_number..end_block_number {
            let header = self.get_header(block_number).await;
            headers.push(header);
        }
        headers
    }
    async fn get_data_commitment(&self, start_block_number: u64, end_block_number: u64) -> H256;
}

pub fn new_fetcher(chain_id: String) -> Box<dyn DataFetcher> {
    if cfg!(test) {
        Box::new(FixtureDataFetcher {
            fixture_path: format!("test/fixtures/{}", chain_id),
        })
    } else {
        Box::new(RpcDataFetcher {
            url: env::var(format!("RPC_{}", chain_id)).expect("RPC url not set in .env"),
            save: false,
            save_fixture_path: format!("test/fixtures/{}", chain_id),
        })
    }
    // TODO: if in a test, return the FixtureDataFetcher with a const fixture path "test/fixtures/{chain_id{"
    // else, read the RpcDataFetch with the env var "RPC_{chain_id}" url from the .env file and panic if the RPC url is not present
}

pub struct RpcDataFetcher {
    pub url: String,
    pub save: bool,
    pub save_fixture_path: String,
}

impl RpcDataFetcher {}

#[async_trait]
impl DataFetcher for RpcDataFetcher {
    async fn get_block(&self, block_number: u64) -> Box<TempSignedBlock> {
        let query_url = format!(
            "{}/block?height={}",
            self.url,
            block_number.to_string().as_str()
        );
        let res = reqwest::get(query_url).await.unwrap().text().await.unwrap();
        if self.save {
            let file_name = format!(
                "{}/block/{}.json",
                self.save_fixture_path.as_str(),
                block_number.to_string().as_str()
            );
            // Ensure the directory exists
            if let Some(parent) = Path::new(&file_name).parent() {
                fs::create_dir_all(parent).unwrap();
            }
            fs::write(file_name.as_str(), res.as_bytes()).expect("Unable to write file");
        }
        let v: SignedBlockResponse = serde_json::from_str(&res).expect("Failed to parse JSON");
        let temp_block = v.result;
        Box::new(temp_block)
    }

    async fn get_header(&self, block_number: u64) -> Header {
        let query_url = format!(
            "{}/header?height={}",
            self.url,
            block_number.to_string().as_str()
        );
        let res = reqwest::get(query_url).await.unwrap().text().await.unwrap();
        if self.save {
            let file_name = format!(
                "{}/header/{}.json",
                self.save_fixture_path.as_str(),
                block_number.to_string().as_str()
            );
            // Ensure the directory exists
            if let Some(parent) = Path::new(&file_name).parent() {
                fs::create_dir_all(parent).unwrap();
            }
            fs::write(file_name.as_str(), res.as_bytes()).expect("Unable to write file");
        }
        let v: HeaderResponse = serde_json::from_str(&res).expect("Failed to parse JSON");
        v.result
    }

    async fn get_data_commitment(&self, start_block_number: u64, end_block_number: u64) -> H256 {
        let query_url = format!(
            "{}/data_commitment?start={}&end={}",
            self.url,
            start_block_number.to_string().as_str(),
            end_block_number.to_string().as_str()
        );
        let res = reqwest::get(query_url).await.unwrap().text().await.unwrap();
        if self.save {
            let file_name = format!(
                "{}/data_commitment/{}_{}.json",
                self.save_fixture_path.as_str(),
                start_block_number.to_string().as_str(),
                end_block_number.to_string().as_str(),
            );
            // Ensure the directory exists
            if let Some(parent) = Path::new(&file_name).parent() {
                fs::create_dir_all(parent).unwrap();
            }
            fs::write(file_name.as_str(), res.as_bytes()).expect("Unable to write file");
        }
        let v: DataCommitmentResponse = serde_json::from_str(&res).expect("Failed to parse JSON");
        H256::from_slice(
            hex::decode_upper(v.result.data_commitment)
                .unwrap()
                .as_slice(),
        )
    }
}

pub struct FixtureDataFetcher {
    pub fixture_path: String,
}

#[async_trait]
impl DataFetcher for FixtureDataFetcher {
    async fn get_block(&self, block_number: u64) -> Box<TempSignedBlock> {
        let file_name = format!(
            "{}/block/{}.json",
            self.fixture_path.as_str(),
            block_number.to_string().as_str()
        );
        let file_content = fs::read_to_string(file_name.as_str());
        let res = file_content.unwrap();
        let v: SignedBlockResponse = serde_json::from_str(&res).expect("Failed to parse JSON");
        let temp_block = v.result;
        Box::new(temp_block)
    }

    async fn get_header(&self, block_number: u64) -> Header {
        let file_name = format!(
            "{}/header/{}.json",
            self.fixture_path.as_str(),
            block_number.to_string().as_str()
        );
        let file_content = fs::read_to_string(file_name.as_str());
        let res = file_content.unwrap();
        let v: HeaderResponse = serde_json::from_str(&res).expect("Failed to parse JSON");
        v.result
    }

    async fn get_data_commitment(&self, start_block_number: u64, end_block_number: u64) -> H256 {
        let file_name = format!(
            "{}/data_commitment/{}_{}.json",
            self.fixture_path.as_str(),
            start_block_number.to_string().as_str(),
            end_block_number.to_string().as_str(),
        );
        let file_content = fs::read_to_string(file_name.as_str());
        let res = file_content.unwrap();
        let v: DataCommitmentResponse = serde_json::from_str(&res).expect("Failed to parse JSON");
        H256::from_slice(
            hex::decode_upper(v.result.data_commitment)
                .unwrap()
                .as_slice(),
        )
    }
}

pub enum InputDataMode {
    Rpc(String),
    Fixture,
}

pub struct InputDataFetcher {
    mode: InputDataMode,
    proof_cache: HashMap<Hash, Vec<Proof>>,
    save: bool,
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
        }
    }

    pub fn set_save(&mut self, save: bool) {
        self.save = save;
    }

    pub async fn get_data_commitment(&self, start_block: u64, end_block: u64) -> [u8; 32] {
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
                    let file_name = format!(
                        "./src/fixtures/updated/{}-{}/data_commitment.json",
                        start_block.to_string().as_str(),
                        end_block.to_string().as_str()
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
                    "./src/fixtures/updated/{}-{}/data_commitment.json",
                    start_block.to_string().as_str(),
                    end_block.to_string().as_str()
                );
                println!("{:?}", file_name);
                let file_content = fs::read_to_string(file_name.as_str());
                println!("Getting fixture");
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

    pub async fn get_data_commitment_inputs<const MAX_LEAVES: usize, F: RichField>(
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
        let start_block = self.get_block_from_number(start_block_number).await;
        let computed_start_header_hash = start_block.header.hash();
        assert_eq!(
            computed_start_header_hash.as_bytes(),
            start_header_hash.as_bytes()
        );

        let end_block = self.get_block_from_number(end_block_number).await;
        let computed_end_header_hash = end_block.header.hash();
        assert_eq!(
            computed_end_header_hash.as_bytes(),
            end_header_hash.as_bytes()
        );

        let mut data_hashes = Vec::new();
        let mut data_hash_proofs = Vec::new();
        let mut prev_header_proofs = Vec::new();
        for i in start_block_number..end_block_number + 1 {
            // TODO: Replace with get_header_from_number once Celestia re-enables the /header endpoint.
            let block = self.get_block_from_number(i).await;
            let data_hash = block.header.data_hash.unwrap();
            data_hashes.push(data_hash.as_bytes().try_into().unwrap());

            let data_hash_proof = self.get_merkle_proof(
                &block.header,
                DATA_HASH_INDEX as u64,
                block.header.data_hash.unwrap().encode_vec(),
            );
            data_hash_proofs.push(data_hash_proof);
            let prev_header_proof = self.get_merkle_proof(
                &block.header,
                LAST_BLOCK_ID_INDEX as u64,
                Protobuf::<RawBlockId>::encode_vec(block.header.last_block_id.unwrap_or_default()),
            );
            prev_header_proofs.push(prev_header_proof);
        }

        // Remove end_block's data_hash, as data_commitment does not include it.
        data_hashes.pop();

        // Remove end_block's data_hash_proof, as data_commitment does not check it.
        data_hash_proofs.pop();

        // Remove start_block's prev_header_proof, as data_commitment does not check it.
        prev_header_proofs = prev_header_proofs[1..].to_vec();

        // TODO: Remove, convert get_merkle_proof to use InclusionProof.
        let mut data_hash_proofs_formatted = data_hash_proofs
            .into_iter()
            .map(
                |proof| InclusionProof::<HEADER_PROOF_DEPTH, PROTOBUF_HASH_SIZE_BYTES, F> {
                    aunts: proof.proof,
                    path_indices: proof.path,
                    leaf: proof.enc_leaf.try_into().unwrap(),
                },
            )
            .collect_vec();

        let mut prev_header_proofs_formatted = prev_header_proofs
            .into_iter()
            .map(
                |proof| InclusionProof::<HEADER_PROOF_DEPTH, PROTOBUF_BLOCK_ID_SIZE_BYTES, F> {
                    aunts: proof.proof,
                    path_indices: proof.path,
                    leaf: proof.enc_leaf.try_into().unwrap(),
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
                aunts: [H256::zero(); HEADER_PROOF_DEPTH].to_vec(),
                path_indices: [false; HEADER_PROOF_DEPTH].to_vec(),
                leaf: [0u8; PROTOBUF_HASH_SIZE_BYTES],
            });
            prev_header_proofs_formatted.push(InclusionProof::<
                HEADER_PROOF_DEPTH,
                PROTOBUF_BLOCK_ID_SIZE_BYTES,
                F,
            > {
                aunts: [H256::zero(); HEADER_PROOF_DEPTH].to_vec(),
                path_indices: [false; HEADER_PROOF_DEPTH].to_vec(),
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
