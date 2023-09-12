use crate::{
    inputs::{convert_to_H256, get_path_indices, InclusionProof},
    utils::{generate_proofs_from_header, leaf_hash, SignedBlock, TempSignedBlock},
};
use ethers::abi::AbiEncode;
use rand::Rng;
use reqwest::Error;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::{
    env,
    fs::{self, File},
    io::Write,
    path::Path,
};
use subtle_encoding::hex;
use tendermint::{merkle::simple_hash_from_byte_vectors, validator::Set as ValidatorSet, Hash};
use tendermint_proto::types::BlockId as RawBlockId;
use tendermint_proto::Protobuf;

#[derive(Debug, Deserialize)]
struct SignedBlockResponse {
    result: TempSignedBlock,
}

#[derive(Debug, Deserialize)]
struct DataCommitmentResponse {
    result: DataCommitment,
}

#[derive(Debug, Deserialize)]
struct DataCommitment {
    pub data_commitment: Hash,
}

#[derive(Debug, Serialize, Deserialize)]
struct VerifySignatureData {
    pubkey: String,
    signature: String,
    message: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DataCommitmentFixture {
    pub start_block: u64,
    pub end_block: u64,
    pub data_hashes: Vec<Hash>,
    pub data_commitment: Hash,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HeaderChainFixture {
    pub current_block: u64,
    pub trusted_block: u64,
    pub curr_header: Hash,
    pub trusted_header: Hash,
    pub data_hash_proofs: Vec<InclusionProof>,
    pub prev_header_proofs: Vec<InclusionProof>,
}

pub fn encode_block_height(block_height: u64) -> Vec<u8> {
    block_height.encode()
}

pub async fn get_data_commitment(start_block: usize, end_block: usize) -> Hash {
    dotenv::dotenv().ok();

    // Get the dataHash of the block range (startBlock, endBlock)
    let mut url = env::var("RPC_MOCHA_4").expect("RPC_MOCHA_4 is not set in .env");

    url.push_str("/data_commitment?start=");

    url.push_str(start_block.to_string().as_str());

    url.push_str("&end=");

    url.push_str(end_block.to_string().as_str());

    let res = reqwest::get(url).await.unwrap().text().await.unwrap();
    let v: DataCommitmentResponse = serde_json::from_str(&res).expect("Failed to parse JSON");
    v.result.data_commitment
}

pub async fn generate_data_commitment(start_block: usize, end_block: usize) {
    dotenv::dotenv().ok();

    // Get the dataHash of the block range (startBlock, endBlock)
    let mut url = env::var("RPC_MOCHA_4").expect("RPC_MOCHA_4 is not set in .env");

    url.push_str("/signed_block?height=");

    let mut encoded_leaves = Vec::new();

    for i in start_block..end_block {
        let mut url = url.clone();
        url.push_str(i.to_string().as_str());

        // println!("Fetching block {}", i);
        let res = reqwest::get(url).await.unwrap().text().await.unwrap();
        let v: SignedBlockResponse = serde_json::from_str(&res).expect("Failed to parse JSON");
        let temp_block = v.result;
        let block = SignedBlock {
            header: temp_block.header,
            data: temp_block.data,
            commit: temp_block.commit,
            validator_set: ValidatorSet::new(
                temp_block.validator_set.validators,
                temp_block.validator_set.proposer,
            ),
        };
        let data_hash = block.header.data_hash;
        // println!("Data hash: {:?}", data_hash.unwrap().as_bytes());

        // concat the block height and the data hash
        let mut encoded_leaf = encode_block_height(i as u64);

        encoded_leaf.extend(data_hash.unwrap().as_bytes().to_vec());

        // println!("Encoded leaf: {:?}", encoded_leaf);

        // println!("Length of encoded leaf: {:?}", encoded_leaf.len());

        encoded_leaves.push(encoded_leaf);
    }

    // println!("Encoded leaves length: {:?}", encoded_leaves.len());

    for leaf in &encoded_leaves {
        println!(
            "{}",
            String::from_utf8(hex::encode(leaf_hash::<Sha256>(leaf))).expect("Found invalid UTF-8")
        );
    }

    let root_hash = simple_hash_from_byte_vectors::<Sha256>(&encoded_leaves);

    // println!("Root Hash Bytes: {:?}", root_hash);

    // Print the root hash
    println!(
        "Root Hash: {:?}",
        String::from_utf8(hex::encode(root_hash)).expect("Found invalid UTF-8")
    );
}

pub async fn get_signed_block_from_rpc(block: usize) -> Box<SignedBlock> {
    dotenv::dotenv().ok();

    let mut url = env::var("RPC_MOCHA_4").expect("RPC_MOCHA_4 is not set in .env");
    url.push_str("/signed_block?height=");
    url.push_str(block.to_string().as_str());

    let res = reqwest::get(url).await.unwrap().text().await.unwrap();
    let v: SignedBlockResponse = serde_json::from_str(&res).expect("Failed to parse JSON");
    let temp_block = v.result;
    Box::new(SignedBlock {
        header: temp_block.header,
        data: temp_block.data,
        commit: temp_block.commit,
        validator_set: ValidatorSet::new(
            temp_block.validator_set.validators,
            temp_block.validator_set.proposer,
        ),
    })
}

pub async fn create_header_chain_fixture(
    trusted_block: usize,
    current_block: usize,
) -> Result<(), Error> {
    let mut fixture: HeaderChainFixture = HeaderChainFixture {
        current_block: current_block as u64,
        trusted_block: trusted_block as u64,
        curr_header: Hash::default(),
        trusted_header: Hash::default(),
        data_hash_proofs: Vec::new(),
        prev_header_proofs: Vec::new(),
    };

    // Get the dataHash of the block range (startBlock, endBlock)
    let block = get_signed_block_from_rpc(current_block).await;
    fixture.curr_header = block.header.hash();

    // Write the trusted header
    let block = get_signed_block_from_rpc(trusted_block).await;
    fixture.trusted_header = block.header.hash();

    let mut data_hash_proofs = Vec::new();
    let mut prev_header_proofs = Vec::new();

    // Loop from endBlock to startBlock
    for i in (trusted_block + 1..current_block + 1).rev() {
        // Fetch the newer block
        let block = get_signed_block_from_rpc(i).await;

        // Get prev_header_hash proof from block 1 (newer block)
        let enc_last_block_id_leaf =
            Protobuf::<RawBlockId>::encode_vec(block.header.last_block_id.unwrap_or_default());
        let (_root, proofs) = generate_proofs_from_header(&block.header);
        let total = proofs[0].total;

        let enc_last_block_id_proof = proofs[4].clone();
        let enc_last_block_id_proof_indices = get_path_indices(4, total);
        let last_block_id_proof = InclusionProof {
            enc_leaf: enc_last_block_id_leaf.clone(),
            path: enc_last_block_id_proof_indices,
            proof: convert_to_H256(enc_last_block_id_proof.clone().aunts),
        };
        prev_header_proofs.push(last_block_id_proof);

        // Fetch the older block
        let block = get_signed_block_from_rpc(i - 1).await;

        // Get data_hash proof from block 2 (older block)
        let enc_data_hash_leaf = block.header.data_hash.unwrap().encode_vec();
        let (_root, proofs) = generate_proofs_from_header(&block.header);
        let total = proofs[0].total;

        let enc_data_hash_proof = proofs[6].clone();
        let enc_data_hash_proof_indices = get_path_indices(6, total);
        let data_hash_proof = InclusionProof {
            enc_leaf: enc_data_hash_leaf.clone(),
            path: enc_data_hash_proof_indices,
            proof: convert_to_H256(enc_data_hash_proof.clone().aunts),
        };
        data_hash_proofs.push(data_hash_proof);
    }

    fixture.data_hash_proofs = data_hash_proofs;
    fixture.prev_header_proofs = prev_header_proofs;

    // Write to JSON file
    let json = serde_json::to_string(&fixture).unwrap();

    let mut path = "./src/fixtures/mocha-4/".to_string();
    path.push_str(trusted_block.to_string().as_str());
    path.push_str("-".to_string().as_str());
    path.push_str(current_block.to_string().as_str());
    path.push_str("/header_chain.json");

    // Ensure the directory exists
    if let Some(parent) = Path::new(&path).parent() {
        fs::create_dir_all(parent).unwrap();
    }

    let mut file = File::create(&path).unwrap();
    file.write_all(json.as_bytes()).unwrap();

    Ok(())
}

pub async fn create_data_commitment_fixture(
    start_block: usize,
    end_block: usize,
) -> Result<(), Error> {
    dotenv::dotenv().ok();

    let mut fixture: DataCommitmentFixture = DataCommitmentFixture {
        start_block: start_block as u64,
        end_block: end_block as u64,
        data_hashes: Vec::new(),
        data_commitment: Hash::default(),
    };

    // Get the dataHash of the block range (startBlock, endBlock)
    let mut url = env::var("RPC_MOCHA_4").expect("RPC_MOCHA_4 is not set in .env");

    url.push_str("/signed_block?height=");

    let mut encoded_leaves = Vec::new();

    for i in start_block..end_block {
        let mut url = url.clone();
        url.push_str(i.to_string().as_str());

        let res = reqwest::get(url).await.unwrap().text().await.unwrap();
        let v: SignedBlockResponse = serde_json::from_str(&res).expect("Failed to parse JSON");
        let temp_block = v.result;
        let block = SignedBlock {
            header: temp_block.header,
            data: temp_block.data,
            commit: temp_block.commit,
            validator_set: ValidatorSet::new(
                temp_block.validator_set.validators,
                temp_block.validator_set.proposer,
            ),
        };
        let data_hash = block.header.data_hash;

        fixture.data_hashes.push(data_hash.unwrap());

        // concat the block height and the data hash
        let mut encoded_leaf = encode_block_height(i as u64);

        encoded_leaf.extend(data_hash.unwrap().as_bytes().to_vec());

        encoded_leaves.push(encoded_leaf);
    }

    let root_hash = simple_hash_from_byte_vectors::<Sha256>(&encoded_leaves);

    fixture.data_commitment = Hash::Sha256(root_hash);

    // Write to JSON file
    let json = serde_json::to_string(&fixture).unwrap();

    let mut path = "./src/fixtures/mocha-4/".to_string();
    path.push_str(start_block.to_string().as_str());
    path.push_str("-".to_string().as_str());
    path.push_str(end_block.to_string().as_str());
    path.push_str("/data_commitment.json");

    // Ensure the directory exists
    if let Some(parent) = Path::new(&path).parent() {
        fs::create_dir_all(parent).unwrap();
    }

    let mut file = File::create(&path).unwrap();
    file.write_all(json.as_bytes()).unwrap();

    Ok(())
}

pub fn generate_val_array(num_validators: usize) {
    let mut rng = rand::thread_rng();
    // Generate an array of byte arrays where the byte arrays have variable length between 38 and 46 bytes and the total length of the array is less than n
    let random_bytes: Vec<Vec<u8>> = (0..num_validators)
        .map(|_| {
            let inner_length = rng.gen_range(38..=46);
            (0..inner_length).map(|_| rng.gen()).collect()
        })
        .collect();

    // Use simple_hash_from_byte_vectors to generate the root hash
    let root_hash = simple_hash_from_byte_vectors::<Sha256>(&random_bytes);

    // Print the random byte arrays as an array of hex strings, that have double quotes around them and are separated by commas

    let mut hex_strings = Vec::new();

    for b in &random_bytes {
        let hex_string = String::from_utf8(hex::encode(b)).expect("Found invalid UTF-8");
        hex_strings.push(hex_string);
    }

    // Format the hex strings with double quotes and commas
    println!("Validators: {:?}", hex_strings);

    // Print the root hash
    println!(
        "Root Hash: {:?}",
        String::from_utf8(hex::encode(root_hash)).expect("Found invalid UTF-8")
    );
}

pub async fn create_block_fixture(block_number: usize) -> Result<(), Error> {
    write_block_fixture(block_number)
        .await
        .expect("Failed to write block fixture");
    write_block_fixture(block_number - 1)
        .await
        .expect("Failed to write previous block fixture");
    Ok(())
}

async fn write_block_fixture(block_number: usize) -> Result<(), Error> {
    // Read RPC_MOCHA_3 from env
    dotenv::dotenv().ok();
    let mut url = env::var("RPC_MOCHA_3").expect("RPC_MOCHA_3 is not set in .env");

    url.push_str("/signed_block?height=");

    url.push_str(block_number.to_string().as_str());

    // Send a GET request and wait for the response

    // Convert response to string
    let res = reqwest::get(url).await?.text().await?;

    let v: SignedBlockResponse = serde_json::from_str(&res).expect("Failed to parse JSON");

    let temp_block = v.result;

    // Cast to SignedBlock
    let block = SignedBlock {
        header: temp_block.header,
        data: temp_block.data,
        commit: temp_block.commit,
        validator_set: ValidatorSet::new(
            temp_block.validator_set.validators,
            temp_block.validator_set.proposer,
        ),
    };

    // Write to JSON file
    let json = serde_json::to_string(&block).unwrap();

    let mut path = "./src/fixtures/mocha-3/".to_string();
    path.push_str(block_number.to_string().as_str());
    path.push_str("/signed_block.json");

    // Ensure the directory exists
    if let Some(parent) = Path::new(&path).parent() {
        fs::create_dir_all(parent).unwrap();
    }

    let mut file = File::create(&path).unwrap();
    file.write_all(json.as_bytes()).unwrap();

    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use crate::utils::{leaf_hash, proofs_from_byte_slices};

    use super::*;
    use sha2::Sha256;

    #[tokio::test]
    async fn calculate_data_commitment() {
        // End exclusive range: https://github.com/celestiaorg/celestia-core/blob/main/rpc/core/blocks.go#L537-L538
        generate_data_commitment(3800, 3804).await
    }

    #[test]
    fn test_encoding() {
        let block_height = 256;
        println!("Block height: {:?}", block_height.encode());
    }

    #[test]
    fn test_commitment() {
        let mut first_arr = vec![0u8, 0];
        let arr = vec![
            0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 6, 229, 160, 61, 150, 183, 210, 56, 231, 224, 69, 111, 106, 248, 231, 205, 240, 166,
            123, 214, 207, 156, 32, 137, 236, 181, 89, 198, 89, 220, 170, 31, 136, 3, 83,
        ];

        first_arr.extend_from_slice(&arr);

        println!("First arr: {:?}, Len: {:?}", first_arr, first_arr.len());

        let result = leaf_hash::<Sha256>(&arr);
        println!("Result Bytes: {:?}", result);
        println!(
            "Result: {:?}",
            String::from_utf8(hex::encode_upper(result)).unwrap()
        );

        // let mut hasher = Sha256::new();
        // hasher.update(&first_arr);

        // let result = hasher.finalize();
        // println!(
        //     "Result: {:?}",
        //     String::from_utf8(hex::encode(result)).unwrap()
        // );
    }

    #[test]
    fn test_merkle_hash() {
        let element = vec![0u8; 48];
        let arr = vec![element; 32];
        let result = simple_hash_from_byte_vectors::<Sha256>(&arr);
        println!(
            "Result: {:?}",
            String::from_utf8(hex::encode(result)).unwrap()
        );
    }

    #[test]
    fn test_merkle_proof() {
        let element = vec![0u8; 48];
        let arr = vec![element; 2];

        let (root_hash, proofs) = proofs_from_byte_slices(arr);

        println!(
            "Root hash: {:?}",
            String::from_utf8(hex::encode(root_hash)).unwrap()
        );

        let computed_root_hash = proofs[0].compute_root_hash().unwrap();

        println!(
            "Leaf: {:?}",
            String::from_utf8(hex::encode(proofs[0].leaf_hash)).unwrap()
        );

        println!(
            "Aunts: {:?}",
            proofs[0]
                .aunts
                .iter()
                .map(|x| String::from_utf8(hex::encode(x)).unwrap())
                .collect::<Vec<_>>()
        );

        println!(
            "Path indices: {:?}",
            get_path_indices(proofs[0].index, proofs[0].total)
        )
    }
}
