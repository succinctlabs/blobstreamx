use crate::utils::{leaf_hash, SignedBlock, TempSignedBlock};
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
    use crate::utils::leaf_hash;

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
}
