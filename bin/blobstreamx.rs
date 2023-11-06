use std::env;

use alloy_sol_types::{sol, SolType};
use ethers::contract::abigen;
use ethers::core::types::Address;
use ethers::providers::{Http, Provider};
use ethers::types::{Bytes, H256};
use log::info;
use subtle_encoding::hex;
use tendermint::block::Header;
use tendermintx::input::tendermint_utils::{
    is_valid_skip, HeaderResponse, SignedBlock, SignedBlockResponse,
};

// Note: Update ABI when updating contract.
abigen!(BlobstreamX, "./abi/BlobstreamX.abi.json");

struct BlobstreamConfig {
    address: Address,
    chain_id: u32,
    next_header_function_id: H256,
    header_range_function_id: H256,
}

#[allow(non_snake_case)]
#[derive(serde::Serialize, serde::Deserialize)]
struct OffchainInput {
    chainId: u32,
    to: String,
    data: String,
    functionId: String,
    input: String,
}

type NextHeaderCalldataTuple = sol! { tuple(uint64,) };
type NextHeaderInputTuple = sol! { tuple(uint64, bytes32) };

type HeaderRangeCalldataTuple = sol! { tuple(uint64, uint64) };
type HeaderRangeInputTuple = sol! { tuple(uint64, bytes32, uint64) };

fn get_config() -> BlobstreamConfig {
    let contract_address = env::var("CONTRACT_ADDRESS").expect("CONTRACT_ADDRESS must be set");
    let chain_id = env::var("CHAIN_ID").expect("CHAIN_ID must be set");

    // TODO: BlobstreamX on Goerli: https://goerli.etherscan.io/address/#code
    let address = contract_address
        .parse::<Address>()
        .expect("invalid address");

    // Load the function IDs.
    let next_header_id_env =
        env::var("NEXT_HEADER_FUNCTION_ID").expect("NEXT_HEADER_FUNCTION_ID must be set");
    let next_header_function_id = H256::from_slice(
        &hex::decode(
            next_header_id_env
                .strip_prefix("0x")
                .unwrap_or(&next_header_id_env),
        )
        .expect("invalid hex for next_header_function_id, expected 0x prefix"),
    );
    let header_range_id_env =
        env::var("HEADER_RANGE_FUNCTION_ID").expect("HEADER_RANGE_FUNCTION_ID must be set");
    let header_range_function_id = H256::from_slice(
        &hex::decode(
            header_range_id_env
                .strip_prefix("0x")
                .unwrap_or(&header_range_id_env),
        )
        .expect("invalid hex for header_range_function_id, expected 0x prefix"),
    );

    BlobstreamConfig {
        address,
        chain_id: chain_id.parse::<u32>().expect("invalid chain id"),
        next_header_function_id,
        header_range_function_id,
    }
}

async fn submit_request(
    config: &BlobstreamConfig,
    function_data: Vec<u8>,
    input: Vec<u8>,
    function_id: H256,
) {
    // All data except for chainId is a string, and needs a 0x prefix.
    let data = OffchainInput {
        chainId: config.chain_id,
        to: Bytes::from(config.address.0).to_string(),
        data: Bytes::from(function_data).to_string(),
        functionId: Bytes::from(function_id.0).to_string(),
        input: Bytes::from(input).to_string(),
    };

    // Stringify the data into JSON format.
    let serialized_data = serde_json::to_string(&data).unwrap();

    // TODO: Update with config.
    let request_url = "https://alpha.succinct.xyz/api/request/new";

    // Submit POST request to the offchain worker.
    let client = reqwest::Client::new();
    let res = client
        .post(request_url)
        .header("Content-Type", "application/json")
        .body(serialized_data)
        .send()
        .await
        .expect("Failed to send request.");

    if res.status().is_success() {
        // TODO: Log success message. Find structure of output.
        info!("Successfully submitted request.");
    } else {
        // TODO: Log error message.
        info!("Failed to submit request.");
    }
}

async fn request_next_header(
    config: &BlobstreamConfig,
    contract: &BlobstreamX<Provider<Http>>,
    trusted_block: u64,
) {
    let trusted_header_hash = contract
        .block_height_to_header_hash(trusted_block)
        .await
        .unwrap();

    let input = NextHeaderInputTuple::abi_encode_packed(&(trusted_block, trusted_header_hash));

    info!("length of step input: {:?}", input.len());

    let function_signature = "commitNextHeader(uint64)";
    let function_selector = ethers::utils::id(function_signature).to_vec();
    let encoded_parameters = NextHeaderCalldataTuple::abi_encode_sequence(&(trusted_block,));
    // Concat function selector and encoded parameters.
    let function_data = [&function_selector[..], &encoded_parameters[..]].concat();

    submit_request(config, function_data, input, config.next_header_function_id).await;
}

async fn request_header_range(
    config: &BlobstreamConfig,
    contract: &BlobstreamX<Provider<Http>>,
    trusted_block: u64,
    target_block: u64,
) {
    let trusted_header_hash = contract
        .block_height_to_header_hash(trusted_block)
        .await
        .unwrap();

    let input = HeaderRangeInputTuple::abi_encode_packed(&(
        trusted_block,
        trusted_header_hash,
        target_block,
    ));

    info!("length of rotate input: {:?}", input.len());

    let function_signature = "commitHeaderRange(uint64,uint64)";
    let function_selector = ethers::utils::id(function_signature).to_vec();
    let encoded_parameters =
        HeaderRangeCalldataTuple::abi_encode_sequence(&(trusted_block, target_block));
    // Concat function selector and encoded parameters.
    let function_data = [&function_selector[..], &encoded_parameters[..]].concat();

    submit_request(
        config,
        function_data,
        input,
        config.header_range_function_id,
    )
    .await;
}

// Tendermint RPC Fetcher
async fn get_latest_tendermint_header(base_url: &str) -> Header {
    let query_url = format!("{}/header", base_url);
    info!("Querying url {:?}", query_url.as_str());
    let res = reqwest::get(query_url).await.unwrap().text().await.unwrap();
    let v: HeaderResponse = serde_json::from_str(&res).expect("Failed to parse JSON");
    v.result.header
}

async fn get_tendermint_signed_block_from_number(base_url: &str, block_number: u64) -> SignedBlock {
    let query_url = format!("{}/signed_block?height={}", base_url, block_number);
    info!("Querying url {:?}", query_url.as_str());
    let res = reqwest::get(query_url).await.unwrap().text().await.unwrap();
    let v: SignedBlockResponse = serde_json::from_str(&res).expect("Failed to parse JSON");
    v.result
}

// Binary search to find the block number to call request_combined_skip on. If the binary search
// returns start_block + 1, then we call request_combined_step instead.
async fn find_request_block(base_url: &str, start_block: u64, end_block: u64) -> u64 {
    let start_signed_block = get_tendermint_signed_block_from_number(base_url, start_block).await;

    let mut curr_end_block = end_block;
    loop {
        if curr_end_block - start_block == 1 {
            return curr_end_block;
        }

        let curr_end_signed_block =
            get_tendermint_signed_block_from_number(base_url, curr_end_block).await;

        if is_valid_skip(&start_signed_block, &curr_end_signed_block) {
            return curr_end_block;
        }

        let mid_block = (curr_end_block + start_block) / 2;
        curr_end_block = mid_block;
    }
}

#[tokio::main]
async fn main() {
    dotenv::dotenv().ok();

    // Loop every 30 minutes.
    const LOOP_DELAY: u64 = 30;

    let config: BlobstreamConfig = get_config();

    let tendermint_rpc_url =
        env::var("TENDERMINT_RPC_URL").expect("TENDERMINT_RPC_URL must be set");

    let ethereum_rpc_url = env::var("RPC_URL").expect("RPC_URL must be set");
    let provider =
        Provider::<Http>::try_from(ethereum_rpc_url).expect("could not connect to client");

    let blobstreamx = BlobstreamX::new(config.address, provider.into());

    let header_range_max = blobstreamx.data_commitment_max().await.unwrap();
    loop {
        let current_block = blobstreamx.latest_block().await.unwrap();

        // Get the head of the chain.
        let latest_header = get_latest_tendermint_header(&tendermint_rpc_url).await;
        let latest_block = latest_header.height.value();

        // Subtract 2 blocks to account for the time it takes for a block to be processed by
        // consensus.
        let max_end_block = std::cmp::min(latest_block - 2, current_block + header_range_max);

        let target_block =
            find_request_block(&tendermint_rpc_url, current_block, max_end_block).await;

        if target_block - current_block == 1 {
            // Request the next header if the target block is the next block.
            request_next_header(&config, &blobstreamx, current_block).await;
        } else {
            // Request a header range if the target block is not the next block.
            request_header_range(&config, &blobstreamx, current_block, target_block).await;
        }

        tokio::time::sleep(tokio::time::Duration::from_secs(60 * LOOP_DELAY)).await;
    }
}
