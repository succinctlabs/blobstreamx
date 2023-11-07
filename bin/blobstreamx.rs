use std::env;

use alloy_sol_types::{sol, SolType};
use ethers::abi::AbiEncode;
use ethers::contract::abigen;
use ethers::core::types::Address;
use ethers::providers::{Http, Provider};
use ethers::types::{Bytes, H256};
use log::{error, info};
use subtle_encoding::hex;
use tendermintx::input::InputDataFetcher;

// Note: Update ABI when updating contract.
abigen!(BlobstreamX, "./abi/BlobstreamX.abi.json");

struct BlobstreamXConfig {
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

type NextHeaderInputTuple = sol! { tuple(uint64, bytes32) };

type HeaderRangeInputTuple = sol! { tuple(uint64, bytes32, uint64) };

struct BlobstreamXOperator {
    config: BlobstreamXConfig,
    contract: BlobstreamX<Provider<Http>>,
    data_fetcher: InputDataFetcher,
}

impl BlobstreamXOperator {
    pub fn new() -> Self {
        let config = Self::get_config();

        let ethereum_rpc_url = env::var("RPC_URL").expect("RPC_URL must be set");
        let provider =
            Provider::<Http>::try_from(ethereum_rpc_url).expect("could not connect to client");

        let contract = BlobstreamX::new(config.address, provider.into());

        let tendermint_rpc_url =
            env::var("TENDERMINT_RPC_URL").expect("TENDERMINT_RPC_URL must be set");
        let data_fetcher = InputDataFetcher::new(&tendermint_rpc_url, "");

        Self {
            config,
            contract,
            data_fetcher,
        }
    }

    fn get_config() -> BlobstreamXConfig {
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

        BlobstreamXConfig {
            address,
            chain_id: chain_id.parse::<u32>().expect("invalid chain id"),
            next_header_function_id,
            header_range_function_id,
        }
    }

    async fn submit_request(&self, function_data: Vec<u8>, input: Vec<u8>, function_id: H256) {
        // All data except for chainId is a string, and needs a 0x prefix.
        let data = OffchainInput {
            chainId: self.config.chain_id,
            to: Bytes::from(self.config.address.0).to_string(),
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
            info!("Successfully submitted request.");
        } else {
            // TODO: Log more specific error message.
            error!("Failed to submit request.");
        }
    }

    async fn request_next_header(&self, trusted_block: u64) {
        let trusted_header_hash = self
            .contract
            .block_height_to_header_hash(trusted_block)
            .await
            .unwrap();

        let input = NextHeaderInputTuple::abi_encode_packed(&(trusted_block, trusted_header_hash));

        let commit_next_header_call = CommitNextHeaderCall {
            trusted_block,
            trusted_header: trusted_header_hash,
        };
        let function_data = commit_next_header_call.encode();

        self.submit_request(function_data, input, self.config.next_header_function_id)
            .await;
    }

    async fn request_header_range(&self, trusted_block: u64, target_block: u64) {
        let trusted_header_hash = self
            .contract
            .block_height_to_header_hash(trusted_block)
            .await
            .unwrap();

        let input = HeaderRangeInputTuple::abi_encode_packed(&(
            trusted_block,
            trusted_header_hash,
            target_block,
        ));

        let commit_header_range_call = CommitHeaderRangeCall {
            trusted_block,
            trusted_header: trusted_header_hash,
            target_block,
        };
        let function_data = commit_header_range_call.encode();

        self.submit_request(function_data, input, self.config.header_range_function_id)
            .await;
    }

    async fn run(&self) {
        // Loop every 30 minutes.
        const LOOP_DELAY: u64 = 30;

        let header_range_max = self.contract.data_commitment_max().await.unwrap();
        loop {
            let current_block = self.contract.latest_block().await.unwrap();

            // Get the head of the chain.
            let latest_header = self.data_fetcher.get_latest_header().await;
            let latest_block = latest_header.height.value();

            // Subtract 2 blocks to account for the time it takes for a block to be processed by
            // consensus.
            let max_end_block = std::cmp::min(latest_block - 2, current_block + header_range_max);

            let target_block = self
                .data_fetcher
                .find_block_to_request(current_block, max_end_block)
                .await;

            if target_block - current_block == 1 {
                // Request the next header if the target block is the next block.
                self.request_next_header(current_block).await;
            } else {
                // Request a header range if the target block is not the next block.
                self.request_header_range(current_block, target_block).await;
            }

            tokio::time::sleep(tokio::time::Duration::from_secs(60 * LOOP_DELAY)).await;
        }
    }
}

#[tokio::main]
async fn main() {
    env::set_var("RUST_LOG", "info");
    dotenv::dotenv().ok();
    env_logger::init();

    let operator = BlobstreamXOperator::new();
    operator.run().await;
}
