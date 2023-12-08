use std::env;

use alloy_primitives::{Address, Bytes, B256};
use alloy_sol_types::{sol, SolType};
use anyhow::Result;
use ethers::abi::AbiEncode;
use ethers::contract::abigen;
use ethers::providers::{Http, Provider};
use log::{error, info};
use subtle_encoding::hex;
use succinct_client::request::SuccinctClient;
use tendermintx::input::InputDataFetcher;

// Note: Update ABI when updating contract.
abigen!(BlobstreamX, "./abi/BlobstreamX.abi.json");

struct BlobstreamXConfig {
    address: Address,
    chain_id: u32,
    next_header_function_id: B256,
    header_range_function_id: B256,
}

type NextHeaderInputTuple = sol! { tuple(uint64, bytes32) };

type HeaderRangeInputTuple = sol! { tuple(uint64, bytes32, uint64) };

struct BlobstreamXOperator {
    config: BlobstreamXConfig,
    contract: BlobstreamX<Provider<Http>>,
    client: SuccinctClient,
    data_fetcher: InputDataFetcher,
}

impl BlobstreamXOperator {
    pub fn new() -> Self {
        let config = Self::get_config();

        let ethereum_rpc_url = env::var("RPC_URL").expect("RPC_URL must be set");
        let provider =
            Provider::<Http>::try_from(ethereum_rpc_url).expect("could not connect to client");

        let contract = BlobstreamX::new(config.address.0 .0, provider.into());

        let tendermint_rpc_url =
            env::var("TENDERMINT_RPC_URL").expect("TENDERMINT_RPC_URL must be set");
        let data_fetcher = InputDataFetcher::new(&tendermint_rpc_url, "");

        let succinct_rpc_url = env::var("SUCCINCT_RPC_URL").expect("SUCCINCT_RPC_URL must be set");
        let succinct_api_key = env::var("SUCCINCT_API_KEY").expect("SUCCINCT_API_KEY must be set");
        let client = SuccinctClient::new(succinct_rpc_url, succinct_api_key);

        Self {
            config,
            contract,
            client,
            data_fetcher,
        }
    }

    fn get_config() -> BlobstreamXConfig {
        let contract_address = env::var("CONTRACT_ADDRESS").expect("CONTRACT_ADDRESS must be set");
        let chain_id = env::var("CHAIN_ID").expect("CHAIN_ID must be set");
        let address = contract_address
            .parse::<Address>()
            .expect("invalid address");

        // Load the function IDs.
        let next_header_id_env =
            env::var("NEXT_HEADER_FUNCTION_ID").expect("NEXT_HEADER_FUNCTION_ID must be set");
        let next_header_function_id = B256::from_slice(
            &hex::decode(
                next_header_id_env
                    .strip_prefix("0x")
                    .unwrap_or(&next_header_id_env),
            )
            .expect("invalid hex for next_header_function_id, expected 0x prefix"),
        );
        let header_range_id_env =
            env::var("HEADER_RANGE_FUNCTION_ID").expect("HEADER_RANGE_FUNCTION_ID must be set");
        let header_range_function_id = B256::from_slice(
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

    async fn request_next_header(&self, trusted_block: u64) -> Result<String> {
        let trusted_header_hash = self
            .contract
            .block_height_to_header_hash(trusted_block)
            .await
            .unwrap();

        let input = NextHeaderInputTuple::abi_encode_packed(&(trusted_block, trusted_header_hash));

        let commit_next_header_call = CommitNextHeaderCall { trusted_block };
        let function_data = commit_next_header_call.encode();

        let request_id = self
            .client
            .submit_platform_request(
                self.config.chain_id,
                self.config.address,
                function_data.into(),
                self.config.next_header_function_id,
                Bytes::copy_from_slice(&input),
            )
            .await?;

        Ok(request_id)
    }

    async fn request_header_range(&self, trusted_block: u64, target_block: u64) -> Result<String> {
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
            target_block,
        };
        let function_data = commit_header_range_call.encode();

        let request_id = self
            .client
            .submit_platform_request(
                self.config.chain_id,
                self.config.address,
                function_data.into(),
                self.config.header_range_function_id,
                Bytes::copy_from_slice(&input),
            )
            .await?;

        Ok(request_id)
    }

    async fn run(&self) {
        // Loop every 60 minutes.
        const LOOP_DELAY: u64 = 60;

        let header_range_max = self.contract.data_commitment_max().await.unwrap();

        // Something is wrong with the contract if this is true.
        if (header_range_max as u64) == 0 {
            panic!("header_range_max must be greater than 0");
        }

        loop {
            let current_block = self.contract.latest_block().await.unwrap();

            // Get the head of the chain.
            let latest_signed_header = self.data_fetcher.get_latest_signed_header().await;
            let latest_block = latest_signed_header.header.height.value();

            // Subtract 2 blocks to account for the time it takes for a block to be processed by
            // consensus.
            let max_end_block = std::cmp::min(latest_block - 2, current_block + header_range_max);

            let target_block = self
                .data_fetcher
                .find_block_to_request(current_block, max_end_block)
                .await;

            if target_block - current_block == 1 {
                // Request the next header if the target block is the next block.
                match self.request_next_header(current_block).await {
                    Ok(request_id) => {
                        info!("Next header request submitted: {}", request_id)
                    }
                    Err(e) => {
                        error!("Next header request failed: {}", e);
                        continue;
                    }
                };
            } else {
                // Request a header range if the target block is not the next block.
                match self.request_header_range(current_block, target_block).await {
                    Ok(request_id) => {
                        info!("Header range request submitted: {}", request_id)
                    }
                    Err(e) => {
                        error!("Header range request failed: {}", e);
                        continue;
                    }
                };
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
