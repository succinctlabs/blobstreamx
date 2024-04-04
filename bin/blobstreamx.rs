use std::env;
use std::str::FromStr;

use alloy_primitives::{Address, Bytes, FixedBytes, B256};
use alloy_sol_types::{sol, SolType};
use anyhow::Result;
use ethers::abi::AbiEncode;
use ethers::contract::abigen;
use ethers::providers::{Http, Provider};
use ethers::signers::LocalWallet;
use log::{error, info};
use succinct_client::request::SuccinctClient;
use tendermintx::input::InputDataFetcher;

// Note: Update ABI when updating contract.
abigen!(BlobstreamX, "./abi/BlobstreamX.abi.json");

struct BlobstreamXConfig {
    address: Address,
    chain_id: u32,
    local_prove_mode: bool,
    local_relay_mode: bool,
}

type NextHeaderInputTuple = sol! { tuple(uint64, bytes32) };

type HeaderRangeInputTuple = sol! { tuple(uint64, bytes32, uint64) };

struct BlobstreamXOperator {
    config: BlobstreamXConfig,
    ethereum_rpc_url: String,
    wallet: Option<LocalWallet>,
    gateway_address: Option<String>,
    contract: BlobstreamX<Provider<Http>>,
    client: SuccinctClient,
    data_fetcher: InputDataFetcher,
}

impl BlobstreamXOperator {
    pub async fn new() -> Self {
        let contract_address = env::var("CONTRACT_ADDRESS").expect("CONTRACT_ADDRESS must be set");
        let chain_id = env::var("CHAIN_ID").expect("CHAIN_ID must be set");
        let address = contract_address
            .parse::<Address>()
            .expect("invalid address");

        // Local prove mode and local relay mode are optional and default to false.
        let local_prove_mode: String =
            env::var("LOCAL_PROVE_MODE").unwrap_or(String::from("false"));
        let local_prove_mode_bool = local_prove_mode.parse::<bool>().unwrap();
        let local_relay_mode: String =
            env::var("LOCAL_RELAY_MODE").unwrap_or(String::from("false"));
        let local_relay_mode_bool = local_relay_mode.parse::<bool>().unwrap();

        let ethereum_rpc_url = env::var("RPC_URL").expect("RPC_URL must be set");
        let provider = Provider::<Http>::try_from(ethereum_rpc_url.clone())
            .expect("could not connect to client");

        let contract = BlobstreamX::new(address.0 .0, provider.into());

        let config = BlobstreamXConfig {
            address,
            chain_id: chain_id.parse::<u32>().expect("invalid chain id"),
            local_prove_mode: local_prove_mode_bool,
            local_relay_mode: local_relay_mode_bool,
        };

        let data_fetcher = InputDataFetcher::default();

        let succinct_rpc_url = env::var("SUCCINCT_RPC_URL").expect("SUCCINCT_RPC_URL must be set");
        let succinct_api_key = env::var("SUCCINCT_API_KEY").expect("SUCCINCT_API_KEY must be set");

        let private_key: Option<String>;
        let wallet: Option<LocalWallet>;
        let gateway_address: Option<String>;

        if config.local_relay_mode {
            // If true, set the variables with the required values
            private_key = Some(env::var("PRIVATE_KEY").expect("PRIVATE_KEY must be set"));

            wallet = Some(
                LocalWallet::from_str(private_key.as_ref().unwrap()).expect("invalid private key"),
            );

            // Set gateway_address if it exists in the environment
            gateway_address = env::var("GATEWAY_ADDRESS").ok();
        } else {
            wallet = None;
            gateway_address = None;
        }

        let client = SuccinctClient::new(
            succinct_rpc_url,
            succinct_api_key,
            config.local_prove_mode,
            config.local_relay_mode,
        );

        Self {
            config,
            ethereum_rpc_url,
            wallet,
            contract,
            gateway_address,
            client,
            data_fetcher,
        }
    }

    async fn request_next_header(
        &self,
        trusted_block: u64,
        next_header_function_id: B256,
    ) -> Result<String> {
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
            .submit_request(
                self.config.chain_id,
                self.config.address,
                function_data.into(),
                next_header_function_id,
                Bytes::copy_from_slice(&input),
            )
            .await?;

        Ok(request_id)
    }

    async fn request_header_range(
        &self,
        trusted_block: u64,
        target_block: u64,
        header_range_function_id: B256,
    ) -> Result<String> {
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

        let commit_header_range_call = CommitHeaderRangeCall { target_block };
        let function_data = commit_header_range_call.encode();

        let request_id = self
            .client
            .submit_request(
                self.config.chain_id,
                self.config.address,
                function_data.into(),
                header_range_function_id,
                Bytes::copy_from_slice(&input),
            )
            .await?;

        Ok(request_id)
    }

    async fn run(&mut self, loop_delay_mins: u64, block_interval: u64, data_commitment_max: u64) {
        info!("Starting BlobstreamX operator");
        let header_range_max = self.contract.data_commitment_max().await.unwrap();

        // Something is wrong with the contract if this is true.
        if header_range_max == 0 {
            panic!("header_range_max must be greater than 0");
        }

        loop {
            // Get the function IDs from the contract (they can change if the contract is updated).
            let next_header_function_id =
                FixedBytes(self.contract.next_header_function_id().await.unwrap());
            let header_range_function_id =
                FixedBytes(self.contract.header_range_function_id().await.unwrap());

            let current_block = self.contract.latest_block().await.unwrap();

            // Get the head of the chain.
            let latest_tendermint_signed_header =
                self.data_fetcher.get_latest_signed_header().await;
            let latest_tendermint_block_nb = latest_tendermint_signed_header.header.height.value();

            // Subtract 1 block to ensure the block is stable.
            let latest_stable_tendermint_block = latest_tendermint_block_nb - 1;

            // block_to_request is the closest interval of block_interval less than min(latest_stable_tendermint_block, data_commitment_max + current_block)
            let max_block = std::cmp::min(
                latest_stable_tendermint_block,
                data_commitment_max + current_block,
            );
            let block_to_request = max_block - (max_block % block_interval);

            // If block_to_request is greater than the current block in the contract, attempt to request.
            if block_to_request > current_block {
                // The next block the operator should request.
                let max_end_block = block_to_request;

                let target_block = self
                    .data_fetcher
                    .find_block_to_request(current_block, max_end_block)
                    .await;

                info!("Attempting to step to block {}", target_block);

                if target_block - current_block == 1 {
                    // Request the next header if the target block is the next block.
                    match self
                        .request_next_header(current_block, next_header_function_id)
                        .await
                    {
                        Ok(request_id) => {
                            info!("Next header request submitted: {}", request_id);

                            // If in local mode, this will submit the request on-chain.
                            let res = self
                                .client
                                .relay_proof(
                                    request_id,
                                    Some(self.ethereum_rpc_url.as_ref()),
                                    self.wallet.clone(),
                                    self.gateway_address.as_deref(),
                                )
                                .await;
                            match res {
                                Ok(_) => info!("Relayed successfully!"),
                                Err(e) => {
                                    error!("Relay failed: {}", e);
                                }
                            }
                        }
                        Err(e) => {
                            error!("Next header request failed: {}", e);
                            continue;
                        }
                    };
                } else {
                    // Request a header range if the target block is not the next block.
                    match self
                        .request_header_range(current_block, target_block, header_range_function_id)
                        .await
                    {
                        Ok(request_id) => {
                            info!("Header range request submitted: {}", request_id);

                            // If in local mode, this will submit the request on-chain.
                            let res = self
                                .client
                                .relay_proof(
                                    request_id,
                                    Some(self.ethereum_rpc_url.as_ref()),
                                    self.wallet.clone(),
                                    self.gateway_address.as_deref(),
                                )
                                .await;
                            match res {
                                Ok(_) => info!("Relayed successfully!"),
                                Err(e) => {
                                    error!("Relay failed: {}", e);
                                }
                            }
                        }
                        Err(e) => {
                            error!("Header range request failed: {}", e);
                            continue;
                        }
                    };
                }
            } else {
                info!("Next block to request is {} which is > the head of the Tendermint chain which is {}. Sleeping.", block_to_request + block_interval, latest_stable_tendermint_block);
            }

            tokio::time::sleep(tokio::time::Duration::from_secs(60 * loop_delay_mins)).await;
        }
    }
}

#[tokio::main]
async fn main() {
    env::set_var("RUST_LOG", "info");
    dotenv::dotenv().ok();
    env_logger::init();

    let loop_delay_mins_env = env::var("LOOP_DELAY_MINS");
    let mut loop_delay_mins = 5;
    if loop_delay_mins_env.is_ok() {
        loop_delay_mins = loop_delay_mins_env
            .unwrap()
            .parse::<u64>()
            .expect("invalid LOOP_DELAY_MINS");
    }

    let update_delay_blocks_env = env::var("UPDATE_DELAY_BLOCKS");
    let mut update_delay_blocks = 300;
    if update_delay_blocks_env.is_ok() {
        update_delay_blocks = update_delay_blocks_env
            .unwrap()
            .parse::<u64>()
            .expect("invalid UPDATE_DELAY_BLOCKS");
    }

    let data_commitment_max_env = env::var("DATA_COMMITMENT_MAX");
    let mut data_commitment_max = 1000;
    if data_commitment_max_env.is_ok() {
        data_commitment_max = data_commitment_max_env
            .unwrap()
            .parse::<u64>()
            .expect("invalid DATA_COMMITMENT_MAX");
    }

    let mut operator = BlobstreamXOperator::new().await;
    operator
        .run(loop_delay_mins, update_delay_blocks, data_commitment_max)
        .await;
}
