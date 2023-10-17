use std::env;
use std::sync::Arc;

use ethers::contract::abigen;
use ethers::core::types::Address;
use ethers::prelude::SignerMiddleware;
use ethers::providers::{Http, Provider};
use ethers::signers::{LocalWallet, Signer};
use ethers::types::H256;
use log::info;
use tendermint::block::Header;
use zk_tendermint::input::tendermint_utils::{
    is_valid_skip, HeaderResponse, SignedBlock, SignedBlockResponse,
};

// Note: Update ABI when updating contract.
abigen!(ZKBlobstream, "./abi/ZKBlobstream.abi.json");

async fn get_latest_header(base_url: &str) -> Header {
    let query_url = format!("{}/header", base_url);
    info!("Querying url {:?}", query_url.as_str());
    let res = reqwest::get(query_url).await.unwrap().text().await.unwrap();
    let v: HeaderResponse = serde_json::from_str(&res).expect("Failed to parse JSON");
    v.result.header
}

async fn get_header_from_number(base_url: &str, block_number: u64) -> Header {
    let query_url = format!("{}/header?height={}", base_url, block_number);
    info!("Querying url {:?}", query_url.as_str());
    let res = reqwest::get(query_url).await.unwrap().text().await.unwrap();
    let v: HeaderResponse = serde_json::from_str(&res).expect("Failed to parse JSON");
    v.result.header
}

async fn get_signed_block_from_number(base_url: &str, block_number: u64) -> SignedBlock {
    let query_url = format!("{}/signed_block?height={}", base_url, block_number);
    info!("Querying url {:?}", query_url.as_str());
    let res = reqwest::get(query_url).await.unwrap().text().await.unwrap();
    let v: SignedBlockResponse = serde_json::from_str(&res).expect("Failed to parse JSON");
    v.result
}

// Binary search to find the block number to call request_combined_skip on. If the binary search
// returns start_block + 1, then we call request_combined_step instead.
async fn find_request_block(base_url: &str, start_block: u64, end_block: u64) -> u64 {
    let start_signed_block = get_signed_block_from_number(base_url, start_block).await;

    let mut curr_end_block = end_block;
    loop {
        if curr_end_block - start_block == 1 {
            return curr_end_block;
        }

        let curr_end_signed_block = get_signed_block_from_number(base_url, curr_end_block).await;

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

    let tendermint_rpc_url = env::var("RPC_MOCHA_4").expect("RPC_MOCHA_4 must be set");

    let ethereum_rpc_url = env::var("RPC_URL").expect("RPC_URL must be set");
    let provider =
        Provider::<Http>::try_from(ethereum_rpc_url).expect("could not connect to client");

    let private_key = env::var("PRIVATE_KEY").expect("PRIVATE_KEY must be set");
    let wallet: LocalWallet = private_key
        .parse::<LocalWallet>()
        .expect("invalid private key")
        .with_chain_id(5u64);

    info!("Wallet address: {:?}", wallet.address());

    let client = SignerMiddleware::new(provider, wallet);
    let client = Arc::new(client);

    // ZKBlobstream on Goerli: https://goerli.etherscan.io/address/0x67ea962864cdad3f2202118dc6f65ff510f7bb4d#code
    let address = "0x67ea962864cdad3f2202118dc6f65ff510f7bb4d";
    let address = address.parse::<Address>().expect("invalid address");

    let zk_blobstream = ZKBlobstream::new(address, client.clone());
    let latest_header = get_latest_header(&tendermint_rpc_url).await;
    let latest_block = latest_header.height.value();

    let head = zk_blobstream
        .latest_block()
        .call()
        .await
        .expect("failed to get head");

    // TODO: Remove in prod
    // Set genesis header if we are more than 1000 blocks behind.
    if (head as u64) < latest_block - 1000 {
        let mut block_to_request = latest_block - 500;
        block_to_request = block_to_request - (block_to_request % 10);

        let genesis_header = get_header_from_number(&tendermint_rpc_url, block_to_request).await;
        zk_blobstream
            .set_genesis_header(
                block_to_request,
                H256::from_slice(genesis_header.hash().as_bytes()).0,
            )
            .send()
            .await
            .expect("failed to set genesis header");
    }

    let mut curr_head = head;

    // Loop every 30 minutes. Call request_combined_skip every 30 minutes with the latest block number.
    // Loop time is currently to the time it takes for a proof to be generated.
    // TODO: Update with prod loop time.
    // TODO: Can update this to only skip to multiples of 10/100.
    let increment = 30;
    loop {
        // Get latest_header
        let latest_header = get_latest_header(&tendermint_rpc_url).await;
        let latest_block = latest_header.height.value();

        // Round down to the nearest 10.
        let max_end_block = latest_block - 10;

        let target_block = find_request_block(&tendermint_rpc_url, curr_head, max_end_block).await;

        if target_block - curr_head == 1 {
            // Call step if necessary.
            zk_blobstream
                .request_combined_step()
                .send()
                .await
                .expect("failed to request combined skip");
        } else {
            // Verify the call succeeded.
            zk_blobstream
                .request_combined_skip(target_block)
                .send()
                .await
                .expect("failed to request combined skip");
        }

        tokio::time::sleep(tokio::time::Duration::from_secs(60 * increment)).await;

        curr_head = target_block;
    }
}
