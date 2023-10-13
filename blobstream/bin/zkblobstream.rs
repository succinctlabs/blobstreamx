use std::env;
use std::sync::Arc;

use ethers::contract::abigen;
use ethers::core::types::Address;
use ethers::prelude::SignerMiddleware;
use ethers::providers::{Http, Provider};
use ethers::signers::Wallet;
use ethers::types::H256;
use subtle_encoding::hex;
use zk_tendermint::input::InputDataFetcher;

// Note: Update ABI when updating contract.
abigen!(ZKBlobstream, "./abi/ZKBlobstream.abi.json");
#[tokio::main]
async fn main() -> Result<(), ()> {
    dotenv::dotenv().ok();

    let provider =
        Provider::<Http>::try_from("http://localhost:8545").expect("could not connect to client");

    let private_key = env::var("PRIVATE_KEY").expect("PRIVATE_KEY must be set");
    let private_key_bytes = &hex::decode(private_key).expect("invalid private key");
    let wallet = Wallet::from_bytes(private_key_bytes).expect("invalid private key");

    let client = SignerMiddleware::new(provider, wallet);
    let client = Arc::new(client);

    let address = "0xb27328047789FA2320B43e3Ecc78Ec3eFf1DC0eA";
    let address = address.parse::<Address>().expect("invalid address");

    let zk_blobstream = ZKBlobstream::new(address, client.clone());
    let tendermint_input_fetcher = InputDataFetcher::new();
    let start_block = 1000_u64;
    let header = tendermint_input_fetcher.get_header_from_number(1000).await;

    zk_blobstream
        .set_genesis_header(start_block, H256::from_slice(header.hash().as_bytes()).0)
        .send()
        .await
        .expect("failed to set genesis header");

    let mut curr_block = start_block;

    // Loop every 30 minutes. Call request_combined_skip every 30 minutes, and incrememnt the block number by 100 each time.
    loop {
        // TODO: Should run mock prove function here.

        zk_blobstream
            .request_combined_skip(curr_block)
            .send()
            .await
            .expect("failed to request combined skip");

        tokio::time::sleep(tokio::time::Duration::from_secs(60 * 30)).await;

        curr_block += 100;
        if curr_block > 1500 {
            break;
        }
    }

    Ok(())
}
