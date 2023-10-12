use ethers::contract::abigen;
use ethers::core::types::Address;
use ethers::providers::{Provider, StreamExt, Ws};

// Note: Update this ABI if contract is updated.
abigen!(ZKBlobStream, "./abi/ZKBlobstream.abi.json");
#[tokio::main]
async fn main() {
    println!("Hello, world!");
}
