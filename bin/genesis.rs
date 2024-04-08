//! To build the binary:
//!
//!     `cargo build --release --bin genesis`
//!
//!
//!
//!
//!

use std::env;

use clap::Parser;
use log::info;
use tendermintx::input::InputDataFetcher;

#[derive(Parser, Debug, Clone)]
#[command(about = "Get the genesis parameters from a block.")]
pub struct GenesisArgs {
    #[arg(long)]
    pub block: Option<u64>,
}

#[tokio::main]
pub async fn main() {
    env::set_var("RUST_LOG", "info");
    dotenv::dotenv().ok();
    env_logger::init();
    let mut data_fetcher = InputDataFetcher::default();
    let args = GenesisArgs::parse();

    if let Some(block) = args.block {
        let signed_header = data_fetcher.get_signed_header_from_number(block).await;
        let header_hash = signed_header.header.hash();
        info!(
            "GENESIS_HEIGHT: {:?}\n GENESIS_HEADER: {}",
            block,
            format!("0x{}", header_hash.to_string())
        );
    } else {
        let signed_header = data_fetcher.get_latest_signed_header().await;
        let header_hash = signed_header.header.hash();
        info!(
            "\nGENESIS_HEIGHT={:?}\nGENESIS_HEADER={}",
            signed_header.header.height.value(),
            format!("0x{}", header_hash.to_string())
        );
    }
}
