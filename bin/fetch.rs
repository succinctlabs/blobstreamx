//! To build the binary:
//!
//!     `cargo build --release --bin fetch`
//!
//!
//!
//!
//!

use std::env;

use clap::Parser;
use tendermintx::input::InputDataFetcher;

#[derive(Parser, Debug, Clone)]
#[command(about = "Get the genesis parameters from a block.")]
pub struct FetchArgs {
    #[arg(long, default_value = "1")]
    pub block: u64,
}

#[tokio::main]
pub async fn main() {
    env::set_var("RUST_LOG", "info");
    dotenv::dotenv().ok();
    env_logger::init();
    let mut data_fetcher = InputDataFetcher {
        save: true,
        fixture_path: "./fixtures/celestia".to_string(),
        ..Default::default()
    };

    let args = FetchArgs::parse();
    let fetch_block = args.block;

    // Write signed_header to JSON.
    let _ = data_fetcher
        .get_signed_header_from_number(fetch_block)
        .await;

    // Write validators to JSON.
    let _ = data_fetcher
        .get_validator_set_from_number(fetch_block)
        .await;

    // Write next_validators to JSON.
    let _ = data_fetcher
        .get_validator_set_from_number(fetch_block + 1)
        .await;
}
