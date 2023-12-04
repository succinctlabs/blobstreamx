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
    #[arg(long, default_value = "1")]
    pub block: u64,
}

#[tokio::main]
pub async fn main() {
    env::set_var("RUST_LOG", "info");
    dotenv::dotenv().ok();
    env_logger::init();
    let tendermint_rpc_url =
        env::var("TENDERMINT_RPC_URL").expect("TENDERMINT_RPC_URL must be set");
    let data_fetcher = InputDataFetcher::new(&tendermint_rpc_url, "");
    let args = GenesisArgs::parse();

    let genesis_block = args.block;

    let header_hash = data_fetcher
        .get_signed_header_from_number(genesis_block)
        .await
        .header
        .hash();
    info!("Block {}'s header hash: {:?}", genesis_block, header_hash);
}
