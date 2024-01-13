// Relay local proof

use std::env;
use std::str::FromStr;

use clap::Parser;
use ethers::contract::abigen;
use ethers::signers::LocalWallet;
use log::info;
use succinct_client::request::SuccinctClient;

// Note: Update ABI when updating contract.
abigen!(BlobstreamX, "./abi/BlobstreamX.abi.json");

struct BlobstreamXRelayer {
    client: SuccinctClient,
    ethereum_rpc_url: String,
    wallet: LocalWallet,
}

impl BlobstreamXRelayer {
    pub fn new() -> Self {
        let ethereum_rpc_url = env::var("RPC_URL").expect("RPC_URL must be set");
        let private_key =
            env::var("PRIVATE_KEY").unwrap_or(String::from("0x00000000000000000000000000000000"));
        let wallet = LocalWallet::from_str(&private_key).expect("invalid private key");

        let succinct_rpc_url = env::var("SUCCINCT_RPC_URL").expect("SUCCINCT_RPC_URL must be set");
        let succinct_api_key = env::var("SUCCINCT_API_KEY").expect("SUCCINCT_API_KEY must be set");

        // Local prove mode and local relay mode are optional and default to false.
        let local_prove_mode: String =
            env::var("LOCAL_PROVE_MODE").unwrap_or(String::from("false"));
        let local_prove_mode_bool = local_prove_mode.parse::<bool>().unwrap();
        let local_relay_mode: String =
            env::var("LOCAL_RELAY_MODE").unwrap_or(String::from("false"));
        let local_relay_mode_bool = local_relay_mode.parse::<bool>().unwrap();

        let client = SuccinctClient::new(
            succinct_rpc_url,
            succinct_api_key,
            local_prove_mode_bool,
            local_relay_mode_bool,
        );

        Self {
            client,
            ethereum_rpc_url,
            wallet,
        }
    }

    async fn run(&self, request_id: String) {
        info!("Starting BlobstreamX relayer");

        // If in local mode, this will submit the request on-chain.
        let res = self
            .client
            .relay_proof(
                request_id,
                Some(self.ethereum_rpc_url.as_ref()),
                Some(self.wallet.clone()),
                None,
            )
            .await;
        info!("Relay result: {:?}", res);
    }
}

#[derive(Parser, Debug, Clone)]
#[command(about = "Get the request ID.")]
pub struct LocalRelayArgs {
    #[arg(long)]
    pub request_id: String,
}

#[tokio::main]
async fn main() {
    env::set_var("RUST_LOG", "debug");
    dotenv::dotenv().ok();
    env_logger::init();

    let operator = BlobstreamXRelayer::new();

    // Read the request ID from the command line.
    let args = LocalRelayArgs::parse();
    let request_id = args.request_id;

    operator.run(request_id).await;
}
