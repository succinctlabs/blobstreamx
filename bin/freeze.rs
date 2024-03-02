use std::env;
use std::str::FromStr;
use std::sync::Arc;

use alloy_sol_types::{sol, SolType};
use blobstreamx::input::DataCommitmentInputs;
use ethers::contract::abigen;
use ethers::core::types::Address;
use ethers::providers::{Middleware, Provider, Ws};
use ethers::types::Filter;
use futures::StreamExt;
use log::{debug, error};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use subtle_encoding::hex;
use tendermintx::input::InputDataFetcher;

// Note: Update ABI when updating contract.
abigen!(BlobstreamX, "./abi/BlobstreamX.abi.json");
struct CelestiaChain;

impl CelestiaChain {
    const MOCHA4: &'static str = "MOCHA4";
    const CELESTIA: &'static str = "CELESTIA";
}

struct ChainConfig {
    chain_id: u64,
    contract_address: &'static str,
    celestia_chain: &'static str,
}

type DataCommitmentStoredTuple = sol! { tuple(uint256, uint64, uint64, bytes32) };
type HeadUpdateTuple = sol! { tuple(uint64, bytes32) };

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum PagerDutyMode {
    General,
    Integrations, // Add other modes as necessary
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum PagerDutySeverity {
    Critical,
    // Add other severities as necessary
}

pub struct MonitorClient {
    http_client: Client,
    page: bool,
    // page_mode: PagerDutyMode,
    api_key: String,
    service: String,
}

const PAGERDUTY_API: &str = "https://events.pagerduty.com";
const PAGERDUTY_V2_EVENTS_ROUTE: &str = "/v2/enqueue";
// const PAGER_DUTY_API_KEY_ENV_VAR: &str = "PAGERDUTY_API_KEY";

const PAGER_DUTY_API_KEY_GENERAL_ENV_VAR: &str = "PAGERDUTY_API_KEY_GENERAL";
const PAGER_DUTY_API_KEY_INTEGRATIONS_ENV_VAR: &str = "PAGERDUTY_API_KEY_INTEGRATIONS";

impl MonitorClient {
    pub fn new(page: bool, page_mode: PagerDutyMode) -> Self {
        let api_key_env = match page_mode {
            PagerDutyMode::General => PAGER_DUTY_API_KEY_GENERAL_ENV_VAR,
            PagerDutyMode::Integrations => PAGER_DUTY_API_KEY_INTEGRATIONS_ENV_VAR,
        };

        let api_key =
            env::var(api_key_env).unwrap_or_else(|_| panic!("{} must be set!", api_key_env));
        Self {
            http_client: Client::new(),
            page,
            // page_mode,
            api_key,
            service: "Blobstream X Freeze Alert".to_string(),
        }
    }

    pub async fn alert(&self, message: &str) {
        self.send_slack_message(message).await;
        if self.page {
            self.send_pagerduty_alert(
                &self.service,
                message,
                PagerDutySeverity::Critical,
                serde_json::Value::Null,
            )
            .await;
        }
    }

    async fn send_slack_message(&self, message: &str) {
        let slack_token = env::var("SLACK_TOKEN").expect("SLACK_TOKEN must be set");
        let channel = "#seal";
        let text = format!("*{} Monitor*: {}", "Blobstream X", message);

        let payload = serde_json::json!({
            "channel": channel,
            "text": text,
        });

        let _res = self
            .http_client
            .post("https://slack.com/api/chat.postMessage")
            .bearer_auth(slack_token)
            .json(&payload)
            .send()
            .await
            .expect("Failed to send message to Slack");
    }

    async fn send_pagerduty_alert(
        &self,
        source: &str,
        summary: &str,
        severity: PagerDutySeverity,
        context: serde_json::Value,
    ) {
        // Implement PagerDuty API call similarly
        // This example does not include a real PagerDuty API call for brevity
        const ACTION: &str = "trigger";
        let internal_paylaod = serde_json::json!({
            "source": source,
            "summary": summary,
            "severity": severity,
            "custom_details": context
        });
        let payload = serde_json::json!({
            "payload": internal_paylaod,
            // If an existing incident with the same dedup_key exists, a new incident will not be created.
            "dedup_key": source,
            "routing_key": self.api_key,
            "event_action": ACTION
        });

        let _res = self
            .http_client
            .post(format!("{}{}", PAGERDUTY_API, PAGERDUTY_V2_EVENTS_ROUTE))
            .json(&payload)
            .send()
            .await
            .expect("Failed to send message to Slack");
    }
}

async fn launch_monitor(config: &ChainConfig) {
    let monitor_client = MonitorClient::new(true, PagerDutyMode::Integrations);

    // Read WS_{chain_id} from .env
    let ws_url = format!("WS_{}", config.chain_id);

    let ws_url =
        env::var(ws_url).unwrap_or_else(|_| panic!("WS for chain {} not found", config.chain_id));

    // Read TENDERMINT_RPC_{celestia_chain} from .env
    let tendermint_rpc = format!("TENDERMINT_RPC_{}", config.celestia_chain);

    let tendermint_rpc = env::var(tendermint_rpc)
        .unwrap_or_else(|_| panic!("Tendermint RPC for {} not found", config.celestia_chain));

    // Split the url's by commas.
    let urls = tendermint_rpc
        .split(',')
        .map(|s| s.to_string())
        .collect::<Vec<String>>();

    let mut input_data_fetcher = InputDataFetcher {
        urls,
        ..Default::default()
    };

    let provider = Provider::<Ws>::connect(ws_url.clone()).await.unwrap();
    let client = Arc::new(provider);

    let contract_address = Address::from_str(config.contract_address).unwrap();

    let data_commitment_filter = Filter::new()
        .address(contract_address)
        .event("DataCommitmentStored(uint256,uint64,uint64,bytes32)");

    let mut stream = client
        .subscribe_logs(&data_commitment_filter)
        .await
        .unwrap();
    while let Some(log) = stream.next().await {
        let log_bytes = log.data;

        // Check the data commitment is correct.
        let decoded = DataCommitmentStoredTuple::abi_decode(&log_bytes.0, true).unwrap();

        let start_block = decoded.1;
        let end_block = decoded.2;
        let contract_data_commitment: Vec<u8> = decoded.3.to_vec();

        let expected_data_commitment = input_data_fetcher
            .get_data_commitment(start_block, end_block)
            .await;

        debug!(
            "Data commitment for range {}-{}: {:?}",
            start_block,
            end_block,
            hex::encode(contract_data_commitment.clone())
        );

        if contract_data_commitment != expected_data_commitment {
            // TODO: Send alert.
            error!(
                "Data commitment mismatch for data commitment over range {}-{}",
                start_block, end_block
            );

            monitor_client
                .alert(&format!(
                    "Data commitment mismatch for Blobstream X light client on chain {} tracking chain {}. Data commitment over range {}-{}",
                    config.chain_id, config.celestia_chain, start_block, end_block
                ))
                .await;
        }

        // Fetch all HeadUpdate events emitted on the block of this log (as they are always emitted on the same block).
        let head_update_filter = Filter::new()
            .address(contract_address)
            .from_block(log.block_number.unwrap())
            .to_block(log.block_number.unwrap())
            .event("HeadUpdate(uin64,bytes32)");
        let head_update_logs = client
            .get_logs(&head_update_filter)
            .await
            .expect("Failed to get logs");
        if head_update_logs.len() != 1 {
            error!(
                "Expected 1 HeadUpdate event on block {} but got {}",
                log.block_number.unwrap(),
                head_update_logs.len()
            );
        }
        let head_update_log = head_update_logs[0].clone();
        let head_update_bytes = head_update_log.data;
        let head_update_decoded = HeadUpdateTuple::abi_decode(&head_update_bytes.0, true).unwrap();

        let target_block = head_update_decoded.0;
        let contract_target_header_hash = head_update_decoded.1;

        let target_header = input_data_fetcher
            .get_signed_header_from_number(target_block)
            .await;
        let expected_header_hash: [u8; 32] =
            target_header.header.hash().as_bytes().try_into().unwrap();

        if contract_target_header_hash != expected_header_hash {
            // TODO: Send alert.
            error!("Header hash mismatch for block {}", target_block);

            monitor_client
                .alert(&format!(
                    "Header hash mismatch for block for Blobstream X light client on chain {} tracking chain {}. Header hash incorrect for block {}.",
                    config.chain_id, config.celestia_chain, target_block
                ))
                .await;
        }
    }
}

const CONFIGS: [ChainConfig; 2] = [
    ChainConfig {
        chain_id: 421614,
        contract_address: "0xf6b3239143d33aeFC893fa5411cdc056F8080418",
        celestia_chain: CelestiaChain::MOCHA4,
    },
    ChainConfig {
        chain_id: 11155111,
        contract_address: "0x48B257EC1610d04191cC2c528d0c940AdbE1E439",
        celestia_chain: CelestiaChain::CELESTIA,
    },
];

#[tokio::main]
async fn main() {
    env::set_var("RUST_LOG", "debug");
    dotenv::dotenv().ok();
    env_logger::init();

    let mut handles = Vec::new();

    for config in CONFIGS.iter() {
        let handle = tokio::spawn(async move {
            launch_monitor(config).await;
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.await.expect("Thread panicked.")
    }
}
