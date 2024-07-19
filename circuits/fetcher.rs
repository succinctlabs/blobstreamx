use anyhow::Result;
use reqwest_middleware::reqwest::Client;
use reqwest_middleware::{ClientBuilder, ClientWithMiddleware};
use reqwest_retry::policies::ExponentialBackoff;
use reqwest_retry::RetryTransientMiddleware;
use tendermint::block::signed_header::SignedHeader;
use tendermint::validator::{Info, Set as TendermintValidatorSet};
use tendermintx::input::tendermint_utils::{is_valid_skip, CommitResponse, ValidatorSetResponse};

pub struct BlobstreamOperatorDataFetcher {
    rpc_url: String,
    client: ClientWithMiddleware,
}

const MAX_NUM_RETRIES: usize = 3;

impl Default for BlobstreamOperatorDataFetcher {
    fn default() -> Self {
        // Read TENDERMINT_RPC_URL from env.
        let rpc_url = std::env::var("TENDERMINT_RPC_URL").expect("TENDERMINT_RPC_URL not set");
        Self::new(rpc_url)
    }
}

impl BlobstreamOperatorDataFetcher {
    pub fn new(rpc_url: String) -> Self {
        let retry_policy =
            ExponentialBackoff::builder().build_with_max_retries(MAX_NUM_RETRIES as u32);

        let client: ClientWithMiddleware = ClientBuilder::new(Client::new())
            .with(RetryTransientMiddleware::new_with_policy(retry_policy))
            .build();
        Self { rpc_url, client }
    }

    pub async fn get_latest_signed_header(&self) -> Result<SignedHeader> {
        let route = format!("{}/commit", self.rpc_url);
        let res = self.client.get(route).send().await?;
        let v: CommitResponse =
            serde_json::from_str(&res.text().await?).expect("Failed to parse JSON");
        Ok(v.result.signed_header)
    }

    pub async fn get_signed_header_from_number(&self, block_number: u64) -> Result<SignedHeader> {
        let route = format!("{}/commit?height={}", self.rpc_url, block_number);
        let res = self.client.get(route).send().await?;
        let v: CommitResponse =
            serde_json::from_str(&res.text().await?).expect("Failed to parse JSON");
        Ok(v.result.signed_header)
    }

    pub async fn find_block_to_request(&self, start_block: u64, max_end_block: u64) -> Result<u64> {
        let mut curr_end_block = max_end_block;
        loop {
            if curr_end_block - start_block == 1 {
                return Ok(curr_end_block);
            }

            let start_block_validators = self.get_validator_set_from_number(start_block).await?;
            let start_validator_set = TendermintValidatorSet::new(start_block_validators, None);

            let target_block_validators =
                self.get_validator_set_from_number(curr_end_block).await?;
            let target_validator_set = TendermintValidatorSet::new(target_block_validators, None);

            let target_block_commit = self.get_signed_header_from_number(curr_end_block).await?;

            if is_valid_skip(
                start_validator_set,
                target_validator_set,
                target_block_commit.commit,
            ) {
                return Ok(curr_end_block);
            }

            let mid_block = (curr_end_block + start_block) / 2;
            curr_end_block = mid_block;
        }
    }

    pub async fn get_validator_set_from_number(&self, block_number: u64) -> Result<Vec<Info>> {
        let mut validators = Vec::new();

        let mut page_number = 1;
        let mut num_so_far = 0;
        loop {
            let fetched_result = self
                .fetch_validator_result(block_number, page_number)
                .await?;

            validators.extend(fetched_result.result.validators);
            // Parse count to u32.
            let parsed_count: u32 = fetched_result.result.count.parse().unwrap();
            // Parse total to u32.
            let parsed_total: u32 = fetched_result.result.total.parse().unwrap();

            num_so_far += parsed_count;
            if num_so_far >= parsed_total {
                break;
            }
            page_number += 1;
        }

        Ok(validators)
    }

    async fn fetch_validator_result(
        &self,
        block_number: u64,
        page_number: u64,
    ) -> Result<ValidatorSetResponse> {
        // Check size of validator set.
        let query_route = format!(
            "{}/validators?height={}&per_page=100&page={}",
            self.rpc_url,
            block_number.to_string().as_str(),
            page_number.to_string().as_str()
        );

        let res = self.client.get(query_route).send().await?;
        let v: ValidatorSetResponse =
            serde_json::from_str(&res.text().await?).expect("Failed to parse JSON");
        Ok(v)
    }
}
