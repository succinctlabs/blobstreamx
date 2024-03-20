use tendermintx::config::{
    TendermintConfig, CELESTIA_CHAIN_ID_BYTES, CELESTIA_CHAIN_ID_SIZE_BYTES,
    MOCHA_4_CHAIN_ID_BYTES, MOCHA_4_CHAIN_ID_SIZE_BYTES,
};

/// Celestia's BlobstreamX config for max batch size of 1024 blocks.
#[derive(Debug, Clone, PartialEq)]
pub struct CelestiaBlobstreamXConfig1024;
impl TendermintConfig<CELESTIA_CHAIN_ID_SIZE_BYTES> for CelestiaBlobstreamXConfig1024 {
    const CHAIN_ID_BYTES: &'static [u8] = CELESTIA_CHAIN_ID_BYTES;
    const SKIP_MAX: usize = 1024;
}

/// Celestia's BlobstreamX config for max batch size of 2048 blocks.
#[derive(Debug, Clone, PartialEq)]
pub struct CelestiaBlobstreamXConfig2048;
impl TendermintConfig<CELESTIA_CHAIN_ID_SIZE_BYTES> for CelestiaBlobstreamXConfig2048 {
    const CHAIN_ID_BYTES: &'static [u8] = CELESTIA_CHAIN_ID_BYTES;
    const SKIP_MAX: usize = 2048;
}

/// Mocha-4's BlobstreamX config.
#[derive(Debug, Clone, PartialEq)]
pub struct Mocha4BlobstreamXConfig1024;
impl TendermintConfig<MOCHA_4_CHAIN_ID_SIZE_BYTES> for Mocha4BlobstreamXConfig1024 {
    const CHAIN_ID_BYTES: &'static [u8] = MOCHA_4_CHAIN_ID_BYTES;
    const SKIP_MAX: usize = 1024;
}
