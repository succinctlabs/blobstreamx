use tendermintx::config::{
    TendermintConfig, CELESTIA_CHAIN_ID_BYTES, CELESTIA_CHAIN_ID_SIZE_BYTES,
    MOCHA_4_CHAIN_ID_BYTES, MOCHA_4_CHAIN_ID_SIZE_BYTES,
};

use crate::consts::{BATCH_SIZE, NB_MAP_JOBS};

/// @notice The maximum number of blocks that can be skipped.
pub const SKIP_MAX: usize = NB_MAP_JOBS * BATCH_SIZE;

/// Celestia's BlobstreamX config.
#[derive(Debug, Clone, PartialEq)]
pub struct CelestiaBlobstreamXConfig;
impl TendermintConfig<CELESTIA_CHAIN_ID_SIZE_BYTES> for CelestiaBlobstreamXConfig {
    const CHAIN_ID_BYTES: &'static [u8] = CELESTIA_CHAIN_ID_BYTES;
    const SKIP_MAX: usize = SKIP_MAX;
}

/// Mocha-4's BlobstreamX config.
#[derive(Debug, Clone, PartialEq)]
pub struct Mocha4BlobstreamXConfig;
impl TendermintConfig<MOCHA_4_CHAIN_ID_SIZE_BYTES> for Mocha4BlobstreamXConfig {
    const CHAIN_ID_BYTES: &'static [u8] = MOCHA_4_CHAIN_ID_BYTES;
    const SKIP_MAX: usize = SKIP_MAX;
}
