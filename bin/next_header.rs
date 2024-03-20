use blobstreamx::next_header::CombinedStepCircuit;
use plonky2x::backend::function::Plonky2xFunction;
use tendermintx::config::{CelestiaConfig, CELESTIA_CHAIN_ID_SIZE_BYTES};

fn main() {
    const VALIDATOR_SET_SIZE_MAX: usize = 100;
    CombinedStepCircuit::<VALIDATOR_SET_SIZE_MAX, CELESTIA_CHAIN_ID_SIZE_BYTES, CelestiaConfig>::entrypoint();
}
