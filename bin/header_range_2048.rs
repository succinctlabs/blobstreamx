use blobstreamx::config::CelestiaBlobstreamXConfig2048;
use blobstreamx::header_range::CombinedSkipCircuit;
use plonky2x::backend::function::Plonky2xFunction;
use tendermintx::config::CELESTIA_CHAIN_ID_SIZE_BYTES;

fn main() {
    // Celestia's maxmimum data commitment size is 1000: https://github.com/celestiaorg/celestia-core/blob/6933af1ead0ddf4a8c7516690e3674c6cdfa7bd8/pkg/consts/consts.go#L44.
    const VALIDATOR_SET_SIZE_MAX: usize = 100;
    const NB_MAP_JOBS: usize = 32;
    const BATCH_SIZE: usize = 64;
    CombinedSkipCircuit::<
        VALIDATOR_SET_SIZE_MAX,
        CELESTIA_CHAIN_ID_SIZE_BYTES,
        CelestiaBlobstreamXConfig2048,
        NB_MAP_JOBS,
        BATCH_SIZE,
    >::entrypoint();
}
