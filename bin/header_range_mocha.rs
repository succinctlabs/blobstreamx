use blobstreamx::config::Mocha4BlobstreamXConfig1024;
use blobstreamx::header_range::CombinedSkipCircuit;
use plonky2x::backend::function::Plonky2xFunction;
use tendermintx::config::MOCHA_4_CHAIN_ID_SIZE_BYTES;

fn main() {
    const VALIDATOR_SET_SIZE_MAX: usize = 100;
    const NB_MAP_JOBS: usize = 32;
    const BATCH_SIZE: usize = 32;
    CombinedSkipCircuit::<
        VALIDATOR_SET_SIZE_MAX,
        MOCHA_4_CHAIN_ID_SIZE_BYTES,
        Mocha4BlobstreamXConfig1024,
        NB_MAP_JOBS,
        BATCH_SIZE,
    >::entrypoint();
}
