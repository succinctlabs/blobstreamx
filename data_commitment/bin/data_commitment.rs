//! To build the binary:
//!
//!     `cargo build --release --bin data_commitment`
//!
//! To build the circuit:
//!
//!     `./target/release/circuit_function_field build`
//!
//! To prove the circuit using evm io:
//!
//!    `./target/release/circuit_function_evm prove --input-json src/bin/circuit_function_evm_input.json`
//!
//! Note that this circuit will not work with field-based io.
//!
//!
//!
use std::env;

use blobstream::circuit::DataCommitmentCircuit;
use plonky2x::backend::function::VerifiableFunction;

fn main() {
    // Celestia's maxmimum data commitment size is 1000: https://github.com/celestiaorg/celestia-core/blob/6933af1ead0ddf4a8c7516690e3674c6cdfa7bd8/pkg/consts/consts.go#L44.
    let env_max_leaves = env::var("MAX_LEAVES").unwrap_or(0.to_string());

    if env_max_leaves == 1024.to_string() {
        // Note: These constants can be tuned.
        const NB_MAP_JOBS: usize = 16;
        const BATCH_SIZE: usize = 64;
        const MAX_LEAVES: usize = 1024;

        VerifiableFunction::<DataCommitmentCircuit<NB_MAP_JOBS, BATCH_SIZE, MAX_LEAVES>>::entrypoint();
    } else if env_max_leaves == 256.to_string() {
        // Note: These constants can be tuned.
        const NB_MAP_JOBS: usize = 16;
        const BATCH_SIZE: usize = 16;
        const MAX_LEAVES: usize = 256;

        VerifiableFunction::<DataCommitmentCircuit<NB_MAP_JOBS, BATCH_SIZE, MAX_LEAVES>>::entrypoint();
    } else if env_max_leaves == 4.to_string() {
        // Note: These constants can be tuned.
        const NB_MAP_JOBS: usize = 2;
        const BATCH_SIZE: usize = 2;
        const MAX_LEAVES: usize = 4;

        VerifiableFunction::<DataCommitmentCircuit<NB_MAP_JOBS, BATCH_SIZE, MAX_LEAVES>>::entrypoint();
    } else {
        panic!("MAX_LEAVES must be set to 1024, 256, or 4");
    }
}
