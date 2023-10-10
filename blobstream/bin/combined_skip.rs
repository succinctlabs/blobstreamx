//! To build the binary:
//!
//!     `cargo build --release --bin combined_skip`
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

use blobstream::combined_skip::CombinedSkipCircuit;
use plonky2x::backend::function::VerifiableFunction;

fn main() {
    // Celestia's maxmimum data commitment size is 1000: https://github.com/celestiaorg/celestia-core/blob/6933af1ead0ddf4a8c7516690e3674c6cdfa7bd8/pkg/consts/consts.go#L44.
    let env_validator_set_size_max = env::var("VALIDATOR_SET_SIZE_MAX").unwrap_or(0.to_string());

    if env_validator_set_size_max == 128.to_string() {
        const VALIDATOR_SET_SIZE_MAX: usize = 128;
        const NB_MAP_JOBS: usize = 16;
        const BATCH_SIZE: usize = 64;
        VerifiableFunction::<CombinedSkipCircuit<VALIDATOR_SET_SIZE_MAX, NB_MAP_JOBS, BATCH_SIZE>>::entrypoint();
    } else if env_validator_set_size_max == 32.to_string() {
        const VALIDATOR_SET_SIZE_MAX: usize = 32;
        const NB_MAP_JOBS: usize = 8;
        const BATCH_SIZE: usize = 32;
        VerifiableFunction::<CombinedSkipCircuit<VALIDATOR_SET_SIZE_MAX, NB_MAP_JOBS, BATCH_SIZE>>::entrypoint();
    } else if env_validator_set_size_max == 4.to_string() {
        const VALIDATOR_SET_SIZE_MAX: usize = 4;
        const NB_MAP_JOBS: usize = 2;
        const BATCH_SIZE: usize = 2;
        VerifiableFunction::<CombinedSkipCircuit<VALIDATOR_SET_SIZE_MAX, NB_MAP_JOBS, BATCH_SIZE>>::entrypoint();
    } else {
        panic!("VALIDATOR_SET_SIZE_MAX must be set to 128, 32, or 4");
    }
}
