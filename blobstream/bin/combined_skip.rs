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
use plonky2x::backend::function::Plonky2xFunction;

fn main() {
    // Celestia's maxmimum data commitment size is 1000: https://github.com/celestiaorg/celestia-core/blob/6933af1ead0ddf4a8c7516690e3674c6cdfa7bd8/pkg/consts/consts.go#L44.
    let env_validator_set_size_max = env::var("VALIDATOR_SET_SIZE_MAX").unwrap_or(0.to_string());

    if env_validator_set_size_max == 128.to_string() {
        const MAX_LEAVES: usize = 1024;
        const VALIDATOR_SET_SIZE_MAX: usize = 128;
        CombinedSkipCircuit::<MAX_LEAVES, VALIDATOR_SET_SIZE_MAX>::entrypoint();
    } else if env_validator_set_size_max == 32.to_string() {
        const MAX_LEAVES: usize = 256;
        const VALIDATOR_SET_SIZE_MAX: usize = 32;
        CombinedSkipCircuit::<MAX_LEAVES, VALIDATOR_SET_SIZE_MAX>::entrypoint();
    } else if env_validator_set_size_max == 4.to_string() {
        const MAX_LEAVES: usize = 32;
        const VALIDATOR_SET_SIZE_MAX: usize = 4;
        CombinedSkipCircuit::<MAX_LEAVES, VALIDATOR_SET_SIZE_MAX>::entrypoint();
    } else {
        panic!("VALIDATOR_SET_SIZE_MAX must be set to 128, 32, or 4");
    }
}
