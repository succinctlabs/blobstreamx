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
use blobstreamx::data_commitment::DataCommitmentCircuit;
use plonky2x::backend::function::Plonky2xFunction;

fn main() {
    // Celestia's maxmimum data commitment size is 1000: https://github.com/celestiaorg/celestia-core/blob/6933af1ead0ddf4a8c7516690e3674c6cdfa7bd8/pkg/consts/consts.go#L44.
    const NB_MAP_JOBS: usize = 64;
    const BATCH_SIZE: usize = 16;
    DataCommitmentCircuit::<NB_MAP_JOBS, BATCH_SIZE>::entrypoint();
}
