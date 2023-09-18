//! To build the binary:
//!
//!     `cargo build --release --bin step`
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

use plonky2x::backend::circuit::Circuit;
use plonky2x::backend::function::VerifiableFunction;
use plonky2x::frontend::generator::hint::Hint;
use plonky2x::frontend::vars::{ByteVariable, ValueStream};
use plonky2x::prelude::{Bytes32Variable, CircuitBuilder, PlonkParameters};
use serde::{Deserialize, Serialize};

// use crate::input_data::InputDataFetcher;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StepOffchainInputs {
    amount: u8,
}

impl<L: PlonkParameters<D>, const D: usize> Hint<L, D> for StepOffchainInputs {
    fn hint(&self, input_stream: &mut ValueStream<L, D>, output_stream: &mut ValueStream<L, D>) {
        let prev_header = input_stream.read_value::<Bytes32Variable>();
        // Use the RPC to get the next_header from the previous header and all the merkle proofs

        // output_stream.write_value::<Bytes32Variable>(header);
    }
}

struct StepCircuit {}

impl Circuit for StepCircuit {
    fn define<L: PlonkParameters<D>, const D: usize>(builder: &mut CircuitBuilder<L, D>) {
        let prev_header = builder.evm_read::<Bytes32Variable>();
        let header = builder.init::<Bytes32Variable>();
        builder.evm_write(header);
    }
}

fn main() {
    VerifiableFunction::<StepCircuit>::entrypoint();
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use plonky2x::prelude::{DefaultBuilder, GoldilocksField, PoseidonGoldilocksConfig};

    use super::*;

    const D: usize = 2;

    #[test]
    fn test_circuit_function_evm() {
        let mut builder = DefaultBuilder::new();
        StepCircuit::define(&mut builder);
        let circuit = builder.build();
        let mut input = circuit.input();
        input.evm_write::<ByteVariable>(0u8);
        input.evm_write::<ByteVariable>(1u8);
        let (proof, mut output) = circuit.prove(&input);
        circuit.verify(&proof, &input, &output);
        let xor = output.evm_read::<ByteVariable>();
        assert_eq!(xor, 1u8);
    }

    #[test]
    fn test_circuit_function_evm_input_json() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let path = format!(
            "{}/examples/circuit_function_evm_input.json",
            root.display()
        );
        todo!();
        // Circuit::test::<F, C, D>(path);
    }
}
