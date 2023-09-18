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
//!
//!
//!
use tokio::runtime::Runtime;

use plonky2x::backend::circuit::Circuit;
use plonky2x::backend::function::VerifiableFunction;
use plonky2x::frontend::generator::hint::Hint;
use plonky2x::frontend::uint::uint64::U64Variable;
use plonky2x::frontend::vars::{ByteVariable, ValueStream};
use plonky2x::prelude::{
    ArrayVariable, Bytes32Variable, CircuitBuilder, GoldilocksField, PlonkParameters,
};
use serde::{Deserialize, Serialize};

use celestia::input_data::{InputDataFetcher, InputDataMode};
use celestia::utils::HEADER_PROOF_DEPTH;
use celestia::verify::{
    BlockIDInclusionProofVariable, HashInclusionProofVariable, TendermintVerify, ValidatorVariable,
};
use plonky2x::frontend::ecc::ed25519::curve::ed25519::Ed25519;
use plonky2x::frontend::vars::VariableStream; // TODO: re-export this instead of this path
#[derive(Debug, Clone, Serialize, Deserialize)]
struct StepOffchainInputs<const MAX_VALIDATOR_SET_SIZE: usize> {
    amount: u8,
}

impl<const MAX_VALIDATOR_SET_SIZE: usize, L: PlonkParameters<D>, const D: usize> Hint<L, D>
    for StepOffchainInputs<MAX_VALIDATOR_SET_SIZE>
{
    fn hint(&self, input_stream: &mut ValueStream<L, D>, output_stream: &mut ValueStream<L, D>) {
        let prev_header_hash = input_stream.read_value::<Bytes32Variable>();
        let prev_block_number = input_stream.read_value::<U64Variable>();
        let mut data_fetcher = InputDataFetcher::new(InputDataMode::Rpc("".to_string()));

        let rt = Runtime::new().expect("failed to create tokio runtime");
        let result = rt.block_on(async {
            data_fetcher
                .get_step_inputs::<MAX_VALIDATOR_SET_SIZE, L::Field>(
                    prev_block_number.as_u64(),
                    prev_header_hash,
                )
                .await
        });

        output_stream.write_value::<Bytes32Variable>(result.0.into()); // next_header
        output_stream
            .write_value::<ArrayVariable<ValidatorVariable<Ed25519>, MAX_VALIDATOR_SET_SIZE>>(
                result.1,
            );
        output_stream.write_value::<HashInclusionProofVariable<HEADER_PROOF_DEPTH>>(
            result.2.to_hash_value_type(),
        );
        output_stream.write_value::<BlockIDInclusionProofVariable<HEADER_PROOF_DEPTH>>(
            result.3.to_block_id_value_type(),
        );
        output_stream.write_value::<HashInclusionProofVariable<HEADER_PROOF_DEPTH>>(
            result.4.to_hash_value_type(),
        );
    }
}

struct StepCircuit<const MAX_VALIDATOR_SET_SIZE: usize> {}

impl<const MAX_VALIDATOR_SET_SIZE: usize> Circuit for StepCircuit<MAX_VALIDATOR_SET_SIZE> {
    fn define<L: PlonkParameters<D>, const D: usize>(builder: &mut CircuitBuilder<L, D>) {
        let prev_header_hash = builder.evm_read::<Bytes32Variable>();
        let prev_block_number = builder.evm_read::<U64Variable>();
        let mut input_stream = VariableStream::new();
        input_stream.write(&prev_header_hash);
        input_stream.write(&prev_block_number);
        let output_stream = builder.hint(
            input_stream,
            StepOffchainInputs::<MAX_VALIDATOR_SET_SIZE> { amount: 1u8 },
        );
        let next_header = output_stream.read::<Bytes32Variable>(builder);
        let next_block_validators = output_stream
            .read::<ArrayVariable<ValidatorVariable<Ed25519>, MAX_VALIDATOR_SET_SIZE>>(builder);
        let next_block_validators_hash_proof =
            output_stream.read::<HashInclusionProofVariable<HEADER_PROOF_DEPTH>>(builder);
        let next_block_last_block_id_proof =
            output_stream.read::<BlockIDInclusionProofVariable<HEADER_PROOF_DEPTH>>(builder);
        let prev_block_next_validators_hash_proof =
            output_stream.read::<HashInclusionProofVariable<HEADER_PROOF_DEPTH>>(builder);

        let round_present = builder._true();
        builder.step(
            &next_block_validators,
            &next_header,
            &prev_header_hash,
            &next_block_validators_hash_proof,
            &prev_block_next_validators_hash_proof,
            &next_block_last_block_id_proof,
            &round_present,
        );
        builder.evm_write(next_header);
    }
}

fn main() {
    const MAX_VALIDATOR_SET_SIZE: usize = 128;
    VerifiableFunction::<StepCircuit<MAX_VALIDATOR_SET_SIZE>>::entrypoint();
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use plonky2x::prelude::{DefaultBuilder, GoldilocksField, PoseidonGoldilocksConfig};

    use super::*;

    const D: usize = 2;

    #[test]
    fn test_circuit_function_evm() {
        const MAX_VALIDATOR_SET_SIZE: usize = 128;
        let mut builder = DefaultBuilder::new();
        StepCircuit::<MAX_VALIDATOR_SET_SIZE>::define(&mut builder);
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
