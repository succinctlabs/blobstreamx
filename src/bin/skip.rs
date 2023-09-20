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
use plonky2x::backend::circuit::Circuit;
use plonky2x::backend::function::VerifiableFunction;
use plonky2x::frontend::generator::simple::hint::Hint;
use plonky2x::frontend::uint::uint64::U64Variable;
use plonky2x::frontend::vars::ValueStream;
use plonky2x::prelude::{
    ArrayVariable, BoolVariable, Bytes32Variable, CircuitBuilder, PlonkParameters,
};
use serde::{Deserialize, Serialize};
use tokio::runtime::Runtime;

use celestia::consts::HEADER_PROOF_DEPTH;
use celestia::input_data::{InputDataFetcher, InputDataMode};
use celestia::verify::{
    HashInclusionProofVariable, TendermintVerify, ValidatorHashFieldVariable, ValidatorVariable,
};
use plonky2x::frontend::ecc::ed25519::curve::ed25519::Ed25519;
use plonky2x::frontend::vars::VariableStream; // TODO: re-export this instead of this path
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SkipOffchainInputs<const MAX_VALIDATOR_SET_SIZE: usize> {
    amount: u8,
}

impl<const MAX_VALIDATOR_SET_SIZE: usize, L: PlonkParameters<D>, const D: usize> Hint<L, D>
    for SkipOffchainInputs<MAX_VALIDATOR_SET_SIZE>
{
    fn hint(&self, input_stream: &mut ValueStream<L, D>, output_stream: &mut ValueStream<L, D>) {
        let trusted_header_hash = input_stream.read_value::<Bytes32Variable>();
        let trusted_block = input_stream.read_value::<U64Variable>();
        let target_block = input_stream.read_value::<U64Variable>();
        let mut data_fetcher = InputDataFetcher::new(InputDataMode::Fixture);
        let rt = Runtime::new().expect("failed to create tokio runtime");
        let result = rt.block_on(async {
            data_fetcher
                .get_skip_inputs::<MAX_VALIDATOR_SET_SIZE, L::Field>(
                    trusted_block.as_u64(),
                    trusted_header_hash,
                    target_block.as_u64(),
                )
                .await
        });
        output_stream
            .write_value::<ArrayVariable<ValidatorVariable<Ed25519>, MAX_VALIDATOR_SET_SIZE>>(
                result.0,
            );
        output_stream.write_value::<Bytes32Variable>(result.1.into()); // target_header
        output_stream.write_value::<BoolVariable>(result.2); // round_present
        output_stream.write_value::<HashInclusionProofVariable<HEADER_PROOF_DEPTH>>(
            result.3.to_hash_value_type(),
        );
        output_stream.write_value::<Bytes32Variable>(result.4.into()); // trusted_header
        output_stream.write_value::<HashInclusionProofVariable<HEADER_PROOF_DEPTH>>(
            result.5.to_hash_value_type(),
        );
        output_stream.write_value::<ArrayVariable<ValidatorHashFieldVariable<Ed25519>, MAX_VALIDATOR_SET_SIZE>>(
            result.6
        );
    }
}

struct StepCircuit<const MAX_VALIDATOR_SET_SIZE: usize> {
    _config: usize,
}

impl<const MAX_VALIDATOR_SET_SIZE: usize> Circuit for StepCircuit<MAX_VALIDATOR_SET_SIZE> {
    fn define<L: PlonkParameters<D>, const D: usize>(builder: &mut CircuitBuilder<L, D>) {
        let trusted_header_hash = builder.evm_read::<Bytes32Variable>();
        let trusted_block = builder.evm_read::<U64Variable>();
        let target_block = builder.evm_read::<U64Variable>();

        let mut input_stream = VariableStream::new();
        input_stream.write(&trusted_header_hash);
        input_stream.write(&trusted_block);
        input_stream.write(&target_block);
        let output_stream = builder.hint(
            input_stream,
            SkipOffchainInputs::<MAX_VALIDATOR_SET_SIZE> { amount: 1u8 },
        );
        let target_block_validators = output_stream
            .read::<ArrayVariable<ValidatorVariable<Ed25519>, MAX_VALIDATOR_SET_SIZE>>(builder);
        let target_header = output_stream.read::<Bytes32Variable>(builder);
        let round_present = output_stream.read::<BoolVariable>(builder);
        let target_header_validators_hash_proof =
            output_stream.read::<HashInclusionProofVariable<HEADER_PROOF_DEPTH>>(builder);
        let trusted_header = output_stream.read::<Bytes32Variable>(builder);
        let trusted_header_validators_hash_proof =
            output_stream.read::<HashInclusionProofVariable<HEADER_PROOF_DEPTH>>(builder);
        let trusted_header_validators_hash_fields = output_stream
            .read::<ArrayVariable<ValidatorHashFieldVariable<Ed25519>, MAX_VALIDATOR_SET_SIZE>>(
                builder,
            );

        builder.skip(
            &target_block_validators,
            &target_header,
            &target_header_validators_hash_proof,
            &round_present,
            trusted_header,
            &trusted_header_validators_hash_proof,
            &trusted_header_validators_hash_fields,
        );
        builder.evm_write(target_header);
    }
}

fn main() {
    const MAX_VALIDATOR_SET_SIZE: usize = 128;
    // let step_circuit = StepCircuit::<MAX_VALIDATOR_SET_SIZE> { config: 0 };
    VerifiableFunction::<StepCircuit<MAX_VALIDATOR_SET_SIZE>>::entrypoint();
}

#[cfg(test)]
mod tests {
    use ethers::types::H256;
    use std::env;

    use plonky2x::prelude::DefaultBuilder;

    use super::*;

    #[test]
    fn test_circuit_function_skip() {
        env::set_var("RUST_LOG", "debug");
        env_logger::try_init().unwrap_or_default();

        const MAX_VALIDATOR_SET_SIZE: usize = 16;
        let mut builder = DefaultBuilder::new();

        log::debug!("Defining circuit");
        StepCircuit::<MAX_VALIDATOR_SET_SIZE>::define(&mut builder);

        log::debug!("Building circuit");
        let circuit = builder.build();
        log::debug!("Done building circuit");

        let mut input = circuit.input();
        let trusted_header: [u8; 32] = [
            101, 148, 196, 246, 245, 248, 99, 125, 20, 181, 200, 0, 157, 159, 211, 222, 105, 149,
            108, 221, 97, 143, 205, 106, 162, 68, 113, 97, 5, 29, 183, 162,
        ];
        let trusted_block = 11000u64;
        let target_block = 11105u64; // mimics test_skip_small
        input.evm_write::<Bytes32Variable>(H256::from_slice(trusted_header.as_slice()));
        input.evm_write::<U64Variable>(trusted_block.into());
        input.evm_write::<U64Variable>(target_block.into());

        log::debug!("Generating proof");
        let (proof, mut output) = circuit.prove(&input);
        log::debug!("Done generating proof");

        circuit.verify(&proof, &input, &output);
        let target_header = output.evm_read::<Bytes32Variable>();
        println!("target_header {:?}", target_header);
    }
}
