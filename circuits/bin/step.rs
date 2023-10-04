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
use std::env;

use celestia::input_data::InputDataFetcher;
use celestia::variables::*;
use celestia::verify::TendermintVerify;
use plonky2x::backend::circuit::Circuit;
use plonky2x::backend::function::VerifiableFunction;
use plonky2x::frontend::hint::simple::hint::Hint;
use plonky2x::frontend::uint::uint64::U64Variable;
use plonky2x::frontend::vars::{ValueStream, VariableStream};
use plonky2x::prelude::{
    ArrayVariable, BoolVariable, Bytes32Variable, CircuitBuilder, PlonkParameters,
};
use serde::{Deserialize, Serialize};
use tokio::runtime::Runtime; // TODO: re-export this instead of this path
#[derive(Debug, Clone, Serialize, Deserialize)]
struct StepOffchainInputs<const MAX_VALIDATOR_SET_SIZE: usize> {}

impl<const MAX_VALIDATOR_SET_SIZE: usize, L: PlonkParameters<D>, const D: usize> Hint<L, D>
    for StepOffchainInputs<MAX_VALIDATOR_SET_SIZE>
{
    fn hint(&self, input_stream: &mut ValueStream<L, D>, output_stream: &mut ValueStream<L, D>) {
        let prev_header_hash = input_stream.read_value::<Bytes32Variable>();
        let prev_block_number = input_stream.read_value::<U64Variable>();
        let mut data_fetcher = InputDataFetcher::new();
        let rt = Runtime::new().expect("failed to create tokio runtime");
        let result = rt.block_on(async {
            data_fetcher
                .get_step_inputs::<MAX_VALIDATOR_SET_SIZE, L::Field>(
                    prev_block_number,
                    prev_header_hash,
                )
                .await
        });
        output_stream.write_value::<Bytes32Variable>(result.0.into()); // next_header
        output_stream.write_value::<BoolVariable>(result.1); // round_present
        output_stream
            .write_value::<ArrayVariable<ValidatorVariable, MAX_VALIDATOR_SET_SIZE>>(result.2);
        output_stream.write_value::<HashInclusionProofVariable>(result.3);
        output_stream.write_value::<BlockIDInclusionProofVariable>(result.4);
        output_stream.write_value::<HashInclusionProofVariable>(result.5);
    }
}

struct StepCircuit<const MAX_VALIDATOR_SET_SIZE: usize> {
    _config: usize,
}

impl<const MAX_VALIDATOR_SET_SIZE: usize> Circuit for StepCircuit<MAX_VALIDATOR_SET_SIZE> {
    fn define<L: PlonkParameters<D>, const D: usize>(builder: &mut CircuitBuilder<L, D>) {
        let prev_header_hash = builder.evm_read::<Bytes32Variable>();
        let prev_block_number = builder.evm_read::<U64Variable>();
        let mut input_stream = VariableStream::new();
        input_stream.write(&prev_header_hash);
        input_stream.write(&prev_block_number);
        let output_stream = builder.hint(
            input_stream,
            StepOffchainInputs::<MAX_VALIDATOR_SET_SIZE> {},
        );
        let next_header = output_stream.read::<Bytes32Variable>(builder);
        let round_present = output_stream.read::<BoolVariable>(builder);
        let next_block_validators =
            output_stream.read::<ArrayVariable<ValidatorVariable, MAX_VALIDATOR_SET_SIZE>>(builder);
        let next_block_validators_hash_proof =
            output_stream.read::<HashInclusionProofVariable>(builder);
        let next_block_last_block_id_proof =
            output_stream.read::<BlockIDInclusionProofVariable>(builder);
        let prev_block_next_validators_hash_proof =
            output_stream.read::<HashInclusionProofVariable>(builder);

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

    fn register_generators<L: PlonkParameters<D>, const D: usize>(
        generator_registry: &mut plonky2x::prelude::HintRegistry<L, D>,
    ) where
        <<L as PlonkParameters<D>>::Config as plonky2::plonk::config::GenericConfig<D>>::Hasher:
            plonky2::plonk::config::AlgebraicHasher<L::Field>,
    {
        generator_registry.register_hint::<StepOffchainInputs<MAX_VALIDATOR_SET_SIZE>>();
    }
}

fn main() {
    let env_validator_set_size_max = env::var("VALIDATOR_SET_SIZE_MAX").unwrap_or(0.to_string());

    if env_validator_set_size_max == 128.to_string() {
        const VALIDATOR_SET_SIZE_MAX: usize = 128;
        VerifiableFunction::<StepCircuit<VALIDATOR_SET_SIZE_MAX>>::entrypoint();
    } else if env_validator_set_size_max == 4.to_string() {
        const VALIDATOR_SET_SIZE_MAX: usize = 4;
        VerifiableFunction::<StepCircuit<VALIDATOR_SET_SIZE_MAX>>::entrypoint();
    } else {
        panic!("VALIDATOR_SET_SIZE_MAX must be set to 128 or 4");
    }
}

#[cfg(test)]
mod tests {
    use std::env;

    use ethers::types::H256;
    use ethers::utils::hex;
    use plonky2x::backend::circuit::PublicInput;
    use plonky2x::prelude::{DefaultBuilder, GateRegistry, HintRegistry};

    use super::*;

    #[test]
    #[cfg_attr(feature = "ci", ignore)]
    fn test_step_serialization() {
        env::set_var("RUST_LOG", "debug");
        env_logger::try_init().unwrap_or_default();

        const MAX_VALIDATOR_SET_SIZE: usize = 2;
        let mut builder = DefaultBuilder::new();

        log::debug!("Defining circuit");
        StepCircuit::<MAX_VALIDATOR_SET_SIZE>::define(&mut builder);
        let circuit = builder.build();
        log::debug!("Done building circuit");

        let mut hint_registry = HintRegistry::new();
        let mut gate_registry = GateRegistry::new();
        StepCircuit::<MAX_VALIDATOR_SET_SIZE>::register_generators(&mut hint_registry);
        StepCircuit::<MAX_VALIDATOR_SET_SIZE>::register_gates(&mut gate_registry);

        circuit.test_serializers(&gate_registry, &hint_registry);
    }

    // TODO: this test should not run in CI because it uses the RPC instead of a fixture
    #[test]
    #[cfg_attr(feature = "ci", ignore)]
    fn test_step_circuit_with_input_bytes() {
        env::set_var("RUST_LOG", "debug");
        env_logger::try_init().unwrap_or_default();

        const MAX_VALIDATOR_SET_SIZE: usize = 4;
        // This is from block 3000
        let input_bytes = hex::decode(
            "a8512f18c34b70e1533cfd5aa04f251fcb0d7be56ec570051fbad9bdb9435e6a0000000000000bb8",
        )
        .unwrap();

        let mut builder = DefaultBuilder::new();

        log::debug!("Defining circuit");
        StepCircuit::<MAX_VALIDATOR_SET_SIZE>::define(&mut builder);

        log::debug!("Building circuit");
        let circuit = builder.build();
        log::debug!("Done building circuit");

        let input = PublicInput::Bytes(input_bytes);
        let (_proof, mut output) = circuit.prove(&input);
        let next_header = output.evm_read::<Bytes32Variable>();
        println!("next_header {:?}", next_header);
    }

    fn test_step_template<const MAX_VALIDATOR_SET_SIZE: usize>(
        block_height: u64,
        header: [u8; 32],
    ) {
        env::set_var("RUST_LOG", "debug");
        env_logger::try_init().unwrap_or_default();
        env::set_var("RPC_MOCHA_4", "fixture"); // Use fixture during testing

        let mut builder = DefaultBuilder::new();

        log::debug!("Defining circuit");
        StepCircuit::<MAX_VALIDATOR_SET_SIZE>::define(&mut builder);

        log::debug!("Building circuit");
        let circuit = builder.build();
        log::debug!("Done building circuit");

        let mut input = circuit.input();
        input.evm_write::<Bytes32Variable>(H256::from_slice(header.as_slice()));
        input.evm_write::<U64Variable>(block_height);

        log::debug!("Generating proof");
        let (proof, mut output) = circuit.prove(&input);
        log::debug!("Done generating proof");

        circuit.verify(&proof, &input, &output);
        let next_header = output.evm_read::<Bytes32Variable>();
        println!("next_header {:?}", next_header);
    }

    #[test]
    #[cfg_attr(feature = "ci", ignore)]
    fn test_step_small() {
        const MAX_VALIDATOR_SET_SIZE: usize = 2;
        let header: [u8; 32] =
            hex::decode("A0123D5E4B8B8888A61F931EE2252D83568B97C223E0ECA9795B29B8BD8CBA2D")
                .unwrap()
                .try_into()
                .unwrap();
        let height = 10000u64;
        test_step_template::<MAX_VALIDATOR_SET_SIZE>(height, header);
    }

    #[test]
    #[cfg_attr(feature = "ci", ignore)]
    fn test_step_with_dummy() {
        const MAX_VALIDATOR_SET_SIZE: usize = 4;
        let header: [u8; 32] =
            hex::decode("E2BA1B86926925A69C2FCC32E5178E7E6653D386C956BB975142FA73211A9444")
                .unwrap()
                .try_into()
                .unwrap();
        let height = 10500u64;
        test_step_template::<MAX_VALIDATOR_SET_SIZE>(height, header);
    }

    #[test]
    #[cfg_attr(feature = "ci", ignore)]
    fn test_step_large() {
        const MAX_VALIDATOR_SET_SIZE: usize = 128;
        let header: [u8; 32] =
            hex::decode("DA1C195D8A0E74E50A8C6ABE24B63024F9865624609726C9954D713E21509E27")
                .unwrap()
                .try_into()
                .unwrap();
        let height = 157000u64;
        test_step_template::<MAX_VALIDATOR_SET_SIZE>(height, header);
    }
}
