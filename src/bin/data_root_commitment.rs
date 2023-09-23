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
use celestia::commitment::DataCommitment;
use celestia::input_data::utils::convert_to_h256;
use celestia::variables::{DataCommitmentProofValueType, DataCommitmentProofVariable};
use ethers::types::H256;
use plonky2x::backend::circuit::Circuit;
use plonky2x::backend::function::VerifiableFunction;
use plonky2x::frontend::generator::simple::hint::Hint;
use plonky2x::frontend::uint::uint64::U64Variable;
use plonky2x::frontend::vars::ValueStream;
use plonky2x::prelude::{Bytes32Variable, CircuitBuilder, PlonkParameters};
use serde::{Deserialize, Serialize};
use tokio::runtime::Runtime;

use celestia::input_data::{InputDataFetcher, InputDataMode};
use plonky2x::frontend::vars::VariableStream; // TODO: re-export this instead of this path
#[derive(Debug, Clone, Serialize, Deserialize)]
struct DataCommitmentOffchainInputs<const WINDOW_SIZE: usize, const NUM_LEAVES: usize> {
    amount: u8,
}

impl<const WINDOW_SIZE: usize, const NUM_LEAVES: usize, L: PlonkParameters<D>, const D: usize>
    Hint<L, D> for DataCommitmentOffchainInputs<WINDOW_SIZE, NUM_LEAVES>
{
    fn hint(&self, input_stream: &mut ValueStream<L, D>, output_stream: &mut ValueStream<L, D>) {
        let start_block = input_stream.read_value::<U64Variable>();
        let start_header_hash = input_stream.read_value::<Bytes32Variable>();
        let end_block = input_stream.read_value::<U64Variable>();
        let end_header_hash = input_stream.read_value::<Bytes32Variable>();

        let mut data_fetcher = InputDataFetcher::new(InputDataMode::Fixture);

        let rt = Runtime::new().expect("failed to create tokio runtime");
        let result = rt.block_on(async {
            data_fetcher
                .get_data_commitment_inputs::<WINDOW_SIZE, NUM_LEAVES, L::Field>(
                    start_block.as_u64(),
                    start_header_hash,
                    end_block.as_u64(),
                    end_header_hash,
                )
                .await
        });
        let data_comm_proof = DataCommitmentProofValueType {
            data_hashes: convert_to_h256(result.0),
            start_header: H256(result.1),
            start_block_height: result.2,
            end_header: H256(result.3),
            end_block_height: result.4,
            data_hash_proofs: result.5,
            prev_header_proofs: result.6,
        };
        output_stream.write_value::<DataCommitmentProofVariable<WINDOW_SIZE>>(data_comm_proof);
        output_stream.write_value::<Bytes32Variable>(H256(result.7));
    }
}

struct DataCommitmentCircuit<const WINDOW_SIZE: usize, const NUM_LEAVES: usize> {
    _config: usize,
}

impl<const WINDOW_SIZE: usize, const NUM_LEAVES: usize> Circuit
    for DataCommitmentCircuit<WINDOW_SIZE, NUM_LEAVES>
{
    fn define<L: PlonkParameters<D>, const D: usize>(builder: &mut CircuitBuilder<L, D>) {
        let start_block_number = builder.evm_read::<U64Variable>();
        let start_header_hash = builder.evm_read::<Bytes32Variable>();
        let end_block_number = builder.evm_read::<U64Variable>();
        let end_header_hash = builder.evm_read::<Bytes32Variable>();

        let mut input_stream = VariableStream::new();
        input_stream.write(&start_block_number);
        input_stream.write(&start_header_hash);
        input_stream.write(&end_block_number);
        input_stream.write(&end_header_hash);
        let output_stream = builder.hint(
            input_stream,
            DataCommitmentOffchainInputs::<WINDOW_SIZE, NUM_LEAVES> { amount: 1u8 },
        );
        let data_comm_proof =
            output_stream.read::<DataCommitmentProofVariable<WINDOW_SIZE>>(builder);

        let expected_data_commitment = output_stream.read::<Bytes32Variable>(builder);

        let data_commitment =
            builder.prove_data_commitment::<WINDOW_SIZE, NUM_LEAVES>(data_comm_proof);

        builder.assert_is_equal(data_commitment, expected_data_commitment);

        builder.evm_write(data_commitment);
    }
}

fn main() {
    const WINDOW_SIZE: usize = 400;
    const NUM_LEAVES: usize = 512;
    VerifiableFunction::<DataCommitmentCircuit<WINDOW_SIZE, NUM_LEAVES>>::entrypoint();
}

#[cfg(test)]
mod tests {
    use std::env;

    use plonky2x::prelude::DefaultBuilder;
    use subtle_encoding::hex;

    use super::*;

    #[test]
    #[cfg_attr(feature = "ci", ignore)]
    fn test_circuit_function_data_commitment() {
        env::set_var("RUST_LOG", "debug");
        env_logger::try_init().unwrap_or_default();

        const WINDOW_SIZE: usize = 4;
        const NUM_LEAVES: usize = 4;
        let mut builder = DefaultBuilder::new();

        log::debug!("Defining circuit");
        DataCommitmentCircuit::<WINDOW_SIZE, NUM_LEAVES>::define(&mut builder);

        log::debug!("Building circuit");
        let circuit = builder.build();
        log::debug!("Done building circuit");

        let mut input = circuit.input();

        let start_block = 10000u64;
        let start_header_hash =
            hex::decode_upper("A0123D5E4B8B8888A61F931EE2252D83568B97C223E0ECA9795B29B8BD8CBA2D")
                .unwrap();
        let end_block = start_block + WINDOW_SIZE as u64;
        let end_header_hash =
            hex::decode_upper("FCDA37FA6306C77737DD911E6101B612E2DBD837F29ED4F4E1C30919FBAC9D05")
                .unwrap();

        input.evm_write::<U64Variable>(start_block.into());
        input.evm_write::<Bytes32Variable>(H256::from_slice(start_header_hash.as_slice()));
        input.evm_write::<U64Variable>(end_block.into());
        input.evm_write::<Bytes32Variable>(H256::from_slice(end_header_hash.as_slice()));

        log::debug!("Generating proof");
        let (proof, mut output) = circuit.prove(&input);
        log::debug!("Done generating proof");

        circuit.verify(&proof, &input, &output);
        let data_commitment = output.evm_read::<Bytes32Variable>();
        println!("data_commitment {:?}", data_commitment);
    }
}
