use async_trait::async_trait;
use celestia::input::utils::convert_to_h256;
use celestia::input::InputDataFetcher;
use ethers::types::H256;
use plonky2x::backend::circuit::Circuit;
use plonky2x::frontend::hint::asynchronous::hint::AsyncHint;
use plonky2x::frontend::uint::uint64::U64Variable;
use plonky2x::frontend::vars::VariableStream;
use plonky2x::prelude::{Bytes32Variable, CircuitBuilder, PlonkParameters, ValueStream};
use serde::{Deserialize, Serialize};

use crate::input::DataCommitmentInputs;
use crate::subchain_verification::SubChainVerifier;
use crate::vars::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataCommitmentOffchainInputs<const MAX_LEAVES: usize> {}

#[async_trait]
impl<const MAX_LEAVES: usize, L: PlonkParameters<D>, const D: usize> AsyncHint<L, D>
    for DataCommitmentOffchainInputs<MAX_LEAVES>
{
    async fn hint(
        &self,
        input_stream: &mut ValueStream<L, D>,
        output_stream: &mut ValueStream<L, D>,
    ) {
        let start_block = input_stream.read_value::<U64Variable>();
        let end_block = input_stream.read_value::<U64Variable>();
        let max_leaves = input_stream.read_value::<U64Variable>();

        let mut data_fetcher = InputDataFetcher::new();

        let result = data_fetcher
            .get_data_commitment_inputs::<L::Field>(start_block, end_block, max_leaves)
            .await;

        let data_comm_proof = DataCommitmentProofValueType {
            data_hashes: convert_to_h256(result.2),
            start_block_height: start_block,
            start_header: H256(result.0),
            end_block_height: end_block,
            end_header: H256(result.1),
            data_hash_proofs: result.3,
            prev_header_proofs: result.4,
        };
        // Write the inputs to the data commitment circuit.
        output_stream.write_value::<DataCommitmentProofVariable<MAX_LEAVES>>(data_comm_proof);
        // Write the expected data commitment.
        output_stream.write_value::<Bytes32Variable>(H256(result.5));
    }
}

#[derive(Debug, Clone)]
pub struct DataCommitmentCircuit<
    const NUM_MAP_JOBS: usize,
    const BATCH_SIZE: usize,
    const MAX_LEAVES: usize,
> {
    _config: usize,
}

impl<const NUM_MAP_JOBS: usize, const BATCH_SIZE: usize, const MAX_LEAVES: usize> Circuit
    for DataCommitmentCircuit<NUM_MAP_JOBS, BATCH_SIZE, MAX_LEAVES>
{
    fn define<L: PlonkParameters<D>, const D: usize>(builder: &mut CircuitBuilder<L, D>) where <<L as plonky2x::prelude::PlonkParameters<D>>::Config as plonky2::plonk::config::GenericConfig<D>>::Hasher: plonky2::plonk::config::AlgebraicHasher<<L as plonky2x::prelude::PlonkParameters<D>>::Field>{
        assert_eq!(NUM_MAP_JOBS * BATCH_SIZE, MAX_LEAVES);

        let start_block_number = builder.evm_read::<U64Variable>();
        let start_header_hash = builder.evm_read::<Bytes32Variable>();
        let end_block_number = builder.evm_read::<U64Variable>();
        let end_header_hash = builder.evm_read::<Bytes32Variable>();

        let mut input_stream = VariableStream::new();
        input_stream.write(&start_block_number);
        input_stream.write(&end_block_number);
        let max_leaves = &builder.constant::<U64Variable>(MAX_LEAVES as u64);
        input_stream.write(max_leaves);

        let output_stream =
            builder.async_hint(input_stream, DataCommitmentOffchainInputs::<MAX_LEAVES> {});

        let _ = output_stream.read::<DataCommitmentProofVariable<MAX_LEAVES>>(builder);
        let expected_data_commitment = output_stream.read::<Bytes32Variable>(builder);

        let data_commitment = builder.verify_subchain::<Self, NUM_MAP_JOBS, BATCH_SIZE>(
            start_block_number,
            start_header_hash,
            end_block_number,
            end_header_hash,
        );

        // Note: Don't need this assert, it's only a sanity check.
        builder.assert_is_equal(data_commitment, expected_data_commitment);

        builder.evm_write(data_commitment);
    }

    fn register_generators<L: PlonkParameters<D>, const D: usize>(
        generator_registry: &mut plonky2x::prelude::HintRegistry<L, D>,
    ) where
        <<L as PlonkParameters<D>>::Config as plonky2::plonk::config::GenericConfig<D>>::Hasher:
            plonky2::plonk::config::AlgebraicHasher<L::Field>,
    {
        generator_registry.register_async_hint::<DataCommitmentOffchainInputs<MAX_LEAVES>>();
    }
}

#[cfg(test)]
mod tests {
    use std::env;

    use ethers::types::H256;
    use plonky2x::prelude::{DefaultBuilder, GateRegistry, HintRegistry};
    use subtle_encoding::hex;

    use super::*;

    #[test]
    #[cfg_attr(feature = "ci", ignore)]
    fn test_data_commitment_serialization() {
        env::set_var("RUST_LOG", "debug");
        env_logger::try_init().unwrap_or_default();

        const MAX_LEAVES: usize = 2;
        const NUM_MAP_JOBS: usize = 1;
        const BATCH_SIZE: usize = 2;
        let mut builder = DefaultBuilder::new();

        log::debug!("Defining circuit");
        DataCommitmentCircuit::<NUM_MAP_JOBS, BATCH_SIZE, MAX_LEAVES>::define(&mut builder);
        let circuit = builder.build();
        log::debug!("Done building circuit");

        let mut hint_registry = HintRegistry::new();
        let mut gate_registry = GateRegistry::new();
        DataCommitmentCircuit::<NUM_MAP_JOBS, BATCH_SIZE, MAX_LEAVES>::register_generators(
            &mut hint_registry,
        );
        DataCommitmentCircuit::<NUM_MAP_JOBS, BATCH_SIZE, MAX_LEAVES>::register_gates(
            &mut gate_registry,
        );

        circuit.test_serializers(&gate_registry, &hint_registry);
    }

    fn test_data_commitment_template<
        const NUM_MAP_JOBS: usize,
        const BATCH_SIZE: usize,
        const MAX_LEAVES: usize,
    >(
        start_block: usize,
        start_header_hash: [u8; 32],
        end_block: usize,
        end_header_hash: [u8; 32],
    ) {
        env::set_var("RUST_LOG", "debug");
        env_logger::try_init().unwrap_or_default();

        // env::set_var("RPC_MOCHA_4", "fixture"); // Use fixture during testing

        let mut builder = DefaultBuilder::new();

        log::debug!("Defining circuit");
        DataCommitmentCircuit::<NUM_MAP_JOBS, BATCH_SIZE, MAX_LEAVES>::define(&mut builder);

        log::debug!("Building circuit");
        let circuit = builder.build();
        log::debug!("Done building circuit");

        let mut input = circuit.input();

        input.evm_write::<U64Variable>(start_block as u64);
        input.evm_write::<Bytes32Variable>(H256::from_slice(start_header_hash.as_slice()));
        input.evm_write::<U64Variable>(end_block as u64);
        input.evm_write::<Bytes32Variable>(H256::from_slice(end_header_hash.as_slice()));

        log::debug!("Generating proof");

        let rt = tokio::runtime::Runtime::new().unwrap();
        let (proof, mut output) = rt.block_on(async { circuit.prove_async(&input).await });

        log::debug!("Done generating proof");

        circuit.verify(&proof, &input, &output);
        let data_commitment = output.evm_read::<Bytes32Variable>();
        println!("data_commitment {:?}", data_commitment);
    }

    #[test]
    #[cfg_attr(feature = "ci", ignore)]
    fn test_data_commitment_small() {
        // Test variable length NUM_BLOCKS.
        const MAX_LEAVES: usize = 8;
        const NUM_MAP_JOBS: usize = 1;
        const BATCH_SIZE: usize = 8;

        let start_block = 10000u64;
        let start_header_hash =
            hex::decode_upper("A0123D5E4B8B8888A61F931EE2252D83568B97C223E0ECA9795B29B8BD8CBA2D")
                .unwrap();
        let end_block = 10004u64;
        let end_header_hash =
            hex::decode_upper("FCDA37FA6306C77737DD911E6101B612E2DBD837F29ED4F4E1C30919FBAC9D05")
                .unwrap();

        test_data_commitment_template::<NUM_MAP_JOBS, BATCH_SIZE, MAX_LEAVES>(
            start_block as usize,
            start_header_hash.as_slice().try_into().unwrap(),
            end_block as usize,
            end_header_hash.as_slice().try_into().unwrap(),
        );
    }

    #[test]
    #[cfg_attr(feature = "ci", ignore)]
    fn test_data_commitment_large() {
        // Test variable length NUM_BLOCKS.
        const MAX_LEAVES: usize = 1024;
        // Note: These can be tuned.
        const NUM_MAP_JOBS: usize = 1;
        const BATCH_SIZE: usize = 1024;

        let start_block = 10000u64;
        let start_header_hash =
            hex::decode_upper("A0123D5E4B8B8888A61F931EE2252D83568B97C223E0ECA9795B29B8BD8CBA2D")
                .unwrap();
        let end_block = 10004u64;
        let end_header_hash =
            hex::decode_upper("FCDA37FA6306C77737DD911E6101B612E2DBD837F29ED4F4E1C30919FBAC9D05")
                .unwrap();

        test_data_commitment_template::<NUM_MAP_JOBS, BATCH_SIZE, MAX_LEAVES>(
            start_block as usize,
            start_header_hash.as_slice().try_into().unwrap(),
            end_block as usize,
            end_header_hash.as_slice().try_into().unwrap(),
        );
    }

    #[test]
    #[cfg_attr(feature = "ci", ignore)]
    fn test_data_commitment_smart_contract() {
        // Test variable length NUM_BLOCKS.
        const MAX_LEAVES: usize = 256;
        // Note: These can be tuned.
        const NUM_MAP_JOBS: usize = 1;
        const BATCH_SIZE: usize = 256;

        let start_block = 10000u64;
        let start_header_hash =
            hex::decode_upper("A0123D5E4B8B8888A61F931EE2252D83568B97C223E0ECA9795B29B8BD8CBA2D")
                .unwrap();
        let end_block = 10004u64;
        let end_header_hash =
            hex::decode_upper("FCDA37FA6306C77737DD911E6101B612E2DBD837F29ED4F4E1C30919FBAC9D05")
                .unwrap();

        test_data_commitment_template::<NUM_MAP_JOBS, BATCH_SIZE, MAX_LEAVES>(
            start_block as usize,
            start_header_hash.as_slice().try_into().unwrap(),
            end_block as usize,
            end_header_hash.as_slice().try_into().unwrap(),
        );
    }
}
