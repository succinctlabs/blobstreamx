use plonky2x::backend::circuit::Circuit;
use plonky2x::frontend::uint::uint64::U64Variable;
use plonky2x::prelude::{Bytes32Variable, CircuitBuilder, PlonkParameters, VariableStream};
use zk_tendermint::step::{StepOffchainInputs, TendermintStepCircuit};

use crate::builder::DataCommitmentBuilder;
use crate::commitment::DataCommitmentOffchainInputs;
use crate::vars::DataCommitmentProofVariable;

#[derive(Debug, Clone)]
pub struct CombinedStepCircuit<const MAX_VALIDATOR_SET_SIZE: usize> {
    _config: usize,
}

impl<const MAX_VALIDATOR_SET_SIZE: usize> Circuit for CombinedStepCircuit<MAX_VALIDATOR_SET_SIZE> {
    fn define<L: PlonkParameters<D>, const D: usize>(builder: &mut CircuitBuilder<L, D>) {
        let prev_block_number = builder.evm_read::<U64Variable>();
        let prev_header_hash = builder.evm_read::<Bytes32Variable>();

        let one = builder.constant::<U64Variable>(1u64);
        let next_block_number = builder.add(prev_block_number, one);

        let next_header_hash =
            builder.step::<MAX_VALIDATOR_SET_SIZE>(prev_block_number, prev_header_hash);

        // Compute data commitment (always for 1 leaf).
        let mut input_stream = VariableStream::new();
        input_stream.write(&prev_block_number);
        input_stream.write(&next_block_number);
        let data_comm_fetcher = DataCommitmentOffchainInputs::<1> {};
        let output_stream = builder.async_hint(input_stream, data_comm_fetcher);
        let data_comm_proof = output_stream.read::<DataCommitmentProofVariable<1>>(builder);
        let _ = output_stream.read::<Bytes32Variable>(builder);

        let encoded_tuple =
            builder.encode_data_root_tuple(&data_comm_proof.data_hashes[0], &prev_block_number);
        let data_commitment = builder.leaf_hash(&encoded_tuple.0);

        builder.evm_write(next_header_hash);
        builder.evm_write(data_commitment);
    }

    fn register_generators<L: PlonkParameters<D>, const D: usize>(
        generator_registry: &mut plonky2x::prelude::HintRegistry<L, D>,
    ) where
        <<L as PlonkParameters<D>>::Config as plonky2::plonk::config::GenericConfig<D>>::Hasher:
            plonky2::plonk::config::AlgebraicHasher<L::Field>,
    {
        generator_registry.register_async_hint::<StepOffchainInputs<MAX_VALIDATOR_SET_SIZE>>();
        generator_registry.register_async_hint::<DataCommitmentOffchainInputs<1>>();
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
    fn test_combined_step_serialization() {
        env::set_var("RUST_LOG", "debug");
        env_logger::try_init().unwrap_or_default();

        const MAX_VALIDATOR_SET_SIZE: usize = 2;
        let mut builder = DefaultBuilder::new();

        log::debug!("Defining circuit");
        CombinedStepCircuit::<MAX_VALIDATOR_SET_SIZE>::define(&mut builder);
        let circuit = builder.build();
        log::debug!("Done building circuit");

        let mut hint_registry = HintRegistry::new();
        let mut gate_registry = GateRegistry::new();
        CombinedStepCircuit::<MAX_VALIDATOR_SET_SIZE>::register_generators(&mut hint_registry);
        CombinedStepCircuit::<MAX_VALIDATOR_SET_SIZE>::register_gates(&mut gate_registry);

        circuit.test_serializers(&gate_registry, &hint_registry);
    }

    fn test_combined_step_template<const MAX_VALIDATOR_SET_SIZE: usize>(
        prev_block: usize,
        prev_header_hash: [u8; 32],
    ) {
        env::set_var("RUST_LOG", "debug");
        env_logger::try_init().unwrap_or_default();
        env::set_var("RPC_MOCHA_4", "fixture"); // Use fixture during testing

        let mut builder = DefaultBuilder::new();

        log::debug!("Defining circuit");
        CombinedStepCircuit::<MAX_VALIDATOR_SET_SIZE>::define(&mut builder);

        log::debug!("Building circuit");
        let circuit = builder.build();
        log::debug!("Done building circuit");

        let mut input = circuit.input();

        input.evm_write::<U64Variable>(prev_block as u64);
        input.evm_write::<Bytes32Variable>(H256::from_slice(prev_header_hash.as_slice()));

        log::debug!("Generating proof");

        let rt = tokio::runtime::Runtime::new().unwrap();
        let (proof, mut output) = rt.block_on(async { circuit.prove_async(&input).await });

        log::debug!("Done generating proof");

        circuit.verify(&proof, &input, &output);

        let next_header_hash = output.evm_read::<Bytes32Variable>();
        println!("next_header_hash {:?}", next_header_hash);

        let data_commitment = output.evm_read::<Bytes32Variable>();
        println!("data_commitment {:?}", data_commitment);
    }

    #[test]
    #[cfg_attr(feature = "ci", ignore)]
    fn test_combined_step_small() {
        const MAX_VALIDATOR_SET_SIZE: usize = 2;

        let start_block = 10000u64;
        let start_header_hash =
            hex::decode_upper("A0123D5E4B8B8888A61F931EE2252D83568B97C223E0ECA9795B29B8BD8CBA2D")
                .unwrap();

        test_combined_step_template::<MAX_VALIDATOR_SET_SIZE>(
            start_block as usize,
            start_header_hash.as_slice().try_into().unwrap(),
        );
    }

    #[test]
    #[cfg_attr(feature = "ci", ignore)]
    fn test_combined_step_large() {
        const MAX_VALIDATOR_SET_SIZE: usize = 128;

        let start_block = 10000u64;
        let start_header_hash =
            hex::decode_upper("A0123D5E4B8B8888A61F931EE2252D83568B97C223E0ECA9795B29B8BD8CBA2D")
                .unwrap();

        test_combined_step_template::<MAX_VALIDATOR_SET_SIZE>(
            start_block as usize,
            start_header_hash.as_slice().try_into().unwrap(),
        );
    }

    #[test]
    #[cfg_attr(feature = "ci", ignore)]
    fn test_combined_step_medium() {
        const MAX_VALIDATOR_SET_SIZE: usize = 32;

        let start_block = 10000u64;
        let start_header_hash =
            hex::decode_upper("A0123D5E4B8B8888A61F931EE2252D83568B97C223E0ECA9795B29B8BD8CBA2D")
                .unwrap();

        test_combined_step_template::<MAX_VALIDATOR_SET_SIZE>(
            start_block as usize,
            start_header_hash.as_slice().try_into().unwrap(),
        );
    }
}
