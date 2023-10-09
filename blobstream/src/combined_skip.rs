use plonky2x::backend::circuit::Circuit;
use plonky2x::frontend::uint::uint64::U64Variable;
use plonky2x::prelude::{Bytes32Variable, CircuitBuilder, PlonkParameters};
use zk_tendermint::skip::{SkipOffchainInputs, TendermintSkipCircuit};

use crate::commitment::{CelestiaDataCommitmentCircuit, DataCommitmentOffchainInputs};

pub struct CombinedSkipCircuit<const MAX_LEAVES: usize, const MAX_VALIDATOR_SET_SIZE: usize> {
    _config: usize,
}

impl<const MAX_LEAVES: usize, const MAX_VALIDATOR_SET_SIZE: usize> Circuit
    for CombinedSkipCircuit<MAX_LEAVES, MAX_VALIDATOR_SET_SIZE>
{
    fn define<L: PlonkParameters<D>, const D: usize>(builder: &mut CircuitBuilder<L, D>) {
        let trusted_block = builder.evm_read::<U64Variable>();
        let trusted_header_hash = builder.evm_read::<Bytes32Variable>();
        let target_block = builder.evm_read::<U64Variable>();

        let target_header_hash = builder.skip::<MAX_VALIDATOR_SET_SIZE>(
            trusted_block,
            trusted_header_hash,
            target_block,
        );

        let data_commitment = builder.data_commitment::<MAX_LEAVES>(
            trusted_block,
            trusted_header_hash,
            target_block,
            target_header_hash,
        );

        builder.evm_write(target_header_hash);
        builder.evm_write(data_commitment);
    }

    fn register_generators<L: PlonkParameters<D>, const D: usize>(
        generator_registry: &mut plonky2x::prelude::HintRegistry<L, D>,
    ) where
        <<L as PlonkParameters<D>>::Config as plonky2::plonk::config::GenericConfig<D>>::Hasher:
            plonky2::plonk::config::AlgebraicHasher<L::Field>,
    {
        generator_registry.register_async_hint::<DataCommitmentOffchainInputs<MAX_LEAVES>>();
        generator_registry.register_async_hint::<SkipOffchainInputs<MAX_VALIDATOR_SET_SIZE>>();
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
        const MAX_VALIDATOR_SET_SIZE: usize = 2;
        let mut builder = DefaultBuilder::new();

        log::debug!("Defining circuit");
        CombinedSkipCircuit::<MAX_LEAVES, MAX_VALIDATOR_SET_SIZE>::define(&mut builder);
        let circuit = builder.build();
        log::debug!("Done building circuit");

        let mut hint_registry = HintRegistry::new();
        let mut gate_registry = GateRegistry::new();
        CombinedSkipCircuit::<MAX_LEAVES, MAX_VALIDATOR_SET_SIZE>::register_generators(
            &mut hint_registry,
        );
        CombinedSkipCircuit::<MAX_LEAVES, MAX_VALIDATOR_SET_SIZE>::register_gates(
            &mut gate_registry,
        );

        circuit.test_serializers(&gate_registry, &hint_registry);
    }

    fn test_combined_skip_template<const MAX_LEAVES: usize, const MAX_VALIDATOR_SET_SIZE: usize>(
        start_block: usize,
        start_header_hash: [u8; 32],
        end_block: usize,
    ) {
        env::set_var("RUST_LOG", "debug");
        env_logger::try_init().unwrap_or_default();
        env::set_var("RPC_MOCHA_4", "fixture"); // Use fixture during testing

        let mut builder = DefaultBuilder::new();

        log::debug!("Defining circuit");
        CombinedSkipCircuit::<MAX_LEAVES, MAX_VALIDATOR_SET_SIZE>::define(&mut builder);

        log::debug!("Building circuit");
        let circuit = builder.build();
        log::debug!("Done building circuit");

        let mut input = circuit.input();

        input.evm_write::<U64Variable>(start_block as u64);
        input.evm_write::<Bytes32Variable>(H256::from_slice(start_header_hash.as_slice()));
        input.evm_write::<U64Variable>(end_block as u64);

        log::debug!("Generating proof");

        let rt = tokio::runtime::Runtime::new().unwrap();
        let (proof, mut output) = rt.block_on(async { circuit.prove_async(&input).await });

        log::debug!("Done generating proof");

        circuit.verify(&proof, &input, &output);
        let target_header_hash = output.evm_read::<Bytes32Variable>();
        println!("target_header_hash {:?}", target_header_hash);

        let data_commitment = output.evm_read::<Bytes32Variable>();
        println!("data_commitment {:?}", data_commitment);
    }

    #[test]
    #[cfg_attr(feature = "ci", ignore)]
    fn test_combined_skip_small() {
        // Test variable length NUM_BLOCKS.
        const MAX_LEAVES: usize = 8;
        const MAX_VALIDATOR_SET_SIZE: usize = 4;

        let start_block = 10000u64;
        let start_header_hash =
            hex::decode_upper("A0123D5E4B8B8888A61F931EE2252D83568B97C223E0ECA9795B29B8BD8CBA2D")
                .unwrap();
        let end_block = 10004u64;
        let _ =
            hex::decode_upper("FCDA37FA6306C77737DD911E6101B612E2DBD837F29ED4F4E1C30919FBAC9D05")
                .unwrap();

        test_combined_skip_template::<MAX_LEAVES, MAX_VALIDATOR_SET_SIZE>(
            start_block as usize,
            start_header_hash.as_slice().try_into().unwrap(),
            end_block as usize,
        );
    }

    #[test]
    #[cfg_attr(feature = "ci", ignore)]
    fn test_combined_skip_large() {
        // Test variable length NUM_BLOCKS.
        const MAX_LEAVES: usize = 1024;
        const MAX_VALIDATOR_SET_SIZE: usize = 128;

        let start_block = 10000u64;
        let start_header_hash =
            hex::decode_upper("A0123D5E4B8B8888A61F931EE2252D83568B97C223E0ECA9795B29B8BD8CBA2D")
                .unwrap();
        let end_block = 10004u64;
        let _ =
            hex::decode_upper("FCDA37FA6306C77737DD911E6101B612E2DBD837F29ED4F4E1C30919FBAC9D05")
                .unwrap();

        test_combined_skip_template::<MAX_LEAVES, MAX_VALIDATOR_SET_SIZE>(
            start_block as usize,
            start_header_hash.as_slice().try_into().unwrap(),
            end_block as usize,
        );
    }

    #[test]
    #[cfg_attr(feature = "ci", ignore)]
    fn test_combined_skip_medium() {
        // Test variable length NUM_BLOCKS.
        const MAX_LEAVES: usize = 256;
        const MAX_VALIDATOR_SET_SIZE: usize = 32;

        let start_block = 10000u64;
        let start_header_hash =
            hex::decode_upper("A0123D5E4B8B8888A61F931EE2252D83568B97C223E0ECA9795B29B8BD8CBA2D")
                .unwrap();
        let end_block = 10004u64;
        let _ =
            hex::decode_upper("FCDA37FA6306C77737DD911E6101B612E2DBD837F29ED4F4E1C30919FBAC9D05")
                .unwrap();

        test_combined_skip_template::<MAX_LEAVES, MAX_VALIDATOR_SET_SIZE>(
            start_block as usize,
            start_header_hash.as_slice().try_into().unwrap(),
            end_block as usize,
        );
    }
}
