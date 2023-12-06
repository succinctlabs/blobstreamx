use plonky2x::backend::circuit::Circuit;
use plonky2x::frontend::mapreduce::generator::MapReduceGenerator;
use plonky2x::frontend::uint::uint64::U64Variable;
use plonky2x::prelude::{Bytes32Variable, CircuitBuilder, PlonkParameters};
use tendermintx::skip::{SkipOffchainInputs, TendermintSkipCircuit};

use crate::builder::{DataCommitmentBuilder, DataCommitmentSharedCtx};
use crate::data_commitment::DataCommitmentOffchainInputs;
use crate::vars::MapReduceSubchainVariable;

#[derive(Debug, Clone)]
pub struct CombinedSkipCircuit<
    const MAX_VALIDATOR_SET_SIZE: usize,
    const NB_MAP_JOBS: usize,
    const BATCH_SIZE: usize,
> {
    _config: usize,
}

impl<const MAX_VALIDATOR_SET_SIZE: usize, const NB_MAP_JOBS: usize, const BATCH_SIZE: usize> Circuit
    for CombinedSkipCircuit<MAX_VALIDATOR_SET_SIZE, NB_MAP_JOBS, BATCH_SIZE>
{
    fn define<L: PlonkParameters<D>, const D: usize>(builder: &mut CircuitBuilder<L, D>)  where <<L as plonky2x::prelude::PlonkParameters<D>>::Config as plonky2::plonk::config::GenericConfig<D>>::Hasher: plonky2::plonk::config::AlgebraicHasher<<L as plonky2x::prelude::PlonkParameters<D>>::Field>{
        let trusted_block = builder.evm_read::<U64Variable>();
        let trusted_header_hash = builder.evm_read::<Bytes32Variable>();
        let target_block = builder.evm_read::<U64Variable>();

        let target_header_hash = builder.skip::<MAX_VALIDATOR_SET_SIZE>(
            trusted_block,
            trusted_header_hash,
            target_block,
        );

        let data_commitment = builder.prove_data_commitment::<Self, NB_MAP_JOBS, BATCH_SIZE>(
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
        generator_registry.register_async_hint::<SkipOffchainInputs<MAX_VALIDATOR_SET_SIZE>>();

        generator_registry.register_async_hint::<DataCommitmentOffchainInputs<BATCH_SIZE>>();
        let mr_id = MapReduceGenerator::<
            L,
            DataCommitmentSharedCtx,
            U64Variable,
            MapReduceSubchainVariable,
            Self,
            BATCH_SIZE,
            D,
        >::id();
        generator_registry.register_simple::<MapReduceGenerator<
            L,
            DataCommitmentSharedCtx,
            U64Variable,
            MapReduceSubchainVariable,
            Self,
            BATCH_SIZE,
            D,
        >>(mr_id);
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
    fn test_header_range_serialization() {
        env::set_var("RUST_LOG", "debug");
        env_logger::try_init().unwrap_or_default();

        const MAX_VALIDATOR_SET_SIZE: usize = 2;
        const NB_MAP_JOBS: usize = 2;
        const BATCH_SIZE: usize = 2;
        let mut builder = DefaultBuilder::new();

        log::debug!("Defining circuit");
        CombinedSkipCircuit::<MAX_VALIDATOR_SET_SIZE, NB_MAP_JOBS, BATCH_SIZE>::define(
            &mut builder,
        );
        let circuit = builder.build();
        log::debug!("Done building circuit");

        let mut hint_registry = HintRegistry::new();
        let mut gate_registry = GateRegistry::new();
        CombinedSkipCircuit::<MAX_VALIDATOR_SET_SIZE, NB_MAP_JOBS, BATCH_SIZE>::register_generators(
            &mut hint_registry,
        );
        CombinedSkipCircuit::<MAX_VALIDATOR_SET_SIZE, NB_MAP_JOBS, BATCH_SIZE>::register_gates(
            &mut gate_registry,
        );

        circuit.test_serializers(&gate_registry, &hint_registry);
    }

    fn test_header_range_template<
        const MAX_VALIDATOR_SET_SIZE: usize,
        const NB_MAP_JOBS: usize,
        const BATCH_SIZE: usize,
    >(
        start_block: usize,
        start_header_hash: [u8; 32],
        end_block: usize,
    ) {
        env::set_var("RUST_LOG", "debug");
        env_logger::try_init().unwrap_or_default();

        let mut builder = DefaultBuilder::new();

        log::debug!("Defining circuit");
        CombinedSkipCircuit::<MAX_VALIDATOR_SET_SIZE, NB_MAP_JOBS, BATCH_SIZE>::define(
            &mut builder,
        );

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
    fn test_header_range_small() {
        // Test variable length NUM_BLOCKS.
        const MAX_VALIDATOR_SET_SIZE: usize = 8;
        const NB_MAP_JOBS: usize = 2;
        const BATCH_SIZE: usize = 2;

        // These blocks are on Mocha-4 testnet.
        let start_block = 500u64;
        let start_header_hash =
            hex::decode_upper("46604E5FF15811D674CBAF2067DE6479A381EEC1BA046B90508939A685B40AE7")
                .unwrap();
        let end_block = 504u64;
        let _ =
            hex::decode_upper("9B6321EC17F092E770724792611E6C9FC3A0FF162CE341B353D6AD31FB75D1C2")
                .unwrap();

        test_header_range_template::<MAX_VALIDATOR_SET_SIZE, NB_MAP_JOBS, BATCH_SIZE>(
            start_block as usize,
            start_header_hash.as_slice().try_into().unwrap(),
            end_block as usize,
        );
    }

    #[test]
    #[cfg_attr(feature = "ci", ignore)]
    fn test_header_range_large() {
        // Test variable length NUM_BLOCKS.
        const MAX_VALIDATOR_SET_SIZE: usize = 100;
        const NB_MAP_JOBS: usize = 16;
        const BATCH_SIZE: usize = 64;

        // These blocks are on Mocha-4 testnet.
        let start_block = 500u64;
        let start_header_hash =
            hex::decode_upper("46604E5FF15811D674CBAF2067DE6479A381EEC1BA046B90508939A685B40AE7")
                .unwrap();
        let end_block = 504u64;
        let _ =
            hex::decode_upper("9B6321EC17F092E770724792611E6C9FC3A0FF162CE341B353D6AD31FB75D1C2")
                .unwrap();

        test_header_range_template::<MAX_VALIDATOR_SET_SIZE, NB_MAP_JOBS, BATCH_SIZE>(
            start_block as usize,
            start_header_hash.as_slice().try_into().unwrap(),
            end_block as usize,
        );
    }

    #[test]
    #[cfg_attr(feature = "ci", ignore)]
    fn test_header_range_medium() {
        // Test variable length NUM_BLOCKS.
        const MAX_VALIDATOR_SET_SIZE: usize = 32;
        const NB_MAP_JOBS: usize = 8;
        const BATCH_SIZE: usize = 32;

        // These blocks are on Mocha-4 testnet.
        let start_block = 500u64;
        let start_header_hash =
            hex::decode_upper("46604E5FF15811D674CBAF2067DE6479A381EEC1BA046B90508939A685B40AE7")
                .unwrap();
        let end_block = 504u64;
        let _ =
            hex::decode_upper("9B6321EC17F092E770724792611E6C9FC3A0FF162CE341B353D6AD31FB75D1C2")
                .unwrap();

        test_header_range_template::<MAX_VALIDATOR_SET_SIZE, NB_MAP_JOBS, BATCH_SIZE>(
            start_block as usize,
            start_header_hash.as_slice().try_into().unwrap(),
            end_block as usize,
        );
    }
}
