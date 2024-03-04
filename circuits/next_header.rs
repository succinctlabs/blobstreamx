use plonky2x::backend::circuit::Circuit;
use plonky2x::frontend::uint::uint64::U64Variable;
use plonky2x::prelude::{Bytes32Variable, CircuitBuilder, PlonkParameters};
use tendermintx::config::TendermintConfig;
use tendermintx::step::{StepOffchainInputs, TendermintStepCircuit};

use crate::builder::DataCommitmentBuilder;
use crate::data_commitment::DataCommitmentOffchainInputs;

#[derive(Debug, Clone)]
pub struct CombinedStepCircuit<
    const MAX_VALIDATOR_SET_SIZE: usize,
    const CHAIN_ID_SIZE_BYTES: usize,
    C: TendermintConfig<CHAIN_ID_SIZE_BYTES>,
> {
    _phantom: std::marker::PhantomData<C>,
}

impl<
        const MAX_VALIDATOR_SET_SIZE: usize,
        const CHAIN_ID_SIZE_BYTES: usize,
        C: TendermintConfig<CHAIN_ID_SIZE_BYTES>,
    > Circuit for CombinedStepCircuit<MAX_VALIDATOR_SET_SIZE, CHAIN_ID_SIZE_BYTES, C>
{
    fn define<L: PlonkParameters<D>, const D: usize>(builder: &mut CircuitBuilder<L, D>) {
        let prev_block_number = builder.evm_read::<U64Variable>();
        let prev_header_hash = builder.evm_read::<Bytes32Variable>();

        let one = builder.constant::<U64Variable>(1u64);
        let next_block_number = builder.add(prev_block_number, one);

        let next_header_hash = builder.step::<MAX_VALIDATOR_SET_SIZE, CHAIN_ID_SIZE_BYTES>(
            C::CHAIN_ID_BYTES,
            prev_block_number,
            prev_header_hash,
        );

        // Prove the data commitment (which only includes the prev_block_number's data hash).
        let data_commitment = builder.prove_next_header_data_commitment(
            prev_block_number,
            prev_header_hash,
            next_block_number,
        );

        builder.evm_write(next_header_hash);
        builder.evm_write(data_commitment);
    }

    fn register_generators<L: PlonkParameters<D>, const D: usize>(
        generator_registry: &mut plonky2x::prelude::HintRegistry<L, D>,
    ) where
        <<L as PlonkParameters<D>>::Config as plonky2x::prelude::plonky2::plonk::config::GenericConfig<D>>::Hasher:
            plonky2x::prelude::plonky2::plonk::config::AlgebraicHasher<L::Field>,
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
    use tendermintx::config::{Mocha4Config, MOCHA_4_CHAIN_ID_SIZE_BYTES};

    use super::*;

    #[test]
    #[cfg_attr(feature = "ci", ignore)]
    fn test_next_header_serialization() {
        env::set_var("RUST_LOG", "debug");
        env_logger::try_init().unwrap_or_default();

        const MAX_VALIDATOR_SET_SIZE: usize = 2;
        let mut builder = DefaultBuilder::new();

        log::debug!("Defining circuit");
        CombinedStepCircuit::<MAX_VALIDATOR_SET_SIZE, MOCHA_4_CHAIN_ID_SIZE_BYTES, Mocha4Config>::define(&mut builder);
        let circuit = builder.build();
        log::debug!("Done building circuit");

        let mut hint_registry = HintRegistry::new();
        let mut gate_registry = GateRegistry::new();
        CombinedStepCircuit::<MAX_VALIDATOR_SET_SIZE, MOCHA_4_CHAIN_ID_SIZE_BYTES, Mocha4Config>::register_generators(&mut hint_registry);
        CombinedStepCircuit::<MAX_VALIDATOR_SET_SIZE, MOCHA_4_CHAIN_ID_SIZE_BYTES, Mocha4Config>::register_gates(&mut gate_registry);

        circuit.test_serializers(&gate_registry, &hint_registry);
    }

    #[cfg(test)]
    fn test_next_header_template<const MAX_VALIDATOR_SET_SIZE: usize>(
        prev_block: usize,
        prev_header_hash: [u8; 32],
    ) {
        env::set_var("RUST_LOG", "debug");
        env_logger::try_init().unwrap_or_default();

        let mut builder = DefaultBuilder::new();

        log::debug!("Defining circuit");
        CombinedStepCircuit::<MAX_VALIDATOR_SET_SIZE, MOCHA_4_CHAIN_ID_SIZE_BYTES, Mocha4Config>::define(&mut builder);

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
    fn test_next_header_small() {
        const MAX_VALIDATOR_SET_SIZE: usize = 4;

        // This block is on Mocha-4 testnet.
        let start_block = 500u64;
        let start_header_hash =
            hex::decode_upper("46604E5FF15811D674CBAF2067DE6479A381EEC1BA046B90508939A685B40AE7")
                .unwrap();

        test_next_header_template::<MAX_VALIDATOR_SET_SIZE>(
            start_block as usize,
            start_header_hash.as_slice().try_into().unwrap(),
        );
    }

    #[test]
    #[cfg_attr(feature = "ci", ignore)]
    fn test_next_header_medium() {
        const MAX_VALIDATOR_SET_SIZE: usize = 32;

        // This block is on Mocha-4 testnet.
        let start_block = 500u64;
        let start_header_hash =
            hex::decode_upper("46604E5FF15811D674CBAF2067DE6479A381EEC1BA046B90508939A685B40AE7")
                .unwrap();

        test_next_header_template::<MAX_VALIDATOR_SET_SIZE>(
            start_block as usize,
            start_header_hash.as_slice().try_into().unwrap(),
        );
    }

    #[test]
    #[cfg_attr(feature = "ci", ignore)]
    fn test_next_header_large() {
        const MAX_VALIDATOR_SET_SIZE: usize = 100;

        // This block is on Mocha-4 testnet.
        let start_block = 500u64;
        let start_header_hash =
            hex::decode_upper("46604E5FF15811D674CBAF2067DE6479A381EEC1BA046B90508939A685B40AE7")
                .unwrap();

        test_next_header_template::<MAX_VALIDATOR_SET_SIZE>(
            start_block as usize,
            start_header_hash.as_slice().try_into().unwrap(),
        );
    }
}
