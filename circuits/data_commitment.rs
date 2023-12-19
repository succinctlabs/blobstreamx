use async_trait::async_trait;
use ethers::types::H256;
use plonky2x::backend::circuit::Circuit;
use plonky2x::frontend::hint::asynchronous::hint::AsyncHint;
use plonky2x::frontend::mapreduce::generator::MapReduceGenerator;
use plonky2x::frontend::merkle::tree::MerkleInclusionProofVariable;
use plonky2x::frontend::uint::uint64::U64Variable;
use plonky2x::prelude::{Bytes32Variable, CircuitBuilder, PlonkParameters, ValueStream};
use serde::{Deserialize, Serialize};
use tendermintx::input::utils::convert_to_h256;
use tendermintx::input::{InputDataFetcher, InputDataMode};

use crate::builder::{DataCommitmentBuilder, DataCommitmentSharedCtx};
use crate::consts::{HEADER_PROOF_DEPTH, PROTOBUF_BLOCK_ID_SIZE_BYTES};
use crate::input::DataCommitmentInputs;
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

        let mut data_fetcher = InputDataFetcher::default();
        data_fetcher.mode = InputDataMode::Rpc;

        let result = data_fetcher
            .get_data_commitment_inputs::<MAX_LEAVES, L::Field>(start_block, end_block)
            .await;

        let data_comm_proof = DataCommitmentProofValueType {
            data_hashes: convert_to_h256(result.2),
            start_block_height: start_block,
            start_header: H256(result.0),
            end_block_height: end_block,
            end_header: H256(result.1),
            data_hash_proofs: result.3,
            last_block_id_proofs: result.4,
        };
        // Write the inputs to the data commitment circuit.
        output_stream.write_value::<DataCommitmentProofVariable<MAX_LEAVES>>(data_comm_proof);
        // Write the expected data commitment.
        output_stream.write_value::<Bytes32Variable>(H256(result.5));
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrevHeaderHashProofOffchainInputs {}

#[async_trait]
impl<L: PlonkParameters<D>, const D: usize> AsyncHint<L, D> for PrevHeaderHashProofOffchainInputs {
    async fn hint(
        &self,
        input_stream: &mut ValueStream<L, D>,
        output_stream: &mut ValueStream<L, D>,
    ) {
        let block_number = input_stream.read_value::<U64Variable>();

        let mut data_fetcher = InputDataFetcher::default();

        let result = data_fetcher
            .get_last_block_id_proof::<L::Field>(block_number)
            .await;

        // Proof of the prev_header_hash against the header_hash of block_number.
        output_stream.write_value::<MerkleInclusionProofVariable<HEADER_PROOF_DEPTH, PROTOBUF_BLOCK_ID_SIZE_BYTES>>(result);
    }
}

#[derive(Debug, Clone)]
pub struct DataCommitmentCircuit<const NB_MAP_JOBS: usize, const BATCH_SIZE: usize> {
    _config: usize,
}

impl<const NB_MAP_JOBS: usize, const BATCH_SIZE: usize> Circuit
    for DataCommitmentCircuit<NB_MAP_JOBS, BATCH_SIZE>
{
    fn define<L: PlonkParameters<D>, const D: usize>(builder: &mut CircuitBuilder<L, D>) where <<L as plonky2x::prelude::PlonkParameters<D>>::Config as plonky2::plonk::config::GenericConfig<D>>::Hasher: plonky2::plonk::config::AlgebraicHasher<<L as plonky2x::prelude::PlonkParameters<D>>::Field>{
        let trusted_block_number = builder.evm_read::<U64Variable>();
        let trusted_header_hash = builder.evm_read::<Bytes32Variable>();
        let end_block_number = builder.evm_read::<U64Variable>();
        let end_header_hash = builder.evm_read::<Bytes32Variable>();

        let data_commitment = builder.prove_data_commitment::<Self, NB_MAP_JOBS, BATCH_SIZE>(
            trusted_block_number,
            trusted_header_hash,
            end_block_number,
            end_header_hash,
        );

        builder.evm_write(data_commitment);
    }

    fn register_generators<L: PlonkParameters<D>, const D: usize>(
        generator_registry: &mut plonky2x::prelude::HintRegistry<L, D>,
    ) where
        <<L as PlonkParameters<D>>::Config as plonky2::plonk::config::GenericConfig<D>>::Hasher:
            plonky2::plonk::config::AlgebraicHasher<L::Field>,
    {
        generator_registry.register_async_hint::<PrevHeaderHashProofOffchainInputs>();
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
    fn test_data_commitment_serialization() {
        env::set_var("RUST_LOG", "debug");
        env_logger::try_init().unwrap_or_default();

        const NB_MAP_JOBS: usize = 2;
        const BATCH_SIZE: usize = 2;
        let mut builder = DefaultBuilder::new();

        log::debug!("Defining circuit");
        DataCommitmentCircuit::<NB_MAP_JOBS, BATCH_SIZE>::define(&mut builder);
        let circuit = builder.build();
        log::debug!("Done building circuit");

        let mut hint_registry = HintRegistry::new();
        let mut gate_registry = GateRegistry::new();
        DataCommitmentCircuit::<NB_MAP_JOBS, BATCH_SIZE>::register_generators(&mut hint_registry);
        DataCommitmentCircuit::<NB_MAP_JOBS, BATCH_SIZE>::register_gates(&mut gate_registry);

        circuit.test_serializers(&gate_registry, &hint_registry);
    }

    fn test_data_commitment_template<const NB_MAP_JOBS: usize, const BATCH_SIZE: usize>(
        start_block: usize,
        start_header_hash: [u8; 32],
        end_block: usize,
        end_header_hash: [u8; 32],
    ) {
        env::set_var("RUST_LOG", "debug");
        env_logger::try_init().unwrap_or_default();

        let mut builder = DefaultBuilder::new();

        log::debug!("Defining circuit");
        DataCommitmentCircuit::<NB_MAP_JOBS, BATCH_SIZE>::define(&mut builder);

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
        const NB_MAP_JOBS: usize = 2;
        const BATCH_SIZE: usize = 8;

        let start_block = 354000u64;
        let start_header_hash =
            hex::decode_upper("F44C7086AE6C317E1C11D89CD0ECEA01BD23821039BC8EC836ECA931C88F6FF2")
                .unwrap();
        let end_block = 354004u64;
        let end_header_hash =
            hex::decode_upper("B15497F60F24513E4384ADC2C83C6135C76ACA613C00E7B1A835761B7445266A")
                .unwrap();

        test_data_commitment_template::<NB_MAP_JOBS, BATCH_SIZE>(
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
        // Note: These can be tuned.
        const NB_MAP_JOBS: usize = 16;
        const BATCH_SIZE: usize = 64;

        let start_block = 500u64;
        let start_header_hash =
            hex::decode_upper("A4580A5609BD420694FB4718645529AC654470489CD4D8BF144C5208EC08819F")
                .unwrap();
        let end_block = 504u64;
        let end_header_hash =
            hex::decode_upper("D6DA719AE76440DD977D6D7E618F71BEF4239D7C5D24A2B7588DFA6227B1EB38")
                .unwrap();

        test_data_commitment_template::<NB_MAP_JOBS, BATCH_SIZE>(
            start_block as usize,
            start_header_hash.as_slice().try_into().unwrap(),
            end_block as usize,
            end_header_hash.as_slice().try_into().unwrap(),
        );
    }

    #[test]
    #[cfg_attr(feature = "ci", ignore)]
    fn test_data_commitment_medium() {
        // Test variable length NUM_BLOCKS.
        // Note: These can be tuned.
        const NB_MAP_JOBS: usize = 16;
        const BATCH_SIZE: usize = 16;

        let start_block = 500u64;
        let start_header_hash =
            hex::decode_upper("A4580A5609BD420694FB4718645529AC654470489CD4D8BF144C5208EC08819F")
                .unwrap();
        let end_block = 504u64;
        let end_header_hash =
            hex::decode_upper("D6DA719AE76440DD977D6D7E618F71BEF4239D7C5D24A2B7588DFA6227B1EB38")
                .unwrap();

        test_data_commitment_template::<NB_MAP_JOBS, BATCH_SIZE>(
            start_block as usize,
            start_header_hash.as_slice().try_into().unwrap(),
            end_block as usize,
            end_header_hash.as_slice().try_into().unwrap(),
        );
    }
}
