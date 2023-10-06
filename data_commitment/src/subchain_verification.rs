use itertools::Itertools;
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig};
use plonky2x::backend::circuit::{Circuit, PlonkParameters};
use plonky2x::frontend::vars::{U32Variable, VariableStream};
use plonky2x::prelude::{
    ArrayVariable, BoolVariable, Bytes32Variable, CircuitBuilder, CircuitVariable, RichField,
    Variable,
};

use crate::builder::DataCommitmentBuilder;
use crate::circuit::DataCommitmentOffchainInputs;
use crate::vars::DataCommitmentProofVariable;

/// The nubmer of map jobs.  This needs to be a power of 2
const NUM_MAP_JOBS: usize = 2;

pub const BATCH_SIZE: usize = 16;

/// Num processed headers per MR job
const HEADERS_PER_JOB: usize = BATCH_SIZE * NUM_MAP_JOBS;

const MAX_HEADER_CHUNK_SIZE: usize = 100;
pub const MAX_HEADER_SIZE: usize = MAX_HEADER_CHUNK_SIZE * 128;

#[derive(Clone, Debug, CircuitVariable)]
pub struct SubchainVerificationCtx {
    pub trusted_block: U32Variable,
    pub trusted_header_hash: Bytes32Variable,
    pub target_block: U32Variable,
}

pub trait SubChainVerifier<L: PlonkParameters<D>, const D: usize> {
    fn verify_subchain<C: Circuit>(
        &mut self,
        trusted_block: U32Variable,
        trusted_header_hash: Bytes32Variable,
        target_block: U32Variable,
    ) -> (Bytes32Variable, Bytes32Variable)
    where
        <<L as PlonkParameters<D>>::Config as GenericConfig<D>>::Hasher:
            AlgebraicHasher<<L as PlonkParameters<D>>::Field>;
}

impl<L: PlonkParameters<D>, const D: usize> SubChainVerifier<L, D> for CircuitBuilder<L, D> {
    fn verify_subchain<C: Circuit>(
        &mut self,
        trusted_block: U32Variable,
        trusted_header_hash: Bytes32Variable,
        target_block: U32Variable,
    ) -> (Bytes32Variable, Bytes32Variable)
    where
        <<L as PlonkParameters<D>>::Config as GenericConfig<D>>::Hasher:
            AlgebraicHasher<<L as PlonkParameters<D>>::Field>,
    {
        let ctx = SubchainVerificationCtx {
            trusted_block,
            trusted_header_hash,
            target_block,
        };

        let relative_block_nums = (0u32..(HEADERS_PER_JOB as u32) + 1).collect_vec();

        let (_, _, _, _, _, end_header_hash, data_merkle_root) = self
            .mapreduce::<SubchainVerificationCtx, U32Variable, (
                BoolVariable,    // is_enabled (whether the leaf contains any valid headers)
                U32Variable,     // first block's num
                Bytes32Variable, // first block's hash
                Bytes32Variable, // first block's parent hash
                U32Variable,     // last block's num
                Bytes32Variable, // last block's hash
                Bytes32Variable, // data merkle root
            ), C, BATCH_SIZE, _, _>(
                ctx,
                relative_block_nums,
                |map_ctx, map_relative_block_nums, builder| {
                    let mut input_stream = VariableStream::new();
                    let start_block =
                        builder.add(map_ctx.trusted_block, map_relative_block_nums.as_vec()[0]);
                    let last_block = builder.add(
                        map_ctx.trusted_block,
                        map_relative_block_nums.as_vec()[BATCH_SIZE - 1],
                    );

                    input_stream.write(&start_block);
                    input_stream.write(&last_block);
                    let header_fetcher = DataCommitmentOffchainInputs::<BATCH_SIZE> {};
                    let data_comm_proof = builder
                        .async_hint(input_stream, header_fetcher)
                        .read::<DataCommitmentProofVariable<BATCH_SIZE>>(builder);

                    // Start and end headers of the batch.
                    let batch_start_header = data_comm_proof.start_header;
                    let batch_end_header = data_comm_proof.end_header;

                    let true_var = self._true();
                    let data_hash_path = self
                        .constant::<ArrayVariable<BoolVariable, 4>>(vec![false, true, true, false]);
                    let last_block_id_path = self.constant::<ArrayVariable<BoolVariable, 4>>(vec![
                        false, false, true, false,
                    ]);

                    let mut is_enabled = self.lte(start_block, map_ctx.target_block);
                    let mut curr_header = batch_start_header;

                    // Select the min of the target block and the last block in the batch.
                    let is_less_than_target = self.lte(last_block, map_ctx.target_block);
                    let end_block_num =
                        builder.select(is_less_than_target, last_block, map_ctx.target_block);

                    // Note: We will only inner hash the data_merkle_root if it's start_block is < target_block.
                    let data_merkle_root = builder.get_data_commitment::<BATCH_SIZE>(
                        &data_comm_proof.data_hashes,
                        start_block,
                        end_block_num,
                    );

                    (
                        is_enabled,
                        start_block,
                        batch_start_header,
                        block_parent_hashes[0],
                        last_block,
                        batch_end_header,
                        data_merkle_root,
                    )
                },
                |_, left_output, right_output, builder| {
                    let (
                        left_num_blocks,
                        left_first_block,
                        left_first_header_hash,
                        left_first_block_parent,
                        left_end_block,
                        left_end_header_hash,
                        left_data_merkle_root,
                    ) = left_output;

                    let (
                        right_num_blocks,
                        right_first_block,
                        _,
                        right_first_block_parent,
                        right_end_block,
                        right_end_header_hash,
                        right_data_merkle_root,
                    ) = right_output;

                    let total_num_blocks = builder.add(left_num_blocks, right_num_blocks);

                    let right_empty = builder.is_zero(right_num_blocks);

                    // Check to see if the left and right nodes are correctly linked.
                    let nodes_linked =
                        builder.is_equal(left_end_header_hash, right_first_block_parent);
                    let one = builder.one();
                    let expected_block_num = builder.sub(right_first_block, one);
                    let nodes_sequential = builder.is_equal(left_end_block, expected_block_num);

                    let nodes_correctly_linked = builder.and(nodes_linked, nodes_sequential);

                    let link_check = builder.or(right_empty, nodes_correctly_linked);
                    let true_const = builder._true();
                    builder.assert_is_equal(link_check, true_const);

                    let end_block = builder.select(right_empty, left_end_block, right_end_block);
                    let end_header_hash =
                        builder.select(right_empty, left_end_header_hash, right_end_header_hash);

                    let mut data_root_bytes = left_data_merkle_root.as_bytes().to_vec();
                    data_root_bytes.extend(&right_data_merkle_root.as_bytes());
                    let data_merkle_root = builder.sha256(&data_root_bytes);

                    (
                        total_num_blocks,
                        left_first_block,
                        left_first_header_hash,
                        left_first_block_parent,
                        end_block,
                        end_header_hash,
                        data_merkle_root,
                    )
                },
            );

        (end_header_hash, data_merkle_root)
    }
}
