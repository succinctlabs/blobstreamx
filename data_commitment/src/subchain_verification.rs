use celestia::consts::*;
use itertools::Itertools;
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig};
use plonky2x::backend::circuit::{Circuit, PlonkParameters};
use plonky2x::prelude::{
    ArrayVariable, BoolVariable, Bytes32Variable, CircuitBuilder, CircuitVariable, RichField,
    Variable, U64Variable, VariableStream,
};
use tendermint::merkle::HASH_SIZE;

use crate::builder::DataCommitmentBuilder;
use crate::circuit::DataCommitmentOffchainInputs;
use crate::vars::DataCommitmentProofVariable;

/// The nubmer of map jobs.  This needs to be a power of 2
const NUM_MAP_JOBS: usize = 2;

pub const BATCH_SIZE: usize = 8;

/// Num processed headers per MR job
const HEADERS_PER_JOB: usize = BATCH_SIZE * NUM_MAP_JOBS;

#[derive(Clone, Debug, CircuitVariable)]
pub struct MapReduceSubchainVariable {
    pub is_enabled: BoolVariable,
    pub start_block: U64Variable,
    pub start_header: Bytes32Variable,
    pub end_block: U64Variable,
    pub end_header: Bytes32Variable,
    pub data_merkle_root: Bytes32Variable,
}

#[derive(Clone, Debug, CircuitVariable)]
pub struct SubchainVerificationCtx {
    pub start_block: U64Variable,
    pub start_header_hash: Bytes32Variable,
    pub end_block: U64Variable,
    pub end_header_hash: Bytes32Variable,
}

pub trait SubChainVerifier<L: PlonkParameters<D>, const D: usize> {
    // Verify the subchain from start_block to end_block, and return the data_merkle_root of the subchain.
    fn verify_subchain<C: Circuit>(
        &mut self,
        start_block: U64Variable,
        start_header_hash: Bytes32Variable,
        end_block: U64Variable,
        end_header_hash: Bytes32Variable,
    ) -> Bytes32Variable
    where
        <<L as PlonkParameters<D>>::Config as GenericConfig<D>>::Hasher:
            AlgebraicHasher<<L as PlonkParameters<D>>::Field>;
}

impl<L: PlonkParameters<D>, const D: usize> SubChainVerifier<L, D> for CircuitBuilder<L, D> {
    fn verify_subchain<C: Circuit>(
        &mut self,
        start_block: U64Variable,
        start_header_hash: Bytes32Variable,
        end_block: U64Variable,
        end_header_hash: Bytes32Variable,
    ) -> Bytes32Variable
    where
        <<L as PlonkParameters<D>>::Config as GenericConfig<D>>::Hasher:
            AlgebraicHasher<<L as PlonkParameters<D>>::Field>,
    {
        let ctx = SubchainVerificationCtx {
            start_block,
            start_header_hash,
            end_block,
            end_header_hash,
        };

        let relative_block_nums = (0u64..(HEADERS_PER_JOB as u64)).collect_vec();

        // The last block in batch i and the start block in batch i+1 are shared.
        let result = self
            .mapreduce::<SubchainVerificationCtx, U64Variable, MapReduceSubchainVariable, C, BATCH_SIZE, _, _>(
                ctx.clone(),
                relative_block_nums,
                |map_ctx, map_relative_block_nums, builder| {

                    let end_header_hash = ctx.end_header_hash;
                    let end_block = ctx.end_block;

                    // Note: map_relative_block_nums is inclusive of the last block.
                    let mut input_stream = VariableStream::new();
                    let start_block =
                        builder.add(map_ctx.start_block, map_relative_block_nums.as_vec()[0]);
                    let last_block = builder.add(
                        map_ctx.start_block,
                        map_relative_block_nums.as_vec()[BATCH_SIZE - 1],
                    );

                    let true_var = builder._true();

                    let one = builder.constant::<U64Variable>(1u64);

                    // Note: batch_end_block - start_block = BATCH_SIZE.
                    let batch_end_block = builder.add(last_block, one);

                    input_stream.write(&start_block);
                    input_stream.write(&batch_end_block);
                    let header_fetcher = DataCommitmentOffchainInputs::<BATCH_SIZE> {};
                    
                    let output_stream = builder
                        .async_hint(input_stream, header_fetcher);

                    let data_comm_proof = output_stream
                        .read::<DataCommitmentProofVariable<BATCH_SIZE>>(builder);

                    let _ = output_stream.read::<Bytes32Variable>(builder);

                    // Start and end headers of the batch.
                    let batch_start_header = data_comm_proof.start_header;
                    let batch_end_header = data_comm_proof.end_header;

                    let data_hash_path = builder
                        .constant::<ArrayVariable<BoolVariable, 4>>(vec![false, true, true, false]);
                    let last_block_id_path = builder.constant::<ArrayVariable<BoolVariable, 4>>(vec![
                        false, false, true, false,
                    ]);

                    // Only need to check these headers if the batch is enabled.
                    // If the start_block = map_ctx.end_block, we still verify the prev_header_proof against the end_block in reduce.
                    let mut is_enabled = builder.lt(start_block, map_ctx.end_block);
                    let is_batch_enabled = is_enabled;

                    let mut curr_header = batch_start_header;

                    let last_block_to_process = builder.sub(end_block, one);
                    // Verify all data_hash_proofs against headers from prev_header_proofs.
                    for i in 0..BATCH_SIZE {
                        let is_disabled = builder.not(is_enabled);
                        // end_block - 1 is the last valid leaf.
                        let curr_idx = builder.constant::<U64Variable>(i as u64);
                        let curr_block = builder.add(start_block, curr_idx);
                        let is_last_valid_leaf = builder.is_equal(last_block_to_process, curr_block);
                        let is_not_last_valid_leaf = builder.not(is_last_valid_leaf);

                        // Header hash of block (start + i).
                        let data_hash_proof_root = builder
                        .get_root_from_merkle_proof::<HEADER_PROOF_DEPTH, PROTOBUF_HASH_SIZE_BYTES>(
                            &data_comm_proof.data_hash_proofs[i],
                            &data_hash_path,
                        );
                        // Header hash of block (start + i + 1).
                        let prev_header_proof_root = builder
                        .get_root_from_merkle_proof::<HEADER_PROOF_DEPTH, PROTOBUF_BLOCK_ID_SIZE_BYTES>(
                            &data_comm_proof.prev_header_proofs[i],
                            &last_block_id_path.clone(),
                        );

                        // Header hash of block (start + i).
                        let header_hash =
                            &data_comm_proof.prev_header_proofs[i].leaf[2..2 + HASH_SIZE];
                        
                        // Verify the data hash proof against the header hash of block (start + i).
                        let is_valid_data_hash =
                        builder.is_equal(data_hash_proof_root, header_hash.into());
                        // NOT is_enabled || (data_hash_proof_root == header_hash) must be true.
                        let data_hash_check = builder.or(is_disabled, is_valid_data_hash);
                        builder.assert_is_equal(data_hash_check, true_var);


                        // Verify the header chain.
                        // 1) Verify the curr_header matches the extracted header_hash.
                        let is_valid_prev_header = builder.is_equal(curr_header, header_hash.into());
                        // NOT is_enabled || (curr_header == header_hash) must be true.
                        let prev_header_check = builder.or(is_disabled, is_valid_prev_header);
                        builder.assert_is_equal(prev_header_check, true_var);

                        // 2) If is_last_valid_leaf is true, then the root of the prev_header_proof must be the end_header.
                        let root_matches_end_header = builder.is_equal(prev_header_proof_root, end_header_hash);
                        // NOT is_valid_leaf || root_matches_end_header must be true.
                        let end_header_check = builder.or(is_not_last_valid_leaf, root_matches_end_header);
                        builder.assert_is_equal(end_header_check, true_var);

                        // Move curr_prev_header to prev_header_proof_root.
                        curr_header = prev_header_proof_root;
                        // Set is_enabled to false if this is the last valid leaf.
                        is_enabled = builder.and(is_enabled, is_not_last_valid_leaf);
                    }

                    // Select the min of the target block and the end block in the batch.
                    let is_less_than_target = builder.lte(batch_end_block, map_ctx.end_block);
                    let end_block_num =
                        builder.select(is_less_than_target, batch_end_block, map_ctx.end_block);

                    // Generate the data_merkle_root for the batch. If the batch is disabled
                    let data_merkle_root = builder.get_data_commitment::<BATCH_SIZE>(
                        &data_comm_proof.data_hashes,
                        start_block,
                        end_block_num,
                    );

                    MapReduceSubchainVariable {
                        is_enabled: is_batch_enabled,
                        start_block,
                        start_header: batch_start_header,
                        end_block: batch_end_block,
                        end_header: batch_end_header,
                        data_merkle_root,
                    }
                },
                |_, left_output, right_output, builder| {
                    let left_subchain = left_output;

                    let right_subchain = right_output;

                    let false_var = builder._false();

                    let right_empty = builder.is_equal(right_subchain.is_enabled, false_var);

                    // Check to see if the left and right nodes are correctly linked.
                    let nodes_linked =
                        builder.is_equal(left_subchain.end_header, right_subchain.start_header);

                    let one = builder.one();
                    let expected_block_num = builder.sub(right_subchain.start_block, one);
                    let nodes_sequential = builder.is_equal(left_subchain.end_block, expected_block_num);

                    let nodes_correctly_linked = builder.and(nodes_linked, nodes_sequential);

                    let link_check = builder.or(right_empty, nodes_correctly_linked);
                    let true_const = builder._true();
                    builder.assert_is_equal(link_check, true_const);

                    let end_block = builder.select(right_empty, left_subchain.end_block, right_subchain.end_block);
                    let end_header_hash =
                        builder.select(right_empty, left_subchain.end_header, right_subchain.end_header);

                    let computed_data_merkle_root = builder.inner_hash(&left_subchain.data_merkle_root, &right_subchain.data_merkle_root);

                    // If the right node is empty, then the data_merkle_root is the left node's data_merkle_root.
                    let data_merkle_root = builder.select(
                        right_empty,
                        left_subchain.data_merkle_root,
                        computed_data_merkle_root,
                    );

                    let either_enabled = builder.or(left_subchain.is_enabled, right_subchain.is_enabled);

                    MapReduceSubchainVariable {
                        is_enabled: either_enabled,
                        start_block: left_subchain.start_block,
                        start_header: left_subchain.start_header,
                        end_block,
                        end_header: end_header_hash,
                        data_merkle_root,
                    }
                },
            );

            result.data_merkle_root
    }
}
