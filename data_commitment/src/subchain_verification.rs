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

const MAX_HEADER_CHUNK_SIZE: usize = 100;
pub const MAX_HEADER_SIZE: usize = MAX_HEADER_CHUNK_SIZE * 128;

#[derive(Clone, Debug, CircuitVariable)]
pub struct SubchainVerificationCtx {
    pub trusted_block: U64Variable,
    pub trusted_header_hash: Bytes32Variable,
    pub target_block: U64Variable,
    pub target_header_hash: Bytes32Variable,
}

pub trait SubChainVerifier<L: PlonkParameters<D>, const D: usize> {
    fn verify_subchain<C: Circuit>(
        &mut self,
        trusted_block: U64Variable,
        trusted_header_hash: Bytes32Variable,
        target_block: U64Variable,
        target_header_hash: Bytes32Variable,
    ) -> Bytes32Variable
    where
        <<L as PlonkParameters<D>>::Config as GenericConfig<D>>::Hasher:
            AlgebraicHasher<<L as PlonkParameters<D>>::Field>;
}

impl<L: PlonkParameters<D>, const D: usize> SubChainVerifier<L, D> for CircuitBuilder<L, D> {
    fn verify_subchain<C: Circuit>(
        &mut self,
        trusted_block: U64Variable,
        trusted_header_hash: Bytes32Variable,
        target_block: U64Variable,
        target_header_hash: Bytes32Variable,
    ) -> Bytes32Variable
    where
        <<L as PlonkParameters<D>>::Config as GenericConfig<D>>::Hasher:
            AlgebraicHasher<<L as PlonkParameters<D>>::Field>,
    {
        let ctx = SubchainVerificationCtx {
            trusted_block,
            trusted_header_hash,
            target_block,
            target_header_hash,
        };

        let relative_block_nums = (0u64..(HEADERS_PER_JOB as u64)).collect_vec();

        // The last block in batch i and the start block in batch i+1 are shared.
        let (_, _, _, _, _, data_merkle_root) = self
            .mapreduce::<SubchainVerificationCtx, U64Variable, (
                BoolVariable,    // is_enabled (whether the leaf contains any valid headers)
                U64Variable,     // first block's num
                Bytes32Variable, // first block's hash
                U64Variable,     // last block's num
                Bytes32Variable, // last block's hash
                Bytes32Variable, // data merkle root
            ), C, BATCH_SIZE, _, _>(
                ctx.clone(),
                relative_block_nums,
                |map_ctx, map_relative_block_nums, builder| {

                    let target_header_hash = ctx.target_header_hash;
                    let target_block = ctx.target_block;

                    // Note: map_relative_block_nums is inclusive of the last block.
                    let mut input_stream = VariableStream::new();
                    let start_block =
                        builder.add(map_ctx.trusted_block, map_relative_block_nums.as_vec()[0]);
                    let last_block = builder.add(
                        map_ctx.trusted_block,
                        map_relative_block_nums.as_vec()[BATCH_SIZE - 1],
                    );

                    let true_var = builder._true();

                    let one = builder.constant::<U64Variable>(1u64);

                    // Add 1 to last_block to match Celestia's format (exclusive of last_block).
                    // Note: last_block - start_block = BATCH_SIZE
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
                    // If the start_block = map_ctx.target_block, we still verify the prev_header_proof against the target_block in reduce.
                    let mut is_enabled = builder.lt(start_block, map_ctx.target_block);
                    let is_batch_enabled = is_enabled;

                    let mut curr_header = batch_start_header;

                    let last_block_to_process = builder.sub(target_block, one);
                    // Verify all data_hash_proofs against headers from prev_header_proofs.
                    for i in 0..BATCH_SIZE {
                        let is_disabled = builder.not(is_enabled);
                        // target_block - 1 is the last valid leaf.
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
                        let root_matches_end_header = builder.is_equal(prev_header_proof_root, target_header_hash);
                        // NOT is_valid_leaf || root_matches_end_header must be true.
                        let end_header_check = builder.or(is_not_last_valid_leaf, root_matches_end_header);
                        builder.assert_is_equal(end_header_check, true_var);

                        // Move curr_prev_header to prev_header_proof_root.
                        curr_header = prev_header_proof_root;
                        // Set is_enabled to false if this is the last valid leaf.
                        is_enabled = builder.and(is_enabled, is_not_last_valid_leaf);
                    }

                    // Select the min of the target block and the end block in the batch.
                    let is_less_than_target = builder.lte(batch_end_block, map_ctx.target_block);
                    let end_block_num =
                        builder.select(is_less_than_target, batch_end_block, map_ctx.target_block);

                    // Note: We will only inner hash the data_merkle_root if its start_block is < target_block.
                    let data_merkle_root = builder.get_data_commitment::<BATCH_SIZE>(
                        &data_comm_proof.data_hashes,
                        start_block,
                        end_block_num,
                    );

                    (
                        is_batch_enabled,
                        start_block,
                        batch_start_header,
                        last_block,
                        batch_end_header,
                        data_merkle_root,
                    )
                },
                |_, left_output, right_output, builder| {
                    let (
                        left_is_batch_enabled,
                        left_start_block,
                        left_batch_start_header,
                        left_last_block,
                        left_batch_end_header,
                        left_data_merkle_root,
                    ) = left_output;

                    let (
                        right_is_batch_enabled,
                        right_start_block,
                        right_batch_start_header,
                        right_last_block,
                        right_batch_end_header,
                        right_data_merkle_root,
                    ) = right_output;

                    let false_var = builder._false();

                    let right_empty = builder.is_equal(right_is_batch_enabled, false_var);

                    // Check to see if the left and right nodes are correctly linked.
                    let nodes_linked =
                        builder.is_equal(left_batch_end_header, right_batch_start_header);

                    let one = builder.one();
                    let expected_block_num = builder.sub(right_start_block, one);
                    let nodes_sequential = builder.is_equal(left_last_block, expected_block_num);

                    let nodes_correctly_linked = builder.and(nodes_linked, nodes_sequential);

                    let link_check = builder.or(right_empty, nodes_correctly_linked);
                    let true_const = builder._true();
                    builder.assert_is_equal(link_check, true_const);

                    let end_block = builder.select(right_empty, left_last_block, right_last_block);
                    let end_header_hash =
                        builder.select(right_empty, left_batch_end_header, right_batch_end_header);

                    let mut data_root_bytes = left_data_merkle_root.as_bytes().to_vec();
                    data_root_bytes.extend(&right_data_merkle_root.as_bytes());

                    let computed_data_merkle_root = builder.inner_hash(&left_data_merkle_root, &right_data_merkle_root);

                    // If the right node is empty, then the data_merkle_root is the left node's data_merkle_root.
                    let data_merkle_root = builder.select(
                        right_empty,
                        left_data_merkle_root,
                        computed_data_merkle_root,
                    );

                    let either_enabled = builder.or(left_is_batch_enabled, right_is_batch_enabled);

                    (
                        either_enabled,
                        left_start_block,
                        left_batch_start_header,
                        end_block,
                        end_header_hash,
                        data_merkle_root,
                    )
                },
            );

        data_merkle_root
    }
}
