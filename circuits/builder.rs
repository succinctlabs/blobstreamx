use plonky2x::backend::circuit::{Circuit, PlonkParameters};
use plonky2x::frontend::merkle::tendermint::TendermintMerkleTree;
use plonky2x::frontend::uint::uint64::U64Variable;
use plonky2x::frontend::vars::{ArrayVariable, Bytes32Variable, EvmVariable};
use plonky2x::prelude::plonky2::plonk::config::{AlgebraicHasher, GenericConfig};
use plonky2x::prelude::*;
use tendermint::merkle::HASH_SIZE;

use crate::consts::*;
use crate::data_commitment::DataCommitmentOffchainInputs;
use crate::vars::{DataCommitmentProofVariable, MapReduceSubchainVariable};

/// Shared context across all data commitment mapreduce jobs.
#[derive(Clone, Debug, CircuitVariable)]
pub struct DataCommitmentSharedCtx {
    pub start_block: U64Variable,
    pub start_header_hash: Bytes32Variable,
    pub end_block: U64Variable,
    pub end_header_hash: Bytes32Variable,
}

pub trait DataCommitmentBuilder<L: PlonkParameters<D>, const D: usize> {
    /// Encodes the data hash and height as a tuple with abi.encode(height, data_hash).
    /// Spec: https://github.com/celestiaorg/celestia-core/blob/6933af1ead0ddf4a8c7516690e3674c6cdfa7bd8/rpc/core/blocks.go#L325-L334
    fn encode_data_root_tuple(
        &mut self,
        data_hash: &Bytes32Variable,
        height: &U64Variable,
    ) -> BytesVariable<ENC_DATA_ROOT_TUPLE_SIZE_BYTES>;

    /// Compute the data commitment from start_block to end_block. Each leaf in the merkle tree is abi.encode(data_hash, height).
    /// Note: Data commitment is exclusive of end_block.
    /// MAX_LEAVES is the maximum range of blocks that can be included in the data commitment.
    fn get_data_commitment<const MAX_LEAVES: usize>(
        &mut self,
        data_hashes: &ArrayVariable<Bytes32Variable, MAX_LEAVES>,
        start_block: U64Variable,
        end_block: U64Variable,
    ) -> Bytes32Variable;

    /// Verify the chain of headers is linked for the subrange in the data commitment proof & generate the subrange's data_merkle_root.
    /// Verify the header at global_end_block is the global_end_header_hash and don't verify blocks after global_end_block.
    ///
    /// Specifically, a MapReduce circuit with <NB_MAP_JOBS=4, BATCH_SIZE=4> over blocks [0, 16) will invoke prove_subchain 4 times. Each of the 4 prove_subchain calls
    /// over [0, 4), [4, 8), [8, 12), [12, 16) will 1) prove the subchain of headers are linked and 2) output their corresponding data_merkle_root.
    fn prove_subchain<const BATCH_SIZE: usize>(
        &mut self,
        data_comm_proof: &DataCommitmentProofVariable<BATCH_SIZE>,
        global_end_block: &U64Variable,
        global_end_header_hash: &Bytes32Variable,
    ) -> MapReduceSubchainVariable;

    /// Verify the chain of headers is linked from start_block to end_block, and generate the corresponding data_merkle_root.
    /// NB_MAP_JOBS * BATCH_SIZE is the maximum range of blocks that can be included in the data commitment.
    /// Note: Data commitment is exclusive of end_block.
    /// mapreduce is used to parallelize the verification of the chain of headers, by splitting the range of blocks into NB_MAP_JOBS batches of BATCH_SIZE blocks.
    fn prove_data_commitment<C: Circuit, const NB_MAP_JOBS: usize, const BATCH_SIZE: usize>(
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

impl<L: PlonkParameters<D>, const D: usize> DataCommitmentBuilder<L, D> for CircuitBuilder<L, D> {
    fn encode_data_root_tuple(
        &mut self,
        data_hash: &Bytes32Variable,
        height: &U64Variable,
    ) -> BytesVariable<ENC_DATA_ROOT_TUPLE_SIZE_BYTES> {
        // Encode the data hash and height into a tuple: abi.encode(height, data_hash).
        let mut encoded_tuple = Vec::new();

        // Encode the height with encodePacked.
        let encoded_height = height.encode(self);

        // Pad abi.encodePacked(height) to 32 bytes. Height is 8 bytes, pad with 32 - 8 = 24 bytes.
        encoded_tuple.extend(
            self.constant::<ArrayVariable<ByteVariable, 24>>(vec![0u8; 24])
                .as_vec(),
        );
        encoded_tuple.extend(encoded_height);
        encoded_tuple.extend(data_hash.as_bytes().to_vec());

        // Convert Vec<ByteVariable> to BytesVariable<64>.
        BytesVariable::<ENC_DATA_ROOT_TUPLE_SIZE_BYTES>(encoded_tuple.try_into().unwrap())
    }

    fn get_data_commitment<const MAX_LEAVES: usize>(
        &mut self,
        data_hashes: &ArrayVariable<Bytes32Variable, MAX_LEAVES>,
        start_block: U64Variable,
        end_block: U64Variable,
    ) -> Bytes32Variable {
        // If end_block < start_block, then this data commitment will be marked as disabled, and the
        // output of this function is not used. Therefore, the logic assumes
        // nb_blocks is always positive.
        let nb_blocks_in_batch = self.sub(end_block, start_block);
        self.watch(&nb_blocks_in_batch, "nb_blocks_in_batch");

        // Note: nb_blocks_in_batch is assumed to be less than 2^32 (which is a reasonable
        // assumption for any data commitment).
        let nb_blocks_in_batch = nb_blocks_in_batch.limbs[0].variable;
        let mut leaves = Vec::new();

        // Compute the leaves of the merkle tree.
        for i in 0..MAX_LEAVES {
            let curr_idx = self.constant::<U64Variable>(i as u64);
            let block_height = self.add(start_block, curr_idx);

            // Each leaf in Blobstream is abi.encodePacked(height, data_hash).
            leaves.push(self.encode_data_root_tuple(&data_hashes[i], &block_height));
        }

        // Compute the root of the merkle tree over the first num_blocks leaves.
        // Note: If nb_blocks_in_batch is larger than MAX_LEAVES, this function will
        // mark all leaves as enabled and compute the root of the merkle tree over all leaves.
        self.compute_root_from_leaves::<MAX_LEAVES, ENC_DATA_ROOT_TUPLE_SIZE_BYTES>(
            ArrayVariable::<BytesVariable<64>, MAX_LEAVES>::from(leaves),
            nb_blocks_in_batch,
        )
    }

    fn prove_subchain<const BATCH_SIZE: usize>(
        &mut self,
        data_comm_proof: &DataCommitmentProofVariable<BATCH_SIZE>,
        global_end_block: &U64Variable,
        global_end_header_hash: &Bytes32Variable,
    ) -> MapReduceSubchainVariable {
        let one = self.constant::<U64Variable>(1u64);
        let true_bool = self._true();

        // Get the start block, start header, end block, and end header from the data_comm_proof.
        let batch_start_block = data_comm_proof.start_block_height;
        let batch_start_header_hash = data_comm_proof.start_header;
        let batch_end_block = data_comm_proof.end_block_height;
        let batch_end_header_hash = data_comm_proof.end_header;

        // Path of the data_hash and last_block_id against the Tendermint header.
        let data_hash_path =
            self.constant::<ArrayVariable<BoolVariable, 4>>(vec![false, true, true, false]);
        let last_block_id_path =
            self.constant::<ArrayVariable<BoolVariable, 4>>(vec![false, false, true, false]);

        // If batch_start_block < global_end_block, this batch has headers that need to be verified.
        // If is_batch_enabled is false, in the reduce stage the batch will be considered empty and skipped.
        let is_batch_enabled = self.lt(batch_start_block, *global_end_block);
        let mut curr_block_enabled = is_batch_enabled;
        let mut curr_header = batch_start_header_hash;
        let last_block_to_process = self.sub(*global_end_block, one);

        // Verify all headers in the batch. If last_block_to_process < batch_end_block, stop verifying at last_block_to_process.
        for i in 0..BATCH_SIZE {
            let loop_idx = self.constant::<U64Variable>(i as u64);
            let curr_idx = self.add(batch_start_block, loop_idx);

            let curr_block_disabled = self.not(curr_block_enabled);
            let is_last_block = self.is_equal(last_block_to_process, curr_idx);
            let is_not_last_block = self.not(is_last_block);

            // Root of data_hash_proofs[i] should be the hash of block curr_idx.
            let data_hash_proof_root = self
                .get_root_from_merkle_proof::<HEADER_PROOF_DEPTH, PROTOBUF_HASH_SIZE_BYTES>(
                    &data_comm_proof.data_hash_proofs[i],
                    &data_hash_path,
                );
            // Root of last_block_id_proofs[i] should be the hash of block curr_idx+1.
            let last_block_id_proof_root = self
                .get_root_from_merkle_proof::<HEADER_PROOF_DEPTH, PROTOBUF_BLOCK_ID_SIZE_BYTES>(
                    &data_comm_proof.last_block_id_proofs[i],
                    &last_block_id_path,
                );

            // Extract the previous header hash from the leaf of last_block_id_proof, and verify it is equal to the header hash of block curr_idx.
            // Note: The leaf of the last_block_id_proof against block curr_idx+1 is the protobuf-encoded last_block_id, which contains the header hash of block curr_idx at [2..2+HASH_SIZE].
            // Always passes if curr_block >= last_block_to_process (curr_block_disabled).
            let header_hash = &data_comm_proof.last_block_id_proofs[i].leaf[2..2 + HASH_SIZE];
            let is_valid_prev_header = self.is_equal(curr_header, header_hash.into());
            let prev_header_check = self.or(curr_block_disabled, is_valid_prev_header);
            self.assert_is_equal(prev_header_check, true_bool);

            // Verify the data hash proof is valid against block curr_idx.
            let is_data_hash_proof_valid = self.is_equal(data_hash_proof_root, header_hash.into());
            let data_hash_check = self.or(curr_block_disabled, is_data_hash_proof_valid);
            self.assert_is_equal(data_hash_check, true_bool);

            // If this is the last valid block, verify the last_block_id_proof_root (header hash of block curr_idx+1) is equal to the global_end_header_hash.
            // This is the final step in the verification that global_start_block -> global_end_block is linked.
            let root_matches_end_header =
                self.is_equal(last_block_id_proof_root, *global_end_header_hash);
            let end_header_check = self.or(is_not_last_block, root_matches_end_header);
            self.assert_is_equal(end_header_check, true_bool);

            // Set current header to the hash of block curr_idx+1.
            curr_header = last_block_id_proof_root;
            // If this is the last valid block, set curr_block_enabled to false.
            curr_block_enabled = self.and(curr_block_enabled, is_not_last_block);
        }

        // The end block of the batch's data_merkle_root is min(batch_end_block, global_end_block).
        // Compute the data_merkle_root for the batch.
        let is_less_than_target = self.lte(batch_end_block, *global_end_block);
        let end_block_num = self.select(is_less_than_target, batch_end_block, *global_end_block);
        let data_merkle_root = self.get_data_commitment::<BATCH_SIZE>(
            &data_comm_proof.data_hashes,
            batch_start_block,
            end_block_num,
        );

        MapReduceSubchainVariable {
            is_enabled: is_batch_enabled,
            start_block: batch_start_block,
            start_header: batch_start_header_hash,
            end_block: batch_end_block,
            end_header: batch_end_header_hash,
            data_merkle_root,
        }
    }

    fn prove_data_commitment<C: Circuit, const NB_MAP_JOBS: usize, const BATCH_SIZE: usize>(
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
        let ctx = DataCommitmentSharedCtx {
            start_block,
            start_header_hash,
            end_block,
            end_header_hash,
        };

        let max_num_blocks = NB_MAP_JOBS * BATCH_SIZE;
        let relative_block_nums = (0u64..(max_num_blocks as u64)).collect::<Vec<_>>();

        let result = self
            .mapreduce::<DataCommitmentSharedCtx, U64Variable, MapReduceSubchainVariable, C, BATCH_SIZE, _, _>(
                ctx.clone(),
                relative_block_nums,
                |map_ctx, map_relative_block_nums, builder| {
                    // The following logic handles the map stage of the mapreduce.
                    //  1) Fetch the data commitment inputs for the batch.
                    //  2) Verify the chain of headers is linked for the batch.
                    //  3) Compute the corresponding data_merkle_root.

                    let one = builder.constant::<U64Variable>(1u64);
                    let global_end_header_hash = map_ctx.end_header_hash;
                    let global_end_block = map_ctx.end_block;

                    let start_block =
                        builder.add(map_ctx.start_block, map_relative_block_nums.as_vec()[0]);
                    let last_block = builder.add(
                        map_ctx.start_block,
                        map_relative_block_nums.as_vec()[BATCH_SIZE - 1],
                    );

                    // The query_end_block = min(batch_end_block, global_end_block) for fetching the data commitment inputs.
                    // If batch_end_block > global_end_block, data_comm_proof will be filled with dummy values.
                    // This is because prove_subchain only checks up to global_end_block, and doing so reduces RPC calls.
                    let batch_end_block = builder.add(last_block, one);
                    let past_global_end = builder.gt(batch_end_block, global_end_block);
                    let query_end_block = builder.select(past_global_end, global_end_block, batch_end_block);

                    // Fetch and read the data commitment inputs.
                    let mut input_stream = VariableStream::new();
                    input_stream.write(&start_block);
                    input_stream.write(&query_end_block);
                    let data_comm_fetcher = DataCommitmentOffchainInputs::<BATCH_SIZE> {};
                    let output_stream = builder
                        .async_hint(input_stream, data_comm_fetcher);
                    let data_comm_proof = output_stream
                        .read::<DataCommitmentProofVariable<BATCH_SIZE>>(builder);
                    let _ = output_stream.read::<Bytes32Variable>(builder);

                    // Verify the chain of headers is linked for the batch & compute the corresponding data_merkle_root.
                    builder.prove_subchain(&data_comm_proof, &global_end_block, &global_end_header_hash)
                },
                |_, left_subchain, right_subchain, builder| {
                    // The following logic handles the reduce stage of the mapreduce.
                    //  1) Verify the left and right subchains are correctly linked.
                    //  2) Compute the combined data_merkle_root of the left and right subchains.

                    let false_var = builder._false();
                    let true_var = builder._true();
                    let is_right_subchain_disabled = builder.is_equal(right_subchain.is_enabled, false_var);

                    // Check the left and right subchains are correctly linked.
                    // Always passes if the right subchain is disabled.
                    let subchains_headers_linked =
                        builder.is_equal(left_subchain.end_header, right_subchain.start_header);
                    let subchains_blocks_linked = builder.is_equal(left_subchain.end_block, right_subchain.start_block);
                    let subchains_linked = builder.and(subchains_headers_linked, subchains_blocks_linked);
                    let link_check = builder.or(is_right_subchain_disabled, subchains_linked);
                    builder.assert_is_equal(link_check, true_var);

                    // Compute Tendermint inner_hash(left_subchain.data_merkle_root, right_subchain.data_merkle_root).
                    let one_byte = ByteVariable::constant(builder, 1u8);
                    let mut encoded_leaf = vec![one_byte];
                    encoded_leaf.extend(left_subchain.data_merkle_root.as_bytes().to_vec());
                    encoded_leaf.extend(right_subchain.data_merkle_root.as_bytes().to_vec());
                    // Note: Use sha256 instead of inner_hash to avoid allocating a Curta gadget.
                    let computed_data_merkle_root = builder.sha256(&encoded_leaf);

                    // If the right node is empty, then the data_merkle_root is the left node's data_merkle_root.
                    let data_merkle_root = builder.select(
                        is_right_subchain_disabled,
                        left_subchain.data_merkle_root,
                        computed_data_merkle_root,
                    );

                    MapReduceSubchainVariable {
                        // If the left_subchain is disabled, then the right_subchain is disabled.
                        is_enabled: left_subchain.is_enabled,
                        start_block: left_subchain.start_block,
                        start_header: left_subchain.start_header,
                        end_block: right_subchain.end_block,
                        end_header: right_subchain.end_header,
                        data_merkle_root,
                    }
                },
            );

        result.data_merkle_root
    }
}

// To run tests with logs (i.e. to see proof generation time), set the environment variable `RUST_LOG=debug` before the test command.
// Alternatively, add env::set_var("RUST_LOG", "debug") to the top of the test.
#[cfg(test)]
pub(crate) mod tests {
    use ethers::types::H256;
    use plonky2x::backend::circuit::DefaultParameters;
    use tendermintx::input::utils::convert_to_h256;
    use tendermintx::input::InputDataFetcher;
    use tokio::runtime::Runtime;

    use super::*;
    use crate::input::DataCommitmentInputs;
    use crate::vars::*;

    type L = DefaultParameters;
    type F = <L as PlonkParameters<D>>::Field;
    const D: usize = 2;

    fn generate_data_commitment_value_inputs<const MAX_LEAVES: usize>(
        start_height: usize,
        end_height: usize,
    ) -> (DataCommitmentProofValueType<MAX_LEAVES, F>, H256) {
        dotenv::dotenv().ok();
        let mut input_data_fetcher = InputDataFetcher::default();

        let rt = Runtime::new().expect("failed to create tokio runtime");

        let result = rt.block_on(async {
            input_data_fetcher
                .get_data_commitment_inputs::<MAX_LEAVES, F>(start_height as u64, end_height as u64)
                .await
        });

        (
            DataCommitmentProofValueType {
                data_hashes: convert_to_h256(result.2),
                start_block_height: (start_height as u64),
                start_header: H256::from_slice(&result.0),
                end_block_height: (end_height as u64),
                end_header: H256::from_slice(&result.1),
                data_hash_proofs: result.3,
                last_block_id_proofs: result.4,
            },
            H256(result.5),
        )
    }

    #[test]
    #[cfg_attr(feature = "ci", ignore)]
    fn test_get_data_commitment() {
        env_logger::try_init().unwrap_or_default();

        let mut builder = CircuitBuilder::<L, D>::new();

        const MAX_LEAVES: usize = 4;
        const NUM_BLOCKS: usize = 4;
        const START_BLOCK: usize = 10000;
        const END_BLOCK: usize = START_BLOCK + NUM_BLOCKS;

        let data_commitment_var = builder.read::<DataCommitmentProofVariable<MAX_LEAVES>>();

        let expected_data_commitment = builder.read::<Bytes32Variable>();

        let start_block = builder.constant::<U64Variable>(START_BLOCK as u64);
        let end_block = builder.constant::<U64Variable>(END_BLOCK as u64);
        let root_hash_target = builder.get_data_commitment::<MAX_LEAVES>(
            &data_commitment_var.data_hashes,
            start_block,
            end_block,
        );
        builder.assert_is_equal(root_hash_target, expected_data_commitment);

        let circuit = builder.build();

        let mut input = circuit.input();

        let inputs = generate_data_commitment_value_inputs(START_BLOCK, END_BLOCK);
        input.write::<DataCommitmentProofVariable<MAX_LEAVES>>(inputs.0);
        input.write::<Bytes32Variable>(inputs.1);
        let (proof, output) = circuit.prove(&input);
        circuit.verify(&proof, &input, &output);
    }

    #[test]
    #[cfg_attr(feature = "ci", ignore)]
    fn test_prove_header_chain() {
        env_logger::try_init().unwrap_or_default();

        let mut builder = CircuitBuilder::<L, D>::new();

        const MAX_LEAVES: usize = 4;
        const START_BLOCK: usize = 10000;
        const END_BLOCK: usize = START_BLOCK + MAX_LEAVES;

        let data_commitment_var = builder.read::<DataCommitmentProofVariable<MAX_LEAVES>>();

        builder.prove_subchain::<MAX_LEAVES>(
            &data_commitment_var,
            &data_commitment_var.end_block_height,
            &data_commitment_var.end_header,
        );

        let circuit = builder.build();

        let mut input = circuit.input();

        // Generate test cases from Celestia blocks:
        input.write::<DataCommitmentProofVariable<MAX_LEAVES>>(
            generate_data_commitment_value_inputs(START_BLOCK, END_BLOCK).0,
        );
        let (proof, output) = circuit.prove(&input);
        circuit.verify(&proof, &input, &output);
    }

    #[test]
    fn test_encode_data_root_tuple() {
        env_logger::try_init().unwrap_or_default();

        let mut builder = CircuitBuilder::<L, D>::new();

        let data_hash =
            builder.constant::<Bytes32Variable>(ethers::types::H256::from_slice(&[255u8; 32]));
        builder.watch(&data_hash, "data_hash");
        let height = builder.constant::<U64Variable>(256);
        builder.watch(&height, "height");
        let data_root_tuple = builder.encode_data_root_tuple(&data_hash, &height);
        builder.watch(&data_root_tuple, "data_root_tuple");
        builder.write(data_root_tuple);
        let circuit = builder.build();

        let mut expected_data_tuple_root = Vec::new();

        let expected_height = [
            0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 1, 0,
        ];

        // Compute the expected output for testing
        let expected_data_root = vec![
            255u8, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        ];

        expected_data_tuple_root.extend_from_slice(&expected_height);

        expected_data_tuple_root.extend_from_slice(&expected_data_root);

        let input = circuit.input();
        let (proof, mut output) = circuit.prove(&input);
        circuit.verify(&proof, &input, &output);

        let data_root_tuple_value =
            output.read::<ArrayVariable<ByteVariable, ENC_DATA_ROOT_TUPLE_SIZE_BYTES>>();
        assert_eq!(data_root_tuple_value, expected_data_tuple_root);

        println!("Verified proof");
    }
}
