use plonky2::plonk::config::{AlgebraicHasher, GenericConfig};
use plonky2x::backend::circuit::{Circuit, PlonkParameters};
use plonky2x::frontend::uint::uint64::U64Variable;
use plonky2x::frontend::vars::{ArrayVariable, Bytes32Variable, EvmVariable};
use plonky2x::prelude::*;
use tendermint::merkle::HASH_SIZE;
use zk_tendermint::consts::*;

use crate::commitment::DataCommitmentOffchainInputs;
use crate::vars::{DataCommitmentProofVariable, MapReduceSubchainVariable};

#[derive(Clone, Debug, CircuitVariable)]
pub struct SubchainVerificationCtx {
    pub start_block: U64Variable,
    pub start_header_hash: Bytes32Variable,
    pub end_block: U64Variable,
    pub end_header_hash: Bytes32Variable,
}

pub trait DataCommitmentBuilder<L: PlonkParameters<D>, const D: usize> {
    /// Encodes the data hash and height into a tuple.
    /// Spec: https://github.com/celestiaorg/celestia-core/blob/6933af1ead0ddf4a8c7516690e3674c6cdfa7bd8/rpc/core/blocks.go#L325-L334
    fn encode_data_root_tuple(
        &mut self,
        data_hash: &Bytes32Variable,
        height: &U64Variable,
    ) -> BytesVariable<ENC_DATA_ROOT_TUPLE_SIZE_BYTES>;

    /// Compute the data commitment from start_block to end_block. Assumes the data hashes correspond to the blocks from start_block to end_block.
    fn get_data_commitment<const MAX_LEAVES: usize>(
        &mut self,
        data_hashes: &ArrayVariable<Bytes32Variable, MAX_LEAVES>,
        start_block: U64Variable,
        end_block: U64Variable,
    ) -> Bytes32Variable;

    /// Verify the chain of headers is linked for the subrange specified in data_comm_proof & generate the subrange's data_merkle_root. Skips verification after global_end_block.
    ///
    /// Specifically, a MapReduce circuit with <NB_MAP_JOBS=4, BATCH_SIZE=4> over blocks [0, 16) will invoke prove_subchain 4 times. Each of the prove_subchain calls
    /// over [0, 4), [4, 8), [8, 12), [12, 16) will 1) prove the chain of headers are linked and 2) output the corresponding data_merkle_root.
    fn prove_subchain<const BATCH_SIZE: usize>(
        &mut self,
        data_comm_proof: &DataCommitmentProofVariable<BATCH_SIZE>,
        global_end_block: &U64Variable,
        global_end_header_hash: &Bytes32Variable,
    ) -> MapReduceSubchainVariable;

    /// Verify the chain of headers is linked from start_block to end_block, and generate the corresponding data_merkle_root.
    /// NB_MAP_JOBS * BATCH_SIZE is the maximum range of blocks that can be included in the data commitment.
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
        let mut encoded_tuple = Vec::new();

        // Encode the height.
        let encoded_height = height.encode(self);

        // Pad the abi.encodePacked(height) to 32 bytes. Height is 8 bytes, pad with 32 - 8 = 24 bytes.
        encoded_tuple.extend(
            self.constant::<ArrayVariable<ByteVariable, 24>>(vec![0u8; 24])
                .as_vec(),
        );

        // Add the abi.encodePacked(height) to the tuple.
        encoded_tuple.extend(encoded_height);

        // Add the data hash to the tuple.
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
        let num_blocks = self.sub(end_block, start_block);
        let mut leaves = Vec::new();

        // Compute the leaves of the merkle tree.
        for i in 0..MAX_LEAVES {
            let curr_idx = self.constant::<U64Variable>(i as u64);
            let block_height = self.add(start_block, curr_idx);

            // Each leaf in Blobstream is abi.encodePacked(height, data_hash).
            leaves.push(self.encode_data_root_tuple(&data_hashes[i], &block_height));
        }

        let mut leaves_enabled = Vec::new();
        let mut is_enabled = self.constant::<BoolVariable>(true);
        for i in 0..MAX_LEAVES {
            leaves_enabled.push(is_enabled);

            let num_blocks_so_far = self.constant::<U64Variable>((i + 1) as u64);

            let is_last_valid_leaf = self.is_equal(num_blocks, num_blocks_so_far);
            let is_not_last_valid_leaf = self.not(is_last_valid_leaf);

            // Mark the first num_blocks leaves as enabled.
            is_enabled = self.and(is_enabled, is_not_last_valid_leaf);
        }

        // Compute the root of the merkle tree over the first num_blocks leaves.
        self.compute_root_from_leaves::<MAX_LEAVES, ENC_DATA_ROOT_TUPLE_SIZE_BYTES>(
            leaves,
            leaves_enabled,
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

        // Path of the data_hash against a Tendermint header.
        let data_hash_path =
            self.constant::<ArrayVariable<BoolVariable, 4>>(vec![false, true, true, false]);
        // Path of the last_block_id against a Tendermint header.
        let last_block_id_path =
            self.constant::<ArrayVariable<BoolVariable, 4>>(vec![false, false, true, false]);

        // If batch_start_block < global_end_block, this batch has headers that need to be verified.
        let is_batch_enabled = self.lt(batch_start_block, *global_end_block);

        let mut curr_header = batch_start_header_hash;
        let mut curr_block_enabled = is_batch_enabled;
        let last_block_to_process = self.sub(*global_end_block, one);

        // Verify all headers in the batch. If last_block_to_process < batch_end_block, stop verifying at last_block_to_process.
        for i in 0..BATCH_SIZE {
            let curr_idx = self.constant::<U64Variable>(i as u64);
            let curr_block = self.add(batch_start_block, curr_idx);

            let curr_block_disabled = self.not(curr_block_enabled);
            let is_last_valid_leaf = self.is_equal(last_block_to_process, curr_block);
            let is_not_last_valid_leaf = self.not(is_last_valid_leaf);

            // The computed root of the data_hash_proof should be the hash of block (start + i + 1).
            let data_hash_proof_root = self
                .get_root_from_merkle_proof::<HEADER_PROOF_DEPTH, PROTOBUF_HASH_SIZE_BYTES>(
                    &data_comm_proof.data_hash_proofs[i],
                    &data_hash_path,
                );
            // The computed root of the last_block_id_proof should be the hash of block (start + i + 1).
            let last_block_id_proof_root = self
                .get_root_from_merkle_proof::<HEADER_PROOF_DEPTH, PROTOBUF_BLOCK_ID_SIZE_BYTES>(
                    &data_comm_proof.last_block_id_proofs[i],
                    &last_block_id_path,
                );

            // Extract the header hash of block (start + i) from the protobuf encoded last block id proof.
            let header_hash = &data_comm_proof.last_block_id_proofs[i].leaf[2..2 + HASH_SIZE];

            // Verify the data hash proof against the header hash of block (start + i).
            let is_valid_data_hash = self.is_equal(data_hash_proof_root, header_hash.into());
            // Either this leaf is disabled or the data hash proof is valid.
            let data_hash_check = self.or(curr_block_disabled, is_valid_data_hash);
            self.assert_is_equal(data_hash_check, true_bool);

            // Verify the header chain.

            // 1) Verify the curr_header matches the extracted header_hash.
            let is_valid_prev_header = self.is_equal(curr_header, header_hash.into());
            // Either this leaf is disabled or the prev header matches.
            let prev_header_check = self.or(curr_block_disabled, is_valid_prev_header);
            self.assert_is_equal(prev_header_check, true_bool);

            // 2) If is_last_valid_leaf is true, then the root of the last_block_id_proof must be the end_header.
            let root_matches_end_header =
                self.is_equal(last_block_id_proof_root, *global_end_header_hash);
            // If this is the last valid leaf, then the last_block_id_proof_root must be the global_end_header.
            let end_header_check = self.or(is_not_last_valid_leaf, root_matches_end_header);
            self.assert_is_equal(end_header_check, true_bool);

            // Move curr_prev_header to last_block_id_proof_root.
            curr_header = last_block_id_proof_root;
            // Set is_enabled to false if this is the last valid leaf.
            curr_block_enabled = self.and(curr_block_enabled, is_not_last_valid_leaf);
        }

        // Select the min of the target block and the end block in the batch.
        let is_less_than_target = self.lte(batch_end_block, *global_end_block);
        let end_block_num = self.select(is_less_than_target, batch_end_block, *global_end_block);

        // Generate the data_merkle_root for the batch. If the batch is disabled
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
        let ctx = SubchainVerificationCtx {
            start_block,
            start_header_hash,
            end_block,
            end_header_hash,
        };

        let total_headers = NB_MAP_JOBS * BATCH_SIZE;

        let relative_block_nums = (0u64..(total_headers as u64)).collect::<Vec<_>>();

        // The last block in batch i and the start block in batch i+1 are shared.
        let result = self
            .mapreduce::<SubchainVerificationCtx, U64Variable, MapReduceSubchainVariable, C, BATCH_SIZE, _, _>(
                ctx.clone(),
                relative_block_nums,
                |map_ctx, map_relative_block_nums, builder| {
                    let one = builder.constant::<U64Variable>(1u64);

                    let global_end_header_hash = map_ctx.end_header_hash;
                    let global_end_block = map_ctx.end_block;

                    // map_relative_block_nums is a [U64Variable; BATCH_SIZE]
                    let start_block =
                        builder.add(map_ctx.start_block, map_relative_block_nums.as_vec()[0]);

                    let last_block = builder.add(
                        map_ctx.start_block,
                        map_relative_block_nums.as_vec()[BATCH_SIZE - 1],
                    );

                    // batch_end_block - start_block = BATCH_SIZE.
                    let batch_end_block = builder.add(last_block, one);

                    let past_global_end = builder.gt(batch_end_block, global_end_block);

                    // If batch_end_block > global_end_block, then the data_commitment's end is the global_end_block.
                    let query_end_block = builder.select(past_global_end, global_end_block, batch_end_block);

                    let mut input_stream = VariableStream::new();
                    input_stream.write(&start_block);
                    input_stream.write(&query_end_block);

                    let data_comm_fetcher = DataCommitmentOffchainInputs::<BATCH_SIZE> {};
                    let output_stream = builder
                        .async_hint(input_stream, data_comm_fetcher);

                    // If batch_end_block > global_end_block, data_comm_proof will have dummy values.
                    // This is because prove_subchain only checks up to global_end_block, and doing so reduces RPC calls.
                    let data_comm_proof = output_stream
                        .read::<DataCommitmentProofVariable<BATCH_SIZE>>(builder);
                    let _ = output_stream.read::<Bytes32Variable>(builder);

                    builder.prove_subchain(&data_comm_proof, &global_end_block, &global_end_header_hash)
                },
                |_, left_subchain, right_subchain, builder| {
                    let false_var = builder._false();

                    let right_empty = builder.is_equal(right_subchain.is_enabled, false_var);

                    // Check to see if the left and right nodes are correctly linked.
                    let nodes_linked =
                        builder.is_equal(left_subchain.end_header, right_subchain.start_header);

                    let nodes_sequential = builder.is_equal(left_subchain.end_block, right_subchain.start_block);

                    let nodes_correctly_linked = builder.and(nodes_linked, nodes_sequential);

                    let link_check = builder.or(right_empty, nodes_correctly_linked);
                    let true_const = builder._true();
                    builder.assert_is_equal(link_check, true_const);

                    let end_block = builder.select(right_empty, left_subchain.end_block, right_subchain.end_block);
                    let end_header_hash =
                        builder.select(right_empty, left_subchain.end_header, right_subchain.end_header);

                    // Call regular SHA to avoid allocating a Curta gadget.
                    let one_byte = ByteVariable::constant(builder, 1u8);
                    let mut encoded_leaf = vec![one_byte];
                    // Append the left bytes to the one byte.
                    encoded_leaf.extend(left_subchain.data_merkle_root.as_bytes().to_vec());
                    // Append the right bytes to the bytes so far.
                    encoded_leaf.extend(right_subchain.data_merkle_root.as_bytes().to_vec());

                    let computed_data_merkle_root = builder.sha256(&encoded_leaf);

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

// To run tests with logs (i.e. to see proof generation time), set the environment variable `RUST_LOG=debug` before the test command.
// Alternatively, add env::set_var("RUST_LOG", "debug") to the top of the test.
#[cfg(test)]
pub(crate) mod tests {
    use std::env;

    use ethers::types::H256;
    use plonky2x::backend::circuit::DefaultParameters;
    use tokio::runtime::Runtime;
    use zk_tendermint::input::utils::convert_to_h256;
    use zk_tendermint::input::InputDataFetcher;

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
        env::set_var("RPC_MOCHA_4", "fixture"); // Use fixture during testing
        let mut input_data_fetcher = InputDataFetcher::new();

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

        // TODO: Remove clone if performance is an issue.
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
