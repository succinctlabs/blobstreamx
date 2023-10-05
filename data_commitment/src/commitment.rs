use celestia::consts::{
    ENC_DATA_ROOT_TUPLE_SIZE_BYTES, HEADER_PROOF_DEPTH, PROTOBUF_BLOCK_ID_SIZE_BYTES,
    PROTOBUF_HASH_SIZE_BYTES,
};
use celestia::variables::DataCommitmentProofVariable;
use plonky2x::backend::circuit::PlonkParameters;
use plonky2x::frontend::uint::uint64::U64Variable;
use plonky2x::frontend::vars::{ArrayVariable, Bytes32Variable, EvmVariable};
use plonky2x::prelude::{BoolVariable, ByteVariable, BytesVariable, CircuitBuilder};
use tendermint::merkle::HASH_SIZE;

pub trait DataCommitmentBuilder<L: PlonkParameters<D>, const D: usize> {
    /// Encodes the data hash and height into a tuple.
    /// Spec: https://github.com/celestiaorg/celestia-core/blob/6933af1ead0ddf4a8c7516690e3674c6cdfa7bd8/rpc/core/blocks.go#L325-L334
    fn encode_data_root_tuple(
        &mut self,
        data_hash: &Bytes32Variable,
        height: &U64Variable,
    ) -> BytesVariable<ENC_DATA_ROOT_TUPLE_SIZE_BYTES>;

    /// Compute the data commitment from the data hashes and block heights. MAX_LEAVES is the maximum number of leaves in the tree for the data commitment.
    /// Assumes the data hashes are already proven.
    fn get_data_commitment<const MAX_LEAVES: usize>(
        &mut self,
        data_hashes: &ArrayVariable<Bytes32Variable, MAX_LEAVES>,
        start_block: U64Variable,
        end_block: U64Variable,
    ) -> Bytes32Variable;

    /// Prove header chain from end_header to start_header & the block heights for the current header and the trusted header.
    /// Merkle prove the last block id against the current header, and the data hash for each header except the current header.
    /// prev_header_proofs are against (start_block + 1, end_block), data_hash_proofs are against (start_block, end_block - 1).
    fn prove_header_chain<const MAX_LEAVES: usize>(
        &mut self,
        input: DataCommitmentProofVariable<MAX_LEAVES>,
    );

    /// Prove the header chain from end_header to start_header & compute the data commitment.
    /// Note: Will only include the first (end_block - start_block) data_hashes.
    /// Note: start_block must be < end_block.
    fn prove_data_commitment<const MAX_LEAVES: usize>(
        &mut self,
        input: DataCommitmentProofVariable<MAX_LEAVES>,
    ) -> Bytes32Variable;
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
        let num_leaves = self.sub(end_block, start_block);
        let mut leaves = Vec::new();

        for i in 0..MAX_LEAVES {
            let curr_idx = self.constant::<U64Variable>(i as u64);
            let block_height = self.add(start_block, curr_idx);
            // Encode the data hash and height into a tuple.
            leaves.push(self.encode_data_root_tuple(&data_hashes[i], &block_height));
        }

        let mut leaves_enabled = Vec::new();
        let mut is_enabled = self.constant::<BoolVariable>(true);
        for i in 0..MAX_LEAVES {
            leaves_enabled.push(is_enabled);

            // Number of leaves included in the data commitment so far (including this leaf).
            let num_leaves_so_far = self.constant::<U64Variable>((i + 1) as u64);
            // If at the last_valid_leaf, must flip is_enabled to false.
            let is_last_valid_leaf = self.is_equal(num_leaves, num_leaves_so_far);
            let is_not_last_valid_leaf = self.not(is_last_valid_leaf);

            is_enabled = self.and(is_enabled, is_not_last_valid_leaf);
        }

        // Return the root hash.
        self.compute_root_from_leaves::<MAX_LEAVES, ENC_DATA_ROOT_TUPLE_SIZE_BYTES>(
            leaves,
            leaves_enabled,
        )
    }
    fn prove_header_chain<const MAX_LEAVES: usize>(
        &mut self,
        input: DataCommitmentProofVariable<MAX_LEAVES>,
    ) {
        let true_var = self._true();
        let num_leaves = self.sub(input.end_block_height, input.start_block_height);

        let data_hash_path =
            self.constant::<ArrayVariable<BoolVariable, 4>>(vec![false, true, true, false]);
        let last_block_id_path =
            self.constant::<ArrayVariable<BoolVariable, 4>>(vec![false, false, true, false]);

        // Verify the header chain of the first (end_block - start_block) headers.
        // is_enabled is true for the first (end_block - start_block) headers, and false for the rest.
        let mut is_enabled = self.constant::<BoolVariable>(true);
        let mut curr_header = input.start_header;
        for i in 0..MAX_LEAVES {
            let is_disabled = self.not(is_enabled);

            // Number of leaves included in the data hash and prove header chain computation so far (including the current leaf).
            let num_leaves_so_far = self.constant::<U64Variable>((i + 1) as u64);

            // If at the last_valid_leaf, flip is_enabled to false and verify end_header's prev_header is curr_header.
            let is_last_valid_leaf = self.is_equal(num_leaves, num_leaves_so_far);
            let is_not_last_valid_leaf = self.not(is_last_valid_leaf);

            // Header hash of block (start + i).
            let data_hash_proof_root = self
                .get_root_from_merkle_proof::<HEADER_PROOF_DEPTH, PROTOBUF_HASH_SIZE_BYTES>(
                    &input.data_hash_proofs[i],
                    &data_hash_path.clone(),
                );
            // Header hash of block (start + i + 1).
            let prev_header_proof_root = self
                .get_root_from_merkle_proof::<HEADER_PROOF_DEPTH, PROTOBUF_BLOCK_ID_SIZE_BYTES>(
                    &input.prev_header_proofs[i],
                    &last_block_id_path.clone(),
                );
            // Header hash of block (start + i).
            let header_hash = &input.prev_header_proofs[i].leaf[2..2 + HASH_SIZE];

            // Verify the data hash proof against the header hash of block (start + i).
            let is_valid_data_hash = self.is_equal(data_hash_proof_root, header_hash.into());
            // NOT is_enabled || (data_hash_proof_root == header_hash) must be true.
            let data_hash_check = self.or(is_disabled, is_valid_data_hash);
            self.assert_is_equal(data_hash_check, true_var);

            // Verify the header chain.
            // 1) Verify the curr_header matches the extracted header_hash.
            let is_valid_prev_header = self.is_equal(curr_header, header_hash.into());
            // NOT is_enabled || (curr_header == header_hash) must be true.
            let prev_header_check = self.or(is_disabled, is_valid_prev_header);
            self.assert_is_equal(prev_header_check, true_var);

            // 2) If is_last_valid_leaf is true, then the root of the prev_header_proof must be the end_header.
            let root_matches_end_header = self.is_equal(prev_header_proof_root, input.end_header);
            // NOT is_valid_leaf || root_matches_end_header must be true.
            let end_header_check = self.or(is_not_last_valid_leaf, root_matches_end_header);
            self.assert_is_equal(end_header_check, true_var);

            // Move curr_prev_header to prev_header_proof_root.
            curr_header = prev_header_proof_root;
            // Set is_enabled to false if this is the last valid leaf.
            is_enabled = self.and(is_enabled, is_not_last_valid_leaf);
        }
    }

    fn prove_data_commitment<const MAX_LEAVES: usize>(
        &mut self,
        input: DataCommitmentProofVariable<MAX_LEAVES>,
    ) -> Bytes32Variable {
        let false_var = self._false();
        // Assert start_block < end_block.
        let start_end_equal = self.is_equal(input.start_block_height, input.end_block_height);
        self.assert_is_equal(start_end_equal, false_var);

        // Compute the data commitment.
        let data_commitment = self.get_data_commitment::<MAX_LEAVES>(
            &input.data_hashes,
            input.start_block_height,
            input.end_block_height,
        );
        // Verify the header chain.
        self.prove_header_chain::<MAX_LEAVES>(input);

        // Return the data commitment.
        data_commitment
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

    use super::*;
    use crate::commitment::DataCommitment;
    use crate::input_data::utils::convert_to_h256;
    use crate::input_data::InputDataFetcher;
    use crate::variables::{DataCommitmentProofValueType, DataCommitmentProofVariable};

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

        let (result, start_header_hash, end_header_hash) = rt.block_on(async {
            let start_header = input_data_fetcher
                .get_header_from_number(start_height as u64)
                .await;
            let start_header_hash = H256::from_slice(start_header.hash().as_bytes());
            let end_header = input_data_fetcher
                .get_header_from_number(end_height as u64)
                .await;
            let end_header_hash = H256::from_slice(end_header.hash().as_bytes());
            let result = input_data_fetcher
                .get_data_commitment_inputs::<MAX_LEAVES, F>(
                    start_height as u64,
                    start_header_hash,
                    end_height as u64,
                    end_header_hash,
                )
                .await;
            (result, start_header_hash, end_header_hash)
        });

        (
            DataCommitmentProofValueType {
                data_hashes: convert_to_h256(result.0),
                start_block_height: (start_height as u64),
                start_header: start_header_hash,
                end_block_height: (end_height as u64),
                end_header: end_header_hash,
                data_hash_proofs: result.1,
                prev_header_proofs: result.2,
            },
            H256(result.3),
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

        builder.prove_header_chain::<MAX_LEAVES>(data_commitment_var);

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
