use plonky2x::backend::circuit::PlonkParameters;
use plonky2x::frontend::ecc::ed25519::curve::curve_types::Curve;
use plonky2x::frontend::ecc::ed25519::curve::ed25519::Ed25519;

use plonky2x::frontend::uint::uint64::U64Variable;
use plonky2x::frontend::vars::{ArrayVariable, Bytes32Variable, EvmVariable};
use plonky2x::prelude::{BoolVariable, ByteVariable, BytesVariable, CircuitBuilder};
use tendermint::merkle::HASH_SIZE;

use crate::consts::{HEADER_PROOF_DEPTH, PROTOBUF_BLOCK_ID_SIZE_BYTES, PROTOBUF_HASH_SIZE_BYTES};
use crate::variables::DataCommitmentProofVariable;

pub trait DataCommitment<L: PlonkParameters<D>, const D: usize> {
    type Curve: Curve;

    /// Encodes the data hash and height into a tuple.
    /// Spec: https://github.com/celestiaorg/celestia-core/blob/6933af1ead0ddf4a8c7516690e3674c6cdfa7bd8/rpc/core/blocks.go#L325-L334
    fn encode_data_root_tuple(
        &mut self,
        data_hash: &Bytes32Variable,
        height: &U64Variable,
    ) -> BytesVariable<64>;

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
    /// prev_header_proofs are against [start_block + 1, end_block], data_hash_proofs are against [start_block, end_block - 1].
    fn prove_header_chain<const MAX_LEAVES: usize>(
        &mut self,
        input: DataCommitmentProofVariable<MAX_LEAVES>,
    );

    /// Prove the header chain from end_header to start_header & compute the data commitment.
    /// Note: Will only include the first [end_block - start_block] data_hashes.
    /// Note: start_block must be < end_block.
    fn prove_data_commitment<const MAX_LEAVES: usize>(
        &mut self,
        input: DataCommitmentProofVariable<MAX_LEAVES>,
    ) -> Bytes32Variable;
}

impl<L: PlonkParameters<D>, const D: usize> DataCommitment<L, D> for CircuitBuilder<L, D> {
    type Curve = Ed25519;

    fn encode_data_root_tuple(
        &mut self,
        data_hash: &Bytes32Variable,
        height: &U64Variable,
    ) -> BytesVariable<64> {
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
        BytesVariable::<64>(encoded_tuple.try_into().unwrap())
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
            let curr_idx = self.constant::<U64Variable>(i.into());
            let block_height = self.add(start_block, curr_idx);
            // Encode the data hash and height into a tuple.
            leaves.push(self.encode_data_root_tuple(&data_hashes[i], &block_height));
        }

        let mut leaves_enabled = Vec::new();
        let mut is_enabled = self.constant::<BoolVariable>(true);
        for i in 0..MAX_LEAVES {
            leaves_enabled.push(is_enabled);

            // Number of leaves included in the data commitment so far (including this leaf).
            let num_leaves_so_far = self.constant::<U64Variable>((i + 1).into());
            // If at the last_valid_leaf, must flip is_enabled to false.
            let is_last_valid_leaf = self.is_equal(num_leaves, num_leaves_so_far);
            let is_not_last_valid_leaf = self.not(is_last_valid_leaf);

            is_enabled = self.and(is_enabled, is_not_last_valid_leaf);
        }

        // Return the root hash.
        self.compute_root_from_leaves::<MAX_LEAVES, 64>(leaves, leaves_enabled)
    }
    fn prove_header_chain<const MAX_LEAVES: usize>(
        &mut self,
        input: DataCommitmentProofVariable<MAX_LEAVES>,
    ) {
        let true_var = self._true();
        // Verify prev_header_proofs from end_header -> start_header.
        // Ignore prev_header_proofs from start_header + MAX_LEAVES -> end_header.
        // let mut prev_header_proofs = input.prev_header_proofs.as_vec();
        // prev_header_proofs.reverse();

        let num_leaves = self.sub(input.end_block_height, input.start_block_height);

        // Verify data_hash_proofs against extracted header hashes from prev_header_proofs.
        // Note: Verify the first (end_block - start_block) data_hash_proofs.
        let mut is_enabled = self.constant::<BoolVariable>(true);
        let mut curr_prev_header = input.start_header;
        for i in 0..MAX_LEAVES {
            let is_disabled = self.not(is_enabled);

            // Number of leaves included in the data hash and prove header chain computation so far (including the current leaf).
            let num_leaves_so_far = self.constant::<U64Variable>((i + 1).into());

            // If at the last_valid_leaf, flip is_enabled to false and check curr_prev_header against the end_header.
            let is_last_valid_leaf = self.is_equal(num_leaves, num_leaves_so_far);
            let is_not_last_valid_leaf = self.not(is_last_valid_leaf);

            let data_hash_proof = &input.data_hash_proofs[i];
            let prev_header_proof = &input.prev_header_proofs[i];
            // Extract the prev header hash from block (start + i + 1), which is the current header hash (start + i).
            let header_hash = prev_header_proof.leaf[2..2 + HASH_SIZE].into();

            let data_hash_proof_root = self
                .get_root_from_merkle_proof::<HEADER_PROOF_DEPTH, PROTOBUF_HASH_SIZE_BYTES>(
                    data_hash_proof,
                );
            let prev_header_proof_root = self
                .get_root_from_merkle_proof::<HEADER_PROOF_DEPTH, PROTOBUF_BLOCK_ID_SIZE_BYTES>(
                    prev_header_proof,
                );

            // Verify the data hash proof against the current header hash.
            let is_valid_data_hash = self.is_equal(data_hash_proof_root, header_hash);
            // NOT is_enabled || (data_hash_proof_root == header_hash) must be true.
            let data_hash_check = self.or(is_disabled, is_valid_data_hash);
            self.assert_is_equal(data_hash_check, true_var);

            // Verify the curr_prev_header matches the extracted curr_header_hash.
            let is_valid_prev_header = self.is_equal(curr_prev_header, header_hash);
            // NOT is_enabled || (curr_prev_header == header_hash) must be true.
            let prev_header_check = self.or(is_disabled, is_valid_prev_header);
            self.assert_is_equal(prev_header_check, true_var);

            // If is_last_valid_leaf is true, then the root of the prev_header_proof must be the end_header.
            let root_matches_end_header = self.is_equal(prev_header_proof_root, input.end_header);
            // NOT is_valid_leaf || root_matches_end_header must be true.
            let end_header_check = self.or(root_matches_end_header, is_not_last_valid_leaf);
            self.assert_is_equal(end_header_check, true_var);

            // Move curr_prev_header to prev_header_proof_root.
            curr_prev_header = prev_header_proof_root;

            // Set is_enabled to true while the current height < end height.
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
    use super::*;
    use plonky2x::backend::circuit::DefaultParameters;

    use crate::{
        commitment::DataCommitment,
        inputs::{generate_data_commitment_inputs, generate_expected_data_commitment},
        variables::DataCommitmentProofVariable,
    };

    type L = DefaultParameters;
    type F = <L as PlonkParameters<D>>::Field;
    const D: usize = 2;

    #[test]
    #[cfg_attr(feature = "ci", ignore)]
    fn test_prove_data_commitment() {
        env_logger::try_init().unwrap_or_default();

        let mut builder = CircuitBuilder::<L, D>::new();

        const MAX_LEAVES: usize = 4;
        const NUM_BLOCKS: usize = 4;
        const START_BLOCK: usize = 3800;
        const END_BLOCK: usize = START_BLOCK + NUM_BLOCKS;

        let data_commitment_var = builder.read::<DataCommitmentProofVariable<MAX_LEAVES>>();

        let expected_data_commitment = builder.read::<Bytes32Variable>();

        let root_hash_target = builder.prove_data_commitment::<MAX_LEAVES>(data_commitment_var);
        builder.assert_is_equal(root_hash_target, expected_data_commitment);

        let circuit = builder.build();

        let mut input = circuit.input();
        input.write::<DataCommitmentProofVariable<MAX_LEAVES>>(generate_data_commitment_inputs::<
            MAX_LEAVES,
            F,
        >(START_BLOCK, END_BLOCK));

        input.write::<Bytes32Variable>(generate_expected_data_commitment::<MAX_LEAVES, F>(
            START_BLOCK,
            END_BLOCK,
        ));
        let (proof, output) = circuit.prove(&input);
        circuit.verify(&proof, &input, &output);
    }

    #[test]
    #[cfg_attr(feature = "ci", ignore)]
    fn test_data_commitment() {
        env_logger::try_init().unwrap_or_default();

        let mut builder = CircuitBuilder::<L, D>::new();

        const MAX_LEAVES: usize = 4;
        const NUM_BLOCKS: usize = 4;
        const START_BLOCK: usize = 3800;
        const END_BLOCK: usize = START_BLOCK + NUM_BLOCKS;

        let data_commitment_var = builder.read::<DataCommitmentProofVariable<MAX_LEAVES>>();

        let expected_data_commitment = builder.read::<Bytes32Variable>();

        let start_block = builder.constant::<U64Variable>(START_BLOCK.into());
        let end_block = builder.constant::<U64Variable>(END_BLOCK.into());
        let root_hash_target = builder.get_data_commitment::<MAX_LEAVES>(
            &data_commitment_var.data_hashes,
            start_block,
            end_block,
        );
        builder.assert_is_equal(root_hash_target, expected_data_commitment);

        let circuit = builder.build();

        let mut input = circuit.input();
        input.write::<DataCommitmentProofVariable<MAX_LEAVES>>(generate_data_commitment_inputs::<
            MAX_LEAVES,
            F,
        >(START_BLOCK, END_BLOCK));
        input.write::<Bytes32Variable>(generate_expected_data_commitment::<MAX_LEAVES, F>(
            START_BLOCK,
            END_BLOCK,
        ));
        let (proof, output) = circuit.prove(&input);
        circuit.verify(&proof, &input, &output);
    }

    #[test]
    #[cfg_attr(feature = "ci", ignore)]
    fn test_prove_header_chain() {
        env_logger::try_init().unwrap_or_default();

        let mut builder = CircuitBuilder::<L, D>::new();

        const WINDOW_SIZE: usize = 4;
        const TRUSTED_BLOCK: usize = 3800;
        const CURRENT_BLOCK: usize = TRUSTED_BLOCK + WINDOW_SIZE;

        let data_commitment_var = builder.read::<DataCommitmentProofVariable<WINDOW_SIZE>>();

        builder.prove_header_chain::<WINDOW_SIZE>(data_commitment_var);

        let circuit = builder.build();

        let mut input = circuit.input();
        input.write::<DataCommitmentProofVariable<WINDOW_SIZE>>(generate_data_commitment_inputs::<
            WINDOW_SIZE,
            F,
        >(
            TRUSTED_BLOCK, CURRENT_BLOCK
        ));
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
        let height = builder.constant::<U64Variable>(256.into());
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

        let data_root_tuple_value = output.read::<ArrayVariable<ByteVariable, 64>>();
        assert_eq!(data_root_tuple_value, expected_data_tuple_root);

        println!("Verified proof");
    }
}
