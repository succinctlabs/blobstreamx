//! This file implements methods for computing the Celestia data commitment within a circuit.
//!
//! TODO: fill in more detailed description etc.
//!
//! For more information about the Celestia data commitment, see:
//!
//! - https://github.com/celestiaorg/celestia-core/blob/main/rpc/core/blocks.go

use plonky2x::backend::circuit::PlonkParameters;
use plonky2x::frontend::ecc::ed25519::curve::curve_types::Curve;
use plonky2x::frontend::ecc::ed25519::curve::ed25519::Ed25519;
use plonky2x::frontend::uint::uint64::U64Variable;
use plonky2x::frontend::vars::{ArrayVariable, Bytes32Variable, EvmVariable};
use plonky2x::prelude::{BoolVariable, ByteVariable, BytesVariable, CircuitBuilder};
use tendermint::merkle::HASH_SIZE;

use crate::circuits::{DataCommitmentProofVariable, TendermintHeaderBuilder};
use crate::constants::{
    HEADER_PROOF_DEPTH, PROTOBUF_BLOCK_ID_SIZE_BYTES, PROTOBUF_HASH_SIZE_BYTES,
};

pub trait DataCommitmentBuilder<L: PlonkParameters<D>, const D: usize> {
    /// The curve used for the commitment.
    type Curve: Curve;

    /// Encodes the data hash and height into a tuple.
    ///
    /// Spec: https://github.com/celestiaorg/celestia-core/blob/6933af1ead0ddf4a8c7516690e3674c6cdfa7bd8/rpc/core/blocks.go#L325-L334
    fn encode_data_root_tuple(
        &mut self,
        data_hash: &Bytes32Variable,
        height: &U64Variable,
    ) -> BytesVariable<64>;

    /// Compute the data commitment from the data hashes and block heights.
    ///
    /// `WINDOW_RANGE` is the number of blocks in the data commitment. `NUM_LEAVES` is the number
    /// of leaves in the tree for the data commitment. Assumes the data hashes are already proven.
    fn get_data_commitment<const WINDOW_RANGE: usize, const NB_LEAVES: usize>(
        &mut self,
        data_hashes: &ArrayVariable<Bytes32Variable, WINDOW_RANGE>,
        start_block: U64Variable,
    ) -> Bytes32Variable;

    /// Prove header chain from `end_header` to `start_header` & the block heights for the current
    /// header and the trusted header. Merkle prove the last block id against the current header,
    /// and the data hash for each header except the current header.
    ///
    /// Note: `data_hash_proofs` and `prev_header_proofs` should be in order from `end_header` to
    /// `start_header`
    fn prove_header_chain<const WINDOW_RANGE: usize>(
        &mut self,
        input: DataCommitmentProofVariable<WINDOW_RANGE>,
    );

    /// Prove the header chain from `end_header` to `start_header` and compute the data commitment.
    fn prove_data_commitment<const WINDOW_RANGE: usize, const NB_LEAVES: usize>(
        &mut self,
        input: DataCommitmentProofVariable<WINDOW_RANGE>,
    ) -> Bytes32Variable;
}

impl<L: PlonkParameters<D>, const D: usize> DataCommitmentBuilder<L, D> for CircuitBuilder<L, D> {
    type Curve = Ed25519;

    fn encode_data_root_tuple(
        &mut self,
        data_hash: &Bytes32Variable,
        height: &U64Variable,
    ) -> BytesVariable<64> {
        let mut encoded_tuple = Vec::new();

        // Encode the height.
        let encoded_height = height.encode(self);

        // Pad the abi.encodePacked(height) to 32 bytes. Height is 8 bytes, so pad with 24 bytes.
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

    fn get_data_commitment<const WINDOW_RANGE: usize, const NB_LEAVES: usize>(
        &mut self,
        data_hashes: &ArrayVariable<Bytes32Variable, WINDOW_RANGE>,
        start_block: U64Variable,
    ) -> Bytes32Variable {
        // Construct the data commitment from the data hashes and block heights.
        let mut leaves = Vec::new();
        for i in 0..WINDOW_RANGE {
            let curr_idx = self.constant::<U64Variable>(i.into());
            let block_height = self.add(start_block, curr_idx);
            leaves.push(self.encode_data_root_tuple(&data_hashes[i], &block_height));
        }
        leaves.resize(NB_LEAVES, self.constant::<BytesVariable<64>>([0u8; 64]));

        // Compute the leaves enabled.
        let mut leaves_enabled = Vec::new();
        leaves_enabled.resize(WINDOW_RANGE, self.constant::<BoolVariable>(true));
        leaves_enabled.resize(NB_LEAVES, self.constant::<BoolVariable>(false));

        // Return the root hash.
        self.compute_root_from_leaves::<NB_LEAVES, 64>(leaves, leaves_enabled)
    }
    fn prove_header_chain<const WINDOW_RANGE: usize>(
        &mut self,
        input: DataCommitmentProofVariable<WINDOW_RANGE>,
    ) {
        // Verify current_block_height - trusted_block_height == WINDOW_RANGE.
        let height_diff = self.sub(
            input.end_header_height_proof.height,
            input.start_header_height_proof.height,
        );
        let window_range_target = self.constant::<U64Variable>(WINDOW_RANGE.into());
        self.assert_is_equal(height_diff, window_range_target);

        // Verify the current block's height.
        self.verify_block_height(
            input.end_header,
            &input.end_header_height_proof.proof,
            &input.end_header_height_proof.height,
            input.end_header_height_proof.enc_height_byte_length,
        );

        // Verify the trusted block's height.
        self.verify_block_height(
            input.start_header,
            &input.start_header_height_proof.proof,
            &input.start_header_height_proof.height,
            input.start_header_height_proof.enc_height_byte_length,
        );

        // Verify the header chain.
        let mut curr_header_hash = input.end_header;
        for i in 0..WINDOW_RANGE {
            let data_hash_proof = &input.data_hash_proofs[i];
            let prev_header_proof = &input.prev_header_proofs[i];
            let data_hash_proof_root = self
                .get_root_from_merkle_proof::<HEADER_PROOF_DEPTH, PROTOBUF_HASH_SIZE_BYTES>(
                    data_hash_proof,
                );
            let prev_header_proof_root = self
                .get_root_from_merkle_proof::<HEADER_PROOF_DEPTH, PROTOBUF_BLOCK_ID_SIZE_BYTES>(
                    prev_header_proof,
                );

            self.assert_is_equal(prev_header_proof_root, curr_header_hash);
            let prev_header_hash = prev_header_proof.leaf[2..2 + HASH_SIZE].into();
            self.assert_is_equal(data_hash_proof_root, prev_header_hash);
            curr_header_hash = prev_header_hash;
        }

        // Verify the last header hash in the chain is the start header.
        self.assert_is_equal(curr_header_hash, input.start_header);
    }

    fn prove_data_commitment<const WINDOW_RANGE: usize, const NB_LEAVES: usize>(
        &mut self,
        input: DataCommitmentProofVariable<WINDOW_RANGE>,
    ) -> Bytes32Variable {
        // Compute the data commitment.
        let data_commitment = self.get_data_commitment::<WINDOW_RANGE, NB_LEAVES>(
            &input.data_hashes,
            input.start_header_height_proof.height,
        );

        // Verify the header chain.
        self.prove_header_chain::<WINDOW_RANGE>(input);
        data_commitment
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use plonky2x::backend::circuit::DefaultParameters;

    use super::*;
    use crate::circuits::{DataCommitmentBuilder, DataCommitmentProofVariable};
    use crate::inputs::{generate_data_commitment_inputs, generate_expected_data_commitment};

    type L = DefaultParameters;
    type F = <L as PlonkParameters<D>>::Field;
    const D: usize = 2;

    const WINDOW_SIZE: usize = 4;
    const NUM_LEAVES: usize = 4;
    const START_BLOCK: usize = 3800;
    const END_BLOCK: usize = START_BLOCK + WINDOW_SIZE;
    const TRUSTED_BLOCK: usize = 3800;
    const CURRENT_BLOCK: usize = TRUSTED_BLOCK + WINDOW_SIZE;

    #[test]
    #[cfg_attr(feature = "ci", ignore)]
    fn test_prove_data_commitment() {
        env_logger::try_init().unwrap_or_default();

        let mut builder = CircuitBuilder::<L, D>::new();
        let data_commitment_var = builder.read::<DataCommitmentProofVariable<WINDOW_SIZE>>();
        let expected_data_commitment = builder.read::<Bytes32Variable>();
        let root_hash_target =
            builder.prove_data_commitment::<WINDOW_SIZE, NUM_LEAVES>(data_commitment_var);
        builder.assert_is_equal(root_hash_target, expected_data_commitment);
        let circuit = builder.build();

        let mut input = circuit.input();
        input.write::<DataCommitmentProofVariable<WINDOW_SIZE>>(generate_data_commitment_inputs::<
            WINDOW_SIZE,
            F,
        >(START_BLOCK, END_BLOCK));

        input.write::<Bytes32Variable>(generate_expected_data_commitment::<WINDOW_SIZE, F>(
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
        let data_commitment_var = builder.read::<DataCommitmentProofVariable<WINDOW_SIZE>>();
        let expected_data_commitment = builder.read::<Bytes32Variable>();
        let start_block = builder.constant::<U64Variable>(START_BLOCK.into());
        let root_hash_target = builder.get_data_commitment::<WINDOW_SIZE, NUM_LEAVES>(
            &data_commitment_var.data_hashes,
            start_block,
        );
        builder.assert_is_equal(root_hash_target, expected_data_commitment);
        let circuit = builder.build();

        let mut input = circuit.input();
        input.write::<DataCommitmentProofVariable<WINDOW_SIZE>>(generate_data_commitment_inputs::<
            WINDOW_SIZE,
            F,
        >(START_BLOCK, END_BLOCK));
        input.write::<Bytes32Variable>(generate_expected_data_commitment::<WINDOW_SIZE, F>(
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