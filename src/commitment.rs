//! The protobuf encoding of a Tendermint validator is a deterministic function of the validator's
//! public key (32 bytes) and voting power (int64). The encoding is as follows in bytes:
//
//!     10 34 10 32 <pubkey> 16 <varint>
//
//! The `pubkey` is encoded as the raw list of bytes used in the public key. The `varint` is
//! encoded using protobuf's default integer encoding, which consist of 7 bit payloads. You can
//! read more about them here: https://protobuf.dev/programming-guides/encoding/#varints.
use plonky2::field::extension::Extendable;
use plonky2::iop::target::BoolTarget;
use plonky2::iop::target::Target;
use plonky2::{hash::hash_types::RichField, plonk::circuit_builder::CircuitBuilder};
use plonky2x::ecc::ed25519::curve::curve_types::Curve;
use plonky2x::ecc::ed25519::curve::ed25519::Ed25519;
use plonky2x::ecc::ed25519::gadgets::curve::{AffinePointTarget, CircuitBuilderCurve};
use plonky2x::hash::sha::sha256::{sha256, sha256_variable_length_single_chunk};
use plonky2x::num::u32::gadgets::arithmetic_u32::CircuitBuilderU32;
use plonky2x::num::u32::gadgets::arithmetic_u32::U32Target;

use crate::utils::{
    I64Target, MarshalledValidatorTarget, TendermintHashTarget, HASH_SIZE_BITS,
    VALIDATOR_BIT_LENGTH_MAX, VALIDATOR_BYTE_LENGTH_MAX, VOTING_POWER_BITS_LENGTH_MAX,
    VOTING_POWER_BYTES_LENGTH_MAX,
};

pub trait CelestiaCommitment<F: RichField + Extendable<D>, const D: usize> {
    type Curve: Curve;

    /// Encodes the data hash and height into a tuple.
    fn encode_data_root_tuple(
        &mut self,
        data_hash: &TendermintHashTarget,
        height: &U32Target,
    ) -> [BoolTarget; HASH_SIZE_BITS * 2];

    /// Verify a merkle proof against the specified root hash.
    /// Note: This function will only work for leaves with a length of 34 bytes (protobuf-encoded SHA256 hash)
    /// Output is the merkle root
    fn get_root_from_merkle_proof<const PROOF_DEPTH: usize>(
        &mut self,
        aunts: &Vec<TendermintHashTarget>,
        path_indices: &Vec<BoolTarget>,
        leaf_hash: &TendermintHashTarget,
    ) -> TendermintHashTarget;

    /// Hashes leaf bytes to get the leaf hash according to the Tendermint spec. (0x00 || leafBytes)
    fn leaf_hash<const LEAF_SIZE_BITS: usize>(
        &mut self,
        leaf: &[BoolTarget; LEAF_SIZE_BITS],
    ) -> TendermintHashTarget;

    /// Hashes two nodes to get the inner node according to the Tendermint spec. (0x01 || left || right)
    fn inner_hash(
        &mut self,
        left: &TendermintHashTarget,
        right: &TendermintHashTarget,
    ) -> TendermintHashTarget;

    /// Hashes a layer of the Merkle tree according to the Tendermint spec. (0x01 || left || right)
    /// If in a pair the right node is not enabled (empty), then the left node is passed up to the next layer.
    /// If neither the left nor right node in a pair is enabled (empty), then the parent node is set to not enabled (empty).
    fn hash_merkle_layer(
        &mut self,
        merkle_hashes: &mut Vec<TendermintHashTarget>,
        merkle_hash_enabled: &mut Vec<BoolTarget>,
        num_hashes: usize,
    ) -> (Vec<TendermintHashTarget>, Vec<BoolTarget>);

    /// Compute the data commitment from the data hashes and block heights. WINDOW_RANGE is the number of blocks in the data commitment. NUM_LEAVES is the number of leaves in the tree for the data commitment.
    fn get_data_commitment<const WINDOW_RANGE: usize, const NUM_LEAVES: usize>(
        &mut self,
        data_hashes: &Vec<TendermintHashTarget>,
        block_heights: &Vec<U32Target>,
    ) -> TendermintHashTarget;
}

impl<F: RichField + Extendable<D>, const D: usize> CelestiaCommitment<F, D>
    for CircuitBuilder<F, D>
{
    type Curve = Ed25519;

    fn encode_data_root_tuple(
        &mut self,
        data_hash: &TendermintHashTarget,
        height: &U32Target,
    ) -> [BoolTarget; HASH_SIZE_BITS * 2] {
        let mut data_root_tuple = [self._false(); HASH_SIZE_BITS * 2];

        // Encode the data hash.
        for i in 0..HASH_SIZE_BITS {
            data_root_tuple[i] = data_hash.0[i];
        }

        // Encode the height.
        let mut height_bits = self.u32_to_bits_le(*height);
        height_bits.reverse();
        for i in 0..32 {
            data_root_tuple[HASH_SIZE_BITS * 2 - 32 + i] = height_bits[i];
        }

        data_root_tuple
    }

    fn get_root_from_merkle_proof<const PROOF_DEPTH: usize>(
        &mut self,
        aunts: &Vec<TendermintHashTarget>,
        // TODO: Should we hard-code path_indices to correspond to dataHash, validatorsHash and nextValidatorsHash?
        path_indices: &Vec<BoolTarget>,
        // This leaf should already be hashed. (0x00 || leafBytes)
        leaf_hash: &TendermintHashTarget,
    ) -> TendermintHashTarget {
        let mut hash_so_far = *leaf_hash;
        for i in 0..PROOF_DEPTH {
            let aunt = aunts[i];
            let path_index = path_indices[i];
            let left_hash_pair = self.inner_hash(&hash_so_far, &aunt);
            let right_hash_pair = self.inner_hash(&aunt, &hash_so_far);

            let mut hash_pair = [self._false(); HASH_SIZE_BITS];
            for j in 0..HASH_SIZE_BITS {
                // If the path index is 0, then the right hash is the aunt.
                hash_pair[j] = BoolTarget::new_unsafe(self.select(
                    path_index,
                    right_hash_pair.0[j].target,
                    left_hash_pair.0[j].target,
                ));
            }
            hash_so_far = TendermintHashTarget(hash_pair);
        }
        hash_so_far
    }

    fn leaf_hash<const LEAF_SIZE_BITS: usize>(
        &mut self,
        leaf: &[BoolTarget; LEAF_SIZE_BITS],
    ) -> TendermintHashTarget {
        // Calculate the length of the message for the leaf hash.
        // 0x00 || leafBytes
        let bits_length = 8 + (LEAF_SIZE_BITS);

        // Calculate the message for the leaf hash.
        let mut leaf_msg_bits = vec![self._false(); bits_length];

        // 0x00
        for k in 0..8 {
            leaf_msg_bits[k] = self._false();
        }

        // validatorBytes
        for k in 8..bits_length {
            leaf_msg_bits[k] = leaf[k - 8];
        }

        // Load the output of the hash.
        let hash = sha256(self, &leaf_msg_bits);
        let mut return_hash = [self._false(); HASH_SIZE_BITS];
        for k in 0..HASH_SIZE_BITS {
            return_hash[k] = hash[k];
        }
        TendermintHashTarget(return_hash)
    }

    fn inner_hash(
        &mut self,
        left: &TendermintHashTarget,
        right: &TendermintHashTarget,
    ) -> TendermintHashTarget {
        // Calculate the length of the message for the inner hash.
        // 0x01 || left || right
        let bits_length = 8 + (HASH_SIZE_BITS * 2);

        // Calculate the message for the inner hash.
        let mut message_bits = vec![self._false(); bits_length];

        // 0x01
        for k in 0..7 {
            message_bits[k] = self._false();
        }
        message_bits[7] = self._true();

        // left
        for k in 8..8 + HASH_SIZE_BITS {
            message_bits[k] = left.0[k - 8];
        }

        // right
        for k in 8 + HASH_SIZE_BITS..bits_length {
            message_bits[k] = right.0[k - (8 + HASH_SIZE_BITS)];
        }

        // Load the output of the hash.
        // Note: Calculate the inner hash as if both validators are enabled.
        let inner_hash = sha256(self, &message_bits);
        let mut ret_inner_hash = [self._false(); HASH_SIZE_BITS];
        for k in 0..HASH_SIZE_BITS {
            ret_inner_hash[k] = inner_hash[k];
        }
        TendermintHashTarget(ret_inner_hash)
    }

    fn hash_merkle_layer(
        &mut self,
        merkle_hashes: &mut Vec<TendermintHashTarget>,
        merkle_hash_enabled: &mut Vec<BoolTarget>,
        num_hashes: usize,
    ) -> (Vec<TendermintHashTarget>, Vec<BoolTarget>) {
        let zero = self.zero();
        let one = self.one();

        for i in (0..num_hashes).step_by(2) {
            let both_nodes_enabled = self.and(merkle_hash_enabled[i], merkle_hash_enabled[i + 1]);

            let first_node_disabled = self.not(merkle_hash_enabled[i]);
            let second_node_disabled = self.not(merkle_hash_enabled[i + 1]);
            let both_nodes_disabled = self.and(first_node_disabled, second_node_disabled);

            // Calculuate the inner hash.
            let inner_hash = self.inner_hash(
                &TendermintHashTarget(merkle_hashes[i].0),
                &TendermintHashTarget(merkle_hashes[i + 1].0),
            );

            for k in 0..HASH_SIZE_BITS {
                // If the left node is enabled and the right node is disabled, we pass up the left hash instead of the inner hash.
                merkle_hashes[i / 2].0[k] = BoolTarget::new_unsafe(self.select(
                    both_nodes_enabled,
                    inner_hash.0[k].target,
                    merkle_hashes[i].0[k].target,
                ));
            }

            // Set the inner node one level up to disabled if both nodes are disabled.
            merkle_hash_enabled[i / 2] =
                BoolTarget::new_unsafe(self.select(both_nodes_disabled, zero, one));
        }

        // Return the hashes and enabled nodes for the next layer up.
        (merkle_hashes.to_vec(), merkle_hash_enabled.to_vec())
    }

    fn get_data_commitment<const WINDOW_RANGE: usize, const NUM_LEAVES: usize>(
        &mut self,
        data_hashes: &Vec<TendermintHashTarget>,
        block_heights: &Vec<U32Target>,
    ) -> TendermintHashTarget {
        let mut leaves = vec![TendermintHashTarget([self._false(); HASH_SIZE_BITS]); NUM_LEAVES];
        let mut leaf_enabled = vec![self._false(); NUM_LEAVES];
        for i in 0..WINDOW_RANGE {
            // Encode the data hash and height into a tuple.
            let data_root_tuple = self.encode_data_root_tuple(&data_hashes[i], &block_heights[i]);
            let leaf_hash = self.leaf_hash(&data_root_tuple);
            leaves[i] = leaf_hash;
            leaf_enabled[i] = self._true();
        }
        for i in WINDOW_RANGE..NUM_LEAVES {
            leaf_enabled[i] = self._false();
        }
        // Hash each of the validators to get their corresponding leaf hash.
        let mut current_nodes = leaves.clone();

        // Whether to treat the validator as empty.
        let mut current_node_enabled = leaf_enabled.clone();

        let mut merkle_layer_size = NUM_LEAVES;

        // Hash each layer of nodes to get the root according to the Tendermint spec, starting from the leaves.
        while merkle_layer_size > 1 {
            (current_nodes, current_node_enabled) = self.hash_merkle_layer(
                &mut current_nodes,
                &mut current_node_enabled,
                merkle_layer_size,
            );
            merkle_layer_size /= 2;
        }

        // Return the root hash.
        current_nodes[0]
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use plonky2::{
        iop::witness::{PartialWitness, WitnessWrite},
        plonk::{
            circuit_builder::CircuitBuilder,
            circuit_data::CircuitConfig,
            config::{GenericConfig, PoseidonGoldilocksConfig},
        },
    };

    use crate::{
        commitment::CelestiaCommitment,
        inputs::get_path_indices,
        utils::{
            f_bits_to_bytes, generate_proofs_from_header, hash_all_leaves, leaf_hash, to_be_bits,
            I64Target, MarshalledValidatorTarget, TendermintHashTarget, HASH_SIZE_BITS,
            HEADER_PROOF_DEPTH, PROTOBUF_BLOCK_ID_SIZE_BITS, PROTOBUF_HASH_SIZE_BITS,
            VALIDATOR_BIT_LENGTH_MAX,
        },
    };

    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;
    type Curve = Ed25519;
    const D: usize = 2;
    const VALIDATOR_SET_SIZE_MAX: usize = 4;

    #[test]
    fn test_encode_data_root_tuple() {
        let mut pw = PartialWitness::new();
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let mut expected_data_tuple_root = vec![
            255u8, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        ];

        let expected_height = [
            0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 1, 0,
        ];

        expected_data_tuple_root.extend_from_slice(&expected_height);

        let expected_data_tuple_root_bits = to_be_bits(expected_data_tuple_root);

        let data_hash = TendermintHashTarget([builder._true(); HASH_SIZE_BITS]);
        let height = builder.constant_u32(256);
        let data_root_tuple = builder.encode_data_root_tuple(&data_hash, &height);

        // Check that the data hash is encoded correctly.
        for i in 0..HASH_SIZE_BITS {
            pw.set_bool_target(data_root_tuple[i], expected_data_tuple_root_bits[i])
        }

        // Check that the height is encoded correctly.
        // let height_bits = builder.u32_to_bits_le(height);
        for i in HASH_SIZE_BITS..HASH_SIZE_BITS * 2 {
            pw.set_bool_target(data_root_tuple[i], expected_data_tuple_root_bits[i])
        }

        let data = builder.build::<C>();
        let proof = data.prove(pw).unwrap();

        data.verify(proof).unwrap();

        println!("Verified proof");
    }
}
