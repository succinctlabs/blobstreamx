//! The protobuf encoding of a Tendermint validator is a deterministic function of the validator's
//! public key (32 bytes) and voting power (int64). The encoding is as follows in bytes:
//
//!     10 34 10 32 <pubkey> 16 <varint>
//
//! The `pubkey` is encoded as the raw list of bytes used in the public key. The `varint` is
//! encoded using protobuf's default integer encoding, which consist of 7 bit payloads. You can
//! read more about them here: https://protobuf.dev/programming-guides/encoding/#varints.
use curta::chip::hash::sha::sha256::builder_gadget::{
    CurtaBytes, SHA256Builder, SHA256BuilderGadget,
};
use curta::math::extension::cubic::parameters::CubicParameters;
use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::BoolTarget;
use plonky2::iop::target::Target;
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig};
use plonky2x::backend::config::PlonkParameters;
use plonky2x::frontend::ecc::ed25519::curve::curve_types::Curve;
use plonky2x::frontend::ecc::ed25519::curve::ed25519::Ed25519;
use plonky2x::frontend::ecc::ed25519::gadgets::curve::{AffinePointTarget, CircuitBuilderCurve};
use plonky2x::frontend::hash::sha::sha256::pad_single_sha256_chunk;
use plonky2x::frontend::num::u32::gadgets::arithmetic_u32::CircuitBuilderU32;
use plonky2x::frontend::vars::{ArrayVariable, Bytes32Variable, EvmVariable, U32Variable};
use plonky2x::prelude::{BoolVariable, ByteVariable, CircuitBuilder, CircuitVariable};
use tendermint::merkle::HASH_SIZE;

use crate::utils::{
    I64Target, MarshalledValidatorTarget, HASH_SIZE_BITS, VALIDATOR_BIT_LENGTH_MAX,
    VALIDATOR_BYTE_LENGTH_MAX, VOTING_POWER_BITS_LENGTH_MAX, VOTING_POWER_BYTES_LENGTH_MAX,
};

pub trait CelestiaCommitment<L: PlonkParameters<D>, const D: usize> {
    type Curve: Curve;

    /// Encodes the data hash and height into a tuple.
    fn encode_data_root_tuple(
        &mut self,
        data_hash: &Bytes32Variable,
        height: &U32Variable,
    ) -> ArrayVariable<ByteVariable, 64>;

    /// Verify a merkle proof against the specified root hash.
    /// Note: This function will only work for leaves with a length of 34 bytes (protobuf-encoded SHA256 hash)
    /// Output is the merkle root
    fn get_root_from_merkle_proof<E: CubicParameters<L::Field>, const PROOF_DEPTH: usize>(
        &mut self,
        aunts: &Vec<Bytes32Variable>,
        path_indices: &Vec<BoolVariable>,
        leaf_hash: &Bytes32Variable,
    ) -> Bytes32Variable;

    /// Hashes leaf bytes to get the leaf hash according to the Tendermint spec. (0x00 || leafBytes)
    /// Note: Uses STARK gadget to generate SHA's.
    /// LEAF_SIZE_BITS_PLUS_8 is the number of bits in the protobuf-encoded leaf bytes.
    fn leaf_hash_stark<
        E: CubicParameters<L::Field>,
        const LEAF_SIZE_BYTES: usize,
        const LEAF_SIZE_BYTES_PLUS_1: usize,
        const PADDED_SHA_NUM_BYTES: usize,
    >(
        &mut self,
        leaf: &ArrayVariable<ByteVariable, LEAF_SIZE_BYTES>,
    ) -> Bytes32Variable;

    /// Hashes two nodes to get the inner node according to the Tendermint spec. (0x01 || left || right)
    fn inner_hash_stark<E: CubicParameters<L::Field>>(
        &mut self,
        left: &Bytes32Variable,
        right: &Bytes32Variable,
    ) -> Bytes32Variable;

    /// Hashes a layer of the Merkle tree according to the Tendermint spec. (0x01 || left || right)
    /// If in a pair the right node is not enabled (empty), then the left node is passed up to the next layer.
    /// If neither the left nor right node in a pair is enabled (empty), then the parent node is set to not enabled (empty).
    fn hash_merkle_layer<E: CubicParameters<L::Field>>(
        &mut self,
        merkle_hashes: &mut Vec<Bytes32Variable>,
        merkle_hash_enabled: &mut Vec<BoolVariable>,
        num_hashes: usize,
    ) -> (Vec<Bytes32Variable>, Vec<BoolVariable>);

    /// Compute the data commitment from the data hashes and block heights. WINDOW_RANGE is the number of blocks in the data commitment. NUM_LEAVES is the number of leaves in the tree for the data commitment.
    fn get_data_commitment<
        E: CubicParameters<L::Field>,
        C: GenericConfig<
                D,
                F = L::Field,
                FE = <<L as PlonkParameters<D>>::Field as Extendable<D>>::Extension,
            > + 'static,
        const WINDOW_RANGE: usize,
        const NUM_LEAVES: usize,
    >(
        &mut self,
        data_hashes: &Vec<Bytes32Variable>,
        block_heights: &Vec<U32Variable>,
    ) -> Bytes32Variable
    where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<L::Field>;
}

impl<L: PlonkParameters<D>, const D: usize> CelestiaCommitment<L, D> for CircuitBuilder<L, D> {
    type Curve = Ed25519;

    fn encode_data_root_tuple(
        &mut self,
        data_hash: &Bytes32Variable,
        height: &U32Variable,
    ) -> ArrayVariable<ByteVariable, 64> {
        self.watch(data_hash, "data_hash");
        let mut encoded_tuple = data_hash.as_bytes().to_vec();

        // Encode the height.
        let encoded_height = height.encode(self);
        for i in 0..encoded_height.len() {
            self.watch(&encoded_height[i], "encoded_height");
        }

        encoded_tuple.extend(
            self.constant::<ArrayVariable<ByteVariable, 28>>(vec![0u8; 28])
                .as_vec(),
        );

        encoded_tuple.extend(encoded_height);

        ArrayVariable::<ByteVariable, 64>::new(encoded_tuple)
    }

    fn get_root_from_merkle_proof<E: CubicParameters<L::Field>, const PROOF_DEPTH: usize>(
        &mut self,
        aunts: &Vec<Bytes32Variable>,
        // TODO: Should we hard-code path_indices to correspond to dataHash, validatorsHash and nextValidatorsHash?
        path_indices: &Vec<BoolVariable>,
        // This leaf should already be hashed. (0x00 || leafBytes)
        leaf_hash: &Bytes32Variable,
    ) -> Bytes32Variable {
        let mut hash_so_far = *leaf_hash;
        for i in 0..PROOF_DEPTH {
            let aunt = aunts[i];
            let path_index = path_indices[i];
            let left_hash_pair = self.inner_hash_stark::<E>(&hash_so_far, &aunt);
            let right_hash_pair = self.inner_hash_stark::<E>(&aunt, &hash_so_far);

            hash_so_far = self.select(path_index, right_hash_pair, left_hash_pair)
        }
        hash_so_far
    }

    fn leaf_hash_stark<
        E: CubicParameters<L::Field>,
        const LEAF_SIZE_BYTES: usize,
        const LEAF_SIZE_BYTES_PLUS_1: usize,
        const PADDED_SHA_NUM_BYTES: usize,
    >(
        &mut self,
        leaf: &ArrayVariable<ByteVariable, LEAF_SIZE_BYTES>,
    ) -> Bytes32Variable {
        // NUM_BYTES must be a multiple of 32
        assert_eq!(PADDED_SHA_NUM_BYTES % 64, 0);

        let zero_byte = ByteVariable::constant(self, 0u8);

        let mut encoded_leaf = vec![zero_byte];

        // Append the leaf bytes to the zero byte.
        encoded_leaf.extend(leaf.as_vec());

        // Calculate the message for the leaf hash.
        let encoded_leaf = ArrayVariable::<ByteVariable, LEAF_SIZE_BYTES_PLUS_1>::new(encoded_leaf);

        // Load the output of the hash.
        // Use curta gadget to generate SHA's.
        // Note: This can be removed when sha256 interface is fixed.
        self.sha256_curta(&encoded_leaf.as_slice())
    }

    fn inner_hash_stark<E: CubicParameters<L::Field>>(
        &mut self,
        left: &Bytes32Variable,
        right: &Bytes32Variable,
    ) -> Bytes32Variable {
        // Calculate the length of the message for the inner hash.
        // 0x01 || left || right
        let one_byte = ByteVariable::constant(self, 1u8);

        let mut encoded_leaf = vec![one_byte];

        // Append the left bytes to the one byte.
        encoded_leaf.extend(left.as_bytes().to_vec());

        // Append the right bytes to the bytes so far.
        encoded_leaf.extend(right.as_bytes().to_vec());

        // Load the output of the hash.
        // Note: Calculate the inner hash as if both validators are enabled.
        self.sha256_curta(&encoded_leaf)
    }

    fn hash_merkle_layer<E: CubicParameters<L::Field>>(
        &mut self,
        merkle_hashes: &mut Vec<Bytes32Variable>,
        merkle_hash_enabled: &mut Vec<BoolVariable>,
        num_hashes: usize,
    ) -> (Vec<Bytes32Variable>, Vec<BoolVariable>) {
        let zero = self._false();
        let one = self._true();

        for i in (0..num_hashes).step_by(2) {
            let both_nodes_enabled = self.and(merkle_hash_enabled[i], merkle_hash_enabled[i + 1]);

            let first_node_disabled = self.not(merkle_hash_enabled[i]);
            let second_node_disabled = self.not(merkle_hash_enabled[i + 1]);
            let both_nodes_disabled = self.and(first_node_disabled, second_node_disabled);

            // Calculuate the inner hash.
            let inner_hash = self.inner_hash_stark::<E>(&merkle_hashes[i], &merkle_hashes[i + 1]);

            merkle_hashes[i / 2] = self.select(both_nodes_enabled, inner_hash, merkle_hashes[i]);

            // Set the inner node one level up to disabled if both nodes are disabled.
            merkle_hash_enabled[i / 2] = self.select(both_nodes_disabled, zero, one);
        }

        // Return the hashes and enabled nodes for the next layer up.
        (merkle_hashes.to_vec(), merkle_hash_enabled.to_vec())
    }

    fn get_data_commitment<
        E: CubicParameters<L::Field>,
        C: GenericConfig<
                D,
                F = L::Field,
                FE = <<L as PlonkParameters<D>>::Field as Extendable<D>>::Extension,
            > + 'static,
        const WINDOW_RANGE: usize,
        const NUM_LEAVES: usize,
    >(
        &mut self,
        data_hashes: &Vec<Bytes32Variable>,
        block_heights: &Vec<U32Variable>,
    ) -> Bytes32Variable
    where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<L::Field>,
    {
        // let mut gadget: SHA256BuilderGadget<L::Field, E, D> = self.api.init_sha256();

        let mut leaves = Vec::new();
        let mut leaf_enabled = vec![self._false(); NUM_LEAVES];
        for i in 0..WINDOW_RANGE {
            // Encode the data hash and height into a tuple.
            let data_root_tuple = self.encode_data_root_tuple(&data_hashes[i], &block_heights[i]);

            const DATA_TUPLE_ROOT_SIZE_BYTES: usize = 64;
            const DATA_TUPLE_ROOT_SIZE_BYTES_PLUS_1: usize = DATA_TUPLE_ROOT_SIZE_BYTES + 1;

            // Number of bytes in the padded message for SHA256.
            const PADDED_SHA256_BYTES: usize = 128;
            let leaf_hash = self
                .leaf_hash_stark::<E, DATA_TUPLE_ROOT_SIZE_BYTES, DATA_TUPLE_ROOT_SIZE_BYTES_PLUS_1, PADDED_SHA256_BYTES>(
                    &data_root_tuple,
                );
            leaves.push(leaf_hash);
            leaf_enabled[i] = self._true();
        }

        leaves.extend(vec![
            self.constant::<Bytes32Variable>(
                ethers::types::H256::zero()
            );
            NUM_LEAVES - WINDOW_RANGE
        ]);

        // Fill out the first SHA256 gadget with empty leaves.
        // First chunk is 800 SHA-chunks
        // Fill out 1024 - 800 = 224 SHA-chunks
        // let num_chunks_left = 224;
        // fill_out_sha_gadget::<L, E, D>(self, &mut gadget, num_chunks_left);
        // self.api.constrain_sha256_gadget::<C>(gadget);

        // let mut gadget: SHA256BuilderGadget<L::Field, E, D> = self.api.init_sha256();

        // Hash each of the validators to get their corresponding leaf hash.
        let mut current_nodes = leaves.clone();

        // Whether to treat the validator as empty.
        let mut current_node_enabled = leaf_enabled.clone();

        let mut merkle_layer_size = NUM_LEAVES;

        // Hash each layer of nodes to get the root according to the Tendermint spec, starting from the leaves.
        while merkle_layer_size > 1 {
            (current_nodes, current_node_enabled) = self.hash_merkle_layer::<E>(
                &mut current_nodes,
                &mut current_node_enabled,
                merkle_layer_size,
            );
            merkle_layer_size /= 2;
        }

        // // If NUM_LEAVES=512, then we have 1024 - (511 * 2) = 2 SHA-chunks left.
        // // Each inner_hash_stark is 2 SHA chunks
        // let num_chunks_left = 2;
        // fill_out_sha_gadget::<L, E, D>(self, &mut gadget, num_chunks_left);
        // self.api.constrain_sha256_gadget::<C>(gadget);

        // Return the root hash.
        current_nodes[0]
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use curta::math::goldilocks::cubic::GoldilocksCubicParameters;
    use plonky2::{
        iop::witness::{PartialWitness, WitnessWrite},
        plonk::{
            circuit_data::CircuitConfig,
            config::{GenericConfig, PoseidonGoldilocksConfig},
        },
    };
    use plonky2x::backend::config::DefaultParameters;
    use subtle_encoding::hex;

    use crate::{
        commitment::CelestiaCommitment,
        inputs::{generate_data_commitment_inputs, get_path_indices},
        utils::{
            f_bits_to_bytes, generate_proofs_from_header, hash_all_leaves, leaf_hash, to_be_bits,
            I64Target, MarshalledValidatorTarget, HASH_SIZE_BITS, HEADER_PROOF_DEPTH,
            PROTOBUF_BLOCK_ID_SIZE_BITS, PROTOBUF_HASH_SIZE_BITS, VALIDATOR_BIT_LENGTH_MAX,
        },
    };

    type L = DefaultParameters;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;
    type E = GoldilocksCubicParameters;
    type Curve = Ed25519;
    const D: usize = 2;

    const WINDOW_SIZE: usize = 400;
    const NUM_LEAVES: usize = 512;

    // #[derive(Clone, Debug, CircuitVariable)]
    // struct CelestiaDataCommitmentProofInputVariable {
    //     data_hashes: Vec<Bytes32Variable>,
    //     block_heights: Vec<U32Variable>,
    //     data_commitment_root: Bytes32Variable,
    // }

    // #[test]
    // fn test_data_commitment() {
    //     let mut pw = PartialWitness::new();
    //     let config = CircuitConfig::standard_recursion_config();
    //     let mut builder = CircuitBuilder::<L, D>::new();

    //     let celestia_data_commitment_var =
    //         builder.read::<CelestiaDataCommitmentProofInputVariable>();
    //     let root_hash_target = builder.get_data_commitment::<E, C, WINDOW_SIZE, NUM_LEAVES>(
    //         &celestia_data_commitment_var.data_hashes,
    //         &celestia_data_commitment_var.block_heights,
    //     );
    //     builder.assert_is_equal(
    //         root_hash_target,
    //         celestia_data_commitment_var.data_commitment_root,
    //     );
    //     let circuit = builder.build();

    //     const START_BLOCK: usize = 3800;
    //     const END_BLOCK: usize = START_BLOCK + WINDOW_SIZE;

    //     let input = circuit.input();
    //     input.write::<CelestiaDataCommitmentProofInputVariable>(generate_data_commitment_inputs(
    //         START_BLOCK,
    //         END_BLOCK,
    //     ));
    //     let (proof, mut output) = circuit.prove(&input);
    //     circuit.verify(&proof, &input, &output);
    // }

    #[test]
    fn test_encode_data_root_tuple() {
        let mut builder = CircuitBuilder::<L, D>::new();

        let data_hash =
            builder.constant::<Bytes32Variable>(ethers::types::H256::from_slice(&[255u8; 32]));
        builder.watch(&data_hash, "data_hash");
        let height = builder.constant::<U32Variable>(256);
        builder.watch(&height, "height");
        let data_root_tuple = builder.encode_data_root_tuple(&data_hash, &height);
        builder.watch(&data_root_tuple, "data_root_tuple");
        builder.write(data_root_tuple);
        let circuit = builder.build();

        // Compute the expected output for testing
        let mut expected_data_tuple_root = vec![
            255u8, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        ];

        let expected_height = [
            0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 1, 0,
        ];

        expected_data_tuple_root.extend_from_slice(&expected_height);

        let input = circuit.input();
        let (proof, mut output) = circuit.prove(&input);
        circuit.verify(&proof, &input, &output);

        let data_root_tuple_value = output.read::<ArrayVariable<ByteVariable, 64>>();
        assert_eq!(data_root_tuple_value, expected_data_tuple_root);

        println!("Verified proof");
    }
}
