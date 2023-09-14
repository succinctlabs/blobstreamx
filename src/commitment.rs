use curta::math::extension::cubic::parameters::CubicParameters;
use curta::maybe_rayon::rayon::str::Bytes;
use plonky2::field::extension::Extendable;

use plonky2::hash::hash_types::RichField;
use plonky2::iop::witness::{Witness, WitnessWrite};
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig};
use plonky2x::backend::circuit::PlonkParameters;
use plonky2x::frontend::ecc::ed25519::curve::curve_types::Curve;
use plonky2x::frontend::ecc::ed25519::curve::ed25519::Ed25519;

use itertools::Itertools;

use plonky2x::frontend::merkle::tree::MerkleInclusionProofVariable;
use plonky2x::frontend::num::u32::gadgets::arithmetic_u32::U32Target;
use plonky2x::frontend::uint::uint64::U64Variable;
use plonky2x::frontend::vars::{ArrayVariable, Bytes32Variable, EvmVariable, U32Variable};
use plonky2x::prelude::{
    BoolVariable, ByteVariable, BytesVariable, CircuitBuilder, CircuitVariable, Variable,
};

use crate::utils::{
    I64Target, HEADER_PROOF_DEPTH, PROTOBUF_BLOCK_ID_SIZE_BYTES, PROTOBUF_HASH_SIZE_BYTES,
    PROTOBUF_VARINT_SIZE_BYTES,
};
use crate::validator::TendermintValidator;

#[derive(Clone, Debug, CircuitVariable)]
#[value_name(CelestiaDataCommitmentProofInput)]
pub struct CelestiaDataCommitmentProofInputVariable<const WINDOW_SIZE: usize> {
    pub data_hashes: ArrayVariable<Bytes32Variable, WINDOW_SIZE>,
    pub block_heights: ArrayVariable<U32Variable, WINDOW_SIZE>,
    pub data_commitment_root: Bytes32Variable,
}

#[derive(Clone, Debug, CircuitVariable)]
#[value_name(CelestiaHeaderChainProofInput)]
pub struct CelestiaHeaderChainProofInputVariable<const WINDOW_RANGE: usize> {
    pub current_header: Bytes32Variable,
    pub current_header_height_proof:
        MerkleInclusionProofVariable<HEADER_PROOF_DEPTH, PROTOBUF_VARINT_SIZE_BYTES>,
    pub current_header_height_byte_length: U32Variable,
    pub current_header_height: U32Variable,
    pub trusted_header: Bytes32Variable,
    pub trusted_header_height_proof:
        MerkleInclusionProofVariable<HEADER_PROOF_DEPTH, PROTOBUF_VARINT_SIZE_BYTES>,
    pub trusted_header_height_byte_length: U32Variable,
    pub trusted_header_height: U32Variable,
    pub data_hash_proofs: ArrayVariable<
        MerkleInclusionProofVariable<HEADER_PROOF_DEPTH, PROTOBUF_HASH_SIZE_BYTES>,
        WINDOW_RANGE,
    >,
    pub prev_header_proofs: ArrayVariable<
        MerkleInclusionProofVariable<HEADER_PROOF_DEPTH, PROTOBUF_BLOCK_ID_SIZE_BYTES>,
        WINDOW_RANGE,
    >,
}

pub trait CelestiaCommitment<L: PlonkParameters<D>, const D: usize> {
    type Curve: Curve;

    /// Serializes a u32 as a protobuf varint.
    /// NOTE: Block height is a i64 (but always positive), but u32 is used for simplicity.
    fn marshal_u32_as_varint(&mut self, num: &U32Variable) -> BytesVariable<9>;

    /// Encodes the data hash and height into a tuple.
    /// Spec: https://github.com/celestiaorg/celestia-core/blob/6933af1ead0ddf4a8c7516690e3674c6cdfa7bd8/rpc/core/blocks.go#L325-L334
    fn encode_data_root_tuple(
        &mut self,
        data_hash: &Bytes32Variable,
        height: &U32Variable,
    ) -> BytesVariable<64>;

    fn extract_hash_from_protobuf<const START_BYTE: usize, const PROTOBUF_LENGTH_BYTES: usize>(
        &mut self,
        bytes: &BytesVariable<PROTOBUF_LENGTH_BYTES>,
    ) -> Bytes32Variable;

    /// Compute the data commitment from the data hashes and block heights. WINDOW_RANGE is the number of blocks in the data commitment. NUM_LEAVES is the number of leaves in the tree for the data commitment.
    fn get_data_commitment<
        E: CubicParameters<L::Field>,
        C: GenericConfig<
                D,
                F = L::Field,
                FE = <<L as PlonkParameters<D>>::Field as Extendable<D>>::Extension,
            > + 'static,
        const WINDOW_RANGE: usize,
        const NB_LEAVES: usize,
    >(
        &mut self,
        data_hashes: &ArrayVariable<Bytes32Variable, WINDOW_RANGE>,
        block_heights: &ArrayVariable<U32Variable, WINDOW_RANGE>,
    ) -> Bytes32Variable
    where
        <<L as PlonkParameters<D>>::Config as GenericConfig<D>>::Hasher: AlgebraicHasher<L::Field>;

    /// Prove header chain from current_header to trusted_header.
    /// Prove the block height for the current header and the trusted header.
    /// Pass in the block height to get_data_commitment.
    /// Merkle prove the last block id against the current header
    /// Merkle prove the data hash for every header (except the current header)
    /// Note: data_hash_proofs and prev_header_proofs should be in order from current_header to trusted_header
    fn prove_header_chain<
        E: CubicParameters<L::Field>,
        C: GenericConfig<
                D,
                F = L::Field,
                FE = <<L as PlonkParameters<D>>::Field as Extendable<D>>::Extension,
            > + 'static,
        const WINDOW_RANGE: usize,
    >(
        &mut self,
        input: CelestiaHeaderChainProofInputVariable<WINDOW_RANGE>,
    ) where
        <<L as PlonkParameters<D>>::Config as GenericConfig<D>>::Hasher: AlgebraicHasher<L::Field>;
}

impl<L: PlonkParameters<D>, const D: usize> CelestiaCommitment<L, D> for CircuitBuilder<L, D> {
    type Curve = Ed25519;

    fn marshal_u32_as_varint(&mut self, num: &U32Variable) -> BytesVariable<9> {
        // Lower then upper bytes.
        let voting_power = I64Target([U32Target(num.targets()[0]), U32Target::default()]);
        let marshalled_bits = self.api.marshal_int64_varint(&voting_power);
        // Convert marshalled_bits to BytesVariable<9>.
        let marshalled_bytes = marshalled_bits
            .chunks(8)
            .map(|chunk| {
                let targets = chunk.iter().map(|b| b.target).collect_vec();
                ByteVariable::from_targets(&targets)
            })
            .collect_vec();

        let mut bytes = [ByteVariable::init(self); 9];
        bytes.copy_from_slice(&marshalled_bytes);
        BytesVariable(bytes)
    }

    fn encode_data_root_tuple(
        &mut self,
        data_hash: &Bytes32Variable,
        height: &U32Variable,
    ) -> BytesVariable<64> {
        let mut encoded_tuple = Vec::new();

        // Encode the height.
        let encoded_height = height.encode(self);

        // Pad the abi.encodePacked(height) to 32 bytes.
        encoded_tuple.extend(
            self.constant::<ArrayVariable<ByteVariable, 28>>(vec![0u8; 28])
                .as_vec(),
        );

        // Add the abi.encodePacked(height) to the tuple.
        encoded_tuple.extend(encoded_height);

        // Add the data hash to the tuple.
        encoded_tuple.extend(data_hash.as_bytes().to_vec());

        // Convert Vec<ByteVariable> to BytesVariable<64>.
        let mut hash_bytes_array = [ByteVariable::init(self); 64];
        hash_bytes_array.copy_from_slice(&encoded_tuple);
        BytesVariable::<64>(hash_bytes_array)
    }

    fn extract_hash_from_protobuf<const START_BYTE: usize, const PROTOBUF_LENGTH_BYTES: usize>(
        &mut self,
        bytes: &BytesVariable<PROTOBUF_LENGTH_BYTES>,
    ) -> Bytes32Variable {
        let vec_slice = bytes.0[START_BYTE..START_BYTE + 32].to_vec();
        let arr = ArrayVariable::<ByteVariable, 32>::new(vec_slice);
        Bytes32Variable(BytesVariable(arr.as_slice().try_into().unwrap()))
    }

    fn get_data_commitment<
        E: CubicParameters<L::Field>,
        C: GenericConfig<
                D,
                F = L::Field,
                FE = <<L as PlonkParameters<D>>::Field as Extendable<D>>::Extension,
            > + 'static,
        const WINDOW_RANGE: usize,
        const NB_LEAVES: usize,
    >(
        &mut self,
        data_hashes: &ArrayVariable<Bytes32Variable, WINDOW_RANGE>,
        block_heights: &ArrayVariable<U32Variable, WINDOW_RANGE>,
    ) -> Bytes32Variable
    where
        <<L as PlonkParameters<D>>::Config as GenericConfig<D>>::Hasher: AlgebraicHasher<L::Field>,
    {
        let mut leaves = Vec::new();

        for i in 0..WINDOW_RANGE {
            // Encode the data hash and height into a tuple.
            leaves.push(self.encode_data_root_tuple(&data_hashes[i], &block_heights[i]));
        }

        let leaves = ArrayVariable::<BytesVariable<64>, WINDOW_RANGE>::new(leaves);
        // self.watch(&leaves, format!("leaves").as_str());
        let root = self.compute_root_from_leaves::<WINDOW_RANGE, NB_LEAVES, 64>(&leaves);

        self.watch(&root, format!("root").as_str());

        // Return the root hash.
        root
    }

    fn prove_header_chain<
        E: CubicParameters<L::Field>,
        C: GenericConfig<
                D,
                F = L::Field,
                FE = <<L as PlonkParameters<D>>::Field as Extendable<D>>::Extension,
            > + 'static,
        const WINDOW_RANGE: usize,
    >(
        &mut self,
        input: CelestiaHeaderChainProofInputVariable<WINDOW_RANGE>,
    ) where
        <<L as PlonkParameters<D>>::Config as GenericConfig<D>>::Hasher: AlgebraicHasher<L::Field>,
    {
        let height_diff = self.sub(input.current_header_height, input.trusted_header_height);
        let window_range_target = self.constant::<U32Variable>(WINDOW_RANGE as u32);
        self.assert_is_equal(height_diff, window_range_target);

        // Verify the current header height proof against the current header.
        let encoded_height = self.marshal_u32_as_varint(&input.current_header_height);
        self.watch(&encoded_height, "encoded_height");
        // Extend encoded_height to 64 bytes.
        let mut encoded_height_extended = [ByteVariable::init(self); 64];
        for i in 0..PROTOBUF_VARINT_SIZE_BYTES {
            encoded_height_extended[i] = encoded_height.0[i];
        }
        let encoded_height = BytesVariable::<64>(encoded_height_extended);

        let last_chunk = self.constant::<U32Variable>(0);
        let leaf_hash = self.curta_sha256_variable::<1>(
            &encoded_height.0,
            last_chunk,
            input.current_header_height_byte_length,
        );
        self.watch(&leaf_hash, "leaf_hash");

        let current_header_height_proof_root = self
            .get_root_from_merkle_proof_hashed_leaf::<HEADER_PROOF_DEPTH>(
                &input.current_header_height_proof.aunts,
                &input.current_header_height_proof.path_indices,
                leaf_hash,
            );
        self.assert_is_equal(current_header_height_proof_root, input.current_header);

        // Verify the trusted header height proof against the current header.
        let mut encoded_height_extended = [ByteVariable::init(self); 64];
        for i in 0..PROTOBUF_VARINT_SIZE_BYTES {
            encoded_height_extended[i] = encoded_height.0[i];
        }
        let encoded_height = BytesVariable::<64>(encoded_height_extended);

        let last_chunk = self.constant::<U32Variable>(0);
        let leaf_hash = self.curta_sha256_variable::<1>(
            &encoded_height.0,
            last_chunk,
            input.trusted_header_height_byte_length,
        );

        self.watch(&leaf_hash, "leaf_hash");

        let trusted_header_height_proof_root = self
            .get_root_from_merkle_proof_hashed_leaf::<HEADER_PROOF_DEPTH>(
                &input.trusted_header_height_proof.aunts,
                &input.trusted_header_height_proof.path_indices,
                leaf_hash,
            );
        self.assert_is_equal(trusted_header_height_proof_root, input.trusted_header);

        let mut curr_header_hash = input.current_header;

        for i in 0..WINDOW_RANGE {
            let data_hash_proof = &input.data_hash_proofs[i];
            let prev_header_proof = &input.prev_header_proofs[i];

            let data_hash_proof_root = self
                .get_root_from_merkle_proof::<HEADER_PROOF_DEPTH, PROTOBUF_HASH_SIZE_BYTES>(
                    &data_hash_proof,
                );
            let prev_header_proof_root = self
                .get_root_from_merkle_proof::<HEADER_PROOF_DEPTH, PROTOBUF_BLOCK_ID_SIZE_BYTES>(
                    &prev_header_proof,
                );

            // Verify the prev header proof against the current header hash.
            self.assert_is_equal(prev_header_proof_root, curr_header_hash);

            // Extract the prev header hash from the prev header proof.
            let prev_header_hash =
                self.extract_hash_from_protobuf::<2, 72>(&prev_header_proof.leaf);

            // Verify the data hash proof against the prev header hash.
            self.assert_is_equal(data_hash_proof_root, prev_header_hash);

            curr_header_hash = prev_header_hash;
        }
        // Verify the last header hash in the chain is the trusted header.
        self.assert_is_equal(curr_header_hash, input.trusted_header);
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::env;

    use super::*;
    use curta::math::goldilocks::cubic::GoldilocksCubicParameters;
    use plonky2::{
        hash::hash_types::RichField,
        iop::witness::{Witness, WitnessWrite},
        plonk::config::PoseidonGoldilocksConfig,
    };
    use plonky2x::{backend::circuit::DefaultParameters, prelude::Variable};

    use crate::{
        commitment::CelestiaCommitment,
        inputs::{generate_data_commitment_inputs, generate_header_chain_inputs},
    };

    type L = DefaultParameters;
    type F = <L as PlonkParameters<D>>::Field;
    type C = PoseidonGoldilocksConfig;
    type E = GoldilocksCubicParameters;
    const D: usize = 2;

    #[test]
    fn test_data_commitment() {
        env::set_var("RUST_LOG", "debug");
        env_logger::try_init().unwrap_or_default();

        let mut builder = CircuitBuilder::<L, D>::new();

        const WINDOW_SIZE: usize = 4;
        const NUM_LEAVES: usize = 4;
        const START_BLOCK: usize = 3800;
        const END_BLOCK: usize = START_BLOCK + WINDOW_SIZE;

        let celestia_data_commitment_var =
            builder.read::<CelestiaDataCommitmentProofInputVariable<WINDOW_SIZE>>();

        let root_hash_target = builder.get_data_commitment::<E, C, WINDOW_SIZE, NUM_LEAVES>(
            &celestia_data_commitment_var.data_hashes,
            &celestia_data_commitment_var.block_heights,
        );
        builder.assert_is_equal(
            root_hash_target,
            celestia_data_commitment_var.data_commitment_root,
        );

        let circuit = builder.build();

        let mut input = circuit.input();
        input.write::<CelestiaDataCommitmentProofInputVariable<WINDOW_SIZE>>(
            generate_data_commitment_inputs::<WINDOW_SIZE, F>(START_BLOCK, END_BLOCK),
        );
        let (proof, output) = circuit.prove(&input);
        circuit.verify(&proof, &input, &output);
    }

    #[test]
    fn test_prove_header_chain() {
        env::set_var("RUST_LOG", "debug");
        env_logger::try_init().unwrap_or_default();

        let mut builder = CircuitBuilder::<L, D>::new();

        const WINDOW_SIZE: usize = 4;
        const TRUSTED_BLOCK: usize = 3800;
        const CURRENT_BLOCK: usize = TRUSTED_BLOCK + WINDOW_SIZE;

        let celestia_header_chain_var =
            builder.read::<CelestiaHeaderChainProofInputVariable<WINDOW_SIZE>>();

        // builder.watch(&celestia_header_chain_var, "header chain var");

        builder.prove_header_chain::<E, C, WINDOW_SIZE>(celestia_header_chain_var);

        let circuit = builder.build();

        let mut input = circuit.input();
        input.write::<CelestiaHeaderChainProofInputVariable<WINDOW_SIZE>>(
            generate_header_chain_inputs::<WINDOW_SIZE, F>(TRUSTED_BLOCK, CURRENT_BLOCK),
        );
        let (proof, output) = circuit.prove(&input);
        circuit.verify(&proof, &input, &output);
    }

    #[test]
    fn test_encode_varint() {
        env::set_var("RUST_LOG", "debug");
        env_logger::try_init().unwrap_or_default();

        let mut builder = CircuitBuilder::<L, D>::new();

        let height = builder.constant::<U32Variable>(1);

        let encoded_height = builder.marshal_u32_as_varint(&height);
        builder.watch(&encoded_height, "encoded_height");

        let circuit = builder.build();

        let input = circuit.input();
        let (proof, mut output) = circuit.prove(&input);
        circuit.verify(&proof, &input, &output);

        println!("Verified proof");
    }

    #[test]
    fn test_encode_data_root_tuple() {
        env::set_var("RUST_LOG", "debug");
        env_logger::try_init().unwrap_or_default();

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
