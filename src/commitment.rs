//! The protobuf encoding of a Tendermint validator is a deterministic function of the validator's
//! public key (32 bytes) and voting power (int64). The encoding is as follows in bytes:
//
//!     10 34 10 32 <pubkey> 16 <varint>
//
//! The `pubkey` is encoded as the raw list of bytes used in the public key. The `varint` is
//! encoded using protobuf's default integer encoding, which consist of 7 bit payloads. You can
//! read more about them here: https://protobuf.dev/programming-guides/encoding/#varints.

use curta::math::extension::cubic::parameters::CubicParameters;
use plonky2::field::extension::Extendable;

use plonky2::hash::hash_types::RichField;
use plonky2::iop::witness::{Witness, WitnessWrite};
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig};
use plonky2x::backend::circuit::PlonkParameters;
use plonky2x::frontend::ecc::ed25519::curve::curve_types::Curve;
use plonky2x::frontend::ecc::ed25519::curve::ed25519::Ed25519;

use plonky2x::frontend::merkle::tree::MerkleInclusionProofVariable;
use plonky2x::frontend::vars::{ArrayVariable, Bytes32Variable, EvmVariable, U32Variable};
use plonky2x::prelude::{
    BoolVariable, ByteVariable, BytesVariable, CircuitBuilder, CircuitVariable, Variable,
};

use crate::utils::{HEADER_PROOF_DEPTH, PROTOBUF_BLOCK_ID_SIZE_BYTES, PROTOBUF_HASH_SIZE_BYTES};

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
    pub trusted_header: Bytes32Variable,
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

    /// Prove header chain from current_header to trusted_header
    /// Merkle prove the last block id against the current ehader
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
        curr_header: Bytes32Variable,
        trusted_header: Bytes32Variable,
        data_hash_proofs: ArrayVariable<
            MerkleInclusionProofVariable<HEADER_PROOF_DEPTH, PROTOBUF_HASH_SIZE_BYTES>,
            WINDOW_RANGE,
        >,
        prev_header_proofs: ArrayVariable<
            MerkleInclusionProofVariable<HEADER_PROOF_DEPTH, PROTOBUF_BLOCK_ID_SIZE_BYTES>,
            WINDOW_RANGE,
        >,
    ) where
        <<L as PlonkParameters<D>>::Config as GenericConfig<D>>::Hasher: AlgebraicHasher<L::Field>;
}

impl<L: PlonkParameters<D>, const D: usize> CelestiaCommitment<L, D> for CircuitBuilder<L, D> {
    type Curve = Ed25519;

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
        curr_header: Bytes32Variable,
        trusted_header: Bytes32Variable,
        data_hash_proofs: ArrayVariable<
            MerkleInclusionProofVariable<HEADER_PROOF_DEPTH, PROTOBUF_HASH_SIZE_BYTES>,
            WINDOW_RANGE,
        >,
        prev_header_proofs: ArrayVariable<
            MerkleInclusionProofVariable<HEADER_PROOF_DEPTH, PROTOBUF_BLOCK_ID_SIZE_BYTES>,
            WINDOW_RANGE,
        >,
    ) where
        <<L as PlonkParameters<D>>::Config as GenericConfig<D>>::Hasher: AlgebraicHasher<L::Field>,
    {
        let mut curr_header_hash = curr_header;
        for i in 0..WINDOW_RANGE {
            let data_hash_proof = &data_hash_proofs[i];
            let prev_header_proof = &prev_header_proofs[i];

            // TODO: Find a cleaner way to add the PLUS_ONE constraint
            let data_hash_proof_root = self
                .get_root_from_merkle_proof::<HEADER_PROOF_DEPTH, PROTOBUF_HASH_SIZE_BYTES>(
                    &data_hash_proof,
                );
            // TODO: Find a cleaner way to add the PLUS_ONE constraint
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
        self.assert_is_equal(curr_header_hash, trusted_header);
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
        // const WINDOW_SIZE: usize = 4;
        // const NUM_LEAVES: usize = 4;
        const START_BLOCK: usize = 3800;
        const END_BLOCK: usize = START_BLOCK + WINDOW_SIZE;

        let celestia_data_commitment_var =
            builder.read::<CelestiaDataCommitmentProofInputVariable<WINDOW_SIZE>>();
        // builder.watch(&celestia_data_commitment_var, "data commitment var");
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

        builder.prove_header_chain::<E, C, WINDOW_SIZE>(
            celestia_header_chain_var.current_header,
            celestia_header_chain_var.trusted_header,
            celestia_header_chain_var.data_hash_proofs,
            celestia_header_chain_var.prev_header_proofs,
        );

        let circuit = builder.build();

        let mut input = circuit.input();
        input.write::<CelestiaHeaderChainProofInputVariable<WINDOW_SIZE>>(
            generate_header_chain_inputs::<WINDOW_SIZE, F>(TRUSTED_BLOCK, CURRENT_BLOCK),
        );
        let (proof, output) = circuit.prove(&input);
        circuit.verify(&proof, &input, &output);
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
