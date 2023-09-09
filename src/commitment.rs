//! The protobuf encoding of a Tendermint validator is a deterministic function of the validator's
//! public key (32 bytes) and voting power (int64). The encoding is as follows in bytes:
//
//!     10 34 10 32 <pubkey> 16 <varint>
//
//! The `pubkey` is encoded as the raw list of bytes used in the public key. The `varint` is
//! encoded using protobuf's default integer encoding, which consist of 7 bit payloads. You can
//! read more about them here: https://protobuf.dev/programming-guides/encoding/#varints.

use curta::math::extension::cubic::parameters::CubicParameters;
use ethers::types::H256;
use plonky2::field::extension::Extendable;

use plonky2::hash::hash_types::RichField;
use plonky2::iop::witness::{Witness, WitnessWrite};
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig};
use plonky2x::backend::config::PlonkParameters;
use plonky2x::frontend::ecc::ed25519::curve::curve_types::Curve;
use plonky2x::frontend::ecc::ed25519::curve::ed25519::Ed25519;

use plonky2x::frontend::vars::{ArrayVariable, Bytes32Variable, EvmVariable, U32Variable};
use plonky2x::prelude::{
    BoolVariable, ByteVariable, BytesVariable, CircuitBuilder, CircuitVariable, Variable,
};

use crate::inputs::{
    CelestiaDataCommitmentProofInputs, CelestiaHeaderChainProofInputs, InclusionProof,
};
use crate::utils::{HEADER_PROOF_DEPTH, PROTOBUF_BLOCK_ID_SIZE_BYTES, PROTOBUF_HASH_SIZE_BYTES};

#[derive(Clone, Debug)]
struct CelestiaDataCommitmentProofInputVariable<const WINDOW_SIZE: usize> {
    data_hashes: ArrayVariable<Bytes32Variable, WINDOW_SIZE>,
    block_heights: ArrayVariable<U32Variable, WINDOW_SIZE>,
    data_commitment_root: Bytes32Variable,
}

impl<const WINDOW_SIZE: usize> CircuitVariable
    for CelestiaDataCommitmentProofInputVariable<WINDOW_SIZE>
{
    type ValueType<F: RichField> = CelestiaDataCommitmentProofInputs;

    fn init<L: PlonkParameters<D>, const D: usize>(builder: &mut CircuitBuilder<L, D>) -> Self {
        Self {
            data_hashes: ArrayVariable::<Bytes32Variable, WINDOW_SIZE>::init(builder),
            block_heights: ArrayVariable::<U32Variable, WINDOW_SIZE>::init(builder),
            data_commitment_root: Bytes32Variable::init(builder),
        }
    }

    fn constant<L: PlonkParameters<D>, const D: usize>(
        builder: &mut CircuitBuilder<L, D>,
        value: Self::ValueType<L::Field>,
    ) -> Self {
        Self {
            data_hashes: ArrayVariable::<Bytes32Variable, WINDOW_SIZE>::constant(
                builder,
                value.data_hashes,
            ),
            block_heights: ArrayVariable::<U32Variable, WINDOW_SIZE>::constant(
                builder,
                value.block_heights,
            ),
            data_commitment_root: Bytes32Variable::constant(builder, value.data_commitment_root),
        }
    }

    fn variables(&self) -> Vec<Variable> {
        let mut vars = Vec::new();
        vars.extend(self.data_hashes.variables());
        vars.extend(self.block_heights.variables());
        vars.extend(self.data_commitment_root.variables());
        vars
    }

    fn from_variables(variables: &[Variable]) -> Self {
        let num_elements = ArrayVariable::<Bytes32Variable, WINDOW_SIZE>::nb_elements();
        let data_hashes = ArrayVariable::<Bytes32Variable, WINDOW_SIZE>::from_variables(
            &variables[0..num_elements],
        );
        let mut offset = num_elements;
        let num_elements = ArrayVariable::<U32Variable, WINDOW_SIZE>::nb_elements();
        let block_heights = ArrayVariable::<U32Variable, WINDOW_SIZE>::from_variables(
            &variables[offset..offset + num_elements],
        );
        offset += num_elements;
        let data_commitment_root = Bytes32Variable::from_variables(
            &variables[offset..offset + Bytes32Variable::nb_elements()],
        );
        Self {
            data_hashes,
            block_heights,
            data_commitment_root,
        }
    }

    fn get<F: RichField, W: Witness<F>>(&self, witness: &W) -> Self::ValueType<F> {
        CelestiaDataCommitmentProofInputs {
            data_hashes: self.data_hashes.get(witness),
            block_heights: self.block_heights.get(witness),
            data_commitment_root: self.data_commitment_root.get(witness),
        }
    }

    fn set<F: RichField, W: WitnessWrite<F>>(&self, witness: &mut W, value: Self::ValueType<F>) {
        self.data_hashes.set(witness, value.data_hashes);
        self.block_heights.set(witness, value.block_heights);
        self.data_commitment_root
            .set(witness, value.data_commitment_root);
    }
}

#[derive(Clone, Debug)]
pub struct MerkleInclusionProofVariable<const PROOF_DEPTH: usize, const LEAF_SIZE_BYTES: usize> {
    aunts: ArrayVariable<Bytes32Variable, PROOF_DEPTH>,
    path_indices: ArrayVariable<BoolVariable, PROOF_DEPTH>,
    enc_leaf: ArrayVariable<ByteVariable, LEAF_SIZE_BYTES>,
}

impl<const PROOF_DEPTH: usize, const LEAF_SIZE_BYTES: usize> CircuitVariable
    for MerkleInclusionProofVariable<PROOF_DEPTH, LEAF_SIZE_BYTES>
{
    type ValueType<F: RichField> = InclusionProof;

    fn init<L: PlonkParameters<D>, const D: usize>(builder: &mut CircuitBuilder<L, D>) -> Self {
        Self {
            aunts: ArrayVariable::<Bytes32Variable, PROOF_DEPTH>::init(builder),
            path_indices: ArrayVariable::<BoolVariable, PROOF_DEPTH>::init(builder),
            enc_leaf: ArrayVariable::<ByteVariable, LEAF_SIZE_BYTES>::init(builder),
        }
    }

    fn constant<L: PlonkParameters<D>, const D: usize>(
        builder: &mut CircuitBuilder<L, D>,
        value: Self::ValueType<L::Field>,
    ) -> Self {
        Self {
            aunts: ArrayVariable::<Bytes32Variable, PROOF_DEPTH>::constant(builder, value.proof),
            path_indices: ArrayVariable::<BoolVariable, PROOF_DEPTH>::constant(builder, value.path),
            enc_leaf: ArrayVariable::<ByteVariable, LEAF_SIZE_BYTES>::constant(
                builder,
                value.enc_leaf,
            ),
        }
    }

    fn variables(&self) -> Vec<Variable> {
        let mut vars = Vec::new();
        vars.extend(self.aunts.variables());
        vars.extend(self.path_indices.variables());
        vars.extend(self.enc_leaf.variables());
        vars
    }

    fn from_variables(variables: &[Variable]) -> Self {
        let num_elements = ArrayVariable::<Bytes32Variable, PROOF_DEPTH>::nb_elements();
        let aunts = ArrayVariable::<Bytes32Variable, PROOF_DEPTH>::from_variables(
            &variables[0..num_elements],
        );
        let mut offset = num_elements;
        let num_elements = ArrayVariable::<BoolVariable, PROOF_DEPTH>::nb_elements();
        let path_indices = ArrayVariable::<BoolVariable, PROOF_DEPTH>::from_variables(
            &variables[offset..offset + num_elements],
        );
        offset += num_elements;
        let enc_leaf = ArrayVariable::<ByteVariable, LEAF_SIZE_BYTES>::from_variables(
            &variables
                [offset..offset + ArrayVariable::<ByteVariable, LEAF_SIZE_BYTES>::nb_elements()],
        );
        Self {
            aunts,
            path_indices,
            enc_leaf,
        }
    }

    fn get<F: RichField, W: Witness<F>>(&self, witness: &W) -> Self::ValueType<F> {
        InclusionProof {
            proof: self.aunts.get(witness),
            path: self.path_indices.get(witness),
            enc_leaf: self.enc_leaf.get(witness),
        }
    }

    fn set<F: RichField, W: WitnessWrite<F>>(&self, witness: &mut W, value: Self::ValueType<F>) {
        self.aunts.set(witness, value.proof);
        self.path_indices.set(witness, value.path);
        self.enc_leaf.set(witness, value.enc_leaf);
    }
}

#[derive(Clone, Debug)]
pub struct CelestiaHeaderChainProofInputVariable<const WINDOW_RANGE: usize> {
    current_header: Bytes32Variable,
    trusted_header: Bytes32Variable,
    data_hash_proofs: ArrayVariable<
        MerkleInclusionProofVariable<HEADER_PROOF_DEPTH, PROTOBUF_HASH_SIZE_BYTES>,
        WINDOW_RANGE,
    >,
    prev_header_proofs: ArrayVariable<
        MerkleInclusionProofVariable<HEADER_PROOF_DEPTH, PROTOBUF_BLOCK_ID_SIZE_BYTES>,
        WINDOW_RANGE,
    >,
}

impl<const WINDOW_RANGE: usize> CircuitVariable
    for CelestiaHeaderChainProofInputVariable<WINDOW_RANGE>
{
    type ValueType<F: RichField> = CelestiaHeaderChainProofInputs;

    fn init<L: PlonkParameters<D>, const D: usize>(builder: &mut CircuitBuilder<L, D>) -> Self {
        Self {
            data_hash_proofs: ArrayVariable::<
                MerkleInclusionProofVariable<HEADER_PROOF_DEPTH, PROTOBUF_HASH_SIZE_BYTES>,
                WINDOW_RANGE,
            >::init(builder),
            prev_header_proofs: ArrayVariable::<
                MerkleInclusionProofVariable<HEADER_PROOF_DEPTH, PROTOBUF_BLOCK_ID_SIZE_BYTES>,
                WINDOW_RANGE,
            >::init(builder),
            current_header: Bytes32Variable::init(builder),
            trusted_header: Bytes32Variable::init(builder),
        }
    }

    fn constant<L: PlonkParameters<D>, const D: usize>(
        builder: &mut CircuitBuilder<L, D>,
        value: Self::ValueType<L::Field>,
    ) -> Self {
        Self {
            data_hash_proofs: ArrayVariable::<
                MerkleInclusionProofVariable<HEADER_PROOF_DEPTH, PROTOBUF_HASH_SIZE_BYTES>,
                WINDOW_RANGE,
            >::constant(builder, value.data_hash_proofs),
            prev_header_proofs: ArrayVariable::<
                MerkleInclusionProofVariable<HEADER_PROOF_DEPTH, PROTOBUF_BLOCK_ID_SIZE_BYTES>,
                WINDOW_RANGE,
            >::constant(builder, value.prev_header_proofs),
            current_header: Bytes32Variable::constant(builder, value.current_header),
            trusted_header: Bytes32Variable::constant(builder, value.trusted_header),
        }
    }

    fn variables(&self) -> Vec<Variable> {
        let mut vars = Vec::new();
        vars.extend(self.data_hash_proofs.variables());
        vars.extend(self.prev_header_proofs.variables());
        vars.extend(self.current_header.variables());
        vars.extend(self.trusted_header.variables());

        vars
    }

    fn from_variables(variables: &[Variable]) -> Self {
        let num_elements = ArrayVariable::<
            MerkleInclusionProofVariable<HEADER_PROOF_DEPTH, PROTOBUF_HASH_SIZE_BYTES>,
            WINDOW_RANGE,
        >::nb_elements();
        let data_hash_proofs = ArrayVariable::<
            MerkleInclusionProofVariable<HEADER_PROOF_DEPTH, PROTOBUF_HASH_SIZE_BYTES>,
            WINDOW_RANGE,
        >::from_variables(&variables[0..num_elements]);

        let mut offset = num_elements;
        let num_elements = ArrayVariable::<
            MerkleInclusionProofVariable<HEADER_PROOF_DEPTH, PROTOBUF_BLOCK_ID_SIZE_BYTES>,
            WINDOW_RANGE,
        >::nb_elements();
        let prev_header_proofs =
            ArrayVariable::<
                MerkleInclusionProofVariable<HEADER_PROOF_DEPTH, PROTOBUF_BLOCK_ID_SIZE_BYTES>,
                WINDOW_RANGE,
            >::from_variables(&variables[offset..offset + num_elements]);

        offset += num_elements;
        let current_header = Bytes32Variable::from_variables(
            &variables[offset..offset + Bytes32Variable::nb_elements()],
        );

        offset += Bytes32Variable::nb_elements();
        let trusted_header = Bytes32Variable::from_variables(
            &variables[offset..offset + Bytes32Variable::nb_elements()],
        );
        Self {
            data_hash_proofs,
            prev_header_proofs,
            current_header,
            trusted_header,
        }
    }

    fn get<F: RichField, W: Witness<F>>(&self, witness: &W) -> Self::ValueType<F> {
        CelestiaHeaderChainProofInputs {
            data_hash_proofs: self.data_hash_proofs.get(witness),
            prev_header_proofs: self.prev_header_proofs.get(witness),
            current_header: self.current_header.get(witness),
            trusted_header: self.trusted_header.get(witness),
        }
    }

    fn set<F: RichField, W: WitnessWrite<F>>(&self, witness: &mut W, value: Self::ValueType<F>) {
        self.data_hash_proofs.set(witness, value.data_hash_proofs);
        self.prev_header_proofs
            .set(witness, value.prev_header_proofs);
        self.current_header.set(witness, value.current_header);
        self.trusted_header.set(witness, value.trusted_header);
    }
}

pub trait CelestiaCommitment<L: PlonkParameters<D>, const D: usize> {
    type Curve: Curve;

    /// Encodes the data hash and height into a tuple.
    /// Spec: https://github.com/celestiaorg/celestia-core/blob/6933af1ead0ddf4a8c7516690e3674c6cdfa7bd8/rpc/core/blocks.go#L325-L334
    fn encode_data_root_tuple(
        &mut self,
        data_hash: &Bytes32Variable,
        height: &U32Variable,
    ) -> ArrayVariable<ByteVariable, 64>;

    fn extract_hash_from_protobuf<const START_BYTE: usize, const PROTOBUF_LENGTH_BYTES: usize>(
        &mut self,
        bytes: &ArrayVariable<ByteVariable, PROTOBUF_LENGTH_BYTES>,
    ) -> Bytes32Variable;

    /// Verify a merkle proof against the specified root hash.
    /// Note: This function will only work for leaves with a length of 34 bytes (protobuf-encoded SHA256 hash)
    /// Output is the merkle root
    fn get_root_from_merkle_proof<
        E: CubicParameters<L::Field>,
        const PROOF_DEPTH: usize,
        const LEAF_SIZE_BYTES: usize,
        const LEAF_SIZE_BYTES_PLUS_1: usize,
    >(
        &mut self,
        inclusion_proof: &MerkleInclusionProofVariable<PROOF_DEPTH, LEAF_SIZE_BYTES>,
    ) -> Bytes32Variable;

    /// Hashes leaf bytes to get the leaf hash according to the Tendermint spec. (0x00 || leafBytes)
    /// Note: Uses STARK gadget to generate SHA's.
    /// LEAF_SIZE_BITS_PLUS_8 is the number of bits in the protobuf-encoded leaf bytes.
    fn leaf_hash_stark<
        E: CubicParameters<L::Field>,
        const LEAF_SIZE_BYTES: usize,
        const LEAF_SIZE_BYTES_PLUS_1: usize,
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
        merkle_hashes: Vec<Bytes32Variable>,
        merkle_hash_enabled: Vec<BoolVariable>,
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
    ) -> ArrayVariable<ByteVariable, 64> {
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

        ArrayVariable::<ByteVariable, 64>::new(encoded_tuple)
    }

    fn extract_hash_from_protobuf<const START_BYTE: usize, const PROTOBUF_LENGTH_BYTES: usize>(
        &mut self,
        bytes: &ArrayVariable<ByteVariable, PROTOBUF_LENGTH_BYTES>,
    ) -> Bytes32Variable {
        let vec_slice = bytes.as_slice()[START_BYTE..START_BYTE + 32].to_vec();
        let arr = ArrayVariable::<ByteVariable, 32>::new(vec_slice);
        Bytes32Variable(BytesVariable(arr.as_slice().try_into().unwrap()))
    }

    fn get_root_from_merkle_proof<
        E: CubicParameters<L::Field>,
        const PROOF_DEPTH: usize,
        const LEAF_SIZE_BYTES: usize,
        const LEAF_SIZE_BYTES_PLUS_1: usize,
    >(
        &mut self,
        inclusion_proof: &MerkleInclusionProofVariable<PROOF_DEPTH, LEAF_SIZE_BYTES>,
    ) -> Bytes32Variable {
        let mut hash_so_far = self.leaf_hash_stark::<E, LEAF_SIZE_BYTES, LEAF_SIZE_BYTES_PLUS_1>(
            &inclusion_proof.enc_leaf,
        );

        for i in 0..PROOF_DEPTH {
            let aunt = inclusion_proof.aunts[i];
            let path_index = inclusion_proof.path_indices[i];
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
    >(
        &mut self,
        leaf: &ArrayVariable<ByteVariable, LEAF_SIZE_BYTES>,
    ) -> Bytes32Variable {
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
        merkle_hashes: Vec<Bytes32Variable>,
        merkle_hash_enabled: Vec<BoolVariable>,
        num_hashes: usize,
    ) -> (Vec<Bytes32Variable>, Vec<BoolVariable>) {
        let zero = self._false();
        let one = self._true();

        let mut new_merkle_hashes = Vec::new();
        let mut new_merkle_hash_enabled = Vec::new();

        for i in (0..num_hashes).step_by(2) {
            let both_nodes_enabled = self.and(merkle_hash_enabled[i], merkle_hash_enabled[i + 1]);

            let first_node_disabled = self.not(merkle_hash_enabled[i]);
            let second_node_disabled = self.not(merkle_hash_enabled[i + 1]);
            let both_nodes_disabled = self.and(first_node_disabled, second_node_disabled);

            // Calculuate the inner hash.
            let inner_hash = self.inner_hash_stark::<E>(&merkle_hashes[i], &merkle_hashes[i + 1]);

            new_merkle_hashes.push(self.select(both_nodes_enabled, inner_hash, merkle_hashes[i]));

            // Set the inner node one level up to disabled if both nodes are disabled.
            new_merkle_hash_enabled.push(self.select(both_nodes_disabled, zero, one));
        }

        // Return the hashes and enabled nodes for the next layer up.
        (new_merkle_hashes, new_merkle_hash_enabled)
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
        data_hashes: &ArrayVariable<Bytes32Variable, WINDOW_RANGE>,
        block_heights: &ArrayVariable<U32Variable, WINDOW_RANGE>,
    ) -> Bytes32Variable
    where
        <<L as PlonkParameters<D>>::Config as GenericConfig<D>>::Hasher: AlgebraicHasher<L::Field>,
    {
        let mut leaves = Vec::new();
        let mut leaf_enabled = Vec::new();
        for i in 0..WINDOW_RANGE {
            // Encode the data hash and height into a tuple.
            let data_root_tuple = self.encode_data_root_tuple(&data_hashes[i], &block_heights[i]);
            // self.watch(&data_root_tuple, format!("data_root_tuple {}", i).as_str());

            const DATA_TUPLE_ROOT_SIZE_BYTES: usize = 64;
            const DATA_TUPLE_ROOT_SIZE_BYTES_PLUS_1: usize = DATA_TUPLE_ROOT_SIZE_BYTES + 1;

            let leaf_hash = self
                .leaf_hash_stark::<E, DATA_TUPLE_ROOT_SIZE_BYTES, DATA_TUPLE_ROOT_SIZE_BYTES_PLUS_1>(
                    &data_root_tuple,
                );
            leaves.push(leaf_hash);
            leaf_enabled.push(self._true());
        }

        for _ in 0..NUM_LEAVES - WINDOW_RANGE {
            leaves.push(self.constant::<Bytes32Variable>(ethers::types::H256::zero()));
            leaf_enabled.push(self._false());
        }

        // Hash each of the validators to get their corresponding leaf hash.
        let mut current_nodes = leaves.clone();

        // Whether to treat the validator as empty.
        let mut current_node_enabled = leaf_enabled.clone();

        let mut merkle_layer_size = NUM_LEAVES;

        // Hash each layer of nodes to get the root according to the Tendermint spec, starting from the leaves.
        while merkle_layer_size > 1 {
            (current_nodes, current_node_enabled) =
                self.hash_merkle_layer::<E>(current_nodes, current_node_enabled, merkle_layer_size);
            merkle_layer_size /= 2;
        }

        // TODO: Move this to the build function once prove header chain is complete
        self.constraint_sha256_curta();

        self.watch(&current_nodes[0], format!("current_nodes AT END").as_str());
        // Return the root hash.
        current_nodes[0]
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
                .get_root_from_merkle_proof::<E, HEADER_PROOF_DEPTH, PROTOBUF_HASH_SIZE_BYTES, 35>(
                    &data_hash_proof,
                );
            // TODO: Find a cleaner way to add the PLUS_ONE constraint
            let prev_header_proof_root = self
                .get_root_from_merkle_proof::<E, HEADER_PROOF_DEPTH, PROTOBUF_BLOCK_ID_SIZE_BYTES, 73>(
                    &prev_header_proof,
                );

            // Verify the prev header proof against the current header hash.
            self.assert_is_equal(prev_header_proof_root, curr_header_hash);

            // Extract the prev header hash from the prev header proof.
            let prev_header_hash =
                self.extract_hash_from_protobuf::<2, 72>(&prev_header_proof.enc_leaf);

            // Verify the data hash proof against the prev header hash.
            self.assert_is_equal(data_hash_proof_root, prev_header_hash);

            curr_header_hash = prev_header_hash;
        }
        // Verify the last header hash in the chain is the trusted header.
        self.assert_is_equal(curr_header_hash, trusted_header);

        // TODO: Move this out of this function once prove header chain is integrated with data commitment
        self.constraint_sha256_curta();
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
    use plonky2x::{backend::config::DefaultParameters, prelude::Variable};

    use crate::{
        commitment::CelestiaCommitment,
        inputs::{
            generate_data_commitment_inputs, generate_header_chain_inputs,
            CelestiaDataCommitmentProofInputs,
        },
    };

    type L = DefaultParameters;
    type C = PoseidonGoldilocksConfig;
    type E = GoldilocksCubicParameters;
    const D: usize = 2;

    #[test]
    fn test_data_commitment() {
        env::set_var("RUST_LOG", "debug");
        env_logger::try_init().unwrap_or_default();

        let mut builder = CircuitBuilder::<L, D>::new();

        const WINDOW_SIZE: usize = 400;
        const NUM_LEAVES: usize = 512;
        // const WINDOW_SIZE: usize = 4;
        // const NUM_LEAVES: usize = 4;
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
            generate_data_commitment_inputs::<WINDOW_SIZE>(START_BLOCK, END_BLOCK),
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
        // const WINDOW_SIZE: usize = 4;
        // const NUM_LEAVES: usize = 4;
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
            generate_header_chain_inputs::<WINDOW_SIZE>(TRUSTED_BLOCK, CURRENT_BLOCK),
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
