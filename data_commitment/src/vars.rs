use celestia::consts::{
    HEADER_PROOF_DEPTH, PROTOBUF_BLOCK_ID_SIZE_BYTES, PROTOBUF_HASH_SIZE_BYTES,
};
use plonky2x::frontend::merkle::tree::MerkleInclusionProofVariable;
use plonky2x::frontend::uint::uint64::U64Variable;
use plonky2x::prelude::{
    ArrayVariable, Bytes32Variable, CircuitBuilder, CircuitVariable, PlonkParameters, RichField,
    Variable, Witness, WitnessWrite,
};

// The data commitment inputs as a struct.
// Note: data_hashes should be in order from start_header to end_header - 1.
// Note: data_hash_proofs and prev_header_proofs should be in order from end_header to start_header.
// Note: data_hash_proofs starts at end_header - 1.
// Note: prev_header_proofs starts at end_header.
#[derive(Clone, Debug, CircuitVariable)]
#[value_name(DataCommitmentProofValueType)]
pub struct DataCommitmentProofVariable<const MAX_LEAVES: usize> {
    pub data_hashes: ArrayVariable<Bytes32Variable, MAX_LEAVES>,
    pub end_header: Bytes32Variable,
    pub end_block_height: U64Variable,
    pub start_header: Bytes32Variable,
    pub start_block_height: U64Variable,
    pub data_hash_proofs: ArrayVariable<
        MerkleInclusionProofVariable<HEADER_PROOF_DEPTH, PROTOBUF_HASH_SIZE_BYTES>,
        MAX_LEAVES,
    >,
    pub prev_header_proofs: ArrayVariable<
        MerkleInclusionProofVariable<HEADER_PROOF_DEPTH, PROTOBUF_BLOCK_ID_SIZE_BYTES>,
        MAX_LEAVES,
    >,
}
