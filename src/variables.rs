use plonky2x::prelude::{
    CircuitBuilder, PlonkParameters, RichField, Variable, Witness, WitnessWrite,
};
use plonky2x::{
    frontend::{
        ecc::ed25519::gadgets::curve::AffinePointTarget,
        merkle::tree::MerkleInclusionProofVariable, num::u32::gadgets::arithmetic_u32::U32Target,
        uint::uint64::U64Variable, vars::U32Variable,
    },
    prelude::{ArrayVariable, Bytes32Variable, BytesVariable, CircuitVariable},
};

use crate::consts::{
    HEADER_PROOF_DEPTH, PROTOBUF_BLOCK_ID_SIZE_BYTES, PROTOBUF_HASH_SIZE_BYTES,
    VALIDATOR_BYTE_LENGTH_MAX, VALIDATOR_MESSAGE_BYTES_LENGTH_MAX,
};

pub type EDDSAPublicKeyVariable<C> = AffinePointTarget<C>;

/// A protobuf-encoded tendermint block ID as a 72 byte target.
pub type EncBlockIDVariable = BytesVariable<PROTOBUF_BLOCK_ID_SIZE_BYTES>;

// A protobuf-encoded tendermint hash as a 34 byte target.
pub type EncTendermintHashVariable = BytesVariable<PROTOBUF_HASH_SIZE_BYTES>;

/// The Tendermint hash as a 32 byte variable.
pub type TendermintHashVariable = Bytes32Variable;

/// The marshalled validator bytes as a variable.
pub type MarshalledValidatorVariable = BytesVariable<VALIDATOR_BYTE_LENGTH_MAX>;

/// The message signed by the validator as a variable.
pub type ValidatorMessageVariable = BytesVariable<VALIDATOR_MESSAGE_BYTES_LENGTH_MAX>;

// A block height proof as a struct.
// Proof is the block height proof against a header.
// Height is the block height of the header as a u64.
// EncHeightByteLength is the length of the protobuf-encoded height as a u32.
// TODO: Make this generic for all variable length header proofs.
#[derive(Clone, Debug, CircuitVariable)]
#[value_name(HeightProofValueType)]
pub struct HeightProofVariable {
    pub proof: ArrayVariable<Bytes32Variable, HEADER_PROOF_DEPTH>,
    pub enc_height_byte_length: U32Variable,
    pub height: U64Variable,
}

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
/// The voting power as a list of 2 u32 targets.
#[derive(Debug, Clone, Copy)]
pub struct I64Target(pub [U32Target; 2]);
