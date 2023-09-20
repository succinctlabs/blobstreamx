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

// The Celestia data commitment inputs as a struct.
#[derive(Clone, Debug, CircuitVariable)]
#[value_name(CelestiaDataCommitmentProofInput)]
pub struct CelestiaDataCommitmentProofInputVariable<const WINDOW_SIZE: usize> {
    pub data_hashes: ArrayVariable<Bytes32Variable, WINDOW_SIZE>,
    pub block_heights: ArrayVariable<U64Variable, WINDOW_SIZE>,
    pub data_commitment_root: Bytes32Variable,
}

// A block height proof as a struct.
// TODO: Make this generic for all variable length header proofs.
#[derive(Clone, Debug, CircuitVariable)]
#[value_name(HeightProofVariableInput)]
pub struct HeightProofVariable {
    pub proof: ArrayVariable<Bytes32Variable, HEADER_PROOF_DEPTH>,
    pub height_byte_length: U32Variable,
    pub height: U64Variable,
}

// The Celestia header chain inputs as a struct.
#[derive(Clone, Debug, CircuitVariable)]
#[value_name(CelestiaHeaderChainProofInput)]
pub struct CelestiaHeaderChainProofInputVariable<const WINDOW_RANGE: usize> {
    pub current_header: Bytes32Variable,
    pub current_header_height_proof: HeightProofVariable,
    pub trusted_header: Bytes32Variable,
    pub trusted_header_height_proof: HeightProofVariable,
    pub data_hash_proofs: ArrayVariable<
        MerkleInclusionProofVariable<HEADER_PROOF_DEPTH, PROTOBUF_HASH_SIZE_BYTES>,
        WINDOW_RANGE,
    >,
    pub prev_header_proofs: ArrayVariable<
        MerkleInclusionProofVariable<HEADER_PROOF_DEPTH, PROTOBUF_BLOCK_ID_SIZE_BYTES>,
        WINDOW_RANGE,
    >,
}
/// The voting power as a list of 2 u32 targets.
#[derive(Debug, Clone, Copy)]
pub struct I64Target(pub [U32Target; 2]);
