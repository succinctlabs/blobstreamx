use plonky2x::{
    frontend::{
        ecc::ed25519::gadgets::curve::AffinePointTarget,
        num::u32::gadgets::arithmetic_u32::U32Target,
    },
    prelude::{Bytes32Variable, BytesVariable},
};

use crate::consts::{
    PROTOBUF_BLOCK_ID_SIZE_BYTES, PROTOBUF_HASH_SIZE_BYTES, VALIDATOR_BYTE_LENGTH_MAX,
    VALIDATOR_MESSAGE_BYTES_LENGTH_MAX,
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
/// The voting power as a list of 2 u32 targets.
#[derive(Debug, Clone, Copy)]
pub struct I64Target(pub [U32Target; 2]);
