use crate::utils::{
    HEADER_PROOF_DEPTH, PROTOBUF_BLOCK_ID_SIZE_BYTES, PROTOBUF_HASH_SIZE_BYTES,
    VALIDATOR_MESSAGE_BYTES_LENGTH_MAX,
};
use crate::verify::BlockIDInclusionProofVariable;
use crate::verify::HashInclusionProofVariable;
use ethers::types::H256;
use num::BigUint;
use plonky2x::frontend::ecc::ed25519::curve::curve_types::AffinePoint;
use plonky2x::frontend::ecc::ed25519::gadgets::eddsa::EDDSASignatureTarget;
use plonky2x::frontend::ecc::{
    ed25519::curve::ed25519::Ed25519, ed25519::field::ed25519_scalar::Ed25519Scalar,
};
use plonky2x::prelude::{CircuitVariable, Field, GoldilocksField};
use serde::{Deserialize, Serialize};
use tendermint::crypto::ed25519::VerificationKey;
use tendermint::{private_key, Signature};

type F = GoldilocksField;
type C = Ed25519;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TempMerkleInclusionProof {
    pub enc_leaf: Vec<u8>,
    // Path and proof should have a fixed length of HEADER_PROOF_DEPTH.
    pub path: Vec<bool>,
    pub proof: Vec<H256>,
}

impl From<TempMerkleInclusionProof>
    for <HashInclusionProofVariable<HEADER_PROOF_DEPTH> as CircuitVariable>::ValueType<
        GoldilocksField,
    >
{
    fn from(proof: TempMerkleInclusionProof) -> Self {
        if proof.proof.len() != HEADER_PROOF_DEPTH {
            panic!("path length does not match");
        }
        if proof.enc_leaf.len() != PROTOBUF_HASH_SIZE_BYTES {
            panic!("enc_leaf length does not match");
        }
        let leaf_as_fixed: [u8; PROTOBUF_HASH_SIZE_BYTES] = proof.enc_leaf[..].try_into().unwrap();
        Self {
            enc_leaf: leaf_as_fixed,
            proof: proof.proof,
        }
    }
}

impl From<TempMerkleInclusionProof>
    for <BlockIDInclusionProofVariable<HEADER_PROOF_DEPTH> as CircuitVariable>::ValueType<
        GoldilocksField,
    >
{
    fn from(proof: TempMerkleInclusionProof) -> Self {
        if proof.proof.len() != HEADER_PROOF_DEPTH {
            panic!("path length does not match");
        }
        if proof.enc_leaf.len() != PROTOBUF_BLOCK_ID_SIZE_BYTES {
            panic!("enc_leaf length does not match");
        }
        let leaf_as_fixed: [u8; PROTOBUF_BLOCK_ID_SIZE_BYTES] =
            proof.enc_leaf[..].try_into().unwrap();
        Self {
            enc_leaf: leaf_as_fixed,
            proof: proof.proof,
        }
    }
}

fn pubkey_to_affine_point(pubkey: &VerificationKey) -> AffinePoint<C> {
    let pubkey_bytes = pubkey.as_bytes();
    AffinePoint::new_from_compressed_point(pubkey_bytes)
}

type SignatureValueType<F> = <EDDSASignatureTarget<Ed25519> as CircuitVariable>::ValueType<F>;

fn signature_to_value_type(signature: &Signature) -> SignatureValueType<F> {
    let sig_bytes = signature.as_bytes();
    let sig_r = AffinePoint::new_from_compressed_point(&sig_bytes[0..32]);
    assert!(sig_r.is_valid());
    let mut sig_s_biguint = BigUint::from_bytes_le(&sig_bytes[32..64]);
    if sig_s_biguint.to_u32_digits().len() == 0 {
        panic!("sig_s_biguint has 0 limbs which will cause problems down the line")
    }
    let sig_s = Ed25519Scalar::from_noncanonical_biguint(sig_s_biguint.clone());
    SignatureValueType::<F> { r: sig_r, s: sig_s }
}
