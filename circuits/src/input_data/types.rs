use ed25519_consensus::SigningKey;
use ethers::types::H256;
use num::BigUint;
use plonky2x::frontend::ecc::ed25519::curve::curve_types::AffinePoint;
use plonky2x::frontend::ecc::ed25519::curve::ed25519::Ed25519;
use plonky2x::frontend::ecc::ed25519::field::ed25519_scalar::Ed25519Scalar;
use plonky2x::frontend::ecc::ed25519::gadgets::eddsa::EDDSASignatureTarget;
use plonky2x::frontend::ecc::ed25519::gadgets::verify::DUMMY_SIGNATURE;
use plonky2x::prelude::{CircuitVariable, Field, GoldilocksField, RichField};
use serde::{Deserialize, Serialize};
use tendermint::crypto::ed25519::VerificationKey;
use tendermint::validator::Set as ValidatorSet;
use tendermint::vote::{SignedVote, ValidatorIndex};
use tendermint::{private_key, Signature};

use super::tendermint_utils::{non_absent_vote, TempSignedBlock};
use crate::consts::{
    HEADER_PROOF_DEPTH, PROTOBUF_BLOCK_ID_SIZE_BYTES, PROTOBUF_HASH_SIZE_BYTES,
    VALIDATOR_MESSAGE_BYTES_LENGTH_MAX,
};
use crate::verify::{
    BlockIDInclusionProof, BlockIDInclusionProofVariable, HashInclusionProof,
    HashInclusionProofVariable, Validator, ValidatorHashField,
};

type C = Ed25519;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TempMerkleInclusionProof {
    pub enc_leaf: Vec<u8>,
    // Proof should have a fixed length of HEADER_PROOF_DEPTH.
    pub proof: Vec<H256>,
}

impl TempMerkleInclusionProof {
    pub fn to_hash_value_type<F: RichField>(&self) -> HashInclusionProof<HEADER_PROOF_DEPTH, F> {
        if self.proof.len() != HEADER_PROOF_DEPTH {
            panic!("path length does not match");
        }
        if self.enc_leaf.len() != PROTOBUF_HASH_SIZE_BYTES {
            panic!("enc_leaf length does not match");
        }
        let leaf_as_fixed: [u8; PROTOBUF_HASH_SIZE_BYTES] = self.enc_leaf[..].try_into().unwrap();
        HashInclusionProof {
            enc_leaf: leaf_as_fixed,
            proof: self.proof.clone(),
        }
    }

    pub fn to_block_id_value_type<F: RichField>(
        &self,
    ) -> BlockIDInclusionProof<HEADER_PROOF_DEPTH, F> {
        if self.proof.len() != HEADER_PROOF_DEPTH {
            panic!("path length does not match");
        }
        if self.enc_leaf.len() != PROTOBUF_BLOCK_ID_SIZE_BYTES {
            panic!("enc_leaf length does not match");
        }
        let leaf_as_fixed: [u8; PROTOBUF_BLOCK_ID_SIZE_BYTES] =
            self.enc_leaf[..].try_into().unwrap();
        BlockIDInclusionProof {
            enc_leaf: leaf_as_fixed,
            proof: self.proof.clone(),
        }
    }
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

fn signature_to_value_type<F: RichField>(signature: &Signature) -> SignatureValueType<F> {
    let sig_bytes = signature.as_bytes();
    let sig_r = AffinePoint::new_from_compressed_point(&sig_bytes[0..32]);
    assert!(sig_r.is_valid());
    let sig_s_biguint = BigUint::from_bytes_le(&sig_bytes[32..64]);
    if sig_s_biguint.to_u32_digits().is_empty() {
        panic!("sig_s_biguint has 0 limbs which will cause problems down the line")
    }
    let sig_s = Ed25519Scalar::from_noncanonical_biguint(sig_s_biguint);
    SignatureValueType::<F> { r: sig_r, s: sig_s }
}

pub fn get_validators_as_input<const VALIDATOR_SET_SIZE_MAX: usize, F: RichField>(
    block: &TempSignedBlock,
) -> Vec<Validator<C, F>> {
    let mut validators = Vec::new();

    // Signatures or dummy
    // Need signature to output either verify or no verify (then we can assert that it matches or doesn't match)
    let validator_set = ValidatorSet::new(
        block.validator_set.validators.clone(),
        block.validator_set.proposer.clone(),
    );
    let block_validators = validator_set.validators();

    // Exclude invalid validators (i.e. those that are malformed & are not included in the validator set).
    for i in 0..block.commit.signatures.len() {
        let val_idx = ValidatorIndex::try_from(i).unwrap();
        let validator = Box::new(match validator_set.validator(block_validators[i].address) {
            Some(validator) => validator,
            None => continue, // Cannot find matching validator, so we skip the vote
        });
        let val_bytes = validator.hash_bytes();
        if block.commit.signatures[i].is_commit() {
            let vote =
                non_absent_vote(&block.commit.signatures[i], val_idx, &block.commit).unwrap();

            let signed_vote = Box::new(
                SignedVote::from_vote(vote.clone(), block.header.chain_id.clone())
                    .expect("missing signature"),
            );
            let mut message_padded = signed_vote.sign_bytes();
            message_padded.resize(VALIDATOR_MESSAGE_BYTES_LENGTH_MAX, 0u8);

            let sig = signed_vote.signature();

            validators.push(Validator {
                pubkey: pubkey_to_affine_point(&validator.pub_key.ed25519().unwrap()),
                signature: signature_to_value_type(&sig.clone()),
                message: message_padded.try_into().unwrap(),
                message_byte_length: F::from_canonical_usize(signed_vote.sign_bytes().len()),
                voting_power: validator.power().into(),
                validator_byte_length: F::from_canonical_usize(val_bytes.len()),
                enabled: true,
                signed: true,
                present_on_trusted_header: false, // This field is ignored in this case
            });
        } else {
            // These are dummy signatures (included in val hash, did not vote)
            validators.push(Validator {
                pubkey: pubkey_to_affine_point(&validator.pub_key.ed25519().unwrap()),
                signature: signature_to_value_type(
                    &Signature::try_from(DUMMY_SIGNATURE.to_vec()).expect("missing signature"),
                ),
                // TODO: Replace these with correct outputs
                message: [0u8; VALIDATOR_MESSAGE_BYTES_LENGTH_MAX],
                message_byte_length: F::from_canonical_usize(32),
                voting_power: validator.power().into(),
                validator_byte_length: F::from_canonical_usize(val_bytes.len()),
                enabled: true,
                signed: false,
                present_on_trusted_header: false, // This field is ignored in this case
            });
        }
    }

    // These are empty signatures (not included in val hash)
    for _ in block.commit.signatures.len()..VALIDATOR_SET_SIZE_MAX {
        let priv_key_bytes = [0u8; 32];
        let signing_key =
            private_key::Ed25519::try_from(&priv_key_bytes[..]).expect("failed to create key");
        let signing_key = SigningKey::try_from(signing_key).unwrap();

        let verification_key = signing_key.verification_key();
        // TODO: Fix empty signatures
        validators.push(Validator {
            pubkey: pubkey_to_affine_point(
                &VerificationKey::try_from(verification_key.as_bytes().as_ref())
                    .expect("failed to create verification key"),
            ),
            signature: signature_to_value_type(
                &Signature::try_from(DUMMY_SIGNATURE.to_vec()).expect("missing signature"),
            ),
            // TODO: Replace these with correct outputs
            message: [0u8; VALIDATOR_MESSAGE_BYTES_LENGTH_MAX],
            message_byte_length: F::from_canonical_usize(32),
            voting_power: 0u64.into(),
            validator_byte_length: F::from_canonical_usize(38),
            enabled: false,
            signed: false,
            present_on_trusted_header: false, // This field ignored for this case
        });
    }

    validators
}

pub fn get_validators_fields_as_input<const VALIDATOR_SET_SIZE_MAX: usize, F: RichField>(
    trusted_block: &TempSignedBlock,
) -> Vec<ValidatorHashField<C, F>> {
    let mut trusted_validator_fields = Vec::new();

    let validator_set = ValidatorSet::new(
        trusted_block.validator_set.validators.clone(),
        trusted_block.validator_set.proposer.clone(),
    );

    let block_validators = validator_set.validators();

    for i in 0..trusted_block.commit.signatures.len() {
        let validator = Box::new(match validator_set.validator(block_validators[i].address) {
            Some(validator) => validator,
            None => continue, // Cannot find matching validator, so we skip the vote
        });
        let val_bytes = validator.hash_bytes();
        trusted_validator_fields.push(ValidatorHashField {
            pubkey: pubkey_to_affine_point(&validator.pub_key.ed25519().unwrap()),
            voting_power: validator.power().into(),
            validator_byte_length: F::from_canonical_usize(val_bytes.len()),
            enabled: true,
        });
    }

    let val_so_far = trusted_validator_fields.len();

    // These are empty signatures (not included in val hash)
    for _ in val_so_far..VALIDATOR_SET_SIZE_MAX {
        let priv_key_bytes = [0u8; 32];
        let signing_key =
            private_key::Ed25519::try_from(&priv_key_bytes[..]).expect("failed to create key");
        let signing_key = SigningKey::try_from(signing_key).unwrap();
        let verification_key = signing_key.verification_key();
        // TODO: Fix empty signatures
        trusted_validator_fields.push(ValidatorHashField {
            pubkey: pubkey_to_affine_point(
                &VerificationKey::try_from(verification_key.as_bytes().as_ref())
                    .expect("failed to create verification key"),
            ),
            voting_power: 0u64.into(),
            validator_byte_length: F::from_canonical_usize(38),
            enabled: false,
        });
    }

    trusted_validator_fields
}

pub fn update_present_on_trusted_header<F: RichField>(
    target_validators: &mut [Validator<C, F>],
    target_block: &TempSignedBlock,
    start_block: &TempSignedBlock,
) {
    // Parse each block to compute the validators that are the same from block_1 to block_2, and the cumulative voting power of the shared validators
    let mut shared_voting_power = 0;

    let threshold = 1_f64 / 3_f64;

    let target_block_validator_set = ValidatorSet::new(
        target_block.validator_set.validators.clone(),
        target_block.validator_set.proposer.clone(),
    );
    let start_block_validator_set = ValidatorSet::new(
        start_block.validator_set.validators.clone(),
        start_block.validator_set.proposer.clone(),
    );

    let target_block_total_voting_power = target_block_validator_set.total_voting_power().value();

    let start_block_validators = start_block_validator_set.validators();

    let mut start_block_idx = 0;
    let start_block_num_validators = start_block_validators.len();

    // Exit if we have already reached the threshold
    // TODO: Confirm this is resilient by testing many different cases.
    while target_block_total_voting_power as f64 * threshold > shared_voting_power as f64
        && start_block_idx < start_block_num_validators
    {
        if let Some(target_block_validator) =
            target_block_validator_set.validator(start_block_validators[start_block_idx].address)
        {
            // Get index of start_block_validators[idx] in target_block_validators
            let target_idx = target_block_validator_set
                .validators()
                .iter()
                .position(|x| *x == target_block_validator)
                .unwrap();

            // Confirm that the validator has signed on block_2
            for sig in target_block.commit.signatures.iter() {
                if sig.validator_address().is_some()
                    && sig.validator_address().unwrap() == target_block_validator.address
                {
                    // Add the shared voting power to the validator
                    shared_voting_power += target_block_validator.power();
                    // Set the present_on_trusted_header field to true
                    target_validators[target_idx].present_on_trusted_header = true;
                    println!(
                        "updated present_on_trusted_header for target validator: {}",
                        target_idx
                    );
                }
            }
        }
        println!("start block idx: {}", start_block_idx);
        start_block_idx += 1;
    }

    assert!(
        target_block_total_voting_power as f64 * threshold <= shared_voting_power as f64,
        "shared voting power is less than threshold"
    );
}
